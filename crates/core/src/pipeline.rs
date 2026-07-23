//! `Pipeline`: wires the four ports together and owns the whole policy
//! matrix (`SHARED.md` "Safety invariants" + the `behavior.*` knobs) on top
//! of the pure `process::{buffer_run, stream_run}` functions.

use std::sync::Arc;

use bytes::Bytes;
use regex::Regex;

use crate::config::settings::{
    OnConfigError, OnMissingObject, OnUnrecognizedObject, ProcessingMode,
};
use crate::config::{ConfigStore, Settings};
use crate::error::{CoreError, StoreError};
use crate::filter::Engine;
use crate::metrics::Metrics;
use crate::model::{ObjectRef, PutMeta, SourceItem};
use crate::ports::{EventDecoder, MetricsSink, ObjectStore};
use crate::process::{Outcome, buffer_run, stream_run};

/// Canonical output metadata (`SHARED.md` "Canonical output PutMeta"): every
/// write this module performs — filtered output, a fail-open raw copy, or an
/// `on_unrecognized_object: copy` raw copy — uses exactly this, so the
/// destination bucket is uniform regardless of which path wrote a given
/// object.
const CANONICAL_META: PutMeta = PutMeta {
    content_type: "application/x-gzip",
    content_encoding: "gzip",
};

/// What `Pipeline::handle` reports back to the composition root: which
/// `SourceItem::ack_id`s (SQS message IDs) failed, for `ReportBatchItemFailures`.
/// Empty when every item succeeded (or `partial_batch_failures` is irrelevant,
/// e.g. a direct S3 invocation with no ack ids at all).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BatchOutcome {
    pub failed_ack_ids: Vec<String>,
}

/// Which processing strategy an object is routed through, decided by
/// `processing.mode` and (for `auto`) `ObjectRef.size` vs.
/// `stream_threshold_bytes` (`SHARED.md` safety invariant 5: missing size
/// picks buffer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObjectMode {
    Buffer,
    Stream,
}

/// Composition root wiring: the four ports plus the resolved `Settings`,
/// process-lived `Metrics`, and the compiled-rules `ConfigStore`.
pub struct Pipeline {
    settings: Arc<Settings>,
    decoder: Arc<dyn EventDecoder>,
    store: Arc<dyn ObjectStore>,
    config: Arc<ConfigStore<Arc<Engine>>>,
    metrics: Arc<Metrics>,
    sink: Arc<dyn MetricsSink>,
    include_regex: Regex,
    exclude_regex: Regex,
}

impl Pipeline {
    pub fn new(
        settings: Arc<Settings>,
        decoder: Arc<dyn EventDecoder>,
        store: Arc<dyn ObjectStore>,
        config: Arc<ConfigStore<Arc<Engine>>>,
        metrics: Arc<Metrics>,
        sink: Arc<dyn MetricsSink>,
    ) -> Self {
        let include_regex = Regex::new(&settings.source.include_key_regex).unwrap_or_else(|e| {
            panic!(
                "invalid source.include_key_regex {:?}: {e}",
                settings.source.include_key_regex
            )
        });
        let exclude_regex = Regex::new(&settings.source.exclude_key_regex).unwrap_or_else(|e| {
            panic!(
                "invalid source.exclude_key_regex {:?}: {e}",
                settings.source.exclude_key_regex
            )
        });
        Self {
            settings,
            decoder,
            store,
            config,
            metrics,
            sink,
            include_regex,
            exclude_regex,
        }
    }

    /// Decodes `payload`, processes every referenced object under the whole
    /// policy matrix, and emits exactly one `MetricSnapshot` (a delta since
    /// the previous call) to `sink` before returning — success or failure.
    pub async fn handle(&self, payload: &[u8]) -> Result<BatchOutcome, CoreError> {
        let result = self.handle_inner(payload).await;
        let snapshot = self.metrics.snapshot_and_reset();
        self.sink.emit(&snapshot);
        result
    }

    async fn handle_inner(&self, payload: &[u8]) -> Result<BatchOutcome, CoreError> {
        let items: Vec<SourceItem> = self.decoder.decode(payload)?;

        let engine = self.config.get().await;
        if engine.is_none() && self.settings.behavior.on_config_error == OnConfigError::Closed {
            return Err(CoreError::Config(crate::error::ConfigError::Source(
                "no compiled ruleset is cached and on_config_error is 'closed'".to_string(),
            )));
        }

        let mut failed_ack_ids = Vec::new();

        for item in &items {
            let mut item_failed = false;

            for object in &item.objects {
                if !self.key_allowed(&object.key) {
                    continue;
                }

                let dest_bucket = self.settings.destination.bucket.clone();
                let dest_key = format!("{}{}", self.settings.destination.key_prefix, object.key);

                if dest_bucket == object.bucket && dest_key == object.key {
                    return Err(CoreError::SelfTrigger {
                        dest_bucket,
                        dest_key,
                    });
                }

                let outcome = match &engine {
                    Some(engine) => {
                        self.process_object(engine, object, &dest_bucket, &dest_key)
                            .await
                    }
                    // Only reachable when on_config_error == open (closed
                    // already returned above): raw byte copy, bypassing
                    // decompress/parse/size checks entirely.
                    None => self.raw_copy(object, &dest_bucket, &dest_key).await,
                };

                if let Err(e) = outcome {
                    if self.settings.behavior.partial_batch_failures && item.ack_id.is_some() {
                        item_failed = true;
                        break;
                    }
                    return Err(e);
                }
            }

            if item_failed && let Some(id) = &item.ack_id {
                failed_ack_ids.push(id.clone());
            }
        }

        Ok(BatchOutcome { failed_ack_ids })
    }

    fn key_allowed(&self, key: &str) -> bool {
        self.include_regex.is_match(key) && !self.exclude_regex.is_match(key)
    }

    fn select_mode(&self, size: Option<u64>) -> ObjectMode {
        match self.settings.processing.mode {
            ProcessingMode::Buffer => ObjectMode::Buffer,
            ProcessingMode::Stream => ObjectMode::Stream,
            ProcessingMode::Auto => match size {
                Some(sz) if sz > self.settings.processing.stream_threshold_bytes => {
                    ObjectMode::Stream
                }
                _ => ObjectMode::Buffer,
            },
        }
    }

    /// Fetches `bucket`/`key`, dispatching `on_missing_object` on
    /// `StoreError::NotFound`. `Ok(None)` means the caller should treat the
    /// object as handled (skipped) with nothing further to do.
    async fn fetch_with_missing_policy(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<Bytes>, CoreError> {
        match self.store.get(bucket, key).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(StoreError::NotFound { .. }) => match self.settings.behavior.on_missing_object {
                OnMissingObject::Skip => {
                    self.metrics.add_objects_skipped(1);
                    Ok(None)
                }
                OnMissingObject::Error => Err(CoreError::Store(StoreError::NotFound {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                })),
            },
            Err(e) => Err(CoreError::Store(e)),
        }
    }

    /// `behavior.on_config_error == open` with no cached ruleset
    /// (`SHARED.md` "Fail-open scope"): a raw byte copy, no decompress, no
    /// parse, no size check.
    async fn raw_copy(
        &self,
        object: &ObjectRef,
        dest_bucket: &str,
        dest_key: &str,
    ) -> Result<(), CoreError> {
        let Some(bytes) = self
            .fetch_with_missing_policy(&object.bucket, &object.key)
            .await?
        else {
            return Ok(());
        };
        self.metrics.add_bytes_in(bytes.len() as u64);
        self.store
            .put(dest_bucket, dest_key, bytes.clone(), CANONICAL_META)
            .await?;
        self.metrics.add_bytes_out(bytes.len() as u64);
        self.metrics.add_objects_processed(1);
        Ok(())
    }

    async fn process_object(
        &self,
        engine: &Arc<Engine>,
        object: &ObjectRef,
        dest_bucket: &str,
        dest_key: &str,
    ) -> Result<(), CoreError> {
        if self.settings.behavior.dry_run {
            return self
                .process_dry_run(engine, object, dest_bucket, dest_key)
                .await;
        }

        match self.select_mode(object.size) {
            ObjectMode::Buffer => {
                self.process_buffer(engine, object, dest_bucket, dest_key)
                    .await
            }
            ObjectMode::Stream => {
                self.process_stream(engine, object, dest_bucket, dest_key)
                    .await
            }
        }
    }

    /// `behavior.dry_run`: still evaluates every record through `engine`
    /// (so `RecordsDropped`/`RuleDrops` reflect what *would* have been
    /// dropped), but always forwards the object unmodified — always buffer
    /// semantics, since dry-run's purpose is cheap evaluation, not streaming
    /// efficiency.
    async fn process_dry_run(
        &self,
        engine: &Arc<Engine>,
        object: &ObjectRef,
        dest_bucket: &str,
        dest_key: &str,
    ) -> Result<(), CoreError> {
        let Some(bytes) = self
            .fetch_with_missing_policy(&object.bucket, &object.key)
            .await?
        else {
            return Ok(());
        };
        self.metrics.add_bytes_in(bytes.len() as u64);

        // Side effect only: updates RecordsIn/RecordsKept/RecordsDropped/
        // RuleDrops via `metrics`. The `Outcome` itself is discarded — the
        // written bytes are always the untouched original.
        buffer_run(&bytes, engine, &self.settings.processing, &self.metrics)?;

        self.store
            .put(dest_bucket, dest_key, bytes.clone(), CANONICAL_META)
            .await?;
        self.metrics.add_bytes_out(bytes.len() as u64);
        self.metrics.add_objects_processed(1);
        Ok(())
    }

    async fn process_buffer(
        &self,
        engine: &Arc<Engine>,
        object: &ObjectRef,
        dest_bucket: &str,
        dest_key: &str,
    ) -> Result<(), CoreError> {
        let Some(bytes) = self
            .fetch_with_missing_policy(&object.bucket, &object.key)
            .await?
        else {
            return Ok(());
        };
        self.metrics.add_bytes_in(bytes.len() as u64);

        let outcome = buffer_run(&bytes, engine, &self.settings.processing, &self.metrics)?;

        match outcome {
            Outcome::Written(Some(out_bytes)) => {
                self.metrics.add_bytes_out(out_bytes.len() as u64);
                self.store
                    .put(dest_bucket, dest_key, out_bytes, CANONICAL_META)
                    .await?;
            }
            Outcome::NothingKept => {
                // Zero empty writes (SHARED.md): nothing to put.
            }
            Outcome::Unrecognized => {
                self.metrics.add_unrecognized_objects(1);
                self.apply_unrecognized_policy(object, dest_bucket, dest_key, bytes)
                    .await?;
            }
            Outcome::Written(None) => unreachable!("buffer_run always returns Written(Some(_))"),
        }

        self.metrics.add_objects_processed(1);
        Ok(())
    }

    async fn process_stream(
        &self,
        engine: &Arc<Engine>,
        object: &ObjectRef,
        dest_bucket: &str,
        dest_key: &str,
    ) -> Result<(), CoreError> {
        let reader = match self.store.get_stream(&object.bucket, &object.key).await {
            Ok(r) => r,
            Err(StoreError::NotFound { .. }) => {
                return match self.settings.behavior.on_missing_object {
                    OnMissingObject::Skip => {
                        self.metrics.add_objects_skipped(1);
                        Ok(())
                    }
                    OnMissingObject::Error => Err(CoreError::Store(StoreError::NotFound {
                        bucket: object.bucket.clone(),
                        key: object.key.clone(),
                    })),
                };
            }
            Err(e) => return Err(CoreError::Store(e)),
        };

        let outcome = stream_run(
            reader,
            engine,
            &self.settings.processing,
            &self.metrics,
            self.store.as_ref(),
            dest_bucket,
            dest_key,
        )
        .await?;

        match outcome {
            Outcome::Written(None) => {
                // Already written via put_stream.
            }
            Outcome::NothingKept => {
                // stream_run aborted the upload: nothing left at dest_key.
            }
            Outcome::Unrecognized => {
                self.metrics.add_unrecognized_objects(1);
                // stream_run already aborted the in-flight upload
                // (SHARED.md "Unrecognized objects in stream mode"); apply
                // the policy by re-fetching (a second `get`) and raw-copying.
                let Some(bytes) = self
                    .fetch_with_missing_policy(&object.bucket, &object.key)
                    .await?
                else {
                    return Ok(());
                };
                self.apply_unrecognized_policy(object, dest_bucket, dest_key, bytes)
                    .await?;
            }
            Outcome::Written(Some(_)) => {
                unreachable!("stream_run never returns Written(Some(_))")
            }
        }

        self.metrics.add_objects_processed(1);
        Ok(())
    }

    /// Applies `behavior.on_unrecognized_object` given the object's already
    /// -fetched raw `bytes` (buffer mode already has them; stream mode
    /// re-fetches them before calling this).
    async fn apply_unrecognized_policy(
        &self,
        object: &ObjectRef,
        dest_bucket: &str,
        dest_key: &str,
        bytes: Bytes,
    ) -> Result<(), CoreError> {
        match self.settings.behavior.on_unrecognized_object {
            OnUnrecognizedObject::Copy => {
                self.metrics.add_bytes_out(bytes.len() as u64);
                self.store
                    .put(dest_bucket, dest_key, bytes, CANONICAL_META)
                    .await?;
                Ok(())
            }
            OnUnrecognizedObject::Skip => Ok(()),
            OnUnrecognizedObject::Error => Err(CoreError::UnrecognizedObject {
                bucket: object.bucket.clone(),
                key: object.key.clone(),
            }),
        }
    }
}

#[cfg(all(test, feature = "testing"))]
mod tests {
    use super::*;
    use crate::config::rules::RuleSet;
    use crate::config::store::Compile;
    use crate::config::{Behavior, Destination, Observability, Processing, Rules, Source, Sqs};
    use crate::error::DecodeError;
    use crate::model::VersionTag;
    use crate::testing::{InMemoryStore, RecordingSink, StaticConfigSource};
    use flate2::Compression;
    use flate2::read::MultiGzDecoder;
    use flate2::write::GzEncoder;
    use std::io::{Read, Write};
    use std::time::Duration;

    fn gzip_bytes(body: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::new(6));
        encoder.write_all(body).unwrap();
        encoder.finish().unwrap()
    }

    fn gunzip(input: &[u8]) -> Vec<u8> {
        let mut decoder = MultiGzDecoder::new(input);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).unwrap();
        out
    }

    /// A trivial `EventDecoder` test double that ignores `payload` entirely
    /// and always returns a fixed set of `SourceItem`s — lets a test drive
    /// `Pipeline::handle` with arbitrary items without needing a real event
    /// envelope.
    struct StubDecoder(Vec<SourceItem>);

    impl EventDecoder for StubDecoder {
        fn decode(&self, _payload: &[u8]) -> Result<Vec<SourceItem>, DecodeError> {
            Ok(self.0.clone())
        }
    }

    fn base_settings() -> Settings {
        Settings {
            source: Source::default(),
            destination: Destination {
                bucket: "dest-bucket".to_string(),
                key_prefix: String::new(),
            },
            processing: Processing::default(),
            behavior: Behavior::default(),
            sqs: Sqs::default(),
            rules: Rules::default(),
            observability: Observability::default(),
        }
    }

    fn no_op_rules() -> &'static [u8] {
        b"version: 1.0.0\nrules: []\n"
    }

    fn drop_decrypt_rules() -> &'static [u8] {
        br#"
version: 1.0.0
rules:
  - name: Drop Decrypt
    matches:
      - field_name: eventName
        regex: "^Decrypt$"
"#
    }

    fn compile_engine() -> Compile<Arc<Engine>> {
        Arc::new(|b: &[u8]| Ok(Arc::new(Engine::new(RuleSet::parse(b)?)?)))
    }

    /// Builds a `ConfigStore<Arc<Engine>>` pre-seeded with `rules_yaml`,
    /// sharing `metrics` with the `Pipeline` under test so a single
    /// `RecordingSink` line reflects both.
    fn config_store(
        rules_yaml: &[u8],
        metrics: Arc<Metrics>,
    ) -> (Arc<ConfigStore<Arc<Engine>>>, Arc<StaticConfigSource>) {
        let src = Arc::new(StaticConfigSource::new(
            rules_yaml.to_vec(),
            VersionTag::Version(1),
        ));
        let store = Arc::new(ConfigStore::new(
            src.clone(),
            Duration::from_secs(300),
            compile_engine(),
            metrics,
        ));
        (store, src)
    }

    fn object(bucket: &str, key: &str, size: Option<u64>) -> ObjectRef {
        ObjectRef {
            bucket: bucket.to_string(),
            key: key.to_string(),
            size,
        }
    }

    fn item(ack_id: Option<&str>, objects: Vec<ObjectRef>) -> SourceItem {
        SourceItem {
            ack_id: ack_id.map(str::to_string),
            objects,
        }
    }

    fn cloudtrail_body(event_names: &[&str]) -> Vec<u8> {
        let records: Vec<String> = event_names
            .iter()
            .map(|n| format!(r#"{{"eventName":"{n}","eventSource":"signin.amazonaws.com"}}"#))
            .collect();
        format!(r#"{{"Records":[{}]}}"#, records.join(",")).into_bytes()
    }

    #[tokio::test]
    async fn excluded_key_is_filtered_before_any_get() {
        let store = Arc::new(InMemoryStore::new());
        // Seed the object anyway: if the pipeline fetched it despite the
        // exclude filter, this test would not catch a missing-object bug
        // masking a real key-filter bug.
        store.seed(
            "src-bucket",
            "logs/CloudTrail-Digest/file.json.gz",
            gzip_bytes(b"{}"),
        );

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            Some("ack-1"),
            vec![object(
                "src-bucket",
                "logs/CloudTrail-Digest/file.json.gz",
                None,
            )],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let pipeline = Pipeline::new(
            Arc::new(base_settings()),
            decoder,
            store.clone(),
            config,
            metrics,
            sink,
        );

        let outcome = pipeline.handle(b"{}").await.expect("must succeed");
        assert!(outcome.failed_ack_ids.is_empty());
        assert_eq!(
            store.read_calls(),
            0,
            "an excluded key must never be fetched"
        );
    }

    #[tokio::test]
    async fn self_trigger_guard_errors_when_dest_equals_source() {
        let store = Arc::new(InMemoryStore::new());
        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object("dest-bucket", "some/file.json.gz", None)],
        )]));
        let sink = Arc::new(RecordingSink::new());

        // key_prefix is "" and destination.bucket == the source bucket, so
        // dest == source for this object.
        let pipeline = Pipeline::new(
            Arc::new(base_settings()),
            decoder,
            store,
            config,
            metrics,
            sink,
        );

        let err = pipeline
            .handle(b"{}")
            .await
            .expect_err("dest == source must be an error");
        assert!(matches!(err, CoreError::SelfTrigger { .. }), "got {err:?}");
    }

    #[tokio::test]
    async fn absent_size_selects_buffer_mode() {
        let store = Arc::new(InMemoryStore::new());
        let body = gzip_bytes(&cloudtrail_body(&["ConsoleLogin"]));
        store.seed("src-bucket", "file.json.gz", body.clone());

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object("src-bucket", "file.json.gz", None)],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let pipeline = Pipeline::new(
            Arc::new(base_settings()),
            decoder,
            store.clone(),
            config,
            metrics,
            sink,
        );

        pipeline.handle(b"{}").await.expect("must succeed");
        assert_eq!(
            store.put_stream_progress(),
            0,
            "absent size must select buffer mode (put, not put_stream)"
        );
        let written = store
            .object("dest-bucket", "file.json.gz")
            .expect("must have written the destination");
        assert_eq!(gunzip(&written), gunzip(&body));
    }

    #[tokio::test]
    async fn size_above_threshold_selects_stream_mode() {
        let store = Arc::new(InMemoryStore::new());
        let body = gzip_bytes(&cloudtrail_body(&["ConsoleLogin"]));
        store.seed("src-bucket", "file.json.gz", body.clone());

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object(
                "src-bucket",
                "file.json.gz",
                Some(9_000_000), // > default 8_388_608 stream_threshold_bytes
            )],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let pipeline = Pipeline::new(
            Arc::new(base_settings()),
            decoder,
            store.clone(),
            config,
            metrics,
            sink,
        );

        pipeline.handle(b"{}").await.expect("must succeed");
        assert!(
            store.put_stream_progress() > 0,
            "size above stream_threshold_bytes must select stream mode (put_stream)"
        );
        let written = store
            .object("dest-bucket", "file.json.gz")
            .expect("must have written the destination");
        assert_eq!(gunzip(&written), gunzip(&body));
    }

    #[tokio::test]
    async fn dry_run_forwards_everything_but_still_counts_drops() {
        let store = Arc::new(InMemoryStore::new());
        let body = gzip_bytes(&cloudtrail_body(&["ConsoleLogin", "Decrypt", "AssumeRole"]));
        store.seed("src-bucket", "file.json.gz", body.clone());

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(drop_decrypt_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object("src-bucket", "file.json.gz", None)],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let mut settings = base_settings();
        settings.behavior.dry_run = true;

        let pipeline = Pipeline::new(
            Arc::new(settings),
            decoder,
            store.clone(),
            config,
            metrics,
            sink.clone(),
        );

        pipeline.handle(b"{}").await.expect("must succeed");

        let written = store
            .object("dest-bucket", "file.json.gz")
            .expect("dry_run must still forward the object");
        assert_eq!(
            gunzip(&written),
            gunzip(&body),
            "dry_run must forward the object completely unfiltered"
        );

        let snapshots = sink.snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(
            snapshots[0].records_dropped, 1,
            "dry_run must still count what would have been dropped"
        );
        assert_eq!(snapshots[0].records_kept, 2);
    }

    #[tokio::test]
    async fn all_records_dropped_in_buffer_mode_writes_nothing() {
        let store = Arc::new(InMemoryStore::new());
        let body = gzip_bytes(&cloudtrail_body(&["Decrypt", "Decrypt"]));
        store.seed("src-bucket", "file.json.gz", body);

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(drop_decrypt_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object("src-bucket", "file.json.gz", None)],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let pipeline = Pipeline::new(
            Arc::new(base_settings()),
            decoder,
            store.clone(),
            config,
            metrics,
            sink,
        );

        pipeline.handle(b"{}").await.expect("must succeed");
        assert!(
            !store.contains("dest-bucket", "file.json.gz"),
            "all-dropped must result in zero empty writes"
        );
    }

    #[tokio::test]
    async fn destination_key_is_key_prefix_plus_source_key() {
        let store = Arc::new(InMemoryStore::new());
        let body = gzip_bytes(&cloudtrail_body(&["ConsoleLogin"]));
        store.seed("src-bucket", "logs/file.json.gz", body.clone());

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object("src-bucket", "logs/file.json.gz", None)],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let mut settings = base_settings();
        settings.destination.key_prefix = "archive/".to_string();

        let pipeline = Pipeline::new(
            Arc::new(settings),
            decoder,
            store.clone(),
            config,
            metrics,
            sink,
        );

        pipeline.handle(b"{}").await.expect("must succeed");
        assert!(store.contains("dest-bucket", "archive/logs/file.json.gz"));
    }

    async fn unrecognized_buffer_pipeline(
        policy: OnUnrecognizedObject,
    ) -> (Arc<InMemoryStore>, Result<BatchOutcome, CoreError>, Vec<u8>) {
        let store = Arc::new(InMemoryStore::new());
        let body = gzip_bytes(br#"{"foo":"bar"}"#);
        store.seed("src-bucket", "file.json.gz", body.clone());

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object("src-bucket", "file.json.gz", None)],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let mut settings = base_settings();
        settings.behavior.on_unrecognized_object = policy;

        let pipeline = Pipeline::new(
            Arc::new(settings),
            decoder,
            store.clone(),
            config,
            metrics,
            sink,
        );

        let result = pipeline.handle(b"{}").await;
        (store, result, body)
    }

    #[tokio::test]
    async fn on_unrecognized_object_copy_raw_copies_in_buffer_mode() {
        let (store, result, body) = unrecognized_buffer_pipeline(OnUnrecognizedObject::Copy).await;
        result.expect("copy policy must not error");
        let written = store
            .object("dest-bucket", "file.json.gz")
            .expect("copy must write the destination");
        assert_eq!(written.as_ref(), body.as_slice());
    }

    #[tokio::test]
    async fn on_unrecognized_object_skip_writes_nothing_in_buffer_mode() {
        let (store, result, _body) = unrecognized_buffer_pipeline(OnUnrecognizedObject::Skip).await;
        result.expect("skip policy must not error");
        assert!(!store.contains("dest-bucket", "file.json.gz"));
    }

    #[tokio::test]
    async fn on_unrecognized_object_error_fails_in_buffer_mode() {
        let (_store, result, _body) =
            unrecognized_buffer_pipeline(OnUnrecognizedObject::Error).await;
        let err = result.expect_err("error policy must fail");
        assert!(
            matches!(err, CoreError::UnrecognizedObject { .. }),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn stream_mode_unrecognized_refetches_and_raw_copies() {
        let store = Arc::new(InMemoryStore::new());
        let body = gzip_bytes(br#"{"foo":"bar"}"#);
        store.seed("src-bucket", "file.json.gz", body.clone());

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object(
                "src-bucket",
                "file.json.gz",
                Some(9_000_000), // forces stream mode
            )],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let mut settings = base_settings();
        settings.behavior.on_unrecognized_object = OnUnrecognizedObject::Copy;

        let pipeline = Pipeline::new(
            Arc::new(settings),
            decoder,
            store.clone(),
            config,
            metrics,
            sink,
        );

        pipeline.handle(b"{}").await.expect("must succeed");

        assert_eq!(
            store.read_calls(),
            2,
            "stream mode's Unrecognized path costs exactly two store reads: the initial \
             get_stream and the re-fetch raw copy"
        );
        let written = store
            .object("dest-bucket", "file.json.gz")
            .expect("must have raw-copied the object");
        assert_eq!(written.as_ref(), body.as_slice());
    }

    #[tokio::test]
    async fn on_missing_object_error_fails() {
        let store = Arc::new(InMemoryStore::new()); // nothing seeded
        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object("src-bucket", "missing.json.gz", None)],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let mut settings = base_settings();
        settings.behavior.on_missing_object = OnMissingObject::Error;

        let pipeline = Pipeline::new(Arc::new(settings), decoder, store, config, metrics, sink);

        let err = pipeline
            .handle(b"{}")
            .await
            .expect_err("missing object with on_missing_object=error must fail");
        assert!(
            matches!(err, CoreError::Store(StoreError::NotFound { .. })),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn on_missing_object_skip_succeeds_with_no_write() {
        let store = Arc::new(InMemoryStore::new()); // nothing seeded
        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object("src-bucket", "missing.json.gz", None)],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let mut settings = base_settings();
        settings.behavior.on_missing_object = OnMissingObject::Skip;

        let pipeline = Pipeline::new(
            Arc::new(settings),
            decoder,
            store.clone(),
            config,
            metrics,
            sink,
        );

        pipeline
            .handle(b"{}")
            .await
            .expect("missing object with on_missing_object=skip must not fail");
        assert!(!store.contains("dest-bucket", "missing.json.gz"));
    }

    #[tokio::test]
    async fn rules_load_failure_with_on_config_error_open_is_a_raw_byte_copy() {
        let store = Arc::new(InMemoryStore::new());
        // Deliberately not valid gzip/JSON: proves the passthrough truly
        // never decompresses or parses.
        let body = b"not gzip, not json, just raw bytes".to_vec();
        store.seed("src-bucket", "file.json.gz", body.clone());

        let metrics = Arc::new(Metrics::default());
        let (config, src) = config_store(no_op_rules(), metrics.clone());
        src.fail_next_fetch(); // ensure the ConfigStore never successfully loads
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object("src-bucket", "file.json.gz", None)],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let mut settings = base_settings();
        settings.behavior.on_config_error = OnConfigError::Open;

        let pipeline = Pipeline::new(
            Arc::new(settings),
            decoder,
            store.clone(),
            config,
            metrics,
            sink,
        );

        pipeline.handle(b"{}").await.expect("open must not fail");
        let written = store
            .object("dest-bucket", "file.json.gz")
            .expect("fail-open must still write a raw copy");
        assert_eq!(
            written.as_ref(),
            body.as_slice(),
            "fail-open passthrough must be byte-for-byte identical to the source, un-decompressed"
        );
    }

    #[tokio::test]
    async fn rules_load_failure_with_on_config_error_closed_is_an_error() {
        let store = Arc::new(InMemoryStore::new());
        store.seed("src-bucket", "file.json.gz", gzip_bytes(b"{}"));

        let metrics = Arc::new(Metrics::default());
        let (config, src) = config_store(no_op_rules(), metrics.clone());
        src.fail_next_fetch();
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object("src-bucket", "file.json.gz", None)],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let mut settings = base_settings();
        settings.behavior.on_config_error = OnConfigError::Closed;

        let pipeline = Pipeline::new(
            Arc::new(settings),
            decoder,
            store.clone(),
            config,
            metrics,
            sink,
        );

        let err = pipeline
            .handle(b"{}")
            .await
            .expect_err("closed with no cached ruleset must fail");
        assert!(matches!(err, CoreError::Config(_)), "got {err:?}");
        assert!(
            !store.contains("dest-bucket", "file.json.gz"),
            "closed must never write anything"
        );
    }

    #[tokio::test]
    async fn one_failing_source_item_collects_its_ack_id_without_failing_siblings() {
        let store = Arc::new(InMemoryStore::new());
        let good_body = gzip_bytes(&cloudtrail_body(&["ConsoleLogin"]));
        store.seed("src-bucket", "good.json.gz", good_body.clone());
        // "bad.json.gz" is deliberately not seeded: on_missing_object=error.

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![
            item(
                Some("failing-ack"),
                vec![object("src-bucket", "bad.json.gz", None)],
            ),
            item(
                Some("succeeding-ack"),
                vec![object("src-bucket", "good.json.gz", None)],
            ),
        ]));
        let sink = Arc::new(RecordingSink::new());

        let mut settings = base_settings();
        settings.behavior.on_missing_object = OnMissingObject::Error;
        settings.behavior.partial_batch_failures = true;

        let pipeline = Pipeline::new(
            Arc::new(settings),
            decoder,
            store.clone(),
            config,
            metrics,
            sink,
        );

        let outcome = pipeline.handle(b"{}").await.expect(
            "partial_batch_failures=true must not fail the whole batch on one item's failure",
        );
        assert_eq!(outcome.failed_ack_ids, vec!["failing-ack".to_string()]);
        assert!(
            store.contains("dest-bucket", "good.json.gz"),
            "the sibling item must still have been processed"
        );
    }

    #[tokio::test]
    async fn partial_batch_failures_false_converts_any_failure_into_a_whole_batch_err() {
        let store = Arc::new(InMemoryStore::new());
        let good_body = gzip_bytes(&cloudtrail_body(&["ConsoleLogin"]));
        store.seed("src-bucket", "good.json.gz", good_body);
        // "bad.json.gz" is deliberately not seeded.

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![
            item(
                Some("failing-ack"),
                vec![object("src-bucket", "bad.json.gz", None)],
            ),
            item(
                Some("succeeding-ack"),
                vec![object("src-bucket", "good.json.gz", None)],
            ),
        ]));
        let sink = Arc::new(RecordingSink::new());

        let mut settings = base_settings();
        settings.behavior.on_missing_object = OnMissingObject::Error;
        settings.behavior.partial_batch_failures = false;

        let pipeline = Pipeline::new(Arc::new(settings), decoder, store, config, metrics, sink);

        let err = pipeline
            .handle(b"{}")
            .await
            .expect_err("partial_batch_failures=false must fail the whole batch");
        assert!(matches!(err, CoreError::Store(StoreError::NotFound { .. })));
    }

    #[tokio::test]
    async fn snapshot_and_reset_emits_a_delta_not_a_running_total_across_invocations() {
        let store = Arc::new(InMemoryStore::new());
        let body = gzip_bytes(&cloudtrail_body(&["ConsoleLogin", "AssumeRole"]));
        store.seed("src-bucket", "file.json.gz", body);

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object("src-bucket", "file.json.gz", None)],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let pipeline = Pipeline::new(
            Arc::new(base_settings()),
            decoder,
            store,
            config,
            metrics,
            sink.clone(),
        );

        pipeline
            .handle(b"{}")
            .await
            .expect("first call must succeed");
        pipeline
            .handle(b"{}")
            .await
            .expect("second call must succeed");

        let snapshots = sink.snapshots();
        assert_eq!(snapshots.len(), 2);
        assert_eq!(snapshots[0].records_in, 2);
        assert_eq!(
            snapshots[1].records_in, 2,
            "the second invocation's RecordsIn must be that invocation's own count, not \
             cumulative across both calls"
        );
    }
}
