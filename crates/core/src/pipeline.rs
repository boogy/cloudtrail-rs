//! `Pipeline`: wires the four ports together and owns the policy matrix
//! (safety invariants + `behavior.*`) over `process::{buffer_run, stream_run}`.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

use crate::config::settings::{
    KeyFilter, OnConfigError, OnMissingObject, OnUnrecognizedObject, ProcessingMode,
};
use crate::config::{ConfigStore, Settings};
use crate::error::{CoreError, DecodeError, StoreError};
use crate::filter::Engine;
use crate::metrics::Metrics;
use crate::model::{ObjectRef, PutMeta, SourceItem};
use crate::ports::{EventDecoder, MetricsSink, ObjectStore};
use crate::process::{DiscardStore, Outcome, buffer_run, stream_run};

/// Metadata for every write this module performs, so the destination bucket is
/// uniform regardless of which path wrote a given object.
const CANONICAL_META: PutMeta = PutMeta {
    content_type: "application/x-gzip",
    content_encoding: "gzip",
};

/// Which `SourceItem::ack_id`s failed, for SQS `ReportBatchItemFailures`.
/// Empty when every item succeeded, or when the topology has no ack ids.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BatchOutcome {
    pub failed_ack_ids: Vec<String>,
}

/// Processing strategy for an object: `processing.mode`, or for `auto` the
/// object size vs. `stream_threshold_bytes` (a missing size picks buffer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObjectMode {
    Buffer,
    Stream,
}

/// Whether a streaming copy bills the bytes it reads to `BytesIn`, or an
/// earlier read of the same object already did. `BytesIn` counts compressed
/// source bytes once per object per invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BytesInPolicy {
    Count,
    AlreadyCounted,
}

/// Wraps a source reader so a streaming copy bills `BytesIn` as it reads, and
/// records the running total for `BytesOut` — which the caller must read only
/// after `put_stream` returns `Ok`. `metrics` is `None` when the caller has
/// already billed these bytes.
struct CountingReader {
    inner: Box<dyn AsyncRead + Send + Unpin>,
    total: Arc<AtomicU64>,
    metrics: Option<Arc<Metrics>>,
}

impl AsyncRead for CountingReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &polled {
            let n = (buf.filled().len() - before) as u64;
            if n > 0 {
                self.total.fetch_add(n, Ordering::Relaxed);
                if let Some(metrics) = &self.metrics {
                    metrics.add_bytes_in(n);
                }
            }
        }
        polled
    }
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
    key_filter: KeyFilter,
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
        // Unreachable in production: `Settings::from_parts` compiles the same
        // `KeyFilter` at load time and refuses to return a `Settings` if it fails.
        let key_filter = KeyFilter::compile(&settings.source).unwrap_or_else(|e| panic!("{e}"));
        Self {
            settings,
            decoder,
            store,
            config,
            metrics,
            sink,
            key_filter,
        }
    }

    /// Decodes `payload`, processes every referenced object, and emits exactly
    /// one `MetricSnapshot` delta to `sink` before returning.
    pub async fn handle(&self, payload: &[u8]) -> Result<BatchOutcome, CoreError> {
        let result = self.handle_inner(payload).await;
        let snapshot = self.metrics.snapshot_and_reset();
        self.sink.emit(&snapshot);
        result
    }

    async fn handle_inner(&self, payload: &[u8]) -> Result<BatchOutcome, CoreError> {
        // Counted here as well as per-item below, so `DecodeErrors` means "a
        // decode failed", full stop — a whole-payload failure moved no counter.
        let items: Vec<SourceItem> = self.decoder.decode(payload).inspect_err(|_| {
            self.metrics.add_decode_errors(1);
        })?;

        let engine = self.config.get().await;
        if engine.is_none() && self.settings.behavior.on_config_error == OnConfigError::Closed {
            return Err(CoreError::Config(crate::error::ConfigError::Source(
                "no compiled ruleset is cached and on_config_error is 'closed'".to_string(),
            )));
        }

        let mut failed_ack_ids = Vec::new();

        for item in &items {
            if let Some(msg) = &item.decode_error {
                self.metrics.add_decode_errors(1);
                tracing::error!(ack_id = ?item.ack_id, error = %msg, "message body failed to decode");

                if self.settings.behavior.partial_batch_failures && item.ack_id.is_some() {
                    // Isolate to this message: it is redriven and retried
                    // instead of being deleted with its object unprocessed.
                    if let Some(id) = &item.ack_id {
                        failed_ack_ids.push(id.clone());
                    }
                    continue;
                }
                return Err(CoreError::Decode(DecodeError::InvalidPayload(msg.clone())));
            }

            if item.objects.is_empty() {
                self.metrics.add_items_without_objects(1);
            }

            let mut item_failed = false;

            for object in &item.objects {
                if !self.key_allowed(&object.key) {
                    // Counted: a wrong include/exclude key regex otherwise
                    // looks identical in metrics to receiving no traffic at all.
                    self.metrics.add_objects_excluded_by_key(1);
                    tracing::debug!(
                        bucket = %object.bucket,
                        key = %object.key,
                        "object excluded by the source key filter"
                    );
                    continue;
                }

                let dest_bucket = self.settings.destination.bucket.clone();
                let key_prefix = &self.settings.destination.key_prefix;
                let dest_key = format!("{key_prefix}{}", object.key);

                // Exact match catches the trivial loop; the prefix test catches
                // same-bucket output being read back in, where no single
                // (bucket, key) pair ever matches.
                let reading_own_output =
                    !key_prefix.is_empty() && object.key.starts_with(key_prefix.as_str());
                if dest_bucket == object.bucket && (dest_key == object.key || reading_own_output) {
                    // Hard `Err`, deliberately not isolated per-message: a
                    // self-trigger is a misconfiguration that hits every object,
                    // and failing loudly is the only thing that stops the loop.
                    self.metrics.add_objects_failed(1);
                    tracing::error!(
                        bucket = %object.bucket,
                        key = %object.key,
                        %dest_bucket,
                        %dest_key,
                        "self-trigger: the destination is the source; refusing to loop"
                    );
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
                    // on_config_error == open: raw byte copy, no decompress,
                    // parse or size check.
                    None => self.raw_copy(object, &dest_bucket, &dest_key).await,
                };

                if let Err(e) = outcome {
                    // The only counter that moves under partial_batch_failures,
                    // where the handler returns `Ok` and AWS `Errors` stays zero.
                    self.metrics.add_objects_failed(1);

                    if self.settings.behavior.partial_batch_failures && item.ack_id.is_some() {
                        // Fail the message but keep going: the poison pill
                        // fails first on every redelivery too, so stopping here
                        // means its siblings are never attempted once. Writes
                        // are idempotent, so re-processing them is safe.
                        tracing::error!(
                            ack_id = ?item.ack_id,
                            bucket = %object.bucket,
                            key = %object.key,
                            error = %e,
                            "object failed; message will be re-driven"
                        );
                        item_failed = true;
                    } else {
                        return Err(e);
                    }
                }
            }

            if item_failed && let Some(id) = &item.ack_id {
                failed_ack_ids.push(id.clone());
            }
        }

        Ok(BatchOutcome { failed_ack_ids })
    }

    fn key_allowed(&self, key: &str) -> bool {
        self.key_filter.allows(key)
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

    /// Opens `bucket`/`key` as a stream, dispatching `on_missing_object` on
    /// `NotFound`. `Ok(None)` means the object was skipped; nothing further.
    async fn open_with_missing_policy(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<Box<dyn AsyncRead + Send + Unpin>>, CoreError> {
        match self.store.get_stream(bucket, key).await {
            Ok(reader) => Ok(Some(reader)),
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

    /// Fetches `bucket`/`key` fully into memory, bounded by `max_object_bytes`.
    ///
    /// The compressed read is capped at the same limit as the decompressed body:
    /// gzip output is never meaningfully larger than its input, so nothing that
    /// would have survived is rejected, and the `ObjectTooLarge` it raises is the
    /// one `auto` mode already retries through stream mode.
    async fn fetch_with_missing_policy(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<Bytes>, CoreError> {
        let Some(reader) = self.open_with_missing_policy(bucket, key).await? else {
            return Ok(None);
        };

        let limit = self.settings.processing.max_object_bytes;
        // One byte past the cap, so exceeding it is detectable. Saturating:
        // at `limit == u64::MAX` a wrapping `+ 1` would `take(0)`.
        let mut buf = Vec::new();
        reader
            .take(limit.saturating_add(1))
            .read_to_end(&mut buf)
            .await
            .map_err(|e| {
                CoreError::Store(StoreError::Backend(format!("reading {bucket}/{key}: {e}")))
            })?;
        if buf.len() as u64 > limit {
            return Err(CoreError::ObjectTooLarge { limit });
        }

        Ok(Some(Bytes::from(buf)))
    }

    /// Copies `object` to `dest_key` without materializing it: peak memory is
    /// one multipart part. `Ok(false)` means a missing source under `skip`.
    async fn stream_copy(
        &self,
        object: &ObjectRef,
        dest_bucket: &str,
        dest_key: &str,
        count_bytes_in: BytesInPolicy,
    ) -> Result<bool, CoreError> {
        let Some(reader) = self
            .open_with_missing_policy(&object.bucket, &object.key)
            .await?
        else {
            return Ok(false);
        };

        let total = Arc::new(AtomicU64::new(0));
        let counting = CountingReader {
            inner: reader,
            total: Arc::clone(&total),
            metrics: match count_bytes_in {
                BytesInPolicy::Count => Some(Arc::clone(&self.metrics)),
                BytesInPolicy::AlreadyCounted => None,
            },
        };

        self.store
            .put_stream(dest_bucket, dest_key, Box::new(counting), CANONICAL_META)
            .await?;

        // Only now have the bytes landed: a failed `put_stream` aborts the
        // upload and returns above, billing none.
        self.metrics.add_bytes_out(total.load(Ordering::Relaxed));
        Ok(true)
    }

    /// Fail-open raw byte copy for `on_config_error == open` with no cached
    /// ruleset: no decompress, no parse, no size check. Streamed, so a degraded
    /// rules fetch cannot turn a large object into an OOM.
    async fn raw_copy(
        &self,
        object: &ObjectRef,
        dest_bucket: &str,
        dest_key: &str,
    ) -> Result<(), CoreError> {
        // First and only read of this object in this invocation, so it bills
        // its own `BytesIn`.
        if self
            .stream_copy(object, dest_bucket, dest_key, BytesInPolicy::Count)
            .await?
        {
            self.metrics.add_objects_processed(1);
        }
        Ok(())
    }

    async fn process_object(
        &self,
        engine: &Arc<Engine>,
        object: &ObjectRef,
        dest_bucket: &str,
        dest_key: &str,
    ) -> Result<(), CoreError> {
        // `dry_run` selects the destination, not the mode: routing it through
        // the same `select_mode` and retry keeps its verdict equal to the live
        // run's.
        let dry_run = self.settings.behavior.dry_run;

        match self.select_mode(object.size) {
            ObjectMode::Buffer => {
                let result = if dry_run {
                    self.process_dry_run(engine, object).await
                } else {
                    self.process_buffer(engine, object, dest_bucket, dest_key)
                        .await
                };
                match result {
                    // Auto picked Buffer off a *compressed*-size estimate; the
                    // decompressed body can still blow `max_object_bytes`, and
                    // without this retry that object is a permanent poison pill.
                    // Explicit `mode: buffer` opted out of stream mode, so
                    // ObjectTooLarge must still surface there.
                    Err(CoreError::ObjectTooLarge { limit })
                        if self.settings.processing.mode == ProcessingMode::Auto =>
                    {
                        tracing::warn!(
                            bucket = %object.bucket,
                            key = %object.key,
                            limit,
                            dry_run,
                            "buffer mode exceeded max_object_bytes in auto mode; retrying via \
                             stream mode (bounded memory, no size cap)"
                        );
                        if dry_run {
                            self.process_dry_run_stream(engine, object).await
                        } else {
                            self.process_stream(engine, object, dest_bucket, dest_key)
                                .await
                        }
                    }
                    other => other,
                }
            }
            ObjectMode::Stream => {
                if dry_run {
                    self.process_dry_run_stream(engine, object).await
                } else {
                    self.process_stream(engine, object, dest_bucket, dest_key)
                        .await
                }
            }
        }
    }

    /// `behavior.dry_run` in buffer mode: every record is still evaluated so the
    /// counters report what would be filtered, but nothing is ever written.
    async fn process_dry_run(
        &self,
        engine: &Arc<Engine>,
        object: &ObjectRef,
    ) -> Result<(), CoreError> {
        let Some(bytes) = self
            .fetch_with_missing_policy(&object.bucket, &object.key)
            .await?
        else {
            return Ok(());
        };
        let result = buffer_run(&bytes, engine, &self.settings.processing);

        // Auto mode's `ObjectTooLarge` retry counts its own bytes; billing here
        // too would report the preview ingesting the object twice.
        let retried_via_stream = matches!(result, Err(CoreError::ObjectTooLarge { .. }))
            && self.settings.processing.mode == ProcessingMode::Auto;
        if !retried_via_stream {
            self.metrics.add_bytes_in(bytes.len() as u64);
        }

        // Evaluation only, but the `Outcome` is still classified: previewing
        // `UnrecognizedObjects` is what dry run is for.
        let (outcome, tally) = result?;
        if matches!(outcome, Outcome::Unrecognized) {
            self.metrics.add_unrecognized_objects(1);
        }
        // Dry run writes nothing, so there is no write to wait on: the
        // object's fate is decided the moment `buffer_run` returns.
        tally.commit(&self.metrics, engine);

        self.metrics.add_objects_processed(1);
        Ok(())
    }

    /// `behavior.dry_run` in stream mode: the real `stream_run` pointed at a
    /// [`DiscardStore`], so the preview executes the code the live run runs.
    /// It publishes to a scratch `Metrics`; all but `BytesOut` is folded back.
    async fn process_dry_run_stream(
        &self,
        engine: &Arc<Engine>,
        object: &ObjectRef,
    ) -> Result<(), CoreError> {
        let Some(reader) = self
            .open_with_missing_policy(&object.bucket, &object.key)
            .await?
        else {
            return Ok(());
        };

        let scratch = Metrics::default();
        let outcome = stream_run(
            reader,
            engine,
            &self.settings.processing,
            &scratch,
            &DiscardStore,
            "",
            "",
        )
        .await;

        // Fold back before `?`: a failed object still read its bytes. Record
        // counters cannot leak — `stream_run` commits past its own upload check.
        let snapshot = scratch.snapshot_and_reset();
        self.metrics.add_bytes_in(snapshot.bytes_in);
        self.metrics.add_records_in(snapshot.records_in);
        self.metrics.add_records_kept(snapshot.records_kept);
        self.metrics.add_records_dropped(snapshot.records_dropped);
        self.metrics.add_parse_errors(snapshot.parse_errors);
        for (rule, n) in &snapshot.rule_drops {
            self.metrics.record_rule_drops(rule, *n);
        }
        // Those bytes went into `DiscardStore`; `BytesOut` means bytes that
        // reached a real destination.

        if matches!(outcome?, Outcome::Unrecognized) {
            self.metrics.add_unrecognized_objects(1);
        }

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
        let result = buffer_run(&bytes, engine, &self.settings.processing);

        // Skipped for the one case `process_object` retries through
        // `process_stream`, which counts the bytes it reads itself.
        let retried_via_stream = matches!(result, Err(CoreError::ObjectTooLarge { .. }))
            && self.settings.processing.mode == ProcessingMode::Auto;
        if !retried_via_stream {
            self.metrics.add_bytes_in(bytes.len() as u64);
        }
        let (outcome, tally) = result?;

        match outcome {
            Outcome::Written(Some(out_bytes)) => {
                // After the `put`, never before: a failed put delivered nothing.
                let out_len = out_bytes.len() as u64;
                self.store
                    .put(dest_bucket, dest_key, out_bytes, CANONICAL_META)
                    .await?;
                self.metrics.add_bytes_out(out_len);
            }
            Outcome::NothingKept => {
                // Zero empty writes: nothing to put.
            }
            Outcome::Unrecognized => {
                self.metrics.add_unrecognized_objects(1);
                self.apply_unrecognized_policy(object, dest_bucket, dest_key, bytes)
                    .await?;
            }
            Outcome::Written(None) => unreachable!("buffer_run always returns Written(Some(_))"),
        }

        // Past every `?` above, the `put` included: committing at evaluation
        // time billed records as kept for an object that never landed.
        tally.commit(&self.metrics, engine);

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
        let Some(reader) = self
            .open_with_missing_policy(&object.bucket, &object.key)
            .await?
        else {
            return Ok(());
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
                // `stream_run` aborted the in-flight upload, so `dest_key` is
                // untouched. Branch before fetching: `skip` and `error` never
                // look at the bytes, and this object took the stream path
                // precisely because it was too big to buffer.
                match self.settings.behavior.on_unrecognized_object {
                    OnUnrecognizedObject::Copy => {
                        // `stream_run` already billed these bytes to `BytesIn`;
                        // this is a second `GetObject` of the same object.
                        if !self
                            .stream_copy(
                                object,
                                dest_bucket,
                                dest_key,
                                BytesInPolicy::AlreadyCounted,
                            )
                            .await?
                        {
                            return Ok(());
                        }
                    }
                    OnUnrecognizedObject::Skip => {}
                    OnUnrecognizedObject::Error => {
                        return Err(CoreError::UnrecognizedObject {
                            bucket: object.bucket.clone(),
                            key: object.key.clone(),
                        });
                    }
                }
            }
            Outcome::Written(Some(_)) => {
                unreachable!("stream_run never returns Written(Some(_))")
            }
        }

        self.metrics.add_objects_processed(1);
        Ok(())
    }

    /// Applies `behavior.on_unrecognized_object` to already-fetched `bytes`.
    /// Buffer mode only: stream mode branches on the policy before fetching.
    async fn apply_unrecognized_policy(
        &self,
        object: &ObjectRef,
        dest_bucket: &str,
        dest_key: &str,
        bytes: Bytes,
    ) -> Result<(), CoreError> {
        match self.settings.behavior.on_unrecognized_object {
            OnUnrecognizedObject::Copy => {
                let out_len = bytes.len() as u64;
                self.store
                    .put(dest_bucket, dest_key, bytes, CANONICAL_META)
                    .await?;
                self.metrics.add_bytes_out(out_len);
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
    use async_trait::async_trait;
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

    /// `EventDecoder` double that ignores `payload` and returns fixed items.
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

    /// `ConfigStore` seeded with `rules_yaml`, sharing `metrics` with the
    /// `Pipeline` under test.
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
        SourceItem::new(ack_id.map(str::to_string), objects)
    }

    /// Like `item`, but pre-marked undecodable.
    fn undecodable_item(ack_id: Option<&str>, error: &str) -> SourceItem {
        SourceItem::undecodable(ack_id.map(str::to_string), error.to_string())
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
        // Seeded anyway, so a missing-object bug cannot masquerade as the
        // key filter working.
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
    async fn self_trigger_guard_errors_when_reading_own_output_prefix_in_same_bucket() {
        // Not an exact match — dest_key is "output/output/some-file.json.gz" —
        // but dest bucket == source bucket and the source key already lives
        // under our own output prefix, so this would loop forever.
        let store = Arc::new(InMemoryStore::new());
        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object("shared-bucket", "output/some-file.json.gz", None)],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let mut settings = base_settings();
        settings.destination.bucket = "shared-bucket".to_string();
        settings.destination.key_prefix = "output/".to_string();

        let pipeline = Pipeline::new(Arc::new(settings), decoder, store, config, metrics, sink);

        let err = pipeline.handle(b"{}").await.expect_err(
            "reading an object under our own output prefix in our own bucket must error",
        );
        assert!(matches!(err, CoreError::SelfTrigger { .. }), "got {err:?}");
    }

    #[tokio::test]
    async fn self_trigger_guard_allows_same_prefix_in_a_different_bucket() {
        // Same key_prefix shape, different destination bucket: cross-bucket is
        // never a self-trigger.
        let store = Arc::new(InMemoryStore::new());
        let body = gzip_bytes(&cloudtrail_body(&["ConsoleLogin"]));
        store.seed("other-bucket", "output/some-file.json.gz", body.clone());

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object("other-bucket", "output/some-file.json.gz", None)],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let mut settings = base_settings();
        settings.destination.bucket = "dest-bucket".to_string();
        settings.destination.key_prefix = "output/".to_string();

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
            .expect("a different destination bucket must never be treated as a self-trigger");
        assert!(store.contains("dest-bucket", "output/output/some-file.json.gz"));
    }

    #[tokio::test]
    async fn undecodable_item_with_ack_id_collects_its_ack_id_without_failing_the_batch() {
        let store = Arc::new(InMemoryStore::new());
        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![
            undecodable_item(Some("bad-ack"), "garbage message body"),
            item(
                Some("good-ack"),
                vec![object("src-bucket", "file.json.gz", None)],
            ),
        ]));
        let body = gzip_bytes(&cloudtrail_body(&["ConsoleLogin"]));
        store.seed("src-bucket", "file.json.gz", body);
        let sink = Arc::new(RecordingSink::new());

        let mut settings = base_settings();
        settings.behavior.partial_batch_failures = true;

        let pipeline = Pipeline::new(
            Arc::new(settings),
            decoder,
            store.clone(),
            config,
            metrics,
            sink,
        );

        let outcome = pipeline
            .handle(b"{}")
            .await
            .expect("an undecodable item with partial_batch_failures=true must not fail the batch");
        assert_eq!(outcome.failed_ack_ids, vec!["bad-ack".to_string()]);
        assert!(
            store.contains("dest-bucket", "file.json.gz"),
            "the sibling item must still have been processed"
        );
    }

    #[tokio::test]
    async fn undecodable_item_without_ack_id_is_a_hard_error() {
        // S3/SNS/EventBridge never set ack_id: no per-message ack to isolate
        // the failure to.
        let store = Arc::new(InMemoryStore::new());
        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![undecodable_item(
            None,
            "garbage message body",
        )]));
        let sink = Arc::new(RecordingSink::new());

        let mut settings = base_settings();
        settings.behavior.partial_batch_failures = true;

        let pipeline = Pipeline::new(Arc::new(settings), decoder, store, config, metrics, sink);

        let err = pipeline
            .handle(b"{}")
            .await
            .expect_err("an undecodable item with no ack_id must be a hard error");
        assert!(matches!(err, CoreError::Decode(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn item_with_no_objects_increments_the_items_without_objects_metric() {
        let store = Arc::new(InMemoryStore::new());
        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(Some("ack-1"), vec![])]));
        let sink = Arc::new(RecordingSink::new());

        let pipeline = Pipeline::new(
            Arc::new(base_settings()),
            decoder,
            store,
            config,
            metrics,
            sink.clone(),
        );

        pipeline.handle(b"{}").await.expect("must succeed");
        let snapshots = sink.snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].items_without_objects, 1);
        assert_eq!(snapshots[0].decode_errors, 0);
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
    async fn auto_mode_retries_via_stream_when_buffer_mode_hits_max_object_bytes() {
        // No `size` (so `select_mode` picks Buffer) and a `max_object_bytes`
        // far below the decompressed body: Auto must retry through stream mode.
        let store = Arc::new(InMemoryStore::new());
        let body = gzip_bytes(&cloudtrail_body(&[
            "ConsoleLogin",
            "AssumeRole",
            "StopInstances",
        ]));
        store.seed("src-bucket", "file.json.gz", body.clone());

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object("src-bucket", "file.json.gz", None)],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let mut settings = base_settings();
        settings.processing.mode = ProcessingMode::Auto;
        settings.processing.max_object_bytes = 10; // far smaller than the decompressed body

        let pipeline = Pipeline::new(
            Arc::new(settings),
            decoder,
            store.clone(),
            config,
            metrics,
            sink.clone(),
        );

        pipeline
            .handle(b"{}")
            .await
            .expect("auto mode must retry via stream and succeed, not fail permanently");
        assert!(
            store.put_stream_progress() > 0,
            "the retry must have gone through stream mode (put_stream)"
        );
        let written = store
            .object("dest-bucket", "file.json.gz")
            .expect("must have written the destination via the stream retry");
        assert_eq!(gunzip(&written), gunzip(&body));

        // Ingested once: the failed buffer attempt must not bill its bytes too.
        let snapshots = sink.snapshots();
        assert_eq!(snapshots.len(), 1, "one snapshot per invocation");
        assert_eq!(
            snapshots[0].bytes_in,
            body.len() as u64,
            "BytesIn must count the retried object once, not once per attempt"
        );
        assert_eq!(
            snapshots[0].objects_processed, 1,
            "the retried object must be counted as processed exactly once"
        );
    }

    #[tokio::test]
    async fn explicit_buffer_mode_still_fails_object_too_large_without_retry() {
        // Same setup, but `mode: buffer` is explicit — ObjectTooLarge must
        // surface as an error rather than being retried.
        let store = Arc::new(InMemoryStore::new());
        let body = gzip_bytes(&cloudtrail_body(&[
            "ConsoleLogin",
            "AssumeRole",
            "StopInstances",
        ]));
        store.seed("src-bucket", "file.json.gz", body);

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object("src-bucket", "file.json.gz", None)],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let mut settings = base_settings();
        settings.processing.mode = ProcessingMode::Buffer;
        settings.processing.max_object_bytes = 10;

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
            .expect_err("explicit buffer mode must not retry via stream");
        assert!(
            matches!(err, CoreError::ObjectTooLarge { .. }),
            "got {err:?}"
        );
        assert!(!store.contains("dest-bucket", "file.json.gz"));
    }

    /// Reads like `InMemoryStore`, but every write fails.
    struct PutRejectingStore {
        inner: InMemoryStore,
    }

    #[async_trait]
    impl ObjectStore for PutRejectingStore {
        async fn get(&self, b: &str, k: &str) -> Result<Bytes, StoreError> {
            self.inner.get(b, k).await
        }

        async fn get_stream(
            &self,
            b: &str,
            k: &str,
        ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, StoreError> {
            self.inner.get_stream(b, k).await
        }

        async fn put(
            &self,
            _b: &str,
            _k: &str,
            _body: Bytes,
            _m: PutMeta,
        ) -> Result<(), StoreError> {
            Err(StoreError::Backend("put rejected".to_string()))
        }

        async fn put_stream(
            &self,
            _b: &str,
            _k: &str,
            _body: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
            _m: PutMeta,
        ) -> Result<(), StoreError> {
            Err(StoreError::Backend("put_stream rejected".to_string()))
        }
    }

    fn put_rejecting_store(key: &str, body: Vec<u8>) -> Arc<PutRejectingStore> {
        let inner = InMemoryStore::new();
        inner.seed("src-bucket", key, body);
        Arc::new(PutRejectingStore { inner })
    }

    #[tokio::test]
    async fn a_failed_write_reports_no_bytes_out_in_buffer_mode() {
        let store = put_rejecting_store(
            "file.json.gz",
            gzip_bytes(&cloudtrail_body(&["ConsoleLogin", "Decrypt"])),
        );

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
            store,
            config,
            metrics,
            sink.clone(),
        );

        let err = pipeline
            .handle(b"{}")
            .await
            .expect_err("a rejected put must fail the object");
        assert!(matches!(err, CoreError::Store(_)), "got {err:?}");

        let snapshots = sink.snapshots();
        assert_eq!(snapshots.len(), 1);
        assert!(
            snapshots[0].bytes_in > 0,
            "the object was read, so BytesIn must count it"
        );
        assert_eq!(
            snapshots[0].bytes_out, 0,
            "the put failed, so nothing reached the destination and BytesOut \
             must stay zero"
        );
    }

    #[tokio::test]
    async fn a_failed_write_publishes_no_record_counters_in_buffer_mode() {
        let store = put_rejecting_store(
            "file.json.gz",
            gzip_bytes(&cloudtrail_body(&["ConsoleLogin", "Decrypt"])),
        );

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
            store,
            config,
            metrics,
            sink.clone(),
        );

        let err = pipeline
            .handle(b"{}")
            .await
            .expect_err("a rejected put must fail the object");
        assert!(matches!(err, CoreError::Store(_)), "got {err:?}");

        let snapshots = sink.snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(
            (
                snapshots[0].records_in,
                snapshots[0].records_kept,
                snapshots[0].records_dropped,
                snapshots[0].parse_errors,
            ),
            (0, 0, 0, 0),
            "the put failed, so no record of this object may be counted — the \
             redelivery re-evaluates it whole and would count them twice"
        );
        assert!(
            snapshots[0].rule_drops.is_empty(),
            "a drop attributed to a rule for an object that was never written \
             is a drop that did not happen, got {:?}",
            snapshots[0].rule_drops
        );
    }

    #[tokio::test]
    async fn a_failed_unrecognized_copy_reports_no_bytes_out() {
        // Same claim for the `on_unrecognized_object: copy` path, which is a
        // second, independent `put` site.
        let store = put_rejecting_store("weird.json.gz", gzip_bytes(br#"{"not":"an envelope"}"#));

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object("src-bucket", "weird.json.gz", None)],
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

        let err = pipeline
            .handle(b"{}")
            .await
            .expect_err("a rejected verbatim copy must fail the object");
        assert!(matches!(err, CoreError::Store(_)), "got {err:?}");

        let snapshots = sink.snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(
            snapshots[0].unrecognized_objects, 1,
            "the object must still be counted as unrecognized"
        );
        assert_eq!(
            snapshots[0].bytes_out, 0,
            "the copy failed, so BytesOut must stay zero"
        );
    }

    #[tokio::test]
    async fn dry_run_writes_nothing_but_still_counts_drops() {
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

        assert!(
            store.object("dest-bucket", "file.json.gz").is_none(),
            "dry_run must not write anything to the destination"
        );

        let snapshots = sink.snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(
            snapshots[0].records_dropped, 1,
            "dry_run must still count what would have been dropped"
        );
        assert_eq!(snapshots[0].records_kept, 2);
        assert_eq!(
            snapshots[0].bytes_out, 0,
            "dry_run must report no bytes written"
        );
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
    async fn a_failing_object_does_not_abandon_its_siblings_in_the_same_message() {
        let store = Arc::new(InMemoryStore::new());
        let body = gzip_bytes(&cloudtrail_body(&["ConsoleLogin"]));
        store.seed("src-bucket", "first.json.gz", body.clone());
        // The two middle keys are deliberately not seeded: on_missing_object
        // is `error`, so each is a failure sitting between two good objects.
        store.seed("src-bucket", "last.json.gz", body);

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            Some("poisoned-ack"),
            vec![
                object("src-bucket", "first.json.gz", None),
                object("src-bucket", "missing-a.json.gz", None),
                object("src-bucket", "missing-b.json.gz", None),
                object("src-bucket", "last.json.gz", None),
            ],
        )]));
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

        let outcome = pipeline
            .handle(b"{}")
            .await
            .expect("partial_batch_failures=true must not fail the whole batch");

        assert_eq!(
            outcome.failed_ack_ids,
            vec!["poisoned-ack".to_string()],
            "the message must be re-driven, and reported exactly once despite two \
             failing objects"
        );
        assert!(
            store.contains("dest-bucket", "first.json.gz"),
            "the object before the failure must have been written"
        );
        assert!(
            store.contains("dest-bucket", "last.json.gz"),
            "the object *after* the failures must still have been attempted"
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

    #[tokio::test]
    async fn a_failing_object_is_counted_even_though_the_invocation_returns_ok() {
        let store = put_rejecting_store(
            "file.json.gz",
            gzip_bytes(&cloudtrail_body(&["ConsoleLogin"])),
        );

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            Some("ack-1"),
            vec![object("src-bucket", "file.json.gz", None)],
        )]));
        let sink = Arc::new(RecordingSink::new());

        // Default settings: partial_batch_failures is true.
        let pipeline = Pipeline::new(
            Arc::new(base_settings()),
            decoder,
            store,
            config,
            metrics,
            sink.clone(),
        );

        let outcome = pipeline
            .handle(b"{}")
            .await
            .expect("partial batch failures must not fail the invocation");
        assert_eq!(
            outcome.failed_ack_ids,
            vec!["ack-1".to_string()],
            "the message must be reported for redelivery"
        );

        let snapshots = sink.snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(
            snapshots[0].objects_failed, 1,
            "the failure must be visible in metrics — this Ok-returning path \
             leaves the AWS Errors metric at zero, so this counter is the only \
             signal that objects are being redriven"
        );
        assert_eq!(
            snapshots[0].objects_processed, 0,
            "a failed object must not also count as processed"
        );
    }

    #[tokio::test]
    async fn a_key_filter_rejecting_everything_is_distinguishable_from_no_traffic() {
        let store = Arc::new(InMemoryStore::new());
        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            Some("ack-1"),
            // `.txt` is excluded by the default `\.json\.gz$` include regex.
            vec![
                object("src-bucket", "a.txt", None),
                object("src-bucket", "b.txt", None),
            ],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let pipeline = Pipeline::new(
            Arc::new(base_settings()),
            decoder,
            store.clone(),
            config,
            metrics,
            sink.clone(),
        );

        let outcome = pipeline.handle(b"{}").await.expect("must succeed");
        assert!(outcome.failed_ack_ids.is_empty());
        assert_eq!(store.read_calls(), 0, "excluded keys must never be fetched");

        let snapshots = sink.snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(
            snapshots[0].objects_excluded_by_key, 2,
            "both excluded objects must be counted; without this the snapshot \
             is all-zero and identical to one from an invocation that received \
             nothing at all"
        );
        assert_eq!(snapshots[0].objects_processed, 0);
        assert_eq!(snapshots[0].records_in, 0);
    }

    #[tokio::test]
    async fn dry_run_reports_unrecognized_objects() {
        let store = Arc::new(InMemoryStore::new());
        store.seed(
            "src-bucket",
            "weird.json.gz",
            gzip_bytes(br#"{"not":"an envelope"}"#),
        );

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object("src-bucket", "weird.json.gz", None)],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let settings = Settings {
            behavior: Behavior {
                dry_run: true,
                ..Behavior::default()
            },
            ..base_settings()
        };

        let pipeline = Pipeline::new(
            Arc::new(settings),
            decoder,
            store.clone(),
            config,
            metrics,
            sink.clone(),
        );

        pipeline.handle(b"{}").await.expect("dry run must succeed");

        let snapshots = sink.snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(
            snapshots[0].unrecognized_objects, 1,
            "dry run must still classify the object it evaluated"
        );
        assert_eq!(
            snapshots[0].bytes_out, 0,
            "dry run must not write, so nothing may be billed to BytesOut"
        );
        assert!(
            store.object("dest-bucket", "weird.json.gz").is_none(),
            "dry run must leave the destination untouched"
        );
    }

    #[tokio::test]
    async fn dry_run_previews_an_over_cap_object_through_the_stream_retry() {
        // The same fixture as the auto-mode retry test; only `dry_run` differs.
        let store = Arc::new(InMemoryStore::new());
        let body = gzip_bytes(&cloudtrail_body(&[
            "ConsoleLogin",
            "AssumeRole",
            "StopInstances",
        ]));
        store.seed("src-bucket", "file.json.gz", body.clone());
        assert!(
            gunzip(&body).len() > body.len(),
            "the fixture must decompress to more than its compressed length, \
             or the cap below is not the one being tested"
        );

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object("src-bucket", "file.json.gz", None)],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let mut settings = base_settings();
        settings.processing.mode = ProcessingMode::Auto;
        // Exactly the compressed length: the fetch fits under the cap, so the
        // buffer attempt bills `BytesIn` before the decompressed body blows it.
        settings.processing.max_object_bytes = body.len() as u64;
        settings.behavior.dry_run = true;

        let pipeline = Pipeline::new(
            Arc::new(settings),
            decoder,
            store.clone(),
            config,
            metrics,
            sink.clone(),
        );

        pipeline
            .handle(b"{}")
            .await
            .expect("a dry run must not fail an object the live run streams successfully");

        assert!(
            store.object("dest-bucket", "file.json.gz").is_none(),
            "the streamed preview must still write nothing"
        );

        let snapshots = sink.snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(
            snapshots[0].objects_failed, 0,
            "the preview must not report a failure the live run does not have"
        );
        assert_eq!(snapshots[0].objects_processed, 1);
        // The counters must survive the scratch `Metrics` the discard path runs
        // through.
        assert_eq!(
            snapshots[0].records_in, 3,
            "every record must still be evaluated"
        );
        assert_eq!(snapshots[0].records_kept, 3);
        assert_eq!(
            snapshots[0].bytes_out, 0,
            "nothing reached a destination, so BytesOut must stay zero"
        );
        // One object, one ingest: the failed buffer attempt bills nothing
        // because the stream retry counts the bytes it reads itself.
        assert_eq!(
            snapshots[0].bytes_in,
            body.len() as u64,
            "BytesIn must count the previewed object once, not once per attempt"
        );
    }

    /// A decoder that always fails, standing in for a payload that is not the
    /// event shape this binary was built for.
    struct FailingDecoder;

    impl EventDecoder for FailingDecoder {
        fn decode(&self, _payload: &[u8]) -> Result<Vec<SourceItem>, DecodeError> {
            Err(DecodeError::InvalidPayload(
                "missing field `Records`".to_string(),
            ))
        }
    }

    #[tokio::test]
    async fn a_whole_payload_decode_failure_is_counted_in_decode_errors() {
        let store = Arc::new(InMemoryStore::new());
        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let sink = Arc::new(RecordingSink::new());

        let pipeline = Pipeline::new(
            Arc::new(base_settings()),
            Arc::new(FailingDecoder),
            store.clone(),
            config,
            metrics,
            sink.clone(),
        );

        pipeline
            .handle(br#"{"Type":"Notification"}"#)
            .await
            .expect_err("an undecodable payload must fail the invocation");

        let snapshots = sink.snapshots();
        assert_eq!(
            snapshots.len(),
            1,
            "a snapshot must still be emitted on the failure path"
        );
        assert_eq!(
            snapshots[0].decode_errors, 1,
            "the failure must be attributable to decoding, in our own namespace"
        );
        assert_eq!(snapshots[0].objects_processed, 0);
    }

    // --- C2: no full-object `get` may be unbounded --------------------

    /// The body is deliberately **not** gzip: with nothing to decompress, an
    /// `ObjectTooLarge` can only have come from the capped fetch itself.
    #[tokio::test]
    async fn an_oversized_object_is_rejected_before_it_is_ever_buffered() {
        let store = Arc::new(InMemoryStore::new());
        let body = vec![b'x'; 4096];
        store.seed("src-bucket", "file.json.gz", body);

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object("src-bucket", "file.json.gz", None)],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let mut settings = base_settings();
        // Explicit buffer mode: auto would retry via stream and mask the cap.
        settings.processing.mode = ProcessingMode::Buffer;
        settings.processing.max_object_bytes = 64;

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
            .expect_err("an object larger than max_object_bytes must fail");
        assert!(
            matches!(err, CoreError::ObjectTooLarge { limit: 64 }),
            "the cap must fire on the fetch, not on decompression; got {err:?}"
        );
        assert!(!store.contains("dest-bucket", "file.json.gz"));
    }

    /// The *compressed* object exceeds the cap — only the fetch-side cap can
    /// detect that, and `auto` mode's existing retry must still recover it.
    #[tokio::test]
    async fn auto_mode_recovers_an_object_too_large_for_the_capped_fetch() {
        let store = Arc::new(InMemoryStore::new());
        let body = gzip_bytes(&cloudtrail_body(&["ConsoleLogin", "Decrypt"]));
        assert!(body.len() > 16, "fixture must exceed the cap set below");
        store.seed("src-bucket", "file.json.gz", body.clone());

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(drop_decrypt_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object("src-bucket", "file.json.gz", None)],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let mut settings = base_settings();
        settings.processing.mode = ProcessingMode::Auto;
        settings.processing.max_object_bytes = 16;

        let pipeline = Pipeline::new(
            Arc::new(settings),
            decoder,
            store.clone(),
            config,
            metrics,
            sink.clone(),
        );

        pipeline
            .handle(b"{}")
            .await
            .expect("the capped fetch must degrade to a stream retry, not a failure");
        let written = store
            .object("dest-bucket", "file.json.gz")
            .expect("the stream retry must still write the destination");
        assert_eq!(
            gunzip(&written),
            cloudtrail_body(&["ConsoleLogin"]),
            "the retry must apply the ruleset, not copy the object through"
        );

        let snapshots = sink.snapshots();
        assert_eq!(snapshots.len(), 1);
        assert!(
            snapshots[0].records_balance(),
            "RecordsIn must still reconcile after a capped-fetch retry: {:?}",
            snapshots[0]
        );
        assert_eq!(snapshots[0].objects_processed, 1);
        assert_eq!(snapshots[0].objects_failed, 0);
    }

    /// Falsifiable: a plain `limit + 1` wraps to 0 at `u64::MAX` and turns the
    /// operator's "no cap" into "read nothing".
    #[tokio::test]
    async fn max_object_bytes_at_u64_max_does_not_wrap_the_capped_fetch() {
        let store = Arc::new(InMemoryStore::new());
        let body = gzip_bytes(&cloudtrail_body(&["ConsoleLogin", "Decrypt"]));
        store.seed("src-bucket", "file.json.gz", body);

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(drop_decrypt_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object("src-bucket", "file.json.gz", None)],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let mut settings = base_settings();
        settings.processing.mode = ProcessingMode::Buffer;
        settings.processing.max_object_bytes = u64::MAX;

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
            .expect("u64::MAX must mean no cap, not take(0)");
        let written = store
            .object("dest-bucket", "file.json.gz")
            .expect("the object must be written, not rejected as too large");
        assert_eq!(
            gunzip(&written),
            cloudtrail_body(&["ConsoleLogin"]),
            "the ruleset must still apply normally under an uncapped fetch"
        );
    }

    /// `put_stream_progress()` is the discriminator: a buffered copy calls
    /// `put`, which leaves it at zero.
    #[tokio::test]
    async fn fail_open_raw_copy_streams_rather_than_buffering() {
        let store = Arc::new(InMemoryStore::new());
        let body = b"not gzip, not json, just raw bytes".to_vec();
        store.seed("src-bucket", "file.json.gz", body.clone());

        let metrics = Arc::new(Metrics::default());
        let (config, src) = config_store(no_op_rules(), metrics.clone());
        src.fail_next_fetch();
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
            sink.clone(),
        );

        pipeline.handle(b"{}").await.expect("open must not fail");
        assert_eq!(
            store.put_stream_progress(),
            body.len() as u64,
            "the passthrough must have delivered every byte through put_stream"
        );
        assert_eq!(
            store.read_calls(),
            1,
            "the passthrough must open the source exactly once, and stream it"
        );
        assert_eq!(
            store
                .object("dest-bucket", "file.json.gz")
                .expect("fail-open must still write a raw copy")
                .as_ref(),
            body.as_slice()
        );

        let snapshots = sink.snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].bytes_in, body.len() as u64);
        assert_eq!(snapshots[0].bytes_out, body.len() as u64);
    }

    /// Reads like `InMemoryStore`, but `put_stream` drains the body to EOF and
    /// *then* fails: every byte read, none committed.
    struct DrainThenRejectStore {
        inner: InMemoryStore,
    }

    #[async_trait]
    impl ObjectStore for DrainThenRejectStore {
        async fn get(&self, b: &str, k: &str) -> Result<Bytes, StoreError> {
            self.inner.get(b, k).await
        }

        async fn get_stream(
            &self,
            b: &str,
            k: &str,
        ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, StoreError> {
            self.inner.get_stream(b, k).await
        }

        async fn put(
            &self,
            _b: &str,
            _k: &str,
            _body: Bytes,
            _m: PutMeta,
        ) -> Result<(), StoreError> {
            Err(StoreError::Backend("put rejected".to_string()))
        }

        async fn put_stream(
            &self,
            _b: &str,
            _k: &str,
            mut body: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
            _m: PutMeta,
        ) -> Result<(), StoreError> {
            let mut sink = Vec::new();
            body.read_to_end(&mut sink).await.ok();
            Err(StoreError::Backend("upload aborted at commit".to_string()))
        }
    }

    #[tokio::test]
    async fn a_streaming_copy_that_fails_at_commit_reports_no_bytes_out() {
        let inner = InMemoryStore::new();
        let body = b"not gzip, not json, just raw bytes".to_vec();
        inner.seed("src-bucket", "file.json.gz", body.clone());
        let store = Arc::new(DrainThenRejectStore { inner });

        let metrics = Arc::new(Metrics::default());
        let (config, src) = config_store(no_op_rules(), metrics.clone());
        src.fail_next_fetch();
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
            store,
            config,
            metrics,
            sink.clone(),
        );

        let err = pipeline
            .handle(b"{}")
            .await
            .expect_err("a rejected streaming copy must fail the object");
        assert!(matches!(err, CoreError::Store(_)), "got {err:?}");

        let snapshots = sink.snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(
            snapshots[0].bytes_in,
            body.len() as u64,
            "the bytes were read, so BytesIn must count them"
        );
        assert_eq!(
            snapshots[0].bytes_out, 0,
            "nothing committed, so BytesOut must stay at zero"
        );
    }

    /// Builds a stream-mode pipeline over an object that is valid gzip+JSON
    /// but carries no `Records` array, under `policy`.
    fn unrecognized_stream_pipeline(
        policy: OnUnrecognizedObject,
    ) -> (
        Arc<Pipeline>,
        Arc<InMemoryStore>,
        Arc<RecordingSink>,
        Vec<u8>,
    ) {
        let store = Arc::new(InMemoryStore::new());
        let body = gzip_bytes(br#"{"not":"an envelope"}"#);
        store.seed("src-bucket", "weird.json.gz", body.clone());

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            vec![object("src-bucket", "weird.json.gz", None)],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let mut settings = base_settings();
        settings.processing.mode = ProcessingMode::Stream;
        settings.behavior.on_unrecognized_object = policy;

        let pipeline = Arc::new(Pipeline::new(
            Arc::new(settings),
            decoder,
            store.clone(),
            config,
            metrics,
            sink.clone(),
        ));
        (pipeline, store, sink, body)
    }

    #[tokio::test]
    async fn stream_mode_skip_policy_re_fetches_nothing() {
        let (pipeline, store, sink, _body) =
            unrecognized_stream_pipeline(OnUnrecognizedObject::Skip);

        pipeline.handle(b"{}").await.expect("skip must not fail");
        assert_eq!(
            store.read_calls(),
            1,
            "skip must open the source once (the stream attempt) and never re-fetch it"
        );
        assert!(!store.contains("dest-bucket", "weird.json.gz"));

        let snapshots = sink.snapshots();
        assert_eq!(snapshots[0].unrecognized_objects, 1);
    }

    /// Same for `error`: it returns without reading a byte of the body.
    #[tokio::test]
    async fn stream_mode_error_policy_re_fetches_nothing() {
        let (pipeline, store, _sink, _body) =
            unrecognized_stream_pipeline(OnUnrecognizedObject::Error);

        let err = pipeline
            .handle(b"{}")
            .await
            .expect_err("on_unrecognized_object=error must fail the object");
        assert!(
            matches!(err, CoreError::UnrecognizedObject { .. }),
            "got {err:?}"
        );
        assert_eq!(
            store.read_calls(),
            1,
            "error must open the source once and never re-fetch it"
        );
    }

    /// `put_stream_progress()` — reset at the start of every `put_stream`, so it
    /// reflects the copy and not the aborted filtering attempt that preceded it
    /// — must equal the source length exactly.
    #[tokio::test]
    async fn stream_mode_copy_policy_streams_the_object() {
        let (pipeline, store, sink, body) =
            unrecognized_stream_pipeline(OnUnrecognizedObject::Copy);

        pipeline.handle(b"{}").await.expect("copy must not fail");
        assert_eq!(
            store.put_stream_progress(),
            body.len() as u64,
            "the copy must have delivered every source byte through put_stream"
        );
        assert_eq!(
            store
                .object("dest-bucket", "weird.json.gz")
                .expect("copy must write the destination")
                .as_ref(),
            body.as_slice(),
            "the copy must be byte-for-byte identical to the source"
        );

        let snapshots = sink.snapshots();
        assert_eq!(snapshots[0].unrecognized_objects, 1);
        assert_eq!(snapshots[0].objects_processed, 1);
        assert_eq!(snapshots[0].bytes_out, body.len() as u64);

        // One object, one `BytesIn`, even though this is the one path that
        // reads it twice (`stream_run`, then the copy).
        assert_eq!(
            snapshots[0].bytes_in,
            body.len() as u64,
            "the copy re-reads bytes stream_run already billed; they must be counted once"
        );
    }

    #[tokio::test]
    async fn a_self_trigger_is_counted_as_a_failed_object() {
        let store = Arc::new(InMemoryStore::new());
        store.seed(
            "same-bucket",
            "filtered/a.json.gz",
            gzip_bytes(br#"{"Records":[{"eventName":"A"}]}"#),
        );

        let metrics = Arc::new(Metrics::default());
        let (config, _src) = config_store(no_op_rules(), metrics.clone());
        let decoder = Arc::new(StubDecoder(vec![item(
            None,
            // Already under our own output prefix in our own destination
            // bucket: reading it means reprocessing our own output.
            vec![object("same-bucket", "filtered/a.json.gz", None)],
        )]));
        let sink = Arc::new(RecordingSink::new());

        let mut settings = base_settings();
        settings.destination.bucket = "same-bucket".to_string();
        settings.destination.key_prefix = "filtered/".to_string();

        let pipeline = Arc::new(Pipeline::new(
            Arc::new(settings),
            decoder,
            store.clone(),
            config,
            metrics,
            sink.clone(),
        ));

        let err = pipeline
            .handle(b"{}")
            .await
            .expect_err("a self-trigger must fail the invocation");
        assert!(matches!(err, CoreError::SelfTrigger { .. }), "got {err:?}");

        let snapshots = sink.snapshots();
        assert_eq!(
            snapshots[0].objects_failed, 1,
            "a self-trigger must be visible as a failed object, not only as an AWS Errors data point"
        );
        assert_eq!(snapshots[0].objects_processed, 0);
    }
}
