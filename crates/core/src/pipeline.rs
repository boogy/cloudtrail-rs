//! `Pipeline`: wires the four ports together and owns the whole policy
//! matrix (the safety invariants + the `behavior.*` knobs) on top
//! of the pure `process::{buffer_run, stream_run}` functions.

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

/// Canonical output metadata: every
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
/// `stream_threshold_bytes` (safety invariant 5: missing size
/// picks buffer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObjectMode {
    Buffer,
    Stream,
}

/// Whether a streaming copy should bill the bytes it reads to `BytesIn`, or
/// whether an earlier read of the same object already did.
///
/// `BytesIn` means "compressed source bytes ingested", counted once per object
/// per invocation — the same rule that makes the `ObjectTooLarge` auto-retry
/// skip its buffer-mode count. Stream mode's `on_unrecognized_object: copy`
/// is the one path that reads an object twice (once to discover it has no
/// `Records`, once to copy it), and billing both reads made the same object
/// report double the `BytesIn` of an identical object small enough to take
/// the buffer path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BytesInPolicy {
    Count,
    AlreadyCounted,
}

/// Wraps a source reader so a streaming copy accounts `BytesIn` chunk by
/// chunk as the bytes are actually ingested — the same accounting
/// `stream_run`'s `pump_input` does — while recording the running total so
/// the caller can bill `BytesOut` once the upload has actually committed.
///
/// The total must be read *after* `put_stream` returns `Ok`, never before:
/// a copy that fails midway has ingested bytes (so `BytesIn` is right) but
/// delivered none (so `BytesOut` must stay at zero).
///
/// `metrics` is `None` when the caller has *already* billed these bytes to
/// `BytesIn` — the `on_unrecognized_object: copy` path in stream mode, where
/// `stream_run` read the whole object before concluding it was unrecognized
/// and the copy is a second `GetObject` of bytes already counted. The running
/// total is still kept, because `BytesOut` is derived from it either way.
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
        // `KeyFilter` at load time and refuses to hand back a `Settings`
        // whose patterns do not compile. This panic only fires for a
        // hand-built `Settings` that never went through that path.
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
        // Counted here as well as per-item below, so `DecodeErrors` means
        // "a decode failed", full stop. A whole-payload failure is the more
        // serious of the two — it takes the *entire* invocation's objects
        // with it, not one message's — yet it used to be the one that moved
        // no counter at all. On S3/SNS/EventBridge the only remaining signal
        // was AWS's own `Errors` metric, in a different namespace with no
        // way to tell a decode failure apart from a bucket permissions
        // problem; and this is precisely the path a payload that is valid
        // JSON but not an S3 notification now takes (see the field docs on
        // `S3Notification::records`).
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
                    // Safe to isolate: fail just this message's ack rather
                    // than the whole batch (mirrors the per-object failure
                    // handling below). The message is redriven and retried,
                    // instead of being silently deleted by SQS with its
                    // referenced object never processed.
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
                    // Counted, not silent. An exclusion here is normally
                    // intentional, but a wrong `include_key_regex` /
                    // `exclude_key_regex` rejects *every* delivery — and
                    // without this counter that state is byte-for-byte
                    // identical in metrics to a function receiving no traffic
                    // at all: `ObjectsProcessed` 0, `RecordsIn` 0, no error,
                    // no log. Every object CloudTrail delivered would be
                    // discarded with nothing anywhere to say so.
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

                // Exact match (dest_key == object.key) catches the trivial
                // loop. But if the destination bucket equals the source
                // bucket and key_prefix is non-empty, every object we
                // *ever write* lives under key_prefix in that same bucket —
                // so reading an object already under our own output prefix
                // means we are about to reprocess our own prior output,
                // which would re-trigger the Lambda forever even though no
                // single (bucket, key) pair is an exact match.
                let reading_own_output =
                    !key_prefix.is_empty() && object.key.starts_with(key_prefix.as_str());
                if dest_bucket == object.bucket && (dest_key == object.key || reading_own_output) {
                    // Counted like any other per-object failure before
                    // returning. This is a hard `Err` — deliberately *not*
                    // isolated to one message under `partial_batch_failures`,
                    // because a self-trigger is a deployment misconfiguration
                    // that will hit every object equally, and failing loudly
                    // is the only thing that stops the loop. But "the handler
                    // returned an error" is a state whose only signal was the
                    // AWS `Errors` metric, which says nothing about *why*;
                    // `ObjectsFailed` alongside it puts the object count in
                    // the same place as every other object-level failure.
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
                    // Only reachable when on_config_error == open (closed
                    // already returned above): raw byte copy, bypassing
                    // decompress/parse/size checks entirely.
                    None => self.raw_copy(object, &dest_bucket, &dest_key).await,
                };

                if let Err(e) = outcome {
                    // Counted before the policy branch, so it counts under
                    // both. This is the only metric that moves on the
                    // `partial_batch_failures` path: that path returns `Ok`
                    // from the handler (the failure is reported through
                    // `batchItemFailures`, which is what makes redelivery
                    // work), so AWS's own `Errors` metric stays at zero and
                    // every counter above is about objects that *succeeded*.
                    // Without this, "objects are failing and heading for the
                    // DLQ" has no metric at all — only a log line.
                    self.metrics.add_objects_failed(1);

                    if self.settings.behavior.partial_batch_failures && item.ack_id.is_some() {
                        // Fail the *message* but keep going through its
                        // remaining objects. Stopping here (the original
                        // `break`) meant a poison-pill object took its
                        // siblings down with it: on every redelivery the
                        // poison pill fails first again, so once
                        // maxReceiveCount is reached those siblings had
                        // never been attempted even once — silent loss with
                        // nothing in the logs to say they existed.
                        //
                        // Continuing is safe because writes are idempotent
                        // (same dest key, same content, full-object PUT):
                        // objects processed before *and* after the failure
                        // are simply re-written identically when the message
                        // is re-driven.
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
    /// `StoreError::NotFound`. `Ok(None)` means the caller should treat the
    /// object as handled (skipped) with nothing further to do.
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

    /// Fetches `bucket`/`key` fully into memory for the buffer-mode paths,
    /// **bounded by `max_object_bytes`**.
    ///
    /// The bound is the point. `max_object_bytes` is documented as buffer
    /// mode's *decompressed* cap, and it was enforced there — inside
    /// `decompress_capped`, which is reached only once the whole compressed
    /// object is already resident. The fetch itself was an unbounded
    /// `store.get()`, so an object large enough to exhaust the function's
    /// memory did so *before* anything could reject it, and under
    /// `panic = "abort"` that takes the container with it. On the S3-direct
    /// topology an async invocation is then retried twice and discarded, with
    /// no DLQ unless an on-failure destination is configured — silent loss.
    ///
    /// Capping the compressed read at the same limit cannot reject anything
    /// that would otherwise have survived: gzip output is never meaningfully
    /// larger than its input, so an object whose *compressed* size exceeds
    /// `max_object_bytes` was always going to exceed it decompressed too. The
    /// error is the same `ObjectTooLarge`, so `auto` mode's existing retry
    /// through stream mode (bounded memory, no size cap) recovers it exactly
    /// as it recovers a decompression overflow.
    async fn fetch_with_missing_policy(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<Bytes>, CoreError> {
        let Some(reader) = self.open_with_missing_policy(bucket, key).await? else {
            return Ok(None);
        };

        let limit = self.settings.processing.max_object_bytes;
        // `limit.saturating_add(1)` so exceeding the cap is detectable
        // without ever holding more than one byte past it. Saturating, not
        // wrapping: at `limit == u64::MAX` (an operator's "no cap"), `+ 1`
        // would wrap to 0 and `take(0)` would read nothing instead of
        // everything.
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

    /// Byte-for-byte copies `object` to `dest_key` without ever materializing
    /// it: `get_stream` straight into `put_stream`, so peak memory is one
    /// multipart part regardless of how large the object is.
    ///
    /// `Ok(false)` means the source was missing and `on_missing_object` is
    /// `skip` — nothing was copied and the caller should not count the object
    /// as processed.
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

        // Only now have the bytes reached the destination. A failed
        // `put_stream` aborts the multipart upload, leaving nothing at
        // `dest_key`, and returns above without billing a single byte out.
        self.metrics.add_bytes_out(total.load(Ordering::Relaxed));
        Ok(true)
    }

    /// `behavior.on_config_error == open` with no cached ruleset
    /// (fail-open scope): a raw byte copy, no decompress, no parse, no size
    /// check.
    ///
    /// Streamed rather than buffered. This path is reached precisely when the
    /// rules document is unavailable — a degraded state that has nothing to do
    /// with object size — so it must not be the thing that turns a large
    /// object into an OOM. Streaming also means it needs no size cap at all:
    /// peak memory is one multipart part, whatever the object weighs.
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
        // `dry_run` selects the *destination*, not the mode. It used to
        // short-circuit here, straight into buffer-mode evaluation, which
        // made the one setting meant for a pre-flight check the one setting
        // whose verdict could differ from the live run's: buffer mode's
        // `max_object_bytes` applies to the fetch and the decompressed body,
        // so an object `mode: auto` would have streamed successfully failed
        // the preview with `ObjectTooLarge` (and counted `ObjectsFailed`).
        // Routing dry run through the same `select_mode` and the same retry
        // below means the preview reaches the live run's verdict by taking
        // the live run's path.
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
                    // Auto mode picked Buffer off `object.size` vs.
                    // `stream_threshold_bytes` (a *compressed*-size
                    // estimate); `max_object_bytes` (buffer mode's memory
                    // cap, applied to the compressed fetch *and* the
                    // decompressed body) can still be blown by a highly
                    // compressible object — or by one that arrived with no
                    // size at all. Without this retry that object fails
                    // identically on every redelivery — a permanent poison
                    // pill. Stream mode has no size cap by design
                    // (bounded-memory), so it always succeeds where buffer
                    // mode overflowed. Only in Auto: an explicit
                    // `mode: buffer` config means the operator opted out of
                    // stream mode, so ObjectTooLarge there must still surface.
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

    /// `behavior.dry_run` in buffer mode: a true no-op against the
    /// destination. Every record is still evaluated through `engine` so
    /// `RecordsDropped`/`RuleDrops` report exactly what *would* be filtered,
    /// but nothing is ever written — no `put`, no `BytesOut`.
    ///
    /// Reached through the same `select_mode` the live path uses, and its
    /// `ObjectTooLarge` is retried through [`Pipeline::process_dry_run_stream`]
    /// by the same `auto`-mode rule, so the preview cannot fail an object the
    /// live run would have handled.
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

        // The same one-object-one-`BytesIn` rule `process_buffer` applies, for
        // the same reason: an `ObjectTooLarge` in auto mode is retried through
        // `process_dry_run_stream`, which counts the bytes it reads itself.
        // Billing here too would report a preview ingesting the object twice.
        let retried_via_stream = matches!(result, Err(CoreError::ObjectTooLarge { .. }))
            && self.settings.processing.mode == ProcessingMode::Auto;
        if !retried_via_stream {
            self.metrics.add_bytes_in(bytes.len() as u64);
        }

        // Evaluation only: updates RecordsIn/RecordsKept/RecordsDropped/
        // RuleDrops via `metrics` so the operator sees what would be filtered.
        // Nothing is written — but the `Outcome` is still classified, because
        // dry run's whole purpose is to preview what a live run would do, and
        // "how many objects don't look like CloudTrail at all" is part of that
        // answer. Discarding it made `UnrecognizedObjects` unreachable in dry
        // run, so the one setting meant for a pre-flight check was blind to
        // the one outcome an operator most needs to see before enabling
        // `on_unrecognized_object`.
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

    /// `behavior.dry_run` in stream mode: the real `stream_run`, pointed at a
    /// [`DiscardStore`].
    ///
    /// Not a second evaluator — that is the point. A dry run that reimplemented
    /// streaming evaluation would be a preview of code the live run does not
    /// execute; this runs the identical producer, encoder and
    /// `Deserializer::end()` trailer check, and only the destination differs.
    ///
    /// `stream_run` publishes straight to the `Metrics` it is handed, so it is
    /// handed a scratch one and everything except `BytesOut` is folded back:
    /// bytes were genuinely read, records were genuinely evaluated, but nothing
    /// reached a destination and `BytesOut` must stay zero.
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

        // Fold back before `?`: an object that failed mid-stream still read
        // the bytes it read, and `BytesIn` is billed on failure in buffer mode
        // too. The record counters cannot leak from a failure — `stream_run`
        // commits its tally only past its own upload check, so a failed object
        // leaves the scratch counters at zero by construction.
        let snapshot = scratch.snapshot_and_reset();
        self.metrics.add_bytes_in(snapshot.bytes_in);
        self.metrics.add_records_in(snapshot.records_in);
        self.metrics.add_records_kept(snapshot.records_kept);
        self.metrics.add_records_dropped(snapshot.records_dropped);
        self.metrics.add_parse_errors(snapshot.parse_errors);
        for (rule, n) in &snapshot.rule_drops {
            self.metrics.record_rule_drops(rule, *n);
        }
        // `snapshot.bytes_out` is deliberately dropped: those bytes went into
        // `DiscardStore`, and `BytesOut` means bytes that reached a real
        // destination.

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

        // `BytesIn` is skipped for exactly one case: an `ObjectTooLarge` in
        // auto mode, which `process_object` retries through `process_stream`.
        // Stream mode counts the input bytes it reads itself, so counting
        // here as well would bill the same object twice. Every other outcome
        // — success or failure — counts the bytes actually ingested.
        let retried_via_stream = matches!(result, Err(CoreError::ObjectTooLarge { .. }))
            && self.settings.processing.mode == ProcessingMode::Auto;
        if !retried_via_stream {
            self.metrics.add_bytes_in(bytes.len() as u64);
        }
        let (outcome, tally) = result?;

        match outcome {
            Outcome::Written(Some(out_bytes)) => {
                // Count after the `put`, never before: `BytesOut` means bytes
                // that reached the destination, and a failed put means none
                // did. Same ordering as `raw_copy` and `stream_run`.
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

        // Past every `?` above — in particular the `put` — so this object's
        // records are now true. `buffer_run` evaluated them long before the
        // write; committing there billed records as kept to an object whose
        // `put` then failed, leaving nothing at the destination and a
        // redelivery that counts the same records again. Same ordering as
        // `BytesOut` directly above, and as `stream_run`'s commit past
        // `upload_result?`.
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
                // stream_run already aborted the in-flight upload, so
                // `dest_key` is untouched and the policy decides afresh.
                //
                // Branch *before* fetching anything. The old code re-fetched
                // the entire object into memory and only then consulted the
                // policy — so `skip` and `error`, which never look at the
                // bytes, paid a full unbounded in-memory download for
                // nothing, on an object that by definition came down the
                // stream path because it was too big to buffer.
                match self.settings.behavior.on_unrecognized_object {
                    OnUnrecognizedObject::Copy => {
                        // `stream_run` already read this object end to end and
                        // billed every byte to `BytesIn`; this is a second
                        // `GetObject` of the same bytes, so it must not bill
                        // them again. Buffer mode's `copy` reuses the bytes it
                        // already holds and counts them once — this keeps the
                        // two modes reporting the same `BytesIn` for the same
                        // object.
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

    /// Applies `behavior.on_unrecognized_object` given the object's already
    /// -fetched raw `bytes`. Buffer mode only: it is the mode that already
    /// holds them. Stream mode never re-fetches — it branches on the policy
    /// first and, for `copy`, streams the object across (`stream_copy`).
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
        SourceItem::new(ack_id.map(str::to_string), objects)
    }

    /// Like `item`, but pre-marked as undecodable — for tests exercising
    /// `Pipeline::handle_inner`'s FIX 1 decode-error handling directly,
    /// without going through a real `EventDecoder`.
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
    async fn self_trigger_guard_errors_when_reading_own_output_prefix_in_same_bucket() {
        // Not an exact-match case: the source key is "output/some-file.json.gz"
        // but the computed dest_key is "output/output/some-file.json.gz" — no
        // single (bucket, key) pair matches. But dest bucket == source bucket
        // and the source key already lives under our own output prefix, so
        // every object we write here would itself be read back in and
        // re-written forever.
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
        // Same key_prefix shape as the positive case above, but the
        // destination bucket differs from the source bucket — cross-bucket
        // is never a self-trigger, so this must succeed.
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
        // Mirrors the S3/SNS/EventBridge decoders, which never set ack_id:
        // there is no per-message ack to isolate the failure to, so it must
        // fail the whole invocation rather than being silently swallowed.
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
        // No `size` on the object (so `select_mode` picks Buffer off the
        // default arm), but `max_object_bytes` is set far smaller than the
        // decompressed body — buffer mode must hit ObjectTooLarge, and Auto
        // mode must retry the same object through stream mode (no size cap)
        // rather than treat ObjectTooLarge as a permanent failure.
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

        // The failed buffer attempt must not also bill its bytes: the
        // object is ingested once, so BytesIn must equal the object size
        // exactly once, not twice.
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
        // Same oversized-decompressed-body setup as the Auto-mode retry
        // test above, but `mode: buffer` is explicit — the operator opted
        // out of stream mode, so ObjectTooLarge must still surface as an
        // error rather than being silently retried.
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

    /// Reads like `InMemoryStore`, but every write fails — the store-side
    /// half of "did the bytes actually land". `BytesOut` is what operators
    /// reconcile ingest against output volume with, so a byte counted for a
    /// `put` that errored reads as data safely delivered when it is not.
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

    /// The record-counter twin of the test above. `buffer_run` evaluates every
    /// record long before `process_buffer` calls `put`, and it used to publish
    /// `RecordsIn`/`RecordsKept`/`RecordsDropped`/`ParseErrors`/`RuleDrops`
    /// itself as it went. A rejected `put` therefore left the destination
    /// empty while the metrics claimed the records had been filtered — and the
    /// redelivery, which re-evaluates the object whole, counted them again.
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

    /// A poison-pill object must fail its *message* without abandoning the
    /// message's remaining objects. Stopping at the first failure looks safe
    /// (the message is re-driven), but the poison pill fails first on every
    /// redelivery too — so once maxReceiveCount is reached the siblings have
    /// never been attempted even once, and nothing recorded that they existed.
    ///
    /// Also pins the ack id to a single entry: with several objects failing in
    /// one message, the id must still be reported exactly once.
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

    /// The observability hole this closes: under the default
    /// `partial_batch_failures = true`, a failing object does **not** fail the
    /// invocation. `handle` returns `Ok` (the failure travels back to SQS via
    /// `batchItemFailures`, which is what makes redelivery work), so AWS's own
    /// `Errors` metric stays at zero, and every other counter in the snapshot
    /// describes objects that *succeeded*. Without `ObjectsFailed` a function
    /// redriving its entire input toward the DLQ emits a metrics line
    /// indistinguishable from a healthy one.
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

    /// A key filter that rejects everything is the worst kind of
    /// misconfiguration: it discards 100% of delivered objects and — before
    /// `ObjectsExcludedByKey` — produced a metrics line byte-identical to an
    /// idle function's. This asserts the two are now distinguishable, which is
    /// the entire point of the counter.
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

    /// `dry_run` exists to preview a live run without touching the
    /// destination. It discarded `buffer_run`'s `Outcome`, so
    /// `UnrecognizedObjects` — the one number that tells an operator how much
    /// of their traffic `on_unrecognized_object` is about to act on — was
    /// unreachable in exactly the mode meant to answer that question.
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

    /// `dry_run` selects the *destination*, not the mode.
    ///
    /// It used to short-circuit before `select_mode` straight into buffer-mode
    /// evaluation, which made the one setting meant for a pre-flight check the
    /// one setting whose verdict could differ from the live run's: this object
    /// exceeds `max_object_bytes`, so the preview failed it (and counted
    /// `ObjectsFailed`) while `auto` would have streamed it without complaint.
    /// An operator reads that as "enabling this will break", and it will not.
    ///
    /// The preview now takes the live run's path — the real `stream_run`
    /// against a `DiscardStore` — so it reaches the live run's verdict.
    #[tokio::test]
    async fn dry_run_previews_an_over_cap_object_through_the_stream_retry() {
        // The same fixture as `auto_mode_retries_via_stream_when_buffer_mode_
        // hits_max_object_bytes`, so the two differ only in `dry_run` — which
        // is exactly the claim: the verdict must not depend on it.
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
        // Exactly the compressed length: the *fetch* fits under the cap, so
        // the buffer attempt gets far enough to bill `BytesIn` before the
        // decompressed body blows the same cap. That is the only shape that
        // exercises the retry's double-billing guard — a cap below the
        // compressed size fails in the fetch and never bills at all.
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
        // The counters survive the scratch `Metrics` the discard path runs
        // through — the preview is worthless if it evaluates and reports
        // nothing.
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

    /// A whole-payload decode failure loses **every** object the invocation
    /// carried — strictly worse than the per-item failure that was already
    /// counted — yet it moved no counter of ours at all. On the S3/SNS/
    /// EventBridge topologies the only signal was AWS's own `Errors` metric,
    /// which cannot distinguish "this payload wasn't an S3 notification" from
    /// "GetObject was denied".
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

    /// `max_object_bytes` used to be enforced only *inside* `buffer_run`,
    /// on the decompressed side — reached after the whole compressed object
    /// was already resident in memory. The cap therefore could not prevent
    /// the allocation it existed to prevent.
    ///
    /// The body here is deliberately **not gzip**: the decompressed-side cap
    /// cannot be what fires (there is nothing to decompress), so an
    /// `ObjectTooLarge` can only have come from the fetch itself. Before the
    /// fix this failed with a gzip error, having first buffered all 4 KiB.
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

    /// The capped fetch must not turn a large-but-legitimate object into a
    /// permanent failure: `auto` mode already retries `ObjectTooLarge`
    /// through stream mode, and the capped fetch raises exactly that error
    /// so the existing recovery covers it. Here the *compressed* object
    /// exceeds the cap, which only the new fetch-side cap can detect.
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

    /// `max_object_bytes = u64::MAX` is an operator's "no cap". The capped
    /// fetch computes `limit.saturating_add(1)` for the `take()` length; a
    /// plain `limit + 1` wraps to 0 and turns "no cap" into "read nothing",
    /// failing every object. Guards the fetch-side site in
    /// `fetch_with_missing_policy`.
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

    /// The fail-open passthrough is reached precisely when the rules
    /// document is unavailable — a degraded state that has nothing to do
    /// with object size. It must therefore never be the thing that turns a
    /// large object into an OOM. It used to `get` the whole object and
    /// `put` it back; it now streams source to destination.
    ///
    /// `put_stream_progress()` is the discriminator: the buffered path
    /// calls `put`, which leaves it at zero.
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

    /// Reads like `InMemoryStore`, but `put_stream` drains the body to EOF
    /// and *then* fails — the multipart upload that ingested every byte and
    /// committed none. `BytesIn` must count those bytes (they were read);
    /// `BytesOut` must not (they never landed).
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

    /// Stream mode's unrecognized branch used to re-fetch the entire object
    /// with an unbounded `get` and only *then* consult the policy — so
    /// `skip`, which never looks at the bytes, paid a full in-memory
    /// download for nothing, on an object that reached the stream path
    /// precisely because it was too big to buffer.
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

    /// And `copy` streams the object across instead of buffering it. The
    /// discriminator is that `put_stream_progress()` — reset at the start of
    /// every `put_stream` call, so it reflects the copy and not the aborted
    /// filtering attempt that preceded it — equals the source length
    /// exactly. The old buffered copy used `put`, which never moves it.
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

        // One object, one `BytesIn` — even though this is the one path that
        // reads it twice (`stream_run` to discover it has no `Records`, then
        // the copy). Billing both reads made an unrecognized object above
        // `stream_threshold_bytes` report double the `BytesIn` of a
        // byte-identical object below it, so the ingest-vs-output
        // reconciliation an operator does with `BytesIn`/`BytesOut` came out
        // 2:1 for reasons that had nothing to do with what was written.
        assert_eq!(
            snapshots[0].bytes_in,
            body.len() as u64,
            "the copy re-reads bytes stream_run already billed; they must be counted once"
        );
    }

    /// A self-trigger (destination == source) is a hard, whole-batch failure
    /// on purpose — it is a deployment misconfiguration that would otherwise
    /// loop forever, and isolating it per-message would let the loop run. But
    /// it used to return without touching a single counter, so the only trace
    /// was the AWS `Errors` metric, which cannot distinguish it from a
    /// timeout, an OOM, or a permissions failure. It is an object-level
    /// failure and now counts as one.
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
