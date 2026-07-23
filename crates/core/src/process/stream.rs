//! Stream-mode processing (`SHARED.md`): decompress and filter the object
//! body incrementally, writing survivors straight to the destination via
//! `ObjectStore::put_stream` instead of buffering the whole object in memory.
//!
//! Trades buffer mode's "zero re-serialization" for constant memory: each
//! kept record is deserialized into an owned `Box<RawValue>` (not a borrowed
//! `&RawValue` slice into one big in-memory buffer) as it comes off the
//! reader, then re-written verbatim (`.get()`) into the output gzip stream.
//!
//! Architecture: three concurrent pieces, joined with `tokio::join!`:
//!   1. `pump_input` (plain async task): reads `input` in bounded chunks and
//!      forwards them over an `mpsc` channel — bridges the async input to
//!      the synchronous `Read` the decompressor/JSON parser need.
//!   2. `extract_records` (`spawn_blocking`): a `MultiGzDecoder` wrapping a
//!      synchronous adapter over that channel, feeding a
//!      `serde_json::Deserializer` that streams `Records` elements out as
//!      `Box<RawValue>` one at a time over a second `mpsc` channel — without
//!      ever materializing the whole array. Runs on its own blocking thread,
//!      touching no borrowed data (only owned channel endpoints), so it has
//!      no trouble satisfying `spawn_blocking`'s `'static` bound even though
//!      `Engine`/`Processing`/`Metrics` are all borrowed by `stream_run`.
//!   3. The `processing` block (plain async, in `stream_run`'s own task):
//!      receives records, runs `Engine::evaluate`, gzip-encodes survivors,
//!      and periodically drains the encoder's internal buffer into a third
//!      `mpsc` channel feeding `store.put_stream`'s body reader — this is
//!      what bounds *output* memory. Never calls `.flush()` on the encoder:
//!      an explicit flush would insert a DEFLATE sync-flush marker, making
//!      the compressed bytes differ from buffer mode's single unflushed
//!      write; draining the sink `Vec` instead doesn't touch encoder state,
//!      so the compressed byte stream stays identical to buffer mode's.
//!
//! Unrecognized objects and "every record dropped" (`SHARED.md`, "Unrecognized
//! objects in stream mode"): stream mode has already started `put_stream`
//! before it can know either of these, so it can't simply skip the call. It
//! aborts the upload instead by failing the *reader* `put_stream` is reading
//! from (delivering an `Err` instead of a clean EOF) — no new `ObjectStore`
//! port method is added for this.

use std::io::{self, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use flate2::Compression;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;
use serde::Deserializer as _;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use serde_json::value::RawValue;
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use tokio::sync::mpsc;

use super::Outcome;
use crate::config::Processing;
use crate::error::CoreError;
use crate::filter::{Decision, Engine};
use crate::metrics::Metrics;
use crate::model::PutMeta;
use crate::ports::ObjectStore;

const INPUT_CHUNK_BYTES: usize = 64 * 1024;
const INPUT_CHANNEL_CAPACITY: usize = 4;
const RECORD_CHANNEL_CAPACITY: usize = 16;
const OUTPUT_CHANNEL_CAPACITY: usize = 4;
/// Drain the gzip encoder's sink into the output channel once it holds at
/// least this many bytes — the knob that bounds output-side peak memory.
const OUTPUT_FLUSH_THRESHOLD: usize = 64 * 1024;

/// One chunk moving across the byte-oriented channels (input pump →
/// blocking decompressor, and processing → `put_stream`): either a chunk of
/// bytes, or the error that ends the stream (used deliberately, by us, to
/// trigger `put_stream`'s abort path).
type ByteMsg = io::Result<Bytes>;

/// One message from the blocking record-extraction task to the async
/// processing block.
enum StreamMsg {
    Record(Box<RawValue>),
    Finished(FinishKind),
}

/// How record extraction ended.
enum FinishKind {
    /// A `Records` array was present and (possibly partially) streamed.
    RecordsFound,
    /// Valid JSON, but no `Records` array (or `Records` wasn't an array).
    Unrecognized,
    /// Gzip or JSON syntax failure.
    Error(ParseFailure),
}

enum ParseFailure {
    Gzip(String),
    Json(String),
}

/// Reads an `mpsc::Receiver<ByteMsg>` synchronously — the bridge that lets a
/// blocking thread consume the async `input` pumped in from the caller's
/// task. `blocking_recv` needs no `Handle`/runtime and is safe to call from
/// a plain (non-Tokio) thread, which is exactly what `spawn_blocking` gives.
struct ChannelSyncRead {
    rx: mpsc::Receiver<ByteMsg>,
    pending: Bytes,
}

impl ChannelSyncRead {
    fn new(rx: mpsc::Receiver<ByteMsg>) -> Self {
        Self {
            rx,
            pending: Bytes::new(),
        }
    }
}

impl Read for ChannelSyncRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if !self.pending.is_empty() {
                let n = std::cmp::min(buf.len(), self.pending.len());
                let chunk = self.pending.split_to(n);
                buf[..n].copy_from_slice(&chunk);
                return Ok(n);
            }
            match self.rx.blocking_recv() {
                Some(Ok(bytes)) => self.pending = bytes,
                Some(Err(e)) => return Err(e),
                None => return Ok(0),
            }
        }
    }
}

/// The async-side mirror of `ChannelSyncRead`: an `AsyncRead` over an
/// `mpsc::Receiver<ByteMsg>`, used to hand `store.put_stream` a body that
/// the processing block feeds incrementally. An `Err` message is delivered
/// as a genuine read error rather than a clean EOF — the "fail the reader"
/// abort signal from `SHARED.md`.
struct ChannelAsyncRead {
    rx: mpsc::Receiver<ByteMsg>,
    pending: Bytes,
}

impl ChannelAsyncRead {
    fn new(rx: mpsc::Receiver<ByteMsg>) -> Self {
        Self {
            rx,
            pending: Bytes::new(),
        }
    }
}

impl AsyncRead for ChannelAsyncRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.pending.is_empty() {
                let n = std::cmp::min(buf.remaining(), this.pending.len());
                let chunk = this.pending.split_to(n);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            match this.rx.poll_recv(cx) {
                Poll::Ready(Some(Ok(bytes))) => this.pending = bytes,
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Reads `input` in bounded chunks and forwards them over `tx` — the async
/// side of the input bridge. Bounded by `INPUT_CHUNK_BYTES` regardless of
/// how much `input` would otherwise be willing to hand back in one `read`
/// call, which is what keeps input-side peak memory bounded.
async fn pump_input(mut input: Box<dyn AsyncRead + Send + Unpin>, tx: mpsc::Sender<ByteMsg>) {
    let mut buf = vec![0u8; INPUT_CHUNK_BYTES];
    loop {
        match input.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if tx
                    .send(Ok(Bytes::copy_from_slice(&buf[..n])))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                break;
            }
        }
    }
}

/// Streams the `Records` array's elements out over `tx` as owned
/// `Box<RawValue>`s without ever materializing the whole array — the
/// streaming-mode analogue of buffer mode's `Vec<&RawValue>`. Returns
/// whether a `Records` array was actually present and of array shape (vs.
/// present-but-wrong-shape or altogether absent, both `Unrecognized`).
struct RecordsSeed<'a> {
    tx: &'a mpsc::Sender<StreamMsg>,
}

impl<'de> DeserializeSeed<'de> for RecordsSeed<'_> {
    type Value = bool;

    fn deserialize<D>(self, deserializer: D) -> Result<bool, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(RecordsVisitor { tx: self.tx })
    }
}

struct RecordsVisitor<'a> {
    tx: &'a mpsc::Sender<StreamMsg>,
}

impl<'de> Visitor<'de> for RecordsVisitor<'_> {
    type Value = bool;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a Records array")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<bool, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(record) = seq.next_element::<Box<RawValue>>()? {
            if self.tx.blocking_send(StreamMsg::Record(record)).is_err() {
                return Err(de::Error::custom("stream_run: record consumer gone"));
            }
        }
        Ok(true)
    }

    // `Records` present but not an array shape: not a valid envelope, but
    // still parses fine as *some* JSON value — matches buffer mode's
    // fallback-to-`Value`-then-`Unrecognized` behavior for parity.
    fn visit_bool<E>(self, _v: bool) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_i64<E>(self, _v: i64) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_u64<E>(self, _v: u64) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_f64<E>(self, _v: f64) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_str<E>(self, _v: &str) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_unit<E>(self) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_map<A>(self, mut map: A) -> Result<bool, A::Error>
    where
        A: MapAccess<'de>,
    {
        while map
            .next_entry::<de::IgnoredAny, de::IgnoredAny>()?
            .is_some()
        {}
        Ok(false)
    }
}

/// Top-level envelope shape detector: streams `Records` (if present and an
/// array) via `RecordsSeed`, ignores every other key without allocating
/// (`serde::de::IgnoredAny`), and reports whether a `Records` array was
/// found — anything else (including a top-level JSON scalar/array) is
/// `Unrecognized`, matching buffer mode.
struct EnvelopeVisitor<'a> {
    tx: &'a mpsc::Sender<StreamMsg>,
}

impl<'de> Visitor<'de> for EnvelopeVisitor<'_> {
    type Value = bool;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON object, optionally with a Records array")
    }

    fn visit_map<A>(self, mut map: A) -> Result<bool, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut found = false;
        while let Some(key) = map.next_key::<String>()? {
            if key == "Records" {
                found = map.next_value_seed(RecordsSeed { tx: self.tx })?;
            } else {
                map.next_value::<de::IgnoredAny>()?;
            }
        }
        Ok(found)
    }

    fn visit_bool<E>(self, _v: bool) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_i64<E>(self, _v: i64) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_u64<E>(self, _v: u64) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_f64<E>(self, _v: f64) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_str<E>(self, _v: &str) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_unit<E>(self) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_seq<A>(self, mut seq: A) -> Result<bool, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while seq.next_element::<de::IgnoredAny>()?.is_some() {}
        Ok(false)
    }
}

/// Runs on `spawn_blocking`: `MultiGzDecoder` (never `GzDecoder` — see
/// `buffer.rs`) over `reader`, streaming `Records` elements out over `tx` as
/// they're parsed. Touches no borrowed data — only owned channel endpoints —
/// so it satisfies `spawn_blocking`'s `'static` bound without needing
/// `Engine`/`Processing`/`Metrics` to be `Clone`.
fn extract_records(reader: ChannelSyncRead, tx: mpsc::Sender<StreamMsg>) {
    let gz = MultiGzDecoder::new(reader);
    let mut deserializer = serde_json::Deserializer::from_reader(gz);
    let result = deserializer.deserialize_any(EnvelopeVisitor { tx: &tx });

    let finish = match result {
        Ok(true) => FinishKind::RecordsFound,
        Ok(false) => FinishKind::Unrecognized,
        Err(e) => {
            if e.is_io() {
                FinishKind::Error(ParseFailure::Gzip(e.to_string()))
            } else {
                FinishKind::Error(ParseFailure::Json(e.to_string()))
            }
        }
    };
    let _ = tx.blocking_send(StreamMsg::Finished(finish));
}

/// Stream-mode entry point (`SHARED.md`): decompress and filter `input`
/// incrementally, writing survivors directly to `dest_bucket`/`dest_key` via
/// `store.put_stream` rather than buffering the whole object.
///
/// Unlike `buffer_run`, this performs the write itself (its signature takes
/// a `store` and destination) — buffer mode instead hands its caller a
/// `Bytes` to `put`, because stream mode can't wait until the end to know
/// the destination is worth writing.
pub async fn stream_run(
    input: Box<dyn AsyncRead + Send + Unpin>,
    engine: &Engine,
    cfg: &Processing,
    metrics: &Metrics,
    store: &dyn ObjectStore,
    dest_bucket: &str,
    dest_key: &str,
) -> Result<Outcome, CoreError> {
    let (in_tx, in_rx) = mpsc::channel::<ByteMsg>(INPUT_CHANNEL_CAPACITY);
    let (raw_tx, mut raw_rx) = mpsc::channel::<StreamMsg>(RECORD_CHANNEL_CAPACITY);
    let (out_tx, out_rx) = mpsc::channel::<ByteMsg>(OUTPUT_CHANNEL_CAPACITY);

    let pump = pump_input(input, in_tx);
    let blocking =
        tokio::task::spawn_blocking(move || extract_records(ChannelSyncRead::new(in_rx), raw_tx));

    // Canonical output metadata (SHARED.md): gzipped CloudTrail JSON is
    // labelled exactly as the buffer path's `put` and the S3 adapter's tests
    // expect — `application/x-gzip` + `gzip` — so the destination bucket is
    // uniform regardless of which mode wrote a given object.
    let meta = PutMeta {
        content_type: "application/x-gzip",
        content_encoding: "gzip",
    };
    let upload = store.put_stream(
        dest_bucket,
        dest_key,
        Box::new(ChannelAsyncRead::new(out_rx)),
        meta,
    );

    // `move`: without it, `out_tx` is captured by reference (its `send`
    // calls only need `&self`), so the real `Sender` would stay alive in
    // `stream_run`'s own stack frame — never dropped, so `put_stream`'s
    // reader would never see a clean EOF and this would deadlock waiting
    // for a termination signal that can only arrive via that drop.
    let processing = async move {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::new(cfg.gzip_level));
        if let Err(e) = encoder.write_all(b"{\"Records\":[") {
            return Err(CoreError::Gzip(e.to_string()));
        }

        let mut first = true;
        let mut kept: u64 = 0;
        let mut records_in: u64 = 0;

        let finish = loop {
            match raw_rx.recv().await {
                Some(StreamMsg::Record(raw)) => {
                    records_in += 1;
                    let text = raw.get();
                    let keep = match serde_json::from_str::<Value>(text) {
                        Ok(value) => match engine.evaluate(&value) {
                            Decision::Keep => true,
                            Decision::Drop { rule_idx } => {
                                metrics.record_rule_drop(engine.rule_name(rule_idx));
                                false
                            }
                        },
                        Err(_) => {
                            // Unparseable individual record: kept, never
                            // dropped — parity with buffer_run.
                            metrics.add_parse_errors(1);
                            true
                        }
                    };

                    if keep {
                        let write_result: io::Result<()> = (|| {
                            if !first {
                                encoder.write_all(b",")?;
                            }
                            encoder.write_all(text.as_bytes())?;
                            Ok(())
                        })();
                        if let Err(e) = write_result {
                            metrics.add_records_in(records_in);
                            return Err(CoreError::Gzip(e.to_string()));
                        }
                        first = false;
                        kept += 1;
                    }

                    if encoder.get_ref().len() >= OUTPUT_FLUSH_THRESHOLD {
                        let chunk = std::mem::take(encoder.get_mut());
                        // If the consumer is already gone there is nothing
                        // further we can do about it here; the loop keeps
                        // draining `raw_rx` so the blocking producer never
                        // jams trying to send into a full channel.
                        let _ = out_tx.send(Ok(Bytes::from(chunk))).await;
                    }
                }
                Some(StreamMsg::Finished(kind)) => break kind,
                None => {
                    metrics.add_records_in(records_in);
                    return Err(CoreError::Json(
                        "stream_run: record producer ended without a Finished message".to_string(),
                    ));
                }
            }
        };

        metrics.add_records_in(records_in);

        match finish {
            FinishKind::RecordsFound if kept > 0 => {
                if let Err(e) = encoder.write_all(b"]}") {
                    let _ = out_tx
                        .send(Err(io::Error::other("aborting: gzip write failed")))
                        .await;
                    return Err(CoreError::Gzip(e.to_string()));
                }
                match encoder.finish() {
                    Ok(tail) => {
                        if !tail.is_empty() {
                            let _ = out_tx.send(Ok(Bytes::from(tail))).await;
                        }
                        metrics.add_records_kept(kept);
                        metrics.add_records_dropped(records_in - kept);
                        Ok(Outcome::Written(None))
                    }
                    Err(e) => {
                        let _ = out_tx
                            .send(Err(io::Error::other("aborting: gzip finish failed")))
                            .await;
                        Err(CoreError::Gzip(e.to_string()))
                    }
                }
            }
            FinishKind::RecordsFound => {
                // Every record was dropped, or `Records` was empty: stream
                // mode must never leave a zero-record object at the
                // destination ("never leave a zero-record object",
                // SHARED.md) — abort the upload instead of committing one.
                metrics.add_records_dropped(records_in);
                let _ = out_tx
                    .send(Err(io::Error::other("aborting: all records dropped")))
                    .await;
                Ok(Outcome::NothingKept)
            }
            FinishKind::Unrecognized => {
                let _ = out_tx
                    .send(Err(io::Error::other("aborting: no Records array")))
                    .await;
                Ok(Outcome::Unrecognized)
            }
            FinishKind::Error(failure) => {
                let _ = out_tx
                    .send(Err(io::Error::other("aborting: parse failure")))
                    .await;
                Err(match failure {
                    ParseFailure::Gzip(msg) => CoreError::Gzip(msg),
                    ParseFailure::Json(msg) => CoreError::Json(msg),
                })
            }
        }
    };

    let (_, blocking_result, processing_result, upload_result) =
        tokio::join!(pump, blocking, processing, upload);

    blocking_result.map_err(|e| {
        CoreError::Json(format!("stream_run: record extraction task panicked: {e}"))
    })?;

    let outcome = processing_result?;

    match &outcome {
        Outcome::Written(None) => {
            // The normal path: the upload must actually have succeeded.
            upload_result?;
        }
        Outcome::NothingKept | Outcome::Unrecognized => {
            // We deliberately failed the reader `put_stream` was reading
            // from; the `Err` it returns after aborting is expected, not a
            // real failure — swallow it (SHARED.md, "How the abort is
            // triggered without a new port method").
        }
        Outcome::Written(Some(_)) => {
            unreachable!("stream_run never returns Outcome::Written(Some(_))")
        }
    }

    Ok(outcome)
}

#[cfg(all(test, feature = "testing"))]
mod tests {
    use super::*;
    use crate::config::rules::RuleSet;
    use crate::process::buffer_run;
    use crate::testing::InMemoryStore;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicU64;

    fn engine_from_yaml(yaml: &[u8]) -> Engine {
        let rule_set = RuleSet::parse(yaml).expect("ruleset must parse");
        Engine::new(rule_set).expect("ruleset must compile")
    }

    fn no_op_engine() -> Engine {
        engine_from_yaml(b"version: 1.0.0\nrules: []\n")
    }

    fn drop_decrypt_engine() -> Engine {
        engine_from_yaml(
            br#"
version: 1.0.0
rules:
  - name: Drop Decrypt
    matches:
      - field_name: eventName
        regex: "^Decrypt$"
"#,
        )
    }

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

    fn reader_over(bytes: Vec<u8>) -> Box<dyn AsyncRead + Send + Unpin> {
        Box::new(std::io::Cursor::new(bytes))
    }

    #[tokio::test]
    async fn stream_run_output_is_byte_for_byte_equal_to_buffer_run() {
        let body = br#"{"Records":[
            {"eventName":"ConsoleLogin"},
            {"eventName":"Decrypt"},
            {"eventName":"AssumeRole"}
        ]}"#;
        let input = gzip_bytes(body);

        let buffered = buffer_run(
            &input,
            &drop_decrypt_engine(),
            &Processing::default(),
            &Metrics::default(),
        )
        .expect("buffer_run must succeed");
        let expected = match buffered {
            Outcome::Written(Some(b)) => b,
            other => panic!("expected Outcome::Written(Some(_)), got {other:?}"),
        };

        let store = InMemoryStore::new();
        let outcome = stream_run(
            reader_over(input),
            &drop_decrypt_engine(),
            &Processing::default(),
            &Metrics::default(),
            &store,
            "bucket",
            "dest",
        )
        .await
        .expect("stream_run must succeed");
        assert!(
            matches!(outcome, Outcome::Written(None)),
            "expected Written(None), got {outcome:?}"
        );

        let written = store
            .object("bucket", "dest")
            .expect("stream_run must have written to the destination key");
        assert_eq!(
            written, expected,
            "stream_run's output must be byte-for-byte identical to buffer_run's on the same \
             fixture"
        );
    }

    #[tokio::test]
    async fn unrecognized_shape_aborts_the_upload_and_leaves_the_destination_empty() {
        let body = br#"{"foo":"bar"}"#;
        let input = gzip_bytes(body);

        let store = InMemoryStore::new();
        let outcome = stream_run(
            reader_over(input),
            &no_op_engine(),
            &Processing::default(),
            &Metrics::default(),
            &store,
            "bucket",
            "dest",
        )
        .await
        .expect("an unrecognized shape must not be an error");

        assert!(
            matches!(outcome, Outcome::Unrecognized),
            "expected Unrecognized, got {outcome:?}"
        );
        assert!(
            !store.contains("bucket", "dest"),
            "an unrecognized-shape object must leave the destination key holding nothing"
        );
    }

    #[tokio::test]
    async fn all_records_dropped_aborts_the_upload_and_leaves_the_destination_empty() {
        let body = br#"{"Records":[{"eventName":"Decrypt"},{"eventName":"Decrypt"}]}"#;
        let input = gzip_bytes(body);

        let store = InMemoryStore::new();
        let outcome = stream_run(
            reader_over(input),
            &drop_decrypt_engine(),
            &Processing::default(),
            &Metrics::default(),
            &store,
            "bucket",
            "dest",
        )
        .await
        .expect("all-dropped must not be an error");

        assert!(
            matches!(outcome, Outcome::NothingKept),
            "expected NothingKept, got {outcome:?}"
        );
        assert!(
            !store.contains("bucket", "dest"),
            "stream mode must never leave a zero-record object at the destination"
        );
    }

    #[tokio::test]
    async fn empty_records_array_also_leaves_the_destination_empty() {
        let body = br#"{"Records":[]}"#;
        let input = gzip_bytes(body);

        let store = InMemoryStore::new();
        let outcome = stream_run(
            reader_over(input),
            &no_op_engine(),
            &Processing::default(),
            &Metrics::default(),
            &store,
            "bucket",
            "dest",
        )
        .await
        .expect("empty Records must not be an error");

        assert!(matches!(outcome, Outcome::NothingKept), "got {outcome:?}");
        assert!(!store.contains("bucket", "dest"));
    }

    /// An `AsyncRead` that records the size of every chunk `read()` actually
    /// filled, and tracks cumulative bytes delivered so far — the input-side
    /// half of the peak-buffer proof below.
    struct TrackingReader {
        inner: std::io::Cursor<Vec<u8>>,
        delivered: Arc<AtomicU64>,
        max_chunk: Arc<AtomicU64>,
    }

    impl AsyncRead for TrackingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let before = buf.filled().len();
            let inner = Pin::new(&mut this.inner);
            let result = inner.poll_read(cx, buf);
            if let Poll::Ready(Ok(())) = result {
                let n = (buf.filled().len() - before) as u64;
                this.delivered.fetch_add(n, Ordering::SeqCst);
                this.max_chunk.fetch_max(n, Ordering::SeqCst);
            }
            result
        }
    }

    use std::sync::atomic::Ordering;

    /// A tiny deterministic PRNG (splitmix64) — used only to give each
    /// synthetic record enough per-record entropy that gzip can't collapse
    /// the whole corpus down to near-nothing via long back-references,
    /// which would otherwise make the compressed output so small that it
    /// never crosses `OUTPUT_FLUSH_THRESHOLD` until the very last record,
    /// masking whether output actually streams incrementally.
    fn splitmix64(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = *seed;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    fn hex_token(seed: &mut u64) -> String {
        format!("{:016x}{:016x}", splitmix64(seed), splitmix64(seed))
    }

    #[tokio::test]
    async fn peak_buffer_stays_bounded_on_a_large_synthetic_object() {
        const RECORD_COUNT: usize = 60_000;

        let mut seed = 0x1234_5678_9abc_def0_u64;
        let mut body = String::from(r#"{"Records":["#);
        for i in 0..RECORD_COUNT {
            if i > 0 {
                body.push(',');
            }
            let token = hex_token(&mut seed);
            body.push_str(&format!(
                r#"{{"eventName":"E{i}","eventSource":"x{i}.amazonaws.com","requestID":"{token}"}}"#
            ));
        }
        body.push_str("]}");
        let compressed = gzip_bytes(body.as_bytes());
        let total_input_len = compressed.len() as u64;

        let delivered = Arc::new(AtomicU64::new(0));
        let max_input_chunk = Arc::new(AtomicU64::new(0));
        let tracking_reader = TrackingReader {
            inner: std::io::Cursor::new(compressed),
            delivered: delivered.clone(),
            max_chunk: max_input_chunk.clone(),
        };

        let store = InMemoryStore::new();
        let engine = no_op_engine();
        let cfg = Processing::default();
        let metrics = Metrics::default();

        let done = Arc::new(AtomicBool::new(false));
        let done_writer = done.clone();

        let run_fut = async {
            let result = stream_run(
                Box::new(tracking_reader),
                &engine,
                &cfg,
                &metrics,
                &store,
                "bucket",
                "dest",
            )
            .await;
            done_writer.store(true, Ordering::SeqCst);
            result
        };

        let mut saw_interleaving = false;
        let sampler = async {
            while !done.load(Ordering::SeqCst) {
                let input_now = delivered.load(Ordering::SeqCst);
                let output_now = store.put_stream_progress();
                if output_now > 0 && input_now < total_input_len {
                    saw_interleaving = true;
                }
                tokio::time::sleep(std::time::Duration::from_micros(100)).await;
            }
        };

        let (result, ()) = tokio::join!(run_fut, sampler);
        let outcome = result.expect("must succeed on a large well-formed object");
        assert!(
            matches!(outcome, Outcome::Written(None)),
            "expected Written(None), got {outcome:?}"
        );

        assert!(
            max_input_chunk.load(Ordering::SeqCst) <= INPUT_CHUNK_BYTES as u64,
            "stream_run must read input in bounded chunks, saw a chunk of {} bytes (cap {})",
            max_input_chunk.load(Ordering::SeqCst),
            INPUT_CHUNK_BYTES
        );
        assert!(
            saw_interleaving,
            "expected output to start flowing to the store before all input was consumed \
             (proves the whole object isn't buffered before any of it is written)"
        );

        let written = store
            .object("bucket", "dest")
            .expect("must have written the survivors");
        let out = gunzip(&written);
        let parsed: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            parsed["Records"].as_array().unwrap().len(),
            RECORD_COUNT,
            "every record must have been kept by the no-op engine"
        );
    }
}
