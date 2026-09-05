//! Stream-mode processing: decompress and filter the object body incrementally,
//! writing survivors straight to `ObjectStore::put_stream` instead of buffering.
//!
//! Three concurrent pieces joined with `tokio::join!`: `pump_input` bridges the
//! async input onto a channel, `extract_records` (`spawn_blocking`) decompresses
//! and streams `Records` elements out as owned `Box<RawValue>`, and the
//! `processing` block evaluates them and feeds `put_stream`'s body reader.
//!
//! The encoder is never `.flush()`ed — that would insert a DEFLATE sync-flush
//! marker and make the compressed bytes differ from buffer mode's; draining the
//! sink `Vec` leaves encoder state untouched.
//!
//! An upload that must not commit (unrecognized object, every record dropped,
//! any error) is aborted by failing the *reader* `put_stream` reads from, since
//! the call is already in flight by the time the outcome is known.

use std::io::{self, Read, Write};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use bytes::Bytes;
use flate2::Compression;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;
use serde::Deserializer as _;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
#[cfg(all(test, feature = "testing"))]
use serde_json::Value;
use serde_json::value::RawValue;
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use tokio::sync::mpsc;

use super::{Outcome, RecordTally};
use crate::config::Processing;
use crate::error::{CoreError, StoreError};
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

/// One chunk on the byte-oriented channels: bytes, or the error that ends the
/// stream (used deliberately to trigger `put_stream`'s abort path).
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
    /// The input body itself failed to read. Indistinguishable from a corrupt
    /// member once `serde_json` has wrapped it, hence the out-of-band flag.
    Transport(String),
}

/// Reads an `mpsc::Receiver<ByteMsg>` synchronously, letting the blocking
/// decompressor consume input pumped in from the caller's task.
struct ChannelSyncRead {
    rx: mpsc::Receiver<ByteMsg>,
    pending: Bytes,
    transport_error: Arc<OnceLock<String>>,
}

impl ChannelSyncRead {
    fn new(rx: mpsc::Receiver<ByteMsg>) -> Self {
        Self {
            rx,
            pending: Bytes::new(),
            transport_error: Arc::new(OnceLock::new()),
        }
    }
}

impl Read for ChannelSyncRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // `Read`'s contract requires `Ok(0)` here and it is not EOF, but
        // reaching it via the loop below would first consume a chunk into
        // `pending` — indistinguishable from EOF to the caller, which would
        // stop reading and silently truncate the object.
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if !self.pending.is_empty() {
                let n = std::cmp::min(buf.len(), self.pending.len());
                let chunk = self.pending.split_to(n);
                buf[..n].copy_from_slice(&chunk);
                return Ok(n);
            }
            match self.rx.blocking_recv() {
                Some(Ok(bytes)) => self.pending = bytes,
                Some(Err(e)) => {
                    let _ = self.transport_error.set(e.to_string());
                    return Err(e);
                }
                None => return Ok(0),
            }
        }
    }
}

/// The async mirror of `ChannelSyncRead`, feeding `store.put_stream` a body
/// incrementally. An `Err` message becomes a genuine read error rather than a
/// clean EOF — the "fail the reader" abort signal.
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
        // `Poll::Ready(Ok(()))` having filled nothing is tokio's EOF signal,
        // so a no-capacity `ReadBuf` must be answered without consuming a
        // chunk — falling through would report EOF mid-object.
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
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

/// Reads `input` in bounded `INPUT_CHUNK_BYTES` chunks and forwards them over
/// `tx`, which is what bounds input-side peak memory.
///
/// Also where stream mode accounts `BytesIn`: the object is never fully
/// materialized, so the counter is fed chunk by chunk as bytes are ingested.
async fn pump_input(
    mut input: Box<dyn AsyncRead + Send + Unpin>,
    tx: mpsc::Sender<ByteMsg>,
    metrics: &Metrics,
) {
    let mut buf = vec![0u8; INPUT_CHUNK_BYTES];
    loop {
        match input.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                metrics.add_bytes_in(n as u64);
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

/// Streams the `Records` array's elements over `tx` as owned `Box<RawValue>`s
/// without materializing the array. Returns whether a `Records` array was
/// present and of array shape.
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

    // `Records` present but not an array: still parses as *some* JSON value,
    // matching buffer mode's fallback-to-`Value`-then-`Unrecognized`.
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

/// Top-level envelope shape detector: streams `Records` via `RecordsSeed`,
/// ignores every other key without allocating, and reports whether a `Records`
/// array was found. Anything else is `Unrecognized`, matching buffer mode — a
/// *repeated* `Records` key included, because buffer mode's derived `Envelope`
/// rejects a duplicate field outright.
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
        let mut records_keys = 0usize;
        while let Some(key) = map.next_key::<String>()? {
            if key == "Records" {
                records_keys += 1;
                // Only the first array is streamed; a second is consumed and
                // discarded, and `records_keys == 1` below makes the object
                // `Unrecognized`, which aborts the in-flight upload.
                if records_keys == 1 {
                    found = map.next_value_seed(RecordsSeed { tx: self.tx })?;
                } else {
                    map.next_value::<de::IgnoredAny>()?;
                }
            } else {
                map.next_value::<de::IgnoredAny>()?;
            }
        }
        Ok(found && records_keys == 1)
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
/// `buffer.rs`) over `reader`, streaming `Records` elements over `tx`. Touches
/// only owned channel endpoints, satisfying `spawn_blocking`'s `'static` bound.
fn extract_records(reader: ChannelSyncRead, tx: mpsc::Sender<StreamMsg>) {
    let transport_error = Arc::clone(&reader.transport_error);
    let gz = MultiGzDecoder::new(reader);
    let mut deserializer = serde_json::Deserializer::from_reader(gz);
    let parsed = deserializer.deserialize_any(EnvelopeVisitor { tx: &tx });

    // `end()` is what makes stream mode's integrity checking equal to buffer
    // mode's. Parsing stops at the top-level `}`, so without it a second
    // concatenated envelope is never looked at, and the reader is never driven
    // to EOF — so `MultiGzDecoder` never checks the member's CRC32/ISIZE and a
    // truncated upload with complete JSON passes. Trailing whitespace still
    // passes. Runs *before* the `Finished` send, so an envelope whose records
    // were already streamed still ends in `FinishKind::Error`.
    let result = parsed.and_then(|found| deserializer.end().map(|()| found));

    let finish = match result {
        Ok(true) => FinishKind::RecordsFound,
        Ok(false) => FinishKind::Unrecognized,
        // The transport check precedes `is_io()`: a failed `GetObject` body
        // reaches `serde_json` as an io error indistinguishable from a corrupt
        // gzip member, and `Gzip` is a class `on_parse_error: copy` fails open on.
        Err(e) => match transport_error.get() {
            Some(msg) => FinishKind::Error(ParseFailure::Transport(msg.clone())),
            None if e.is_io() => FinishKind::Error(ParseFailure::Gzip(e.to_string())),
            None => FinishKind::Error(ParseFailure::Json(e.to_string())),
        },
    };
    let _ = tx.blocking_send(StreamMsg::Finished(finish));
}

/// Stream-mode entry point: decompress and filter `input` incrementally,
/// writing survivors directly to `dest_bucket`/`dest_key`.
///
/// Unlike `buffer_run` this performs the write itself — it cannot wait until
/// the end to know the destination is worth writing — and therefore commits its
/// own [`RecordTally`], once `put_stream` has returned.
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

    let pump = pump_input(input, in_tx, metrics);
    let blocking =
        tokio::task::spawn_blocking(move || extract_records(ChannelSyncRead::new(in_rx), raw_tx));

    // Labelled exactly as the buffer path's `put`, so the destination bucket
    // is uniform regardless of which mode wrote a given object.
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

    // `move`: captured by reference, the real `Sender` would outlive this
    // block in `stream_run`'s frame, so `put_stream`'s reader would never see
    // the clean EOF that only the drop can deliver, and this would deadlock.
    let processing = async move {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::new(cfg.gzip_level));
        if let Err(e) = encoder.write_all(b"{\"Records\":[") {
            // Dropping `out_tx` alone is a clean EOF, which `put_stream` commits.
            let _ = out_tx
                .send(Err(io::Error::other("aborting: gzip write failed")))
                .await;
            return Err(CoreError::Internal(e.to_string()));
        }

        let mut first = true;
        // Tallied locally and committed in one place — `stream_run`, past
        // `upload_result?`. Counting as it went published drops and parse
        // errors for objects that then failed and were re-driven whole.
        let mut tally = RecordTally::default();
        // Compressed bytes handed to `put_stream` so far. Every non-`Written`
        // outcome aborts the upload, so this is billed to `BytesOut` only after
        // `upload_result?` proves the write landed.
        let mut bytes_out: u64 = 0;

        let finish = loop {
            match raw_rx.recv().await {
                Some(StreamMsg::Record(raw)) => {
                    tally.record_in();
                    let text = raw.get();
                    let keep = match engine.evaluate_raw(text) {
                        Ok(Decision::Keep) => true,
                        Ok(Decision::Drop { rule_idx }) => {
                            tally.drop_by_rule(rule_idx);
                            false
                        }
                        Err(_) => {
                            // Unparseable individual record: kept, never
                            // dropped — parity with buffer_run.
                            tally.parse_error();
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
                            // Abort before returning: dropping `out_tx` alone
                            // is a clean EOF, so `put_stream` would complete
                            // the upload and commit an object with no `]}` and
                            // no gzip trailer.
                            let _ = out_tx
                                .send(Err(io::Error::other("aborting: gzip write failed")))
                                .await;
                            return Err(CoreError::Internal(e.to_string()));
                        }
                        first = false;
                        tally.keep();
                    }

                    if encoder.get_ref().len() >= OUTPUT_FLUSH_THRESHOLD {
                        let chunk = std::mem::take(encoder.get_mut());
                        bytes_out += chunk.len() as u64;
                        // The loop keeps draining `raw_rx` even with no
                        // consumer, so the blocking producer never jams.
                        let _ = out_tx.send(Ok(Bytes::from(chunk))).await;
                    }
                }
                Some(StreamMsg::Finished(kind)) => break kind,
                None => {
                    // The extraction task panicked. Without the sentinel this
                    // is a clean EOF, and `put_stream` commits a truncated
                    // object.
                    let _ = out_tx
                        .send(Err(io::Error::other("aborting: record producer vanished")))
                        .await;
                    return Err(CoreError::Internal(
                        "stream_run: record producer ended without a Finished message".to_string(),
                    ));
                }
            }
        };

        // The tally leaves here and is reported in exactly one place:
        // `stream_run`, once `upload_result?` has proven the object's fate.
        // Reporting `RecordsIn` here made an unrecognized or malformed object
        // publish `RecordsIn > 0` with kept and dropped both zero, where buffer
        // mode reports 0/0/0 — breaking `RecordsIn == RecordsKept +
        // RecordsDropped` in one mode only. See `MetricSnapshot::records_balance`
        // and the metric-parity cases in `tests/mode_parity.rs`.
        match finish {
            FinishKind::RecordsFound if tally.kept_count() > 0 => {
                if let Err(e) = encoder.write_all(b"]}") {
                    let _ = out_tx
                        .send(Err(io::Error::other("aborting: gzip write failed")))
                        .await;
                    return Err(CoreError::Internal(e.to_string()));
                }
                match encoder.finish() {
                    Ok(tail) => {
                        if !tail.is_empty() {
                            bytes_out += tail.len() as u64;
                            let _ = out_tx.send(Ok(Bytes::from(tail))).await;
                        }
                        Ok((Outcome::Written(None), bytes_out, tally))
                    }
                    Err(e) => {
                        let _ = out_tx
                            .send(Err(io::Error::other("aborting: gzip finish failed")))
                            .await;
                        Err(CoreError::Internal(e.to_string()))
                    }
                }
            }
            FinishKind::RecordsFound => {
                // Every record dropped, or `Records` empty: abort rather than
                // leave a zero-record object at the destination. The tally is
                // still committed — writing nothing is the correct outcome, not
                // a failure — and `kept == 0` makes `RecordsDropped ==
                // RecordsIn`.
                let _ = out_tx
                    .send(Err(io::Error::other("aborting: all records dropped")))
                    .await;
                Ok((Outcome::NothingKept, 0, tally))
            }
            FinishKind::Unrecognized => {
                let _ = out_tx
                    .send(Err(io::Error::other("aborting: no Records array")))
                    .await;
                // Discarded, not committed. An object is ruled unrecognized
                // only after some records were already emitted and counted
                // (`{"Records":[…],"Records":[…]}`), and buffer mode reports
                // 0/0/0 for the same bytes.
                Ok((Outcome::Unrecognized, 0, RecordTally::default()))
            }
            FinishKind::Error(failure) => {
                let _ = out_tx
                    .send(Err(io::Error::other("aborting: parse failure")))
                    .await;
                Err(match failure {
                    ParseFailure::Gzip(msg) => CoreError::Gzip(msg),
                    ParseFailure::Json(msg) => CoreError::Json(msg),
                    // Buffer mode raises the same variant for the same failure
                    // (`fetch_with_missing_policy`), so both modes retry.
                    ParseFailure::Transport(msg) => CoreError::Store(StoreError::Backend(format!(
                        "reading source object: {msg}"
                    ))),
                })
            }
        }
    };

    let (_, blocking_result, processing_result, upload_result) =
        tokio::join!(pump, blocking, processing, upload);

    blocking_result.map_err(|e| {
        CoreError::Internal(format!("stream_run: record extraction task panicked: {e}"))
    })?;

    let (outcome, bytes_out, tally) = processing_result?;

    match &outcome {
        Outcome::Written(None) => {
            // The normal path: the upload must actually have succeeded.
            upload_result?;
            // Only now are the bytes at the destination: counting them inside
            // the processing block would bill a failed upload to `BytesOut`.
            metrics.add_bytes_out(bytes_out);
        }
        Outcome::NothingKept | Outcome::Unrecognized => {
            // We deliberately failed the reader; the `Err` `put_stream`
            // returns after aborting is expected, not a real failure.
        }
        Outcome::Written(Some(_)) => {
            unreachable!("stream_run never returns Outcome::Written(Some(_))")
        }
    }

    // Past every `?`, `upload_result?` included: the object's fate is decided,
    // so its records may be published. Returning early counts nothing and
    // leaves the redelivery to re-count the object whole.
    tally.commit(metrics, engine);

    Ok(outcome)
}

#[cfg(all(test, feature = "testing"))]
mod tests {
    use super::*;
    use crate::config::rules::RuleSet;
    use crate::error::StoreError;
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

        let (buffered, _tally) = buffer_run(&input, &drop_decrypt_engine(), &Processing::default())
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

    #[test]
    fn sync_reader_zero_length_read_does_not_consume_from_the_channel() {
        let (tx, rx) = mpsc::channel::<ByteMsg>(4);
        let mut reader = ChannelSyncRead::new(rx);
        let (done_tx, done_rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let n = reader
                .read(&mut [])
                .expect("a zero-length read is not an error");
            let _ = done_tx.send(n);
            // Hold the reader (and so the channel) open until the test ends.
            drop(reader);
        });

        // Nothing is ever sent on `tx`: without the guard the thread parks in
        // `blocking_recv` and this times out. Sending a chunk would mask the
        // bug, since the buggy path also returns `Ok(0)` once one arrives.
        let n = done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect(
                "a zero-length read must return immediately instead of blocking on a chunk the \
                 caller has no room for",
            );
        assert_eq!(n, 0, "a zero-length read reports zero bytes");
        drop(tx);
    }

    #[tokio::test]
    async fn async_reader_zero_capacity_read_does_not_consume_from_the_channel() {
        let (tx, rx) = mpsc::channel::<ByteMsg>(4);
        let mut reader = ChannelAsyncRead::new(rx);

        let n = tokio::time::timeout(std::time::Duration::from_secs(5), reader.read(&mut []))
            .await
            .expect(
                "a no-capacity read must return immediately instead of awaiting a chunk the \
                 caller has no room for",
            )
            .expect("a no-capacity read is not an error");
        assert_eq!(n, 0, "a no-capacity read reports zero bytes");

        tx.send(Ok(Bytes::from_static(b"payload")))
            .await
            .expect("receiver is alive");
        drop(tx);

        let mut rest = Vec::new();
        reader
            .read_to_end(&mut rest)
            .await
            .expect("the rest of the stream must still be readable");
        assert_eq!(
            rest, b"payload",
            "the no-capacity read must not have swallowed any of the stream"
        );
    }

    #[tokio::test]
    async fn stream_run_accounts_bytes_in_and_bytes_out() {
        let body = br#"{"Records":[
            {"eventName":"ConsoleLogin"},
            {"eventName":"Decrypt"},
            {"eventName":"AssumeRole"}
        ]}"#;
        let input = gzip_bytes(body);

        let store = InMemoryStore::new();
        let metrics = Metrics::default();
        stream_run(
            reader_over(input.clone()),
            &drop_decrypt_engine(),
            &Processing::default(),
            &metrics,
            &store,
            "bucket",
            "dest",
        )
        .await
        .expect("stream_run must succeed");

        let written = store
            .object("bucket", "dest")
            .expect("stream_run must have written to the destination key");
        let snapshot = metrics.snapshot_and_reset();
        assert_eq!(
            snapshot.bytes_in,
            input.len() as u64,
            "BytesIn must equal the compressed bytes read from the source"
        );
        assert_eq!(
            snapshot.bytes_out,
            written.len() as u64,
            "BytesOut must equal the compressed bytes actually committed to the destination"
        );
    }

    #[tokio::test]
    async fn an_aborted_upload_reports_bytes_in_but_no_bytes_out() {
        let body = br#"{"Records":[{"eventName":"Decrypt"}]}"#;
        let input = gzip_bytes(body);

        let store = InMemoryStore::new();
        let metrics = Metrics::default();
        let outcome = stream_run(
            reader_over(input.clone()),
            &drop_decrypt_engine(),
            &Processing::default(),
            &metrics,
            &store,
            "bucket",
            "dest",
        )
        .await
        .expect("dropping every record is not an error");
        assert!(
            matches!(outcome, Outcome::NothingKept),
            "expected NothingKept, got {outcome:?}"
        );

        let snapshot = metrics.snapshot_and_reset();
        assert_eq!(
            snapshot.bytes_in,
            input.len() as u64,
            "the bytes were still read, so BytesIn must count them"
        );
        assert_eq!(
            snapshot.bytes_out, 0,
            "an aborted upload writes nothing, so BytesOut must stay zero"
        );
    }

    /// Reads the whole body and *then* rejects the write, so the processing
    /// block reaches its success arm and hands over every byte before anything
    /// fails — a real `CompleteMultipartUpload` failure, not a deliberate abort.
    struct RejectingStore;

    #[async_trait::async_trait]
    impl ObjectStore for RejectingStore {
        async fn get(&self, _b: &str, _k: &str) -> Result<Bytes, StoreError> {
            unimplemented!("stream_run never gets through this store")
        }

        async fn get_stream(
            &self,
            _b: &str,
            _k: &str,
        ) -> Result<Box<dyn AsyncRead + Send + Unpin>, StoreError> {
            unimplemented!("stream_run never gets through this store")
        }

        async fn put(
            &self,
            _b: &str,
            _k: &str,
            _body: Bytes,
            _meta: PutMeta,
        ) -> Result<(), StoreError> {
            unimplemented!("stream mode never calls put")
        }

        async fn put_stream(
            &self,
            _b: &str,
            _k: &str,
            mut body: Box<dyn AsyncRead + Send + Unpin>,
            _meta: PutMeta,
        ) -> Result<(), StoreError> {
            // Drain first, so the failure is "the store said no", not "the
            // reader was never read".
            let mut sink = Vec::new();
            body.read_to_end(&mut sink)
                .await
                .expect("the reader must deliver a clean EOF in this test");
            assert!(!sink.is_empty(), "the encoder must have produced bytes");
            Err(StoreError::Backend("upload rejected".to_string()))
        }
    }

    #[tokio::test]
    async fn a_failing_upload_publishes_no_record_counters() {
        let input = gzip_bytes(
            br#"{"Records":[{"eventName":"ConsoleLogin"},{"eventName":"Decrypt"},{"broken":"\uD800"}]}"#,
        );
        let metrics = Metrics::default();

        stream_run(
            reader_over(input),
            &drop_decrypt_engine(),
            &Processing::default(),
            &metrics,
            &RejectingStore,
            "bucket",
            "dest",
        )
        .await
        .expect_err("a rejected upload must surface as an error");

        let snapshot = metrics.snapshot_and_reset();
        assert_eq!(
            (
                snapshot.records_in,
                snapshot.records_kept,
                snapshot.records_dropped,
                snapshot.parse_errors,
            ),
            (0, 0, 0, 0),
            "the object never landed, so none of its records may be counted — \
             the redelivery re-evaluates it whole and would count them twice"
        );
        assert!(
            snapshot.rule_drops.is_empty(),
            "a drop attributed to a rule for an object that was never written \
             is a drop that did not happen, got {:?}",
            snapshot.rule_drops
        );
    }

    #[tokio::test]
    async fn a_failing_upload_reports_no_bytes_out() {
        let input = gzip_bytes(br#"{"Records":[{"eventName":"ConsoleLogin"}]}"#);
        let metrics = Metrics::default();
        let error = stream_run(
            reader_over(input.clone()),
            &no_op_engine(),
            &Processing::default(),
            &metrics,
            &RejectingStore,
            "bucket",
            "dest",
        )
        .await
        .expect_err("a rejected upload must surface as an error");
        assert!(
            matches!(error, CoreError::Store(_)),
            "expected the store error to propagate, got {error:?}"
        );

        let snapshot = metrics.snapshot_and_reset();
        assert_eq!(
            snapshot.bytes_in,
            input.len() as u64,
            "the bytes were read, so BytesIn must count them"
        );
        assert_eq!(
            snapshot.bytes_out, 0,
            "the write failed, so nothing reached the destination and \
             BytesOut must stay zero"
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

    /// An `AsyncRead` that delivers `prefix` and then fails, standing in for a
    /// connection reset or a throttle part-way through `GetObject`'s body.
    struct TruncatingReader {
        prefix: std::io::Cursor<Vec<u8>>,
    }

    impl AsyncRead for TruncatingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.prefix.position() as usize == this.prefix.get_ref().len() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "connection reset by peer",
                )));
            }
            Pin::new(&mut this.prefix).poll_read(cx, buf)
        }
    }

    /// Falsifiable: classify this as `Gzip` and `on_parse_error: copy` fails
    /// open on a transient S3 read, copying the unfiltered source verbatim.
    #[tokio::test]
    async fn a_read_failure_mid_body_is_a_store_error_not_a_parse_failure() {
        let (body, _) = {
            let body = br#"{"Records":[{"eventName":"ConsoleLogin"}]}"#.to_vec();
            (gzip_bytes(&body), ())
        };
        // Enough bytes to get past the gzip header, then the reset.
        let prefix = body[..body.len() / 2].to_vec();
        let store = InMemoryStore::new();
        let metrics = Metrics::default();
        let cfg = Processing::default();

        let err = stream_run(
            Box::new(TruncatingReader {
                prefix: std::io::Cursor::new(prefix),
            }),
            &no_op_engine(),
            &cfg,
            &metrics,
            &store,
            "bucket",
            "dest",
        )
        .await
        .expect_err("a reset mid-body must fail the object");

        assert!(
            matches!(err, CoreError::Store(StoreError::Backend(_))),
            "got {err:?}"
        );
        assert!(
            !err.is_unparsable_source(),
            "a transport failure must never fail open"
        );
    }

    /// An `AsyncRead` recording the size of every chunk `read()` filled and the
    /// cumulative bytes delivered — the input half of the peak-buffer proof.
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

    /// Gives each synthetic record enough entropy that gzip cannot collapse the
    /// corpus via long back-references, which would keep the compressed output
    /// under `OUTPUT_FLUSH_THRESHOLD` until the last record and mask whether
    /// output streams incrementally.
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

    #[test]
    fn gzencoder_flush_changes_output_bytes() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let body = b"{\"Records\":[{\"eventName\":\"A\"},{\"eventName\":\"B\"}]}";

        let mut plain = GzEncoder::new(Vec::new(), Compression::new(6));
        plain.write_all(body).expect("write");
        let plain = plain.finish().expect("finish");

        let mut flushed = GzEncoder::new(Vec::new(), Compression::new(6));
        flushed.write_all(&body[..20]).expect("write");
        flushed.flush().expect("flush");
        flushed.write_all(&body[20..]).expect("write");
        let flushed = flushed.finish().expect("finish");

        assert_ne!(
            plain, flushed,
            "flush must remain observable: if these are equal, the no-flush \
             invariant in this module's docs is no longer load-bearing and the \
             buffer/stream byte-parity guarantee needs re-deriving"
        );
    }

    #[test]
    fn gzencoder_write_granularity_does_not_change_output_bytes() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let mut body: Vec<u8> = Vec::new();
        for i in 0..8192u32 {
            body.extend_from_slice(format!("{{\"n\":{i}}},").as_bytes());
        }

        for level in 0..=9u32 {
            let mut one = GzEncoder::new(Vec::new(), Compression::new(level));
            one.write_all(&body).expect("write");
            let one = one.finish().expect("finish");

            let mut many = GzEncoder::new(Vec::new(), Compression::new(level));
            for chunk in body.chunks(97) {
                many.write_all(chunk).expect("write");
            }
            let many = many.finish().expect("finish");

            assert_eq!(
                one, many,
                "write granularity changed output at level {level}"
            );
        }
    }
}
