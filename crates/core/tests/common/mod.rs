//! The shared buffer/stream parity oracle.
//!
//! `processing.mode: auto` routes an object to buffer or stream mode purely on
//! its *compressed size* vs. `stream_threshold_bytes`. That makes mode a
//! deployment detail, not a semantic one: the same bytes must produce the same
//! decision, the same destination payload, the same error classification and
//! the same counters either way. [`assert_parity`] is the single place that
//! claim is checked, so a divergence fails identically no matter which test
//! file noticed it.
//!
//! Two files drive it: `mode_parity.rs` with minimal hand-built envelopes that
//! isolate one structural property each, and `corpus_parity.rs` with realistic
//! CloudTrail records from `core::testing::corpus`. Same oracle, different
//! inputs — the synthetic cases pin the edges, the corpus pins the shapes
//! production actually emits.
//!
//! Not every consumer uses every helper; `dead_code` is allowed rather than
//! splitting the harness to match whichever file happens to need less.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::sync::Arc;

use cloudtrail_rs_core::config::{Processing, RuleSet};
use cloudtrail_rs_core::error::CoreError;
use cloudtrail_rs_core::filter::Engine;
use cloudtrail_rs_core::metrics::Metrics;
use cloudtrail_rs_core::model::MetricSnapshot;
use cloudtrail_rs_core::process::{Outcome, buffer_run, stream_run};
use cloudtrail_rs_core::testing::InMemoryStore;
use flate2::Compression;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;

pub const DEST_BUCKET: &str = "dest";
pub const DEST_KEY: &str = "logs/object.json.gz";

pub fn gzip(body: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(6));
    encoder.write_all(body).expect("fixture must compress");
    encoder.finish().expect("fixture must compress")
}

pub fn gunzip(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    MultiGzDecoder::new(input)
        .read_to_end(&mut out)
        .expect("output must be valid gzip");
    out
}

pub fn no_op_engine() -> Engine {
    engine(b"version: 1.0.0\nrules: []\n")
}

pub fn engine(yaml: &[u8]) -> Engine {
    Engine::new(RuleSet::parse(yaml).expect("ruleset must parse")).expect("ruleset must compile")
}

pub fn drop_decrypt_engine() -> Engine {
    engine(
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

/// Both modes' observable results, projected onto one comparable value.
///
/// `Written` holds the **decompressed** destination payload: that is the
/// data-integrity claim (which records survived, byte-for-byte), independent
/// of how each mode happened to frame its gzip writes. Errors compare by
/// *variant*, not message — buffer and stream reach the same classification
/// through different code (`decompress_capped`'s `read_to_end` vs. serde's
/// `is_io()`), and the exact wording is not the contract. The `Gzip`/`Json`
/// split is, because `pipeline.rs` and the CLI branch on `CoreError`.
#[derive(PartialEq, Eq)]
pub enum Verdict {
    Written(String),
    NothingKept,
    Unrecognized,
    JsonError,
    GzipError,
    ObjectTooLarge,
    OtherError(String),
}

/// Comparison stays byte-exact; only the *rendering* is bounded. The
/// multi-chunk fixtures are ~400 KiB, and a failed `assert_eq!` on two of
/// those buries the actual signal (which mode did what) under a megabyte of
/// padding in the CI log.
impl std::fmt::Debug for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const MAX: usize = 160;
        match self {
            Verdict::Written(body) if body.len() > MAX => {
                let head: String = body.chars().take(MAX).collect();
                write!(f, "Written({} bytes: {head:?}…)", body.len())
            }
            Verdict::Written(body) => write!(f, "Written({body:?})"),
            Verdict::NothingKept => f.write_str("NothingKept"),
            Verdict::Unrecognized => f.write_str("Unrecognized"),
            Verdict::JsonError => f.write_str("JsonError"),
            Verdict::GzipError => f.write_str("GzipError"),
            Verdict::ObjectTooLarge => f.write_str("ObjectTooLarge"),
            Verdict::OtherError(msg) => write!(f, "OtherError({msg:?})"),
        }
    }
}

pub fn classify(err: &CoreError) -> Verdict {
    match err {
        CoreError::Json(_) => Verdict::JsonError,
        CoreError::Gzip(_) => Verdict::GzipError,
        CoreError::ObjectTooLarge { .. } => Verdict::ObjectTooLarge,
        other => Verdict::OtherError(format!("{other:?}")),
    }
}

/// The record counters, projected for comparison. Deliberately *not* the whole
/// `MetricSnapshot`: `bytes_in` is legitimately mode-specific (stream mode's
/// `pump_input` counts the compressed bytes it reads; buffer mode leaves
/// `BytesIn` to `pipeline.rs`, which holds the buffer), and `bytes_out` is only
/// committed by stream mode. The record counters have no such excuse — they
/// describe the same `Records` array either way.
#[derive(Debug, PartialEq, Eq)]
pub struct RecordCounters {
    pub records_in: u64,
    pub records_kept: u64,
    pub records_dropped: u64,
    pub parse_errors: u64,
    pub rule_drops: Vec<(String, u64)>,
}

impl RecordCounters {
    pub fn of(snapshot: &MetricSnapshot) -> Self {
        RecordCounters {
            records_in: snapshot.records_in,
            records_kept: snapshot.records_kept,
            records_dropped: snapshot.records_dropped,
            parse_errors: snapshot.parse_errors,
            rule_drops: snapshot.rule_drops.clone(),
        }
    }
}

/// Runs `input` through buffer mode. Returns the verdict, the raw gzip bytes it
/// would have `put` (so the caller can compare compressed framing), and the
/// metric snapshot it produced.
pub fn run_buffer(
    input: &[u8],
    engine: &Engine,
    cfg: &Processing,
) -> (Verdict, Option<Vec<u8>>, MetricSnapshot) {
    let metrics = Metrics::default();
    let verdict = match buffer_run(input, engine, cfg) {
        Ok((outcome, tally)) => {
            // `buffer_run` publishes nothing itself — its caller commits the
            // tally once the object's fate is decided. This harness stands in
            // for that caller, so the snapshot below sees what
            // `Pipeline::process_buffer` would have published for a successful
            // object. Stream mode's equivalent commit happens inside
            // `stream_run`, past its own upload check.
            tally.commit(&metrics, engine);
            match outcome {
                Outcome::Written(Some(bytes)) => (
                    Verdict::Written(String::from_utf8_lossy(&gunzip(&bytes)).into_owned()),
                    Some(bytes.to_vec()),
                ),
                Outcome::Written(None) => {
                    unreachable!("buffer_run always returns Written(Some(_))")
                }
                Outcome::NothingKept => (Verdict::NothingKept, None),
                Outcome::Unrecognized => (Verdict::Unrecognized, None),
            }
        }
        Err(e) => (classify(&e), None),
    };
    (verdict.0, verdict.1, metrics.snapshot_and_reset())
}

/// Runs `input` through stream mode against an `InMemoryStore`, reading the
/// verdict off what actually landed at the destination rather than off the
/// return value alone — a `NothingKept`/`Unrecognized`/error result must also
/// have left the destination key untouched (the abort path), and this catches
/// it if one ever commits a partial object.
pub async fn run_stream(
    input: &[u8],
    engine: &Engine,
    cfg: &Processing,
) -> (Verdict, Option<Vec<u8>>, MetricSnapshot) {
    let metrics = Metrics::default();
    let store = Arc::new(InMemoryStore::new());
    let reader: Box<dyn tokio::io::AsyncRead + Send + Unpin> =
        Box::new(std::io::Cursor::new(input.to_vec()));

    let result = stream_run(
        reader,
        engine,
        cfg,
        &metrics,
        store.as_ref(),
        DEST_BUCKET,
        DEST_KEY,
    )
    .await;

    let landed = store.object(DEST_BUCKET, DEST_KEY);
    let snapshot = metrics.snapshot_and_reset();

    let verdict = match result {
        Ok(Outcome::Written(None)) => {
            let bytes = landed.expect("stream mode reported Written but wrote no object");
            (
                Verdict::Written(String::from_utf8_lossy(&gunzip(&bytes)).into_owned()),
                Some(bytes.to_vec()),
            )
        }
        Ok(Outcome::Written(Some(_))) => {
            unreachable!("stream_run never returns Written(Some(_))")
        }
        Ok(other) => {
            assert!(
                landed.is_none(),
                "stream mode returned {other:?} but left an object at the destination: \
                 the upload must have been aborted"
            );
            match other {
                Outcome::NothingKept => (Verdict::NothingKept, None),
                Outcome::Unrecognized => (Verdict::Unrecognized, None),
                Outcome::Written(_) => unreachable!("handled above"),
            }
        }
        Err(e) => {
            assert!(
                landed.is_none(),
                "stream mode failed with {e:?} but left an object at the destination: \
                 a failed object must never be committed"
            );
            (classify(&e), None)
        }
    };
    (verdict.0, verdict.1, snapshot)
}

/// The core assertion: both modes agree, and the expectation is what we think
/// it is. Pinning `expected` too (rather than only buffer == stream) keeps a
/// future change from making both modes wrong in the same direction — which
/// an equality-only harness would happily accept.
pub async fn assert_parity(case: &str, input: &[u8], engine: &Engine, expected: Verdict) {
    assert_parity_with(case, input, engine, &Processing::default(), expected).await;
}

/// [`assert_parity`] with an explicit `Processing`, for cases that need a
/// non-default cap or compression level. The parity claim is unchanged: `cfg`
/// applies to *both* modes, so it can shift the expected verdict but never let
/// the two disagree.
pub async fn assert_parity_with(
    case: &str,
    input: &[u8],
    engine: &Engine,
    cfg: &Processing,
    expected: Verdict,
) {
    let (buffered, buffer_bytes, buffer_metrics) = run_buffer(input, engine, cfg);
    let (streamed, stream_bytes, stream_metrics) = run_stream(input, engine, cfg).await;

    assert_eq!(
        buffered, streamed,
        "{case}: buffer and stream mode disagree — the same object would be \
         handled differently depending only on its size"
    );
    assert_eq!(buffered, expected, "{case}: buffer mode");
    assert_eq!(streamed, expected, "{case}: stream mode");

    // Metrics are part of the contract, not decoration. A mode that reaches
    // the right verdict while reporting different counters still breaks every
    // dashboard and alarm the moment traffic crosses `stream_threshold_bytes`
    // — and this file existed for a full round *without* comparing them, which
    // is exactly why stream mode was able to report `RecordsIn` for objects
    // buffer mode counted as zero.
    assert_eq!(
        RecordCounters::of(&buffer_metrics),
        RecordCounters::of(&stream_metrics),
        "{case}: both modes reached {expected:?} but reported different record \
         counters — the same object would be measured differently depending \
         only on its size"
    );

    // The reconciliation identity, asserted independently of parity: equal
    // counters could still be equally wrong. `RecordsIn == RecordsKept +
    // RecordsDropped` is the one piece of arithmetic an operator can alarm on
    // to detect a record that entered and was never accounted for, so it has
    // to hold for *every* input, including the ones that fail.
    assert!(
        buffer_metrics.records_balance(),
        "{case}: buffer mode lost a record: in={} kept={} dropped={}",
        buffer_metrics.records_in,
        buffer_metrics.records_kept,
        buffer_metrics.records_dropped
    );
    assert!(
        stream_metrics.records_balance(),
        "{case}: stream mode lost a record: in={} kept={} dropped={}",
        stream_metrics.records_in,
        stream_metrics.records_kept,
        stream_metrics.records_dropped
    );

    // The second reconciliation identity: every dropped record is attributable
    // to exactly one rule, so the per-rule breakdown must sum to the total.
    // `RuleDrops` exceeding `RecordsDropped` is the signature of drops being
    // published for records the object never actually dropped — work an
    // object did before failing, which is then re-counted on every retry.
    for (mode, snapshot) in [("buffer", &buffer_metrics), ("stream", &stream_metrics)] {
        let attributed: u64 = snapshot.rule_drops.iter().map(|(_, n)| n).sum();
        assert_eq!(
            attributed, snapshot.records_dropped,
            "{case}: {mode} mode's per-rule drops ({:?}) do not sum to RecordsDropped ({})",
            snapshot.rule_drops, snapshot.records_dropped
        );
    }

    // stream.rs documents that draining the encoder's sink (instead of
    // `.flush()`ing it) keeps the compressed byte stream identical to buffer
    // mode's. Where both modes wrote, hold that claim to account: it is what
    // makes the destination bucket uniform regardless of which mode produced
    // an object.
    if let (Some(b), Some(s)) = (&buffer_bytes, &stream_bytes) {
        assert_eq!(
            b, s,
            "{case}: both modes wrote, but the compressed bytes differ — \
             stream mode's gzip framing has diverged from buffer mode's"
        );
    }
}
