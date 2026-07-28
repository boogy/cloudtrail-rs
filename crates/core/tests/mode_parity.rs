//! Buffer/stream **mode parity** harness.
//!
//! `processing.mode: auto` routes an object to buffer or stream mode purely on
//! its *compressed size* vs. `stream_threshold_bytes`. That makes mode a
//! deployment detail, not a semantic one: the same bytes must produce the same
//! decision, the same destination payload, and the same error classification
//! either way. Any divergence is a bug whose blast radius is "objects above
//! some size threshold behave differently" — historically the shape of silent
//! data loss in this codebase, because the loud mode is the one nobody runs at
//! scale.
//!
//! So this file asserts equality rather than behavior: every case is fed to
//! `buffer_run` and `stream_run` and both are normalized to a `Verdict` that
//! must match. A new divergence fails here without anyone having to think of
//! the specific case again.
//!
//! Deliberately an **integration** test: it drives `core` through its public
//! API (`buffer_run` / `stream_run` / `InMemoryStore`) exactly as a Lambda
//! composition root does. The in-crate unit tests cover each mode's internals
//! well, which is precisely why a *cross-mode* gap could sit undetected in
//! both — neither module's tests are looking at the other.
//!
//! Needs the `testing` feature for `InMemoryStore`; `make test` / `make ci`
//! run `--all-features`.
#![cfg(feature = "testing")]

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

const DEST_BUCKET: &str = "dest";
const DEST_KEY: &str = "logs/object.json.gz";

fn gzip(body: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(6));
    encoder.write_all(body).expect("fixture must compress");
    encoder.finish().expect("fixture must compress")
}

fn gunzip(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    MultiGzDecoder::new(input)
        .read_to_end(&mut out)
        .expect("output must be valid gzip");
    out
}

fn no_op_engine() -> Engine {
    engine(b"version: 1.0.0\nrules: []\n")
}

fn engine(yaml: &[u8]) -> Engine {
    Engine::new(RuleSet::parse(yaml).expect("ruleset must parse")).expect("ruleset must compile")
}

fn drop_decrypt_engine() -> Engine {
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
enum Verdict {
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

fn classify(err: &CoreError) -> Verdict {
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
struct RecordCounters {
    records_in: u64,
    records_kept: u64,
    records_dropped: u64,
    parse_errors: u64,
    rule_drops: Vec<(String, u64)>,
}

impl RecordCounters {
    fn of(snapshot: &MetricSnapshot) -> Self {
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
fn run_buffer(
    input: &[u8],
    engine: &Engine,
    cfg: &Processing,
) -> (Verdict, Option<Vec<u8>>, MetricSnapshot) {
    let metrics = Metrics::default();
    let verdict = match buffer_run(input, engine, cfg, &metrics) {
        Ok(Outcome::Written(Some(bytes))) => (
            Verdict::Written(String::from_utf8_lossy(&gunzip(&bytes)).into_owned()),
            Some(bytes.to_vec()),
        ),
        Ok(Outcome::Written(None)) => {
            unreachable!("buffer_run always returns Written(Some(_))")
        }
        Ok(Outcome::NothingKept) => (Verdict::NothingKept, None),
        Ok(Outcome::Unrecognized) => (Verdict::Unrecognized, None),
        Err(e) => (classify(&e), None),
    };
    (verdict.0, verdict.1, metrics.snapshot_and_reset())
}

/// Runs `input` through stream mode against an `InMemoryStore`, reading the
/// verdict off what actually landed at the destination rather than off the
/// return value alone — a `NothingKept`/`Unrecognized`/error result must also
/// have left the destination key untouched (the abort path), and this catches
/// it if one ever commits a partial object.
async fn run_stream(
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
async fn assert_parity(case: &str, input: &[u8], engine: &Engine, expected: Verdict) {
    let cfg = Processing::default();
    let (buffered, buffer_bytes, buffer_metrics) = run_buffer(input, engine, &cfg);
    let (streamed, stream_bytes, stream_metrics) = run_stream(input, engine, &cfg).await;

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

// ---------------------------------------------------------------------------
// Ordinary envelopes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_record_kept() {
    assert_parity(
        "no rules, two records",
        &gzip(br#"{"Records":[{"eventName":"A"},{"eventName":"B"}]}"#),
        &no_op_engine(),
        Verdict::Written(r#"{"Records":[{"eventName":"A"},{"eventName":"B"}]}"#.to_string()),
    )
    .await;
}

#[tokio::test]
async fn some_records_dropped() {
    assert_parity(
        "drop Decrypt, keep the rest",
        &gzip(
            br#"{"Records":[{"eventName":"Decrypt"},{"eventName":"ConsoleLogin"},{"eventName":"Decrypt"}]}"#,
        ),
        &drop_decrypt_engine(),
        Verdict::Written(r#"{"Records":[{"eventName":"ConsoleLogin"}]}"#.to_string()),
    )
    .await;
}

#[tokio::test]
async fn every_record_dropped_writes_nothing() {
    assert_parity(
        "all records match the drop rule",
        &gzip(br#"{"Records":[{"eventName":"Decrypt"},{"eventName":"Decrypt"}]}"#),
        &drop_decrypt_engine(),
        Verdict::NothingKept,
    )
    .await;
}

#[tokio::test]
async fn empty_records_array_writes_nothing() {
    assert_parity(
        "Records present but empty",
        &gzip(br#"{"Records":[]}"#),
        &no_op_engine(),
        Verdict::NothingKept,
    )
    .await;
}

#[tokio::test]
async fn sibling_keys_alongside_records_are_ignored() {
    assert_parity(
        "unknown sibling keys must not change the outcome",
        &gzip(br#"{"nextToken":"abc","Records":[{"eventName":"A"}],"extra":{"deep":[1,2]}}"#),
        &no_op_engine(),
        Verdict::Written(r#"{"Records":[{"eventName":"A"}]}"#.to_string()),
    )
    .await;
}

// ---------------------------------------------------------------------------
// Unrecognized shapes — `on_unrecognized_object` territory, never an error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn object_without_a_records_key_is_unrecognized() {
    assert_parity(
        "no Records key",
        &gzip(br#"{"something":"else"}"#),
        &no_op_engine(),
        Verdict::Unrecognized,
    )
    .await;
}

#[tokio::test]
async fn records_that_is_not_an_array_is_unrecognized() {
    assert_parity(
        "Records is an object, not an array",
        &gzip(br#"{"Records":{"not":"an array"}}"#),
        &no_op_engine(),
        Verdict::Unrecognized,
    )
    .await;
}

#[tokio::test]
async fn records_that_is_a_string_is_unrecognized() {
    assert_parity(
        "Records is a string",
        &gzip(br#"{"Records":"nope"}"#),
        &no_op_engine(),
        Verdict::Unrecognized,
    )
    .await;
}

#[tokio::test]
async fn a_repeated_records_key_is_unrecognized_in_both_modes() {
    // Two `Records` keys in one object: JSON says nothing about which wins, so
    // neither mode may pick one. Buffer mode's derived `Envelope` rejects the
    // duplicate field and falls back to `Unrecognized`; stream mode's visitor
    // used to stream *both* arrays and report `Written`, so the same bytes
    // produced a merged object above the size threshold and a verbatim copy
    // below it. Pinned to `Unrecognized` — the object is forwarded untouched
    // under the default `on_unrecognized_object: copy`, so nothing is lost
    // either way, and an operator can look at it.
    assert_parity(
        "Records appears twice",
        &gzip(br#"{"Records":[{"eventName":"A"}],"Records":[{"eventName":"B"}]}"#),
        &no_op_engine(),
        Verdict::Unrecognized,
    )
    .await;
}

#[tokio::test]
async fn top_level_array_is_unrecognized() {
    assert_parity(
        "top-level JSON array",
        &gzip(br#"[{"eventName":"A"}]"#),
        &no_op_engine(),
        Verdict::Unrecognized,
    )
    .await;
}

#[tokio::test]
async fn top_level_scalar_is_unrecognized() {
    assert_parity(
        "top-level JSON number",
        &gzip(b"42"),
        &no_op_engine(),
        Verdict::Unrecognized,
    )
    .await;
}

#[tokio::test]
async fn top_level_null_is_unrecognized() {
    assert_parity(
        "top-level JSON null",
        &gzip(b"null"),
        &no_op_engine(),
        Verdict::Unrecognized,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Gzip framing — the multi-member cases `MultiGzDecoder` exists for
// ---------------------------------------------------------------------------

#[tokio::test]
async fn one_envelope_split_across_two_gzip_members_is_fully_read() {
    // A plain `GzDecoder` stops after member 1 and would truncate this to
    // invalid JSON. Both modes use `MultiGzDecoder`, so both must recover the
    // whole envelope.
    let body = br#"{"Records":[{"eventName":"A"},{"eventName":"B"}]}"#;
    let mid = body.len() / 2;
    let mut input = gzip(&body[..mid]);
    input.extend(gzip(&body[mid..]));

    assert_parity(
        "single envelope spanning two gzip members",
        &input,
        &no_op_engine(),
        Verdict::Written(r#"{"Records":[{"eventName":"A"},{"eventName":"B"}]}"#.to_string()),
    )
    .await;
}

#[tokio::test]
async fn two_complete_envelopes_in_two_gzip_members_is_an_error() {
    // The finding this harness was written for. Stream mode used to stop at
    // the first top-level `}` and report success, silently discarding the
    // second envelope's records *and* acking the message. Buffer mode always
    // rejected it. Neither mode may guess which envelope was intended — a
    // hard error is the only non-lossy answer.
    let mut input = gzip(br#"{"Records":[{"eventName":"A"}]}"#);
    input.extend(gzip(br#"{"Records":[{"eventName":"B"}]}"#));

    assert_parity(
        "two concatenated envelopes",
        &input,
        &no_op_engine(),
        Verdict::JsonError,
    )
    .await;
}

/// The counter half of the case above. Every other error case here fails on an
/// input where no rule ever fires, so the modes agreed on "no per-rule drops"
/// for the trivial reason that neither had any to report.
///
/// Put a rule-matching record and an unparseable record *before* the failure
/// and the two modes diverge: buffer mode decides the object is malformed
/// before it evaluates anything, so it reports nothing; stream mode had
/// already evaluated both records by the time the trailing envelope surfaced.
/// Publishing that work attributed `RuleDrops` to a rule for a record that was
/// never dropped and `ParseErrors` for a record that was never kept — on an
/// object that failed whole and will be re-driven whole, so every redelivery
/// re-counts them. Meanwhile `RecordsDropped` for the same snapshot is zero,
/// so `sum(RuleDrops) > RecordsDropped`: the cross-check `docs/metrics.md`
/// tells an operator to make reports drops that did not happen.
#[tokio::test]
async fn a_failure_after_records_were_evaluated_publishes_no_per_rule_drops() {
    // The middle record is a lone UTF-16 surrogate escape: a well-formed
    // enough span to be captured, but not decodable into a `Value` — the one
    // shape that reaches `ParseErrors` in either mode.
    let mut input = gzip(
        br#"{"Records":[{"eventName":"Decrypt"},{"eventName":"\ud800"},{"eventName":"Keep"}]}"#,
    );
    input.extend(gzip(br#"{"Records":[{"eventName":"B"}]}"#));

    assert_parity(
        "rule drops and parse errors evaluated before a trailing-envelope failure",
        &input,
        &drop_decrypt_engine(),
        Verdict::JsonError,
    )
    .await;
}

#[tokio::test]
async fn content_after_the_envelope_is_an_error() {
    assert_parity(
        "trailing non-whitespace after the top-level value",
        &gzip(br#"{"Records":[{"eventName":"A"}]} and then some garbage"#),
        &no_op_engine(),
        Verdict::JsonError,
    )
    .await;
}

#[tokio::test]
async fn trailing_whitespace_after_the_envelope_is_accepted() {
    // The guard rail on the fix above: rejecting *content* after the envelope
    // must not also reject a harmless trailing newline. A producer that ends
    // its object with `\n` is writing valid data and must keep working.
    assert_parity(
        "trailing newline and spaces",
        &gzip(b"{\"Records\":[{\"eventName\":\"A\"}]}\n  \n"),
        &no_op_engine(),
        Verdict::Written(r#"{"Records":[{"eventName":"A"}]}"#.to_string()),
    )
    .await;
}

#[tokio::test]
async fn a_truncated_gzip_trailer_is_an_error() {
    // Complete, parseable JSON, but the gzip member's CRC32/ISIZE trailer was
    // cut off — the signature of a truncated upload or a partial read. The
    // JSON parser alone cannot see this; only draining the decompressor to
    // EOF surfaces it. Accepting it means accepting a possibly-truncated
    // object as authoritative.
    let full = gzip(br#"{"Records":[{"eventName":"A"}]}"#);
    let truncated = full[..full.len() - 4].to_vec();

    assert_parity(
        "gzip trailer chopped off",
        &truncated,
        &no_op_engine(),
        Verdict::GzipError,
    )
    .await;
}

#[tokio::test]
async fn input_that_is_not_gzip_at_all_is_an_error() {
    assert_parity(
        "plain uncompressed JSON",
        br#"{"Records":[{"eventName":"A"}]}"#,
        &no_op_engine(),
        Verdict::GzipError,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Multi-chunk objects — the only cases that exercise stream mode's actual
// pipelining (input chunking, periodic output drains, multipart parts)
// ---------------------------------------------------------------------------

/// An envelope big enough to cross `INPUT_CHUNK_BYTES` (64 KiB) on the way in
/// and `OUTPUT_FLUSH_THRESHOLD` (64 KiB) on the way out several times over, so
/// stream mode really does chunk, drain and upload in pieces rather than
/// behaving like a one-shot buffer.
fn large_envelope(records: usize, event_name: &str) -> String {
    let mut body = String::from(r#"{"Records":["#);
    for i in 0..records {
        if i > 0 {
            body.push(',');
        }
        // ~200 bytes per record: 2000 records lands around 400 KiB.
        body.push_str(&format!(
            r#"{{"eventName":"{event_name}","eventSource":"kms.amazonaws.com","seq":{i},"padding":"{}"}}"#,
            "x".repeat(140)
        ));
    }
    body.push_str("]}");
    body
}

#[tokio::test]
async fn a_multi_chunk_object_round_trips_identically_in_both_modes() {
    let body = large_envelope(2000, "ConsoleLogin");
    assert!(
        body.len() > 4 * 64 * 1024,
        "fixture must span several input chunks and output drains, got {} bytes",
        body.len()
    );

    assert_parity(
        "multi-chunk object, every record kept",
        &gzip(body.as_bytes()),
        &no_op_engine(),
        Verdict::Written(body),
    )
    .await;
}

#[tokio::test]
async fn a_multi_chunk_object_with_a_second_envelope_appended_commits_nothing() {
    // The production shape of the concatenation bug, and the case the fix's
    // ordering claim rests on: by the time the trailing envelope is reached,
    // stream mode has already streamed thousands of records out and handed
    // several parts to `put_stream`. The error must still abort that in-flight
    // upload rather than commit the truncated prefix — `run_stream` asserts
    // the destination key is empty on every non-`Written` result, so a
    // committed partial object fails this test.
    let first = large_envelope(2000, "ConsoleLogin");
    let mut input = gzip(first.as_bytes());
    input.extend(gzip(
        br#"{"Records":[{"eventName":"AppendedAndWouldBeLost"}]}"#,
    ));

    assert_parity(
        "multi-chunk object with a second envelope concatenated",
        &input,
        &no_op_engine(),
        Verdict::JsonError,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Malformed JSON
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unterminated_envelope_is_an_error() {
    assert_parity(
        "envelope cut mid-array",
        &gzip(br#"{"Records":[{"eventName":"A"}"#),
        &no_op_engine(),
        Verdict::JsonError,
    )
    .await;
}

#[tokio::test]
async fn not_json_at_all_is_an_error() {
    assert_parity(
        "gzip of non-JSON bytes",
        &gzip(b"this is not json {{{"),
        &no_op_engine(),
        Verdict::JsonError,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Record-level edge cases
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_record_missing_the_matched_field_is_kept() {
    // `resolve` returning `None` must never make a drop rule fire.
    assert_parity(
        "record has no eventName at all",
        &gzip(br#"{"Records":[{"eventSource":"kms.amazonaws.com"},{"eventName":"Decrypt"}]}"#),
        &drop_decrypt_engine(),
        Verdict::Written(r#"{"Records":[{"eventSource":"kms.amazonaws.com"}]}"#.to_string()),
    )
    .await;
}

#[tokio::test]
async fn a_record_that_is_a_scalar_is_kept() {
    // Not an object, so no field can be resolved: keep, never drop.
    assert_parity(
        "scalar elements inside Records",
        &gzip(br#"{"Records":[42,"text",{"eventName":"Decrypt"}]}"#),
        &drop_decrypt_engine(),
        Verdict::Written(r#"{"Records":[42,"text"]}"#.to_string()),
    )
    .await;
}

#[tokio::test]
async fn records_are_written_back_byte_for_byte() {
    // Zero re-serialization: key order, whitespace and number formatting
    // inside a surviving record must survive untouched in both modes.
    let body = r#"{"Records":[{"z":1,"a":{"nested":  [1,2 , 3]},"n":1.50,"u":"é"}]}"#;
    assert_parity(
        "surviving records are not reformatted",
        &gzip(body.as_bytes()),
        &no_op_engine(),
        Verdict::Written(
            r#"{"Records":[{"z":1,"a":{"nested":  [1,2 , 3]},"n":1.50,"u":"é"}]}"#.to_string(),
        ),
    )
    .await;
}
