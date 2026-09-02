//! Buffer/stream **mode parity**: the structural cases.
//!
//! `processing.mode: auto` picks a mode from an object's compressed size, so
//! mode is a deployment detail and never a semantic one. Every case here is fed
//! to `buffer_run` and `stream_run` through [`common::assert_parity`] and both
//! are normalized to a `Verdict` that must match.
//!
//! The envelopes are deliberately **minimal**, so each case isolates one
//! structural property; realistic records go through the same oracle in
//! `corpus_parity.rs`. An integration test on purpose: it drives `core` through
//! the public API a Lambda composition root uses, where a cross-mode gap that
//! both modules' unit tests miss would sit. Needs the `testing` feature.
#![cfg(feature = "testing")]

mod common;

use cloudtrail_rs_core::config::Processing;
use common::{Verdict, assert_parity, drop_decrypt_engine, gzip, no_op_engine, run_buffer};

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
    // neither mode may pick one. Pinned to `Unrecognized` — the object is
    // forwarded untouched under the default `on_unrecognized_object: copy`.
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
    // invalid JSON. Both modes use `MultiGzDecoder`.
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
    // Neither mode may guess which of two concatenated envelopes was intended:
    // a hard error is the only non-lossy answer.
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

/// Every other error case here fails on an input where no rule ever fires, so
/// the modes agree on "no per-rule drops" trivially. With a rule-matching record
/// and an unparseable record *before* the failure, stream mode has evaluated
/// both by the time the trailing envelope surfaces: publishing that work makes
/// `sum(RuleDrops) > RecordsDropped` on an object that will be re-driven whole.
#[tokio::test]
async fn a_failure_after_records_were_evaluated_publishes_no_per_rule_drops() {
    // The middle record is a lone UTF-16 surrogate escape: capturable as a
    // span, not decodable into a `Value` — the one shape reaching `ParseErrors`.
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
    // Rejecting content after the envelope must not reject a trailing newline:
    // a producer that ends its object with `\n` is writing valid data.
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
    // Parseable JSON whose gzip CRC32/ISIZE trailer was cut off. Only draining
    // the decompressor to EOF surfaces it; the JSON parser cannot.
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
// Multi-chunk objects — the only cases exercising stream mode's pipelining
// ---------------------------------------------------------------------------

/// An envelope big enough to cross `INPUT_CHUNK_BYTES` and
/// `OUTPUT_FLUSH_THRESHOLD` (64 KiB each) several times over, so stream mode
/// really chunks, drains and uploads in pieces.
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
    // By the time the trailing envelope is reached, stream mode has handed
    // several parts to `put_stream`. The error must abort that in-flight upload
    // rather than commit the truncated prefix — `run_stream` asserts the
    // destination key is empty on every non-`Written` result.
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
    // Zero re-serialization: key order, whitespace and number formatting inside
    // a surviving record must survive untouched in both modes.
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

#[tokio::test]
async fn an_unparseable_record_survives_inside_a_written_object_and_is_counted() {
    // Nothing here makes the *object* fail: the lone surrogate escape is kept,
    // so the object is written whole and the parse error still counts.
    let input =
        gzip(br#"{"Records":[{"eventName":"A"},{"eventName":"\ud800"},{"eventName":"B"}]}"#);
    let expected = Verdict::Written(
        r#"{"Records":[{"eventName":"A"},{"eventName":"\ud800"},{"eventName":"B"}]}"#.to_string(),
    );

    assert_parity(
        "one unparseable record among two ordinary ones, object still written",
        &input,
        &no_op_engine(),
        expected,
    )
    .await;

    let (_, _, metrics) = run_buffer(&input, &no_op_engine(), &Processing::default());
    assert_eq!(
        metrics.parse_errors, 1,
        "the \\ud800 record is one parse error"
    );
    assert_eq!(
        metrics.records_kept, 3,
        "all three records survive, including the unparseable one"
    );
}
