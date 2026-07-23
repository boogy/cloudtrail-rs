//! Buffer-mode processing: decompress the whole object into
//! memory, filter record-by-record, and gzip the survivors back out as one
//! buffer.
//!
//! "Zero re-serialization" (performance design #1): the
//! `Records` array is parsed straight into `Vec<&RawValue>`, so a surviving
//! record's **original byte slice** is what gets written out — no
//! `serde_json::Value` is ever re-serialized.

use std::io::{Read, Write};

use bytes::Bytes;
use flate2::Compression;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;
use serde_json::Value;
use serde_json::value::RawValue;

use crate::config::Processing;
use crate::error::CoreError;
use crate::filter::{Decision, Engine};
use crate::metrics::Metrics;

/// Result of running one object's body through `buffer_run` (or, later,
/// `stream_run`).
#[derive(Debug)]
pub enum Outcome {
    /// Buffer mode: gzip bytes ready to `put`. Stream mode: `None` — already
    /// written via `put_stream`.
    Written(Option<Bytes>),
    /// Every record was dropped (or `Records` was empty): the caller writes
    /// nothing — "zero empty writes".
    NothingKept,
    /// Parsed as JSON but has no `Records` array: the caller applies its
    /// `on_unrecognized_object` policy. Never DLQ'd on an unanticipated
    /// shape.
    Unrecognized,
}

/// The envelope shape read straight out of the decompressed bytes. Each
/// `Records` element is captured as an unparsed JSON span (`&RawValue`)
/// rather than deserialized into a `Value`, so it can be written back out
/// byte-for-byte if it survives filtering.
#[derive(serde::Deserialize)]
struct Envelope<'a> {
    #[serde(rename = "Records", borrow)]
    records: Vec<&'a RawValue>,
}

/// Decompress `input` with `MultiGzDecoder` (never `GzDecoder`: concatenated
/// gzip members are otherwise silently truncated at the first member), never
/// buffering more than `max_object_bytes + 1` bytes so an oversized or
/// bomb-like object fails fast with `Err` instead of exhausting memory.
fn decompress_capped(input: &[u8], max_object_bytes: u64) -> Result<Vec<u8>, CoreError> {
    let decoder = MultiGzDecoder::new(input);
    let mut limited = decoder.take(max_object_bytes + 1);
    let mut buf = Vec::new();
    limited
        .read_to_end(&mut buf)
        .map_err(|e| CoreError::Gzip(e.to_string()))?;
    if buf.len() as u64 > max_object_bytes {
        return Err(CoreError::ObjectTooLarge {
            limit: max_object_bytes,
        });
    }
    Ok(buf)
}

/// Gzip-compress `body` at `level`.
fn gzip_compress(body: &[u8], level: u32) -> Result<Vec<u8>, CoreError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(level));
    encoder
        .write_all(body)
        .map_err(|e| CoreError::Gzip(e.to_string()))?;
    encoder.finish().map_err(|e| CoreError::Gzip(e.to_string()))
}

/// Buffer-mode entry point: `MultiGzDecoder` → `Vec<&RawValue>` → peek
/// `eventSource` (via `Engine::evaluate`) → write surviving raw slices →
/// gzip out as `Outcome::Written(Some(bytes))`.
///
/// `max_object_bytes` (buffer mode only) bounds the decompressed
/// size; exceeding it is an `Err`, not an out-of-memory buffer growth.
pub fn buffer_run(
    input: &[u8],
    engine: &Engine,
    cfg: &Processing,
    metrics: &Metrics,
) -> Result<Outcome, CoreError> {
    let decompressed = decompress_capped(input, cfg.max_object_bytes)?;

    let records = match serde_json::from_slice::<Envelope>(&decompressed) {
        Ok(envelope) => envelope.records,
        Err(_) => {
            // Distinguish "not valid JSON at all" (a data error: `Err`, the
            // Lambda retries via DLQ) from "valid JSON, just not the
            // `{"Records": [...]}` envelope" (`Unrecognized`: the caller's
            // `on_unrecognized_object` policy applies — never DLQ on an
            // unanticipated shape).
            return match serde_json::from_slice::<Value>(&decompressed) {
                Ok(_) => Ok(Outcome::Unrecognized),
                Err(e) => Err(CoreError::Json(e.to_string())),
            };
        }
    };

    metrics.add_records_in(records.len() as u64);

    let mut survivors: Vec<&str> = Vec::with_capacity(records.len());
    for raw in &records {
        let text = raw.get();
        match serde_json::from_str::<Value>(text) {
            Ok(value) => match engine.evaluate(&value) {
                Decision::Keep => survivors.push(text),
                Decision::Drop { rule_idx } => {
                    metrics.record_rule_drop(engine.rule_name(rule_idx));
                }
            },
            Err(_) => {
                // Unparseable individual record: never dropped, only
                // counted ("Unparseable individual record ⇒
                // KEPT, never dropped"). Reachable even though the raw span
                // was itself syntactically well-formed enough to capture —
                // e.g. a lone UTF-16 surrogate escape parses as a span but
                // fails full decode into a `Value`.
                metrics.add_parse_errors(1);
                survivors.push(text);
            }
        }
    }

    if survivors.is_empty() {
        metrics.add_records_dropped(records.len() as u64);
        return Ok(Outcome::NothingKept);
    }

    metrics.add_records_kept(survivors.len() as u64);
    metrics.add_records_dropped((records.len() - survivors.len()) as u64);

    let body = format!("{{\"Records\":[{}]}}", survivors.join(","));
    let gzipped = gzip_compress(body.as_bytes(), cfg.gzip_level)?;
    Ok(Outcome::Written(Some(Bytes::from(gzipped))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::rules::RuleSet;

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
        gzip_compress(body, 6).expect("test fixture body must compress")
    }

    fn gunzip(input: &[u8]) -> Vec<u8> {
        let mut decoder = MultiGzDecoder::new(input);
        let mut out = Vec::new();
        decoder
            .read_to_end(&mut out)
            .expect("test fixture must decompress");
        out
    }

    fn written_bytes(outcome: Outcome) -> Bytes {
        match outcome {
            Outcome::Written(Some(b)) => b,
            other => panic!("expected Outcome::Written(Some(_)), got {other:?}"),
        }
    }

    fn kept_event_names(gzipped: &Bytes) -> Vec<String> {
        let out = gunzip(gzipped);
        let parsed: Value = serde_json::from_slice(&out).expect("output must be valid JSON");
        parsed["Records"]
            .as_array()
            .expect("output must have a Records array")
            .iter()
            .map(|r| r["eventName"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    #[test]
    fn kept_record_bytes_appear_verbatim_in_output() {
        let record = r#"{"eventName":"ConsoleLogin","eventSource":"signin.amazonaws.com"}"#;
        let body = format!(r#"{{"Records":[{record}]}}"#);
        let input = gzip_bytes(body.as_bytes());

        let outcome = buffer_run(
            &input,
            &no_op_engine(),
            &Processing::default(),
            &Metrics::default(),
        )
        .expect("must succeed");
        let bytes = written_bytes(outcome);
        let out = gunzip(&bytes);
        let out_str = String::from_utf8(out).expect("output must be valid utf8");
        assert!(
            out_str.contains(record),
            "expected the kept record's exact original bytes in output, got {out_str:?}"
        );
    }

    #[test]
    fn output_reparses_to_the_expected_kept_set() {
        let body = br#"{"Records":[
            {"eventName":"ConsoleLogin"},
            {"eventName":"Decrypt"},
            {"eventName":"AssumeRole"}
        ]}"#;
        let input = gzip_bytes(body);

        let outcome = buffer_run(
            &input,
            &drop_decrypt_engine(),
            &Processing::default(),
            &Metrics::default(),
        )
        .expect("must succeed");
        let bytes = written_bytes(outcome);
        assert_eq!(
            kept_event_names(&bytes),
            vec!["ConsoleLogin".to_string(), "AssumeRole".to_string()]
        );
    }

    #[test]
    fn max_object_bytes_exceeded_is_an_error_not_an_oom() {
        let big_value = "a".repeat(10_000);
        let body = format!(r#"{{"Records":["{big_value}"]}}"#);
        let input = gzip_bytes(body.as_bytes());

        let cfg = Processing {
            max_object_bytes: 100,
            ..Processing::default()
        };

        let err = buffer_run(&input, &no_op_engine(), &cfg, &Metrics::default())
            .expect_err("oversized decompressed object must be an error, not OOM");
        assert!(
            matches!(err, CoreError::ObjectTooLarge { limit: 100 }),
            "expected ObjectTooLarge {{ limit: 100 }}, got {err:?}"
        );
    }

    #[test]
    fn all_records_dropped_yields_nothing_kept() {
        let body = br#"{"Records":[{"eventName":"Decrypt"},{"eventName":"Decrypt"}]}"#;
        let input = gzip_bytes(body);

        let outcome = buffer_run(
            &input,
            &drop_decrypt_engine(),
            &Processing::default(),
            &Metrics::default(),
        )
        .expect("must succeed");
        assert!(
            matches!(outcome, Outcome::NothingKept),
            "expected NothingKept, got {outcome:?}"
        );
    }

    #[test]
    fn empty_records_array_yields_nothing_kept_not_an_error() {
        let body = br#"{"Records":[]}"#;
        let input = gzip_bytes(body);

        let outcome = buffer_run(
            &input,
            &no_op_engine(),
            &Processing::default(),
            &Metrics::default(),
        )
        .expect("empty Records must not be an error");
        assert!(
            matches!(outcome, Outcome::NothingKept),
            "expected NothingKept, got {outcome:?}"
        );
    }

    #[test]
    fn valid_json_with_no_records_key_is_unrecognized() {
        let body = br#"{"foo":"bar"}"#;
        let input = gzip_bytes(body);

        let outcome = buffer_run(
            &input,
            &no_op_engine(),
            &Processing::default(),
            &Metrics::default(),
        )
        .expect("valid JSON with no Records key must not be an error");
        assert!(
            matches!(outcome, Outcome::Unrecognized),
            "expected Unrecognized, got {outcome:?}"
        );
    }

    #[test]
    fn genuinely_invalid_json_is_an_error() {
        let body = b"not json at all {{{";
        let input = gzip_bytes(body);

        let err = buffer_run(
            &input,
            &no_op_engine(),
            &Processing::default(),
            &Metrics::default(),
        )
        .expect_err("bad JSON must be a data error");
        assert!(matches!(err, CoreError::Json(_)), "got {err:?}");
    }

    #[test]
    fn unparseable_individual_record_is_kept_and_counted() {
        // A lone (unpaired) UTF-16 high-surrogate escape is syntactically
        // well-formed enough for the raw-value scan to capture a span for
        // it, but fails when that span is later parsed into a real `Value`
        // — exactly the "unparseable individual record" case guards
        // against.
        let body = br#"{"Records":[{"eventName":"ConsoleLogin"},{"broken":"\uD800"}]}"#;
        let input = gzip_bytes(body);
        let metrics = Metrics::default();

        let outcome = buffer_run(&input, &no_op_engine(), &Processing::default(), &metrics)
            .expect("an unparseable individual record must not fail the whole object");
        let bytes = written_bytes(outcome);
        let out = gunzip(&bytes);
        let out_str = String::from_utf8(out).expect("output must be valid utf8");
        assert!(
            out_str.contains(r#"{"broken":"\uD800"}"#),
            "unparseable record must be kept verbatim, got {out_str:?}"
        );

        assert_eq!(
            metrics.snapshot_and_reset().parse_errors,
            1,
            "the unparseable record must increment ParseErrors exactly once"
        );
    }

    #[test]
    fn concatenated_multi_member_gzip_is_fully_read() {
        let body = br#"{"Records":[{"eventName":"ConsoleLogin"},{"eventName":"AssumeRole"}]}"#;
        let mid = body.len() / 2;
        let (first_half, second_half) = body.split_at(mid);
        let mut input = gzip_bytes(first_half);
        input.extend(gzip_bytes(second_half));

        // Sanity check on the test fixture itself: a single-member decoder
        // must NOT reproduce the full body — this is exactly the silent
        // truncation `MultiGzDecoder` exists to avoid, and why this test
        // fails with `GzDecoder` and passes with `MultiGzDecoder`.
        let mut single_member = flate2::read::GzDecoder::new(input.as_slice());
        let mut truncated = Vec::new();
        single_member
            .read_to_end(&mut truncated)
            .expect("single-member decode of the first member must succeed");
        assert_eq!(
            truncated, first_half,
            "fixture sanity check: a single-member decoder must truncate at the first member"
        );

        let outcome = buffer_run(
            &input,
            &no_op_engine(),
            &Processing::default(),
            &Metrics::default(),
        )
        .expect("a concatenated multi-member gzip must be fully read");
        let bytes = written_bytes(outcome);
        assert_eq!(
            kept_event_names(&bytes),
            vec!["ConsoleLogin".to_string(), "AssumeRole".to_string()]
        );
    }
}
