//! Buffer-mode processing: decompress the whole object into memory, filter
//! record-by-record, and gzip the survivors back out as one buffer.
//!
//! Zero re-serialization: `Records` is parsed into `Vec<&RawValue>`, so a
//! surviving record's original byte slice is what gets written out.

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
use crate::process::RecordTally;

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
    /// `on_unrecognized_object` policy. Never DLQ'd on an unanticipated shape.
    Unrecognized,
}

/// The envelope read straight out of the decompressed bytes. Each `Records`
/// element is captured as an unparsed span (`&RawValue`) so a survivor can be
/// written back out byte-for-byte.
#[derive(serde::Deserialize)]
struct Envelope<'a> {
    #[serde(rename = "Records", borrow)]
    records: Vec<&'a RawValue>,
}

/// DEFLATE cannot expand by more than 1032:1, so a hint above this is a lie the
/// input cannot back up.
const MAX_DEFLATE_RATIO: usize = 1032;

/// Capacity hint for the decompressed body, read from gzip's ISIZE trailer.
///
/// ISIZE is attacker-controlled and only describes the last member, so it is
/// clamped by both the configured cap and what `input`'s length can physically
/// expand to; a wrong hint costs a realloc, never correctness.
fn decompressed_size_hint(input: &[u8], max_object_bytes: u64) -> usize {
    let Some(trailer) = input.get(input.len().wrapping_sub(4)..) else {
        return 0;
    };
    let isize_field = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]) as usize;
    let cap = usize::try_from(max_object_bytes.saturating_add(1)).unwrap_or(usize::MAX);
    isize_field
        .min(cap)
        .min(input.len().saturating_mul(MAX_DEFLATE_RATIO))
}

/// Decompress `input` with `MultiGzDecoder` (never `GzDecoder`: concatenated
/// members would be silently truncated at the first), buffering at most
/// `max_object_bytes.saturating_add(1)` bytes. Saturating, not wrapping: at
/// `u64::MAX` — an operator's "no cap" — `+ 1` would `take(0)`.
fn decompress_capped(input: &[u8], max_object_bytes: u64) -> Result<Vec<u8>, CoreError> {
    let decoder = MultiGzDecoder::new(input);
    let mut limited = decoder.take(max_object_bytes.saturating_add(1));
    let mut buf = Vec::with_capacity(decompressed_size_hint(input, max_object_bytes));
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

/// Gzip-compress `body` at `level`. Output side, so a failure is `Internal`,
/// never `Gzip`: `on_parse_error: copy` must not treat it as unreadable source.
fn gzip_compress(body: &[u8], level: u32) -> Result<Vec<u8>, CoreError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(level));
    encoder
        .write_all(body)
        .map_err(|e| CoreError::Internal(e.to_string()))?;
    encoder
        .finish()
        .map_err(|e| CoreError::Internal(e.to_string()))
}

/// Below this, a member's framing and its lost back-reference window cost more
/// than the parallelism buys.
const MIN_CHUNK_BYTES: usize = 64 * 1024;

/// Gzip-compress `body` as `chunks` independently-deflated members, concatenated.
///
/// A gzip stream decompresses to the concatenation of its members, so the split
/// is a plain byte offset: the decompressed payload is identical at every chunk
/// count and only the framing and the compressed size change. Chunks above the
/// first are compressed on scoped threads, so this only pays where there is
/// more than one vCPU.
fn gzip_compress_chunked(body: &[u8], level: u32, chunks: usize) -> Result<Vec<u8>, CoreError> {
    let chunks = chunks.min(body.len() / MIN_CHUNK_BYTES).max(1);
    if chunks == 1 {
        return gzip_compress(body, level);
    }

    let parts: Vec<&[u8]> = body.chunks(body.len().div_ceil(chunks)).collect();
    let members = std::thread::scope(|scope| {
        let workers: Vec<_> = parts[1..]
            .iter()
            .copied()
            .map(|part| scope.spawn(move || gzip_compress(part, level)))
            .collect();
        let mut members = Vec::with_capacity(parts.len());
        members.push(gzip_compress(parts[0], level));
        members.extend(workers.into_iter().map(|w| {
            w.join()
                .unwrap_or_else(|_| Err(CoreError::Internal("compression worker panicked".into())))
        }));
        members
    });

    let mut out = Vec::with_capacity(members.iter().flatten().map(Vec::len).sum());
    for member in members {
        out.extend_from_slice(&member?);
    }
    Ok(out)
}

/// Buffer-mode entry point: `MultiGzDecoder` → `Vec<&RawValue>` → evaluate →
/// write surviving raw slices → gzip out as `Outcome::Written(Some(bytes))`.
/// `max_object_bytes` bounds the decompressed size; exceeding it is an `Err`.
///
/// Publishes **no** metrics: the per-record counters come back in the
/// [`RecordTally`], which the caller commits only once the `put` has returned
/// and the object's fate is decided. See [`crate::process::tally`].
pub fn buffer_run(
    input: &[u8],
    engine: &Engine,
    cfg: &Processing,
) -> Result<(Outcome, RecordTally), CoreError> {
    let decompressed = decompress_capped(input, cfg.max_object_bytes)?;

    let mut tally = RecordTally::default();

    let records = match serde_json::from_slice::<Envelope>(&decompressed) {
        Ok(envelope) => envelope.records,
        Err(_) => {
            // Distinguish "not valid JSON at all" (an `Err`, retried via DLQ)
            // from "valid JSON, just not the envelope" (`Unrecognized`, where
            // the caller's policy applies).
            return match serde_json::from_slice::<Value>(&decompressed) {
                // An empty tally, not the records seen so far: there were
                // none, and stream mode reports 0/0/0 for these same bytes.
                Ok(_) => Ok((Outcome::Unrecognized, tally)),
                Err(e) => Err(CoreError::Json(e.to_string())),
            };
        }
    };

    let mut survivors: Vec<&str> = Vec::with_capacity(records.len());
    for raw in &records {
        tally.record_in();
        let text = raw.get();
        match engine.evaluate_raw(text) {
            Ok(Decision::Keep) => {
                tally.keep();
                survivors.push(text);
            }
            Ok(Decision::Drop { rule_idx }) => {
                tally.drop_by_rule(rule_idx);
            }
            Err(_) => {
                // Unparseable individual record: kept, only counted. Reachable
                // even for a well-formed raw span — a lone UTF-16 surrogate
                // escape captures as a span but fails full decode.
                tally.parse_error();
                tally.keep();
                survivors.push(text);
            }
        }
    }

    if survivors.is_empty() {
        // `kept` is 0, so `commit` derives `RecordsDropped == RecordsIn`.
        return Ok((Outcome::NothingKept, tally));
    }

    let mut body = Vec::with_capacity(survivors.iter().map(|s| s.len() + 1).sum::<usize>() + 14);
    body.extend_from_slice(b"{\"Records\":[");
    for (i, s) in survivors.iter().enumerate() {
        if i > 0 {
            body.push(b',');
        }
        body.extend_from_slice(s.as_bytes());
    }
    body.extend_from_slice(b"]}");
    let gzipped = gzip_compress_chunked(&body, cfg.gzip_level, cfg.gzip_chunks)?;
    Ok((Outcome::Written(Some(Bytes::from(gzipped))), tally))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::rules::RuleSet;
    use crate::metrics::Metrics;
    use crate::testing::corpus;

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

    #[test]
    fn size_hint_reads_the_isize_trailer_for_a_normal_object() {
        let body = corpus::full_envelope();
        let gz = gzip_bytes(body.as_bytes());
        assert_eq!(decompressed_size_hint(&gz, u64::MAX), body.len());
    }

    #[test]
    fn size_hint_is_clamped_by_what_the_input_length_can_physically_expand_to() {
        let mut hostile = gzip_bytes(b"tiny");
        let n = hostile.len();
        hostile[n - 4..].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            decompressed_size_hint(&hostile, u64::MAX),
            hostile.len() * MAX_DEFLATE_RATIO
        );
    }

    #[test]
    fn size_hint_is_clamped_by_max_object_bytes() {
        let mut hostile = vec![0u8; 1 << 20];
        let n = hostile.len();
        hostile[n - 4..].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decompressed_size_hint(&hostile, 4096), 4097);
    }

    #[test]
    fn size_hint_on_input_too_short_to_hold_a_trailer_is_zero() {
        assert_eq!(decompressed_size_hint(b"", u64::MAX), 0);
        assert_eq!(decompressed_size_hint(b"ab", u64::MAX), 0);
    }

    #[test]
    fn a_lying_isize_trailer_is_rejected_by_the_decoder_not_trusted_as_a_length() {
        let body = corpus::full_envelope();
        let mut gz = gzip_bytes(body.as_bytes());
        let n = gz.len();
        gz[n - 4..].copy_from_slice(&7u32.to_le_bytes());
        assert!(
            matches!(decompress_capped(&gz, u64::MAX), Err(CoreError::Gzip(_))),
            "gzip validates ISIZE as part of the trailer, so a forged hint cannot \
             truncate the output — it fails the stream instead"
        );
    }

    #[test]
    fn an_honest_object_decompresses_to_the_same_bytes_as_before_the_hint() {
        let body = corpus::full_envelope();
        let gz = gzip_bytes(body.as_bytes());
        assert_eq!(
            decompress_capped(&gz, u64::MAX).expect("corpus object must decompress"),
            body.as_bytes()
        );
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

        let (outcome, _tally) =
            buffer_run(&input, &no_op_engine(), &Processing::default()).expect("must succeed");
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

        let (outcome, _tally) = buffer_run(&input, &drop_decrypt_engine(), &Processing::default())
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

        let err = buffer_run(&input, &no_op_engine(), &cfg)
            .expect_err("oversized decompressed object must be an error, not OOM");
        assert!(
            matches!(err, CoreError::ObjectTooLarge { limit: 100 }),
            "expected ObjectTooLarge {{ limit: 100 }}, got {err:?}"
        );
    }

    /// Falsifiable: a plain `max_object_bytes + 1` wraps to 0 at `u64::MAX`,
    /// making `.take(0)` read nothing and every object fail to decompress.
    #[test]
    fn max_object_bytes_at_u64_max_reads_the_full_body_not_zero() {
        let body = br#"{"Records":[{"eventName":"ConsoleLogin"}]}"#;
        let input = gzip_bytes(body);

        let cfg = Processing {
            max_object_bytes: u64::MAX,
            ..Processing::default()
        };

        let (outcome, _tally) = buffer_run(&input, &no_op_engine(), &cfg)
            .expect("u64::MAX must mean no cap, not a Gzip/Json error from reading 0 bytes");
        let bytes = written_bytes(outcome);
        assert_eq!(
            kept_event_names(&bytes),
            vec!["ConsoleLogin".to_string()],
            "the full decompressed body must survive under an uncapped read"
        );
    }

    #[test]
    fn all_records_dropped_yields_nothing_kept() {
        let body = br#"{"Records":[{"eventName":"Decrypt"},{"eventName":"Decrypt"}]}"#;
        let input = gzip_bytes(body);

        let (outcome, _tally) = buffer_run(&input, &drop_decrypt_engine(), &Processing::default())
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

        let (outcome, _tally) = buffer_run(&input, &no_op_engine(), &Processing::default())
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

        let (outcome, _tally) = buffer_run(&input, &no_op_engine(), &Processing::default())
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

        let err = buffer_run(&input, &no_op_engine(), &Processing::default())
            .expect_err("bad JSON must be a data error");
        assert!(matches!(err, CoreError::Json(_)), "got {err:?}");
    }

    #[test]
    fn unparseable_individual_record_is_kept_and_counted() {
        // A lone UTF-16 high-surrogate escape captures as a raw span but fails
        // when that span is parsed into a `Value`.
        let body = br#"{"Records":[{"eventName":"ConsoleLogin"},{"broken":"\uD800"}]}"#;
        let input = gzip_bytes(body);
        let metrics = Metrics::default();

        let (outcome, tally) = buffer_run(&input, &no_op_engine(), &Processing::default())
            .expect("an unparseable individual record must not fail the whole object");
        tally.commit(&metrics, &no_op_engine());
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

        // Fixture check: a single-member decoder must NOT reproduce the full
        // body — the silent truncation `MultiGzDecoder` exists to avoid.
        let mut single_member = flate2::read::GzDecoder::new(input.as_slice());
        let mut truncated = Vec::new();
        single_member
            .read_to_end(&mut truncated)
            .expect("single-member decode of the first member must succeed");
        assert_eq!(
            truncated, first_half,
            "fixture sanity check: a single-member decoder must truncate at the first member"
        );

        let (outcome, _tally) = buffer_run(&input, &no_op_engine(), &Processing::default())
            .expect("a concatenated multi-member gzip must be fully read");
        let bytes = written_bytes(outcome);
        assert_eq!(
            kept_event_names(&bytes),
            vec!["ConsoleLogin".to_string(), "AssumeRole".to_string()]
        );
    }

    /// Big enough that 16 chunks all clear `MIN_CHUNK_BYTES`, so a chunked run
    /// really is chunked rather than silently collapsing to one member.
    fn corpus_input() -> Vec<u8> {
        let envelope = corpus::scale_envelope(2_000);
        assert!(envelope.len() > MIN_CHUNK_BYTES * 16);
        gzip_bytes(envelope.as_bytes())
    }

    /// The `bufread` decoder consumes exactly one member and no lookahead, so
    /// the cursor lands on the next member's header.
    fn member_count(gzipped: &[u8]) -> usize {
        let mut cursor = std::io::Cursor::new(gzipped);
        let mut members = 0;
        while (cursor.position() as usize) < gzipped.len() {
            let before = cursor.position();
            let mut sink = Vec::new();
            flate2::bufread::GzDecoder::new(&mut cursor)
                .read_to_end(&mut sink)
                .expect("every member must be valid gzip");
            assert!(cursor.position() > before, "member decode made no progress");
            members += 1;
        }
        members
    }

    fn run_with_chunks(input: &[u8], chunks: usize) -> Bytes {
        let cfg = Processing {
            gzip_chunks: chunks,
            ..Processing::default()
        };
        let (outcome, _) =
            buffer_run(input, &drop_decrypt_engine(), &cfg).expect("buffer_run must succeed");
        written_bytes(outcome)
    }

    #[test]
    fn chunked_output_decompresses_to_exactly_the_same_payload_as_a_single_member() {
        let input = corpus_input();
        let single = gunzip(&run_with_chunks(&input, 1));
        assert_eq!(member_count(&run_with_chunks(&input, 1)), 1);
        for chunks in [2, 3, 4, 8, 16] {
            assert_eq!(member_count(&run_with_chunks(&input, chunks)), chunks);
            assert_eq!(
                gunzip(&run_with_chunks(&input, chunks)),
                single,
                "gzip_chunks {chunks} changed the decompressed payload"
            );
        }
    }

    #[test]
    fn gzip_chunks_of_one_is_byte_identical_to_the_unchunked_encoder() {
        let body = br#"{"Records":[{"eventName":"ConsoleLogin"}]}"#;
        assert_eq!(
            gzip_compress_chunked(body, 6, 1).expect("must compress"),
            gzip_compress(body, 6).expect("must compress"),
        );
    }

    #[test]
    fn chunked_output_really_is_multi_member() {
        let input = corpus_input();
        for chunks in [1, 2, 4, 8] {
            assert_eq!(
                member_count(&run_with_chunks(&input, chunks)),
                chunks,
                "gzip_chunks {chunks} did not emit {chunks} members"
            );
        }
    }

    #[test]
    fn chunking_is_deterministic_so_a_re_driven_object_rewrites_the_same_bytes() {
        let input = corpus_input();
        assert_eq!(run_with_chunks(&input, 4), run_with_chunks(&input, 4));
    }

    #[test]
    fn a_body_too_small_to_fill_one_chunk_stays_a_single_member() {
        let body = b"{}";
        assert_eq!(
            gzip_compress_chunked(body, 6, 16).expect("must compress"),
            gzip_compress(body, 6).expect("must compress"),
            "chunking a 2-byte body would pay 18 bytes of framing per member for nothing"
        );
    }

    #[test]
    fn the_chunk_count_is_capped_so_no_member_is_below_the_floor() {
        let body = vec![b'x'; MIN_CHUNK_BYTES * 3 + 7];
        let out = gzip_compress_chunked(&body, 6, 16).expect("must compress");
        assert_eq!(gunzip(&Bytes::from(out)), body);

        // 3 chunks' worth of body must not become 16 members.
        let mut first = Vec::new();
        flate2::read::GzDecoder::new(
            &gzip_compress_chunked(&body, 6, 16).expect("must compress")[..],
        )
        .read_to_end(&mut first)
        .expect("the first member must be valid gzip on its own");
        assert!(
            first.len() >= MIN_CHUNK_BYTES,
            "a member came out below the {MIN_CHUNK_BYTES}-byte floor: {}",
            first.len()
        );
    }

    #[test]
    fn survivors_stay_verbatim_through_the_chunked_path() {
        let input = corpus_input();
        let plain =
            String::from_utf8(gunzip(&run_with_chunks(&input, 8))).expect("output must be utf-8");
        let mut checked = 0;
        for body in corpus::scale_records(2_000).iter().step_by(97) {
            if body.contains(r#""eventName":"Decrypt""#) {
                continue;
            }
            assert!(
                plain.contains(body.as_str()),
                "a survivor was re-rendered rather than copied"
            );
            checked += 1;
        }
        assert!(checked > 10, "the sweep checked only {checked} survivors");
    }
}
