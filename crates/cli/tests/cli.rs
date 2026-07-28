//! End-to-end tests for the `cloudtrail-rs` CLI binary (task 17), driven
//! through `assert_cmd` so they exercise the compiled binary exactly as a
//! user would invoke it — argument parsing, exit codes, and stdout/stderr
//! included.

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use assert_cmd::Command;
use flate2::Compression;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;

static UNIQUE: AtomicU64 = AtomicU64::new(0);

/// A path under the OS temp dir, unique per call so parallel tests never
/// collide (same approach `FileConfigSource`'s own tests use).
fn temp_path(label: &str) -> PathBuf {
    let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "cloudtrail-rs-cli-test-{}-{label}-{n}",
        std::process::id()
    ))
}

fn example_rules_path() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/rules.example.yaml"
    ))
}

fn gzip_bytes(body: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body).unwrap();
    encoder.finish().unwrap()
}

fn gunzip(input: &[u8]) -> Vec<u8> {
    let mut decoder = MultiGzDecoder::new(input);
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut decoder, &mut out).unwrap();
    out
}

#[test]
fn validate_example_ruleset_exits_zero_and_warns_about_always_rules() {
    let assert = Command::cargo_bin("cloudtrail-rs")
        .unwrap()
        .arg("validate")
        .arg(example_rules_path())
        .assert();
    let output = assert.get_output();

    assert!(
        output.status.success(),
        "validate must exit 0 on a valid ruleset, got {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("AWS Config Recorder"),
        "expected a warning naming \"AWS Config Recorder\", got stderr: {stderr}"
    );
    assert!(
        stderr.contains(r".*\.amazonaws\.com$"),
        "expected the warning to name the offending eventSource pattern, got stderr: {stderr}"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("25"),
        "expected the rule count (25) in stdout, got stdout: {stdout}"
    );
}

#[test]
fn validate_broken_ruleset_exits_nonzero() {
    let path = temp_path("broken-rules");
    std::fs::write(
        &path,
        br#"
version: 1.0.0
rules:
  - name: Bad Rule
    matches:
      - field_name: eventSource
        regex: "("
"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("cloudtrail-rs")
        .unwrap()
        .arg("validate")
        .arg(&path)
        .assert();
    let output = assert.get_output();

    assert!(
        !output.status.success(),
        "validate must exit non-zero on a broken ruleset"
    );

    std::fs::remove_file(&path).unwrap();
}

#[test]
fn filter_writes_filtered_gzip_output_via_buffer_run() {
    let rules_path = temp_path("filter-rules");
    std::fs::write(
        &rules_path,
        br#"
version: 1.0.0
rules:
  - name: Drop Decrypt
    matches:
      - field_name: eventName
        regex: "^Decrypt$"
"#,
    )
    .unwrap();

    let input_path = temp_path("filter-input.json.gz");
    let body = br#"{"Records":[{"eventName":"ConsoleLogin"},{"eventName":"Decrypt"}]}"#;
    std::fs::write(&input_path, gzip_bytes(body)).unwrap();

    let output_path = temp_path("filter-output.json.gz");

    let assert = Command::cargo_bin("cloudtrail-rs")
        .unwrap()
        .arg("filter")
        .arg(&input_path)
        .arg(&output_path)
        .arg("--rules")
        .arg(&rules_path)
        .assert();
    let output = assert.get_output();

    assert!(
        output.status.success(),
        "filter must exit 0 on success, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let written = std::fs::read(&output_path).expect("filter must write an output file");
    let decompressed = gunzip(&written);
    let parsed: serde_json::Value = serde_json::from_slice(&decompressed).unwrap();
    let names: Vec<&str> = parsed["Records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["eventName"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["ConsoleLogin"]);

    std::fs::remove_file(&rules_path).unwrap();
    std::fs::remove_file(&input_path).unwrap();
    std::fs::remove_file(&output_path).unwrap();
}

#[test]
fn filter_writes_nothing_when_all_records_dropped() {
    let rules_path = temp_path("filter-all-dropped-rules");
    std::fs::write(
        &rules_path,
        br#"
version: 1.0.0
rules:
  - name: Drop Decrypt
    matches:
      - field_name: eventName
        regex: "^Decrypt$"
"#,
    )
    .unwrap();

    let input_path = temp_path("filter-all-dropped-input.json.gz");
    let body = br#"{"Records":[{"eventName":"Decrypt"}]}"#;
    std::fs::write(&input_path, gzip_bytes(body)).unwrap();

    let output_path = temp_path("filter-all-dropped-output.json.gz");

    let assert = Command::cargo_bin("cloudtrail-rs")
        .unwrap()
        .arg("filter")
        .arg(&input_path)
        .arg(&output_path)
        .arg("--rules")
        .arg(&rules_path)
        .assert();
    let output = assert.get_output();

    assert!(
        output.status.success(),
        "filter must exit 0 even when nothing is kept, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output_path.exists(),
        "zero empty writes: filter must not create an output file when all records are dropped"
    );

    std::fs::remove_file(&rules_path).unwrap();
    std::fs::remove_file(&input_path).unwrap();
}

#[test]
fn filter_directory_mirrors_relative_paths_and_skips_all_dropped() {
    let rules_path = temp_path("filter-dir-rules");
    std::fs::write(
        &rules_path,
        br#"
version: 1.0.0
rules:
  - name: Drop Decrypt
    matches:
      - field_name: eventName
        regex: "^Decrypt$"
"#,
    )
    .unwrap();

    let in_dir = temp_path("filter-dir-in");
    let out_dir = temp_path("filter-dir-out");
    std::fs::create_dir_all(in_dir.join("nested")).unwrap();

    // Top-level object: one record survives.
    std::fs::write(
        in_dir.join("a.json.gz"),
        gzip_bytes(br#"{"Records":[{"eventName":"ConsoleLogin"},{"eventName":"Decrypt"}]}"#),
    )
    .unwrap();
    // Nested object: all records dropped => no output file.
    std::fs::write(
        in_dir.join("nested/b.json.gz"),
        gzip_bytes(br#"{"Records":[{"eventName":"Decrypt"}]}"#),
    )
    .unwrap();
    // Non-candidate file: must be ignored entirely.
    std::fs::write(in_dir.join("ignore.txt"), b"not a log").unwrap();

    let assert = Command::cargo_bin("cloudtrail-rs")
        .unwrap()
        .arg("filter")
        .arg(&in_dir)
        .arg(&out_dir)
        .arg("--rules")
        .arg(&rules_path)
        .assert();
    let output = assert.get_output();
    assert!(
        output.status.success(),
        "filter must exit 0 on a directory, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Surviving object mirrored at the same relative path.
    let written = std::fs::read(out_dir.join("a.json.gz")).expect("a.json.gz must be written");
    let parsed: serde_json::Value = serde_json::from_slice(&gunzip(&written)).unwrap();
    let names: Vec<&str> = parsed["Records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["eventName"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["ConsoleLogin"]);

    // All-dropped nested object: zero empty writes.
    assert!(
        !out_dir.join("nested/b.json.gz").exists(),
        "all-dropped object must not be written"
    );
    // Non-candidate file never mirrored.
    assert!(!out_dir.join("ignore.txt").exists());

    std::fs::remove_file(&rules_path).unwrap();
    std::fs::remove_dir_all(&in_dir).unwrap();
    std::fs::remove_dir_all(&out_dir).unwrap();
}

#[test]
fn test_command_reports_per_record_keep_drop_and_summary() {
    let rules_path = temp_path("test-cmd-rules");
    std::fs::write(
        &rules_path,
        br#"
version: 1.0.0
rules:
  - name: Drop Decrypt
    matches:
      - field_name: eventName
        regex: "^Decrypt$"
"#,
    )
    .unwrap();

    let sample_path = temp_path("test-cmd-sample.json.gz");
    let body = br#"{"Records":[
        {"eventName":"ConsoleLogin"},
        {"eventName":"Decrypt"},
        {"eventName":"AssumeRole"}
    ]}"#;
    std::fs::write(&sample_path, gzip_bytes(body)).unwrap();

    let assert = Command::cargo_bin("cloudtrail-rs")
        .unwrap()
        .arg("test")
        .arg(&rules_path)
        .arg(&sample_path)
        .assert();
    let output = assert.get_output();

    assert!(
        output.status.success(),
        "test must exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("KEEP") && stdout.contains("DROP"),
        "expected per-record KEEP/DROP lines, got stdout: {stdout}"
    );
    assert!(
        stdout.contains("Drop Decrypt"),
        "expected the dropping rule's name in the output, got stdout: {stdout}"
    );
    assert!(
        stdout.contains('%'),
        "expected summary percentages in the output, got stdout: {stdout}"
    );

    std::fs::remove_file(&rules_path).unwrap();
    std::fs::remove_file(&sample_path).unwrap();
}

#[test]
fn validate_settings_accepts_defaults_via_env_only() {
    let assert = Command::cargo_bin("cloudtrail-rs")
        .unwrap()
        .arg("validate-settings")
        .env("CT_DEST_BUCKET", "env-only-bucket")
        .assert();
    let output = assert.get_output();

    assert!(
        output.status.success(),
        "validate-settings must accept built-in defaults + CT_DEST_BUCKET, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("env-only-bucket"),
        "expected the effective dest bucket in the summary, got stdout: {stdout}"
    );
}

#[test]
fn validate_settings_accepts_a_valid_file() {
    let path = temp_path("validate-settings-good.yaml");
    std::fs::write(
        &path,
        b"version: 1\ndestination:\n  bucket: file-bucket\nprocessing:\n  gzip_level: 9\n",
    )
    .unwrap();

    let assert = Command::cargo_bin("cloudtrail-rs")
        .unwrap()
        .arg("validate-settings")
        .arg(&path)
        .assert();
    let output = assert.get_output();

    assert!(
        output.status.success(),
        "validate-settings must exit 0 on a valid settings file, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("file-bucket"));

    std::fs::remove_file(&path).unwrap();
}

#[test]
fn validate_settings_rejects_gzip_level_above_nine() {
    let path = temp_path("validate-settings-bad-gzip.yaml");
    std::fs::write(
        &path,
        b"version: 1\ndestination:\n  bucket: b\nprocessing:\n  gzip_level: 11\n",
    )
    .unwrap();

    let assert = Command::cargo_bin("cloudtrail-rs")
        .unwrap()
        .arg("validate-settings")
        .arg(&path)
        .assert();
    let output = assert.get_output();

    assert!(
        !output.status.success(),
        "validate-settings must exit non-zero on gzip_level 11"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("gzip_level"),
        "error must name the offending key, got stderr: {stderr}"
    );

    std::fs::remove_file(&path).unwrap();
}

#[test]
fn validate_settings_rejects_max_object_bytes_below_stream_threshold() {
    let path = temp_path("validate-settings-bad-thresholds.yaml");
    std::fs::write(
        &path,
        b"version: 1\ndestination:\n  bucket: b\nprocessing:\n  stream_threshold_bytes: 100\n  max_object_bytes: 10\n",
    )
    .unwrap();

    let assert = Command::cargo_bin("cloudtrail-rs")
        .unwrap()
        .arg("validate-settings")
        .arg(&path)
        .assert();
    let output = assert.get_output();

    assert!(
        !output.status.success(),
        "validate-settings must exit non-zero when max_object_bytes < stream_threshold_bytes"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("max_object_bytes") && stderr.contains("stream_threshold_bytes"),
        "error must name both keys, got stderr: {stderr}"
    );

    std::fs::remove_file(&path).unwrap();
}

#[test]
fn validate_settings_env_override_wins_over_file() {
    let path = temp_path("validate-settings-env-override.yaml");
    std::fs::write(&path, b"version: 1\ndestination:\n  bucket: file-bucket\n").unwrap();

    let assert = Command::cargo_bin("cloudtrail-rs")
        .unwrap()
        .arg("validate-settings")
        .arg(&path)
        .env("CT_DEST_BUCKET", "env-wins-bucket")
        .assert();
    let output = assert.get_output();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("env-wins-bucket") && !stdout.contains("file-bucket"),
        "CT_DEST_BUCKET must override the file value, got stdout: {stdout}"
    );

    std::fs::remove_file(&path).unwrap();
}

// ---------------------------------------------------------------------------
// `filter --settings`: a backfill must select and process the same objects,
// the same way, as the deployment whose settings it is handed.
// ---------------------------------------------------------------------------

/// A rules document that drops exactly `Decrypt`, reused by the tests below.
fn drop_decrypt_rules(label: &str) -> PathBuf {
    let path = temp_path(label);
    std::fs::write(
        &path,
        br#"
version: 1.0.0
rules:
  - name: Drop Decrypt
    matches:
      - field_name: eventName
        regex: "^Decrypt$"
"#,
    )
    .unwrap();
    path
}

/// A settings document. `destination.bucket` is required by `validate` even
/// though `filter` takes its destination from the `dest` argument.
fn write_settings(label: &str, body: &str) -> PathBuf {
    let path = temp_path(label);
    std::fs::write(&path, body.as_bytes()).unwrap();
    path
}

fn kept_event_names(bytes: &[u8]) -> Vec<String> {
    let parsed: serde_json::Value = serde_json::from_slice(&gunzip(bytes)).unwrap();
    parsed["Records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["eventName"].as_str().unwrap().to_string())
        .collect()
}

/// #10: the key filter comes from `source.include_key_regex` /
/// `exclude_key_regex`, not from a hardcoded `.json.gz` check. With a
/// deployment that names its objects `.log.gz`, a backfill must pick up
/// exactly those — and must skip what the deployment's exclude pattern
/// skips — or it selects a different object set than production.
#[test]
fn filter_settings_key_regexes_select_the_production_object_set() {
    let rules_path = drop_decrypt_rules("filter-keys-rules");
    let settings_path = write_settings(
        "filter-keys-settings.yaml",
        "version: 1\n\
         source:\n  \
           include_key_regex: \"\\\\.log\\\\.gz$\"\n  \
           exclude_key_regex: \"(^|/)skipme/\"\n\
         destination:\n  bucket: unused-by-the-cli\n",
    );

    let in_dir = temp_path("filter-keys-in");
    let out_dir = temp_path("filter-keys-out");
    std::fs::create_dir_all(in_dir.join("skipme")).unwrap();

    let body = br#"{"Records":[{"eventName":"ConsoleLogin"},{"eventName":"Decrypt"}]}"#;
    // In scope under this deployment's include pattern.
    std::fs::write(in_dir.join("a.log.gz"), gzip_bytes(body)).unwrap();
    // The old hardcoded filter would have taken this one; the deployment does not.
    std::fs::write(in_dir.join("b.json.gz"), gzip_bytes(body)).unwrap();
    // Matches include, but the deployment excludes the whole path segment.
    std::fs::write(in_dir.join("skipme/c.log.gz"), gzip_bytes(body)).unwrap();

    let assert = Command::cargo_bin("cloudtrail-rs")
        .unwrap()
        .arg("filter")
        .arg(&in_dir)
        .arg(&out_dir)
        .arg("--rules")
        .arg(&rules_path)
        .arg("--settings")
        .arg(&settings_path)
        .assert();
    let output = assert.get_output();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let written = std::fs::read(out_dir.join("a.log.gz")).expect("a.log.gz is in scope");
    assert_eq!(kept_event_names(&written), vec!["ConsoleLogin"]);
    assert!(
        !out_dir.join("b.json.gz").exists(),
        "b.json.gz does not match source.include_key_regex and must not be processed"
    );
    assert!(
        !out_dir.join("skipme/c.log.gz").exists(),
        "skipme/c.log.gz matches source.exclude_key_regex and must not be processed"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("processed 1 object(s)"),
        "exactly one object is in scope, got stdout: {stdout}"
    );

    std::fs::remove_file(&rules_path).unwrap();
    std::fs::remove_file(&settings_path).unwrap();
    std::fs::remove_dir_all(&in_dir).unwrap();
    std::fs::remove_dir_all(&out_dir).unwrap();
}

/// #11: `mode: stream` must actually stream — through `stream_run`, writing
/// via the destination store — and an all-dropped object must leave nothing
/// behind, not even the partial file the streaming write goes through.
///
/// `max_object_bytes` is what makes this a real test of the mode rather than
/// of the output: it is buffer mode's memory cap and stream mode has
/// none, so the kept object here can only be written by streaming it.
#[test]
fn filter_settings_stream_mode_round_trips_and_leaves_no_partial() {
    let rules_path = drop_decrypt_rules("filter-stream-rules");
    let settings_path = write_settings(
        "filter-stream-settings.yaml",
        "version: 1\n\
         destination:\n  bucket: unused-by-the-cli\n\
         processing:\n  mode: stream\n  \
           stream_threshold_bytes: 1024\n  max_object_bytes: 1024\n",
    );

    let in_dir = temp_path("filter-stream-in");
    let out_dir = temp_path("filter-stream-out");
    std::fs::create_dir_all(&in_dir).unwrap();
    let padding = "a".repeat(4096);
    std::fs::write(
        in_dir.join("kept.json.gz"),
        gzip_bytes(
            format!(
                r#"{{"Records":[{{"eventName":"ConsoleLogin","userAgent":"{padding}"}},{{"eventName":"Decrypt"}}]}}"#
            )
            .as_bytes(),
        ),
    )
    .unwrap();
    std::fs::write(
        in_dir.join("dropped.json.gz"),
        gzip_bytes(br#"{"Records":[{"eventName":"Decrypt"}]}"#),
    )
    .unwrap();

    let assert = Command::cargo_bin("cloudtrail-rs")
        .unwrap()
        .arg("filter")
        .arg(&in_dir)
        .arg(&out_dir)
        .arg("--rules")
        .arg(&rules_path)
        .arg("--settings")
        .arg(&settings_path)
        .assert();
    let output = assert.get_output();
    assert!(
        output.status.success(),
        "stream mode must succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let written = std::fs::read(out_dir.join("kept.json.gz")).expect("survivors must be written");
    assert_eq!(kept_event_names(&written), vec!["ConsoleLogin"]);
    assert!(
        !out_dir.join("dropped.json.gz").exists(),
        "zero empty writes: an all-dropped object must not be written in stream mode either"
    );
    // The aborted streaming upload must not leave its temp file behind.
    let leftovers: Vec<String> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".partial"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "aborted streaming write left {leftovers:?} behind"
    );

    std::fs::remove_file(&rules_path).unwrap();
    std::fs::remove_file(&settings_path).unwrap();
    std::fs::remove_dir_all(&in_dir).unwrap();
    std::fs::remove_dir_all(&out_dir).unwrap();
}

/// #11: an object the Lambda handles must not fail the CLI. In `auto` mode a
/// small-but-highly-compressible object is routed to buffer mode and blows
/// `max_object_bytes` (buffer mode's memory cap); the pipeline retries
/// it through stream mode, and so must `filter`. Under an explicit
/// `mode: buffer` the operator opted out of streaming, so the error stands.
#[test]
fn filter_auto_mode_retries_oversized_object_through_stream() {
    let rules_path = drop_decrypt_rules("filter-oversize-rules");
    // Compresses to well under stream_threshold_bytes (so `auto` picks
    // buffer) but decompresses to well over max_object_bytes.
    let padding = "a".repeat(4096);
    let body = format!(
        r#"{{"Records":[{{"eventName":"ConsoleLogin","userAgent":"{padding}"}},{{"eventName":"Decrypt"}}]}}"#
    );
    let input_path = temp_path("filter-oversize-input.json.gz");
    std::fs::write(&input_path, gzip_bytes(body.as_bytes())).unwrap();
    assert!(
        std::fs::metadata(&input_path).unwrap().len() < 1024,
        "the fixture must compress below stream_threshold_bytes to be routed to buffer mode"
    );

    let caps = "processing:\n  stream_threshold_bytes: 1024\n  max_object_bytes: 1024\n  mode: ";
    let auto_settings = write_settings(
        "filter-oversize-auto.yaml",
        &format!("version: 1\ndestination:\n  bucket: unused-by-the-cli\n{caps}auto\n"),
    );
    let buffer_settings = write_settings(
        "filter-oversize-buffer.yaml",
        &format!("version: 1\ndestination:\n  bucket: unused-by-the-cli\n{caps}buffer\n"),
    );

    let output_path = temp_path("filter-oversize-output.json.gz");
    let assert = Command::cargo_bin("cloudtrail-rs")
        .unwrap()
        .arg("filter")
        .arg(&input_path)
        .arg(&output_path)
        .arg("--rules")
        .arg(&rules_path)
        .arg("--settings")
        .arg(&auto_settings)
        .assert();
    let output = assert.get_output();
    assert!(
        output.status.success(),
        "auto mode must retry an over-cap object through stream mode, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let written = std::fs::read(&output_path).expect("the retry must write the object");
    assert_eq!(kept_event_names(&written), vec!["ConsoleLogin"]);

    // Explicit buffer mode: no retry, the cap is enforced.
    let buffer_out = temp_path("filter-oversize-buffer-output.json.gz");
    let assert = Command::cargo_bin("cloudtrail-rs")
        .unwrap()
        .arg("filter")
        .arg(&input_path)
        .arg(&buffer_out)
        .arg("--rules")
        .arg(&rules_path)
        .arg("--settings")
        .arg(&buffer_settings)
        .assert();
    let output = assert.get_output();
    assert!(
        !output.status.success(),
        "an explicit mode: buffer must not silently fall back to streaming"
    );
    assert!(!buffer_out.exists());

    std::fs::remove_file(&rules_path).unwrap();
    std::fs::remove_file(&auto_settings).unwrap();
    std::fs::remove_file(&buffer_settings).unwrap();
    std::fs::remove_file(&input_path).unwrap();
    std::fs::remove_file(&output_path).unwrap();
}

/// #11: one unreadable object must not abandon the rest of the batch. The
/// run continues, the summary still prints, every failure is listed, and the
/// exit code is non-zero.
#[test]
fn filter_batch_continues_past_a_failure_and_exits_nonzero() {
    let rules_path = drop_decrypt_rules("filter-failure-rules");

    let in_dir = temp_path("filter-failure-in");
    let out_dir = temp_path("filter-failure-out");
    std::fs::create_dir_all(&in_dir).unwrap();
    let body = br#"{"Records":[{"eventName":"ConsoleLogin"},{"eventName":"Decrypt"}]}"#;
    // Enumeration is sorted, so the corrupt object sits between two healthy
    // ones: the object after it proves the run did not stop.
    std::fs::write(in_dir.join("a.json.gz"), gzip_bytes(body)).unwrap();
    std::fs::write(in_dir.join("b-corrupt.json.gz"), b"this is not gzip").unwrap();
    std::fs::write(in_dir.join("c.json.gz"), gzip_bytes(body)).unwrap();

    let assert = Command::cargo_bin("cloudtrail-rs")
        .unwrap()
        .arg("filter")
        .arg(&in_dir)
        .arg(&out_dir)
        .arg("--rules")
        .arg(&rules_path)
        .assert();
    let output = assert.get_output();

    assert!(
        !output.status.success(),
        "a failed object must produce a non-zero exit"
    );
    assert_eq!(
        kept_event_names(&std::fs::read(out_dir.join("a.json.gz")).expect("a.json.gz")),
        vec!["ConsoleLogin"]
    );
    assert_eq!(
        kept_event_names(
            &std::fs::read(out_dir.join("c.json.gz"))
                .expect("the object after the failure must still be processed")
        ),
        vec!["ConsoleLogin"]
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("processed 3 object(s)") && stdout.contains("1 failed"),
        "the summary must print despite the failure, got stdout: {stdout}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("b-corrupt.json.gz"),
        "the failed object must be named, got stderr: {stderr}"
    );

    std::fs::remove_file(&rules_path).unwrap();
    std::fs::remove_dir_all(&in_dir).unwrap();
    std::fs::remove_dir_all(&out_dir).unwrap();
}

/// #9: `behavior.dry_run` is the deployment's "evaluate but write nothing"
/// switch; a backfill handed those settings must honour it.
#[test]
fn filter_settings_dry_run_evaluates_and_writes_nothing() {
    let rules_path = drop_decrypt_rules("filter-dryrun-rules");
    let settings_path = write_settings(
        "filter-dryrun-settings.yaml",
        "version: 1\n\
         destination:\n  bucket: unused-by-the-cli\n\
         behavior:\n  dry_run: true\n",
    );

    let input_path = temp_path("filter-dryrun-input.json.gz");
    std::fs::write(
        &input_path,
        gzip_bytes(br#"{"Records":[{"eventName":"ConsoleLogin"},{"eventName":"Decrypt"}]}"#),
    )
    .unwrap();
    let output_path = temp_path("filter-dryrun-output.json.gz");

    let assert = Command::cargo_bin("cloudtrail-rs")
        .unwrap()
        .arg("filter")
        .arg(&input_path)
        .arg(&output_path)
        .arg("--rules")
        .arg(&rules_path)
        .arg("--settings")
        .arg(&settings_path)
        .assert();
    let output = assert.get_output();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output_path.exists(), "behavior.dry_run must write nothing");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("dry run"), "got stdout: {stdout}");
    // Records are still evaluated and counted — that is the point of a dry run.
    assert!(
        stdout.contains("records: 2 in, 1 kept, 1 dropped"),
        "a dry run must still report what would be filtered, got stdout: {stdout}"
    );

    std::fs::remove_file(&rules_path).unwrap();
    std::fs::remove_file(&settings_path).unwrap();
    std::fs::remove_file(&input_path).unwrap();
}

/// #9: `behavior.on_unrecognized_object` decides what happens to an object
/// with no `Records` array. The default copies it verbatim; a deployment set
/// to `skip` must not have its backfill copy it.
#[test]
fn filter_settings_on_unrecognized_object_skip_does_not_copy() {
    let rules_path = drop_decrypt_rules("filter-unrecognized-rules");
    let input_path = temp_path("filter-unrecognized-input.json.gz");
    std::fs::write(&input_path, gzip_bytes(br#"{"someOtherShape":true}"#)).unwrap();

    // Default behavior (no --settings): copy verbatim, never discard.
    let copied_path = temp_path("filter-unrecognized-copied.json.gz");
    let assert = Command::cargo_bin("cloudtrail-rs")
        .unwrap()
        .arg("filter")
        .arg(&input_path)
        .arg(&copied_path)
        .arg("--rules")
        .arg(&rules_path)
        .assert();
    assert!(assert.get_output().status.success());
    assert_eq!(
        gunzip(&std::fs::read(&copied_path).expect("default policy copies verbatim")),
        br#"{"someOtherShape":true}"#.to_vec()
    );

    // Same object, a deployment configured to skip.
    let settings_path = write_settings(
        "filter-unrecognized-settings.yaml",
        "version: 1\n\
         destination:\n  bucket: unused-by-the-cli\n\
         behavior:\n  on_unrecognized_object: skip\n",
    );
    let skipped_path = temp_path("filter-unrecognized-skipped.json.gz");
    let assert = Command::cargo_bin("cloudtrail-rs")
        .unwrap()
        .arg("filter")
        .arg(&input_path)
        .arg(&skipped_path)
        .arg("--rules")
        .arg(&rules_path)
        .arg("--settings")
        .arg(&settings_path)
        .assert();
    let output = assert.get_output();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !skipped_path.exists(),
        "on_unrecognized_object: skip must not copy the object"
    );

    std::fs::remove_file(&rules_path).unwrap();
    std::fs::remove_file(&settings_path).unwrap();
    std::fs::remove_file(&input_path).unwrap();
    std::fs::remove_file(&copied_path).unwrap();
}
