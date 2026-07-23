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
