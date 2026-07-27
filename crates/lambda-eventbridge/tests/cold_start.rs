//! Drives the **real** `bootstrap` binary of the EventBridge Lambda end to end
//! against a live MiniStack, via a fake Lambda Runtime API.
//!
//! `#[ignore]`d: needs the container from `docker-compose.test.yml`. Run with
//! `cargo test --workspace -- --ignored`.

#![allow(clippy::unwrap_used)]

use std::time::Duration;

use cloudtrail_rs_testkit::fixtures::{
    DROP_DECRYPT_RULES, cloudtrail_body, eventbridge_event, gunzip, gzip_bytes,
};
use cloudtrail_rs_testkit::ministack::{
    self, ensure_bucket, get_object, lambda_env, put_object, put_parameter,
};
use cloudtrail_rs_testkit::{FakeRuntimeApi, LambdaProcess};

const SRC_BUCKET: &str = "ct-lambda-eb-src";
const DEST_BUCKET: &str = "ct-lambda-eb-dest";
const RULES_PARAM: &str = "/cloudtrail-rs-tests/lambda-eb-rules";
const TIMEOUT: Duration = Duration::from_secs(60);

#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn real_bootstrap_binary_filters_an_eventbridge_event_end_to_end() {
    let s3 = ministack::s3_client();
    let ssm = ministack::ssm_client();

    ensure_bucket(&s3, SRC_BUCKET).await;
    ensure_bucket(&s3, DEST_BUCKET).await;
    put_parameter(&ssm, RULES_PARAM, DROP_DECRYPT_RULES).await;

    let key = "lambda-eb/cold-start/cloudtrail.json.gz";
    let (body, expected_body) = cloudtrail_body(20);
    let gzipped = gzip_bytes(&body, 6);
    put_object(&s3, SRC_BUCKET, key, gzipped.clone()).await;
    ministack::delete_object(&s3, DEST_BUCKET, key).await;

    let api = FakeRuntimeApi::start(&[eventbridge_event(SRC_BUCKET, key, gzipped.len() as u64)]);
    let env = lambda_env(DEST_BUCKET, &format!("ssm://{RULES_PARAM}"));
    let mut lambda = LambdaProcess::spawn(
        env!("CARGO_BIN_EXE_bootstrap-eventbridge"),
        &api.addr(),
        &env,
    );

    let response = lambda.expect_one_response(&api, TIMEOUT);
    assert_eq!(response, "null", "handler returns unit on success");

    let written = get_object(&s3, DEST_BUCKET, key).await;
    assert_eq!(
        gunzip(&written),
        expected_body,
        "destination bytes must decompress to exactly the surviving Records\n\
         ---- child output ----\n{}",
        lambda.logs()
    );
}

/// A `file://` ruleset exercises `build_config_source`'s third arm — the one
/// deployment shape that needs no AWS call to load rules at all.
#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn real_bootstrap_binary_reads_a_file_ruleset() {
    let s3 = ministack::s3_client();

    ensure_bucket(&s3, SRC_BUCKET).await;
    ensure_bucket(&s3, DEST_BUCKET).await;

    // Written under the crate's target dir so the path exists for the child
    // process and is cleaned up by `cargo clean` like any other build output.
    let rules_path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("eb-rules.yaml");
    std::fs::write(&rules_path, DROP_DECRYPT_RULES).expect("write rules file");

    let key = "lambda-eb/file-rules/cloudtrail.json.gz";
    let (body, expected_body) = cloudtrail_body(10);
    let gzipped = gzip_bytes(&body, 6);
    put_object(&s3, SRC_BUCKET, key, gzipped.clone()).await;
    ministack::delete_object(&s3, DEST_BUCKET, key).await;

    let api = FakeRuntimeApi::start(&[eventbridge_event(SRC_BUCKET, key, gzipped.len() as u64)]);
    let env = lambda_env(
        DEST_BUCKET,
        &format!("file://{}", rules_path.to_string_lossy()),
    );
    let mut lambda = LambdaProcess::spawn(
        env!("CARGO_BIN_EXE_bootstrap-eventbridge"),
        &api.addr(),
        &env,
    );

    lambda.expect_one_response(&api, TIMEOUT);

    let written = get_object(&s3, DEST_BUCKET, key).await;
    assert_eq!(gunzip(&written), expected_body);
}

/// `CT_DRY_RUN=true` is a true no-op against the destination: it evaluates the
/// ruleset (metrics report what *would* be dropped) but writes nothing at all —
/// the safety valve for previewing a ruleset against production traffic.
#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn dry_run_writes_no_destination_object() {
    let s3 = ministack::s3_client();
    let ssm = ministack::ssm_client();

    ensure_bucket(&s3, SRC_BUCKET).await;
    ensure_bucket(&s3, DEST_BUCKET).await;
    put_parameter(&ssm, RULES_PARAM, DROP_DECRYPT_RULES).await;

    let key = "lambda-eb/dry-run/cloudtrail.json.gz";
    let (body, _) = cloudtrail_body(10);
    let gzipped = gzip_bytes(&body, 6);
    put_object(&s3, SRC_BUCKET, key, gzipped.clone()).await;
    ministack::delete_object(&s3, DEST_BUCKET, key).await;

    let api = FakeRuntimeApi::start(&[eventbridge_event(SRC_BUCKET, key, gzipped.len() as u64)]);
    let mut env = lambda_env(DEST_BUCKET, &format!("ssm://{RULES_PARAM}"));
    env.push(("CT_DRY_RUN", "true".to_string()));
    let mut lambda = LambdaProcess::spawn(
        env!("CARGO_BIN_EXE_bootstrap-eventbridge"),
        &api.addr(),
        &env,
    );

    lambda.expect_one_response(&api, TIMEOUT);

    assert!(
        !ministack::object_exists(&s3, DEST_BUCKET, key).await,
        "dry run must not write to the destination bucket\n\
         ---- child output ----\n{}",
        lambda.logs()
    );
}
