//! Drives the **real** `bootstrap` binary end to end: a fake Lambda Runtime
//! API hands it an S3 notification, the binary's own `main` performs cold-start
//! init against a live MiniStack, and the filtered object must land in the
//! destination bucket.
//!
//! This is the only kind of test that covers a composition root. Everything
//! `main` does — `Settings::load`, `load_aws_config`, adapter construction,
//! `ConfigStore::prime` — runs in a separate process here, exactly as it does
//! in Lambda, so an init-time panic is a test failure rather than a
//! production incident.
//!
//! `#[ignore]`d: needs the container from `docker-compose.test.yml`. Run with
//! `cargo test --workspace -- --ignored`.

#![allow(clippy::unwrap_used)]

use std::time::Duration;

use cloudtrail_rs_testkit::fixtures::{
    DROP_DECRYPT_RULES, cloudtrail_body, gunzip, gzip_bytes, s3_event,
};
use cloudtrail_rs_testkit::ministack::{
    self, ensure_bucket, get_object, lambda_env, put_object, put_parameter,
};
use cloudtrail_rs_testkit::{FakeRuntimeApi, LambdaProcess};

const SRC_BUCKET: &str = "ct-lambda-s3-src";
const DEST_BUCKET: &str = "ct-lambda-s3-dest";
const RULES_PARAM: &str = "/cloudtrail-rs-tests/lambda-s3-rules";
const TIMEOUT: Duration = Duration::from_secs(60);

#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn real_bootstrap_binary_filters_an_s3_notification_end_to_end() {
    let s3 = ministack::s3_client();
    let ssm = ministack::ssm_client();

    ensure_bucket(&s3, SRC_BUCKET).await;
    ensure_bucket(&s3, DEST_BUCKET).await;
    put_parameter(&ssm, RULES_PARAM, DROP_DECRYPT_RULES).await;

    let key = "lambda-s3/cold-start/cloudtrail.json.gz";
    let (body, expected_body) = cloudtrail_body(20);
    let gzipped = gzip_bytes(&body, 6);
    put_object(&s3, SRC_BUCKET, key, gzipped.clone()).await;
    // Start from a known state: without this, a stale object from a previous
    // run would satisfy the final assertion even if the binary wrote nothing.
    ministack::delete_object(&s3, DEST_BUCKET, key).await;

    let api = FakeRuntimeApi::start(&[s3_event(SRC_BUCKET, key, gzipped.len() as u64)]);
    let env = lambda_env(DEST_BUCKET, &format!("ssm://{RULES_PARAM}"));
    let mut lambda = LambdaProcess::spawn(env!("CARGO_BIN_EXE_bootstrap-s3"), &api.addr(), &env);

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

/// The same path with the ruleset in S3 rather than SSM, so `S3ConfigSource`
/// is covered by a real binary too — `build_config_source`'s `s3://` arm is
/// otherwise never executed outside a unit test.
#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn real_bootstrap_binary_reads_its_ruleset_from_s3() {
    let s3 = ministack::s3_client();

    ensure_bucket(&s3, SRC_BUCKET).await;
    ensure_bucket(&s3, DEST_BUCKET).await;

    let rules_key = "config/rules.yaml";
    put_object(
        &s3,
        SRC_BUCKET,
        rules_key,
        DROP_DECRYPT_RULES.as_bytes().to_vec(),
    )
    .await;

    let key = "lambda-s3/cold-start-s3-rules/cloudtrail.json.gz";
    let (body, expected_body) = cloudtrail_body(10);
    let gzipped = gzip_bytes(&body, 6);
    put_object(&s3, SRC_BUCKET, key, gzipped.clone()).await;
    ministack::delete_object(&s3, DEST_BUCKET, key).await;

    let api = FakeRuntimeApi::start(&[s3_event(SRC_BUCKET, key, gzipped.len() as u64)]);
    let env = lambda_env(DEST_BUCKET, &format!("s3://{SRC_BUCKET}/{rules_key}"));
    let mut lambda = LambdaProcess::spawn(env!("CARGO_BIN_EXE_bootstrap-s3"), &api.addr(), &env);

    lambda.expect_one_response(&api, TIMEOUT);

    let written = get_object(&s3, DEST_BUCKET, key).await;
    assert_eq!(gunzip(&written), expected_body);
}
