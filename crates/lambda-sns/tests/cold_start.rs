//! Drives the **real** `bootstrap` binary of the SNS Lambda end to end
//! against a live MiniStack, via a fake Lambda Runtime API.
//!
//! `#[ignore]`d: needs the container from `docker-compose.test.yml`. Run with
//! `cargo test --workspace -- --ignored`.

#![allow(clippy::unwrap_used)]

use std::time::Duration;

use cloudtrail_rs_testkit::fixtures::{
    DROP_DECRYPT_RULES, cloudtrail_body, gunzip, gzip_bytes, sns_event,
};
use cloudtrail_rs_testkit::ministack::{
    self, ensure_bucket, get_object, lambda_env, put_object, put_parameter,
};
use cloudtrail_rs_testkit::{FakeRuntimeApi, LambdaProcess};

const SRC_BUCKET: &str = "ct-lambda-sns-src";
const DEST_BUCKET: &str = "ct-lambda-sns-dest";
const RULES_PARAM: &str = "/cloudtrail-rs-tests/lambda-sns-rules";
const TIMEOUT: Duration = Duration::from_secs(60);

#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn real_bootstrap_binary_filters_an_sns_notification_end_to_end() {
    let s3 = ministack::s3_client();
    let ssm = ministack::ssm_client();

    ensure_bucket(&s3, SRC_BUCKET).await;
    ensure_bucket(&s3, DEST_BUCKET).await;
    put_parameter(&ssm, RULES_PARAM, DROP_DECRYPT_RULES).await;

    let key = "lambda-sns/cold-start/cloudtrail.json.gz";
    let (body, expected_body) = cloudtrail_body(20);
    let gzipped = gzip_bytes(&body, 6);
    put_object(&s3, SRC_BUCKET, key, gzipped.clone()).await;
    ministack::delete_object(&s3, DEST_BUCKET, key).await;

    let api = FakeRuntimeApi::start(&[sns_event(SRC_BUCKET, key, gzipped.len() as u64)]);
    let env = lambda_env(DEST_BUCKET, &format!("ssm://{RULES_PARAM}"));
    let mut lambda = LambdaProcess::spawn(env!("CARGO_BIN_EXE_bootstrap-sns"), &api.addr(), &env);

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

/// `CT_KEY_PREFIX` is applied by the pipeline, but only a real binary proves
/// the env override survives `Settings::load` and reaches the destination key.
#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn key_prefix_env_override_reaches_the_destination_key() {
    let s3 = ministack::s3_client();
    let ssm = ministack::ssm_client();

    ensure_bucket(&s3, SRC_BUCKET).await;
    ensure_bucket(&s3, DEST_BUCKET).await;
    put_parameter(&ssm, RULES_PARAM, DROP_DECRYPT_RULES).await;

    let key = "lambda-sns/prefixed/cloudtrail.json.gz";
    let prefixed = format!("filtered/{key}");
    let (body, expected_body) = cloudtrail_body(10);
    let gzipped = gzip_bytes(&body, 6);
    put_object(&s3, SRC_BUCKET, key, gzipped.clone()).await;
    ministack::delete_object(&s3, DEST_BUCKET, &prefixed).await;

    let api = FakeRuntimeApi::start(&[sns_event(SRC_BUCKET, key, gzipped.len() as u64)]);
    let mut env = lambda_env(DEST_BUCKET, &format!("ssm://{RULES_PARAM}"));
    env.push(("CT_KEY_PREFIX", "filtered/".to_string()));
    let mut lambda = LambdaProcess::spawn(env!("CARGO_BIN_EXE_bootstrap-sns"), &api.addr(), &env);

    lambda.expect_one_response(&api, TIMEOUT);

    let written = get_object(&s3, DEST_BUCKET, &prefixed).await;
    assert_eq!(gunzip(&written), expected_body);
}
