//! Drives the **real** `bootstrap` binary of the SQS Lambda end to end against a
//! live MiniStack, via a fake Lambda Runtime API.
//!
//! Beyond the composition root's cold-start init, this is the only test that
//! observes the actual partial-batch response the event source mapping receives.
//!
//! `#[ignore]`d: needs the container from `docker-compose.test.yml`.

#![allow(clippy::unwrap_used)]

use std::time::Duration;

use cloudtrail_rs_testkit::fixtures::{
    DROP_DECRYPT_RULES, cloudtrail_body, gunzip, gzip_bytes, sqs_event_with_s3_body,
    sqs_event_with_sns_body,
};
use cloudtrail_rs_testkit::ministack::{
    self, ensure_bucket, get_object, lambda_env, put_object, put_parameter,
};
use cloudtrail_rs_testkit::{FakeRuntimeApi, LambdaProcess};

const SRC_BUCKET: &str = "ct-lambda-sqs-src";
const DEST_BUCKET: &str = "ct-lambda-sqs-dest";
const RULES_PARAM: &str = "/cloudtrail-rs-tests/lambda-sqs-rules";
const TIMEOUT: Duration = Duration::from_secs(60);

#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn real_bootstrap_binary_processes_an_sqs_batch_and_reports_no_failures() {
    let s3 = ministack::s3_client();
    let ssm = ministack::ssm_client();

    ensure_bucket(&s3, SRC_BUCKET).await;
    ensure_bucket(&s3, DEST_BUCKET).await;
    put_parameter(&ssm, RULES_PARAM, DROP_DECRYPT_RULES).await;

    let key = "lambda-sqs/cold-start/cloudtrail.json.gz";
    let (body, expected_body) = cloudtrail_body(20);
    let gzipped = gzip_bytes(&body, 6);
    put_object(&s3, SRC_BUCKET, key, gzipped.clone()).await;
    ministack::delete_object(&s3, DEST_BUCKET, key).await;

    let event = sqs_event_with_s3_body("msg-1", SRC_BUCKET, key, gzipped.len() as u64);
    let api = FakeRuntimeApi::start(&[event]);
    let env = lambda_env(DEST_BUCKET, &format!("ssm://{RULES_PARAM}"));
    let mut lambda = LambdaProcess::spawn(env!("CARGO_BIN_EXE_bootstrap-sqs"), &api.addr(), &env);

    let response = lambda.expect_one_response(&api, TIMEOUT);
    let response: serde_json::Value = serde_json::from_str(&response).expect("response is JSON");
    assert_eq!(
        response,
        serde_json::json!({ "batchItemFailures": [] }),
        "a fully successful batch must report no item failures\n\
         ---- child output ----\n{}",
        lambda.logs()
    );

    let written = get_object(&s3, DEST_BUCKET, key).await;
    assert_eq!(gunzip(&written), expected_body);
}

/// A message naming a missing object must come back as an `itemIdentifier` so
/// the mapping re-drives only that message. `on_missing_object` at its `error`
/// default is the production failure path.
#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn missing_object_is_reported_as_a_partial_batch_failure() {
    let s3 = ministack::s3_client();
    let ssm = ministack::ssm_client();

    ensure_bucket(&s3, SRC_BUCKET).await;
    ensure_bucket(&s3, DEST_BUCKET).await;
    put_parameter(&ssm, RULES_PARAM, DROP_DECRYPT_RULES).await;

    let missing_key = "lambda-sqs/cold-start/definitely-absent.json.gz";
    ministack::delete_object(&s3, SRC_BUCKET, missing_key).await;

    let event = sqs_event_with_s3_body("msg-doomed", SRC_BUCKET, missing_key, 1024);
    let api = FakeRuntimeApi::start(&[event]);
    let env = lambda_env(DEST_BUCKET, &format!("ssm://{RULES_PARAM}"));
    let mut lambda = LambdaProcess::spawn(env!("CARGO_BIN_EXE_bootstrap-sqs"), &api.addr(), &env);

    let response = lambda.expect_one_response(&api, TIMEOUT);
    let response: serde_json::Value = serde_json::from_str(&response).expect("response is JSON");
    assert_eq!(
        response,
        serde_json::json!({
            "batchItemFailures": [{ "itemIdentifier": "msg-doomed" }]
        }),
        "the absent object's message must be the only one re-driven\n\
         ---- child output ----\n{}",
        lambda.logs()
    );
}

/// S3 -> SNS -> SQS fan-out, covering `CT_SQS_BODY_FORMAT=sns` reaching the
/// decoder through the real binary's settings load.
#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn sns_wrapped_message_bodies_are_decoded_when_configured() {
    let s3 = ministack::s3_client();
    let ssm = ministack::ssm_client();

    ensure_bucket(&s3, SRC_BUCKET).await;
    ensure_bucket(&s3, DEST_BUCKET).await;
    put_parameter(&ssm, RULES_PARAM, DROP_DECRYPT_RULES).await;

    let key = "lambda-sqs/cold-start-sns/cloudtrail.json.gz";
    let (body, expected_body) = cloudtrail_body(15);
    let gzipped = gzip_bytes(&body, 6);
    put_object(&s3, SRC_BUCKET, key, gzipped.clone()).await;
    ministack::delete_object(&s3, DEST_BUCKET, key).await;

    let event = sqs_event_with_sns_body("msg-sns", SRC_BUCKET, key, gzipped.len() as u64);
    let api = FakeRuntimeApi::start(&[event]);
    let mut env = lambda_env(DEST_BUCKET, &format!("ssm://{RULES_PARAM}"));
    env.push(("CT_SQS_BODY_FORMAT", "sns".to_string()));
    let mut lambda = LambdaProcess::spawn(env!("CARGO_BIN_EXE_bootstrap-sqs"), &api.addr(), &env);

    lambda.expect_one_response(&api, TIMEOUT);

    let written = get_object(&s3, DEST_BUCKET, key).await;
    assert_eq!(gunzip(&written), expected_body);
}

/// Two invocations on one container: the second is served from the same process,
/// reusing the primed `ConfigStore` and every adapter built at cold start.
#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn a_warm_container_serves_a_second_invocation() {
    let s3 = ministack::s3_client();
    let ssm = ministack::ssm_client();

    ensure_bucket(&s3, SRC_BUCKET).await;
    ensure_bucket(&s3, DEST_BUCKET).await;
    put_parameter(&ssm, RULES_PARAM, DROP_DECRYPT_RULES).await;

    let (body, expected_body) = cloudtrail_body(12);
    let gzipped = gzip_bytes(&body, 6);
    let keys = [
        "lambda-sqs/warm/first.json.gz",
        "lambda-sqs/warm/second.json.gz",
    ];
    for key in keys {
        put_object(&s3, SRC_BUCKET, key, gzipped.clone()).await;
        ministack::delete_object(&s3, DEST_BUCKET, key).await;
    }

    let events: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            sqs_event_with_s3_body(&format!("msg-{i}"), SRC_BUCKET, key, gzipped.len() as u64)
        })
        .collect();
    let api = FakeRuntimeApi::start(&events);
    let env = lambda_env(DEST_BUCKET, &format!("ssm://{RULES_PARAM}"));
    let mut lambda = LambdaProcess::spawn(env!("CARGO_BIN_EXE_bootstrap-sqs"), &api.addr(), &env);

    let outcomes = lambda.wait_for_outcomes(&api, 2, TIMEOUT);
    assert_eq!(outcomes.len(), 2, "both invocations must be answered");
    for outcome in &outcomes {
        assert_eq!(
            outcome.body(),
            r#"{"batchItemFailures":[]}"#,
            "logs:\n{}",
            lambda.logs()
        );
    }

    for key in keys {
        let written = get_object(&s3, DEST_BUCKET, key).await;
        assert_eq!(gunzip(&written), expected_body, "for {key}");
    }
}
