//! Drives the real `bootstrap-sqs` binary with S3 notifications a live
//! MiniStack **produced**, rather than ones the test hand-wrote.
//!
//! The other suites prove the pipeline handles the fixture shapes in
//! `testkit::fixtures`. These prove those shapes are the ones a real S3 event
//! notification actually emits — including `s3:TestEvent`, which S3 sends on
//! every notification configuration and which must be acked, not DLQ'd.
//!
//! Keys stay free of characters needing URL-encoding: MiniStack emits them
//! verbatim where real S3 form-urlencodes, so an encoding assertion here would
//! be testing MiniStack rather than the decoder.
//!
//! `#[ignore]`d: needs the container from `docker-compose.test.yml`.

#![allow(clippy::unwrap_used)]

use std::time::Duration;

use cloudtrail_rs_testkit::fixtures::{
    DROP_DECRYPT_RULES, cloudtrail_body, gunzip, gzip_bytes, sqs_event_from_bodies,
};
use cloudtrail_rs_testkit::ministack::{
    self, drain_queue, ensure_bucket, ensure_queue, ensure_topic, get_object, lambda_env,
    notify_queue, notify_topic, purge_queue, put_object, put_parameter, subscribe_queue,
};
use cloudtrail_rs_testkit::{FakeRuntimeApi, LambdaProcess};

const SRC_BUCKET: &str = "ct-notify-sqs-src";
const SNS_SRC_BUCKET: &str = "ct-notify-sns-src";
const DEST_BUCKET: &str = "ct-notify-sqs-dest";
const QUEUE: &str = "ct-notify-sqs-q";
const SNS_QUEUE: &str = "ct-notify-sns-q";
const TOPIC: &str = "ct-notify-topic";
const RULES_PARAM: &str = "/cloudtrail-rs-tests/notify-sqs-rules";
const TIMEOUT: Duration = Duration::from_secs(60);
const DRAIN: Duration = Duration::from_secs(20);

#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn a_real_s3_notification_and_its_test_event_both_drive_the_sqs_lambda() {
    let s3 = ministack::s3_client();
    let ssm = ministack::ssm_client();
    let sqs = ministack::sqs_client();

    ensure_bucket(&s3, SRC_BUCKET).await;
    ensure_bucket(&s3, DEST_BUCKET).await;
    put_parameter(&ssm, RULES_PARAM, DROP_DECRYPT_RULES).await;

    let (queue_url, queue_arn) = ensure_queue(&sqs, QUEUE).await;
    purge_queue(&sqs, &queue_url).await;
    // Re-applying the configuration is what re-emits `s3:TestEvent`, so the
    // batch below carries one on every run and not only the first.
    notify_queue(&s3, SRC_BUCKET, &queue_arn).await;

    let key = "AWSLogs/notify-sqs/cloudtrail.json.gz";
    let (body, expected_body) = cloudtrail_body(20);
    let gzipped = gzip_bytes(&body, 6);
    ministack::delete_object(&s3, DEST_BUCKET, key).await;
    put_object(&s3, SRC_BUCKET, key, gzipped).await;

    let bodies = drain_queue(&sqs, &queue_url, 2, DRAIN).await;
    assert!(
        bodies.iter().any(|b| b.contains("s3:TestEvent")),
        "S3 must have emitted a TestEvent for the notification configuration: {bodies:#?}"
    );

    let api = FakeRuntimeApi::start(&[sqs_event_from_bodies(&bodies)]);
    let env = lambda_env(DEST_BUCKET, &format!("ssm://{RULES_PARAM}"));
    let mut lambda = LambdaProcess::spawn(env!("CARGO_BIN_EXE_bootstrap-sqs"), &api.addr(), &env);

    let response = lambda.expect_one_response(&api, TIMEOUT);
    let response: serde_json::Value = serde_json::from_str(&response).expect("response is JSON");
    assert_eq!(
        response,
        serde_json::json!({ "batchItemFailures": [] }),
        "the TestEvent carries no objects and must ack, not fail its message\n\
         ---- child output ----\n{}",
        lambda.logs()
    );

    let written = get_object(&s3, DEST_BUCKET, key).await;
    assert_eq!(gunzip(&written), expected_body);
}

#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn a_real_sns_wrapped_notification_drives_the_sqs_lambda() {
    let s3 = ministack::s3_client();
    let ssm = ministack::ssm_client();
    let sqs = ministack::sqs_client();
    let sns = ministack::sns_client();

    ensure_bucket(&s3, SNS_SRC_BUCKET).await;
    ensure_bucket(&s3, DEST_BUCKET).await;
    put_parameter(&ssm, RULES_PARAM, DROP_DECRYPT_RULES).await;

    let (queue_url, queue_arn) = ensure_queue(&sqs, SNS_QUEUE).await;
    let topic_arn = ensure_topic(&sns, TOPIC).await;
    subscribe_queue(&sns, &topic_arn, &queue_arn).await;
    purge_queue(&sqs, &queue_url).await;
    notify_topic(&s3, SNS_SRC_BUCKET, &topic_arn).await;

    let key = "AWSLogs/notify-sns/cloudtrail.json.gz";
    let (body, expected_body) = cloudtrail_body(20);
    let gzipped = gzip_bytes(&body, 6);
    ministack::delete_object(&s3, DEST_BUCKET, key).await;
    put_object(&s3, SNS_SRC_BUCKET, key, gzipped).await;

    let bodies = drain_queue(&sqs, &queue_url, 2, DRAIN).await;
    for b in &bodies {
        assert!(
            b.contains("\"Type\""),
            "SNS must deliver a Notification envelope, got: {b}"
        );
    }

    let api = FakeRuntimeApi::start(&[sqs_event_from_bodies(&bodies)]);
    let mut env = lambda_env(DEST_BUCKET, &format!("ssm://{RULES_PARAM}"));
    env.push(("CT_SQS_BODY_FORMAT", "sns".to_string()));
    let mut lambda = LambdaProcess::spawn(env!("CARGO_BIN_EXE_bootstrap-sqs"), &api.addr(), &env);

    let response = lambda.expect_one_response(&api, TIMEOUT);
    let response: serde_json::Value = serde_json::from_str(&response).expect("response is JSON");
    assert_eq!(
        response,
        serde_json::json!({ "batchItemFailures": [] }),
        "an SNS-wrapped batch, TestEvent included, must ack clean\n\
         ---- child output ----\n{}",
        lambda.logs()
    );

    let written = get_object(&s3, DEST_BUCKET, key).await;
    assert_eq!(gunzip(&written), expected_body);
}
