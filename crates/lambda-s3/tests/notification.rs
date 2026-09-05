//! Drives the real `bootstrap-s3` binary with an S3 notification a live
//! MiniStack **produced**, rather than one the test hand-wrote.
//!
//! The notification is read off an SQS subscription because MiniStack cannot
//! invoke a Lambda directly, but the body it delivers is byte-for-byte the
//! payload a real S3 -> Lambda trigger passes to the handler — S3 builds the
//! notification once and the transport only carries it.
//!
//! Keys stay free of characters needing URL-encoding: MiniStack emits them
//! verbatim where real S3 form-urlencodes, so an encoding assertion here would
//! be testing MiniStack rather than the decoder.
//!
//! `#[ignore]`d: needs the container from `docker-compose.test.yml`.

#![allow(clippy::unwrap_used)]

use std::time::Duration;

use cloudtrail_rs_testkit::fixtures::{DROP_DECRYPT_RULES, cloudtrail_body, gunzip, gzip_bytes};
use cloudtrail_rs_testkit::ministack::{
    self, drain_queue, ensure_bucket, ensure_queue, get_object, lambda_env, notify_queue,
    purge_queue, put_object, put_parameter,
};
use cloudtrail_rs_testkit::{FakeRuntimeApi, LambdaProcess};

const DEST_BUCKET: &str = "ct-notify-s3-dest";
const RULES_PARAM: &str = "/cloudtrail-rs-tests/notify-s3-rules";
const TIMEOUT: Duration = Duration::from_secs(60);
const DRAIN: Duration = Duration::from_secs(20);

/// The `s3:TestEvent` body and the `ObjectCreated` body S3 emitted for `key`,
/// in that order, with the notification configuration re-applied so the test
/// event is produced on every run rather than only the first.
///
/// `bucket` and `queue` are per-test: `cargo test` runs these concurrently, and
/// a shared queue would hand one test the other's notifications.
async fn real_notifications(
    bucket: &str,
    queue: &str,
    key: &str,
    gzipped: Vec<u8>,
) -> (String, String) {
    let s3 = ministack::s3_client();
    let sqs = ministack::sqs_client();

    ensure_bucket(&s3, bucket).await;
    let (queue_url, queue_arn) = ensure_queue(&sqs, queue).await;
    purge_queue(&sqs, &queue_url).await;
    notify_queue(&s3, bucket, &queue_arn).await;
    put_object(&s3, bucket, key, gzipped).await;

    let bodies = drain_queue(&sqs, &queue_url, 2, DRAIN).await;
    let test_event = bodies
        .iter()
        .find(|b| b.contains("s3:TestEvent"))
        .expect("S3 must emit a TestEvent for the notification configuration")
        .clone();
    let created = bodies
        .iter()
        .find(|b| b.contains("ObjectCreated"))
        .expect("S3 must emit an ObjectCreated notification for the put")
        .clone();
    (test_event, created)
}

#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn a_real_s3_notification_drives_the_s3_lambda() {
    let s3 = ministack::s3_client();
    let ssm = ministack::ssm_client();

    ensure_bucket(&s3, DEST_BUCKET).await;
    put_parameter(&ssm, RULES_PARAM, DROP_DECRYPT_RULES).await;

    let key = "AWSLogs/notify-s3/cloudtrail.json.gz";
    let (body, expected_body) = cloudtrail_body(20);
    ministack::delete_object(&s3, DEST_BUCKET, key).await;
    let (_, created) = real_notifications(
        "ct-notify-s3-src",
        "ct-notify-s3-q",
        key,
        gzip_bytes(&body, 6),
    )
    .await;

    let event: serde_json::Value = serde_json::from_str(&created).expect("notification is JSON");
    let api = FakeRuntimeApi::start(&[event]);
    let env = lambda_env(DEST_BUCKET, &format!("ssm://{RULES_PARAM}"));
    let mut lambda = LambdaProcess::spawn(env!("CARGO_BIN_EXE_bootstrap-s3"), &api.addr(), &env);

    lambda.expect_one_response(&api, TIMEOUT);

    let written = get_object(&s3, DEST_BUCKET, key).await;
    assert_eq!(gunzip(&written), expected_body);
}

/// S3 sends `s3:TestEvent` on every notification configuration, so a Lambda
/// wired to a bucket receives one before any log ever arrives. It carries no
/// `Records`, and the invocation must still succeed.
#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn a_real_test_event_succeeds_without_writing_anything() {
    let s3 = ministack::s3_client();
    let ssm = ministack::ssm_client();

    ensure_bucket(&s3, DEST_BUCKET).await;
    put_parameter(&ssm, RULES_PARAM, DROP_DECRYPT_RULES).await;

    let key = "AWSLogs/notify-s3/test-event-run.json.gz";
    let (body, _) = cloudtrail_body(4);
    ministack::delete_object(&s3, DEST_BUCKET, key).await;
    let (test_event, _) = real_notifications(
        "ct-notify-s3-testevent-src",
        "ct-notify-s3-testevent-q",
        key,
        gzip_bytes(&body, 6),
    )
    .await;

    let event: serde_json::Value = serde_json::from_str(&test_event).expect("TestEvent is JSON");
    let api = FakeRuntimeApi::start(&[event]);
    let env = lambda_env(DEST_BUCKET, &format!("ssm://{RULES_PARAM}"));
    let mut lambda = LambdaProcess::spawn(env!("CARGO_BIN_EXE_bootstrap-s3"), &api.addr(), &env);

    lambda.expect_one_response(&api, TIMEOUT);

    assert!(
        !ministack::object_exists(&s3, DEST_BUCKET, key).await,
        "a TestEvent references no object, so nothing may be written"
    );
}
