//! Drives the real `bootstrap-eventbridge` binary with an `Object Created`
//! event a live MiniStack **produced** and routed through a real EventBridge
//! rule, rather than one the test hand-wrote.
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
    self, drain_queue, ensure_bucket, ensure_queue, ensure_rule_to_queue, get_object, lambda_env,
    notify_eventbridge, purge_queue, put_object, put_parameter,
};
use cloudtrail_rs_testkit::{FakeRuntimeApi, LambdaProcess};

const SRC_BUCKET: &str = "ct-notify-eb-src";
const DEST_BUCKET: &str = "ct-notify-eb-dest";
const QUEUE: &str = "ct-notify-eb-q";
const RULE: &str = "ct-notify-eb-rule";
const RULES_PARAM: &str = "/cloudtrail-rs-tests/notify-eb-rules";
const TIMEOUT: Duration = Duration::from_secs(60);
const DRAIN: Duration = Duration::from_secs(20);

#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn a_real_eventbridge_object_created_event_drives_the_eventbridge_lambda() {
    let s3 = ministack::s3_client();
    let ssm = ministack::ssm_client();
    let sqs = ministack::sqs_client();
    let events = ministack::eventbridge_client();

    ensure_bucket(&s3, SRC_BUCKET).await;
    ensure_bucket(&s3, DEST_BUCKET).await;
    put_parameter(&ssm, RULES_PARAM, DROP_DECRYPT_RULES).await;

    let (queue_url, queue_arn) = ensure_queue(&sqs, QUEUE).await;
    ensure_rule_to_queue(
        &events,
        RULE,
        r#"{"source":["aws.s3"],"detail-type":["Object Created"]}"#,
        &queue_arn,
    )
    .await;
    purge_queue(&sqs, &queue_url).await;
    notify_eventbridge(&s3, SRC_BUCKET).await;

    let key = "AWSLogs/notify-eb/cloudtrail.json.gz";
    let (body, expected_body) = cloudtrail_body(20);
    let gzipped = gzip_bytes(&body, 6);
    ministack::delete_object(&s3, DEST_BUCKET, key).await;
    put_object(&s3, SRC_BUCKET, key, gzipped).await;

    // EventBridge has no `s3:TestEvent` equivalent, so the bus carries exactly
    // the one event the put produced.
    let bodies = drain_queue(&sqs, &queue_url, 1, DRAIN).await;
    let event: serde_json::Value = serde_json::from_str(&bodies[0]).expect("bus event is JSON");
    assert_eq!(event["detail-type"], "Object Created");

    let api = FakeRuntimeApi::start(&[event]);
    let env = lambda_env(DEST_BUCKET, &format!("ssm://{RULES_PARAM}"));
    let mut lambda = LambdaProcess::spawn(
        env!("CARGO_BIN_EXE_bootstrap-eventbridge"),
        &api.addr(),
        &env,
    );

    lambda.expect_one_response(&api, TIMEOUT);

    let written = get_object(&s3, DEST_BUCKET, key).await;
    assert_eq!(gunzip(&written), expected_body);
}
