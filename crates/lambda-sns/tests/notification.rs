//! Drives the real `bootstrap-sns` binary with an S3 notification a live
//! MiniStack **produced** and delivered through a real SNS topic.
//!
//! MiniStack cannot subscribe a Lambda to a topic, so the notification is read
//! off an SQS subscription to the same topic and re-wrapped in the envelope
//! Lambda would deliver. The `Sns.Message` — the only part the decoder reads —
//! is what SNS actually published.
//!
//! Keys stay free of characters needing URL-encoding: MiniStack emits them
//! verbatim where real S3 form-urlencodes, so an encoding assertion here would
//! be testing MiniStack rather than the decoder.
//!
//! `#[ignore]`d: needs the container from `docker-compose.test.yml`.

#![allow(clippy::unwrap_used)]

use std::time::Duration;

use cloudtrail_rs_testkit::fixtures::{
    DROP_DECRYPT_RULES, cloudtrail_body, gunzip, gzip_bytes, sns_event_from_messages,
};
use cloudtrail_rs_testkit::ministack::{
    self, drain_queue, ensure_bucket, ensure_queue, ensure_topic, get_object, lambda_env,
    notify_topic, purge_queue, put_object, put_parameter, subscribe_queue,
};
use cloudtrail_rs_testkit::{FakeRuntimeApi, LambdaProcess};

const SRC_BUCKET: &str = "ct-notify-snslambda-src";
const DEST_BUCKET: &str = "ct-notify-snslambda-dest";
const QUEUE: &str = "ct-notify-snslambda-q";
const TOPIC: &str = "ct-notify-snslambda-topic";
const RULES_PARAM: &str = "/cloudtrail-rs-tests/notify-snslambda-rules";
const TIMEOUT: Duration = Duration::from_secs(60);
const DRAIN: Duration = Duration::from_secs(20);

#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn a_real_sns_published_notification_drives_the_sns_lambda() {
    let s3 = ministack::s3_client();
    let ssm = ministack::ssm_client();
    let sqs = ministack::sqs_client();
    let sns = ministack::sns_client();

    ensure_bucket(&s3, SRC_BUCKET).await;
    ensure_bucket(&s3, DEST_BUCKET).await;
    put_parameter(&ssm, RULES_PARAM, DROP_DECRYPT_RULES).await;

    let (queue_url, queue_arn) = ensure_queue(&sqs, QUEUE).await;
    let topic_arn = ensure_topic(&sns, TOPIC).await;
    subscribe_queue(&sns, &topic_arn, &queue_arn).await;
    purge_queue(&sqs, &queue_url).await;
    notify_topic(&s3, SRC_BUCKET, &topic_arn).await;

    let key = "AWSLogs/notify-snslambda/cloudtrail.json.gz";
    let (body, expected_body) = cloudtrail_body(20);
    ministack::delete_object(&s3, DEST_BUCKET, key).await;
    put_object(&s3, SRC_BUCKET, key, gzip_bytes(&body, 6)).await;

    // Both the TestEvent and the ObjectCreated notification, in one event, so
    // the batch also proves the TestEvent does not fail the invocation.
    let messages: Vec<String> = drain_queue(&sqs, &queue_url, 2, DRAIN)
        .await
        .iter()
        .map(|b| {
            let env: serde_json::Value = serde_json::from_str(b).expect("SNS envelope is JSON");
            env["Message"]
                .as_str()
                .expect("SNS envelope must carry a string Message")
                .to_string()
        })
        .collect();

    let api = FakeRuntimeApi::start(&[sns_event_from_messages(&messages)]);
    let env = lambda_env(DEST_BUCKET, &format!("ssm://{RULES_PARAM}"));
    let mut lambda = LambdaProcess::spawn(env!("CARGO_BIN_EXE_bootstrap-sns"), &api.addr(), &env);

    lambda.expect_one_response(&api, TIMEOUT);

    let written = get_object(&s3, DEST_BUCKET, key).await;
    assert_eq!(gunzip(&written), expected_body);
}
