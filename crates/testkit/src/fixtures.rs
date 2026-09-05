//! CloudTrail-shaped payload builders and gzip helpers shared by every
//! integration test.

use std::io::{Read, Write};
use std::sync::Arc;

use cloudtrail_rs_core::config::rules::RuleSet;
use cloudtrail_rs_core::config::store::Compile;
use cloudtrail_rs_core::config::{
    Behavior, Destination, Observability, Processing, Rules, Settings, Source, Sqs,
};
use cloudtrail_rs_core::filter::Engine;
use flate2::Compression;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;

/// The ruleset used by most integration tests: drops any record whose
/// `eventName` is exactly `Decrypt`.
pub const DROP_DECRYPT_RULES: &str = r#"
version: 1.0.0
rules:
  - name: Drop Decrypt
    matches:
      - field_name: eventName
        regex: "^Decrypt$"
"#;

/// A ruleset that drops nothing, for tests that care about transport rather
/// than filtering.
pub const KEEP_ALL_RULES: &str = r#"
version: 1.0.0
rules:
  - name: Drop nothing
    matches:
      - field_name: eventName
        regex: "^__never_matches__$"
"#;

/// The `Compile` closure every `ConfigStore` under test is built with.
pub fn compile_engine() -> Compile<Arc<Engine>> {
    Arc::new(|b: &[u8]| Ok(Arc::new(Engine::new(RuleSet::parse(b)?)?)))
}

pub fn gzip_bytes(body: &[u8], level: u32) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(level));
    encoder.write_all(body).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

pub fn gunzip(input: &[u8]) -> Vec<u8> {
    let mut decoder = MultiGzDecoder::new(input);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).expect("gunzip");
    out
}

/// One CloudTrail-shaped record. `idx` gives each record distinct content so
/// gzip cannot compress a large fixture down to a handful of bytes.
pub fn record_json(idx: usize, event_name: &str) -> String {
    format!(
        r#"{{"eventName":"{event_name}","eventSource":"signin.amazonaws.com","eventID":"{idx:010}"}}"#
    )
}

/// Builds a `{"Records":[...]}` body of `count` records, every fifth one
/// `Decrypt` (dropped by [`DROP_DECRYPT_RULES`]), the rest `ConsoleLogin`
/// (kept). Returns the body plus the expected survivor body — assembled the
/// same way the pipeline assembles it (raw slices joined by `,`), so the
/// comparison is byte-exact rather than a re-parse.
pub fn cloudtrail_body(count: usize) -> (Vec<u8>, Vec<u8>) {
    let mut records = Vec::with_capacity(count);
    let mut survivors = Vec::new();
    for i in 0..count {
        let name = if i % 5 == 0 {
            "Decrypt"
        } else {
            "ConsoleLogin"
        };
        let record = record_json(i, name);
        if name != "Decrypt" {
            survivors.push(record.clone());
        }
        records.push(record);
    }
    let body = format!(r#"{{"Records":[{}]}}"#, records.join(","));
    let expected = format!(r#"{{"Records":[{}]}}"#, survivors.join(","));
    (body.into_bytes(), expected.into_bytes())
}

/// The S3 bucket-notification payload `S3EventDecoder` expects, naming exactly
/// one object.
///
/// `size` drives the auto buffer/stream decision. Real S3 always reports the
/// true byte count; here it is set explicitly so a test can select a
/// processing mode deterministically.
pub fn s3_event(bucket: &str, key: &str, size: u64) -> serde_json::Value {
    serde_json::json!({
        "Records": [{
            "s3": {
                "bucket": { "name": bucket },
                "object": { "key": key, "size": size }
            }
        }]
    })
}

/// An SQS event whose single message body is an embedded S3 notification —
/// the shape produced by S3 -> SQS fan-out.
pub fn sqs_event_with_s3_body(
    message_id: &str,
    bucket: &str,
    key: &str,
    size: u64,
) -> serde_json::Value {
    serde_json::json!({
        "Records": [{
            "messageId": message_id,
            "receiptHandle": "receipt",
            "body": s3_event(bucket, key, size).to_string(),
            "attributes": {},
            "messageAttributes": {},
            "eventSource": "aws:sqs"
        }]
    })
}

/// An SQS event carrying an S3 notification wrapped in an SNS envelope —
/// the shape produced by S3 -> SNS -> SQS fan-out.
pub fn sqs_event_with_sns_body(
    message_id: &str,
    bucket: &str,
    key: &str,
    size: u64,
) -> serde_json::Value {
    let sns = serde_json::json!({
        "Type": "Notification",
        "MessageId": "sns-message-id",
        "TopicArn": "arn:aws:sns:us-east-1:000000000000:ct",
        "Message": s3_event(bucket, key, size).to_string(),
    });
    serde_json::json!({
        "Records": [{
            "messageId": message_id,
            "receiptHandle": "receipt",
            "body": sns.to_string(),
            "attributes": {},
            "messageAttributes": {},
            "eventSource": "aws:sqs"
        }]
    })
}

/// An SQS event whose message bodies are supplied verbatim — for driving a
/// Lambda with bodies a live MiniStack produced rather than ones a test wrote.
/// The envelope around them is Lambda's, not S3's, so it stays hand-built.
pub fn sqs_event_from_bodies(bodies: &[String]) -> serde_json::Value {
    let records: Vec<_> = bodies
        .iter()
        .enumerate()
        .map(|(i, body)| {
            serde_json::json!({
                "messageId": format!("m-{i}"),
                "receiptHandle": "receipt",
                "body": body,
                "attributes": {},
                "messageAttributes": {},
                "eventSource": "aws:sqs"
            })
        })
        .collect();
    serde_json::json!({ "Records": records })
}

/// An SNS event whose `Sns.Message` values are supplied verbatim. MiniStack
/// cannot subscribe a Lambda to a topic, so a real S3 notification is read off
/// an SQS subscription and re-wrapped in the envelope Lambda would deliver.
pub fn sns_event_from_messages(messages: &[String]) -> serde_json::Value {
    let records: Vec<_> = messages
        .iter()
        .map(|message| {
            serde_json::json!({
                "EventSource": "aws:sns",
                "Sns": {
                    "Type": "Notification",
                    "MessageId": "sns-message-id",
                    "TopicArn": "arn:aws:sns:us-east-1:000000000000:ct",
                    "Message": message,
                }
            })
        })
        .collect();
    serde_json::json!({ "Records": records })
}

/// An SNS event whose `Message` is an embedded S3 notification.
pub fn sns_event(bucket: &str, key: &str, size: u64) -> serde_json::Value {
    serde_json::json!({
        "Records": [{
            "EventSource": "aws:sns",
            "Sns": {
                "Type": "Notification",
                "MessageId": "sns-message-id",
                "TopicArn": "arn:aws:sns:us-east-1:000000000000:ct",
                "Message": s3_event(bucket, key, size).to_string(),
            }
        }]
    })
}

/// An EventBridge `Object Created` event for `bucket`/`key`.
pub fn eventbridge_event(bucket: &str, key: &str, size: u64) -> serde_json::Value {
    serde_json::json!({
        "version": "0",
        "id": "eb-event-id",
        "detail-type": "Object Created",
        "source": "aws.s3",
        "account": "000000000000",
        "region": "us-east-1",
        "detail": {
            "version": "0",
            "event-version": "1.0",
            "bucket": { "name": bucket },
            "object": { "key": key, "size": size }
        }
    })
}

/// A `Settings` with everything at its default except the destination bucket
/// and ruleset URI.
pub fn base_settings(dest_bucket: &str, rules_uri: String) -> Settings {
    Settings {
        source: Source::default(),
        destination: Destination {
            bucket: dest_bucket.to_string(),
            key_prefix: String::new(),
        },
        processing: Processing::default(),
        behavior: Behavior::default(),
        sqs: Sqs::default(),
        rules: Rules {
            uri: rules_uri,
            ttl_seconds: 300,
        },
        observability: Observability::default(),
    }
}
