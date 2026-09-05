//! Decodes SQS-delivered events (feature `decode-sqs`).
//!
//! A message body is a raw S3 bucket notification or an SNS one wrapping it,
//! so this module reuses `parse_s3_notification`. Its SNS envelope is the
//! bare `Notification` object, not `sns.rs`'s `Records[].Sns` wrapper, so the
//! unwrap is self-contained here.

use crate::config::settings::SqsBodyFormat;
use crate::decode::s3::parse_s3_notification;
use crate::error::DecodeError;
use crate::model::{ObjectRef, SourceItem};
use crate::ports::EventDecoder;
use serde::Deserialize;
use std::borrow::Cow;

/// Decodes an SQS event whose message bodies carry S3 notifications,
/// optionally wrapped in an SNS envelope.
pub struct SqsEventDecoder {
    body_format: SqsBodyFormat,
}

impl SqsEventDecoder {
    pub fn new(body_format: SqsBodyFormat) -> Self {
        SqsEventDecoder { body_format }
    }
}

#[derive(Debug, Deserialize)]
struct SqsEvent {
    /// No `#[serde(default)]`: a payload without `Records` is a failure, not a
    /// silently acked empty batch.
    #[serde(rename = "Records")]
    records: Vec<SqsRecord>,
}

#[derive(Debug, Deserialize)]
struct SqsRecord {
    #[serde(rename = "messageId")]
    message_id: String,
    body: String,
}

#[derive(Debug, Deserialize)]
struct SnsNotificationBody {
    #[serde(rename = "Message")]
    message: String,
}

impl EventDecoder for SqsEventDecoder {
    fn decode(&self, payload: &[u8]) -> Result<Vec<SourceItem>, DecodeError> {
        let event: SqsEvent = serde_json::from_slice(payload)
            .map_err(|e| DecodeError::InvalidPayload(e.to_string()))?;

        let mut items = Vec::with_capacity(event.records.len());
        for record in event.records {
            // Neither sinks the batch nor drops silently: an undecodable
            // item carries the failure so the pipeline fails this ack_id.
            let item = match decode_body(&record.body, self.body_format) {
                // All-delete: no item, or every delete counts as
                // `items_without_objects`. Nothing to fetch, nothing to retry.
                Ok((objects, skipped)) if objects.is_empty() && skipped => continue,
                Ok((objects, _)) => SourceItem::new(Some(record.message_id), objects),
                Err(e) => SourceItem::undecodable(Some(record.message_id), e.to_string()),
            };
            items.push(item);
        }
        Ok(items)
    }
}

/// Unwraps `body_format` and hands the resulting S3-notification bytes to
/// [`parse_s3_notification`]. `auto` sniffs the body's `Type` field for a
/// bare SNS `Notification` envelope; `s3`/`sns` skip the sniff for *routing*
/// — `s3` still sniffs to *reject*, see below.
fn decode_body(body: &str, format: SqsBodyFormat) -> Result<(Vec<ObjectRef>, bool), DecodeError> {
    let s3_payload: Cow<[u8]> = match format {
        // Fail rather than unwrap: silently unwrapping would make an
        // explicit `s3` mean the same as `auto`.
        SqsBodyFormat::S3 if looks_like_sns_notification(body) => {
            return Err(DecodeError::InvalidPayload(
                "sqs.body_format is `s3` but this message body is an SNS Notification envelope; \
                 set sqs.body_format to `sns` (or `auto`)"
                    .to_string(),
            ));
        }
        SqsBodyFormat::S3 => Cow::Borrowed(body.as_bytes()),
        SqsBodyFormat::Sns => Cow::Owned(unwrap_sns(body)?),
        SqsBodyFormat::Auto if looks_like_sns_notification(body) => Cow::Owned(unwrap_sns(body)?),
        SqsBodyFormat::Auto => Cow::Borrowed(body.as_bytes()),
    };

    parse_s3_notification(&s3_payload)
}

fn looks_like_sns_notification(body: &str) -> bool {
    #[derive(Deserialize)]
    struct TypeSniff {
        #[serde(rename = "Type")]
        type_: Option<String>,
    }

    serde_json::from_str::<TypeSniff>(body)
        .is_ok_and(|sniff| sniff.type_.as_deref() == Some("Notification"))
}

fn unwrap_sns(body: &str) -> Result<Vec<u8>, DecodeError> {
    let envelope: SnsNotificationBody =
        serde_json::from_str(body).map_err(|e| DecodeError::InvalidPayload(e.to_string()))?;
    Ok(envelope.message.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SQS_S3_EVENT: &[u8] = include_bytes!("../../tests/fixtures/sqs-s3-event.json");
    const SQS_SNS_EVENT: &[u8] = include_bytes!("../../tests/fixtures/sqs-sns-event.json");
    const SQS_BATCH_PARTIAL_GARBAGE: &[u8] =
        include_bytes!("../../tests/fixtures/sqs-batch-partial-garbage.json");

    #[test]
    fn decodes_raw_s3_event_in_sqs_body_with_s3_format() {
        let decoder = SqsEventDecoder::new(SqsBodyFormat::S3);
        let items = decoder.decode(SQS_S3_EVENT).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].ack_id,
            Some("059f36b4-87a3-44ab-83d2-661975830a7d".to_string())
        );
        assert_eq!(items[0].objects.len(), 1);
        assert_eq!(
            items[0].objects[0],
            ObjectRef {
                bucket: "lambda-artifacts-deafc19498e3f2df".to_string(),
                key: "b21b84d653bb07b05b1e6b33684dc11b".to_string(),
                size: Some(1305107),
            }
        );
    }

    #[test]
    fn decodes_raw_s3_event_in_sqs_body_with_auto_format() {
        let decoder = SqsEventDecoder::new(SqsBodyFormat::Auto);
        let items = decoder.decode(SQS_S3_EVENT).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].objects[0].bucket,
            "lambda-artifacts-deafc19498e3f2df"
        );
    }

    #[test]
    fn decodes_sns_wrapped_s3_event_in_sqs_body_with_sns_format() {
        let decoder = SqsEventDecoder::new(SqsBodyFormat::Sns);
        let items = decoder.decode(SQS_SNS_EVENT).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].ack_id,
            Some("2e1424d4-f796-459a-8184-9c92662be6da".to_string())
        );
        assert_eq!(items[0].objects.len(), 1);
        assert_eq!(
            items[0].objects[0],
            ObjectRef {
                bucket: "lambda-artifacts-deafc19498e3f2df".to_string(),
                key: "b21b84d653bb07b05b1e6b33684dc11b".to_string(),
                size: Some(1305107),
            }
        );
    }

    #[test]
    fn decodes_sns_wrapped_s3_event_in_sqs_body_with_auto_format() {
        let decoder = SqsEventDecoder::new(SqsBodyFormat::Auto);
        let items = decoder.decode(SQS_SNS_EVENT).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].objects[0].bucket,
            "lambda-artifacts-deafc19498e3f2df"
        );
    }

    #[test]
    fn sns_body_with_s3_format_is_an_undecodable_message_not_an_empty_ack() {
        let decoder = SqsEventDecoder::new(SqsBodyFormat::S3);
        let items = decoder.decode(SQS_SNS_EVENT).unwrap();

        assert_eq!(items.len(), 1, "the message must survive as an item");
        assert_eq!(
            items[0].ack_id,
            Some("2e1424d4-f796-459a-8184-9c92662be6da".to_string()),
            "it must carry its ack_id so the pipeline can fail *this* message"
        );
        assert!(items[0].objects.is_empty());
        let error = items[0]
            .decode_error
            .as_deref()
            .expect("must be marked undecodable, not acked clean");
        assert!(
            error.contains("body_format"),
            "the error must name the setting to fix, got: {error}"
        );
    }

    #[test]
    fn s3_body_with_sns_format_is_an_undecodable_message() {
        let decoder = SqsEventDecoder::new(SqsBodyFormat::Sns);
        let items = decoder.decode(SQS_S3_EVENT).unwrap();
        assert_eq!(items.len(), 1);
        assert!(items[0].objects.is_empty());
        assert!(items[0].decode_error.is_some());
    }

    #[test]
    fn batch_with_one_garbage_message_still_decodes_siblings() {
        let decoder = SqsEventDecoder::new(SqsBodyFormat::Auto);
        let items = decoder.decode(SQS_BATCH_PARTIAL_GARBAGE).unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(
            items[0].ack_id,
            Some("059f36b4-87a3-44ab-83d2-661975830a7d".to_string())
        );
        assert_eq!(items[0].objects[0].key, "b21b84d653bb07b05b1e6b33684dc11b");
        assert!(items[0].decode_error.is_none());

        assert_eq!(
            items[1].ack_id,
            Some("bad00000-0000-0000-0000-000000000002".to_string())
        );
        assert!(items[1].objects.is_empty());
        assert!(items[1].decode_error.is_some());

        assert_eq!(
            items[2].ack_id,
            Some("2e1424d4-f796-459a-8184-9c92662be6da".to_string())
        );
        assert_eq!(items[2].objects[0].key, "second-sibling-object.json.gz");
        assert_eq!(items[2].objects[0].bucket, "ct-siem-sync");
        assert!(items[2].decode_error.is_none());
    }

    #[test]
    fn every_object_in_one_message_body_survives_decoding() {
        let body = r#"{"Records":[
          {"s3":{"bucket":{"name":"bkt"},"object":{"key":"a.json.gz","size":1}}},
          {"s3":{"bucket":{"name":"bkt"},"object":{"key":"b.json.gz","size":2}}},
          {"s3":{"bucket":{"name":"bkt"},"object":{"key":"c.json.gz","size":3}}}
        ]}"#;
        let event = serde_json::json!({
            "Records": [{ "messageId": "m-1", "body": body }]
        })
        .to_string();

        let items = SqsEventDecoder::new(SqsBodyFormat::S3)
            .decode(event.as_bytes())
            .unwrap();

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].ack_id, Some("m-1".to_string()));
        let keys: Vec<&str> = items[0].objects.iter().map(|o| o.key.as_str()).collect();
        assert_eq!(keys, ["a.json.gz", "b.json.gz", "c.json.gz"]);
    }

    #[test]
    fn garbage_top_level_payload_is_a_decode_error() {
        let decoder = SqsEventDecoder::new(SqsBodyFormat::Auto);
        assert!(decoder.decode(b"not json").is_err());
    }

    #[test]
    fn empty_records_decodes_to_empty_vec() {
        let decoder = SqsEventDecoder::new(SqsBodyFormat::Auto);
        let items = decoder.decode(br#"{"Records":[]}"#).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn valid_json_without_a_records_array_is_a_decode_error_not_an_empty_batch() {
        let decoder = SqsEventDecoder::new(SqsBodyFormat::Auto);
        let err = decoder
            .decode(br#"{"Type":"Notification","Message":"something else entirely"}"#)
            .expect_err("a payload with no Records array must not ack as zero messages");
        assert!(
            err.to_string().contains("Records"),
            "the error must name the missing field, got: {err}"
        );
    }

    #[test]
    fn all_removed_message_yields_no_source_item() {
        let body = r#"{"Records":[
          {"eventName":"ObjectRemoved:Delete","s3":{"bucket":{"name":"bkt"},"object":{"key":"gone.json.gz"}}}
        ]}"#;
        let event = serde_json::json!({
            "Records": [{ "messageId": "m-1", "body": body }]
        })
        .to_string();

        let items = SqsEventDecoder::new(SqsBodyFormat::S3)
            .decode(event.as_bytes())
            .unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn test_event_message_still_yields_an_objectless_item() {
        let event = serde_json::json!({
            "Records": [{
                "messageId": "m-1",
                "body": r#"{"Service":"Amazon S3","Event":"s3:TestEvent"}"#,
            }]
        })
        .to_string();

        let items = SqsEventDecoder::new(SqsBodyFormat::S3)
            .decode(event.as_bytes())
            .unwrap();
        assert_eq!(items.len(), 1);
        assert!(items[0].objects.is_empty());
        assert!(items[0].decode_error.is_none());
    }

    #[test]
    fn mixed_created_and_removed_message_keeps_the_created_object() {
        let body = r#"{"Records":[
          {"eventName":"ObjectCreated:Put","s3":{"bucket":{"name":"bkt"},"object":{"key":"kept.json.gz","size":11}}},
          {"eventName":"ObjectRemoved:Delete","s3":{"bucket":{"name":"bkt"},"object":{"key":"gone.json.gz"}}}
        ]}"#;
        let event = serde_json::json!({
            "Records": [{ "messageId": "m-1", "body": body }]
        })
        .to_string();

        let items = SqsEventDecoder::new(SqsBodyFormat::S3)
            .decode(event.as_bytes())
            .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].ack_id, Some("m-1".to_string()));
        let keys: Vec<&str> = items[0].objects.iter().map(|o| o.key.as_str()).collect();
        assert_eq!(keys, ["kept.json.gz"]);
    }
}
