//! Decodes SQS-delivered events (feature `decode-sqs`).
//!
//! An SQS message body carries either a raw S3 bucket notification or an
//! SNS notification wrapping one — the same two JSON shapes `s3.rs`
//! already parses, so this module reuses `parse_s3_notification` rather
//! than duplicating it. The SNS envelope here is a *different* shape than
//! `sns.rs`'s: `sns.rs` unwraps the Lambda `Records[].Sns.Message` event
//! (direct SNS-to-Lambda delivery); an SQS message body is the bare SNS
//! `Notification` object itself (`{"Type":"Notification",...,"Message":
//! "..."}`), since SQS has no notion of an "Sns" record wrapper — so that
//! unwrap is self-contained here rather than shared with `sns.rs`.

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
    #[serde(rename = "Records", default)]
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
            // A single message's body failing to decode must not sink the
            // whole batch (SHARED partial-batch foundation) — drop just
            // this one and keep going.
            if let Ok(objects) = decode_body(&record.body, self.body_format) {
                items.push(SourceItem {
                    ack_id: Some(record.message_id),
                    objects,
                });
            }
        }
        Ok(items)
    }
}

/// Unwraps `body_format` and hands the resulting S3-notification bytes to
/// [`parse_s3_notification`]. `auto` sniffs the body's `Type` field for a
/// bare SNS `Notification` envelope; `s3`/`sns` skip the sniff entirely.
fn decode_body(body: &str, format: SqsBodyFormat) -> Result<Vec<ObjectRef>, DecodeError> {
    let s3_payload: Cow<[u8]> = match format {
        SqsBodyFormat::S3 => Cow::Borrowed(body.as_bytes()),
        SqsBodyFormat::Sns => Cow::Owned(unwrap_sns(body)?),
        SqsBodyFormat::Auto if looks_like_sns_notification(body) => Cow::Owned(unwrap_sns(body)?),
        SqsBodyFormat::Auto => Cow::Borrowed(body.as_bytes()),
    };

    let items = parse_s3_notification(&s3_payload)?;
    Ok(items
        .into_iter()
        .next()
        .map(|i| i.objects)
        .unwrap_or_default())
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
    fn sns_body_is_not_unwrapped_when_format_is_s3() {
        // Forcing `s3` on an SNS-wrapped body hands it straight to the S3
        // parser, which finds no `Records` array in the bare SNS envelope
        // shape — same as any unrecognized-shape JSON, so this decodes to
        // zero objects for the message rather than unwrapping the SNS
        // envelope or erroring.
        let decoder = SqsEventDecoder::new(SqsBodyFormat::S3);
        let items = decoder.decode(SQS_SNS_EVENT).unwrap();
        assert_eq!(items.len(), 1);
        assert!(items[0].objects.is_empty());
    }

    #[test]
    fn batch_with_one_garbage_message_still_decodes_siblings() {
        let decoder = SqsEventDecoder::new(SqsBodyFormat::Auto);
        let items = decoder.decode(SQS_BATCH_PARTIAL_GARBAGE).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(
            items[0].ack_id,
            Some("059f36b4-87a3-44ab-83d2-661975830a7d".to_string())
        );
        assert_eq!(items[0].objects[0].key, "b21b84d653bb07b05b1e6b33684dc11b");
        assert_eq!(
            items[1].ack_id,
            Some("2e1424d4-f796-459a-8184-9c92662be6da".to_string())
        );
        assert_eq!(items[1].objects[0].key, "second-sibling-object.json.gz");
        assert_eq!(items[1].objects[0].bucket, "ct-siem-sync");
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
}
