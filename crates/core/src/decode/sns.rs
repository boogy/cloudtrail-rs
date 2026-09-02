//! Decodes SNS notifications wrapping an S3 event notification message
//! (feature `decode-sns`).

use crate::decode::s3::{as_source_item, parse_s3_notification};
use crate::error::DecodeError;
use crate::model::SourceItem;
use crate::ports::EventDecoder;
use serde::Deserialize;

/// Unwraps `.Records[].Sns.Message` — a JSON string containing an S3 event
/// notification (or `s3:TestEvent`) — and decodes it the same way
/// `S3EventDecoder` would.
pub struct SnsEventDecoder;

impl SnsEventDecoder {
    pub fn new() -> Self {
        SnsEventDecoder
    }
}

impl Default for SnsEventDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Deserialize)]
struct SnsNotification {
    #[serde(rename = "Records", default)]
    records: Vec<SnsRecordEnvelope>,
}

#[derive(Debug, Deserialize)]
struct SnsRecordEnvelope {
    #[serde(rename = "Sns")]
    sns: SnsMessage,
}

#[derive(Debug, Deserialize)]
struct SnsMessage {
    #[serde(rename = "Message")]
    message: String,
}

impl EventDecoder for SnsEventDecoder {
    fn decode(&self, payload: &[u8]) -> Result<Vec<SourceItem>, DecodeError> {
        let notification: SnsNotification = serde_json::from_slice(payload)
            .map_err(|e| DecodeError::InvalidPayload(e.to_string()))?;

        let mut items = Vec::new();
        for record in notification.records {
            let (objects, _) = parse_s3_notification(record.sns.message.as_bytes())?;
            items.extend(as_source_item(objects));
        }
        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SNS_S3_EVENT: &[u8] = include_bytes!("../../tests/fixtures/sns-s3-event.json");
    const SNS_S3_TEST_EVENT: &[u8] = include_bytes!("../../tests/fixtures/sns-s3-test-event.json");

    #[test]
    fn unwraps_message_and_decodes_s3_event() {
        let decoder = SnsEventDecoder::new();
        let items = decoder.decode(SNS_S3_EVENT).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].ack_id, None);
        assert_eq!(items[0].objects.len(), 1);
        assert_eq!(
            items[0].objects[0].bucket,
            "lambda-artifacts-deafc19498e3f2df"
        );
        assert_eq!(items[0].objects[0].key, "b21b84d653bb07b05b1e6b33684dc11b");
        assert_eq!(items[0].objects[0].size, Some(1305107));
    }

    #[test]
    fn every_sns_record_becomes_its_own_item_with_all_its_objects() {
        let notification = |keys: &[&str]| {
            let records: Vec<_> = keys
                .iter()
                .map(|k| {
                    serde_json::json!({
                        "s3": {"bucket": {"name": "bkt"}, "object": {"key": k, "size": 1}}
                    })
                })
                .collect();
            serde_json::json!({ "Records": records }).to_string()
        };
        let event = serde_json::json!({
            "Records": [
                { "Sns": { "Message": notification(&["first.json.gz"]) } },
                { "Sns": { "Message": notification(&["second.json.gz", "third.json.gz"]) } },
            ]
        })
        .to_string();

        let items = SnsEventDecoder::new().decode(event.as_bytes()).unwrap();

        assert_eq!(items.len(), 2, "each SNS record is its own item");
        assert_eq!(items[0].objects[0].key, "first.json.gz");
        let second: Vec<&str> = items[1].objects.iter().map(|o| o.key.as_str()).collect();
        assert_eq!(second, ["second.json.gz", "third.json.gz"]);
    }

    #[test]
    fn unwraps_test_event_to_empty_vec() {
        let decoder = SnsEventDecoder::new();
        let items = decoder.decode(SNS_S3_TEST_EVENT).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn empty_records_decodes_to_empty_vec() {
        let decoder = SnsEventDecoder::new();
        let items = decoder.decode(br#"{"Records":[]}"#).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn garbage_payload_is_a_decode_error() {
        let decoder = SnsEventDecoder::new();
        assert!(decoder.decode(b"not json").is_err());
    }
}
