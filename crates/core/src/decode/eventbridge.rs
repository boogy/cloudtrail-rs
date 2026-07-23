//! Decodes S3 EventBridge notifications (feature `decode-eventbridge`).
//!
//! Only `detail-type: "Object Created"` carries an object worth copying;
//! every other S3 EventBridge detail type (`Object Deleted`, `Object
//! Restore Completed`, `Object Annotation Created`, ...) decodes to an
//! empty `Vec` rather than an error — it is a real event, just not one
//! this pipeline acts on.
//!
//! Unlike S3 bucket notifications, EventBridge object keys are **not**
//! form-urlencoded (safety invariant 4) — `decode_form_urlencoded_key`
//! from `s3.rs` must never be applied here, or a key containing `+` or `%`
//! is corrupted.

use crate::error::DecodeError;
use crate::model::{ObjectRef, SourceItem};
use crate::ports::EventDecoder;
use serde::Deserialize;

/// Decodes an S3 EventBridge notification delivered directly to Lambda.
pub struct EventBridgeDecoder;

impl EventBridgeDecoder {
    pub fn new() -> Self {
        EventBridgeDecoder
    }
}

impl Default for EventBridgeDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Deserialize)]
struct EventBridgeEvent {
    #[serde(rename = "detail-type")]
    detail_type: String,
    detail: Detail,
}

#[derive(Debug, Deserialize)]
struct Detail {
    #[serde(rename = "event-version")]
    event_version: String,
    bucket: Bucket,
    object: ObjectDetail,
}

#[derive(Debug, Deserialize)]
struct Bucket {
    name: String,
}

#[derive(Debug, Deserialize)]
struct ObjectDetail {
    key: String,
    size: Option<u64>,
}

const OBJECT_CREATED: &str = "Object Created";

impl EventDecoder for EventBridgeDecoder {
    fn decode(&self, payload: &[u8]) -> Result<Vec<SourceItem>, DecodeError> {
        let event: EventBridgeEvent = serde_json::from_slice(payload)
            .map_err(|e| DecodeError::InvalidPayload(e.to_string()))?;

        if event.detail_type != OBJECT_CREATED {
            return Ok(Vec::new());
        }

        let major = event_version_major(&event.detail.event_version)?;
        if major != 1 {
            return Err(DecodeError::InvalidPayload(format!(
                "unsupported detail.event-version {:?}: expected major version 1",
                event.detail.event_version
            )));
        }

        Ok(vec![SourceItem {
            ack_id: None,
            objects: vec![ObjectRef {
                bucket: event.detail.bucket.name,
                // Verbatim — EventBridge keys are not url-encoded.
                key: event.detail.object.key,
                size: event.detail.object.size,
            }],
        }])
    }
}

fn event_version_major(event_version: &str) -> Result<u64, DecodeError> {
    event_version
        .split('.')
        .next()
        .and_then(|major| major.parse::<u64>().ok())
        .ok_or_else(|| {
            DecodeError::InvalidPayload(format!("invalid detail.event-version {event_version:?}"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const OBJECT_CREATED_EVENT: &[u8] =
        include_bytes!("../../tests/fixtures/eventbridge-object-created.json");
    const OBJECT_CREATED_PLUS_KEY: &[u8] =
        include_bytes!("../../tests/fixtures/eventbridge-object-created-plus-key.json");
    const OBJECT_CREATED_UNSUPPORTED_VERSION: &[u8] =
        include_bytes!("../../tests/fixtures/eventbridge-object-created-unsupported-version.json");
    const OBJECT_DELETED: &[u8] =
        include_bytes!("../../tests/fixtures/eventbridge-object-deleted.json");
    const OBJECT_RESTORE_COMPLETED: &[u8] =
        include_bytes!("../../tests/fixtures/eventbridge-object-restore-completed.json");
    const OBJECT_ANNOTATION_CREATED: &[u8] =
        include_bytes!("../../tests/fixtures/eventbridge-object-annotation-created.json");

    #[test]
    fn decodes_object_created_event() {
        let decoder = EventBridgeDecoder::new();
        let items = decoder.decode(OBJECT_CREATED_EVENT).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].ack_id, None);
        assert_eq!(items[0].objects.len(), 1);
        assert_eq!(
            items[0].objects[0],
            ObjectRef {
                bucket: "amzn-s3-demo-bucket1".to_string(),
                key: "example-key".to_string(),
                size: Some(5),
            }
        );
    }

    #[test]
    fn key_containing_plus_is_used_verbatim_not_decoded() {
        // Opposite of the S3 decoder: EventBridge keys are not
        // form-urlencoded, so a literal `+` must survive untouched.
        let decoder = EventBridgeDecoder::new();
        let items = decoder.decode(OBJECT_CREATED_PLUS_KEY).unwrap();
        assert_eq!(items[0].objects[0].key, "my+file.json.gz");
    }

    #[test]
    fn unsupported_major_event_version_is_a_decode_error() {
        let decoder = EventBridgeDecoder::new();
        assert!(decoder.decode(OBJECT_CREATED_UNSUPPORTED_VERSION).is_err());
    }

    #[test]
    fn object_deleted_decodes_to_empty_not_error() {
        let decoder = EventBridgeDecoder::new();
        let items = decoder.decode(OBJECT_DELETED).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn object_restore_completed_decodes_to_empty_not_error() {
        let decoder = EventBridgeDecoder::new();
        let items = decoder.decode(OBJECT_RESTORE_COMPLETED).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn object_annotation_created_decodes_to_empty_not_error() {
        let decoder = EventBridgeDecoder::new();
        let items = decoder.decode(OBJECT_ANNOTATION_CREATED).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn garbage_payload_is_a_decode_error() {
        let decoder = EventBridgeDecoder::new();
        assert!(decoder.decode(b"not json").is_err());
    }
}
