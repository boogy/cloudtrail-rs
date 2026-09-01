//! Decodes S3 bucket notification events (feature `decode-s3`).
//!
//! Also compiled under `decode-sns` alone, which reuses
//! [`parse_s3_notification`]; `S3EventDecoder` itself is gated behind
//! `decode-s3` so it never ships in a `decode-sns`-only binary.

use crate::error::DecodeError;
use crate::model::ObjectRef;
use percent_encoding::percent_decode_str;
use serde::Deserialize;

#[cfg(any(feature = "decode-s3", feature = "decode-sns"))]
use crate::model::SourceItem;

#[cfg(feature = "decode-s3")]
use crate::ports::EventDecoder;

/// Decodes an S3 bucket notification event delivered directly to Lambda.
#[cfg(feature = "decode-s3")]
pub struct S3EventDecoder;

#[cfg(feature = "decode-s3")]
impl S3EventDecoder {
    pub fn new() -> Self {
        S3EventDecoder
    }
}

#[cfg(feature = "decode-s3")]
impl Default for S3EventDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "decode-s3")]
impl EventDecoder for S3EventDecoder {
    fn decode(&self, payload: &[u8]) -> Result<Vec<SourceItem>, DecodeError> {
        Ok(as_source_item(parse_s3_notification(payload)?.0)
            .into_iter()
            .collect())
    }
}

#[derive(Debug, Deserialize)]
struct S3Notification {
    /// Deliberately **not** `#[serde(default)]`: with a default, any JSON
    /// object at all decodes to zero objects and vanishes with no error, no
    /// log and no metric. A payload without a `Records` array is a failure.
    #[serde(rename = "Records")]
    records: Vec<S3RecordEnvelope>,
}

#[derive(Debug, Deserialize)]
struct S3RecordEnvelope {
    /// Optional on purpose: a missing `eventName` keeps the record. See
    /// [`is_object_created`].
    #[serde(rename = "eventName")]
    event_name: Option<String>,
    s3: S3Detail,
}

#[derive(Debug, Deserialize)]
struct S3Detail {
    bucket: S3Bucket,
    object: S3Object,
}

#[derive(Debug, Deserialize)]
struct S3Bucket {
    name: String,
}

#[derive(Debug, Deserialize)]
struct S3Object {
    key: String,
    size: Option<u64>,
}

/// Parses an S3 bucket notification into the objects it references — **every**
/// `Records` entry, in order. Shared by the S3, SNS and SQS decoders.
///
/// `s3:TestEvent` decodes to an empty `Vec`, not an `Err`; any other payload
/// with no `Records` array is an `Err`. Records that are not object-creations
/// are skipped — the key a delete names is gone. The second return value is
/// whether any record was skipped that way, which is how `sqs.rs` tells an
/// all-delete notification from a genuinely objectless one.
pub(crate) fn parse_s3_notification(payload: &[u8]) -> Result<(Vec<ObjectRef>, bool), DecodeError> {
    let value: serde_json::Value =
        serde_json::from_slice(payload).map_err(|e| DecodeError::InvalidPayload(e.to_string()))?;

    if value.get("Event").and_then(|e| e.as_str()) == Some("s3:TestEvent") {
        return Ok((Vec::new(), false));
    }

    let notification: S3Notification =
        serde_json::from_value(value).map_err(|e| DecodeError::InvalidPayload(e.to_string()))?;

    let mut objects = Vec::with_capacity(notification.records.len());
    let mut skipped = false;
    for r in notification.records {
        if !is_object_created(r.event_name.as_deref()) {
            skipped = true;
            tracing::debug!(
                event_name = r.event_name.as_deref(),
                bucket = %r.s3.bucket.name,
                key = %r.s3.object.key,
                "skipping non-ObjectCreated S3 notification record"
            );
            continue;
        }
        objects.push(ObjectRef {
            bucket: r.s3.bucket.name,
            key: decode_form_urlencoded_key(&r.s3.object.key)?,
            size: r.s3.object.size,
        });
    }
    Ok((objects, skipped))
}

/// True when `event_name` names an object-creation event, with or without the
/// `s3:` prefix AWS's *Supported Event Types* docs use.
///
/// `None` returns `true`. This must never flip: a shape where AWS stops
/// sending `eventName` would otherwise drop every object silently.
fn is_object_created(event_name: Option<&str>) -> bool {
    match event_name {
        None => true,
        Some(name) => name
            .strip_prefix("s3:")
            .unwrap_or(name)
            .starts_with("ObjectCreated:"),
    }
}

/// Wraps a notification's objects as the single ack-less `SourceItem` the S3
/// and SNS decoders yield. `None` when empty, so an objectless notification
/// decodes to no item rather than to one the pipeline counts as
/// `items_without_objects`.
#[cfg(any(feature = "decode-s3", feature = "decode-sns"))]
pub(crate) fn as_source_item(objects: Vec<ObjectRef>) -> Option<SourceItem> {
    (!objects.is_empty()).then(|| SourceItem::new(None, objects))
}

/// Form-urlencoded decode of an S3 notification key: `+` is a space as well
/// as the usual `%XX`. EventBridge keys are NOT encoded — never reuse this
/// there (safety invariant 4).
pub(crate) fn decode_form_urlencoded_key(key: &str) -> Result<String, DecodeError> {
    let plus_decoded = key.replace('+', " ");
    percent_decode_str(&plus_decoded)
        .decode_utf8()
        .map(|s| s.into_owned())
        .map_err(|e| DecodeError::InvalidPayload(e.to_string()))
}

#[cfg(all(test, feature = "decode-s3"))]
mod tests {
    use super::*;

    const OBJECT_CREATED: &[u8] =
        include_bytes!("../../tests/fixtures/s3-event-object-created.json");
    const URLENCODED_KEY: &[u8] =
        include_bytes!("../../tests/fixtures/s3-event-urlencoded-key.json");
    const TEST_EVENT: &[u8] = include_bytes!("../../tests/fixtures/s3-test-event.json");

    #[test]
    fn decodes_object_created_event() {
        let decoder = S3EventDecoder::new();
        let items = decoder.decode(OBJECT_CREATED).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].ack_id, None);
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
    fn every_records_entry_becomes_an_object() {
        const THREE_OBJECTS: &[u8] = br#"{"Records":[
          {"s3":{"bucket":{"name":"bucket-a"},"object":{"key":"one.json.gz","size":11}}},
          {"s3":{"bucket":{"name":"bucket-a"},"object":{"key":"two.json.gz","size":22}}},
          {"s3":{"bucket":{"name":"bucket-b"},"object":{"key":"three+x.json.gz","size":33}}}
        ]}"#;

        let items = S3EventDecoder::new().decode(THREE_OBJECTS).unwrap();
        assert_eq!(items.len(), 1, "one notification is exactly one item");

        let keys: Vec<&str> = items[0].objects.iter().map(|o| o.key.as_str()).collect();
        assert_eq!(
            keys,
            ["one.json.gz", "two.json.gz", "three x.json.gz"],
            "all three entries must survive, in order, each key decoded"
        );
        assert_eq!(items[0].objects[1].size, Some(22));
        assert_eq!(
            items[0].objects[2].bucket, "bucket-b",
            "per-entry bucket must not be taken from the first entry"
        );
    }

    #[test]
    fn object_removed_record_is_skipped() {
        const REMOVED: &[u8] = br#"{"Records":[
          {"eventName":"ObjectRemoved:Delete","s3":{"bucket":{"name":"bucket-a"},"object":{"key":"gone.json.gz"}}}
        ]}"#;

        let items = S3EventDecoder::new().decode(REMOVED).unwrap();
        assert!(
            items.is_empty(),
            "an all-removed notification must decode to zero objects, not an error"
        );
    }

    #[test]
    fn s3_prefixed_object_removed_record_is_skipped() {
        const REMOVED: &[u8] = br#"{"Records":[
          {"eventName":"s3:ObjectRemoved:Delete","s3":{"bucket":{"name":"bucket-a"},"object":{"key":"gone.json.gz"}}}
        ]}"#;

        let items = S3EventDecoder::new().decode(REMOVED).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn mixed_created_and_removed_keeps_only_the_created_object() {
        const MIXED: &[u8] = br#"{"Records":[
          {"eventName":"ObjectCreated:Put","s3":{"bucket":{"name":"bucket-a"},"object":{"key":"kept.json.gz","size":11}}},
          {"eventName":"ObjectRemoved:Delete","s3":{"bucket":{"name":"bucket-a"},"object":{"key":"gone.json.gz"}}}
        ]}"#;

        let items = S3EventDecoder::new().decode(MIXED).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].objects.len(), 1);
        assert_eq!(items[0].objects[0].key, "kept.json.gz");
    }

    #[test]
    fn record_with_no_event_name_field_is_kept() {
        const NO_EVENT_NAME: &[u8] = br#"{"Records":[
          {"s3":{"bucket":{"name":"bucket-a"},"object":{"key":"no-event-name.json.gz","size":5}}}
        ]}"#;

        let items = S3EventDecoder::new().decode(NO_EVENT_NAME).unwrap();
        assert_eq!(items.len(), 1, "absent eventName must not be dropped");
        assert_eq!(items[0].objects[0].key, "no-event-name.json.gz");
    }

    #[test]
    fn all_removed_notification_decodes_to_zero_source_items() {
        const ALL_REMOVED: &[u8] = br#"{"Records":[
          {"eventName":"ObjectRemoved:Delete","s3":{"bucket":{"name":"bucket-a"},"object":{"key":"one.json.gz"}}},
          {"eventName":"ObjectRemoved:Delete","s3":{"bucket":{"name":"bucket-a"},"object":{"key":"two.json.gz"}}}
        ]}"#;

        let items = S3EventDecoder::new().decode(ALL_REMOVED).unwrap();
        assert_eq!(
            items.len(),
            0,
            "an all-removed notification must yield no SourceItem at all"
        );
    }

    #[test]
    fn decodes_plus_as_space_in_key() {
        let decoded = decode_form_urlencoded_key("my+file%3Da.json.gz").unwrap();
        assert_eq!(decoded, "my file=a.json.gz");
    }

    #[test]
    fn decodes_percent_escape_in_key() {
        let decoded = decode_form_urlencoded_key("my%3Dfile.json.gz").unwrap();
        assert_eq!(decoded, "my=file.json.gz");
    }

    #[test]
    fn decodes_urlencoded_key_fixture_end_to_end() {
        let decoder = S3EventDecoder::new();
        let items = decoder.decode(URLENCODED_KEY).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].objects[0].key, "my file=a.json.gz");
    }

    #[test]
    fn s3_test_event_decodes_to_empty_vec() {
        let decoder = S3EventDecoder::new();
        let items = decoder.decode(TEST_EVENT).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn empty_records_decodes_to_empty_vec() {
        let decoder = S3EventDecoder::new();
        let items = decoder.decode(br#"{"Records":[]}"#).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn garbage_payload_is_a_decode_error() {
        let decoder = S3EventDecoder::new();
        assert!(decoder.decode(b"not json").is_err());
    }

    #[test]
    fn valid_json_without_a_records_array_is_a_decode_error_not_zero_objects() {
        let decoder = S3EventDecoder::new();
        let err = decoder
            .decode(br#"{"Type":"Notification","Message":"something else entirely"}"#)
            .expect_err("a payload with no Records array must not decode to zero objects");
        assert!(
            err.to_string().contains("Records"),
            "the error must name the missing field, got: {err}"
        );
    }
}
