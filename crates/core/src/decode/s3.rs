//! Decodes S3 bucket notification events (feature `decode-s3`).
//!
//! Also compiled under `decode-sns` alone: `SnsEventDecoder` (in `sns.rs`)
//! unwraps `.Records[].Sns.Message` and hands the resulting bytes to
//! [`parse_s3_notification`], since an SNS-wrapped message is this same
//! JSON shape. `S3EventDecoder` itself — the `EventDecoder` port impl — is
//! gated behind `decode-s3` alone, so it never ships in a `decode-sns`-only
//! binary.

use crate::error::DecodeError;
use crate::model::ObjectRef;
use percent_encoding::percent_decode_str;
use serde::Deserialize;

// `SourceItem` is only built by the two decoders that wrap a whole
// notification as one item; `decode-sqs` uses the object list directly.
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
        Ok(as_source_item(parse_s3_notification(payload)?)
            .into_iter()
            .collect())
    }
}

#[derive(Debug, Deserialize)]
struct S3Notification {
    /// Required — deliberately **not** `#[serde(default)]`. With a default,
    /// any valid JSON object whatsoever deserialized into "zero objects": an
    /// SNS topic carrying something that is not an S3 notification, or an S3
    /// notification shape AWS changes under us, decoded to an empty object
    /// list, produced no `SourceItem` at all on the S3/SNS paths and a clean
    /// ack on the SQS path — 100% loss with no error, no log and no metric.
    /// That is the same silent-loss shape as the `sqs.body_format`
    /// misconfiguration, and it deserves the same treatment: a payload that
    /// does not carry a `Records` array is a decode *failure*.
    ///
    /// The two legitimate zero-object payloads are unaffected: `s3:TestEvent`
    /// short-circuits above this, and an explicit `{"Records":[]}` still
    /// deserializes to an empty list.
    #[serde(rename = "Records")]
    records: Vec<S3RecordEnvelope>,
}

#[derive(Debug, Deserialize)]
struct S3RecordEnvelope {
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

/// Parses an S3 bucket notification payload into the objects it references —
/// **every** `Records` entry, in order. Shared by `S3EventDecoder` and, via
/// `sns.rs` / `sqs.rs`, the SNS and SQS decoders.
///
/// Returns objects rather than `SourceItem`s on purpose. One notification is
/// always one item (an S3 notification has no per-object ack identity), so a
/// `Vec<SourceItem>` return gave callers an item dimension that was never
/// more than one element long — and `sqs.rs` duly collapsed it with
/// `.into_iter().next()`, a silent object-drop that would activate the moment
/// this function's fan-out shape changed. With objects as the return type
/// there is no item dimension to discard: callers that need an item wrap the
/// whole `Vec` via [`as_source_item`].
///
/// S3 sends a flat `{"Service":"Amazon S3","Event":"s3:TestEvent",...}`
/// message the first time a notification configuration is saved — no
/// `Records` array. That is not a decode failure, just an event with no
/// objects in it, so it decodes to an empty `Vec` rather than an `Err`. Any
/// *other* payload lacking a `Records` array is an `Err` — see the field
/// docs on `S3Notification::records`.
pub(crate) fn parse_s3_notification(payload: &[u8]) -> Result<Vec<ObjectRef>, DecodeError> {
    let value: serde_json::Value =
        serde_json::from_slice(payload).map_err(|e| DecodeError::InvalidPayload(e.to_string()))?;

    if value.get("Event").and_then(|e| e.as_str()) == Some("s3:TestEvent") {
        return Ok(Vec::new());
    }

    let notification: S3Notification =
        serde_json::from_value(value).map_err(|e| DecodeError::InvalidPayload(e.to_string()))?;

    notification
        .records
        .into_iter()
        .map(|r| {
            Ok(ObjectRef {
                bucket: r.s3.bucket.name,
                key: decode_form_urlencoded_key(&r.s3.object.key)?,
                size: r.s3.object.size,
            })
        })
        .collect()
}

/// Wraps a notification's objects as the single ack-less `SourceItem` the
/// S3 and SNS decoders yield. `None` for an empty notification (an
/// `s3:TestEvent` or an empty `Records`), so those decode to no items at all
/// rather than to one item with nothing in it — which the pipeline would
/// otherwise count as `items_without_objects`.
#[cfg(any(feature = "decode-s3", feature = "decode-sns"))]
pub(crate) fn as_source_item(objects: Vec<ObjectRef>) -> Option<SourceItem> {
    (!objects.is_empty()).then(|| SourceItem::new(None, objects))
}

/// S3 notification object keys are form-urlencoded
/// (`application/x-www-form-urlencoded`): `+` decodes to a space, in
/// addition to ordinary `%XX` escapes. Percent-decoding alone leaves a
/// literal `+` in the key and every such `GetObject` 404s (safety
/// invariant 4). EventBridge keys are NOT encoded — this function must
/// never be reused for that decoder.
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

    /// S3 batches several object notifications into one event's `Records`
    /// array. Every entry must become an `ObjectRef` on the single item, in
    /// order: the event is handled as a unit, so an entry dropped here is one
    /// the pipeline never learns about.
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

    /// Valid JSON that is simply not an S3 notification must fail, not decode
    /// to zero objects. Decoding it to zero objects yielded no `SourceItem`
    /// at all, so the pipeline loop never ran and the payload vanished with
    /// no error, no log and no metric — the same silent-loss shape as the
    /// `sqs.body_format` misconfiguration. The `s3:TestEvent` case below
    /// proves the legitimate zero-object payload is still not an error.
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
