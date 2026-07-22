//! Decodes S3 bucket notification events (feature `decode-s3`).
//!
//! Also compiled under `decode-sns` alone: `SnsEventDecoder` (in `sns.rs`)
//! unwraps `.Records[].Sns.Message` and hands the resulting bytes to
//! [`parse_s3_notification`], since an SNS-wrapped message is this same
//! JSON shape. `S3EventDecoder` itself — the `EventDecoder` port impl — is
//! gated behind `decode-s3` alone, so it never ships in a `decode-sns`-only
//! binary.

use crate::error::DecodeError;
use crate::model::{ObjectRef, SourceItem};
use percent_encoding::percent_decode_str;
use serde::Deserialize;

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
        parse_s3_notification(payload)
    }
}

#[derive(Debug, Deserialize)]
struct S3Notification {
    #[serde(rename = "Records", default)]
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

/// Parses an S3 bucket notification payload into `SourceItem`s. Shared by
/// `S3EventDecoder` and, via `sns.rs`, `SnsEventDecoder`.
///
/// S3 sends a flat `{"Service":"Amazon S3","Event":"s3:TestEvent",...}`
/// message the first time a notification configuration is saved — no
/// `Records` array. That is not a decode failure, just an event with no
/// objects in it, so it decodes to an empty `Vec` rather than an `Err`.
pub(crate) fn parse_s3_notification(payload: &[u8]) -> Result<Vec<SourceItem>, DecodeError> {
    let value: serde_json::Value =
        serde_json::from_slice(payload).map_err(|e| DecodeError::InvalidPayload(e.to_string()))?;

    if value.get("Event").and_then(|e| e.as_str()) == Some("s3:TestEvent") {
        return Ok(Vec::new());
    }

    let notification: S3Notification =
        serde_json::from_value(value).map_err(|e| DecodeError::InvalidPayload(e.to_string()))?;

    let objects = notification
        .records
        .into_iter()
        .map(|r| {
            Ok(ObjectRef {
                bucket: r.s3.bucket.name,
                key: decode_form_urlencoded_key(&r.s3.object.key)?,
                size: r.s3.object.size,
            })
        })
        .collect::<Result<Vec<_>, DecodeError>>()?;

    if objects.is_empty() {
        return Ok(Vec::new());
    }

    Ok(vec![SourceItem {
        ack_id: None,
        objects,
    }])
}

/// S3 notification object keys are form-urlencoded
/// (`application/x-www-form-urlencoded`): `+` decodes to a space, in
/// addition to ordinary `%XX` escapes. Percent-decoding alone leaves a
/// literal `+` in the key and every such `GetObject` 404s (SHARED safety
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
}
