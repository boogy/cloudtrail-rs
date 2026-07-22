//! Dot-path field resolution against a `serde_json::Value` record.
//!
//! Used by the rule engine to pull the string representation of a field named
//! in a rule's `field_name` out of a decoded CloudTrail record, without a full
//! typed model of every possible record shape.

use serde_json::Value;
use std::borrow::Cow;

/// Resolve a dot-separated `path` (e.g. `userIdentity.sessionContext.sessionIssuer.arn`)
/// against `v`, coercing the leaf scalar to its string representation.
///
/// - String leaf: returned borrowed, zero-copy (`Cow::Borrowed`).
/// - Bool / number leaf: returned as its literal text form (`Cow::Owned`).
/// - Missing field, `null`, object leaf, array leaf, or traversal through a
///   non-object: `None`. A missing/uncoercible field must never be treated as
///   a match, so callers can safely fold this into "condition false".
///
/// v1 limitation (documented, not a bug): path segments do not support array
/// indexing syntax (`resources[0].ARN`), because `.` splitting treats the
/// whole segment as a literal object key, which then simply is not present.
pub fn resolve<'a>(v: &'a Value, path: &str) -> Option<Cow<'a, str>> {
    let mut current = v;
    for segment in path.split('.') {
        match current {
            Value::Object(map) => current = map.get(segment)?,
            _ => return None,
        }
    }
    match current {
        Value::String(s) => Some(Cow::Borrowed(s.as_str())),
        Value::Bool(b) => Some(Cow::Owned(b.to_string())),
        Value::Number(n) => Some(Cow::Owned(n.to_string())),
        Value::Null | Value::Object(_) | Value::Array(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_record() -> Value {
        json!({
            "eventSource": "kms.amazonaws.com",
            "userIdentity": {
                "sessionContext": {
                    "sessionIssuer": {
                        "arn": "arn:aws:iam::123456789012:role/Foo"
                    }
                }
            },
            "readOnly": true,
            "eventVersion": 42,
            "requestParameters": null,
            "responseElements": {},
            "resources": [{ "ARN": "arn:aws:s3:::bucket" }]
        })
    }

    #[test]
    fn resolve_table_driven() {
        let record = sample_record();
        let cases: &[(&str, Option<&str>)] = &[
            ("eventSource", Some("kms.amazonaws.com")),
            (
                "userIdentity.sessionContext.sessionIssuer.arn",
                Some("arn:aws:iam::123456789012:role/Foo"),
            ),
            ("readOnly", Some("true")),
            ("eventVersion", Some("42")),
            ("doesNotExist", None),
            ("userIdentity.doesNotExist", None),
            ("requestParameters", None),
            ("responseElements", None),
            ("resources", None),
            ("eventSource.subfield", None),
            ("resources[0].ARN", None),
        ];

        for (path, expected) in cases {
            let got = resolve(&record, path);
            assert_eq!(got.as_deref(), *expected, "path = {path:?}");
        }
    }

    #[test]
    fn resolve_string_leaf_is_borrowed_not_owned() {
        let record = sample_record();
        match resolve(&record, "eventSource") {
            Some(Cow::Borrowed(s)) => assert_eq!(s, "kms.amazonaws.com"),
            other => panic!("expected Cow::Borrowed, got {other:?}"),
        }
    }
}
