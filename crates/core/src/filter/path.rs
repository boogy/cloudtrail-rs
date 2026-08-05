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

/// One step in a parsed field path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    /// An object key: the `userIdentity` in `userIdentity.type`.
    Key(String),
    /// A fixed array index: the `[0]` in `resources[0].ARN`.
    Index(usize),
    /// Every element of an array: the `[*]` in `resources[*].ARN`.
    Wildcard,
}

/// A parsed field path. Built once at config load, never per record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    pub segments: Vec<Segment>,
}

/// Why a field path could not be parsed. Fatal at config load, like an
/// uncompilable regex -- a malformed path must never silently become a
/// literal key that simply never matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathParseError(pub String);

impl std::fmt::Display for PathParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Parse a dot path with optional array subscripts:
/// `resources[0].ARN`, `resources[*].ARN`, `userIdentity.sessionContext.sessionIssuer.arn`.
///
/// An empty path, an empty segment (`a..b`, `.a`, `a.`), an unclosed `[`, or a
/// subscript that is neither `*` nor a non-negative integer is an error.
pub fn parse_path(s: &str) -> Result<Path, PathParseError> {
    if s.is_empty() {
        return Err(PathParseError("empty field path".into()));
    }
    let mut segments = Vec::new();
    for part in s.split('.') {
        let (name, mut rest) = match part.find('[') {
            Some(i) => part.split_at(i),
            None => (part, ""),
        };
        if name.is_empty() {
            return Err(PathParseError(format!("empty path segment in {s:?}")));
        }
        segments.push(Segment::Key(name.to_string()));
        while !rest.is_empty() {
            if !rest.starts_with('[') {
                return Err(PathParseError(format!(
                    "unexpected text {rest:?} after subscript in {s:?}"
                )));
            }
            let close = rest
                .find(']')
                .ok_or_else(|| PathParseError(format!("unclosed '[' in {s:?}")))?;
            let inner = &rest[1..close];
            segments.push(if inner == "*" {
                Segment::Wildcard
            } else {
                Segment::Index(inner.parse::<usize>().map_err(|_| {
                    PathParseError(format!("invalid array subscript {inner:?} in {s:?}"))
                })?)
            });
            rest = &rest[close + 1..];
        }
    }
    Ok(Path { segments })
}

/// Lower a v1 `field_name` into a `Path` exactly the way `resolve` traverses
/// it: split on `.`, every part a literal object key, no subscript syntax.
/// Infallible — there is no syntax to reject, which is the point: a v1 path
/// that `parse_path` would reject (`a[`, `a..b`, `.a`, `""`) instead becomes a
/// key segment that simply never matches a real record, the same as it always
/// has for v1.
pub fn literal_path(s: &str) -> Path {
    Path {
        segments: s
            .split('.')
            .map(|part| Segment::Key(part.to_string()))
            .collect(),
    }
}

/// Call `f` with every scalar `path` resolves to against `v`, stopping at the
/// first call that returns `true`. Returns whether any call returned `true`.
///
/// A wildcard-free path yields at most one value and is therefore exactly
/// equivalent to `resolve` (enforced by test). A wildcard path is
/// *existential*: the caller's predicate is satisfied if any element satisfies
/// it. Scalar coercion is identical to `resolve` -- string as-is, bool and
/// number stringified, null/object/array yield nothing -- so a missing or
/// uncoercible field can never satisfy a condition.
pub fn visit_values<'a>(
    v: &'a Value,
    path: &Path,
    f: &mut impl FnMut(Cow<'a, str>) -> bool,
) -> bool {
    walk(v, &path.segments, f)
}

fn walk<'a>(
    current: &'a Value,
    segments: &[Segment],
    f: &mut impl FnMut(Cow<'a, str>) -> bool,
) -> bool {
    let Some((segment, rest)) = segments.split_first() else {
        return match current {
            Value::String(s) => f(Cow::Borrowed(s.as_str())),
            Value::Bool(b) => f(Cow::Owned(b.to_string())),
            Value::Number(n) => f(Cow::Owned(n.to_string())),
            Value::Null | Value::Object(_) | Value::Array(_) => false,
        };
    };
    match (segment, current) {
        (Segment::Key(k), Value::Object(map)) => map.get(k).is_some_and(|next| walk(next, rest, f)),
        (Segment::Index(i), Value::Array(items)) => {
            items.get(*i).is_some_and(|next| walk(next, rest, f))
        }
        (Segment::Wildcard, Value::Array(items)) => items.iter().any(|next| walk(next, rest, f)),
        _ => false,
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

    #[test]
    fn parses_object_and_array_segments() {
        let cases: &[(&str, Vec<Segment>)] = &[
            ("eventName", vec![Segment::Key("eventName".into())]),
            (
                "userIdentity.type",
                vec![
                    Segment::Key("userIdentity".into()),
                    Segment::Key("type".into()),
                ],
            ),
            (
                "resources[0].ARN",
                vec![
                    Segment::Key("resources".into()),
                    Segment::Index(0),
                    Segment::Key("ARN".into()),
                ],
            ),
            (
                "resources[*].ARN",
                vec![
                    Segment::Key("resources".into()),
                    Segment::Wildcard,
                    Segment::Key("ARN".into()),
                ],
            ),
            (
                "a[0][1]",
                vec![
                    Segment::Key("a".into()),
                    Segment::Index(0),
                    Segment::Index(1),
                ],
            ),
        ];
        for (input, want) in cases {
            let got = parse_path(input).unwrap_or_else(|e| panic!("{input:?} must parse: {e}"));
            assert_eq!(&got.segments, want, "parsing {input:?}");
        }
    }

    #[test]
    fn rejects_malformed_paths() {
        for bad in [
            "", "a.", ".a", "a[", "a[]", "a[x]", "a[-1]", "a..b", "a[0]y*]", "a[0]y5]", "a[0]x",
            "a[0]5]",
        ] {
            assert!(
                parse_path(bad).is_err(),
                "{bad:?} must be rejected, not silently accepted"
            );
        }
    }

    /// Collect every value a path resolves to, for assertions.
    fn collect(v: &Value, path: &str) -> Vec<String> {
        let parsed = parse_path(path).expect("test path must parse");
        let mut out = Vec::new();
        visit_values(v, &parsed, &mut |value| {
            out.push(value.into_owned());
            false // never short-circuit: collect them all
        });
        out
    }

    #[test]
    fn visit_values_matches_resolve_for_wildcard_free_paths() {
        let record = sample_record();
        for path in [
            "eventSource",
            "userIdentity.type",
            "userIdentity.sessionContext.sessionIssuer.arn",
            "missingField",
            "eventSource.notAnObject",
        ] {
            let via_resolve: Vec<String> = resolve(&record, path)
                .map(|c| c.into_owned())
                .into_iter()
                .collect();
            assert_eq!(collect(&record, path), via_resolve, "path {path:?}");
        }
    }

    /// Spec finding F2: this is the case that is impossible today.
    #[test]
    fn visit_values_traverses_arrays() {
        let record = json!({
            "resources": [
                { "ARN": "arn:aws:s3:::noisy-bucket", "type": "AWS::S3::Bucket" },
                { "ARN": "arn:aws:s3:::other-bucket", "type": "AWS::S3::Bucket" }
            ]
        });
        assert_eq!(
            collect(&record, "resources[0].ARN"),
            ["arn:aws:s3:::noisy-bucket"]
        );
        assert_eq!(
            collect(&record, "resources[1].ARN"),
            ["arn:aws:s3:::other-bucket"]
        );
        assert!(collect(&record, "resources[9].ARN").is_empty());
        assert_eq!(
            collect(&record, "resources[*].ARN"),
            ["arn:aws:s3:::noisy-bucket", "arn:aws:s3:::other-bucket"]
        );
    }

    #[test]
    fn visit_values_short_circuits() {
        let record = json!({ "resources": [{ "ARN": "a" }, { "ARN": "b" }] });
        let parsed = parse_path("resources[*].ARN").unwrap();
        let mut seen = 0usize;
        let any = visit_values(&record, &parsed, &mut |_| {
            seen += 1;
            true // stop at the first value
        });
        assert!(any, "a matching value exists");
        assert_eq!(seen, 1, "must stop at the first value that satisfies");
    }

    #[test]
    fn visit_values_coerces_scalars_like_resolve() {
        let record =
            json!({ "readOnly": true, "count": 42, "nothing": null, "obj": {}, "arr": [] });
        assert_eq!(collect(&record, "readOnly"), ["true"]);
        assert_eq!(collect(&record, "count"), ["42"]);
        for non_scalar in ["nothing", "obj", "arr"] {
            assert!(
                collect(&record, non_scalar).is_empty(),
                "{non_scalar} is not a scalar"
            );
        }
    }
}
