//! Projected parsing: read only the fields the ruleset references, skipping
//! every other subtree.
//!
//! The engine reads a handful of scalars per record, but the record carries
//! bulky `requestParameters`/`responseElements` subtrees no rule touches.
//! Per spec findings F4/F5, fully materialising a `serde_json::Value` is
//! measured at ~88% of per-record time, and walking the JSON once against a
//! trie of the ruleset's own field paths (discarding the rest) is measured at
//! ~3x cheaper on the parse.
//!
//! Correctness rule: this must agree with `path::visit_values` on a fully
//! parsed `Value` for every (record, path) pair. Enforced by differential
//! test, because a divergence here silently changes which records are dropped.

use crate::filter::path::{Path, Segment};
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use std::collections::HashMap;
use std::fmt;

#[derive(Default)]
pub(crate) struct Node {
    pub(crate) keys: HashMap<String, Node>,
    /// Fixed array subscripts kept as `(index, child)` pairs rather than a
    /// map: rulesets touch only a handful of indices per array.
    #[allow(dead_code)] // T12/T13
    pub(crate) indices: Vec<(usize, Node)>,
    #[allow(dead_code)] // T12/T13
    pub(crate) wildcard: Option<Box<Node>>,
    pub(crate) terminals: Vec<usize>,
}

/// The set of field paths a ruleset references, arranged as a trie so one
/// pass over the JSON can fill them all.
pub(crate) struct Projection {
    pub(crate) root: Node,
    len: usize,
}

impl Projection {
    /// Build the trie. Path id `i` is `paths[i]`.
    #[allow(dead_code)] // Unused until T13 wires this in as a caller.
    pub(crate) fn build(paths: &[Path]) -> Projection {
        let mut root = Node::default();
        for (id, path) in paths.iter().enumerate() {
            let mut node = &mut root;
            for segment in &path.segments {
                node = match segment {
                    Segment::Key(k) => node.keys.entry(k.clone()).or_default(),
                    Segment::Index(i) => {
                        let pos = node.indices.iter().position(|(n, _)| n == i);
                        match pos {
                            Some(p) => &mut node.indices[p].1,
                            None => {
                                node.indices.push((*i, Node::default()));
                                &mut node.indices.last_mut().expect("just pushed").1
                            }
                        }
                    }
                    Segment::Wildcard => node
                        .wildcard
                        .get_or_insert_with(|| Box::new(Node::default())),
                };
            }
            node.terminals.push(id);
        }
        Projection {
            root,
            len: paths.len(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

/// Walk `json` once against `projection`, capturing only the scalars its
/// paths name. Returns one slot per path id.
///
/// Errors exactly when `serde_json::from_str::<Value>` would: a skipped
/// subtree is still parsed (and discarded) via `IgnoredAny`, so malformed
/// JSON there is still an error and the caller still keeps the record.
#[allow(dead_code)] // Unused until T13 wires this into evaluate_raw.
pub(crate) fn project(
    json: &str,
    projection: &Projection,
) -> Result<Vec<Option<String>>, serde_json::Error> {
    let mut out = vec![None; projection.len()];
    let mut de = serde_json::Deserializer::from_str(json);
    LevelSeed {
        node: &projection.root,
        out: &mut out,
    }
    .deserialize(&mut de)?;
    de.end()?;
    Ok(out)
}

/// Walks one JSON value against one trie node.
struct LevelSeed<'a> {
    node: &'a Node,
    out: &'a mut Vec<Option<String>>,
}

impl LevelSeed<'_> {
    fn capture_terminals(&mut self, value: Option<String>) {
        for &id in &self.node.terminals {
            self.out[id] = value.clone();
        }
    }
}

impl<'de, 'a> DeserializeSeed<'de> for LevelSeed<'a> {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de, 'a> Visitor<'de> for LevelSeed<'a> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_map<A: MapAccess<'de>>(mut self, mut m: A) -> Result<(), A::Error> {
        // An object reaching this node's own terminal yields nothing (path.rs:137).
        self.capture_terminals(None);
        while let Some(key) = m.next_key::<String>()? {
            match self.node.keys.get(&key) {
                None => {
                    m.next_value::<IgnoredAny>()?;
                }
                Some(child) => {
                    m.next_value_seed(LevelSeed {
                        node: child,
                        out: &mut *self.out,
                    })?;
                }
            }
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(mut self, mut s: A) -> Result<(), A::Error> {
        // T12 descends into arrays; for now this matches `visit_values`,
        // which also yields nothing for a path with no array subscript.
        self.capture_terminals(None);
        while s.next_element::<IgnoredAny>()?.is_some() {}
        Ok(())
    }

    fn visit_str<E>(mut self, v: &str) -> Result<(), E> {
        self.capture_terminals(Some(v.to_string()));
        Ok(())
    }
    fn visit_string<E>(mut self, v: String) -> Result<(), E> {
        self.capture_terminals(Some(v));
        Ok(())
    }
    fn visit_bool<E>(mut self, v: bool) -> Result<(), E> {
        self.capture_terminals(Some(v.to_string()));
        Ok(())
    }
    fn visit_i64<E>(mut self, v: i64) -> Result<(), E> {
        self.capture_terminals(Some(v.to_string()));
        Ok(())
    }
    fn visit_u64<E>(mut self, v: u64) -> Result<(), E> {
        self.capture_terminals(Some(v.to_string()));
        Ok(())
    }
    fn visit_f64<E>(mut self, v: f64) -> Result<(), E> {
        // `f64::to_string()` disagrees with `Number`'s Display on float-lexed
        // literals (`1.0` -> "1", `1.5e-7` -> decimal); match path.rs:135 by
        // going through `Number` itself. `from_f64` is `None` only for
        // NaN/infinity, which JSON can't express, so `None` is correct there too.
        self.capture_terminals(serde_json::Number::from_f64(v).map(|n| n.to_string()));
        Ok(())
    }
    fn visit_unit<E>(mut self) -> Result<(), E> {
        self.capture_terminals(None);
        Ok(())
    }
    fn visit_none<E>(mut self) -> Result<(), E> {
        self.capture_terminals(None);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::path::parse_path;
    use crate::filter::path::visit_values;
    use serde_json::Value;

    fn paths(specs: &[&str]) -> Vec<Path> {
        specs
            .iter()
            .map(|s| parse_path(s).expect("must parse"))
            .collect()
    }

    fn first_value(v: &Value, path: &Path) -> Option<String> {
        let mut out = None;
        visit_values(v, path, &mut |value| {
            out = Some(value.into_owned());
            true
        });
        out
    }

    /// The property that makes projection safe: for every (record, path), the
    /// projected value equals what the fully-parsed `Value` resolves to.
    #[test]
    fn projection_agrees_with_visit_values() {
        let specs = [
            "eventName",
            "eventSource",
            "readOnly",
            "errorCode",
            "userIdentity.type",
            "userIdentity.sessionContext.sessionIssuer.arn",
            "requestParameters.roleArn",
            "missing.entirely",
        ];
        let p = paths(&specs);
        let proj = Projection::build(&p);

        let records = [
            r#"{"eventName":"Decrypt","eventSource":"kms.amazonaws.com","readOnly":true}"#,
            r#"{"userIdentity":{"type":"AssumedRole","sessionContext":{"sessionIssuer":{"arn":"arn:aws:iam::1:role/R"}}},"eventName":"X"}"#,
            r#"{"eventName":"Y","requestParameters":{"roleArn":"arn:x","extra":{"deep":[1,2,3]}},"responseElements":null}"#,
            r#"{"errorCode":"AccessDenied","readOnly":false,"userIdentity":{"type":null}}"#,
            r#"{"eventName":{"not":"a scalar"},"eventSource":[1,2]}"#,
        ];

        for record in records {
            let value: Value = serde_json::from_str(record).expect("test record must parse");
            let projected = project(record, &proj).expect("must project");
            for (id, path) in p.iter().enumerate() {
                assert_eq!(
                    projected[id],
                    first_value(&value, path),
                    "path {:?} diverged on record {record}",
                    specs[id]
                );
            }
        }
    }

    /// Spec F6: a derived struct raises `duplicate field`; `Value` takes
    /// last-wins. Projection must follow `Value`, or a record that drops today
    /// would start being kept.
    #[test]
    fn duplicate_keys_take_the_last_value() {
        let p = paths(&["eventName"]);
        let proj = Projection::build(&p);
        let json = r#"{"eventName":"first","eventName":"second"}"#;
        let value: Value = serde_json::from_str(json).expect("serde_json accepts duplicates");
        assert_eq!(value["eventName"], "second", "baseline: Value is last-wins");
        assert_eq!(
            project(json, &proj).expect("must project")[0].as_deref(),
            Some("second")
        );
    }

    /// Spec F6: skipping a subtree must not skip validating it. An unparseable
    /// record is KEPT by the pipeline, so projection must agree with a full
    /// parse about what "unparseable" means.
    #[test]
    fn malformed_json_in_skipped_subtrees_still_errors() {
        let p = paths(&["eventName"]);
        let proj = Projection::build(&p);
        let cases = [
            (r#"{"eventName":"A","other":{"a":[1,2,3]}}"#, true),
            (r#"{"eventName":"A","other":{"a":[1,2,3,]}}"#, false),
            (r#"{"eventName":"A","other":{a:1}}"#, false),
            (r#"{"eventName":"A","other":{"a":[1,2}"#, false),
            (r#"{"eventName":"A","other":{"a":NaN}}"#, false),
            (r#"{"eventName":"A","other":{"a":1}"#, false),
        ];
        for (json, should_parse) in cases {
            let full_ok = serde_json::from_str::<Value>(json).is_ok();
            let projected_ok = project(json, &proj).is_ok();
            assert_eq!(full_ok, should_parse, "baseline wrong for {json}");
            assert_eq!(
                projected_ok, full_ok,
                "projection disagreed with full parse on {json}"
            );
        }
    }

    #[test]
    fn shares_common_prefixes() {
        let p = paths(&["userIdentity.type", "userIdentity.accountId", "eventName"]);
        let proj = Projection::build(&p);
        assert_eq!(proj.len(), 3);
        assert_eq!(proj.root.keys.len(), 2, "userIdentity and eventName");
        let ui = proj.root.keys.get("userIdentity").expect("present");
        assert_eq!(ui.keys.len(), 2, "type and accountId share the prefix");
        assert_eq!(
            proj.root.keys.get("eventName").expect("present").terminals,
            vec![2]
        );
    }

    #[test]
    fn records_index_and_wildcard_children() {
        let p = paths(&["resources[0].ARN", "resources[*].ARN"]);
        let proj = Projection::build(&p);
        let res = proj.root.keys.get("resources").expect("present");
        assert_eq!(res.indices.len(), 1);
        assert_eq!(res.indices[0].0, 0);
        assert!(res.wildcard.is_some());
    }

    /// Finding 1: `f64::to_string()` and `serde_json::Number`'s Display
    /// disagree on float-lexed literals. Regression for the specific literals
    /// `testing::corpus` carries deliberately (see its module doc).
    #[test]
    fn numeric_agreement_with_visit_values() {
        let specs = ["value"];
        let p = paths(&specs);
        let proj = Projection::build(&p);

        let records = [
            r#"{"value":1.0}"#,
            r#"{"value":1.5e-7}"#,
            r#"{"value":-0.0}"#,
            r#"{"value":9007199254740993}"#,
            r#"{"value":42}"#,
        ];

        for record in records {
            let value: Value = serde_json::from_str(record).expect("test record must parse");
            let projected = project(record, &proj).expect("must project");
            assert_eq!(
                projected[0],
                first_value(&value, &p[0]),
                "numeric literal diverged on record {record}"
            );
        }
    }

    /// Finding 2: a key that is both a terminal (`userIdentity`) and a branch
    /// (`userIdentity.type`) must still descend into its object value.
    #[test]
    fn terminal_and_descendant_both_resolve() {
        let specs = ["userIdentity", "userIdentity.type", "a.b", "a.b.c"];
        let p = paths(&specs);
        let proj = Projection::build(&p);
        let json = r#"{"userIdentity":{"type":"AssumedRole"},"a":{"b":{"c":"deep"}}}"#;
        let value: Value = serde_json::from_str(json).expect("test record must parse");
        let projected = project(json, &proj).expect("must project");
        for (id, path) in p.iter().enumerate() {
            assert_eq!(
                projected[id],
                first_value(&value, path),
                "path {:?} diverged",
                specs[id]
            );
        }
        // Pin the concrete expectation, not just agreement with the oracle.
        assert_eq!(projected[1].as_deref(), Some("AssumedRole"));
        assert_eq!(projected[3].as_deref(), Some("deep"));
    }

    /// Finding 2's trap: a duplicate key whose first occurrence is a scalar
    /// and whose second is a non-scalar must end `None` for its own terminal
    /// (last-wins, and the second, object value yields nothing) while still
    /// descending into the second occurrence's children. A plain single path
    /// (no sibling branch) already passes against the unfixed code here,
    /// because its `ScalarSeed` fallback happens to null out every duplicate
    /// regardless of descent -- so this uses a terminal-and-branch key
    /// (`eventName` / `eventName.x`) to force a real descent, which is what
    /// actually exposes a fix that forgets to clear stale terminals.
    #[test]
    fn duplicate_key_second_occurrence_non_scalar_yields_none() {
        let p = paths(&["eventName", "eventName.x"]);
        let proj = Projection::build(&p);
        let json = r#"{"eventName":"A","eventName":{"x":1}}"#;
        let value: Value = serde_json::from_str(json).expect("serde_json accepts duplicates");
        assert_eq!(
            first_value(&value, &p[0]),
            None,
            "baseline: Value's last-wins entry is an object, which yields nothing"
        );
        assert_eq!(
            first_value(&value, &p[1]),
            Some("1".to_string()),
            "baseline: the surviving object's child is reachable"
        );
        let projected = project(json, &proj).expect("must project");
        assert_eq!(
            projected[0], None,
            "projection must not keep the stale first scalar"
        );
        assert_eq!(projected[1].as_deref(), Some("1"));
    }

    #[test]
    fn duplicate_paths_get_distinct_ids() {
        let p = paths(&["eventName", "eventName"]);
        let proj = Projection::build(&p);
        assert_eq!(
            proj.root.keys.get("eventName").expect("present").terminals,
            vec![0, 1],
            "both ids must be filled, or one rule silently sees nothing"
        );
    }
}
