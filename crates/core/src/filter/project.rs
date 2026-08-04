//! Projected parsing: read only the fields the ruleset references, skipping
//! every other subtree.
//!
//! The engine reads a handful of scalars per record, but the record carries
//! bulky `requestParameters`/`responseElements` subtrees no rule touches.
//! Fully materialising a `serde_json::Value` dominates per-record time (spec
//! F4/F5). Measured on the 14-record corpus (~1.16 KB mean, ~70% of bytes
//! skipped), this walk is ~1.4x cheaper end-to-end than parse-then-evaluate —
//! not the ~3x the spec predicted for its 4.2 KB synthetic records, because
//! the JSON is still scanned byte-for-byte whether a subtree is captured or
//! skipped. `crates/core/benches/filter.rs` is the measurement.
//!
//! Correctness rule: this must agree with `path::visit_values` on a fully
//! parsed `Value` for every (record, path) pair. Enforced by differential
//! test, because a divergence here silently changes which records are dropped.

use crate::filter::path::{Path, Segment};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::collections::HashMap;
use std::fmt;

#[derive(Default)]
pub(crate) struct Node {
    pub(crate) keys: HashMap<String, Node>,
    /// Fixed array subscripts kept as `(index, child)` pairs rather than a
    /// map: rulesets touch only a handful of indices per array.
    pub(crate) indices: Vec<(usize, Node)>,
    pub(crate) wildcard: Option<Box<Node>>,
    pub(crate) terminals: Vec<usize>,
    /// Every path id whose terminal lives anywhere in this node's subtree
    /// (including its own `terminals`). Lets a parent null out a whole
    /// subtree in one flat loop before re-dispatching into a duplicate key,
    /// instead of walking the trie at parse time.
    pub(crate) subtree_terminals: Vec<usize>,
}

/// The set of field paths a ruleset references, arranged as a trie so one
/// pass over the JSON can fill them all.
pub(crate) struct Projection {
    pub(crate) root: Node,
    len: usize,
    has_wildcard: bool,
}

impl Projection {
    /// Build the trie. Path id `i` is `paths[i]`.
    pub(crate) fn build(paths: &[Path]) -> Projection {
        let mut root = Node::default();
        let mut has_wildcard = false;
        for (id, path) in paths.iter().enumerate() {
            let mut node = &mut root;
            node.subtree_terminals.push(id);
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
                    Segment::Wildcard => {
                        has_wildcard = true;
                        node.wildcard
                            .get_or_insert_with(|| Box::new(Node::default()))
                    }
                };
                node.subtree_terminals.push(id);
            }
            node.terminals.push(id);
        }
        Projection {
            root,
            len: paths.len(),
            has_wildcard,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Whether any projected path contains `[*]`. A wildcard path captures only
    /// the first element that yields a scalar, not the existential semantics
    /// of `visit_values` — `Engine::evaluate_raw` must fall back to a full
    /// parse whenever this is true. A wildcard sharing an array node with a
    /// fixed subscript (see `records_index_and_wildcard_children`) can also
    /// miss the very element that subscript claims, since `visit_seq` gives
    /// the indexed child priority at that position — making the fallback
    /// mandatory, not an optimization choice.
    pub(crate) fn has_wildcard(&self) -> bool {
        self.has_wildcard
    }
}

/// Walk `json` once against `projection`, capturing only the scalars its
/// paths name. Returns one slot per path id.
///
/// Errors exactly when `serde_json::from_str::<Value>` would: a skipped
/// subtree is still walked and discarded via [`Skip`], which drives
/// `deserialize_any` (not `IgnoredAny`'s fast structural skip) so every
/// string in a skipped subtree is still fully decoded -- including its
/// `\uXXXX` escapes -- and a lone surrogate or truncated escape there is
/// still an error and the caller still keeps the record. `IgnoredAny` does
/// not decode string contents, only skips past them structurally, so it
/// silently accepted malformed escapes a full parse rejects; that was the
/// bug this type exists to fix.
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

/// `deserialize_str` decodes escapes the same way `next_key::<String>()`
/// does, so malformed keys still error identically -- only the `.to_owned()`
/// is skipped.
struct KeyLookup<'a> {
    keys: &'a HashMap<String, Node>,
}

impl<'de, 'a> DeserializeSeed<'de> for KeyLookup<'a> {
    type Value = Option<&'a Node>;

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_str(self)
    }
}

impl<'de, 'a> Visitor<'de> for KeyLookup<'a> {
    type Value = Option<&'a Node>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
        Ok(self.keys.get(v))
    }
    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E> {
        Ok(self.keys.get(v))
    }
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

    fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<(), A::Error> {
        while let Some(found) = m.next_key_seed(KeyLookup {
            keys: &self.node.keys,
        })? {
            match found {
                None => {
                    m.next_value_seed(Skip)?;
                }
                Some(child) => {
                    // Last-wins: a repeated key's earlier occurrence may have
                    // descended and filled slots anywhere in `child`'s
                    // subtree. Null the whole subtree before re-dispatching,
                    // or a later occurrence that doesn't refill a slot leaves
                    // the earlier occurrence's stale value behind.
                    for &id in &child.subtree_terminals {
                        self.out[id] = None;
                    }
                    m.next_value_seed(LevelSeed {
                        node: child,
                        out: &mut *self.out,
                    })?;
                }
            }
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<(), A::Error> {
        let LevelSeed { node, out } = self;
        if node.indices.is_empty() && node.wildcard.is_none() {
            while s.next_element_seed(Skip)?.is_some() {}
            return Ok(());
        }
        let mut position = 0usize;
        loop {
            let indexed = node.indices.iter().find(|(i, _)| *i == position);
            let consumed = match (indexed, node.wildcard.as_deref()) {
                // No unfilled-check here: `Projection::build` dedupes fixed
                // subscripts by position, so this child is dispatched at most
                // once per array, unlike the wildcard child below, which is a
                // candidate at every position.
                (Some((_, child)), _) => s
                    .next_element_seed(LevelSeed {
                        node: child,
                        out: &mut *out,
                    })?
                    .is_some(),
                (None, Some(child)) => {
                    // Existential, not last-wins: `visit_values` short-circuits
                    // on the first element that yields a scalar, so once every
                    // terminal under this wildcard is filled, later elements
                    // must not overwrite it.
                    let unfilled = child.subtree_terminals.iter().any(|&id| out[id].is_none());
                    if unfilled {
                        s.next_element_seed(LevelSeed {
                            node: child,
                            out: &mut *out,
                        })?
                        .is_some()
                    } else {
                        s.next_element_seed(Skip)?.is_some()
                    }
                }
                (None, None) => s.next_element_seed(Skip)?.is_some(),
            };
            if !consumed {
                return Ok(());
            }
            position += 1;
        }
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
    // `null` (visit_unit) and a bare `visit_none` both yield nothing
    // (path.rs:136), same as visit_map/visit_seq above: the caller already
    // nulled this node's whole subtree before dispatching here.
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E>(self) -> Result<(), E> {
        Ok(())
    }
}

/// Consumes and discards one JSON value in a subtree the projection does not
/// name -- but, unlike `serde::de::IgnoredAny`, still *validates* it.
///
/// `IgnoredAny` skips a value structurally without decoding string content
/// (serde_json's `deserialize_ignored_any` fast path just scans past bytes),
/// so a string escape serde_json's real string parser would reject -- most
/// notably a lone UTF-16 surrogate half in a `\uXXXX` escape, which has no
/// valid UTF-8/char encoding -- silently passes. `Skip` instead drives
/// `deserialize_any`, the same entry point `serde_json::Value` uses: every
/// string is routed through `visit_str`/`visit_borrowed_str`, which only run
/// after serde_json has fully decoded the escape sequence, so a malformed one
/// still surfaces as a deserialize error there. Maps and sequences recurse
/// into `Skip` again so nested skipped subtrees get the same treatment; every
/// visited value is otherwise dropped.
struct Skip;

impl<'de> DeserializeSeed<'de> for Skip {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

/// See `KeyLookup`.
struct DiscardKey;

impl<'de> DeserializeSeed<'de> for DiscardKey {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_str(self)
    }
}

impl<'de> Visitor<'de> for DiscardKey {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }

    fn visit_str<E>(self, _v: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_borrowed_str<E>(self, _v: &'de str) -> Result<(), E> {
        Ok(())
    }
}

impl<'de> Visitor<'de> for Skip {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<(), A::Error> {
        while m.next_key_seed(DiscardKey)?.is_some() {
            m.next_value_seed(Skip)?;
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<(), A::Error> {
        while s.next_element_seed(Skip)?.is_some() {}
        Ok(())
    }

    fn visit_str<E>(self, _v: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_string<E>(self, _v: String) -> Result<(), E> {
        Ok(())
    }
    fn visit_bool<E>(self, _v: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _v: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _v: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _v: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E>(self) -> Result<(), E> {
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

    /// Reverse-order variant of `duplicate_key_second_occurrence_non_scalar_yields_none`:
    /// the branch occurrence comes *first* and the scalar occurrence *last*, so
    /// last-wins means the final value is the scalar and the descendant slot
    /// filled by the earlier object occurrence must be cleared, not just the
    /// terminal at the shared node.
    #[test]
    fn duplicate_key_reverse_order_clears_stale_descendant() {
        let p = paths(&["eventName", "eventName.x"]);
        let proj = Projection::build(&p);
        let json = r#"{"eventName":{"x":1},"eventName":"A"}"#;
        let value: Value = serde_json::from_str(json).expect("serde_json accepts duplicates");
        let projected = project(json, &proj).expect("must project");
        for (id, path) in p.iter().enumerate() {
            assert_eq!(
                projected[id],
                first_value(&value, path),
                "path {:?} diverged",
                p[id]
            );
        }
        assert_eq!(
            projected[0].as_deref(),
            Some("A"),
            "baseline: last-wins scalar survives"
        );
        assert_eq!(
            projected[1], None,
            "stale descendant from the shadowed first occurrence must not survive"
        );
    }

    /// Object-then-object shadowing on a branch-only node (no terminal at the
    /// shared key itself): the second `a` never mentions `b`, so `a.b` must
    /// end `None` even though the first `a` filled it.
    #[test]
    fn duplicate_object_shadows_descendant_with_no_parent_terminal() {
        let p = paths(&["a.b"]);
        let proj = Projection::build(&p);
        let json = r#"{"a":{"b":1},"a":{"c":2}}"#;
        let value: Value = serde_json::from_str(json).expect("serde_json accepts duplicates");
        assert_eq!(
            first_value(&value, &p[0]),
            None,
            "baseline: Value's last-wins `a` has no `b`"
        );
        let projected = project(json, &proj).expect("must project");
        assert_eq!(
            projected[0], None,
            "stale value from the shadowed first `a.b` must not survive"
        );
    }

    /// Deeper shadowing: the stale value is two levels below the shared key,
    /// exercising subtree clearing through more than one intermediate node.
    #[test]
    fn duplicate_object_shadows_deeper_descendant() {
        let p = paths(&["a.b.c"]);
        let proj = Projection::build(&p);
        let json = r#"{"a":{"b":{"c":1}},"a":{"b":{}}}"#;
        let value: Value = serde_json::from_str(json).expect("serde_json accepts duplicates");
        assert_eq!(
            first_value(&value, &p[0]),
            None,
            "baseline: last-wins `a.b` has no `c`"
        );
        let projected = project(json, &proj).expect("must project");
        assert_eq!(
            projected[0], None,
            "stale value from the shadowed first `a.b.c` must not survive"
        );
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

    #[test]
    fn projects_fixed_array_subscripts() {
        let specs = ["resources[0].ARN", "resources[1].ARN", "resources[9].ARN"];
        let p = paths(&specs);
        let proj = Projection::build(&p);
        let record = r#"{"resources":[{"ARN":"a","type":"T"},{"ARN":"b"}],"eventName":"X"}"#;
        let value: Value = serde_json::from_str(record).expect("must parse");
        let projected = project(record, &proj).expect("must project");
        for (id, path) in p.iter().enumerate() {
            assert_eq!(
                projected[id],
                first_value(&value, path),
                "path {:?}",
                specs[id]
            );
        }
        assert_eq!(projected[0].as_deref(), Some("a"));
        assert_eq!(projected[1].as_deref(), Some("b"));
        assert_eq!(projected[2], None);
    }

    #[test]
    fn projects_wildcard_as_first_scalar() {
        let p = paths(&["resources[*].ARN"]);
        let proj = Projection::build(&p);
        assert!(proj.has_wildcard(), "wildcard presence must be reported");
        let record = r#"{"resources":[{"ARN":"first"},{"ARN":"second"}]}"#;
        assert_eq!(
            project(record, &proj).expect("must project")[0].as_deref(),
            Some("first"),
            "wildcard capture takes the first element yielding a scalar"
        );
    }

    #[test]
    fn wildcard_skips_elements_without_the_key() {
        let p = paths(&["resources[*].ARN"]);
        let proj = Projection::build(&p);
        let record = r#"{"resources":[{"type":"T"},{"ARN":"found"}]}"#;
        assert_eq!(
            project(record, &proj).expect("must project")[0].as_deref(),
            Some("found")
        );
    }

    #[test]
    fn non_wildcard_projection_reports_no_wildcard() {
        let p = paths(&["eventName", "resources[0].ARN"]);
        assert!(!Projection::build(&p).has_wildcard());
    }

    /// Documents a known limitation, not a desired property: when a fixed
    /// index and a wildcard share the same array node (see
    /// `records_index_and_wildcard_children`), `visit_seq` gives the indexed
    /// child priority at that position, so the wildcard child never sees that
    /// element. Here element 0 yields a scalar (`"a"`) and is skipped by the
    /// wildcard for a structural reason, not because it failed the module's
    /// own stated first-scalar rule -- and `visit_values`'s existential
    /// short-circuit lands on that same element 0, so the two disagree. This
    /// is exactly why `has_wildcard()` forces `Engine::evaluate_raw` to fall
    /// back to a full parse whenever a wildcard path is present: it is not an
    /// optional optimization, it is required for correctness.
    #[test]
    fn wildcard_sharing_a_node_with_a_fixed_index_skips_that_element() {
        let specs = ["resources[0].ARN", "resources[*].ARN"];
        let p = paths(&specs);
        let proj = Projection::build(&p);
        let record = r#"{"resources":[{"ARN":"a"},{"ARN":"b"}]}"#;
        let value: Value = serde_json::from_str(record).expect("must parse");

        // The fixed-index slot must still agree with `visit_values`.
        let indexed = first_value(&value, &p[0]);
        assert_eq!(indexed, Some("a".to_string()));
        let projected = project(record, &proj).expect("must project");
        assert_eq!(
            projected[0], indexed,
            "fixed-index slot must agree with visit_values"
        );

        // `visit_values` short-circuits on element 0 for the wildcard path too.
        assert_eq!(
            first_value(&value, &p[1]),
            Some("a".to_string()),
            "baseline: visit_values existential wildcard takes element 0"
        );
        // But project()'s wildcard child never gets to see element 0, because
        // the indexed child at position 0 consumed it first -- so the
        // wildcard slot lands on element 1 instead.
        assert_eq!(
            projected[1].as_deref(),
            Some("b"),
            "known divergence: wildcard sharing this node with a fixed index \
             misses the element the index claims, which is why has_wildcard() \
             forces a full-parse fallback rather than being an optimization choice"
        );
    }

    /// Differential test for fixed-subscript array paths, in the style of
    /// `projection_agrees_with_visit_values`. Wildcard semantics deliberately
    /// diverge from `visit_values` (first-scalar-wins vs. existential), so
    /// this covers only `Segment::Index`, the class of bug T11 shipped twice:
    /// short array, scalar-not-object element, `null` element, object instead
    /// of array, an empty array, and an object element missing the queried key.
    #[test]
    fn projects_array_subscripts_agrees_with_visit_values() {
        let specs = ["resources[0].ARN", "resources[1].ARN", "resources[2].ARN"];
        let p = paths(&specs);
        let proj = Projection::build(&p);

        let records = [
            r#"{"resources":[{"ARN":"only-one"}]}"#,
            r#"{"resources":["not-an-object","also-not"]}"#,
            r#"{"resources":[null,{"ARN":"after-null"}]}"#,
            r#"{"resources":{"ARN":"not-an-array"}}"#,
            r#"{"resources":[{"ARN":"a"},{"ARN":"b"},{"ARN":"c"}]}"#,
            r#"{"resources":[]}"#,
            r#"{"resources":[{"type":"T"}]}"#,
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

    /// Spec F6 / T13: the contract `project()` documents is "errors exactly
    /// when a full parse would," which is exactly what `IgnoredAny` breaks --
    /// it skips a value's bytes structurally without decoding string escapes,
    /// so a lone UTF-16 surrogate half deep in a subtree the projection never
    /// names silently parses as OK where a full `Value` parse rejects it. Each
    /// case here plants its malformation inside `"other"`, a key no path in
    /// `p` names, so it only exercises the skip path (`Skip`, formerly
    /// `IgnoredAny`) -- never the captured (`"eventName"`) path.
    #[test]
    fn skip_path_agrees_with_full_parse_on_malformed_escapes() {
        let p = paths(&["eventName"]);
        let proj = Projection::build(&p);

        let cases: &[(&str, &str)] = &[
            (
                "lone high surrogate",
                r#"{"eventName":"A","other":"\uD800"}"#,
            ),
            (
                "lone low surrogate",
                r#"{"eventName":"A","other":"\uDC00"}"#,
            ),
            (
                "truncated surrogate pair",
                r#"{"eventName":"A","other":"\uD800\u"}"#,
            ),
            (
                "valid surrogate pair (emoji) must NOT be rejected",
                r#"{"eventName":"A","other":"😀"}"#,
            ),
            (
                "invalid hex escape \\uZZZZ",
                r#"{"eventName":"A","other":"\uZZZZ"}"#,
            ),
            ("invalid escape \\q", r#"{"eventName":"A","other":"\q"}"#),
            (
                "unterminated string",
                r#"{"eventName":"A","other":"unterminated}"#,
            ),
            (
                "raw control byte (literal newline) inside a string",
                "{\"eventName\":\"A\",\"other\":\"line\nbreak\"}",
            ),
            (
                "trailing garbage after the top-level value",
                r#"{"eventName":"A","other":"fine"} garbage"#,
            ),
            ("truncated document", r#"{"eventName":"A","other":{"a":1"#),
        ];

        for (label, json) in cases {
            let full_ok = serde_json::from_str::<Value>(json).is_ok();
            let skip_ok = project(json, &proj).is_ok();
            assert_eq!(
                skip_ok, full_ok,
                "{label}: project() disagreed with a full parse on {json:?} \
                 (full_ok={full_ok}, project_ok={skip_ok})"
            );
        }
    }

    /// Same malformation table as
    /// `skip_path_agrees_with_full_parse_on_malformed_escapes`, but the
    /// malformed string now lives inside a *projected* subtree
    /// (`"eventName"` itself), exercising `LevelSeed::visit_str` /
    /// `visit_map`'s captured-key path rather than `Skip`. This path goes
    /// through serde_json's real string decoding regardless -- it was never
    /// broken -- so this pins that it still isn't, now that `Skip` exists
    /// alongside it.
    #[test]
    fn captured_path_agrees_with_full_parse_on_malformed_escapes() {
        let p = paths(&["eventName"]);
        let proj = Projection::build(&p);

        let cases: &[(&str, &str)] = &[
            ("lone high surrogate", r#"{"eventName":"\uD800"}"#),
            ("lone low surrogate", r#"{"eventName":"\uDC00"}"#),
            ("truncated surrogate pair", r#"{"eventName":"\uD800\u"}"#),
            (
                "valid surrogate pair (emoji) must NOT be rejected",
                r#"{"eventName":"😀"}"#,
            ),
            ("invalid hex escape \\uZZZZ", r#"{"eventName":"\uZZZZ"}"#),
            ("invalid escape \\q", r#"{"eventName":"\q"}"#),
            ("unterminated string", r#"{"eventName":"unterminated}"#),
            (
                "raw control byte (literal newline) inside a string",
                "{\"eventName\":\"line\nbreak\"}",
            ),
        ];

        for (label, json) in cases {
            let full_ok = serde_json::from_str::<Value>(json).is_ok();
            let projected_ok = project(json, &proj).is_ok();
            assert_eq!(
                projected_ok, full_ok,
                "{label}: project() disagreed with a full parse on {json:?} \
                 (full_ok={full_ok}, project_ok={projected_ok})"
            );
        }
    }

    /// serde_json enforces a 128-level nesting limit when building a `Value`
    /// (`recursion_limit` feature default). `Skip`'s recursion goes through
    /// `deserialize_any`/`visit_seq`/`visit_map` on the *same*
    /// `serde_json::Deserializer`, whose depth counter is incremented by the
    /// deserializer itself (in `parse_array`/`parse_object`), not by which
    /// `Visitor` is driving it -- so this checks the skip path enforces the
    /// identical limit rather than assuming it, per T13's instructions.
    /// Measured directly: depth 128 already errors on both sides (127 nested
    /// arrays parse fine, 128 do not), and they agree at every depth tried.
    #[test]
    fn skip_path_enforces_the_same_recursion_limit_as_a_full_parse() {
        let p = paths(&["eventName"]);
        let proj = Projection::build(&p);

        for depth in [100usize, 127, 128, 129, 150, 500] {
            let mut nested = String::new();
            for _ in 0..depth {
                nested.push('[');
            }
            for _ in 0..depth {
                nested.push(']');
            }
            let json = format!(r#"{{"eventName":"A","other":{nested}}}"#);
            let full_ok = serde_json::from_str::<Value>(&json).is_ok();
            let skip_ok = project(&json, &proj).is_ok();
            assert_eq!(
                skip_ok, full_ok,
                "recursion-limit disagreement at depth {depth}: \
                 full parse ok={full_ok}, project() ok={skip_ok}"
            );
        }
    }
}
