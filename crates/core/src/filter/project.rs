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
use std::collections::HashMap;

// Fields read by T11's visitor; only Projection::build (below) writes them
// until then.
#[allow(dead_code)]
#[derive(Default)]
pub(crate) struct Node {
    pub(crate) keys: HashMap<String, Node>,
    /// Fixed array subscripts kept as `(index, child)` pairs rather than a
    /// map: rulesets touch only a handful of indices per array.
    pub(crate) indices: Vec<(usize, Node)>,
    pub(crate) wildcard: Option<Box<Node>>,
    pub(crate) terminals: Vec<usize>,
}

/// The set of field paths a ruleset references, arranged as a trie so one
/// pass over the JSON can fill them all.
pub(crate) struct Projection {
    // Read by T11's visitor.
    #[allow(dead_code)]
    pub(crate) root: Node,
    len: usize,
}

impl Projection {
    /// Build the trie. Path id `i` is `paths[i]`.
    // Unused until T11/T13 wire this in as a caller.
    #[allow(dead_code)]
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

    // Unused until T11/T13 wire the visitor and evaluate_raw in as callers.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::path::parse_path;

    fn paths(specs: &[&str]) -> Vec<Path> {
        specs
            .iter()
            .map(|s| parse_path(s).expect("must parse"))
            .collect()
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
