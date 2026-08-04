//! Rule index: narrows candidate rules by `eventSource` and `eventName`
//! literals, so `Engine::evaluate` only checks a candidate subset of rules
//! instead of scanning all of them (`evaluate_linear`, the oracle, still does
//! the latter).
//!
//! Over-inclusion (a rule landing in `always` when it didn't need to) is
//! safe; over-exclusion is a silent correctness bug, so extraction is
//! deliberately conservative.

use std::collections::HashMap;

/// The literal values each indexable field restricts a rule to. `None` means
/// the rule places no reducible constraint on that field, so it must be
/// considered for every value of it.
pub(super) struct RuleKeys {
    pub(super) event_source: Option<Vec<String>>,
    pub(super) event_name: Option<Vec<String>>,
}

pub(super) struct RuleIndex {
    by_event_source: HashMap<String, Vec<usize>>,
    /// Rules with no reducible `eventSource` constraint.
    any_event_source: Vec<usize>,
    by_event_name: HashMap<String, Vec<usize>>,
    any_event_name: Vec<usize>,
    /// Rules constrained on neither field.
    always: Vec<usize>,
    rule_count: usize,
}

impl RuleIndex {
    /// `keys[rule_idx]` corresponds to the engine's compiled rule order --
    /// `rule_idx` here is the same index `Decision::Drop` and
    /// `Engine::rule_name` use.
    pub(super) fn build(keys: &[RuleKeys]) -> RuleIndex {
        let mut by_event_source: HashMap<String, Vec<usize>> = HashMap::new();
        let mut any_event_source = Vec::new();
        let mut by_event_name: HashMap<String, Vec<usize>> = HashMap::new();
        let mut any_event_name = Vec::new();
        let mut always = Vec::new();

        for (rule_idx, k) in keys.iter().enumerate() {
            match &k.event_source {
                Some(literals) => {
                    for lit in literals {
                        by_event_source
                            .entry(lit.clone())
                            .or_default()
                            .push(rule_idx);
                    }
                }
                None => any_event_source.push(rule_idx),
            }
            match &k.event_name {
                Some(literals) => {
                    for lit in literals {
                        by_event_name.entry(lit.clone()).or_default().push(rule_idx);
                    }
                }
                None => any_event_name.push(rule_idx),
            }
            if k.event_source.is_none() && k.event_name.is_none() {
                always.push(rule_idx);
            }
        }

        RuleIndex {
            by_event_source,
            any_event_source,
            by_event_name,
            any_event_name,
            always,
            rule_count: keys.len(),
        }
    }

    /// Candidate rules for a record, in ascending `rule_idx` order so
    /// first-match-wins agrees with `evaluate_linear`. Kept for this module's
    /// own tests; the engine walks `permits` directly to avoid the `Vec`.
    #[cfg(test)]
    pub(super) fn candidates(
        &self,
        event_source: Option<&str>,
        event_name: Option<&str>,
    ) -> Vec<usize> {
        let mut out = Vec::new();
        self.candidates_into(event_source, event_name, &mut out);
        out
    }

    pub(super) fn always(&self) -> &[usize] {
        &self.always
    }

    /// Number of compiled rules, i.e. the exclusive upper bound on `rule_idx`.
    pub(super) fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Whether the rule at `idx` must be considered for a record with the
    /// given `eventSource`/`eventName`. The sole implementation of the
    /// conservative selection rule -- both `candidates_into` and the engine's
    /// hot path go through this.
    pub(super) fn permits(
        &self,
        idx: usize,
        event_source: Option<&str>,
        event_name: Option<&str>,
    ) -> bool {
        // Buckets are built in ascending rule_idx order, so binary_search is
        // valid here without an explicit sort.
        let permitted_by_source = match event_source {
            None => true,
            Some(es) => {
                self.any_event_source.binary_search(&idx).is_ok()
                    || self
                        .by_event_source
                        .get(es)
                        .is_some_and(|v| v.binary_search(&idx).is_ok())
            }
        };
        let permitted_by_name = match event_name {
            None => true,
            Some(en) => {
                self.any_event_name.binary_search(&idx).is_ok()
                    || self
                        .by_event_name
                        .get(en)
                        .is_some_and(|v| v.binary_search(&idx).is_ok())
            }
        };
        permitted_by_source && permitted_by_name
    }

    /// Fill `out` with the candidate rule indices. `out` is cleared first.
    #[cfg(test)]
    pub(super) fn candidates_into(
        &self,
        event_source: Option<&str>,
        event_name: Option<&str>,
        out: &mut Vec<usize>,
    ) {
        out.clear();
        for idx in 0..self.rule_count {
            if self.permits(idx, event_source, event_name) {
                out.push(idx);
            }
        }
    }
}

/// Conservatively extract the finite set of literal strings a `^...$`-anchored
/// regex can match, or `None` if it cannot be reduced to exact literals
/// without risking a silent under-match.
///
/// Accepts exactly two shapes, both fully anchored:
/// - a plain escaped literal: `^kms\.amazonaws\.com$` -> `["kms.amazonaws.com"]`
/// - a literal with exactly one top-level alternation group:
///   `^(cloudwatch|logs|ec2)\.amazonaws\.com$` -> three literals, the shared
///   prefix/suffix distributed over each alternative.
///
/// Everything else — inline flags (`(?i)`), character classes, quantifiers,
/// nested or multiple groups, a non-anchored pattern, an escaped `|` inside
/// the group — returns `None`, and the caller must fall back to `always`.
pub(super) fn extract_literals(pattern: &str) -> Option<Vec<String>> {
    if pattern.contains("(?") {
        return None;
    }
    let inner = pattern.strip_prefix('^')?.strip_suffix('$')?;

    let parens = find_unescaped_parens(inner);
    if parens.is_empty() {
        return unescape_literal(inner).map(|lit| vec![lit]);
    }
    if parens.len() != 2 || parens[0].1 != '(' || parens[1].1 != ')' {
        // Anything other than exactly one flat, non-nested group is not a
        // shape we conservatively reduce — multiple/nested groups included.
        return None;
    }
    let (open, _) = parens[0];
    let (close, _) = parens[1];
    let prefix = unescape_literal(&inner[..open])?;
    let body = &inner[open + 1..close];
    let suffix = unescape_literal(&inner[close + 1..])?;

    if body.contains("\\|") {
        // An escaped literal pipe inside the group would make a naive
        // `split('|')` wrong; too unusual to special-case, so bail out.
        return None;
    }

    let mut literals = Vec::with_capacity(body.matches('|').count() + 1);
    for alt in body.split('|') {
        let alt = unescape_literal(alt)?;
        literals.push(format!("{prefix}{alt}{suffix}"));
    }
    Some(literals)
}

/// Byte positions and kinds of `(` / `)` in `s` that are not escaped by a
/// preceding backslash.
fn find_unescaped_parens(s: &str) -> Vec<(usize, char)> {
    let mut positions = Vec::new();
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '(' | ')' => positions.push((i, c)),
            _ => {}
        }
    }
    positions
}

/// Unescape a fragment of a regex that is claimed to contain no metacharacter
/// with special meaning — i.e. it must match only the literal string it
/// spells out. Returns `None` the moment that claim looks false: any
/// unescaped metacharacter, or a backslash-escape of an alphanumeric (`\d`,
/// `\w`, `\s`, `\b`, ...), which denotes a character class or anchor rather
/// than an escaped literal.
fn unescape_literal(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let escaped = chars.next()?;
                if escaped.is_ascii_alphanumeric() {
                    return None;
                }
                out.push(escaped);
            }
            '.' | '*' | '+' | '?' | '{' | '}' | '^' | '$' | '(' | ')' | '[' | ']' | '|' => {
                return None;
            }
            _ => out.push(c),
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_anchored_literal_extracts_itself() {
        assert_eq!(
            extract_literals(r"^kms\.amazonaws\.com$"),
            Some(vec!["kms.amazonaws.com".to_string()])
        );
    }

    #[test]
    fn alternation_group_with_shared_suffix_extracts_each_literal() {
        assert_eq!(
            extract_literals(r"^(cloudwatch|logs|ec2)\.amazonaws\.com$"),
            Some(vec![
                "cloudwatch.amazonaws.com".to_string(),
                "logs.amazonaws.com".to_string(),
                "ec2.amazonaws.com".to_string(),
            ])
        );
    }

    #[test]
    fn non_anchored_leading_wildcard_returns_none() {
        // "AWS Config Recorder"'s eventSource pattern: unanchored at the
        // start, so it cannot be reduced to a fixed set of literals.
        assert_eq!(extract_literals(r".*\.amazonaws\.com$"), None);
    }

    #[test]
    fn inline_flag_returns_none() {
        assert_eq!(extract_literals(r"(?i)^kms\.amazonaws\.com$"), None);
    }

    #[test]
    fn character_class_returns_none() {
        assert_eq!(extract_literals(r"^kms[0-9]\.amazonaws\.com$"), None);
    }

    #[test]
    fn quantifier_returns_none() {
        assert_eq!(extract_literals(r"^kms+\.amazonaws\.com$"), None);
    }

    #[test]
    fn missing_trailing_anchor_returns_none() {
        assert_eq!(extract_literals(r"^kms\.amazonaws\.com"), None);
    }

    #[test]
    fn missing_leading_anchor_returns_none() {
        assert_eq!(extract_literals(r"kms\.amazonaws\.com$"), None);
    }

    #[test]
    fn nested_group_returns_none() {
        assert_eq!(extract_literals(r"^(a(b|c))$"), None);
    }

    #[test]
    fn multiple_groups_returns_none() {
        assert_eq!(extract_literals(r"^(a|b)(c|d)$"), None);
    }

    #[test]
    fn character_class_shorthand_escape_returns_none() {
        assert_eq!(extract_literals(r"^\d+\.amazonaws\.com$"), None);
    }

    #[test]
    fn build_buckets_by_extracted_literal_and_always() {
        let event_sources: Vec<Option<Vec<String>>> = vec![
            extract_literals(r"^kms\.amazonaws\.com$"), // 0: index under one literal
            extract_literals(r"^(cloudwatch|logs|ec2)\.amazonaws\.com$"), // 1: three literals
            None,                                       // 2: no eventSource condition -> always
            extract_literals(r".*\.amazonaws\.com$"),   // 3: unreducible -> always
            extract_literals(r"^logs\.amazonaws\.com$"), // 4: shares a literal with rule 1
        ];
        let keys: Vec<RuleKeys> = event_sources
            .into_iter()
            .map(|event_source| RuleKeys {
                event_source,
                event_name: None,
            })
            .collect();
        let index = RuleIndex::build(&keys);

        assert_eq!(index.always(), &[2, 3]);
        assert_eq!(
            index.candidates(Some("kms.amazonaws.com"), None),
            vec![0, 2, 3]
        );
        assert_eq!(
            index.candidates(Some("logs.amazonaws.com"), None),
            vec![1, 2, 3, 4]
        );
        assert_eq!(
            index.candidates(Some("unrelated.amazonaws.com"), None),
            vec![2, 3]
        );
        assert_eq!(
            index.candidates(None, None),
            vec![0, 1, 2, 3, 4],
            "a record with no eventSource must still consider every rule"
        );
    }

    #[test]
    fn indexes_rules_that_only_constrain_event_name() {
        let keys = vec![
            RuleKeys {
                event_source: None,
                event_name: Some(vec!["Decrypt".into()]),
            },
            RuleKeys {
                event_source: None,
                event_name: None,
            },
        ];
        let index = RuleIndex::build(&keys);
        assert_eq!(
            index.always(),
            &[1],
            "only the wholly-unconstrained rule belongs in `always`"
        );
        assert_eq!(index.candidates(None, Some("Decrypt")), vec![0, 1]);
        assert_eq!(index.candidates(None, Some("Encrypt")), vec![1]);
        assert_eq!(
            index.candidates(None, None),
            vec![0, 1],
            "a record with no eventName must still consider every rule"
        );
    }

    #[test]
    fn a_negated_condition_never_supplies_an_index_key() {
        // Enforced in engine.rs, asserted here as documentation of the rule:
        // a rule that fires when eventSource is NOT kms must not be filed
        // under "kms", or it would be skipped for every other source.
        let keys = vec![RuleKeys {
            event_source: None,
            event_name: None,
        }];
        let index = RuleIndex::build(&keys);
        assert_eq!(index.always(), &[0]);
    }
}
