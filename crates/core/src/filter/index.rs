//! Rule index: maps an `eventSource` value to the rules whose `eventSource`
//! condition it can satisfy, so `Engine::evaluate` only checks a candidate
//! subset of rules instead of scanning all of them (`evaluate_linear`, the
//! oracle, still does the latter).
//!
//! Built once, in `Engine::new`, from each rule's `eventSource` pattern (or
//! `None` if the rule has no `eventSource` condition).
//! Over-inclusion (a rule landing in `always` when it didn't
//! need to) is safe; over-exclusion is a silent correctness bug, so
//! extraction is deliberately conservative.

use std::collections::HashMap;

/// `HashMap<eventSource literal, rule indices>` plus the `always` bucket —
/// rules whose `eventSource` condition (or its absence) could not be
/// conservatively reduced to a fixed set of literals, and so must be checked
/// against every record regardless of its `eventSource`.
pub(super) struct RuleIndex {
    literal: HashMap<String, Vec<usize>>,
    always: Vec<usize>,
}

impl RuleIndex {
    /// `event_source_patterns[rule_idx]` is `Some(pattern)` if that rule has
    /// an `eventSource` condition, `None` otherwise. Order must match the
    /// engine's compiled rule order — `rule_idx` here is the same index
    /// `Decision::Drop` and `Engine::rule_name` use.
    pub(super) fn build(event_source_patterns: &[Option<&str>]) -> RuleIndex {
        let mut literal: HashMap<String, Vec<usize>> = HashMap::new();
        let mut always = Vec::new();
        for (rule_idx, pattern) in event_source_patterns.iter().enumerate() {
            match pattern.and_then(extract_literals) {
                Some(literals) => {
                    for lit in literals {
                        literal.entry(lit).or_default().push(rule_idx);
                    }
                }
                None => always.push(rule_idx),
            }
        }
        RuleIndex { literal, always }
    }

    /// Candidate rule indices for a record whose `eventSource` resolved to
    /// `event_source` (`None` if the record has no `eventSource` field, or
    /// its value did not coerce to a string): `index[event_source] ∪ always`,
    /// in ascending `rule_idx` order so first-match-wins agrees with
    /// `evaluate_linear`.
    pub(super) fn candidates(&self, event_source: Option<&str>) -> Vec<usize> {
        let mut out = event_source
            .and_then(|es| self.literal.get(es))
            .cloned()
            .unwrap_or_default();
        out.extend_from_slice(&self.always);
        out.sort_unstable();
        out
    }

    pub(super) fn always(&self) -> &[usize] {
        &self.always
    }
}

/// Conservatively extract the finite set of literal strings a `^...$`-anchored
/// `eventSource` regex can match, or `None` if it cannot be reduced to exact
/// literals without risking a silent under-match.
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
fn extract_literals(pattern: &str) -> Option<Vec<String>> {
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
        let patterns: Vec<Option<&str>> = vec![
            Some(r"^kms\.amazonaws\.com$"), // 0: index under one literal
            Some(r"^(cloudwatch|logs|ec2)\.amazonaws\.com$"), // 1: three literals
            None,                           // 2: no eventSource condition -> always
            Some(r".*\.amazonaws\.com$"),   // 3: unreducible -> always
            Some(r"^logs\.amazonaws\.com$"), // 4: shares a literal with rule 1
        ];
        let index = RuleIndex::build(&patterns);

        assert_eq!(index.always(), &[2, 3]);
        assert_eq!(index.candidates(Some("kms.amazonaws.com")), vec![0, 2, 3]);
        assert_eq!(
            index.candidates(Some("logs.amazonaws.com")),
            vec![1, 2, 3, 4]
        );
        assert_eq!(
            index.candidates(Some("unrelated.amazonaws.com")),
            vec![2, 3]
        );
        assert_eq!(index.candidates(None), vec![2, 3]);
    }
}
