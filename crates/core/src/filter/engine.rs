//! Rule evaluation: compiles a `RuleSet` into a set of regexes and evaluates
//! records against it. See `SHARED.md` for the AND/OR semantics.
//!
//! `evaluate_linear` walks `rules` in order and, within a rule, `matches` in
//! order — no rule index yet (that is a later task; `evaluate` does not
//! exist here). It is kept permanently as the correctness oracle any indexed
//! evaluator must agree with.

use regex::{Regex, RegexBuilder};
use serde_json::Value;

use crate::config::rules::{REGEX_SIZE_LIMIT, RuleSet};
use crate::error::ConfigError;
use crate::filter::resolve;

/// Outcome of evaluating one record against the engine's rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// No rule matched: forward the record.
    Keep,
    /// The rule at `rule_idx` matched (all its `matches` matched): drop the
    /// record. `rule_idx` indexes into the `RuleSet` the engine was built
    /// from, and is stable input to `Engine::rule_name`.
    Drop { rule_idx: usize },
}

/// One compiled condition: a dot-path (see `crate::filter::resolve`) and the
/// regex its resolved value must match.
struct CompiledMatch {
    field_name: String,
    regex: Regex,
}

/// One compiled rule: fires only if every `matches` condition matches (AND).
struct CompiledRule {
    name: String,
    matches: Vec<CompiledMatch>,
}

/// Compiled, ready-to-evaluate exclusion rules.
///
/// Built once, at config load (`Engine::new`), from a validated `RuleSet`.
/// The per-record hot path (`evaluate_linear`) does no compilation, no
/// allocation beyond what `resolve` already returns.
pub struct Engine {
    rules: Vec<CompiledRule>,
}

/// Cheap selectivity ordinal used to order a rule's conditions
/// most-selective-first: an exact literal anchored on both ends
/// (`^kms\.amazonaws\.com$`) is checked before a `.*`-prefixed pattern, which
/// can only reject after scanning past the wildcard. AND is order-independent
/// for correctness — this only changes which field gets resolved and matched
/// first when a rule ultimately fails.
fn selectivity_rank(pattern: &str) -> u8 {
    if pattern.starts_with(".*") || pattern.starts_with("^.*") {
        1
    } else {
        0
    }
}

impl Engine {
    /// Compile every rule's regexes. Fatal (returns `Err`) if any pattern
    /// fails to compile within `REGEX_SIZE_LIMIT` — the same limit
    /// `RuleSet::parse` validates against, reused here (not redefined) so a
    /// ruleset that passes validation cannot then fail to build.
    pub fn new(rules: RuleSet) -> Result<Engine, ConfigError> {
        let mut compiled = Vec::with_capacity(rules.rules.len());
        for rule in rules.rules {
            let mut matches = Vec::with_capacity(rule.matches.len());
            for m in rule.matches {
                let regex = RegexBuilder::new(&m.regex)
                    .size_limit(REGEX_SIZE_LIMIT)
                    .build()
                    .map_err(|e| {
                        ConfigError::Parse(format!(
                            "rule {:?}: invalid regex {:?}: {e}",
                            rule.name, m.regex
                        ))
                    })?;
                matches.push(CompiledMatch {
                    field_name: m.field_name,
                    regex,
                });
            }
            matches.sort_by_key(|m| selectivity_rank(m.regex.as_str()));
            compiled.push(CompiledRule {
                name: rule.name,
                matches,
            });
        }
        Ok(Engine { rules: compiled })
    }

    /// Name of the rule at `rule_idx`, for the `RuleDrops` metrics dimension.
    pub fn rule_name(&self, rule_idx: usize) -> &str {
        &self.rules[rule_idx].name
    }

    /// Evaluate `record` against every rule in order, first match wins.
    ///
    /// A condition whose `field_name` resolves to nothing (missing field,
    /// `null`, or a non-scalar leaf) is FALSE, never TRUE — a typo'd
    /// `field_name` must never make a rule fire on every record.
    pub fn evaluate_linear(&self, record: &Value) -> Decision {
        for (rule_idx, rule) in self.rules.iter().enumerate() {
            let fires = rule.matches.iter().all(|m| {
                resolve(record, &m.field_name).is_some_and(|value| m.regex.is_match(&value))
            });
            if fires {
                return Decision::Drop { rule_idx };
            }
        }
        Decision::Keep
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Decision, Engine};
    use crate::config::rules::RuleSet;
    use serde_json::json;

    const EXAMPLE_RULES: &[u8] = include_bytes!("../../tests/fixtures/rules.example.yaml");

    fn engine() -> Engine {
        let rule_set = RuleSet::parse(EXAMPLE_RULES).expect("example ruleset must parse");
        Engine::new(rule_set).expect("example ruleset must compile")
    }

    #[test]
    fn eks_kms_decrypt_drops_via_eks_kms_operations() {
        let engine = engine();
        let record = json!({
            "eventName": "Decrypt",
            "eventSource": "kms.amazonaws.com",
            "sourceIPAddress": "eks.amazonaws.com"
        });
        match engine.evaluate_linear(&record) {
            Decision::Drop { rule_idx } => {
                assert_eq!(engine.rule_name(rule_idx), "EKS KMS Operations");
            }
            Decision::Keep => panic!("expected the record to be dropped"),
        }
    }

    #[test]
    fn same_record_different_source_ip_is_kept() {
        let engine = engine();
        let record = json!({
            "eventName": "Decrypt",
            "eventSource": "kms.amazonaws.com",
            "sourceIPAddress": "203.0.113.5"
        });
        assert_eq!(engine.evaluate_linear(&record), Decision::Keep);
    }

    #[test]
    fn consolelogin_record_survives_all_25_rules() {
        let rule_set = RuleSet::parse(EXAMPLE_RULES).expect("example ruleset must parse");
        assert_eq!(rule_set.rules.len(), 25);
        let engine = Engine::new(rule_set).expect("example ruleset must compile");
        let record = json!({
            "eventName": "ConsoleLogin",
            "eventSource": "signin.amazonaws.com",
            "sourceIPAddress": "203.0.113.5",
            "userIdentity": {
                "type": "IAMUser",
                "accountId": "123456789012"
            }
        });
        assert_eq!(engine.evaluate_linear(&record), Decision::Keep);
    }

    #[test]
    fn missing_invoked_by_is_kept_by_aws_config_recorder() {
        let engine = engine();
        let record = json!({
            "eventName": "DescribeConfigRules",
            "eventSource": "config.amazonaws.com",
            "userIdentity": {
                "type": "AssumedRole"
            }
        });
        assert_eq!(engine.evaluate_linear(&record), Decision::Keep);
    }
}
