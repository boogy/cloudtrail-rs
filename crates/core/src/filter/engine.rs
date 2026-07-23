//! Rule evaluation: compiles a `RuleSet` into a set of regexes and evaluates
//! records against it. AND within a rule, OR across rules.
//!
//! `evaluate_linear` walks `rules` in order and, within a rule, `matches` in
//! order — no rule index yet (that is a later task; `evaluate` does not
//! exist here). It is kept permanently as the correctness oracle any indexed
//! evaluator must agree with.

use regex::{Regex, RegexBuilder};
use serde_json::Value;

use crate::config::rules::{REGEX_SIZE_LIMIT, RuleSet};
use crate::error::ConfigError;
use crate::filter::index::RuleIndex;
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
    index: RuleIndex,
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

        // Index by each rule's `eventSource` condition — conservatively: a
        // rule whose eventSource pattern cannot be reduced to a fixed set of
        // literals (or that has no eventSource condition at all) falls into
        // `always` and is checked against every record. See `filter::index`.
        let event_source_patterns: Vec<Option<&str>> = compiled
            .iter()
            .map(|rule| {
                rule.matches
                    .iter()
                    .find(|m| m.field_name == "eventSource")
                    .map(|m| m.regex.as_str())
            })
            .collect();
        let index = RuleIndex::build(&event_source_patterns);

        Ok(Engine {
            rules: compiled,
            index,
        })
    }

    /// Name of the rule at `rule_idx`, for the `RuleDrops` metrics dimension.
    pub fn rule_name(&self, rule_idx: usize) -> &str {
        &self.rules[rule_idx].name
    }

    /// Indices of rules the rule index could not conservatively narrow to a
    /// fixed set of `eventSource` literals — these are checked against every
    /// record regardless of `eventSource`. Exposed so the CLI (`validate`,
    /// Task 17) can warn, by name, about each one: this is the user's lever
    /// to get the indexed evaluator's speedup.
    pub fn always_rules(&self) -> &[usize] {
        self.index.always()
    }

    /// Whether the rule at `rule_idx` fires against `record` — every one of
    /// its `matches` conditions matches (AND). A condition whose
    /// `field_name` resolves to nothing (missing field, `null`, or a
    /// non-scalar leaf) is FALSE, never TRUE — a typo'd `field_name` must
    /// never make a rule fire on every record.
    fn rule_fires(&self, rule_idx: usize, record: &Value) -> bool {
        self.rules[rule_idx]
            .matches
            .iter()
            .all(|m| resolve(record, &m.field_name).is_some_and(|value| m.regex.is_match(&value)))
    }

    /// Evaluate `record` against every rule in order, first match wins. The
    /// correctness oracle — no rule index, kept permanently so an indexed
    /// evaluator (`evaluate`) always has something to be checked against.
    pub fn evaluate_linear(&self, record: &Value) -> Decision {
        for rule_idx in 0..self.rules.len() {
            if self.rule_fires(rule_idx, record) {
                return Decision::Drop { rule_idx };
            }
        }
        Decision::Keep
    }

    /// Evaluate `record` against only the candidate rules the rule index
    /// selects for its `eventSource` (`index[eventSource] ∪ always`),
    /// still in ascending `rule_idx` order so first-match-wins agrees with
    /// `evaluate_linear`. Semantics are identical to `evaluate_linear`; see
    /// the equivalence test below.
    pub fn evaluate(&self, record: &Value) -> Decision {
        let event_source = resolve(record, "eventSource");
        for rule_idx in self.index.candidates(event_source.as_deref()) {
            if self.rule_fires(rule_idx, record) {
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
    use serde_json::{Value, json};

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

    #[test]
    fn exactly_three_of_25_example_rules_land_in_always() {
        let engine = engine();
        let mut always_names: Vec<&str> = engine
            .always_rules()
            .iter()
            .map(|&i| engine.rule_name(i))
            .collect();
        always_names.sort_unstable();
        // "AWS Config Recorder": eventSource `.*\.amazonaws\.com$` is not
        // anchored at the start. "IAM Session Renewals" and "Automated Tool
        // Describe Operations" have no eventSource condition at all. Every
        // other rule's eventSource is an anchored literal or literal
        // alternation and lands in the literal index instead.
        assert_eq!(
            always_names,
            vec![
                "AWS Config Recorder",
                "Automated Tool Describe Operations",
                "IAM Session Renewals",
            ]
        );
    }

    fn rule_idx_named(engine: &Engine, name: &str) -> usize {
        (0..25)
            .find(|&i| engine.rule_name(i) == name)
            .unwrap_or_else(|| panic!("no rule named {name:?}"))
    }

    #[test]
    fn aws_config_recorder_lands_in_always() {
        let engine = engine();
        let idx = rule_idx_named(&engine, "AWS Config Recorder");
        assert!(
            engine.always_rules().contains(&idx),
            "AWS Config Recorder's eventSource pattern (`.*\\.amazonaws\\.com$`) is not \
             anchored at the start and must fall back to always"
        );
    }

    #[test]
    fn iam_session_renewals_lands_in_always_and_still_drops_with_no_event_source() {
        let engine = engine();
        let idx = rule_idx_named(&engine, "IAM Session Renewals");
        assert!(
            engine.always_rules().contains(&idx),
            "IAM Session Renewals has no eventSource condition and must fall back to always"
        );

        // No eventSource field at all: evaluate() must fall back to `always`
        // only, and this rule's other conditions still fire.
        let record = json!({
            "eventName": "AssumeRole",
            "requestParameters": { "roleSessionName": "botocore-session-1690000000" },
            "userIdentity": { "type": "AssumedRole" }
        });
        assert!(!record.as_object().unwrap().contains_key("eventSource"));
        match engine.evaluate(&record) {
            Decision::Drop { rule_idx } => assert_eq!(rule_idx, idx),
            Decision::Keep => panic!("expected the record to be dropped by IAM Session Renewals"),
        }
    }

    #[test]
    fn inline_flag_pattern_lands_in_always() {
        let yaml = br#"
version: 1.0.0
rules:
  - name: Case Insensitive KMS
    matches:
      - field_name: eventSource
        regex: "(?i)^kms\\.amazonaws\\.com$"
"#;
        let rule_set = RuleSet::parse(yaml).expect("ruleset must parse");
        let engine = Engine::new(rule_set).expect("ruleset must compile");
        assert_eq!(engine.always_rules(), &[0]);
    }

    /// Deterministic, realistic corpus of CloudTrail-shaped records, varying
    /// `eventSource`, `eventName`, `sourceIPAddress`, `userIdentity`,
    /// `userAgent`, `requestParameters` and `errorCode` enough to exercise
    /// both drops and keeps across all 25 example rules.
    fn corpus() -> Vec<Value> {
        let event_sources: [Option<&str>; 8] = [
            Some("kms.amazonaws.com"),
            Some("ec2.amazonaws.com"),
            Some("logs.amazonaws.com"),
            Some("cloudwatch.amazonaws.com"),
            Some("s3.amazonaws.com"),
            Some("sts.amazonaws.com"),
            Some("signin.amazonaws.com"), // matches no rule's eventSource literal
            None,                         // no eventSource field at all
        ];
        let event_names = [
            "Decrypt",
            "AssumeRole",
            "DescribeLaunchTemplateVersions",
            "CreateLogStream",
            "GetObject",
            "DescribeInstances",
            "ConsoleLogin",
            "BatchImportFindings",
        ];
        let source_ips = ["eks.amazonaws.com", "ec2.amazonaws.com", "203.0.113.5"];
        let identity_types = ["AssumedRole", "IAMUser"];
        let invoked_by = [
            None,
            Some("config.amazonaws.com"),
            Some("lambda.amazonaws.com"),
            Some("rds.amazonaws.com"),
        ];
        let user_agents = [
            "aws-cli/2.0",
            "boto3/1.28",
            "Terraform/1.5",
            "health-check-agent/1.0",
        ];
        let role_session_names = [
            None,
            Some("botocore-session-12345"),
            Some("terraform-9876"),
            Some("other-session"),
        ];
        let session_issuer_arns = [
            None,
            Some(
                "arn:aws:iam::123456789012:role/aws-service-role/\
                 eks-nodegroup.amazonaws.com/AWSServiceRoleForAmazonEKSNodegroup",
            ),
            Some("arn:aws:iam::123456789012:role/service-role/datadog-integration"),
            Some("arn:aws:iam::123456789012:role/AWSServiceRoleForAmazonEKS"),
        ];

        let mut records = Vec::new();
        let mut i = 0usize;
        for es in event_sources {
            for name in event_names {
                for ip in source_ips {
                    for itype in identity_types {
                        for ib in invoked_by {
                            for ua in user_agents {
                                let mut user_identity = serde_json::Map::new();
                                user_identity.insert("type".into(), json!(itype));
                                user_identity.insert(
                                    "accountId".into(),
                                    json!(if i.is_multiple_of(5) {
                                        "amazon-cf"
                                    } else {
                                        "123456789012"
                                    }),
                                );
                                if let Some(ib) = ib {
                                    user_identity.insert("invokedBy".into(), json!(ib));
                                }
                                if let Some(arn) =
                                    session_issuer_arns[i % session_issuer_arns.len()]
                                {
                                    user_identity.insert(
                                        "sessionContext".into(),
                                        json!({
                                            "sessionIssuer": {
                                                "arn": arn,
                                                "type": "Role",
                                                "principalId": format!("AROAEXAMPLE{i}:aws-lambda-x"),
                                            }
                                        }),
                                    );
                                }

                                let mut record = serde_json::Map::new();
                                record.insert("eventName".into(), json!(name));
                                record.insert("sourceIPAddress".into(), json!(ip));
                                record.insert("userAgent".into(), json!(ua));
                                record.insert("readOnly".into(), json!(i.is_multiple_of(2)));
                                record.insert(
                                    "errorCode".into(),
                                    if i.is_multiple_of(7) {
                                        json!("AccessDenied")
                                    } else {
                                        Value::Null
                                    },
                                );
                                record.insert("userIdentity".into(), Value::Object(user_identity));
                                if let Some(es) = es {
                                    record.insert("eventSource".into(), json!(es));
                                }

                                let mut request_parameters = serde_json::Map::new();
                                if let Some(rsn) = role_session_names[i % role_session_names.len()]
                                {
                                    request_parameters.insert("roleSessionName".into(), json!(rsn));
                                }
                                request_parameters.insert(
                                    "logGroupName".into(),
                                    json!(if i.is_multiple_of(3) {
                                        "/aws/vpc/flowlogs/eni-0123"
                                    } else {
                                        "/aws/lambda/some-function"
                                    }),
                                );
                                request_parameters.insert(
                                    "key".into(),
                                    json!(if i.is_multiple_of(4) {
                                        "env/prod/terraform.tfstate"
                                    } else {
                                        "env/prod/data.json"
                                    }),
                                );
                                request_parameters.insert(
                                    "roleArn".into(),
                                    json!(if i.is_multiple_of(6) {
                                        "arn:aws:iam::123456789012:role/myapp-eks-cluster-irsa-svc"
                                    } else {
                                        "arn:aws:iam::123456789012:role/other"
                                    }),
                                );
                                record.insert(
                                    "requestParameters".into(),
                                    Value::Object(request_parameters),
                                );

                                records.push(Value::Object(record));
                                i += 1;
                            }
                        }
                    }
                }
            }
        }
        records
    }

    #[test]
    fn evaluate_agrees_with_evaluate_linear_over_full_corpus() {
        let engine = engine();
        let records = corpus();
        assert!(
            records.len() >= 500,
            "corpus must have at least 500 records, has {}",
            records.len()
        );

        let mut kept = 0;
        let mut dropped = 0;
        for record in &records {
            let linear = engine.evaluate_linear(record);
            let indexed = engine.evaluate(record);
            assert_eq!(
                indexed, linear,
                "evaluate() disagreed with evaluate_linear() for record {record}"
            );
            match linear {
                Decision::Keep => kept += 1,
                Decision::Drop { .. } => dropped += 1,
            }
        }
        assert!(kept > 0, "corpus never kept a record");
        assert!(dropped > 0, "corpus never dropped a record");
    }
}
