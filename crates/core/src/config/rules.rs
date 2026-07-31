//! Parsing and structural validation for the exclusion rules YAML document
//! (fetched from `rules.uri`).
//!
//! This module parses and validates *shape* only. Regex *compilability* is
//! checked here (a throwaway `Regex` build per `match`), but no compiled
//! `Regex` or rule index is produced or stored — that is `Engine::new`
//! (tasks 05/06).

use std::collections::HashSet;

use regex::RegexBuilder;

use crate::error::ConfigError;

/// Upper bound on a single compiled regex's internal size, well below the
/// `regex` crate's own default (10 MiB): a pathological pattern is rejected
/// at config load, not left to blow up memory on the first match.
/// Compiled-size ceiling for a single rule pattern, 1 MiB.
///
/// `RuleSet::parse` uses this to reject a pattern that cannot be compiled within
/// budget. `Engine::new` performs the *real* compile later and MUST use this same
/// constant — a smaller limit there would let a ruleset pass validation and then
/// fail to build, which at runtime means falling back to `on_config_error`.
pub(crate) const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// One exclusion rule: fires (drops the record) only if *all* of its
/// `matches` match (AND). Across rules, `Engine` ORs the result.
#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub matches: Vec<Match>,
}

/// What a condition tests, once its `field` path has been resolved.
#[derive(Debug, Clone)]
pub enum MatchOp {
    /// The v1 operator, and the general escape hatch in v2.
    Regex(String),
    Equals(String),
    AnyOf(Vec<String>),
    /// `true`: the path must resolve to no scalar; `false`: it must resolve to one.
    Absent(bool),
}

/// One condition within a rule: a field path into the record and the operator
/// its resolved value(s) must satisfy. Both schema versions parse into this.
#[derive(Debug, Clone)]
pub struct Match {
    pub field: String,
    pub op: MatchOp,
    pub negate: bool,
}

/// The parsed and structurally-validated rules document.
#[derive(Debug, Clone)]
pub struct RuleSet {
    pub version: String,
    /// Free-form: parsed but not schema-checked. Typing this as
    /// `HashMap<String, String>` breaks on the user's own file, because
    /// `created_at: 2024-01-01` resolves to a YAML date, not a string.
    pub meta: Option<serde_yaml_ng::Mapping>,
    pub rules: Vec<Rule>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRuleSet {
    version: String,
    #[serde(default)]
    meta: Option<serde_yaml_ng::Mapping>,
    #[serde(default)]
    rules: Vec<serde_yaml_ng::Value>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRuleV1 {
    name: String,
    matches: Vec<WireMatchV1>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WireMatchV1 {
    field_name: String,
    regex: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRuleV2 {
    name: String,
    matches: Vec<WireMatchV2>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WireMatchV2 {
    field: String,
    #[serde(default)]
    regex: Option<String>,
    #[serde(default)]
    equals: Option<String>,
    #[serde(default)]
    any_of: Option<Vec<String>>,
    #[serde(default)]
    absent: Option<bool>,
    #[serde(default)]
    negate: bool,
}

impl WireMatchV2 {
    /// Exactly one operator per match: zero is meaningless, more than one is
    /// ambiguous. Both are fatal at load rather than resolved by precedence.
    fn into_match(self, rule_name: &str) -> Result<Match, ConfigError> {
        let mut ops: Vec<MatchOp> = Vec::new();
        if let Some(r) = self.regex {
            ops.push(MatchOp::Regex(r));
        }
        if let Some(e) = self.equals {
            ops.push(MatchOp::Equals(e));
        }
        if let Some(a) = self.any_of {
            if a.is_empty() {
                return Err(ConfigError::Parse(format!(
                    "rule {rule_name:?}: field {:?}: any_of must not be empty",
                    self.field
                )));
            }
            ops.push(MatchOp::AnyOf(a));
        }
        if let Some(b) = self.absent {
            ops.push(MatchOp::Absent(b));
        }
        if ops.len() != 1 {
            return Err(ConfigError::Parse(format!(
                "rule {rule_name:?}: field {:?}: expected exactly one of \
                 regex/equals/any_of/absent, found {}",
                self.field,
                ops.len()
            )));
        }
        Ok(Match {
            field: self.field,
            op: ops.pop().expect("length checked above"),
            negate: self.negate,
        })
    }
}

impl RuleSet {
    /// Parse a YAML rules document and validate it structurally.
    ///
    /// Accepts major version `1` (`field_name` + `regex`) and major version `2`
    /// (`field` + exactly one of `regex`/`equals`/`any_of`/`absent`, plus an
    /// optional `negate`). Both normalize into the same `Match`.
    ///
    /// Fatal at load (returns `Err`) on: invalid/non-semver `version`, a major
    /// version other than 1 or 2, an uncompilable or oversized `regex`, a
    /// malformed field path, a duplicate or empty rule `name`, or an empty
    /// `matches` list (which would vacuously match, and drop, every record).
    pub fn parse(bytes: &[u8]) -> Result<RuleSet, ConfigError> {
        let wire: WireRuleSet =
            serde_yaml_ng::from_slice(bytes).map_err(|e| ConfigError::Parse(e.to_string()))?;

        let version = semver::Version::parse(&wire.version)
            .map_err(|e| ConfigError::Parse(format!("invalid version {:?}: {e}", wire.version)))?;

        let rules = match version.major {
            1 => wire
                .rules
                .into_iter()
                .map(|raw| {
                    let r: WireRuleV1 = serde_yaml_ng::from_value(raw)
                        .map_err(|e| ConfigError::Parse(format!("invalid v1 rule: {e}")))?;
                    Ok(Rule {
                        name: r.name,
                        matches: r
                            .matches
                            .into_iter()
                            .map(|m| Match {
                                field: m.field_name,
                                op: MatchOp::Regex(m.regex),
                                negate: false,
                            })
                            .collect(),
                    })
                })
                .collect::<Result<Vec<_>, ConfigError>>()?,
            2 => wire
                .rules
                .into_iter()
                .map(|raw| {
                    let r: WireRuleV2 = serde_yaml_ng::from_value(raw)
                        .map_err(|e| ConfigError::Parse(format!("invalid v2 rule: {e}")))?;
                    let name = r.name;
                    let matches = r
                        .matches
                        .into_iter()
                        .map(|m| m.into_match(&name))
                        .collect::<Result<Vec<_>, ConfigError>>()?;
                    Ok(Rule { name, matches })
                })
                .collect::<Result<Vec<_>, ConfigError>>()?,
            other => {
                return Err(ConfigError::Parse(format!(
                    "unsupported rules version {} (major {other}): major version must be 1 or 2",
                    wire.version
                )));
            }
        };

        let parsed = RuleSet {
            version: wire.version,
            meta: wire.meta,
            rules,
        };
        parsed.validate()?;
        Ok(parsed)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let mut names = HashSet::with_capacity(self.rules.len());
        for rule in &self.rules {
            if rule.name.is_empty() {
                return Err(ConfigError::Parse("rule name must not be empty".into()));
            }
            if !names.insert(rule.name.as_str()) {
                return Err(ConfigError::Parse(format!(
                    "duplicate rule name: {:?}",
                    rule.name
                )));
            }
            if rule.matches.is_empty() {
                return Err(ConfigError::Parse(format!(
                    "rule {:?} has no matches: an empty list would vacuously match, \
                     and drop, every record",
                    rule.name
                )));
            }
            for m in &rule.matches {
                crate::filter::parse_path(&m.field).map_err(|e| {
                    ConfigError::Parse(format!(
                        "rule {:?}: invalid field path {:?}: {e}",
                        rule.name, m.field
                    ))
                })?;
                if let MatchOp::Regex(pattern) = &m.op {
                    RegexBuilder::new(pattern)
                        .size_limit(REGEX_SIZE_LIMIT)
                        .build()
                        .map_err(|e| {
                            ConfigError::Parse(format!(
                                "rule {:?}: invalid regex {pattern:?}: {e}",
                                rule.name
                            ))
                        })?;
                }
            }
        }
        Ok(())
    }

    /// Describe the rule's `eventSource` condition for diagnostics, or `None`
    /// if it has none. The CLI's `validate` uses this so it never has to
    /// reach into `Match` internals, which differ between schema versions.
    pub fn index_key_description(&self, rule_idx: usize) -> Option<String> {
        let m = self
            .rules
            .get(rule_idx)?
            .matches
            .iter()
            .find(|m| m.field == "eventSource")?;
        // Quoted via Display, never Debug: the pattern must appear verbatim so
        // a user can find it in their YAML, and Debug would double every
        // backslash in a regex.
        let described = match &m.op {
            MatchOp::Regex(p) => format!("regex \"{p}\""),
            MatchOp::Equals(s) => format!("equals \"{s}\""),
            MatchOp::AnyOf(v) => {
                let items: Vec<String> = v.iter().map(|s| format!("\"{s}\"")).collect();
                format!("any_of [{}]", items.join(", "))
            }
            MatchOp::Absent(b) => format!("absent {b}"),
        };
        Some(if m.negate {
            format!("negated {described}")
        } else {
            described
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The user's real 25-rule example, committed verbatim to both
    /// `examples/rules.example.yaml` and this crate's fixtures (they must
    /// stay identical — Task 17's CLI tests read the `examples/` copy).
    const EXAMPLE_RULES: &[u8] = include_bytes!("../../tests/fixtures/rules.example.yaml");

    #[test]
    fn parses_example_ruleset_to_25_rules_with_expected_match_counts() {
        let rule_set = RuleSet::parse(EXAMPLE_RULES).expect("example ruleset must parse");
        assert_eq!(rule_set.rules.len(), 25);

        let expected: &[(&str, usize)] = &[
            ("EKS KMS Operations", 3),
            ("EKS Nodegroup Launch Templates", 4),
            ("EKS Describe Operations", 3),
            ("Service Role STS Operations", 3),
            ("IAM Session Renewals", 3),
            ("Lambda CloudWatch Logs", 4),
            ("DataDog Integration", 3),
            ("AWS Config Recorder", 3),
            ("S3 Automated Operations", 3),
            ("CloudFront S3 Access", 3),
            ("EC2 Instance Metadata", 3),
            ("Lambda Internal Operations", 3),
            ("Auto Scaling Health Checks", 4),
            ("RDS Automated Backups", 3),
            ("DynamoDB Auto Scaling", 3),
            ("VPC Flow Logs", 3),
            ("Route53 Health Checks", 3),
            ("Security Hub Findings Collection", 4),
            ("GuardDuty Internal Operations", 3),
            ("CodeBuild Operations", 3),
            ("CodePipeline Executions", 3),
            ("Terraform State Operations", 4),
            ("Kubernetes Service Accounts", 3),
            ("Automated Tool Describe Operations", 4),
            ("CloudFormation Drift Detection", 3),
        ];
        let got: Vec<(&str, usize)> = rule_set
            .rules
            .iter()
            .map(|r| (r.name.as_str(), r.matches.len()))
            .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn meta_free_form_date_field_does_not_break_parsing() {
        // `created_at: 2024-01-01` resolves to a YAML date, not a string —
        // this is exactly why `meta` is `Option<serde_yaml_ng::Mapping>` and
        // not a typed `HashMap<String, String>`.
        let rule_set = RuleSet::parse(EXAMPLE_RULES).expect("example ruleset must parse");
        let meta = rule_set.meta.expect("example ruleset has meta");
        assert!(meta.contains_key("created_at"));
    }

    #[test]
    fn accepts_empty_rules_list() {
        let yaml = b"version: 1.0.0\nrules: []\n";
        let rule_set = RuleSet::parse(yaml).expect("empty rules list must be accepted");
        assert_eq!(rule_set.rules.len(), 0);
    }

    #[test]
    fn accepts_rules_omitted_entirely() {
        let yaml = b"version: 1.0.0\n";
        let rule_set = RuleSet::parse(yaml).expect("omitted rules must default to empty");
        assert_eq!(rule_set.rules.len(), 0);
    }

    #[test]
    fn rejects_field_names_typo() {
        let yaml = br#"
version: 1.0.0
rules:
  - name: Bad Rule
    matches:
      - field_names: eventSource
        regex: "^kms\\.amazonaws\\.com$"
"#;
        let err = RuleSet::parse(yaml).expect_err("field_names typo must be rejected");
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn rejects_regexp_typo() {
        let yaml = br#"
version: 1.0.0
rules:
  - name: Bad Rule
    matches:
      - field_name: eventSource
        regexp: "^kms\\.amazonaws\\.com$"
"#;
        let err = RuleSet::parse(yaml).expect_err("regexp typo must be rejected");
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn rejects_unsupported_major_version() {
        let yaml = br#"
version: 3.0.0
rules: []
"#;
        let err = RuleSet::parse(yaml).expect_err("major version 3 must be rejected");
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn rejects_uncompilable_regex() {
        let yaml = br#"
version: 1.0.0
rules:
  - name: Bad Rule
    matches:
      - field_name: eventSource
        regex: "("
"#;
        let err = RuleSet::parse(yaml).expect_err("unbalanced regex must be rejected");
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn rejects_oversized_regex() {
        // Deeply nested counted repetition blows past REGEX_SIZE_LIMIT
        // (1 MiB) while still being syntactically valid.
        let yaml = format!(
            "version: 1.0.0\nrules:\n  - name: Bad Rule\n    matches:\n      - field_name: eventSource\n        regex: \"{}\"\n",
            "a{100}{100}{100}"
        );
        let err = RuleSet::parse(yaml.as_bytes()).expect_err("oversized regex must be rejected");
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn rejects_duplicate_rule_name() {
        let yaml = br#"
version: 1.0.0
rules:
  - name: Same Name
    matches:
      - field_name: eventSource
        regex: "^kms\\.amazonaws\\.com$"
  - name: Same Name
    matches:
      - field_name: eventSource
        regex: "^ec2\\.amazonaws\\.com$"
"#;
        let err = RuleSet::parse(yaml).expect_err("duplicate rule name must be rejected");
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn rejects_empty_matches() {
        let yaml = br#"
version: 1.0.0
rules:
  - name: Vacuous Rule
    matches: []
"#;
        let err = RuleSet::parse(yaml).expect_err("empty matches list must be rejected");
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn rejects_empty_name() {
        let yaml = br#"
version: 1.0.0
rules:
  - name: ""
    matches:
      - field_name: eventSource
        regex: "^kms\\.amazonaws\\.com$"
"#;
        let err = RuleSet::parse(yaml).expect_err("empty rule name must be rejected");
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn parses_v2_operators() {
        let yaml = br#"
version: 2.0.0
rules:
  - name: Example
    matches:
      - field: eventName
        regex: "^Describe"
      - field: readOnly
        equals: "true"
      - field: userAgent
        any_of: ["aws-cli", "boto3"]
      - field: errorCode
        absent: true
      - field: resources[*].ARN
        regex: "^arn:aws:s3"
        negate: true
"#;
        let rs = RuleSet::parse(yaml).expect("v2 ruleset must parse");
        let m = &rs.rules[0].matches;
        assert_eq!(m.len(), 5);
        assert!(matches!(&m[0].op, MatchOp::Regex(r) if r == "^Describe"));
        assert!(matches!(&m[1].op, MatchOp::Equals(s) if s == "true"));
        assert!(matches!(&m[2].op, MatchOp::AnyOf(v) if v.len() == 2));
        assert!(matches!(&m[3].op, MatchOp::Absent(true)));
        assert!(m[4].negate, "negate must round-trip");
        assert_eq!(m[4].field, "resources[*].ARN");
    }

    #[test]
    fn v1_still_parses_and_lowers_to_regex_ops() {
        let yaml = br#"
version: 1.0.0
rules:
  - name: Example
    matches:
      - field_name: eventSource
        regex: "^kms\\.amazonaws\\.com$"
"#;
        let rs = RuleSet::parse(yaml).expect("v1 ruleset must still parse");
        assert_eq!(rs.rules[0].matches[0].field, "eventSource");
        assert!(matches!(&rs.rules[0].matches[0].op, MatchOp::Regex(_)));
        assert!(!rs.rules[0].matches[0].negate);
    }

    #[test]
    fn v2_rejects_zero_or_multiple_operators() {
        let none = br#"
version: 2.0.0
rules:
  - name: Example
    matches:
      - field: eventName
"#;
        let two = br#"
version: 2.0.0
rules:
  - name: Example
    matches:
      - field: eventName
        regex: "^A"
        equals: "B"
"#;
        for (label, yaml) in [("no operator", &none[..]), ("two operators", &two[..])] {
            assert!(
                RuleSet::parse(yaml).is_err(),
                "{label} must be rejected: exactly one operator is required"
            );
        }
    }

    #[test]
    fn v2_rejects_v1_field_name_key() {
        let yaml = br#"
version: 2.0.0
rules:
  - name: Example
    matches:
      - field_name: eventName
        regex: "^A"
"#;
        assert!(
            RuleSet::parse(yaml).is_err(),
            "v2 must not silently accept the v1 key name"
        );
    }

    #[test]
    fn rejects_major_version_3() {
        let yaml = br#"
version: 3.0.0
rules: []
"#;
        assert!(
            RuleSet::parse(yaml).is_err(),
            "major version 3 must be rejected"
        );
    }

    #[test]
    fn describes_the_event_source_condition_for_diagnostics() {
        let v1 = br#"
version: 1.0.0
rules:
  - name: Has eventSource
    matches:
      - field_name: eventSource
        regex: "^kms\\.amazonaws\\.com$"
  - name: No eventSource
    matches:
      - field_name: eventName
        regex: "^Describe"
"#;
        let rs = RuleSet::parse(v1).expect("must parse");
        // Display, not Debug: `crates/cli/tests/cli.rs:80` asserts the raw
        // pattern text appears in the warning, and Debug would escape the
        // backslashes into `\\.` and break it.
        assert_eq!(
            rs.index_key_description(0).as_deref(),
            Some(r#"regex "^kms\.amazonaws\.com$""#)
        );
        assert_eq!(rs.index_key_description(1), None);

        let v2 = br#"
version: 2.0.0
rules:
  - name: Literal eventSource
    matches:
      - field: eventSource
        any_of: ["kms.amazonaws.com", "ec2.amazonaws.com"]
"#;
        let rs = RuleSet::parse(v2).expect("must parse");
        assert_eq!(
            rs.index_key_description(0).as_deref(),
            Some("any_of [\"kms.amazonaws.com\", \"ec2.amazonaws.com\"]")
        );
    }

    #[test]
    fn rejects_invalid_field_path() {
        let yaml = br#"
version: 2.0.0
rules:
  - name: Example
    matches:
      - field: "resources[x].ARN"
        regex: "^A"
"#;
        assert!(
            RuleSet::parse(yaml).is_err(),
            "a malformed field path must be fatal at load, not a never-matching key"
        );
    }
}
