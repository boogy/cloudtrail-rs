//! Parsing and structural validation for the exclusion rules YAML document
//! (fetched from `rules.uri`, see `SHARED.md`).
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
const REGEX_SIZE_LIMIT: usize = 1 << 20; // 1 MiB

/// One exclusion rule: fires (drops the record) only if *all* of its
/// `matches` match (AND). Across rules, `Engine` ORs the result.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    pub matches: Vec<Match>,
}

/// One condition within a rule: a dot-path into the record (`field_name`,
/// resolved by `crate::filter::resolve`) and a regex it must match.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Match {
    pub field_name: String,
    pub regex: String,
}

/// The parsed and structurally-validated rules document.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    pub version: String,
    /// Free-form: parsed but not schema-checked. Typing this as
    /// `HashMap<String, String>` breaks on the user's own file, because
    /// `created_at: 2024-01-01` resolves to a YAML date, not a string.
    #[serde(default)]
    pub meta: Option<serde_yaml_ng::Mapping>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl RuleSet {
    /// Parse a YAML rules document and validate it structurally. Fatal at
    /// load (returns `Err`) on: invalid/non-semver `version`, major version
    /// other than `1`, an uncompilable or oversized `regex`, a duplicate or
    /// empty rule `name`, or an empty `matches` list (which would vacuously
    /// match, and drop, every record).
    pub fn parse(bytes: &[u8]) -> Result<RuleSet, ConfigError> {
        let parsed: RuleSet =
            serde_yaml_ng::from_slice(bytes).map_err(|e| ConfigError::Parse(e.to_string()))?;
        parsed.validate()?;
        Ok(parsed)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let version = semver::Version::parse(&self.version)
            .map_err(|e| ConfigError::Parse(format!("invalid version {:?}: {e}", self.version)))?;
        if version.major != 1 {
            return Err(ConfigError::Parse(format!(
                "unsupported rules version {}: major version must be 1",
                self.version
            )));
        }

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
                RegexBuilder::new(&m.regex)
                    .size_limit(REGEX_SIZE_LIMIT)
                    .build()
                    .map_err(|e| {
                        ConfigError::Parse(format!(
                            "rule {:?}: invalid regex {:?}: {e}",
                            rule.name, m.regex
                        ))
                    })?;
            }
        }
        Ok(())
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
    fn rejects_non_major_1_version() {
        let yaml = br#"
version: 2.0.0
rules: []
"#;
        let err = RuleSet::parse(yaml).expect_err("major version 2 must be rejected");
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
}
