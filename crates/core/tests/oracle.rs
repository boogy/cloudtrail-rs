//! The agreement property: every evaluator must return the identical
//! `Decision` for every record. `evaluate_linear` is the oracle -- it has no
//! index and no projection, so it cannot be wrong in the ways the optimised
//! paths can. Over-exclusion by the index is silent data loss, which is why
//! this property is enforced rather than assumed.
//!
//! Needs the `testing` feature; `make test` / `make ci` run `--all-features`.
#![cfg(feature = "testing")]

use cloudtrail_rs_core::config::rules::RuleSet;
use cloudtrail_rs_core::filter::{Decision, Engine};
use cloudtrail_rs_core::testing::corpus;
use serde_json::{Value, json};

const EXAMPLE_RULES: &[u8] = include_bytes!("fixtures/rules.example.yaml");

fn engine() -> Engine {
    Engine::new(RuleSet::parse(EXAMPLE_RULES).expect("example ruleset must parse"))
        .expect("engine must build")
}

/// Built once and shared across every generated case in
/// `raw_agrees_with_linear_on_generated_records`: constructing an `Engine` per
/// case (256 by default) is a repeat compile of the same 25-rule ruleset and
/// dominates that test's runtime for no property-strengthening reason.
fn cached_engine() -> &'static Engine {
    static ENGINE: std::sync::OnceLock<Engine> = std::sync::OnceLock::new();
    ENGINE.get_or_init(engine)
}

#[test]
fn indexed_agrees_with_linear_on_corpus() {
    let engine = engine();
    let mut checked = 0usize;
    for record in corpus::records() {
        let value: Value =
            serde_json::from_str(record.json).expect("corpus record must be valid JSON");
        assert_eq!(
            engine.evaluate_linear(&value),
            engine.evaluate(&value),
            "indexed evaluator disagreed with the oracle on corpus record {:?}",
            record.name
        );
        checked += 1;
    }
    assert!(checked > 0, "corpus was empty: the property proved nothing");
}

/// The example ruleset is committed in two places and they must not drift:
/// `examples/` is what users copy, `tests/fixtures/` is what the suite
/// compiles against. Nothing enforced this before -- a fix applied to one
/// copy would silently leave the other wrong.
#[test]
fn example_ruleset_copies_are_identical() {
    let shipped = include_str!("../../../examples/rules.example.yaml");
    let fixture = include_str!("fixtures/rules.example.yaml");
    assert_eq!(
        shipped, fixture,
        "examples/rules.example.yaml and crates/core/tests/fixtures/rules.example.yaml \
         have drifted; they must be byte-identical"
    );
}

#[test]
fn example_ruleset_is_v2_and_uses_absent() {
    let shipped = include_str!("fixtures/rules.example.yaml");
    assert!(
        shipped.contains("version: 2."),
        "example ruleset must be migrated to schema v2"
    );
    assert!(
        shipped.contains("absent:"),
        "example ruleset must express the errorCode-absent condition (spec F1)"
    );
    RuleSet::parse(shipped.as_bytes()).expect("shipped example must parse");
}

/// Guards spec finding F1 against a revert: with the old `errorCode` regex
/// this pair collapses to Keep/Drop the wrong way round.
#[test]
fn shipped_describe_rule_keeps_denied_and_drops_successful() {
    let engine = engine();

    let successful = json!({
        "eventName": "DescribeInstances",
        "readOnly": true,
        "userAgent": "aws-cli/2.15.0",
    });
    let denied = json!({
        "eventName": "DescribeInstances",
        "readOnly": true,
        "userAgent": "aws-cli/2.15.0",
        "errorCode": "AccessDenied",
    });

    assert!(
        matches!(engine.evaluate(&successful), Decision::Drop { .. }),
        "a successful automated Describe is noise and must be dropped"
    );
    assert_eq!(
        engine.evaluate(&denied),
        Decision::Keep,
        "an AccessDenied automated Describe is a security signal and must be kept"
    );
}

/// The three-way agreement property. `evaluate_linear` has no index and no
/// projection, so it is the oracle; the other two must match it on every
/// record. A divergence is silent data loss.
#[test]
fn raw_agrees_with_linear_and_indexed_on_corpus() {
    let engine = engine();
    let mut checked = 0usize;
    for record in corpus::records() {
        let value: Value =
            serde_json::from_str(record.json).expect("corpus record must be valid JSON");
        let linear = engine.evaluate_linear(&value);
        let indexed = engine.evaluate(&value);
        let raw = engine
            .evaluate_raw(record.json)
            .expect("a corpus record parses, so projection must not error");
        assert_eq!(linear, indexed, "indexed diverged on {:?}", record.name);
        assert_eq!(linear, raw, "raw diverged on {:?}", record.name);
        checked += 1;
    }
    assert!(checked > 0, "corpus was empty: the property proved nothing");
}

/// Projection must error exactly when a full parse errors, so the pipeline's
/// "unparseable record is KEPT" rule is unchanged.
#[test]
fn raw_errors_exactly_when_full_parse_errors() {
    let engine = engine();
    for bad in [
        r#"{"eventName":"A","x":{"a":[1,2,3,]}}"#,
        r#"{"eventName":"A","x":{a:1}}"#,
        r#"{"eventName":"A""#,
        r#"not json at all"#,
        r#""#,
    ] {
        let full_ok = serde_json::from_str::<Value>(bad).is_ok();
        let raw_ok = engine.evaluate_raw(bad).is_ok();
        assert_eq!(full_ok, raw_ok, "disagreed on {bad:?}");
    }
}

/// The wildcard fallback is load-bearing, not an optimization: with no `[*]`
/// path in the ruleset, `has_wildcard()` is always false and this branch never
/// runs. The shipped example ruleset has no such path, so the corpus and
/// proptest properties above never exercise it.
///
/// This ruleset has only a `[*]` path -- no fixed subscript sharing its array
/// node -- so projection's wildcard capture is plain first-scalar-wins
/// (`project.rs`'s `projects_wildcard_as_first_scalar`). The matching element
/// here is the *second* one, which first-scalar-wins misses but
/// `evaluate_linear`'s existential `visit_values` does not.
#[test]
fn evaluate_raw_wildcard_fallback_handles_a_non_first_match() {
    let yaml = br#"
version: 2.0.0
rules:
  - name: Noisy bucket anywhere
    matches:
      - field: "resources[*].ARN"
        equals: "arn:aws:s3:::noisy-bucket"
"#;
    let engine = Engine::new(RuleSet::parse(yaml).expect("must parse")).expect("engine must build");
    let record = json!({
        "resources": [
            {"ARN": "arn:aws:s3:::quiet-bucket"},
            {"ARN": "arn:aws:s3:::noisy-bucket"}
        ]
    });
    assert_eq!(
        engine.evaluate_linear(&record),
        engine
            .evaluate_raw(&record.to_string())
            .expect("record parses"),
        "raw diverged from linear when the matching element was not first"
    );
}

/// A fixed subscript and a wildcard addressing the same array node: per
/// project.rs's `wildcard_sharing_a_node_with_a_fixed_index_skips_that_element`,
/// `visit_seq` gives the indexed child priority at that position, so the
/// wildcard child in `project()` never sees element 0 -- while
/// `evaluate_linear`'s existential wildcard checks element 0 first (and
/// short-circuits there, since it matches). Without the fallback, `evaluate_raw`
/// would see only element 1 through the wildcard slot and disagree with
/// `evaluate_linear`.
#[test]
fn evaluate_raw_wildcard_fallback_handles_index_and_wildcard_sharing_a_node() {
    let yaml = br#"
version: 2.0.0
rules:
  - name: Wildcard matches the shared element
    matches:
      - field: "resources[*].ARN"
        equals: "arn:aws:s3:::a"
  - name: Also touches the fixed subscript
    matches:
      - field: "resources[0].ARN"
        equals: "arn:aws:s3:::never-matches-this-value"
"#;
    let engine = Engine::new(RuleSet::parse(yaml).expect("must parse")).expect("engine must build");
    let record = json!({
        "resources": [
            {"ARN": "arn:aws:s3:::a"},
            {"ARN": "arn:aws:s3:::other"}
        ]
    });
    assert_eq!(
        engine.evaluate_linear(&record),
        engine
            .evaluate_raw(&record.to_string())
            .expect("record parses"),
        "raw diverged from linear when a fixed index and a wildcard shared an array node"
    );
}

proptest::proptest! {
    /// Generated records, including missing fields and non-scalar leaves, must
    /// not separate the three evaluators.
    #[test]
    fn raw_agrees_with_linear_on_generated_records(
        event_source in proptest::option::of("[a-z]{1,8}\\.amazonaws\\.com"),
        event_name in proptest::option::of("[A-Za-z]{1,12}"),
        read_only in proptest::option::of(proptest::bool::ANY),
        error_code in proptest::option::of("[A-Za-z]{1,16}"),
    ) {
        let mut obj = serde_json::Map::new();
        if let Some(v) = event_source { obj.insert("eventSource".into(), v.into()); }
        if let Some(v) = event_name { obj.insert("eventName".into(), v.into()); }
        if let Some(v) = read_only { obj.insert("readOnly".into(), v.into()); }
        if let Some(v) = error_code { obj.insert("errorCode".into(), v.into()); }
        let value = Value::Object(obj);
        let text = value.to_string();

        let engine = cached_engine();
        proptest::prop_assert_eq!(
            engine.evaluate_linear(&value),
            engine.evaluate_raw(&text).expect("generated JSON parses")
        );
    }
}
