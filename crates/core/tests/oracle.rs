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
