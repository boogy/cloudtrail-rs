//! The agreement property: every evaluator must return the identical
//! `Decision` for every record. `evaluate_linear` is the oracle -- it has no
//! index and no projection, so it cannot be wrong in the ways the optimised
//! paths can. Over-exclusion by the index is silent data loss, which is why
//! this property is enforced rather than assumed.
//!
//! Needs the `testing` feature; `make test` / `make ci` run `--all-features`.
#![cfg(feature = "testing")]

use cloudtrail_rs_core::config::rules::RuleSet;
use cloudtrail_rs_core::filter::Engine;
use cloudtrail_rs_core::testing::corpus;
use serde_json::Value;

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
