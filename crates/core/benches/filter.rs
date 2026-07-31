//! Where per-record time goes. The spec's F4 measurement, as a repeatable
//! benchmark: JSON parse dominates evaluation by roughly 10x, so this is the
//! guard that the projection work (T10-T15) actually moved the number it
//! claimed to move.

use cloudtrail_rs_core::config::rules::RuleSet;
use cloudtrail_rs_core::filter::Engine;
use cloudtrail_rs_core::testing::corpus;
use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::Value;
use std::hint::black_box;

const EXAMPLE_RULES: &[u8] = include_bytes!("../tests/fixtures/rules.example.yaml");

fn bench_filter(c: &mut Criterion) {
    let engine = Engine::new(RuleSet::parse(EXAMPLE_RULES).expect("example ruleset must parse"))
        .expect("engine must build");
    let records: Vec<String> = corpus::scale_records(500);
    let values: Vec<Value> = records
        .iter()
        .map(|r| serde_json::from_str(r).expect("corpus record must parse"))
        .collect();

    c.bench_function("parse_value", |b| {
        b.iter(|| {
            for r in &records {
                black_box(serde_json::from_str::<Value>(r).unwrap());
            }
        })
    });

    c.bench_function("evaluate", |b| {
        b.iter(|| {
            for v in &values {
                black_box(engine.evaluate(v));
            }
        })
    });

    c.bench_function("evaluate_linear", |b| {
        b.iter(|| {
            for v in &values {
                black_box(engine.evaluate_linear(v));
            }
        })
    });
}

criterion_group!(benches, bench_filter);
criterion_main!(benches);
