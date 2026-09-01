//! Per-object record counters, tallied while an object is processed and
//! published to `Metrics` only once its fate is decided — a failed object is
//! re-driven and re-evaluated whole, so its tally must never land.

use std::collections::HashMap;

use crate::filter::Engine;
use crate::metrics::Metrics;

/// One object's record counters, held until the object's fate is known.
///
/// Rule drops are keyed by `rule_idx`, not name, so the per-record path
/// touches neither the `Engine`'s name table nor the `RuleDrops` mutex.
#[derive(Debug, Default)]
pub struct RecordTally {
    records_in: u64,
    kept: u64,
    parse_errors: u64,
    rule_drops: HashMap<usize, u64>,
}

impl RecordTally {
    /// A record arrived in the `Records` array.
    pub(crate) fn record_in(&mut self) {
        self.records_in += 1;
    }

    /// The record survives filtering and is written to the output.
    pub(crate) fn keep(&mut self) {
        self.kept += 1;
    }

    /// The record was dropped by rule `rule_idx`. Implies it is not kept.
    pub(crate) fn drop_by_rule(&mut self, rule_idx: usize) {
        *self.rule_drops.entry(rule_idx).or_insert(0) += 1;
    }

    /// The record could not be parsed into a `Value`. Never implies a drop —
    /// the caller still calls [`RecordTally::keep`] for it.
    pub(crate) fn parse_error(&mut self) {
        self.parse_errors += 1;
    }

    /// How many records survived so far.
    pub(crate) fn kept_count(&self) -> u64 {
        self.kept
    }

    /// Publishes every counter to `metrics` as one unit.
    ///
    /// Call **only** once the object's fate is decided. A failed object must
    /// drop its tally uncommitted and let the redelivery re-count it.
    pub fn commit(&self, metrics: &Metrics, engine: &Engine) {
        debug_assert!(
            self.kept <= self.records_in,
            "kept ({}) must never exceed records_in ({}): RecordsDropped is their difference",
            self.kept,
            self.records_in
        );
        metrics.add_records_in(self.records_in);
        metrics.add_records_kept(self.kept);
        metrics.add_records_dropped(self.records_in - self.kept);
        metrics.add_parse_errors(self.parse_errors);
        for (rule_idx, n) in &self.rule_drops {
            metrics.record_rule_drops(engine.rule_name(*rule_idx), *n);
        }
    }
}
