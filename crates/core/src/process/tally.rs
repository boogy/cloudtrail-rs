//! Per-object record counters, tallied while an object is processed and
//! published only once its fate is decided.
//!
//! Both modes evaluate records long before they know whether the object will
//! survive: buffer mode still has to `put` what it produced, stream mode still
//! has to wait for `put_stream` to complete the multipart upload. Anything
//! either one learns about a record — that it arrived, that a rule dropped it,
//! that it would not parse — is therefore *observed* mid-flight but is not
//! *true* until the object finishes, because a failed object is re-driven and
//! re-evaluated whole.
//!
//! `RecordTally` is where that observation is held. It touches no `Metrics`
//! until [`RecordTally::commit`], which the caller invokes only on the far
//! side of the write. That keeps the counters describing objects that were
//! actually accounted for, which is what makes `RecordsIn == RecordsKept +
//! RecordsDropped` and `sum(RuleDrops) <= RecordsDropped` hold — the two
//! identities `docs/metrics.md` tells an operator to alarm on.
//!
//! One type shared by both modes rather than one per mode: the buffer/stream
//! parity invariant requires they agree on every counter, and two
//! implementations of the same arithmetic are two chances to disagree.

use std::collections::HashMap;

use crate::filter::Engine;
use crate::metrics::Metrics;

/// One object's record counters, held until the object's fate is known.
///
/// Built incrementally by `buffer_run`/`stream_run`, then published as one
/// unit by [`RecordTally::commit`]. Rule drops are keyed by `rule_idx` rather
/// than rule name so the streaming loop never touches the `Engine`'s name
/// table or the `RuleDrops` mutex per record.
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

    /// The record could not be parsed into a `Value`. Never implies a drop:
    /// an unparseable individual record is *kept*, only counted — the caller
    /// still calls [`RecordTally::keep`] for it.
    pub(crate) fn parse_error(&mut self) {
        self.parse_errors += 1;
    }

    /// How many records survived so far. Stream mode branches on this to tell
    /// "every record dropped" (abort the upload, write nothing) from "there is
    /// an object worth committing".
    pub(crate) fn kept_count(&self) -> u64 {
        self.kept
    }

    /// Publishes every counter to `metrics` as one unit.
    ///
    /// Call this **only** once the object's fate is decided: after the write
    /// returns for an object that was written, or on a path that deliberately
    /// writes nothing (all records dropped, dry run). An object that failed —
    /// including one whose upload failed after its last record was evaluated —
    /// must drop its tally uncommitted and let the redelivery re-count it.
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
