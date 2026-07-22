//! `Metrics`: the process-lived atomic counters behind `MetricSnapshot`, and
//! the two production `MetricsSink` impls (`EmfMetricsSink`, `NoopMetricsSink`).
//! `RecordingSink`, the test double, lives in `testing.rs`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::model::MetricSnapshot;
use crate::ports::MetricsSink;

/// Process-lived atomic counters. Held behind an `Arc` and shared across
/// invocations (`ConfigStore` keeps one), so every field must be safe to
/// mutate from concurrent handler tasks without a lock — except `rule_drops`,
/// whose key set is unbounded and dynamic, so it gets a `Mutex<HashMap<..>>`.
///
/// `snapshot_and_reset` swaps every counter back to zero as it reads it, so
/// the `MetricSnapshot` it returns is a delta since the previous call, not a
/// running total.
#[derive(Default)]
pub struct Metrics {
    cold_start_emitted: AtomicBool,
    objects_processed: AtomicU64,
    objects_skipped: AtomicU64,
    unrecognized_objects: AtomicU64,
    records_in: AtomicU64,
    records_kept: AtomicU64,
    records_dropped: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    config_load_errors: AtomicU64,
    parse_errors: AtomicU64,
    rule_drops: Mutex<HashMap<String, u64>>,
}

impl Metrics {
    pub fn add_objects_processed(&self, n: u64) {
        self.objects_processed.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_objects_skipped(&self, n: u64) {
        self.objects_skipped.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_unrecognized_objects(&self, n: u64) {
        self.unrecognized_objects.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_records_in(&self, n: u64) {
        self.records_in.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_records_kept(&self, n: u64) {
        self.records_kept.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_records_dropped(&self, n: u64) {
        self.records_dropped.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_bytes_in(&self, n: u64) {
        self.bytes_in.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_bytes_out(&self, n: u64) {
        self.bytes_out.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_config_load_errors(&self, n: u64) {
        self.config_load_errors.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_parse_errors(&self, n: u64) {
        self.parse_errors.fetch_add(n, Ordering::Relaxed);
    }

    /// Records one dropped record attributed to `rule_name` (the `RuleDrops`
    /// metric's `Rule` dimension).
    pub fn record_rule_drop(&self, rule_name: &str) {
        let mut rule_drops = self.rule_drops.lock().expect("Metrics mutex poisoned");
        *rule_drops.entry(rule_name.to_string()).or_insert(0) += 1;
    }

    /// Reads every counter and resets it to zero, returning the delta since
    /// the previous call as a plain `MetricSnapshot`. `cold_start` is `true`
    /// only on the very first call this process makes.
    pub fn snapshot_and_reset(&self) -> MetricSnapshot {
        let cold_start = !self.cold_start_emitted.swap(true, Ordering::SeqCst);

        let mut rule_drops: Vec<(String, u64)> = self
            .rule_drops
            .lock()
            .expect("Metrics mutex poisoned")
            .drain()
            .collect();
        rule_drops.sort();

        MetricSnapshot {
            cold_start,
            objects_processed: self.objects_processed.swap(0, Ordering::Relaxed),
            objects_skipped: self.objects_skipped.swap(0, Ordering::Relaxed),
            unrecognized_objects: self.unrecognized_objects.swap(0, Ordering::Relaxed),
            records_in: self.records_in.swap(0, Ordering::Relaxed),
            records_kept: self.records_kept.swap(0, Ordering::Relaxed),
            records_dropped: self.records_dropped.swap(0, Ordering::Relaxed),
            bytes_in: self.bytes_in.swap(0, Ordering::Relaxed),
            bytes_out: self.bytes_out.swap(0, Ordering::Relaxed),
            config_load_errors: self.config_load_errors.swap(0, Ordering::Relaxed),
            parse_errors: self.parse_errors.swap(0, Ordering::Relaxed),
            rule_drops,
        }
    }
}

/// Used when `observability.metrics == none`: discards every snapshot.
pub struct NoopMetricsSink;

impl MetricsSink for NoopMetricsSink {
    fn emit(&self, _snapshot: &MetricSnapshot) {}
}

/// Emits `MetricSnapshot`s as CloudWatch embedded metric format (EMF) JSON
/// lines on stdout — no AWS SDK involved, CloudWatch Logs picks EMF lines up
/// from whatever ships the Lambda log stream.
pub struct EmfMetricsSink {
    namespace: String,
}

impl EmfMetricsSink {
    pub fn new(namespace: String) -> Self {
        Self { namespace }
    }

    fn timestamp_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Builds the JSON documents `emit` prints, one per line: one aggregate
    /// line covering every counter except `RuleDrops`, plus one additional
    /// line per rule that dropped records this invocation.
    ///
    /// A single flat EMF document can only hold one value per dimension name,
    /// so `Rule` can't vary across entries within one line — a second rule
    /// dropping records needs its own line to keep both counts visible. With
    /// zero or one rule dropping records (the common case), this is exactly
    /// the one line `emit` promises.
    fn build_lines(&self, snapshot: &MetricSnapshot) -> Vec<Value> {
        let timestamp = Self::timestamp_millis();

        let mut lines = vec![json!({
            "_aws": {
                "Timestamp": timestamp,
                "CloudWatchMetrics": [{
                    "Namespace": self.namespace,
                    "Dimensions": [[]],
                    "Metrics": [
                        {"Name": "ObjectsProcessed", "Unit": "Count"},
                        {"Name": "ObjectsSkipped", "Unit": "Count"},
                        {"Name": "UnrecognizedObjects", "Unit": "Count"},
                        {"Name": "RecordsIn", "Unit": "Count"},
                        {"Name": "RecordsKept", "Unit": "Count"},
                        {"Name": "RecordsDropped", "Unit": "Count"},
                        {"Name": "BytesIn", "Unit": "Bytes"},
                        {"Name": "BytesOut", "Unit": "Bytes"},
                        {"Name": "ConfigLoadErrors", "Unit": "Count"},
                        {"Name": "ParseErrors", "Unit": "Count"},
                        {"Name": "ColdStart", "Unit": "Count"}
                    ]
                }]
            },
            "ObjectsProcessed": snapshot.objects_processed,
            "ObjectsSkipped": snapshot.objects_skipped,
            "UnrecognizedObjects": snapshot.unrecognized_objects,
            "RecordsIn": snapshot.records_in,
            "RecordsKept": snapshot.records_kept,
            "RecordsDropped": snapshot.records_dropped,
            "BytesIn": snapshot.bytes_in,
            "BytesOut": snapshot.bytes_out,
            "ConfigLoadErrors": snapshot.config_load_errors,
            "ParseErrors": snapshot.parse_errors,
            "ColdStart": u8::from(snapshot.cold_start)
        })];

        for (rule, count) in &snapshot.rule_drops {
            lines.push(json!({
                "_aws": {
                    "Timestamp": timestamp,
                    "CloudWatchMetrics": [{
                        "Namespace": self.namespace,
                        "Dimensions": [["Rule"]],
                        "Metrics": [
                            {"Name": "RuleDrops", "Unit": "Count"}
                        ]
                    }]
                },
                "Rule": rule,
                "RuleDrops": count
            }));
        }

        lines
    }
}

impl MetricsSink for EmfMetricsSink {
    fn emit(&self, snapshot: &MetricSnapshot) {
        for line in self.build_lines(snapshot) {
            println!("{line}");
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::metrics::{EmfMetricsSink, Metrics, NoopMetricsSink};
    use crate::model::MetricSnapshot;
    use crate::ports::MetricsSink;
    use serde_json::json;

    #[test]
    fn default_metrics_snapshot_is_all_zero_except_cold_start() {
        let metrics = Metrics::default();
        let snapshot = metrics.snapshot_and_reset();
        assert_eq!(
            snapshot,
            MetricSnapshot {
                cold_start: true,
                ..Default::default()
            }
        );
    }

    #[test]
    fn cold_start_is_true_on_first_snapshot_and_false_after() {
        let metrics = Metrics::default();
        assert!(metrics.snapshot_and_reset().cold_start);
        assert!(!metrics.snapshot_and_reset().cold_start);
        assert!(!metrics.snapshot_and_reset().cold_start);
    }

    #[test]
    fn snapshot_and_reset_returns_a_delta_not_a_running_total() {
        let metrics = Metrics::default();
        metrics.add_records_in(5);
        metrics.add_bytes_in(1000);
        let first = metrics.snapshot_and_reset();
        assert_eq!(first.records_in, 5);
        assert_eq!(first.bytes_in, 1000);

        metrics.add_records_in(3);
        let second = metrics.snapshot_and_reset();
        assert_eq!(second.records_in, 3, "must be a delta, not cumulative");
        assert_eq!(second.bytes_in, 0);
    }

    #[test]
    fn every_counter_is_independently_tracked() {
        let metrics = Metrics::default();
        metrics.add_objects_processed(1);
        metrics.add_objects_skipped(2);
        metrics.add_unrecognized_objects(3);
        metrics.add_records_in(4);
        metrics.add_records_kept(5);
        metrics.add_records_dropped(6);
        metrics.add_bytes_in(7);
        metrics.add_bytes_out(8);
        metrics.add_config_load_errors(9);
        metrics.add_parse_errors(10);

        let snapshot = metrics.snapshot_and_reset();
        assert_eq!(
            snapshot,
            MetricSnapshot {
                cold_start: true,
                objects_processed: 1,
                objects_skipped: 2,
                unrecognized_objects: 3,
                records_in: 4,
                records_kept: 5,
                records_dropped: 6,
                bytes_in: 7,
                bytes_out: 8,
                config_load_errors: 9,
                parse_errors: 10,
                rule_drops: vec![],
            }
        );
    }

    #[test]
    fn rule_drops_are_recorded_per_rule_and_reset_after_snapshot() {
        let metrics = Metrics::default();
        metrics.record_rule_drop("block-kms-decrypt");
        metrics.record_rule_drop("block-kms-decrypt");
        metrics.record_rule_drop("allow-console-noise");

        let mut rule_drops = metrics.snapshot_and_reset().rule_drops;
        rule_drops.sort();
        assert_eq!(
            rule_drops,
            vec![
                ("allow-console-noise".to_string(), 1),
                ("block-kms-decrypt".to_string(), 2),
            ]
        );

        assert!(metrics.snapshot_and_reset().rule_drops.is_empty());
    }

    #[test]
    fn noop_metrics_sink_discards_snapshots_without_panicking() {
        let sink = NoopMetricsSink;
        sink.emit(&MetricSnapshot::default());
    }

    #[test]
    fn emf_sink_emits_one_line_with_the_correct_cloudwatch_metrics_structure() {
        let sink = EmfMetricsSink::new("cloudtrail-rs".to_string());
        let snapshot = MetricSnapshot {
            cold_start: true,
            objects_processed: 10,
            objects_skipped: 2,
            unrecognized_objects: 1,
            records_in: 100,
            records_kept: 90,
            records_dropped: 10,
            bytes_in: 5000,
            bytes_out: 4500,
            config_load_errors: 0,
            parse_errors: 3,
            rule_drops: vec![],
        };

        let lines = sink.build_lines(&snapshot);
        assert_eq!(lines.len(), 1, "no rule drops => exactly one EMF line");

        let timestamp = lines[0]["_aws"]["Timestamp"].clone();
        assert_eq!(
            lines[0],
            json!({
                "_aws": {
                    "Timestamp": timestamp,
                    "CloudWatchMetrics": [{
                        "Namespace": "cloudtrail-rs",
                        "Dimensions": [[]],
                        "Metrics": [
                            {"Name": "ObjectsProcessed", "Unit": "Count"},
                            {"Name": "ObjectsSkipped", "Unit": "Count"},
                            {"Name": "UnrecognizedObjects", "Unit": "Count"},
                            {"Name": "RecordsIn", "Unit": "Count"},
                            {"Name": "RecordsKept", "Unit": "Count"},
                            {"Name": "RecordsDropped", "Unit": "Count"},
                            {"Name": "BytesIn", "Unit": "Bytes"},
                            {"Name": "BytesOut", "Unit": "Bytes"},
                            {"Name": "ConfigLoadErrors", "Unit": "Count"},
                            {"Name": "ParseErrors", "Unit": "Count"},
                            {"Name": "ColdStart", "Unit": "Count"}
                        ]
                    }]
                },
                "ObjectsProcessed": 10,
                "ObjectsSkipped": 2,
                "UnrecognizedObjects": 1,
                "RecordsIn": 100,
                "RecordsKept": 90,
                "RecordsDropped": 10,
                "BytesIn": 5000,
                "BytesOut": 4500,
                "ConfigLoadErrors": 0,
                "ParseErrors": 3,
                "ColdStart": 1
            })
        );
    }

    #[test]
    fn emf_sink_emits_one_additional_line_per_rule_with_a_rule_dimension() {
        let sink = EmfMetricsSink::new("cloudtrail-rs".to_string());
        let snapshot = MetricSnapshot {
            rule_drops: vec![("block-kms-decrypt".to_string(), 3)],
            ..Default::default()
        };

        let lines = sink.build_lines(&snapshot);
        assert_eq!(lines.len(), 2);

        let timestamp = lines[1]["_aws"]["Timestamp"].clone();
        assert_eq!(
            lines[1],
            json!({
                "_aws": {
                    "Timestamp": timestamp,
                    "CloudWatchMetrics": [{
                        "Namespace": "cloudtrail-rs",
                        "Dimensions": [["Rule"]],
                        "Metrics": [
                            {"Name": "RuleDrops", "Unit": "Count"}
                        ]
                    }]
                },
                "Rule": "block-kms-decrypt",
                "RuleDrops": 3
            })
        );
    }

    #[test]
    fn emf_sink_emits_independent_deltas_across_two_invocations() {
        let metrics = Metrics::default();
        let sink = EmfMetricsSink::new("cloudtrail-rs".to_string());

        metrics.add_records_in(5);
        let first = metrics.snapshot_and_reset();
        sink.emit(&first);
        assert_eq!(first.records_in, 5);

        metrics.add_records_in(2);
        let second = metrics.snapshot_and_reset();
        sink.emit(&second);
        assert_eq!(
            second.records_in, 2,
            "second emit must not include the first's count"
        );
    }
}
