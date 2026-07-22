//! Test doubles for the ports in `ports.rs`, gated behind the `testing`
//! feature so they never ship in a Lambda binary. `InMemoryStore` and
//! `StaticConfigSource` arrive with the tasks that need them; this task adds
//! `RecordingSink`.

use std::sync::Mutex;

use crate::model::MetricSnapshot;
use crate::ports::MetricsSink;

/// Records every `MetricSnapshot` passed to `emit`, in order. Lets a test
/// assert what a pipeline actually reported without parsing EMF off stdout.
#[derive(Default)]
pub struct RecordingSink {
    snapshots: Mutex<Vec<MetricSnapshot>>,
}

impl RecordingSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// All snapshots recorded so far, in emission order.
    pub fn snapshots(&self) -> Vec<MetricSnapshot> {
        self.snapshots
            .lock()
            .expect("RecordingSink mutex poisoned")
            .clone()
    }
}

impl MetricsSink for RecordingSink {
    fn emit(&self, snapshot: &MetricSnapshot) {
        self.snapshots
            .lock()
            .expect("RecordingSink mutex poisoned")
            .push(snapshot.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_sink_records_snapshots_in_emission_order() {
        let sink = RecordingSink::new();
        let a = MetricSnapshot {
            records_in: 1,
            ..Default::default()
        };
        let b = MetricSnapshot {
            records_in: 2,
            ..Default::default()
        };

        sink.emit(&a);
        sink.emit(&b);

        assert_eq!(sink.snapshots(), vec![a, b]);
    }
}
