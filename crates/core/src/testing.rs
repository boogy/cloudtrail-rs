//! Test doubles for the ports in `ports.rs`, gated behind the `testing`
//! feature so they never ship in a Lambda binary. `InMemoryStore` arrives
//! with the task that needs it; this task adds `StaticConfigSource` and
//! `RecordingSink`.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;

use crate::error::ConfigError;
use crate::model::{MetricSnapshot, VersionTag};
use crate::ports::{ConfigSource, MetricsSink};

/// A `ConfigSource` double whose content, version, and failures are all
/// controlled by the test. Counts calls to `version()`/`fetch()` so a
/// `ConfigStore` test can assert exactly how many round trips a scenario
/// costs (e.g. "unchanged past TTL costs one `version()` and zero fetches").
pub struct StaticConfigSource {
    state: Mutex<StaticState>,
    version_calls: AtomicUsize,
    fetch_calls: AtomicUsize,
}

struct StaticState {
    bytes: Vec<u8>,
    version: VersionTag,
    fail_next_version: bool,
    fail_next_fetch: bool,
}

impl Default for StaticConfigSource {
    fn default() -> Self {
        Self::new(Vec::new(), VersionTag::None)
    }
}

impl StaticConfigSource {
    pub fn new(bytes: impl Into<Vec<u8>>, version: VersionTag) -> Self {
        Self {
            state: Mutex::new(StaticState {
                bytes: bytes.into(),
                version,
                fail_next_version: false,
                fail_next_fetch: false,
            }),
            version_calls: AtomicUsize::new(0),
            fetch_calls: AtomicUsize::new(0),
        }
    }

    /// Replaces the content and version an upcoming `fetch()`/`version()`
    /// call will see — simulates the document changing at the source.
    pub fn set(&self, bytes: impl Into<Vec<u8>>, version: VersionTag) {
        let mut state = self.state.lock().expect("StaticConfigSource poisoned");
        state.bytes = bytes.into();
        state.version = version;
    }

    /// Arms a single `ConfigError` for the next `version()` call only.
    pub fn fail_next_version(&self) {
        self.state
            .lock()
            .expect("StaticConfigSource poisoned")
            .fail_next_version = true;
    }

    /// Arms a single `ConfigError` for the next `fetch()` call only.
    pub fn fail_next_fetch(&self) {
        self.state
            .lock()
            .expect("StaticConfigSource poisoned")
            .fail_next_fetch = true;
    }

    pub fn version_calls(&self) -> usize {
        self.version_calls.load(Ordering::SeqCst)
    }

    pub fn fetch_calls(&self) -> usize {
        self.fetch_calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ConfigSource for StaticConfigSource {
    async fn version(&self) -> Result<VersionTag, ConfigError> {
        self.version_calls.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().expect("StaticConfigSource poisoned");
        if state.fail_next_version {
            state.fail_next_version = false;
            return Err(ConfigError::Source(
                "StaticConfigSource: forced version() failure".to_string(),
            ));
        }
        Ok(state.version.clone())
    }

    async fn fetch(&self) -> Result<(Vec<u8>, VersionTag), ConfigError> {
        self.fetch_calls.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().expect("StaticConfigSource poisoned");
        if state.fail_next_fetch {
            state.fail_next_fetch = false;
            return Err(ConfigError::Source(
                "StaticConfigSource: forced fetch() failure".to_string(),
            ));
        }
        Ok((state.bytes.clone(), state.version.clone()))
    }
}

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

    #[tokio::test]
    async fn fetch_returns_configured_bytes_and_version() {
        let src = StaticConfigSource::new(b"a: 1".to_vec(), VersionTag::Version(1));
        let (bytes, version) = src.fetch().await.unwrap();
        assert_eq!(bytes, b"a: 1");
        assert_eq!(version, VersionTag::Version(1));
    }

    #[tokio::test]
    async fn set_replaces_content_seen_by_a_later_fetch() {
        let src = StaticConfigSource::new(b"a: 1".to_vec(), VersionTag::Version(1));
        src.set(b"a: 2".to_vec(), VersionTag::Version(2));
        let (bytes, version) = src.fetch().await.unwrap();
        assert_eq!(bytes, b"a: 2");
        assert_eq!(version, VersionTag::Version(2));
    }

    #[tokio::test]
    async fn fail_next_version_fails_exactly_one_call() {
        let src = StaticConfigSource::new(b"a: 1".to_vec(), VersionTag::Version(1));
        src.fail_next_version();
        assert!(src.version().await.is_err());
        assert!(src.version().await.is_ok());
    }

    #[tokio::test]
    async fn fail_next_fetch_fails_exactly_one_call() {
        let src = StaticConfigSource::new(b"a: 1".to_vec(), VersionTag::Version(1));
        src.fail_next_fetch();
        assert!(src.fetch().await.is_err());
        assert!(src.fetch().await.is_ok());
    }

    #[tokio::test]
    async fn version_and_fetch_calls_are_counted_independently() {
        let src = StaticConfigSource::new(b"a: 1".to_vec(), VersionTag::Version(1));
        assert_eq!(src.version_calls(), 0);
        assert_eq!(src.fetch_calls(), 0);

        src.version().await.unwrap();
        src.version().await.unwrap();
        src.fetch().await.unwrap();

        assert_eq!(src.version_calls(), 2);
        assert_eq!(src.fetch_calls(), 1);
    }

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
