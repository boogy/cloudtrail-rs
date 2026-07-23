//! Test doubles for the ports in `ports.rs`, gated behind the `testing`
//! feature so they never ship in a Lambda binary. `StaticConfigSource` and
//! `RecordingSink` arrived with task-12; `InMemoryStore` arrives here
//! (task-13), needed to assert what `stream_run` leaves at a destination key.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::AsyncReadExt;

use crate::error::{ConfigError, StoreError};
use crate::model::{MetricSnapshot, PutMeta, VersionTag};
use crate::ports::{ConfigSource, MetricsSink, ObjectStore};

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

/// An in-memory `ObjectStore`: `get`/`put` against a `Mutex<HashMap>` keyed
/// by `(bucket, key)`, plus `put_stream` accumulating the body it is handed
/// so a `stream_run` test can assert exactly what landed at a destination
/// key — including "nothing", when the upload was aborted.
///
/// `put_stream` treats an `Err` from the body reader as the abort signal
/// (how the abort is triggered without a new port method):
/// on `Err`, it returns `Err` itself *without* inserting into `objects`, so
/// the destination key is left holding whatever it held before the call
/// (nothing, for a fresh key) — simulating `AbortMultipartUpload` leaving no
/// object behind.
///
/// `put_stream_progress()` reports cumulative bytes read so far by the
/// *most recent* `put_stream` call (reset to 0 at the start of each call) —
/// a live progress counter a concurrently-polling test can sample to prove
/// the store started receiving bytes before the producer finished, i.e.
/// that the two sides are actually pipelined rather than "buffer everything,
/// then write everything".
#[derive(Default)]
pub struct InMemoryStore {
    objects: Mutex<HashMap<(String, String), Bytes>>,
    put_stream_progress: AtomicU64,
    read_calls: AtomicUsize,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seeds `bucket`/`key` with `bytes`, as if a prior `put` had written it.
    pub fn seed(&self, bucket: &str, key: &str, bytes: impl Into<Bytes>) {
        self.objects
            .lock()
            .expect("InMemoryStore mutex poisoned")
            .insert((bucket.to_string(), key.to_string()), bytes.into());
    }

    /// The bytes currently held at `bucket`/`key`, if any.
    pub fn object(&self, bucket: &str, key: &str) -> Option<Bytes> {
        self.objects
            .lock()
            .expect("InMemoryStore mutex poisoned")
            .get(&(bucket.to_string(), key.to_string()))
            .cloned()
    }

    /// Whether `bucket`/`key` holds anything at all.
    pub fn contains(&self, bucket: &str, key: &str) -> bool {
        self.objects
            .lock()
            .expect("InMemoryStore mutex poisoned")
            .contains_key(&(bucket.to_string(), key.to_string()))
    }

    /// Cumulative bytes read so far by the most recent `put_stream` call.
    pub fn put_stream_progress(&self) -> u64 {
        self.put_stream_progress.load(Ordering::SeqCst)
    }

    /// Number of `get()` calls made so far — including the internal `get()`
    /// that `get_stream()`'s default-ish implementation delegates to here,
    /// so e.g. "one `get_stream()` plus one re-fetch `get()`" reads as 2.
    pub fn read_calls(&self) -> usize {
        self.read_calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ObjectStore for InMemoryStore {
    async fn get(&self, b: &str, k: &str) -> Result<Bytes, StoreError> {
        self.read_calls.fetch_add(1, Ordering::SeqCst);
        self.object(b, k).ok_or_else(|| StoreError::NotFound {
            bucket: b.to_string(),
            key: k.to_string(),
        })
    }

    async fn get_stream(
        &self,
        b: &str,
        k: &str,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, StoreError> {
        let bytes = self.get(b, k).await?;
        Ok(Box::new(std::io::Cursor::new(bytes)))
    }

    async fn put(&self, b: &str, k: &str, body: Bytes, _meta: PutMeta) -> Result<(), StoreError> {
        self.objects
            .lock()
            .expect("InMemoryStore mutex poisoned")
            .insert((b.to_string(), k.to_string()), body);
        Ok(())
    }

    async fn put_stream(
        &self,
        b: &str,
        k: &str,
        mut body: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        _meta: PutMeta,
    ) -> Result<(), StoreError> {
        self.put_stream_progress.store(0, Ordering::SeqCst);
        let mut buf = Vec::new();
        let mut chunk = [0u8; 64 * 1024];
        loop {
            match body.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    self.put_stream_progress
                        .fetch_add(n as u64, Ordering::SeqCst);
                }
                Err(e) => {
                    // The reader failed mid-stream: simulate
                    // AbortMultipartUpload by leaving the destination
                    // untouched instead of committing a partial object.
                    return Err(StoreError::Backend(format!(
                        "put_stream aborted after {} bytes: {e}",
                        buf.len()
                    )));
                }
            }
        }
        self.objects
            .lock()
            .expect("InMemoryStore mutex poisoned")
            .insert((b.to_string(), k.to_string()), Bytes::from(buf));
        Ok(())
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

    fn no_meta() -> PutMeta {
        PutMeta {
            content_type: "application/json",
            content_encoding: "gzip",
        }
    }

    #[tokio::test]
    async fn put_then_get_round_trips_the_exact_bytes() {
        let store = InMemoryStore::new();
        store
            .put("bucket", "key", Bytes::from_static(b"hello"), no_meta())
            .await
            .unwrap();
        assert_eq!(store.get("bucket", "key").await.unwrap(), "hello");
    }

    #[tokio::test]
    async fn get_on_a_missing_key_is_not_found() {
        let store = InMemoryStore::new();
        let err = store.get("bucket", "missing").await.unwrap_err();
        assert!(matches!(err, StoreError::NotFound { .. }), "got {err:?}");
    }

    #[tokio::test]
    async fn put_stream_captures_the_full_body_at_the_destination_key() {
        let store = InMemoryStore::new();
        let body: Box<dyn tokio::io::AsyncRead + Send + Unpin> =
            Box::new(std::io::Cursor::new(Bytes::from_static(b"streamed body")));
        store
            .put_stream("bucket", "dest", body, no_meta())
            .await
            .unwrap();
        assert_eq!(
            store.object("bucket", "dest"),
            Some(Bytes::from_static(b"streamed body"))
        );
    }

    /// An `AsyncRead` whose one and only `poll_read` call reports an error —
    /// the abort-triggering shape `stream_run` needs (how the
    /// abort is triggered without a new port method).
    struct FailingReader;

    impl tokio::io::AsyncRead for FailingReader {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::Error::other("simulated abort")))
        }
    }

    #[tokio::test]
    async fn put_stream_leaves_the_destination_key_empty_when_the_reader_fails() {
        let store = InMemoryStore::new();
        let body: Box<dyn tokio::io::AsyncRead + Send + Unpin> = Box::new(FailingReader);
        let err = store
            .put_stream("bucket", "dest", body, no_meta())
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Backend(_)), "got {err:?}");
        assert!(
            !store.contains("bucket", "dest"),
            "an aborted put_stream must leave the destination key holding nothing"
        );
    }
}
