//! Plain data types shared across ports and the pipeline.

/// A single S3 object referenced by a decoded event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectRef {
    pub bucket: String,
    pub key: String,
    pub size: Option<u64>,
}

/// One decoded unit of work: zero or more objects to process, plus the
/// upstream ack token (if any) needed to report partial batch failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceItem {
    pub ack_id: Option<String>,
    pub objects: Vec<ObjectRef>,
}

/// Metadata attached to an `ObjectStore::put`/`put_stream` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PutMeta {
    pub content_type: &'static str,
    pub content_encoding: &'static str,
}

/// Opaque version marker for a config source, used to detect changes
/// without always re-fetching the full body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionTag {
    Etag(String),
    Version(i64),
    Mtime(u64),
    None,
}

/// A point-in-time delta of `Metrics`, produced by `Metrics::snapshot_and_reset`
/// and consumed by `MetricsSink::emit`. Plain data: no atomics, no locks.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MetricSnapshot {
    pub cold_start: bool,
    pub config_load_errors: u64,
    pub rule_drops: Vec<(String, u64)>,
}
