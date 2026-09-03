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
///
/// `decode_error` is `Some(_)` only for a message whose body failed to
/// decode; `objects` is then always empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceItem {
    pub ack_id: Option<String>,
    pub objects: Vec<ObjectRef>,
    pub decode_error: Option<String>,
}

impl SourceItem {
    /// A cleanly decoded item: zero or more objects, no decode error.
    pub fn new(ack_id: Option<String>, objects: Vec<ObjectRef>) -> Self {
        SourceItem {
            ack_id,
            objects,
            decode_error: None,
        }
    }

    /// A message whose body failed to decode, so the pipeline can fail this
    /// item's `ack_id` rather than ack it clean.
    pub fn undecodable(ack_id: Option<String>, error: String) -> Self {
        SourceItem {
            ack_id,
            objects: Vec::new(),
            decode_error: Some(error),
        }
    }
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
    pub objects_processed: u64,
    pub objects_skipped: u64,
    /// Objects whose processing returned an error. Under the default
    /// `partial_batch_failures = true` AWS's own `Errors` metric stays at
    /// zero, so this is the only counter that moves.
    pub objects_failed: u64,
    /// Objects excluded by `source.include_key_regex` /
    /// `source.exclude_key_regex`, so never fetched. A rate equal to the
    /// delivery rate means the key filter is rejecting everything.
    pub objects_excluded_by_key: u64,
    pub unrecognized_objects: u64,
    pub objects_copied_unparsed: u64,
    pub records_in: u64,
    pub records_kept: u64,
    pub records_dropped: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub config_load_errors: u64,
    pub parse_errors: u64,
    pub decode_errors: u64,
    /// Items that decoded cleanly but carried zero objects. A sustained
    /// nonzero rate usually means `sqs.body_format` is misconfigured against
    /// what the queue carries, acking every message clean.
    pub items_without_objects: u64,
    pub rule_drops: Vec<(String, u64)>,
}

impl MetricSnapshot {
    /// Whether `records_in == records_kept + records_dropped` — the
    /// reconciliation invariant both processing modes uphold.
    pub fn records_balance(&self) -> bool {
        self.records_in == self.records_kept + self.records_dropped
    }
}
