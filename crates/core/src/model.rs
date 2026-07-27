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
/// `decode_error` is `Some(_)` when the message's own body failed to
/// decode (e.g. a garbage SQS message body): `objects` is then always
/// empty, and the pipeline must not silently ack the message — see
/// `SourceItem::undecodable`.
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

    /// A message whose body failed to decode: no objects were extracted,
    /// and `error` records why — so the pipeline can fail this item's
    /// `ack_id` instead of silently dropping it (which would ack a message
    /// whose referenced object, if any, is never processed).
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
    pub unrecognized_objects: u64,
    pub records_in: u64,
    pub records_kept: u64,
    pub records_dropped: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub config_load_errors: u64,
    pub parse_errors: u64,
    pub decode_errors: u64,
    /// Items that decoded cleanly but carried zero objects. Not inherently
    /// an error: a legitimate `s3:TestEvent` delivered via SQS trips this
    /// once when the notification config is first saved. Treat it as an
    /// alarm signal — a *sustained* nonzero rate usually means
    /// `sqs.body_format` is misconfigured against what the queue actually
    /// carries, discarding every message with a clean ack and no other
    /// evidence.
    pub items_without_objects: u64,
    pub rule_drops: Vec<(String, u64)>,
}
