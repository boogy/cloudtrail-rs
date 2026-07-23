//! Error types for the ports defined in `ports.rs`.

use thiserror::Error;

/// Failure decoding a raw event payload into `SourceItem`s.
#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("failed to decode event payload: {0}")]
    InvalidPayload(String),
}

/// Failure performing an `ObjectStore` operation.
///
/// `NotFound` is a distinct variant (not folded into a generic error) because
/// `on_missing_object` policy dispatches on it specifically.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("object not found: {bucket}/{key}")]
    NotFound { bucket: String, key: String },
    #[error("object store operation failed: {0}")]
    Backend(String),
}

/// Failure performing a `ConfigSource` operation, or parsing/compiling what
/// it returned.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config source operation failed: {0}")]
    Source(String),
    #[error("failed to parse config: {0}")]
    Parse(String),
}

/// The pipeline/process error type: what `buffer_run`/`stream_run`/
/// `Pipeline::handle` return on failure. Carries a `StoreError` and a
/// `ConfigError` without losing the `NotFound` distinction (Task 14
/// dispatches `on_missing_object` off `CoreError::Store(StoreError::NotFound
/// { .. })`), plus the data-error cases (`SHARED.md`: bad gzip, bad JSON, an
/// object too large to buffer) that only arrive with the processors.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("failed to decompress gzip: {0}")]
    Gzip(String),
    #[error("failed to parse JSON: {0}")]
    Json(String),
    #[error(
        "decompressed object exceeds max_object_bytes ({limit} bytes): buffer mode refuses to \
         keep reading rather than risk OOM on an oversized or bomb-like object"
    )]
    ObjectTooLarge { limit: u64 },
    /// Failure decoding the raw Lambda event payload itself (`Pipeline::handle`'s
    /// first step) — distinct from a per-object data error, since it means no
    /// `SourceItem`s could be extracted at all.
    #[error("failed to decode event payload: {0}")]
    Decode(#[from] DecodeError),
    /// Safety invariant (`SHARED.md` #1): the computed destination
    /// `(bucket, key)` equals the source `(bucket, key)`. Refusing to write
    /// here is what stops an infinite self-triggering loop that would
    /// otherwise bill until someone notices.
    #[error(
        "destination ({dest_bucket}/{dest_key}) equals source: refusing to process to avoid an infinite self-triggering loop"
    )]
    SelfTrigger {
        dest_bucket: String,
        dest_key: String,
    },
    /// `behavior.on_unrecognized_object == error`: the object parsed as JSON
    /// but had no `Records` array, and the configured policy is to fail
    /// rather than copy or skip it.
    #[error("unrecognized object shape ({bucket}/{key}): on_unrecognized_object is 'error'")]
    UnrecognizedObject { bucket: String, key: String },
}
