//! Error types for the ports defined in `ports.rs`.

use thiserror::Error;

/// Failure decoding a raw event payload into `SourceItem`s.
#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("failed to decode event payload: {0}")]
    InvalidPayload(String),
}

/// Failure performing an `ObjectStore` operation. `NotFound` is distinct
/// because `on_missing_object` dispatches on it.
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

/// What `buffer_run`/`stream_run`/`Pipeline::handle` return on failure.
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
        "object exceeds max_object_bytes ({limit} bytes), compressed or decompressed: buffer \
         mode refuses to keep reading rather than risk OOM on an oversized or bomb-like object"
    )]
    ObjectTooLarge { limit: u64 },
    /// Failure decoding the raw event payload: no `SourceItem`s at all.
    #[error("failed to decode event payload: {0}")]
    Decode(#[from] DecodeError),
    /// Safety invariant #1: destination `(bucket, key)` equals the source's.
    /// Refusing the write is what stops an infinite self-trigger loop.
    #[error(
        "destination ({dest_bucket}/{dest_key}) equals source: refusing to process to avoid an infinite self-triggering loop"
    )]
    SelfTrigger {
        dest_bucket: String,
        dest_key: String,
    },
    /// The object parsed as JSON but had no `Records` array, under
    /// `behavior.on_unrecognized_object = error`.
    #[error("unrecognized object shape ({bucket}/{key}): on_unrecognized_object is 'error'")]
    UnrecognizedObject { bucket: String, key: String },
}
