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
    /// The *source* object's own bytes would not inflate. Only this and
    /// [`CoreError::Json`] are what `on_parse_error: copy` fails open on.
    #[error("failed to decompress gzip: {0}")]
    Gzip(String),
    /// The *source* object's own bytes are not JSON.
    #[error("failed to parse JSON: {0}")]
    Json(String),
    /// Producing the output failed, or a worker task panicked. Never a verdict
    /// on the source bytes, so `on_parse_error: copy` must not fail open on it:
    /// the object may already have been filtered, and copying it verbatim would
    /// forward the dropped records.
    #[error("internal processing failure: {0}")]
    Internal(String),
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

impl CoreError {
    /// Whether this is the *source* object's own bytes failing to parse — the
    /// only class `behavior.on_parse_error: copy` may fail open on.
    ///
    /// `Internal` is excluded deliberately: the object may already have been
    /// decompressed, parsed and filtered, so copying its source verbatim would
    /// forward every record the rules dropped. `Store` must retry and
    /// `ObjectTooLarge` is `on_object_too_large`'s business.
    pub fn is_unparsable_source(&self) -> bool {
        matches!(self, CoreError::Gzip(_) | CoreError::Json(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Falsifiable: admit `Internal` here and a compression or worker-task
    /// failure on a filtered object makes `on_parse_error: copy` write the
    /// unfiltered source to the destination.
    #[test]
    fn only_source_side_parse_failures_are_unparsable_sources() {
        assert!(CoreError::Gzip("bad source".into()).is_unparsable_source());
        assert!(CoreError::Json("bad source".into()).is_unparsable_source());

        assert!(!CoreError::Internal("worker panicked".into()).is_unparsable_source());
        assert!(!CoreError::ObjectTooLarge { limit: 1 }.is_unparsable_source());
        assert!(
            !CoreError::Store(StoreError::NotFound {
                bucket: "b".into(),
                key: "k".into(),
            })
            .is_unparsable_source()
        );
    }
}
