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
