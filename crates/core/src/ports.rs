//! The four ports `cloudtrail-rs-core` depends on. Production adapters live
//! in `cloudtrail-rs-aws` and the lambda binaries' decoders; test adapters
//! live in `testing.rs`.

use crate::error::{ConfigError, DecodeError, StoreError};
use crate::model::{MetricSnapshot, PutMeta, SourceItem, VersionTag};
use async_trait::async_trait;
use bytes::Bytes;

/// Decodes a raw Lambda event payload (S3/SQS/SNS/EventBridge, one per
/// compiled binary) into the objects it references.
pub trait EventDecoder: Send + Sync {
    fn decode(&self, payload: &[u8]) -> Result<Vec<SourceItem>, DecodeError>;
}

/// Reads and writes the objects a `SourceItem` points at.
#[async_trait]
pub trait ObjectStore: Send + Sync {
    async fn get(&self, b: &str, k: &str) -> Result<Bytes, StoreError>;
    async fn get_stream(
        &self,
        b: &str,
        k: &str,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, StoreError>;
    async fn put(&self, b: &str, k: &str, body: Bytes, meta: PutMeta) -> Result<(), StoreError>;
    async fn put_stream(
        &self,
        b: &str,
        k: &str,
        body: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        meta: PutMeta,
    ) -> Result<(), StoreError>;
}

/// Fetches the exclusion rules document and lets a `ConfigStore` cheaply
/// check whether it has changed since the last fetch.
#[async_trait]
pub trait ConfigSource: Send + Sync {
    async fn version(&self) -> Result<VersionTag, ConfigError>;
    async fn fetch(&self) -> Result<(Vec<u8>, VersionTag), ConfigError>;
}

/// Emits a `MetricSnapshot` to wherever metrics go (EMF logs, or nowhere).
pub trait MetricsSink: Send + Sync {
    fn emit(&self, snapshot: &MetricSnapshot);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // Throwaway implementations whose only purpose is to prove each trait
    // is object-safe (`Arc<dyn Trait>` compiles and is callable) across
    // every method, including the `Box<dyn AsyncRead>` ones.

    struct NullDecoder;
    impl EventDecoder for NullDecoder {
        fn decode(&self, _payload: &[u8]) -> Result<Vec<SourceItem>, DecodeError> {
            Ok(Vec::new())
        }
    }

    struct NullStore;
    #[async_trait]
    impl ObjectStore for NullStore {
        async fn get(&self, _b: &str, _k: &str) -> Result<Bytes, StoreError> {
            Ok(Bytes::new())
        }
        async fn get_stream(
            &self,
            _b: &str,
            _k: &str,
        ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, StoreError> {
            Ok(Box::new(tokio::io::empty()))
        }
        async fn put(
            &self,
            _b: &str,
            _k: &str,
            _body: Bytes,
            _meta: PutMeta,
        ) -> Result<(), StoreError> {
            Ok(())
        }
        async fn put_stream(
            &self,
            _b: &str,
            _k: &str,
            _body: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
            _meta: PutMeta,
        ) -> Result<(), StoreError> {
            Ok(())
        }
    }

    struct NullConfigSource;
    #[async_trait]
    impl ConfigSource for NullConfigSource {
        async fn version(&self) -> Result<VersionTag, ConfigError> {
            Ok(VersionTag::None)
        }
        async fn fetch(&self) -> Result<(Vec<u8>, VersionTag), ConfigError> {
            Ok((Vec::new(), VersionTag::None))
        }
    }

    struct NullSink;
    impl MetricsSink for NullSink {
        fn emit(&self, _snapshot: &MetricSnapshot) {}
    }

    #[test]
    fn event_decoder_is_object_safe() {
        let d: Arc<dyn EventDecoder> = Arc::new(NullDecoder);
        assert!(d.decode(b"{}").is_ok());
    }

    #[tokio::test]
    async fn object_store_is_object_safe() {
        let s: Arc<dyn ObjectStore> = Arc::new(NullStore);
        assert!(s.get("bucket", "key").await.is_ok());
        assert!(s.get_stream("bucket", "key").await.is_ok());

        let meta = PutMeta {
            content_type: "application/json",
            content_encoding: "gzip",
        };
        assert!(s.put("bucket", "key", Bytes::new(), meta).await.is_ok());
        assert!(
            s.put_stream("bucket", "key", Box::new(tokio::io::empty()), meta)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn config_source_is_object_safe() {
        let c: Arc<dyn ConfigSource> = Arc::new(NullConfigSource);
        assert!(c.version().await.is_ok());
        assert!(c.fetch().await.is_ok());
    }

    #[test]
    fn metrics_sink_is_object_safe() {
        let sink: Arc<dyn MetricsSink> = Arc::new(NullSink);
        sink.emit(&MetricSnapshot::default());
    }
}
