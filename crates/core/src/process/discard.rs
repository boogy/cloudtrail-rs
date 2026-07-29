//! An [`ObjectStore`] that accepts writes and throws them away.
//!
//! `behavior.dry_run` means "evaluate everything, write nothing", and until
//! now that was implemented by refusing to take the stream path at all: dry
//! run always ran buffer mode. That made the one mode meant for a pre-flight
//! check the one mode whose answer could differ from the live run's — an
//! object over `max_object_bytes` failed the dry run with `ObjectTooLarge`
//! while `mode: auto` would have streamed it successfully, so the preview
//! reported a failure the real thing does not have.
//!
//! `stream_run` writes through the [`ObjectStore`] port, so the fix is a
//! destination rather than a second evaluator: run the real stream path
//! against a store that drains its reader and keeps nothing. Two properties
//! make it a faithful stand-in and not merely a silent sink:
//!
//! - it **drains to EOF**, so the producer side runs to completion exactly as
//!   it would against S3 — records are evaluated, the gzip encoder is driven,
//!   `Deserializer::end()` still verifies the trailer;
//! - it **propagates a reader error**, so `stream_run`'s abort sentinel still
//!   fails the "upload". A sink that swallowed it would turn every aborted
//!   object into a successful write in the preview.
//!
//! The caller is responsible for not billing `BytesOut` for what lands here —
//! see `Pipeline::process_dry_run_stream`.

use async_trait::async_trait;
use bytes::Bytes;

use crate::error::StoreError;
use crate::model::PutMeta;
use crate::ports::ObjectStore;

/// A destination that consumes writes and keeps nothing. See the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct DiscardStore;

#[async_trait]
impl ObjectStore for DiscardStore {
    /// Never a source. Dry run reads through the real store; this type is
    /// only ever the destination half.
    async fn get(&self, bucket: &str, key: &str) -> Result<Bytes, StoreError> {
        Err(StoreError::NotFound {
            bucket: bucket.to_string(),
            key: key.to_string(),
        })
    }

    async fn get_stream(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, StoreError> {
        Err(StoreError::NotFound {
            bucket: bucket.to_string(),
            key: key.to_string(),
        })
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
        mut body: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        _meta: PutMeta,
    ) -> Result<(), StoreError> {
        // Drain to EOF so the producer completes, and surface a reader error
        // so `stream_run`'s abort sentinel is not mistaken for a clean write.
        tokio::io::copy(&mut body, &mut tokio::io::sink())
            .await
            .map(|_| ())
            .map_err(|e| StoreError::Backend(format!("dry-run discard: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    const META: PutMeta = PutMeta {
        content_type: "application/x-gzip",
        content_encoding: "gzip",
    };

    #[tokio::test]
    async fn put_stream_drains_the_whole_reader() {
        let body = vec![b'x'; 1 << 16];
        assert!(
            DiscardStore
                .put_stream("b", "k", Box::new(io::Cursor::new(body)), META)
                .await
                .is_ok()
        );
    }

    /// The property that makes this a stand-in for a real destination rather
    /// than a sink: `stream_run` aborts an upload by failing the reader, so a
    /// discard store that swallowed the error would report every aborted
    /// object as written.
    #[tokio::test]
    async fn put_stream_propagates_a_reader_error() {
        struct Failing;
        impl tokio::io::AsyncRead for Failing {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::task::Poll::Ready(Err(io::Error::other("aborting")))
            }
        }

        let err = DiscardStore
            .put_stream("b", "k", Box::new(Failing), META)
            .await
            .expect_err("a failed reader must fail the write");
        assert!(err.to_string().contains("aborting"), "got: {err}");
    }
}
