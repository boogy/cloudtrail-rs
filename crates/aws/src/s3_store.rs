//! S3-backed `ObjectStore`.

use async_trait::async_trait;
use aws_config::SdkConfig;
use aws_sdk_s3::Client;
use aws_sdk_s3::operation::get_object::GetObjectError;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use aws_smithy_types::byte_stream::ByteStream;
use aws_smithy_types::error::display::DisplayErrorContext;
use bytes::Bytes;
use cloudtrail_rs_core::error::StoreError;
use cloudtrail_rs_core::model::PutMeta;
use cloudtrail_rs_core::ports::ObjectStore;
use tokio::io::AsyncReadExt;

use crate::http_client::ring_http_client;

/// Default multipart part size, matching `processing.multipart_part_bytes`'s
/// documented default in `SHARED.md`. Override with `with_multipart_part_bytes`.
pub const DEFAULT_MULTIPART_PART_BYTES: usize = 8 * 1024 * 1024;

pub struct S3ObjectStore {
    client: Client,
    multipart_part_bytes: usize,
}

impl S3ObjectStore {
    /// Builds the S3 client from `conf`, wired for rustls+ring.
    pub fn new(conf: &SdkConfig) -> Self {
        let s3_conf = aws_sdk_s3::config::Builder::from(conf)
            .http_client(ring_http_client())
            .build();
        Self::from_client(Client::from_conf(s3_conf))
    }

    /// For tests: wraps an already-built client (e.g. an `aws-smithy-mocks`
    /// client) directly, bypassing HTTP client construction entirely.
    pub fn from_client(client: Client) -> Self {
        Self {
            client,
            multipart_part_bytes: DEFAULT_MULTIPART_PART_BYTES,
        }
    }

    pub fn with_multipart_part_bytes(mut self, n: usize) -> Self {
        self.multipart_part_bytes = n;
        self
    }

    /// Lists every object key under `prefix` in `bucket`, following
    /// `ListObjectsV2` pagination to completion.
    ///
    /// Inherent rather than part of the `ObjectStore` port: only the CLI's
    /// batch/backfill mode enumerates a bucket. The Lambda hot path is handed
    /// exact keys by its event decoder and never lists, so keeping this off
    /// the trait avoids burdening `InMemoryStore` and every future adapter
    /// with a method they do not need.
    pub async fn list_keys(&self, bucket: &str, prefix: &str) -> Result<Vec<String>, StoreError> {
        let mut keys = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let mut req = self.client.list_objects_v2().bucket(bucket).prefix(prefix);
            if let Some(token) = &continuation {
                req = req.continuation_token(token);
            }
            let out = req
                .send()
                .await
                .map_err(|e| StoreError::Backend(format!("{}", DisplayErrorContext(e))))?;
            for obj in out.contents() {
                if let Some(k) = obj.key() {
                    keys.push(k.to_string());
                }
            }
            match out.next_continuation_token() {
                Some(token) if out.is_truncated() == Some(true) => {
                    continuation = Some(token.to_string());
                }
                _ => break,
            }
        }
        Ok(keys)
    }
}

#[async_trait]
impl ObjectStore for S3ObjectStore {
    async fn get(&self, b: &str, k: &str) -> Result<Bytes, StoreError> {
        let out = self
            .client
            .get_object()
            .bucket(b)
            .key(k)
            .send()
            .await
            .map_err(|e| map_get_error(e, b, k))?;
        out.body
            .collect()
            .await
            .map(|agg| agg.into_bytes())
            .map_err(|e| StoreError::Backend(format!("reading object body: {e}")))
    }

    async fn get_stream(
        &self,
        b: &str,
        k: &str,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, StoreError> {
        let out = self
            .client
            .get_object()
            .bucket(b)
            .key(k)
            .send()
            .await
            .map_err(|e| map_get_error(e, b, k))?;
        Ok(Box::new(tokio::io::BufReader::new(
            out.body.into_async_read(),
        )))
    }

    async fn put(&self, b: &str, k: &str, body: Bytes, meta: PutMeta) -> Result<(), StoreError> {
        // No `.server_side_encryption(...)`/`.ssekms_key_id(...)`: the bucket's
        // default encryption configuration applies, never a hardcoded key.
        self.client
            .put_object()
            .bucket(b)
            .key(k)
            .content_type(meta.content_type)
            .content_encoding(meta.content_encoding)
            .body(aws_smithy_types::byte_stream::ByteStream::from(body))
            .send()
            .await
            .map_err(|e| StoreError::Backend(format!("{}", DisplayErrorContext(e))))?;
        Ok(())
    }

    async fn put_stream(
        &self,
        b: &str,
        k: &str,
        mut body: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        meta: PutMeta,
    ) -> Result<(), StoreError> {
        let created = self
            .client
            .create_multipart_upload()
            .bucket(b)
            .key(k)
            .content_type(meta.content_type)
            .content_encoding(meta.content_encoding)
            .send()
            .await
            .map_err(|e| StoreError::Backend(format!("{}", DisplayErrorContext(e))))?;
        let upload_id = created.upload_id().ok_or_else(|| {
            StoreError::Backend("CreateMultipartUpload response missing upload_id".to_string())
        })?;

        // Any failure past this point — including one surfaced by `body`
        // itself — must abort the upload so no billable orphan parts remain.
        match self.upload_parts(b, k, upload_id, body.as_mut()).await {
            Ok(parts) => {
                self.client
                    .complete_multipart_upload()
                    .bucket(b)
                    .key(k)
                    .upload_id(upload_id)
                    .multipart_upload(
                        CompletedMultipartUpload::builder()
                            .set_parts(Some(parts))
                            .build(),
                    )
                    .send()
                    .await
                    .map_err(|e| StoreError::Backend(format!("{}", DisplayErrorContext(e))))?;
                Ok(())
            }
            Err(e) => {
                // Best-effort: the original error is what the caller sees
                // regardless of whether the abort call itself succeeds.
                let _ = self
                    .client
                    .abort_multipart_upload()
                    .bucket(b)
                    .key(k)
                    .upload_id(upload_id)
                    .send()
                    .await;
                Err(e)
            }
        }
    }
}

impl S3ObjectStore {
    /// Reads `body` in `multipart_part_bytes`-sized chunks, uploading each as
    /// a part. Returns the completed parts in order, ready for
    /// `CompleteMultipartUpload`.
    async fn upload_parts(
        &self,
        b: &str,
        k: &str,
        upload_id: &str,
        body: &mut (dyn tokio::io::AsyncRead + Send + Unpin),
    ) -> Result<Vec<CompletedPart>, StoreError> {
        let part_size = self.multipart_part_bytes;
        let mut parts = Vec::new();
        let mut part_number: i32 = 1;

        loop {
            let mut buf = vec![0u8; part_size];
            let mut filled = 0usize;
            while filled < part_size {
                let n = body
                    .read(&mut buf[filled..])
                    .await
                    .map_err(|e| StoreError::Backend(format!("reading upload body: {e}")))?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            if filled == 0 {
                break;
            }
            buf.truncate(filled);

            let out = self
                .client
                .upload_part()
                .bucket(b)
                .key(k)
                .upload_id(upload_id)
                .part_number(part_number)
                .body(ByteStream::from(buf))
                .send()
                .await
                .map_err(|e| StoreError::Backend(format!("{}", DisplayErrorContext(e))))?;
            let e_tag = out.e_tag().ok_or_else(|| {
                StoreError::Backend("UploadPart response missing e_tag".to_string())
            })?;
            parts.push(
                CompletedPart::builder()
                    .part_number(part_number)
                    .e_tag(e_tag)
                    .build(),
            );

            part_number += 1;
            if filled < part_size {
                break;
            }
        }

        if parts.is_empty() {
            return Err(StoreError::Backend(
                "put_stream: empty body produces zero multipart parts".to_string(),
            ));
        }
        Ok(parts)
    }
}

/// Maps a `GetObject` error to `StoreError`, folding `NoSuchKey` into the
/// distinct `NotFound` variant `on_missing_object` dispatches on.
fn map_get_error(
    err: aws_sdk_s3::error::SdkError<GetObjectError>,
    bucket: &str,
    key: &str,
) -> StoreError {
    match err.as_service_error() {
        Some(GetObjectError::NoSuchKey(_)) => StoreError::NotFound {
            bucket: bucket.to_string(),
            key: key.to_string(),
        },
        _ => StoreError::Backend(format!("{}", DisplayErrorContext(err))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_s3::operation::get_object::GetObjectError;
    use aws_sdk_s3::operation::get_object::GetObjectOutput;
    use aws_sdk_s3::types::error::NoSuchKey;
    use aws_smithy_mocks::{RuleMode, mock, mock_client};
    use aws_smithy_types::byte_stream::ByteStream;

    #[tokio::test]
    async fn get_returns_object_bytes() {
        let rule = mock!(Client::get_object)
            .match_requests(|r| r.bucket() == Some("b") && r.key() == Some("k"))
            .then_output(|| {
                GetObjectOutput::builder()
                    .body(ByteStream::from_static(b"hello"))
                    .build()
            });
        let client = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&rule]);
        let store = S3ObjectStore::from_client(client);

        let bytes = store.get("b", "k").await.unwrap();

        assert_eq!(bytes, Bytes::from_static(b"hello"));
    }

    #[tokio::test]
    async fn get_maps_no_such_key_to_not_found() {
        let rule = mock!(Client::get_object)
            .then_error(|| GetObjectError::NoSuchKey(NoSuchKey::builder().build()));
        let client = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&rule]);
        let store = S3ObjectStore::from_client(client);

        let err = store.get("b", "missing").await.unwrap_err();

        assert!(matches!(
            err,
            StoreError::NotFound { bucket, key }
                if bucket == "b" && key == "missing"
        ));
    }

    #[tokio::test]
    async fn get_stream_reads_object_bytes() {
        use tokio::io::AsyncReadExt;

        let rule = mock!(Client::get_object).then_output(|| {
            GetObjectOutput::builder()
                .body(ByteStream::from_static(b"streamed"))
                .build()
        });
        let client = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&rule]);
        let store = S3ObjectStore::from_client(client);

        let mut reader = store.get_stream("b", "k").await.unwrap();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();

        assert_eq!(buf, b"streamed");
    }

    #[tokio::test]
    async fn put_sends_body_and_gzip_metadata() {
        use aws_sdk_s3::operation::put_object::PutObjectOutput;

        let rule = mock!(Client::put_object)
            .match_requests(|r| {
                r.bucket() == Some("b")
                    && r.key() == Some("k")
                    && r.content_type() == Some("application/x-gzip")
                    && r.content_encoding() == Some("gzip")
                    && r.server_side_encryption().is_none()
            })
            .then_output(|| PutObjectOutput::builder().build());
        let client = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&rule]);
        let store = S3ObjectStore::from_client(client);
        let meta = PutMeta {
            content_type: "application/x-gzip",
            content_encoding: "gzip",
        };

        store
            .put("b", "k", Bytes::from_static(b"payload"), meta)
            .await
            .unwrap();
    }

    /// Minimal in-memory `AsyncRead` that always completes a `poll_read`
    /// immediately (no pending state), serving bytes from a `Vec<u8>`.
    struct BytesReader {
        data: Vec<u8>,
        pos: usize,
    }

    impl BytesReader {
        fn new(data: impl Into<Vec<u8>>) -> Self {
            Self {
                data: data.into(),
                pos: 0,
            }
        }
    }

    impl tokio::io::AsyncRead for BytesReader {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let this = self.get_mut();
            let remaining = &this.data[this.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.pos += n;
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// Serves `first_chunk` once, then fails every subsequent read — models
    /// task 13 cancelling an in-flight upload by failing the body reader.
    struct FailingReader {
        first_chunk: Option<Vec<u8>>,
    }

    impl tokio::io::AsyncRead for FailingReader {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            match self.get_mut().first_chunk.take() {
                Some(chunk) => {
                    buf.put_slice(&chunk);
                    std::task::Poll::Ready(Ok(()))
                }
                None => std::task::Poll::Ready(Err(std::io::Error::other("reader exploded"))),
            }
        }
    }

    #[tokio::test]
    async fn list_keys_follows_pagination_across_pages() {
        use aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Output;
        use aws_sdk_s3::types::Object;

        let page1 = mock!(Client::list_objects_v2)
            .match_requests(|r| {
                r.bucket() == Some("b")
                    && r.prefix() == Some("logs/")
                    && r.continuation_token().is_none()
            })
            .then_output(|| {
                ListObjectsV2Output::builder()
                    .contents(Object::builder().key("logs/a.json.gz").build())
                    .contents(Object::builder().key("logs/b.json.gz").build())
                    .is_truncated(true)
                    .next_continuation_token("tok-2")
                    .build()
            });
        let page2 = mock!(Client::list_objects_v2)
            .match_requests(|r| r.continuation_token() == Some("tok-2"))
            .then_output(|| {
                ListObjectsV2Output::builder()
                    .contents(Object::builder().key("logs/c.json.gz").build())
                    .is_truncated(false)
                    .build()
            });
        let client = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&page1, &page2]);
        let store = S3ObjectStore::from_client(client);

        let keys = store.list_keys("b", "logs/").await.unwrap();

        assert_eq!(
            keys,
            vec!["logs/a.json.gz", "logs/b.json.gz", "logs/c.json.gz"]
        );
    }

    #[tokio::test]
    async fn put_stream_uploads_body_in_parts_and_completes() {
        use aws_sdk_s3::operation::complete_multipart_upload::CompleteMultipartUploadOutput;
        use aws_sdk_s3::operation::create_multipart_upload::CreateMultipartUploadOutput;
        use aws_sdk_s3::operation::upload_part::UploadPartOutput;

        let create_rule = mock!(Client::create_multipart_upload)
            .match_requests(|r| {
                r.bucket() == Some("b")
                    && r.key() == Some("k")
                    && r.content_type() == Some("application/x-gzip")
                    && r.content_encoding() == Some("gzip")
            })
            .then_output(|| {
                CreateMultipartUploadOutput::builder()
                    .upload_id("up1")
                    .build()
            });
        let part1 = mock!(Client::upload_part)
            .match_requests(|r| r.upload_id() == Some("up1") && r.part_number() == Some(1))
            .then_output(|| UploadPartOutput::builder().e_tag("etag-1").build());
        let part2 = mock!(Client::upload_part)
            .match_requests(|r| r.upload_id() == Some("up1") && r.part_number() == Some(2))
            .then_output(|| UploadPartOutput::builder().e_tag("etag-2").build());
        let part3 = mock!(Client::upload_part)
            .match_requests(|r| r.upload_id() == Some("up1") && r.part_number() == Some(3))
            .then_output(|| UploadPartOutput::builder().e_tag("etag-3").build());
        let complete_rule = mock!(Client::complete_multipart_upload)
            .match_requests(|r| {
                r.upload_id() == Some("up1")
                    && r.multipart_upload().map(|m| m.parts().len()) == Some(3)
                    && r.multipart_upload().unwrap().parts()[0].part_number() == Some(1)
                    && r.multipart_upload().unwrap().parts()[0].e_tag() == Some("etag-1")
                    && r.multipart_upload().unwrap().parts()[2].part_number() == Some(3)
                    && r.multipart_upload().unwrap().parts()[2].e_tag() == Some("etag-3")
            })
            .then_output(|| CompleteMultipartUploadOutput::builder().build());
        let client = mock_client!(
            aws_sdk_s3,
            RuleMode::Sequential,
            &[&create_rule, &part1, &part2, &part3, &complete_rule]
        );
        let store = S3ObjectStore::from_client(client).with_multipart_part_bytes(4);
        let meta = PutMeta {
            content_type: "application/x-gzip",
            content_encoding: "gzip",
        };
        let body = Box::new(BytesReader::new(*b"abcdefghij"));

        store.put_stream("b", "k", body, meta).await.unwrap();

        assert_eq!(complete_rule.num_calls(), 1);
    }

    #[tokio::test]
    async fn put_stream_aborts_multipart_upload_on_reader_error() {
        use aws_sdk_s3::operation::abort_multipart_upload::AbortMultipartUploadOutput;
        use aws_sdk_s3::operation::create_multipart_upload::CreateMultipartUploadOutput;
        use aws_sdk_s3::operation::upload_part::UploadPartOutput;

        let create_rule = mock!(Client::create_multipart_upload).then_output(|| {
            CreateMultipartUploadOutput::builder()
                .upload_id("up1")
                .build()
        });
        let part1 = mock!(Client::upload_part)
            .match_requests(|r| r.upload_id() == Some("up1") && r.part_number() == Some(1))
            .then_output(|| UploadPartOutput::builder().e_tag("etag-1").build());
        let abort_rule = mock!(Client::abort_multipart_upload)
            .match_requests(|r| {
                r.bucket() == Some("b") && r.key() == Some("k") && r.upload_id() == Some("up1")
            })
            .then_output(|| AbortMultipartUploadOutput::builder().build());
        let client = mock_client!(
            aws_sdk_s3,
            RuleMode::Sequential,
            &[&create_rule, &part1, &abort_rule]
        );
        let store = S3ObjectStore::from_client(client).with_multipart_part_bytes(4);
        let meta = PutMeta {
            content_type: "application/x-gzip",
            content_encoding: "gzip",
        };
        // First read serves a full part ("abcd"); the second read fails,
        // simulating task 13 cancelling an in-flight upload.
        let body = Box::new(FailingReader {
            first_chunk: Some(b"abcd".to_vec()),
        });

        let err = store.put_stream("b", "k", body, meta).await.unwrap_err();

        assert!(matches!(err, StoreError::Backend(_)));
        assert_eq!(abort_rule.num_calls(), 1);
    }
}
