//! S3-backed `ConfigSource`: the ruleset lives at a fixed bucket/key, and
//! `version` is a cheap `HeadObject` ETag check (no body transfer) per
//! `SHARED.md`'s caching design.

use async_trait::async_trait;
use aws_config::SdkConfig;
use aws_sdk_s3::Client;
use aws_smithy_types::error::display::DisplayErrorContext;
use cloudtrail_rs_core::error::ConfigError;
use cloudtrail_rs_core::model::VersionTag;
use cloudtrail_rs_core::ports::ConfigSource;

use crate::http_client::ring_http_client;

pub struct S3ConfigSource {
    client: Client,
    bucket: String,
    key: String,
}

impl S3ConfigSource {
    /// Builds the S3 client from `conf`, wired for rustls+ring.
    pub fn new(conf: &SdkConfig, bucket: impl Into<String>, key: impl Into<String>) -> Self {
        let s3_conf = aws_sdk_s3::config::Builder::from(conf)
            .http_client(ring_http_client())
            .build();
        Self::from_client(Client::from_conf(s3_conf), bucket, key)
    }

    /// For tests: wraps an already-built client directly, bypassing HTTP
    /// client construction entirely.
    pub fn from_client(client: Client, bucket: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            client,
            bucket: bucket.into(),
            key: key.into(),
        }
    }
}

#[async_trait]
impl ConfigSource for S3ConfigSource {
    async fn version(&self) -> Result<VersionTag, ConfigError> {
        let out = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&self.key)
            .send()
            .await
            .map_err(|e| ConfigError::Source(format!("{}", DisplayErrorContext(e))))?;
        let etag = out
            .e_tag()
            .ok_or_else(|| ConfigError::Source("HeadObject response missing ETag".to_string()))?;
        Ok(VersionTag::Etag(etag.to_string()))
    }

    async fn fetch(&self) -> Result<(Vec<u8>, VersionTag), ConfigError> {
        let out = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&self.key)
            .send()
            .await
            .map_err(|e| ConfigError::Source(format!("{}", DisplayErrorContext(e))))?;
        let etag = out
            .e_tag()
            .ok_or_else(|| ConfigError::Source("GetObject response missing ETag".to_string()))?
            .to_string();
        let bytes = out
            .body
            .collect()
            .await
            .map_err(|e| ConfigError::Source(format!("reading config object body: {e}")))?
            .into_bytes();
        Ok((bytes.to_vec(), VersionTag::Etag(etag)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_s3::operation::get_object::GetObjectOutput;
    use aws_sdk_s3::operation::head_object::{HeadObjectError, HeadObjectOutput};
    use aws_sdk_s3::types::error::NotFound;
    use aws_smithy_mocks::{RuleMode, mock, mock_client};
    use aws_smithy_types::byte_stream::ByteStream;

    #[tokio::test]
    async fn version_returns_etag_from_head_object() {
        let rule = mock!(Client::head_object)
            .match_requests(|r| r.bucket() == Some("b") && r.key() == Some("rules.json"))
            .then_output(|| HeadObjectOutput::builder().e_tag("\"abc123\"").build());
        let client = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&rule]);
        let source = S3ConfigSource::from_client(client, "b", "rules.json");

        let version = source.version().await.unwrap();

        assert!(matches!(version, VersionTag::Etag(t) if t == "\"abc123\""));
    }

    #[tokio::test]
    async fn version_maps_missing_object_to_config_source_error() {
        let rule = mock!(Client::head_object)
            .then_error(|| HeadObjectError::NotFound(NotFound::builder().build()));
        let client = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&rule]);
        let source = S3ConfigSource::from_client(client, "b", "missing.json");

        let err = source.version().await.unwrap_err();

        assert!(matches!(err, ConfigError::Source(_)));
    }

    #[tokio::test]
    async fn fetch_returns_body_and_etag() {
        let rule = mock!(Client::get_object)
            .match_requests(|r| r.bucket() == Some("b") && r.key() == Some("rules.json"))
            .then_output(|| {
                GetObjectOutput::builder()
                    .e_tag("\"abc123\"")
                    .body(ByteStream::from_static(b"{}"))
                    .build()
            });
        let client = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&rule]);
        let source = S3ConfigSource::from_client(client, "b", "rules.json");

        let (bytes, version) = source.fetch().await.unwrap();

        assert_eq!(bytes, b"{}".to_vec());
        assert!(matches!(version, VersionTag::Etag(t) if t == "\"abc123\""));
    }
}
