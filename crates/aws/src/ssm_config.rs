//! SSM Parameter Store-backed `ConfigSource`. Unlike S3, SSM has no cheap
//! metadata-only check: both `version` and `fetch` issue a full
//! `GetParameter` call, but `version` alone is enough to skip the parse/
//! recompile when `Version` is unchanged (see `SHARED.md`'s caching design).

use async_trait::async_trait;
use aws_config::SdkConfig;
use aws_sdk_ssm::Client;
use aws_smithy_types::error::display::DisplayErrorContext;
use cloudtrail_rs_core::error::ConfigError;
use cloudtrail_rs_core::model::VersionTag;
use cloudtrail_rs_core::ports::ConfigSource;

use crate::http_client::ring_http_client;

pub struct SsmConfigSource {
    client: Client,
    name: String,
}

impl SsmConfigSource {
    /// Builds the SSM client from `conf`, wired for rustls+ring.
    pub fn new(conf: &SdkConfig, name: impl Into<String>) -> Self {
        let ssm_conf = aws_sdk_ssm::config::Builder::from(conf)
            .http_client(ring_http_client())
            .build();
        Self::from_client(Client::from_conf(ssm_conf), name)
    }

    /// For tests: wraps an already-built client directly, bypassing HTTP
    /// client construction entirely.
    pub fn from_client(client: Client, name: impl Into<String>) -> Self {
        Self {
            client,
            name: name.into(),
        }
    }

    async fn get_parameter(&self) -> Result<aws_sdk_ssm::types::Parameter, ConfigError> {
        let out = self
            .client
            .get_parameter()
            .name(&self.name)
            .with_decryption(true)
            .send()
            .await
            .map_err(|e| ConfigError::Source(format!("{}", DisplayErrorContext(e))))?;
        out.parameter.ok_or_else(|| {
            ConfigError::Source("GetParameter response missing parameter".to_string())
        })
    }
}

#[async_trait]
impl ConfigSource for SsmConfigSource {
    async fn version(&self) -> Result<VersionTag, ConfigError> {
        let param = self.get_parameter().await?;
        Ok(VersionTag::Version(param.version()))
    }

    async fn fetch(&self) -> Result<(Vec<u8>, VersionTag), ConfigError> {
        let param = self.get_parameter().await?;
        let version = VersionTag::Version(param.version());
        let value = param
            .value()
            .ok_or_else(|| ConfigError::Source("GetParameter response missing value".to_string()))?
            .as_bytes()
            .to_vec();
        Ok((value, version))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_ssm::operation::get_parameter::GetParameterOutput;
    use aws_sdk_ssm::types::Parameter;
    use aws_smithy_mocks::{RuleMode, mock, mock_client};

    #[tokio::test]
    async fn version_returns_parameter_version() {
        let rule = mock!(Client::get_parameter)
            .match_requests(|r| r.name() == Some("/ct/rules") && r.with_decryption() == Some(true))
            .then_output(|| {
                GetParameterOutput::builder()
                    .parameter(Parameter::builder().value("{}").version(7).build())
                    .build()
            });
        let client = mock_client!(aws_sdk_ssm, RuleMode::Sequential, &[&rule]);
        let source = SsmConfigSource::from_client(client, "/ct/rules");

        let version = source.version().await.unwrap();

        assert!(matches!(version, VersionTag::Version(7)));
    }

    #[tokio::test]
    async fn fetch_returns_value_and_version() {
        let rule = mock!(Client::get_parameter)
            .match_requests(|r| r.with_decryption() == Some(true))
            .then_output(|| {
                GetParameterOutput::builder()
                    .parameter(Parameter::builder().value("{\"k\":1}").version(3).build())
                    .build()
            });
        let client = mock_client!(aws_sdk_ssm, RuleMode::Sequential, &[&rule]);
        let source = SsmConfigSource::from_client(client, "/ct/rules");

        let (bytes, version) = source.fetch().await.unwrap();

        assert_eq!(bytes, b"{\"k\":1}".to_vec());
        assert!(matches!(version, VersionTag::Version(3)));
    }

    #[tokio::test]
    async fn fetch_maps_parameter_not_found_to_config_source_error() {
        use aws_sdk_ssm::operation::get_parameter::GetParameterError;
        use aws_sdk_ssm::types::error::ParameterNotFound;

        let rule = mock!(Client::get_parameter).then_error(|| {
            GetParameterError::ParameterNotFound(ParameterNotFound::builder().build())
        });
        let client = mock_client!(aws_sdk_ssm, RuleMode::Sequential, &[&rule]);
        let source = SsmConfigSource::from_client(client, "/ct/missing");

        let err = source.fetch().await.unwrap_err();

        assert!(matches!(err, ConfigError::Source(_)));
    }
}
