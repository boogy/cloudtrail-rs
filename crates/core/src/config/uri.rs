//! Parses the `ssm://` / `s3://` / `file://` scheme strings used for both
//! `rules.uri` and (indirectly) `SETTINGS_URI` (see `SHARED.md`). Resolving
//! `Ssm`/`S3` into bytes needs an AWS SDK, which `core` does not depend on —
//! that is `cloudtrail-rs-aws`'s job. `File` is resolved right here, by
//! `FileConfigSource`.

use crate::error::ConfigError;

/// A parsed config document location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigUri {
    Ssm { path: String },
    S3 { bucket: String, key: String },
    File { path: String },
}

impl ConfigUri {
    /// Parses `uri`, rejecting any scheme other than the three above.
    pub fn parse(uri: &str) -> Result<Self, ConfigError> {
        if let Some(path) = uri.strip_prefix("ssm://") {
            return Ok(Self::Ssm {
                path: path.to_string(),
            });
        }
        if let Some(rest) = uri.strip_prefix("s3://") {
            let (bucket, key) = rest.split_once('/').ok_or_else(|| {
                ConfigError::Source(format!(
                    "invalid s3:// uri {uri:?}: expected s3://bucket/key"
                ))
            })?;
            return Ok(Self::S3 {
                bucket: bucket.to_string(),
                key: key.to_string(),
            });
        }
        if let Some(path) = uri.strip_prefix("file://") {
            return Ok(Self::File {
                path: path.to_string(),
            });
        }
        Err(ConfigError::Source(format!(
            "unsupported config uri scheme in {uri:?}: expected ssm://, s3://, or file://"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ssm_scheme() {
        assert_eq!(
            ConfigUri::parse("ssm://path/to/param").unwrap(),
            ConfigUri::Ssm {
                path: "path/to/param".to_string()
            }
        );
    }

    #[test]
    fn parses_s3_scheme() {
        assert_eq!(
            ConfigUri::parse("s3://bucket/key.yaml").unwrap(),
            ConfigUri::S3 {
                bucket: "bucket".to_string(),
                key: "key.yaml".to_string()
            }
        );
    }

    #[test]
    fn parses_s3_scheme_with_nested_key() {
        assert_eq!(
            ConfigUri::parse("s3://bucket/cloudtrail/rules.yaml").unwrap(),
            ConfigUri::S3 {
                bucket: "bucket".to_string(),
                key: "cloudtrail/rules.yaml".to_string()
            }
        );
    }

    #[test]
    fn parses_file_scheme() {
        assert_eq!(
            ConfigUri::parse("file:///abs/path.yaml").unwrap(),
            ConfigUri::File {
                path: "/abs/path.yaml".to_string()
            }
        );
    }

    #[test]
    fn rejects_unknown_scheme() {
        let err = ConfigUri::parse("http://example.com/rules.yaml")
            .expect_err("unknown scheme must be rejected");
        assert!(matches!(err, ConfigError::Source(_)));
    }

    #[test]
    fn rejects_s3_uri_with_no_key() {
        let err =
            ConfigUri::parse("s3://bucket-only").expect_err("s3:// with no key must be rejected");
        assert!(matches!(err, ConfigError::Source(_)));
    }
}
