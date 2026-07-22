//! `ConfigSource` for `file://` URIs. Local-disk reads are synchronous
//! (`std::fs`, same choice `Settings::load` already makes) — this runs at
//! most once per TTL window, never per record, so there is no reason to pull
//! in `tokio`'s `fs` feature for it.

use std::path::PathBuf;
use std::time::UNIX_EPOCH;

use async_trait::async_trait;

use crate::error::ConfigError;
use crate::model::VersionTag;
use crate::ports::ConfigSource;

/// Reads a config document from a local path.
pub struct FileConfigSource {
    path: PathBuf,
}

impl FileConfigSource {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Stats the file (no read) and returns its mtime as a `VersionTag`, so a
    /// `ConfigStore` past its TTL can skip the read+parse+compile when the
    /// file is untouched.
    fn mtime(&self) -> Result<VersionTag, ConfigError> {
        let meta = std::fs::metadata(&self.path)
            .map_err(|e| ConfigError::Source(format!("failed to stat {:?}: {e}", self.path)))?;
        let modified = meta
            .modified()
            .map_err(|e| ConfigError::Source(format!("no mtime for {:?}: {e}", self.path)))?;
        let secs = modified
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                ConfigError::Source(format!("mtime before epoch for {:?}: {e}", self.path))
            })?
            .as_secs();
        Ok(VersionTag::Mtime(secs))
    }
}

#[async_trait]
impl ConfigSource for FileConfigSource {
    async fn version(&self) -> Result<VersionTag, ConfigError> {
        self.mtime()
    }

    async fn fetch(&self) -> Result<(Vec<u8>, VersionTag), ConfigError> {
        let bytes = std::fs::read(&self.path)
            .map_err(|e| ConfigError::Source(format!("failed to read {:?}: {e}", self.path)))?;
        let version = self.mtime()?;
        Ok((bytes, version))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    /// A path under the OS temp dir, unique per call so parallel tests never
    /// collide. No `tempfile` dependency in this crate for one test helper.
    fn temp_path(label: &str) -> PathBuf {
        let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "cloudtrail-rs-file-source-test-{}-{label}-{n}",
            std::process::id()
        ))
    }

    #[tokio::test]
    async fn fetch_returns_file_bytes_and_a_version() {
        let path = temp_path("fetch");
        std::fs::write(&path, b"hello: world\n").unwrap();

        let src = FileConfigSource::new(&path);
        let (bytes, version) = src.fetch().await.expect("fetch must succeed");

        assert_eq!(bytes, b"hello: world\n");
        assert!(matches!(version, VersionTag::Mtime(_)));

        std::fs::remove_file(&path).unwrap();
    }

    #[tokio::test]
    async fn version_matches_fetch_version_when_file_is_untouched() {
        let path = temp_path("version");
        std::fs::write(&path, b"a: 1\n").unwrap();

        let src = FileConfigSource::new(&path);
        let (_, fetch_version) = src.fetch().await.expect("fetch must succeed");
        let version = src.version().await.expect("version must succeed");

        assert_eq!(version, fetch_version);

        std::fs::remove_file(&path).unwrap();
    }

    #[tokio::test]
    async fn fetch_of_missing_file_is_a_config_error() {
        let path = temp_path("missing");
        let src = FileConfigSource::new(&path);

        let err = src.fetch().await.expect_err("missing file must error");
        assert!(matches!(err, ConfigError::Source(_)));
    }

    #[tokio::test]
    async fn version_of_missing_file_is_a_config_error() {
        let path = temp_path("missing-version");
        let src = FileConfigSource::new(&path);

        let err = src.version().await.expect_err("missing file must error");
        assert!(matches!(err, ConfigError::Source(_)));
    }
}
