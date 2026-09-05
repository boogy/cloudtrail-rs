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
    ///
    /// Nanoseconds, not seconds: `ConfigStore` refetches only when the tag
    /// changes, so a whole-second tag pins the ruleset a process already
    /// cached against every later rewrite within that same second.
    fn mtime(&self) -> Result<VersionTag, ConfigError> {
        let meta = std::fs::metadata(&self.path)
            .map_err(|e| ConfigError::Source(format!("failed to stat {:?}: {e}", self.path)))?;
        let modified = meta
            .modified()
            .map_err(|e| ConfigError::Source(format!("no mtime for {:?}: {e}", self.path)))?;
        let since_epoch = modified.duration_since(UNIX_EPOCH).map_err(|e| {
            ConfigError::Source(format!("mtime before epoch for {:?}: {e}", self.path))
        })?;
        // Saturating: an mtime past year 2554 overflows the tag rather than
        // panicking a Lambda built with `panic = "abort"`.
        let nanos = since_epoch
            .as_secs()
            .saturating_mul(1_000_000_000)
            .saturating_add(u64::from(since_epoch.subsec_nanos()));
        Ok(VersionTag::Mtime(nanos))
    }
}

#[async_trait]
impl ConfigSource for FileConfigSource {
    async fn version(&self) -> Result<VersionTag, ConfigError> {
        self.mtime()
    }

    async fn fetch(&self) -> Result<(Vec<u8>, VersionTag), ConfigError> {
        // Stat first: a write racing the read then leaves the bytes tagged
        // with the older mtime, so the next revalidation refetches instead of
        // pinning stale content forever.
        let version = self.mtime()?;
        let bytes = std::fs::read(&self.path)
            .map_err(|e| ConfigError::Source(format!("failed to read {:?}: {e}", self.path)))?;
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

    /// Pins the mtime so a precision test does not depend on how fast the
    /// test machine runs, nor on the filesystem's own timestamp granularity.
    fn set_mtime(path: &std::path::Path, at: std::time::SystemTime) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(at)
            .unwrap();
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

    /// Falsifiable: with a whole-second tag both writes land on the same
    /// version, `ConfigStore::refresh` takes its `new_version ==
    /// cached_version` branch, and the first ruleset stays cached for the life
    /// of the process.
    #[tokio::test]
    async fn two_writes_in_the_same_second_get_different_versions() {
        let path = temp_path("same-second");
        let base = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);

        std::fs::write(&path, b"a: 1\n").unwrap();
        set_mtime(&path, base);
        let src = FileConfigSource::new(&path);
        let (_, first) = src.fetch().await.expect("fetch must succeed");

        std::fs::write(&path, b"a: 2\n").unwrap();
        set_mtime(&path, base + std::time::Duration::from_millis(500));
        let second = src.version().await.expect("version must succeed");

        assert_ne!(
            first, second,
            "a rewrite 500ms later must change the version tag"
        );

        std::fs::remove_file(&path).unwrap();
    }

    /// Falsifiable: read first and the bytes carry the *newer* mtime, so the
    /// next revalidation matches and the content read before the write is
    /// pinned. Stat first and they carry the older one, which no longer
    /// matches.
    #[tokio::test]
    async fn fetch_tags_bytes_with_the_mtime_they_were_read_at_or_older() {
        let path = temp_path("stat-order");
        let base = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);

        std::fs::write(&path, b"a: 1\n").unwrap();
        set_mtime(&path, base);
        let src = FileConfigSource::new(&path);
        let (bytes, version) = src.fetch().await.expect("fetch must succeed");
        assert_eq!(bytes, b"a: 1\n");

        // Stands in for a write that lands between `fetch`'s stat and its read.
        std::fs::write(&path, b"a: 2\n").unwrap();
        set_mtime(&path, base + std::time::Duration::from_millis(500));

        assert_ne!(
            src.version().await.expect("version must succeed"),
            version,
            "bytes tagged with the newer mtime would pin the pre-write content"
        );

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
