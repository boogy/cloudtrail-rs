//! Parsing, defaults, and environment overrides for the settings document
//! (fetched from `SETTINGS_URI`, see `SHARED.md`).
//!
//! Env wins over file, always. To keep that logic testable without touching
//! process-global `std::env` state (`cargo test` runs in parallel, and
//! `std::env::set_var`/`remove_var` would flake or corrupt sibling tests),
//! the override step is a pure function of an injected `env` lookup:
//! `Settings::load()` is the only place that closes over `std::env::var`.

use crate::error::ConfigError;

/// How an object's size determines buffer vs. stream processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
pub enum ProcessingMode {
    #[serde(rename = "auto")]
    #[default]
    Auto,
    #[serde(rename = "buffer")]
    Buffer,
    #[serde(rename = "stream")]
    Stream,
}

impl std::str::FromStr for ProcessingMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "auto" => Ok(Self::Auto),
            "buffer" => Ok(Self::Buffer),
            "stream" => Ok(Self::Stream),
            other => Err(format!(
                "invalid processing mode {other:?}: expected auto, buffer, or stream"
            )),
        }
    }
}

/// Whether a rules-load failure forwards records unfiltered (`Open`) or
/// drops the batch (`Closed`). Governs rules-load failure only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
pub enum OnConfigError {
    #[serde(rename = "open")]
    #[default]
    Open,
    #[serde(rename = "closed")]
    Closed,
}

impl std::str::FromStr for OnConfigError {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "open" => Ok(Self::Open),
            "closed" => Ok(Self::Closed),
            other => Err(format!(
                "invalid on_config_error {other:?}: expected open or closed"
            )),
        }
    }
}

/// What to do when the source object named by an event is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
pub enum OnMissingObject {
    #[serde(rename = "error")]
    #[default]
    Error,
    #[serde(rename = "skip")]
    Skip,
}

impl std::str::FromStr for OnMissingObject {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "error" => Ok(Self::Error),
            "skip" => Ok(Self::Skip),
            other => Err(format!(
                "invalid on_missing_object {other:?}: expected error or skip"
            )),
        }
    }
}

/// What to do with an object that parses as JSON but has no `Records` array.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
pub enum OnUnrecognizedObject {
    #[serde(rename = "copy")]
    #[default]
    Copy,
    #[serde(rename = "skip")]
    Skip,
    #[serde(rename = "error")]
    Error,
}

impl std::str::FromStr for OnUnrecognizedObject {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "copy" => Ok(Self::Copy),
            "skip" => Ok(Self::Skip),
            "error" => Ok(Self::Error),
            other => Err(format!(
                "invalid on_unrecognized_object {other:?}: expected copy, skip, or error"
            )),
        }
    }
}

/// How to interpret an SQS message body: sniff it (`Auto`), or skip the
/// sniff because it is known to be a direct S3 event or an SNS envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
pub enum SqsBodyFormat {
    #[serde(rename = "auto")]
    #[default]
    Auto,
    #[serde(rename = "s3")]
    S3,
    #[serde(rename = "sns")]
    Sns,
}

impl std::str::FromStr for SqsBodyFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "auto" => Ok(Self::Auto),
            "s3" => Ok(Self::S3),
            "sns" => Ok(Self::Sns),
            other => Err(format!(
                "invalid sqs body_format {other:?}: expected auto, s3, or sns"
            )),
        }
    }
}

/// Where the per-invocation `MetricSnapshot` goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
pub enum MetricsMode {
    #[serde(rename = "emf")]
    #[default]
    Emf,
    #[serde(rename = "none")]
    None,
}

impl std::str::FromStr for MetricsMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "emf" => Ok(Self::Emf),
            "none" => Ok(Self::None),
            other => Err(format!(
                "invalid metrics mode {other:?}: expected emf or none"
            )),
        }
    }
}

fn default_include_key_regex() -> String {
    r"\.json\.gz$".to_string()
}
fn default_exclude_key_regex() -> String {
    r"(/CloudTrail-Digest/|/CloudTrail-Insight/|/$)".to_string()
}
fn default_stream_threshold_bytes() -> u64 {
    8_388_608
}
fn default_max_object_bytes() -> u64 {
    134_217_728
}
fn default_multipart_part_bytes() -> u64 {
    8_388_608
}
fn default_gzip_level() -> u32 {
    6
}
fn default_partial_batch_failures() -> bool {
    true
}
fn default_rules_uri() -> String {
    "s3://sec-config/cloudtrail/rules.yaml".to_string()
}
fn default_rules_ttl_seconds() -> u64 {
    300
}
fn default_namespace() -> String {
    "cloudtrail-rs".to_string()
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_version() -> i64 {
    1
}

/// Source-key filtering, applied before any `GetObject` (safety invariant 2
/// in `SHARED.md`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    #[serde(default = "default_include_key_regex")]
    pub include_key_regex: String,
    #[serde(default = "default_exclude_key_regex")]
    pub exclude_key_regex: String,
}

impl Default for Source {
    fn default() -> Self {
        Self {
            include_key_regex: default_include_key_regex(),
            exclude_key_regex: default_exclude_key_regex(),
        }
    }
}

/// Where survivors are written. `bucket` is the one field with no usable
/// default — required in the file, or via `CT_DEST_BUCKET`.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    #[serde(default)]
    pub bucket: String,
    #[serde(default)]
    pub key_prefix: String,
}

/// Buffer vs. stream selection and their size knobs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Processing {
    #[serde(default)]
    pub mode: ProcessingMode,
    #[serde(default = "default_stream_threshold_bytes")]
    pub stream_threshold_bytes: u64,
    #[serde(default = "default_max_object_bytes")]
    pub max_object_bytes: u64,
    #[serde(default = "default_multipart_part_bytes")]
    pub multipart_part_bytes: u64,
    #[serde(default = "default_gzip_level")]
    pub gzip_level: u32,
}

impl Default for Processing {
    fn default() -> Self {
        Self {
            mode: ProcessingMode::default(),
            stream_threshold_bytes: default_stream_threshold_bytes(),
            max_object_bytes: default_max_object_bytes(),
            multipart_part_bytes: default_multipart_part_bytes(),
            gzip_level: default_gzip_level(),
        }
    }
}

/// Fail-open/closed and per-object policy knobs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Behavior {
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub on_config_error: OnConfigError,
    #[serde(default)]
    pub on_missing_object: OnMissingObject,
    #[serde(default)]
    pub on_unrecognized_object: OnUnrecognizedObject,
    #[serde(default = "default_partial_batch_failures")]
    pub partial_batch_failures: bool,
}

impl Default for Behavior {
    fn default() -> Self {
        Self {
            dry_run: false,
            on_config_error: OnConfigError::default(),
            on_missing_object: OnMissingObject::default(),
            on_unrecognized_object: OnUnrecognizedObject::default(),
            partial_batch_failures: default_partial_batch_failures(),
        }
    }
}

/// SQS-specific settings (`decode-sqs` binary only).
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sqs {
    #[serde(default)]
    pub body_format: SqsBodyFormat,
}

/// Where the exclusion rules document lives and how long it is cached.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    #[serde(default = "default_rules_uri")]
    pub uri: String,
    #[serde(default = "default_rules_ttl_seconds")]
    pub ttl_seconds: u64,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            uri: default_rules_uri(),
            ttl_seconds: default_rules_ttl_seconds(),
        }
    }
}

/// Metrics sink selection and logging verbosity.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observability {
    #[serde(default)]
    pub metrics: MetricsMode,
    #[serde(default = "default_namespace")]
    pub namespace: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl Default for Observability {
    fn default() -> Self {
        Self {
            metrics: MetricsMode::default(),
            namespace: default_namespace(),
            log_level: default_log_level(),
        }
    }
}

/// The fully resolved settings document: file (if any) merged with `CT_*`
/// env overrides, validated. Held for the life of the container
/// (`Pipeline::new` takes an `Arc<Settings>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub source: Source,
    pub destination: Destination,
    pub processing: Processing,
    pub behavior: Behavior,
    pub sqs: Sqs,
    pub rules: Rules,
    pub observability: Observability,
}

/// The raw parse target: identical to `Settings` plus the schema-version
/// guard, which has no place in the resolved `Settings` (it is checked once,
/// here, and dropped).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    #[serde(default = "default_version")]
    version: i64,
    #[serde(default)]
    source: Source,
    #[serde(default)]
    destination: Destination,
    #[serde(default)]
    processing: Processing,
    #[serde(default)]
    behavior: Behavior,
    #[serde(default)]
    sqs: Sqs,
    #[serde(default)]
    rules: Rules,
    #[serde(default)]
    observability: Observability,
}

impl Default for Document {
    fn default() -> Self {
        Self {
            version: default_version(),
            source: Source::default(),
            destination: Destination::default(),
            processing: Processing::default(),
            behavior: Behavior::default(),
            sqs: Sqs::default(),
            rules: Rules::default(),
            observability: Observability::default(),
        }
    }
}

/// Parse `key`'s value out of `env` and apply it to `settings` via `f`,
/// short-circuiting with a `ConfigError` that names the offending key on a
/// bad value. A no-op when `key` is unset — env overrides are opt-in per
/// field, file (or built-in default) value stands otherwise.
fn apply<T>(
    env: &dyn Fn(&str) -> Option<String>,
    key: &str,
    set: impl FnOnce(T),
) -> Result<(), ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    if let Some(raw) = env(key) {
        let value = raw
            .parse::<T>()
            .map_err(|e| ConfigError::Parse(format!("invalid {key}={raw:?}: {e}")))?;
        set(value);
    }
    Ok(())
}

impl Document {
    fn apply_env(&mut self, env: &dyn Fn(&str) -> Option<String>) -> Result<(), ConfigError> {
        apply(env, "CT_DEST_BUCKET", |v| self.destination.bucket = v)?;
        apply(env, "CT_KEY_PREFIX", |v| self.destination.key_prefix = v)?;
        apply(env, "CT_SOURCE_INCLUDE_KEY_REGEX", |v| {
            self.source.include_key_regex = v
        })?;
        apply(env, "CT_SOURCE_EXCLUDE_KEY_REGEX", |v| {
            self.source.exclude_key_regex = v
        })?;
        apply(env, "CT_PROCESSING_MODE", |v| self.processing.mode = v)?;
        apply(env, "CT_STREAM_THRESHOLD_BYTES", |v| {
            self.processing.stream_threshold_bytes = v
        })?;
        apply(env, "CT_MAX_OBJECT_BYTES", |v| {
            self.processing.max_object_bytes = v
        })?;
        apply(env, "CT_MULTIPART_PART_BYTES", |v| {
            self.processing.multipart_part_bytes = v
        })?;
        apply(env, "CT_GZIP_LEVEL", |v| self.processing.gzip_level = v)?;
        apply(env, "CT_DRY_RUN", |v| self.behavior.dry_run = v)?;
        apply(env, "CT_ON_CONFIG_ERROR", |v| {
            self.behavior.on_config_error = v
        })?;
        apply(env, "CT_ON_MISSING_OBJECT", |v| {
            self.behavior.on_missing_object = v
        })?;
        apply(env, "CT_ON_UNRECOGNIZED_OBJECT", |v| {
            self.behavior.on_unrecognized_object = v
        })?;
        apply(env, "CT_PARTIAL_BATCH_FAILURES", |v| {
            self.behavior.partial_batch_failures = v
        })?;
        apply(env, "CT_SQS_BODY_FORMAT", |v| self.sqs.body_format = v)?;
        apply(env, "CT_RULES_URI", |v| self.rules.uri = v)?;
        apply(env, "CT_RULES_TTL_SECONDS", |v| self.rules.ttl_seconds = v)?;
        apply(env, "CT_METRICS", |v| self.observability.metrics = v)?;
        apply(env, "CT_METRICS_NAMESPACE", |v| {
            self.observability.namespace = v
        })?;
        apply(env, "CT_LOG_LEVEL", |v| self.observability.log_level = v)?;
        Ok(())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.version != 1 {
            return Err(ConfigError::Parse(format!(
                "unsupported settings version {}: must be 1 (this is a plain integer, not semver)",
                self.version
            )));
        }
        if self.destination.bucket.is_empty() {
            return Err(ConfigError::Parse(
                "destination.bucket is required: set it in the settings file or via \
                 CT_DEST_BUCKET"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn into_settings(self) -> Settings {
        Settings {
            source: self.source,
            destination: self.destination,
            processing: self.processing,
            behavior: self.behavior,
            sqs: self.sqs,
            rules: self.rules,
            observability: self.observability,
        }
    }
}

impl Settings {
    /// Production entry point: reads `SETTINGS_URI` and every `CT_*` var
    /// from the process environment.
    ///
    /// `SETTINGS_URI` is optional (an env-only deployment is valid). If set,
    /// only `file://` is resolved here — `core` has no `aws-sdk-*`
    /// dependency (`SHARED.md`), so an `s3://`/`ssm://` settings URI needs a
    /// composition root that can reach those services and hand this
    /// function the fetched bytes instead.
    pub async fn load() -> Result<Settings, ConfigError> {
        let bytes = match std::env::var("SETTINGS_URI") {
            Ok(uri) => Some(read_settings_uri(&uri)?),
            Err(_) => None,
        };
        Self::from_parts(bytes.as_deref(), &|key| std::env::var(key).ok())
    }

    /// Parse `bytes` (or fall back to built-in defaults when `None`), apply
    /// `env` overrides, and validate. Pure function of its arguments — no
    /// process environment or filesystem access — so every override and
    /// default combination is directly testable without `std::env` global
    /// state.
    fn from_parts(
        bytes: Option<&[u8]>,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Settings, ConfigError> {
        let mut doc: Document = match bytes {
            Some(b) => {
                serde_yaml_ng::from_slice(b).map_err(|e| ConfigError::Parse(e.to_string()))?
            }
            None => Document::default(),
        };
        doc.apply_env(env)?;
        doc.validate()?;
        Ok(doc.into_settings())
    }
}

fn read_settings_uri(uri: &str) -> Result<Vec<u8>, ConfigError> {
    let path = uri.strip_prefix("file://").ok_or_else(|| {
        ConfigError::Source(format!(
            "unsupported SETTINGS_URI scheme {uri:?}: core has no AWS SDK dependency, so only \
             file:// is resolvable without a composition root fetching bytes for it"
        ))
    })?;
    std::fs::read(path).map_err(|e| ConfigError::Source(format!("failed to read {uri:?}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const EXAMPLE_SETTINGS: &[u8] = include_bytes!("../../tests/fixtures/settings.example.yaml");

    fn env_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn no_env(_key: &str) -> Option<String> {
        None
    }

    #[test]
    fn parses_example_settings_file() {
        let settings = Settings::from_parts(Some(EXAMPLE_SETTINGS), &no_env)
            .expect("example settings must parse");

        assert_eq!(settings.source.include_key_regex, r"\.json\.gz$");
        assert_eq!(
            settings.source.exclude_key_regex,
            r"(/CloudTrail-Digest/|/CloudTrail-Insight/|/$)"
        );
        assert_eq!(settings.destination.bucket, "ct-siem-sync");
        assert_eq!(settings.destination.key_prefix, "");
        assert_eq!(settings.processing.mode, ProcessingMode::Auto);
        assert_eq!(settings.processing.stream_threshold_bytes, 8_388_608);
        assert_eq!(settings.processing.max_object_bytes, 134_217_728);
        assert_eq!(settings.processing.multipart_part_bytes, 8_388_608);
        assert_eq!(settings.processing.gzip_level, 6);
        assert!(!settings.behavior.dry_run);
        assert_eq!(settings.behavior.on_config_error, OnConfigError::Open);
        assert_eq!(settings.behavior.on_missing_object, OnMissingObject::Error);
        assert_eq!(
            settings.behavior.on_unrecognized_object,
            OnUnrecognizedObject::Copy
        );
        assert!(settings.behavior.partial_batch_failures);
        assert_eq!(settings.sqs.body_format, SqsBodyFormat::Auto);
        assert_eq!(settings.rules.uri, "s3://sec-config/cloudtrail/rules.yaml");
        assert_eq!(settings.rules.ttl_seconds, 300);
        assert_eq!(settings.observability.metrics, MetricsMode::Emf);
        assert_eq!(settings.observability.namespace, "cloudtrail-rs");
        assert_eq!(settings.observability.log_level, "info");
    }

    #[test]
    fn every_documented_default_holds_with_no_file() {
        let env = env_map(&[("CT_DEST_BUCKET", "only-the-required-bucket")]);
        let settings = Settings::from_parts(None, &|k| env.get(k).cloned())
            .expect("no-file load with CT_DEST_BUCKET must succeed");

        assert_eq!(settings.destination.bucket, "only-the-required-bucket");
        assert_eq!(settings.source.include_key_regex, r"\.json\.gz$");
        assert_eq!(
            settings.source.exclude_key_regex,
            r"(/CloudTrail-Digest/|/CloudTrail-Insight/|/$)"
        );
        assert_eq!(settings.destination.key_prefix, "");
        assert_eq!(settings.processing.mode, ProcessingMode::Auto);
        assert_eq!(settings.processing.stream_threshold_bytes, 8_388_608);
        assert_eq!(settings.processing.max_object_bytes, 134_217_728);
        assert_eq!(settings.processing.multipart_part_bytes, 8_388_608);
        assert_eq!(settings.processing.gzip_level, 6);
        assert!(!settings.behavior.dry_run);
        assert_eq!(settings.behavior.on_config_error, OnConfigError::Open);
        assert_eq!(settings.behavior.on_missing_object, OnMissingObject::Error);
        assert_eq!(
            settings.behavior.on_unrecognized_object,
            OnUnrecognizedObject::Copy
        );
        assert!(settings.behavior.partial_batch_failures);
        assert_eq!(settings.sqs.body_format, SqsBodyFormat::Auto);
        assert_eq!(settings.rules.uri, "s3://sec-config/cloudtrail/rules.yaml");
        assert_eq!(settings.rules.ttl_seconds, 300);
        assert_eq!(settings.observability.metrics, MetricsMode::Emf);
        assert_eq!(settings.observability.namespace, "cloudtrail-rs");
        assert_eq!(settings.observability.log_level, "info");
    }

    #[test]
    fn loads_with_no_file_when_ct_dest_bucket_is_set() {
        let env = env_map(&[("CT_DEST_BUCKET", "env-only-bucket")]);
        let settings = Settings::from_parts(None, &|k| env.get(k).cloned())
            .expect("CT_DEST_BUCKET alone must be enough with no file");
        assert_eq!(settings.destination.bucket, "env-only-bucket");
    }

    #[test]
    fn missing_destination_bucket_is_a_hard_error() {
        let err = Settings::from_parts(None, &no_env)
            .expect_err("no file and no CT_DEST_BUCKET must fail");
        assert!(matches!(err, crate::error::ConfigError::Parse(_)));
    }

    #[test]
    fn every_ct_var_overrides_its_file_value() {
        let env = env_map(&[
            ("CT_DEST_BUCKET", "overridden-bucket"),
            ("CT_KEY_PREFIX", "overridden/"),
            ("CT_SOURCE_INCLUDE_KEY_REGEX", "overridden-include$"),
            ("CT_SOURCE_EXCLUDE_KEY_REGEX", "overridden-exclude$"),
            ("CT_PROCESSING_MODE", "stream"),
            ("CT_STREAM_THRESHOLD_BYTES", "1"),
            ("CT_MAX_OBJECT_BYTES", "2"),
            ("CT_MULTIPART_PART_BYTES", "3"),
            ("CT_GZIP_LEVEL", "9"),
            ("CT_DRY_RUN", "true"),
            ("CT_ON_CONFIG_ERROR", "closed"),
            ("CT_ON_MISSING_OBJECT", "skip"),
            ("CT_ON_UNRECOGNIZED_OBJECT", "error"),
            ("CT_PARTIAL_BATCH_FAILURES", "false"),
            ("CT_SQS_BODY_FORMAT", "sns"),
            ("CT_RULES_URI", "file:///tmp/overridden-rules.yaml"),
            ("CT_RULES_TTL_SECONDS", "42"),
            ("CT_METRICS", "none"),
            ("CT_METRICS_NAMESPACE", "overridden-namespace"),
            ("CT_LOG_LEVEL", "debug"),
        ]);

        let settings = Settings::from_parts(Some(EXAMPLE_SETTINGS), &|k| env.get(k).cloned())
            .expect("fully overridden settings must still load");

        assert_eq!(settings.destination.bucket, "overridden-bucket");
        assert_eq!(settings.destination.key_prefix, "overridden/");
        assert_eq!(settings.source.include_key_regex, "overridden-include$");
        assert_eq!(settings.source.exclude_key_regex, "overridden-exclude$");
        assert_eq!(settings.processing.mode, ProcessingMode::Stream);
        assert_eq!(settings.processing.stream_threshold_bytes, 1);
        assert_eq!(settings.processing.max_object_bytes, 2);
        assert_eq!(settings.processing.multipart_part_bytes, 3);
        assert_eq!(settings.processing.gzip_level, 9);
        assert!(settings.behavior.dry_run);
        assert_eq!(settings.behavior.on_config_error, OnConfigError::Closed);
        assert_eq!(settings.behavior.on_missing_object, OnMissingObject::Skip);
        assert_eq!(
            settings.behavior.on_unrecognized_object,
            OnUnrecognizedObject::Error
        );
        assert!(!settings.behavior.partial_batch_failures);
        assert_eq!(settings.sqs.body_format, SqsBodyFormat::Sns);
        assert_eq!(settings.rules.uri, "file:///tmp/overridden-rules.yaml");
        assert_eq!(settings.rules.ttl_seconds, 42);
        assert_eq!(settings.observability.metrics, MetricsMode::None);
        assert_eq!(settings.observability.namespace, "overridden-namespace");
        assert_eq!(settings.observability.log_level, "debug");
    }

    #[test]
    fn rejects_version_other_than_one() {
        let yaml = b"version: 2\ndestination:\n  bucket: b\n";
        let err =
            Settings::from_parts(Some(yaml), &no_env).expect_err("version 2 must be rejected");
        assert!(matches!(err, crate::error::ConfigError::Parse(_)));
    }

    #[test]
    fn rejects_non_integer_version() {
        let yaml = b"version: \"1\"\ndestination:\n  bucket: b\n";
        let err = Settings::from_parts(Some(yaml), &no_env).expect_err(
            "a string version must be rejected: version is an integer here, not semver",
        );
        assert!(matches!(err, crate::error::ConfigError::Parse(_)));
    }

    #[test]
    fn rejects_unknown_field() {
        let yaml = b"version: 1\ndestination:\n  bucket: b\n  bogus: true\n";
        let err =
            Settings::from_parts(Some(yaml), &no_env).expect_err("unknown field must be rejected");
        assert!(matches!(err, crate::error::ConfigError::Parse(_)));
    }
}
