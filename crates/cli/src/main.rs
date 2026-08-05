//! `cloudtrail-rs` — local/offline CLI companion to the Lambda binaries
//! (task 17).
//!
//! Depends on `cloudtrail-rs-core` **and** `cloudtrail-rs-aws` so a rules
//! `uri` may be `ssm://`, `s3://`, `file://`, or a bare local path.
//!
//! Four subcommands, all reusing `core`'s existing engine/process/config
//! logic — nothing here reimplements filtering or validation:
//! - `validate <uri>`: builds the `Engine`, prints rule/pattern counts, and
//!   warns (non-fatally) about every rule `Engine::always_rules()` could not
//!   index. Non-zero exit on a config/build error; `--max-unindexed` adds an
//!   opt-in CI gate on top of that.
//! - `test <rules> <sample.json.gz>`: per-record KEEP/DROP against the
//!   compiled ruleset, plus a summary, so dead rules are visible.
//! - `filter <source> <dest> --rules <uri> [--settings <path>]`:
//!   local/backfill filtering, via `core::process::{buffer_run, stream_run}`
//!   directly. Each of `source` and `dest` is auto-detected as a local path
//!   or an `s3://bucket/prefix` URI; a local directory or an `s3://` prefix
//!   triggers batch mode (every in-scope object filtered into a mirrored
//!   destination), so filtering is visible on the local filesystem and the
//!   same command works against S3 when AWS credentials are present.
//!   `--settings` makes a backfill use the *deployment's* own
//!   `processing.*`/`source.*`/`behavior.*` values instead of built-in
//!   defaults — see [`FilterConfig`].
//! - `validate-settings [path]`: runs a settings document through the exact
//!   `Settings::from_parts` validation the Lambda binaries run at cold
//!   start, so a bad value that would otherwise panic mid-invocation is
//!   caught pre-deploy. Honours `CT_*` env overrides same as production.
#![forbid(unsafe_code)]

use std::io::Read;
use std::path::{Component, Path, PathBuf};

use anyhow::Context;
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use bytes::Bytes;
use clap::{Parser, Subcommand};
use cloudtrail_rs_aws::{S3ConfigSource, S3ObjectStore, SsmConfigSource, load_aws_config};
use cloudtrail_rs_core::config::{
    Behavior, ConfigUri, KeyFilter, OnUnrecognizedObject, Processing, ProcessingMode, RuleSet,
    Settings, Source,
};
use cloudtrail_rs_core::error::{CoreError, StoreError};
use cloudtrail_rs_core::filter::{Decision, Engine};
use cloudtrail_rs_core::metrics::Metrics;
use cloudtrail_rs_core::model::PutMeta;
use cloudtrail_rs_core::ports::{ConfigSource, ObjectStore};
use cloudtrail_rs_core::process::{DiscardStore, Outcome, RecordTally, buffer_run, stream_run};
use flate2::read::MultiGzDecoder;

/// Object metadata for every gzip object this CLI writes to S3, matching the
/// canonical `PutMeta` the Lambda pipeline uses.
const GZIP_META: PutMeta = PutMeta {
    content_type: "application/x-gzip",
    content_encoding: "gzip",
};

#[derive(Parser)]
#[command(
    name = "cloudtrail-rs",
    about = "Local tooling for cloudtrail-rs exclusion rules",
    version = cloudtrail_rs_core::build_info::LONG
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build the Engine from a rules document; report rule/pattern counts
    /// and warn about every rule that could not be indexed by eventSource or
    /// eventName.
    Validate {
        /// `ssm://`, `s3://`, `file://`, or a bare local path.
        uri: String,
        /// Fail (exit 1) if more than this percentage of rules could not be
        /// indexed. Omit for no gate. Intended for CI: an un-indexed ruleset
        /// still works, but checks every rule against every record.
        #[arg(long, value_name = "PERCENT")]
        max_unindexed: Option<u8>,
    },
    /// Evaluate every record in a decompressed CloudTrail sample against a
    /// ruleset, reporting KEEP/DROP (with rule name) per record plus a
    /// summary.
    Test {
        /// `ssm://`, `s3://`, `file://`, or a bare local path.
        rules: String,
        /// Local `.json.gz` sample (a gzip'd `{"Records": [...]}` envelope).
        sample: PathBuf,
    },
    /// Filter CloudTrail gzip objects through `core::process::{buffer_run,
    /// stream_run}` — the same two processors the Lambda runs.
    ///
    /// `source` and `dest` are each a local path or an `s3://bucket/prefix`
    /// URI. A single local **file** filters that one object to `dest`. A
    /// local **directory** or any `s3://` prefix filters every in-scope
    /// object under it, mirroring the relative path into `dest` (which may
    /// itself be a local directory or an `s3://` prefix). Objects with all
    /// records dropped are not written ("zero empty writes").
    ///
    /// A failing object does not stop the run: the batch continues, the
    /// summary still prints, and the failures are listed at the end with a
    /// non-zero exit.
    Filter {
        /// Local file/directory, or `s3://bucket/prefix`.
        source: String,
        /// Local file/directory, or `s3://bucket/prefix`.
        dest: String,
        /// `ssm://`, `s3://`, `file://`, or a bare local path.
        #[arg(long)]
        rules: String,
        /// The deployment's settings YAML, so a backfill uses the same
        /// `processing.*` (mode, thresholds, gzip level), `source.*` (which
        /// keys are in scope), and `behavior.*` (dry run, unrecognized-object
        /// policy) values production does. Omit for built-in defaults.
        #[arg(long)]
        settings: Option<PathBuf>,
    },
    /// Load a settings document and run the exact validation the Lambda
    /// binaries run at cold start (`Settings::from_parts`), so a bad value
    /// that would otherwise panic mid-invocation — `gzip_level` out of
    /// range, an uncompilable key regex, `max_object_bytes` smaller than
    /// `stream_threshold_bytes`, `multipart_part_bytes` below S3's 5 MiB
    /// minimum — is caught pre-deploy instead. Prints a summary of the
    /// effective settings on success; exits non-zero with the error on
    /// failure.
    ValidateSettings {
        /// Local settings YAML file. Omit to validate built-in defaults
        /// (plus any `CT_*` env overrides) — a valid env-only deployment.
        path: Option<PathBuf>,
    },
}

/// A filesystem path or an `s3://bucket/prefix` URI. `filter`'s source and
/// destination are each one of these, so a single command moves objects
/// local→local, local→s3, s3→local, or s3→s3.
enum Location {
    Local(PathBuf),
    S3 { bucket: String, prefix: String },
}

impl Location {
    fn parse(s: &str) -> anyhow::Result<Self> {
        if let Some(rest) = s.strip_prefix("s3://") {
            let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
            if bucket.is_empty() {
                anyhow::bail!("invalid s3 uri {s:?}: missing bucket");
            }
            Ok(Location::S3 {
                bucket: bucket.to_string(),
                prefix: prefix.to_string(),
            })
        } else {
            Ok(Location::Local(PathBuf::from(s)))
        }
    }

    fn is_s3(&self) -> bool {
        matches!(self, Location::S3 { .. })
    }

    /// The bucket to address this side's `ObjectStore` with. Empty for a
    /// local side: [`LocalObjectStore`] ignores it and treats the key as a
    /// filesystem path.
    fn bucket(&self) -> &str {
        match self {
            Location::Local(_) => "",
            Location::S3 { bucket, .. } => bucket,
        }
    }

    /// How a `bucket`/`key` on this side is shown in progress lines.
    fn display(&self, key: &str) -> String {
        match self {
            Location::Local(_) => key.to_string(),
            Location::S3 { bucket, .. } => format!("s3://{bucket}/{key}"),
        }
    }
}

/// One source object queued for filtering: `fetch` is the store key that
/// reads its bytes (a local path or a full S3 key); `rel` is the path used
/// to mirror it into the destination; `size` is its *compressed* size when
/// cheaply known, which is what picks buffer vs. stream in `auto` mode.
///
/// `size` is `None` for an S3 source: `ListObjectsV2` sizes are not carried
/// through `S3ObjectStore::list_keys`, and an unknown size means buffer mode
/// — the same conservative choice `Pipeline::select_mode` makes when an
/// event carries no size (safety invariant 5). Nothing is lost by it: an
/// object too large to buffer is retried through stream mode below, exactly
/// as the pipeline retries it.
struct SrcObject {
    fetch: String,
    rel: String,
    size: Option<u64>,
}

/// The parts of a settings document `filter` honours, resolved once per run.
///
/// Scope is deliberate — these are the settings that change *what a backfill
/// selects and writes*:
/// - `processing.*` — mode, `stream_threshold_bytes`, `max_object_bytes`,
///   `multipart_part_bytes`, `gzip_level`.
/// - `source.*` — via [`KeyFilter`], which objects are in scope at all.
/// - `behavior.dry_run` — evaluate and report, write nothing.
/// - `behavior.on_unrecognized_object` — copy / skip / error.
///
/// The rest is Lambda-only and ignored here: `destination.*` (the `dest`
/// argument is the destination), `rules.*` (`--rules` is), `sqs.*`,
/// `behavior.on_config_error` and `behavior.partial_batch_failures` (no
/// event source, no batch to fail), `behavior.on_missing_object` (objects
/// are enumerated, not named by an event), and `observability.*`.
struct FilterConfig {
    processing: Processing,
    keys: KeyFilter,
    dry_run: bool,
    on_unrecognized: OnUnrecognizedObject,
}

impl FilterConfig {
    /// `Some(path)` runs the document through the exact production
    /// `Settings::from_parts` validation (`CT_*` overrides included);
    /// `None` is built-in defaults. Defaults are assembled from the same
    /// `Default` impls `Settings` parses into rather than through
    /// `from_parts`, because `from_parts` requires a `destination.bucket`
    /// that a CLI run has no use for — `dest` is the destination.
    fn resolve(path: Option<&Path>) -> anyhow::Result<Self> {
        let (source, processing, behavior) = match path {
            Some(p) => {
                let s = load_and_validate_settings(Some(p))?;
                (s.source, s.processing, s.behavior)
            }
            None => (
                Source::default(),
                Processing::default(),
                Behavior::default(),
            ),
        };
        Ok(Self {
            keys: KeyFilter::compile(&source)?,
            processing,
            dry_run: behavior.dry_run,
            on_unrecognized: behavior.on_unrecognized_object,
        })
    }

    /// Buffer vs. stream for an object of (compressed) `size` — the same
    /// decision `Pipeline::select_mode` makes, including the missing-size
    /// fallback to buffer.
    fn select_mode(&self, size: Option<u64>) -> Mode {
        match self.processing.mode {
            ProcessingMode::Buffer => Mode::Buffer,
            ProcessingMode::Stream => Mode::Stream,
            ProcessingMode::Auto => match size {
                Some(sz) if sz > self.processing.stream_threshold_bytes => Mode::Stream,
                _ => Mode::Buffer,
            },
        }
    }
}

/// The resolved per-object mode: `auto` is a decision, not a mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Buffer,
    Stream,
}

/// `core`'s `ObjectStore` port over the local filesystem, so the local side
/// of a `filter` run is addressed exactly like the S3 side and `stream_run`
/// — which writes through the port — works against a local destination too.
/// `bucket` is meaningless locally and ignored; `key` is the path.
struct LocalObjectStore;

impl LocalObjectStore {
    fn create_parent(key: &str) -> Result<(), StoreError> {
        if let Some(parent) = Path::new(key).parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| {
                StoreError::Backend(format!("failed to create directory {parent:?}: {e}"))
            })?;
        }
        Ok(())
    }

    fn io_error(key: &str, what: &str, e: std::io::Error) -> StoreError {
        if e.kind() == std::io::ErrorKind::NotFound {
            StoreError::NotFound {
                bucket: String::new(),
                key: key.to_string(),
            }
        } else {
            StoreError::Backend(format!("failed to {what} {key:?}: {e}"))
        }
    }
}

#[async_trait]
impl ObjectStore for LocalObjectStore {
    async fn get(&self, _bucket: &str, key: &str) -> Result<Bytes, StoreError> {
        tokio::fs::read(key)
            .await
            .map(Bytes::from)
            .map_err(|e| Self::io_error(key, "read", e))
    }

    async fn get_stream(
        &self,
        _bucket: &str,
        key: &str,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, StoreError> {
        let file = tokio::fs::File::open(key)
            .await
            .map_err(|e| Self::io_error(key, "open", e))?;
        Ok(Box::new(file))
    }

    async fn put(
        &self,
        _bucket: &str,
        key: &str,
        body: Bytes,
        _meta: PutMeta,
    ) -> Result<(), StoreError> {
        Self::create_parent(key)?;
        tokio::fs::write(key, &body)
            .await
            .map_err(|e| Self::io_error(key, "write", e))
    }

    /// Writes through a temporary sibling and renames on success, so an
    /// aborted stream leaves *nothing* at `key`. `stream_run` signals
    /// "abandon this upload" by failing the reader mid-flight (all records
    /// dropped, an unrecognized object, a parse failure); writing `key`
    /// directly would leave a truncated or zero-record object behind, which
    /// the whole design exists to prevent.
    async fn put_stream(
        &self,
        _bucket: &str,
        key: &str,
        mut body: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        _meta: PutMeta,
    ) -> Result<(), StoreError> {
        Self::create_parent(key)?;
        let partial = format!("{key}.{}.partial", std::process::id());

        let mut file = tokio::fs::File::create(&partial)
            .await
            .map_err(|e| Self::io_error(&partial, "create", e))?;

        let copied = tokio::io::copy(&mut body, &mut file).await;
        // Close before renaming: the rename must not race the last write.
        drop(file);

        match copied {
            Ok(_) => tokio::fs::rename(&partial, key)
                .await
                .map_err(|e| Self::io_error(key, "rename into", e)),
            Err(e) => {
                let _ = tokio::fs::remove_file(&partial).await;
                Err(StoreError::Backend(format!(
                    "streaming write to {key:?} aborted: {e}"
                )))
            }
        }
    }
}

/// Resolves a rules `uri` to raw bytes. A bare path with no `scheme://` is
/// read directly off disk — the ergonomic case for `validate
/// examples/rules.example.yaml` — otherwise the URI is dispatched to the
/// matching `ConfigSource` (`file://` locally, `s3://`/`ssm://` via the AWS
/// SDK, credentials resolved lazily so a local/file invocation never pays
/// for it).
async fn load_rules_bytes(uri: &str) -> anyhow::Result<Vec<u8>> {
    if !uri.contains("://") {
        return std::fs::read(uri).with_context(|| format!("failed to read {uri:?}"));
    }
    match ConfigUri::parse(uri)? {
        ConfigUri::File { path } => {
            std::fs::read(&path).with_context(|| format!("failed to read {path:?}"))
        }
        ConfigUri::S3 { bucket, key } => {
            let conf = load_aws_config(BehaviorVersion::latest()).await;
            let source = S3ConfigSource::new(&conf, bucket, key);
            let (bytes, _version) = source.fetch().await?;
            Ok(bytes)
        }
        ConfigUri::Ssm { path } => {
            let conf = load_aws_config(BehaviorVersion::latest()).await;
            let source = SsmConfigSource::new(&conf, path);
            let (bytes, _version) = source.fetch().await?;
            Ok(bytes)
        }
    }
}

/// Builds an `Engine` from a rules `uri`, along with the `RuleSet` it was
/// built from (`Engine::new` consumes its `RuleSet`, but `validate` needs
/// the original rule/match data to explain each `always_rules()` entry).
async fn load_engine(uri: &str) -> anyhow::Result<(Engine, RuleSet)> {
    let bytes = load_rules_bytes(uri).await?;
    let rule_set = RuleSet::parse(&bytes)?;
    let engine = Engine::new(rule_set.clone())?;
    Ok((engine, rule_set))
}

/// Names the rule at `rule_idx` and explains, in prose, why the rule index
/// could not narrow it on `eventSource` or `eventName` — either it has no
/// condition on either field, or the condition(s) it has are not one of the
/// two conservative shapes `Engine::new`'s index extraction accepts.
fn explain_always_rule(rule_set: &RuleSet, rule_idx: usize) -> String {
    let name = &rule_set.rules[rule_idx].name;
    match rule_set.index_key_description(rule_idx) {
        Some(described) => format!(
            "warning: rule {name:?} not indexed ({described} could not be reduced to a fixed \
             set of literals): checked against every record"
        ),
        None => format!(
            "warning: rule {name:?} not indexed (no eventSource or eventName condition): \
             checked against every record"
        ),
    }
}

async fn cmd_validate(uri: &str, max_unindexed: Option<u8>) -> anyhow::Result<()> {
    let (engine, rule_set) = load_engine(uri).await?;

    let rule_count = rule_set.rules.len();
    let pattern_count: usize = rule_set.rules.iter().map(|r| r.matches.len()).sum();
    println!("{rule_count} rules, {pattern_count} patterns compiled");

    for &rule_idx in engine.always_rules() {
        eprintln!("{}", explain_always_rule(&rule_set, rule_idx));
    }

    let unindexed = engine.always_rules().len();
    if let Some(ceiling) = max_unindexed {
        // Integer percentage, rounded up, so "1 of 3 unindexed" is 34% and
        // trips a 33% ceiling rather than silently passing it.
        let percent = if rule_count == 0 {
            0
        } else {
            unindexed.saturating_mul(100).div_ceil(rule_count)
        };
        if percent > usize::from(ceiling) {
            anyhow::bail!(
                "{unindexed} of {rule_count} rules ({percent}%) could not be indexed, \
                 exceeding --max-unindexed {ceiling}"
            );
        }
    }

    Ok(())
}

/// The envelope shape a decompressed CloudTrail sample must have: a
/// `Records` array. Unlike `buffer_run`'s `Envelope`, this is a plain,
/// already-parsed `Vec<Value>` — `test` reports every record individually
/// and has no need for the raw-byte-preserving `RawValue` trick that only
/// matters when re-emitting survivors verbatim.
#[derive(serde::Deserialize)]
struct Sample {
    #[serde(rename = "Records")]
    records: Vec<serde_json::Value>,
}

async fn cmd_test(rules_uri: &str, sample_path: &Path) -> anyhow::Result<()> {
    let (engine, _rule_set) = load_engine(rules_uri).await?;

    let gz_bytes =
        std::fs::read(sample_path).with_context(|| format!("failed to read {sample_path:?}"))?;
    let mut decompressed = Vec::new();
    MultiGzDecoder::new(gz_bytes.as_slice())
        .read_to_end(&mut decompressed)
        .with_context(|| format!("failed to decompress {sample_path:?}"))?;
    let sample: Sample = serde_json::from_slice(&decompressed).with_context(|| {
        format!("{sample_path:?} is not a valid {{\"Records\": [...]}} envelope")
    })?;

    let mut kept = 0usize;
    let mut dropped = 0usize;
    for (i, record) in sample.records.iter().enumerate() {
        match engine.evaluate(record) {
            Decision::Keep => {
                kept += 1;
                println!("KEEP  record {}", i + 1);
            }
            Decision::Drop { rule_idx } => {
                dropped += 1;
                println!(
                    "DROP  record {} (rule: \"{}\")",
                    i + 1,
                    engine.rule_name(rule_idx)
                );
            }
        }
    }

    let total = kept + dropped;
    let pct = |n: usize| -> f64 {
        if total == 0 {
            0.0
        } else {
            n as f64 * 100.0 / total as f64
        }
    };
    println!(
        "summary: {total} records, {kept} kept ({:.1}%), {dropped} dropped ({:.1}%)",
        pct(kept),
        pct(dropped)
    );

    Ok(())
}

/// The "directory" portion of an S3 prefix — everything up to and including
/// its last `/`. Stripping this from a listed key yields the relative key to
/// mirror into the destination, so both a directory-style prefix
/// (`logs/`) and an exact object key (`logs/x.json.gz`) relativize sensibly.
fn dir_prefix(prefix: &str) -> String {
    match prefix.rfind('/') {
        Some(i) => prefix[..=i].to_string(),
        None => String::new(),
    }
}

/// Joins a destination prefix and a relative key into a full S3 key.
fn join_key(prefix: &str, rel: &str) -> String {
    if prefix.is_empty() {
        rel.to_string()
    } else {
        format!("{}/{}", prefix.trim_end_matches('/'), rel)
    }
}

/// Recursively collects in-scope objects under `dir`, recording each one's
/// path relative to `root` (with `/` separators) as its `rel`. `rel` is what
/// `keys` is matched against — locally there is no S3 key, and `rel` is the
/// closest analogue of one.
fn collect_local(
    root: &Path,
    dir: &Path,
    keys: &KeyFilter,
    out: &mut Vec<SrcObject>,
) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("failed to read dir {dir:?}"))? {
        let path = entry?.path();
        if path.is_dir() {
            collect_local(root, &path, keys, out)?;
        } else {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            if keys.allows(&rel) {
                out.push(SrcObject {
                    fetch: path.to_string_lossy().into_owned(),
                    rel,
                    size: std::fs::metadata(&path).ok().map(|m| m.len()),
                });
            }
        }
    }
    Ok(())
}

/// Enumerates every in-scope source object under a batch source (a local
/// directory or an `s3://` prefix), sorted by relative key for deterministic
/// output. In scope means exactly what it means in production: the
/// deployment's `source.include_key_regex`/`exclude_key_regex`, compiled
/// into the same [`KeyFilter`] the pipeline applies before any `GetObject`.
async fn enumerate(
    src: &Location,
    keys: &KeyFilter,
    s3: &Option<S3ObjectStore>,
) -> anyhow::Result<Vec<SrcObject>> {
    let mut objs = match src {
        Location::Local(root) => {
            let mut objs = Vec::new();
            collect_local(root, root, keys, &mut objs)?;
            objs
        }
        Location::S3 { bucket, prefix } => {
            let store = s3.as_ref().expect("s3 store built when a side is s3");
            let dir = dir_prefix(prefix);
            store
                .list_keys(bucket, prefix)
                .await?
                .into_iter()
                .filter(|k| keys.allows(k))
                .map(|k| {
                    let rel = k
                        .strip_prefix(dir.as_str())
                        .unwrap_or(k.as_str())
                        .to_string();
                    SrcObject {
                        fetch: k,
                        rel,
                        size: None,
                    }
                })
                .collect()
        }
    };
    objs.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(objs)
}

/// Builds one S3 client (credential chain resolved once) if either side is
/// S3; a purely local run never touches AWS.
async fn build_s3_if_needed(src: &Location, dst: &Location) -> Option<S3ObjectStore> {
    if src.is_s3() || dst.is_s3() {
        let conf = load_aws_config(BehaviorVersion::latest()).await;
        Some(S3ObjectStore::new(&conf))
    } else {
        None
    }
}

/// What became of one object. Every variant carries enough to print the
/// object's progress line without re-deriving where it went.
enum ObjectOutcome {
    Written(String),
    NothingKept,
    Copied(String),
    Skipped,
    DryRun,
}

/// Rejects a relative key that would escape the destination root once
/// joined to it, and returns the safe, root-relative `PathBuf` otherwise.
///
/// `rel` may come from an S3 key (`enumerate`'s `Location::S3` branch: a
/// naive `strip_prefix` of an attacker-controlled key, reachable by anyone
/// with `s3:PutObject` on the source bucket) or a local directory walk. Two
/// escapes matter, and only a per-component check catches both:
/// - `..` components (`Component::ParentDir`) walk back out of the root.
/// - A `rel` that is itself absolute (`Component::RootDir`) — e.g. an S3 key
///   `logs//etc/cron.d/x.json.gz` strips its `logs/` prefix down to
///   `/etc/cron.d/x.json.gz` because of the doubled slash — is worse:
///   `Path::join` with an absolute path *discards* the base entirely, so the
///   write lands at the absolute path with no root prefix at all. Rust's
///   component parser collapses any run of leading slashes (one or many)
///   into a single `RootDir`, so this same check catches the doubled-slash
///   case without separately normalizing empty segments.
///
/// Requiring every component to be `Component::Normal` rejects both in one
/// pass, plus `.` (`CurDir`) and a Windows drive prefix, rather than
/// hand-rolling a string check for `".."` that would miss the absolute case.
fn contain_rel(rel: &str) -> anyhow::Result<PathBuf> {
    let mut safe = PathBuf::new();
    for component in Path::new(rel).components() {
        match component {
            Component::Normal(part) => safe.push(part),
            _ => anyhow::bail!("unsafe relative key {rel:?}: escapes the destination root"),
        }
    }
    Ok(safe)
}

/// The batch destination key for a source object's relative key.
///
/// Only the local-destination case needs the [`contain_rel`] containment
/// check: `join_key`'s `..` in an S3 key is a literal key-name character,
/// never traversal, so the S3 branch is untouched.
fn batch_dest_key(dst: &Location, rel: &str) -> anyhow::Result<String> {
    match dst {
        Location::Local(root) => {
            let safe_rel = contain_rel(rel)?;
            Ok(root.join(safe_rel).to_string_lossy().into_owned())
        }
        Location::S3 { prefix, .. } => Ok(join_key(prefix, rel)),
    }
}

/// The destination key when the source was a single named file. Local: the
/// exact path given. S3: the prefix is the full object key.
fn single_dest_key(dst: &Location) -> anyhow::Result<String> {
    match dst {
        Location::Local(path) => Ok(path.to_string_lossy().into_owned()),
        Location::S3 { prefix, .. } => {
            if prefix.is_empty() {
                anyhow::bail!("s3 destination for a single file needs a key, not just a bucket");
            }
            Ok(prefix.clone())
        }
    }
}

/// Everything a `filter` run needs to process one object, so the single-file
/// and batch paths share one implementation — and so that implementation can
/// mirror `Pipeline`'s per-object policy (mode selection, the auto-mode
/// stream retry, the unrecognized-object policy) instead of approximating it.
struct Filterer {
    engine: Engine,
    cfg: FilterConfig,
    metrics: Metrics,
    src: Location,
    dst: Location,
    local: LocalObjectStore,
    s3: Option<S3ObjectStore>,
}

impl Filterer {
    fn store(&self, loc: &Location) -> &dyn ObjectStore {
        match loc {
            Location::Local(_) => &self.local,
            Location::S3 { .. } => self.s3.as_ref().expect("s3 store built when a side is s3"),
        }
    }

    /// Refuses to filter an object over itself.
    ///
    /// `Pipeline` has `CoreError::SelfTrigger` for the deployment shape this
    /// mirrors (destination bucket == source bucket, same key), because
    /// writing the filtered object back over its input destroys the original
    /// and — in the Lambda's case — re-triggers itself. The CLI had no such
    /// guard, so `filter ./logs ./logs` rewrote a directory of CloudTrail
    /// objects in place, unrecoverably.
    ///
    /// Local paths are compared canonically (the destination need not exist
    /// yet, so its parent is canonicalized and the file name re-joined) —
    /// `./logs/x.gz` and `logs/x.gz` are the same file, and a string compare
    /// would have missed it.
    fn overwrites_source(&self, src_key: &str, dst_key: &str) -> bool {
        match (&self.src, &self.dst) {
            (Location::S3 { bucket: sb, .. }, Location::S3 { bucket: db, .. }) => {
                sb == db && src_key == dst_key
            }
            (Location::Local(_), Location::Local(_)) => {
                let canonical = |p: &Path| -> Option<PathBuf> {
                    std::fs::canonicalize(p).ok().or_else(|| {
                        let parent = std::fs::canonicalize(p.parent()?).ok()?;
                        Some(parent.join(p.file_name()?))
                    })
                };
                match (canonical(Path::new(src_key)), canonical(Path::new(dst_key))) {
                    (Some(s), Some(d)) => s == d,
                    _ => false,
                }
            }
            // Different backends: a local path and an S3 key are never the
            // same object.
            _ => false,
        }
    }

    /// Reads the source object with `processing.max_object_bytes` applied to
    /// the **fetch**, not merely to the decompressed body.
    ///
    /// `ObjectStore::get` is uncapped: it buffers whatever the object is.
    /// Using it here meant the CLI's own comment ("applied to the fetch and
    /// the decompressed body alike") and `docs/cli.md` described a cap that
    /// the code did not apply, and a multi-gigabyte object OOM-killed the
    /// process before `buffer_run` ever got the chance to reject it. This is
    /// the read `Pipeline::fetch_with_missing_policy` performs.
    async fn fetch_capped(&self, src_key: &str) -> Result<Bytes, CoreError> {
        use tokio::io::AsyncReadExt;

        let limit = self.cfg.processing.max_object_bytes;
        let bucket = self.src.bucket();
        let reader = self.store(&self.src).get_stream(bucket, src_key).await?;
        // `limit + 1` so exceeding the cap is detectable without ever holding
        // more than one byte past it.
        let mut buf = Vec::new();
        reader
            .take(limit + 1)
            .read_to_end(&mut buf)
            .await
            .map_err(|e| {
                CoreError::Store(StoreError::Backend(format!("reading {src_key}: {e}")))
            })?;
        if buf.len() as u64 > limit {
            return Err(CoreError::ObjectTooLarge { limit });
        }
        Ok(Bytes::from(buf))
    }

    /// The buffer-mode evaluation, up to but not including the write. Split
    /// out so the `auto` `ObjectTooLarge` → stream retry can match on one
    /// `CoreError` covering both the capped fetch and `buffer_run` — the two
    /// places that cap can be hit.
    async fn buffer_eval(&self, src_key: &str) -> Result<(Bytes, Outcome, RecordTally), CoreError> {
        let bytes = self.fetch_capped(src_key).await?;
        let (outcome, tally) = buffer_run(&bytes, &self.engine, &self.cfg.processing)?;
        Ok((bytes, outcome, tally))
    }

    async fn process(
        &self,
        src_key: &str,
        dst_key: &str,
        size: Option<u64>,
    ) -> anyhow::Result<ObjectOutcome> {
        if !self.cfg.dry_run && self.overwrites_source(src_key, dst_key) {
            anyhow::bail!(
                "refusing to write {} over its own source: pick a destination that is not \
                 the source",
                self.dst.display(dst_key)
            );
        }

        // `dry_run` selects the *destination*, not the mode. It used to
        // short-circuit here into buffer-mode evaluation, which made the one
        // setting meant for a pre-flight check the one setting whose verdict
        // could differ from the real run's: an object `mode: auto` would have
        // streamed failed the preview with `ObjectTooLarge`. Both dry run and
        // the real run now take the same `select_mode` and the same retry.
        let dry_run = self.cfg.dry_run;

        match self.cfg.select_mode(size) {
            Mode::Stream => {
                if dry_run {
                    self.process_dry_run_stream(src_key).await
                } else {
                    self.process_stream(src_key, dst_key).await
                }
            }
            Mode::Buffer => {
                let result = self.buffer_eval(src_key).await;
                match result {
                    // The same retry `Pipeline::process_object` performs:
                    // `stream_threshold_bytes` is a compressed-size estimate,
                    // so a highly compressible object can be routed to buffer
                    // mode and still blow `max_object_bytes` (buffer mode's
                    // memory cap, applied to the fetch and the decompressed
                    // body alike). Stream mode has no such cap. Only in
                    // `auto`: an explicit `mode: buffer` means the operator
                    // opted out of streaming, so the error must surface.
                    Err(CoreError::ObjectTooLarge { limit })
                        if self.cfg.processing.mode == ProcessingMode::Auto =>
                    {
                        eprintln!(
                            "  note: {src_key} exceeds max_object_bytes ({limit}); \
                             retrying via stream mode"
                        );
                        if dry_run {
                            self.process_dry_run_stream(src_key).await
                        } else {
                            self.process_stream(src_key, dst_key).await
                        }
                    }
                    Err(e) => Err(e.into()),
                    Ok((bytes, outcome, tally)) => {
                        let object_outcome = if dry_run {
                            // Nothing is written, so the object's fate is
                            // decided the moment `buffer_run` returns — but
                            // the outcome is still classified, so a preview
                            // reports the unrecognized objects the real run
                            // would copy or skip.
                            if matches!(outcome, Outcome::Unrecognized) {
                                self.metrics.add_unrecognized_objects(1);
                            }
                            ObjectOutcome::DryRun
                        } else {
                            match outcome {
                                Outcome::Written(Some(out)) => {
                                    ObjectOutcome::Written(self.put(dst_key, out).await?)
                                }
                                Outcome::NothingKept => ObjectOutcome::NothingKept,
                                Outcome::Unrecognized => {
                                    self.unrecognized(src_key, dst_key, Some(bytes)).await?
                                }
                                Outcome::Written(None) => {
                                    unreachable!(
                                        "buffer_run returns Written(Some(_)) when it writes"
                                    )
                                }
                            }
                        };
                        // Past the `put`, exactly as `Pipeline::process_buffer`
                        // does it: a write that failed must leave the records
                        // uncounted rather than report them as filtered.
                        tally.commit(&self.metrics, &self.engine);
                        Ok(object_outcome)
                    }
                }
            }
        }
    }

    /// `behavior.dry_run` in stream mode: the real `stream_run`, pointed at a
    /// [`DiscardStore`], so the preview reaches its verdict by taking the live
    /// run's path rather than through a second evaluator.
    ///
    /// `stream_run` publishes straight to the `Metrics` it is handed, so it is
    /// handed a scratch one and everything except `BytesOut` is folded back —
    /// those bytes went nowhere.
    async fn process_dry_run_stream(&self, src_key: &str) -> anyhow::Result<ObjectOutcome> {
        let reader = self
            .store(&self.src)
            .get_stream(self.src.bucket(), src_key)
            .await?;

        let scratch = Metrics::default();
        let outcome = stream_run(
            reader,
            &self.engine,
            &self.cfg.processing,
            &scratch,
            &DiscardStore,
            "",
            "",
        )
        .await;

        // Folded back before `?`: an object that failed mid-stream still read
        // the bytes it read. The record counters cannot leak from a failure —
        // `stream_run` commits its tally only past its own upload check, so a
        // failed object leaves the scratch counters at zero by construction.
        let snapshot = scratch.snapshot_and_reset();
        self.metrics.add_bytes_in(snapshot.bytes_in);
        self.metrics.add_records_in(snapshot.records_in);
        self.metrics.add_records_kept(snapshot.records_kept);
        self.metrics.add_records_dropped(snapshot.records_dropped);
        self.metrics.add_parse_errors(snapshot.parse_errors);
        for (rule, n) in &snapshot.rule_drops {
            self.metrics.record_rule_drops(rule, *n);
        }

        if matches!(outcome?, Outcome::Unrecognized) {
            self.metrics.add_unrecognized_objects(1);
        }
        Ok(ObjectOutcome::DryRun)
    }

    async fn process_stream(&self, src_key: &str, dst_key: &str) -> anyhow::Result<ObjectOutcome> {
        let reader = self
            .store(&self.src)
            .get_stream(self.src.bucket(), src_key)
            .await?;
        let outcome = stream_run(
            reader,
            &self.engine,
            &self.cfg.processing,
            &self.metrics,
            self.store(&self.dst),
            self.dst.bucket(),
            dst_key,
        )
        .await?;

        match outcome {
            Outcome::Written(None) => Ok(ObjectOutcome::Written(self.dst.display(dst_key))),
            // `stream_run` aborted the upload: nothing landed at `dst_key`.
            Outcome::NothingKept => Ok(ObjectOutcome::NothingKept),
            // The upload is already aborted. Hand the policy no bytes: it
            // decides *first*, exactly as `Pipeline::process_stream` does, and
            // only `copy` re-reads the object — as a stream, straight into the
            // destination. Buffering the whole object up front undid stream
            // mode's entire reason for existing, on the one path reached by
            // objects too big to buffer.
            Outcome::Unrecognized => self.unrecognized(src_key, dst_key, None).await,
            Outcome::Written(Some(_)) => {
                unreachable!("stream_run never returns Written(Some(_))")
            }
        }
    }

    /// `behavior.on_unrecognized_object` for an object that parsed as JSON
    /// but carried no `Records` array. The default is `copy` — forward
    /// verbatim, never discard.
    ///
    /// `bytes` is the already-buffered source object when the caller happens
    /// to hold it (buffer mode always does); `None` makes the `copy` branch
    /// stream source → destination instead, so the streaming caller never has
    /// to materialize the object.
    async fn unrecognized(
        &self,
        src_key: &str,
        dst_key: &str,
        bytes: Option<Bytes>,
    ) -> anyhow::Result<ObjectOutcome> {
        match self.cfg.on_unrecognized {
            OnUnrecognizedObject::Copy => {
                self.metrics.add_unrecognized_objects(1);
                let at = match bytes {
                    Some(b) => self.put(dst_key, b).await?,
                    None => self.stream_copy(src_key, dst_key).await?,
                };
                Ok(ObjectOutcome::Copied(at))
            }
            OnUnrecognizedObject::Skip => {
                self.metrics.add_unrecognized_objects(1);
                Ok(ObjectOutcome::Skipped)
            }
            OnUnrecognizedObject::Error => anyhow::bail!(
                "{src_key}: no Records array, and behavior.on_unrecognized_object is \"error\""
            ),
        }
    }

    /// Copies the source object to the destination verbatim without ever
    /// holding it in memory — `Pipeline::stream_copy`'s counterpart.
    async fn stream_copy(&self, src_key: &str, dst_key: &str) -> anyhow::Result<String> {
        let reader = self
            .store(&self.src)
            .get_stream(self.src.bucket(), src_key)
            .await?;
        self.store(&self.dst)
            .put_stream(self.dst.bucket(), dst_key, reader, GZIP_META)
            .await?;
        Ok(self.dst.display(dst_key))
    }

    async fn put(&self, dst_key: &str, bytes: Bytes) -> anyhow::Result<String> {
        self.store(&self.dst)
            .put(self.dst.bucket(), dst_key, bytes, GZIP_META)
            .await?;
        Ok(self.dst.display(dst_key))
    }
}

async fn cmd_filter(
    source: &str,
    dest: &str,
    rules_uri: &str,
    settings_path: Option<&Path>,
) -> anyhow::Result<()> {
    let (engine, _rule_set) = load_engine(rules_uri).await?;
    let cfg = FilterConfig::resolve(settings_path)?;

    let src = Location::parse(source)?;
    let dst = Location::parse(dest)?;
    let s3 = build_s3_if_needed(&src, &dst).await;

    // Single local file → filter exactly that object to `dest`. The key
    // filter deliberately does not apply: the operator named this file.
    let single = match &src {
        Location::Local(p) if p.is_file() => Some(p.clone()),
        Location::Local(p) if !p.exists() => anyhow::bail!("source path {p:?} does not exist"),
        _ => None,
    };

    let objects = match &single {
        Some(p) => vec![SrcObject {
            fetch: p.to_string_lossy().into_owned(),
            rel: String::new(),
            size: std::fs::metadata(p).ok().map(|m| m.len()),
        }],
        None => enumerate(&src, &cfg.keys, &s3).await?,
    };
    if objects.is_empty() {
        println!("no in-scope objects found under {source}");
        return Ok(());
    }

    let single_dst = match &single {
        Some(_) => Some(single_dest_key(&dst)?),
        None => None,
    };

    let f = Filterer {
        engine,
        cfg,
        metrics: Metrics::default(),
        src,
        dst,
        local: LocalObjectStore,
        s3,
    };

    let (mut written, mut fully_dropped, mut copied, mut skipped) =
        (0usize, 0usize, 0usize, 0usize);
    // A failing object must not abandon the objects after it: the run
    // continues, and every failure is reported together at the end with a
    // non-zero exit. Aborting on the first error left an operator with a
    // half-finished backfill and no summary saying how far it got.
    let mut failures: Vec<(String, String)> = Vec::new();

    for obj in &objects {
        let dst_key = match &single_dst {
            Some(key) => Ok(key.clone()),
            None => batch_dest_key(&f.dst, &obj.rel),
        };
        // The single-file path has no relative key; name the object by what
        // was fetched instead.
        let label = if single_dst.is_some() {
            obj.fetch.as_str()
        } else {
            obj.rel.as_str()
        };

        // An unsafe `rel` fails this object exactly like any other error: it
        // never stops the batch (see the module doc above `failures`), it is
        // never a silent skip, and it still drives the non-zero exit code.
        let outcome = match dst_key {
            Ok(dst_key) => f.process(&obj.fetch, &dst_key, obj.size).await,
            Err(e) => Err(e),
        };

        match outcome {
            Ok(ObjectOutcome::Written(at)) => {
                written += 1;
                println!("  {label} -> {at}");
            }
            Ok(ObjectOutcome::NothingKept) => {
                fully_dropped += 1;
                println!("  {label} -> (all records dropped, nothing written)");
            }
            Ok(ObjectOutcome::Copied(at)) => {
                copied += 1;
                println!("  {label} -> {at} (unrecognized shape, copied verbatim)");
            }
            Ok(ObjectOutcome::Skipped) => {
                skipped += 1;
                println!("  {label} -> (unrecognized shape, skipped)");
            }
            Ok(ObjectOutcome::DryRun) => {
                println!("  {label} -> (dry run, nothing written)");
            }
            Err(e) => {
                eprintln!("  {label} -> FAILED: {e:#}");
                failures.push((label.to_string(), format!("{e:#}")));
            }
        }
    }

    let snap = f.metrics.snapshot_and_reset();
    if f.cfg.dry_run {
        // The unrecognized count is what a preview is *for* on this axis: it
        // is the number of objects the real run would hand to
        // `behavior.on_unrecognized_object` — copied verbatim, skipped, or
        // (under `error`) failed. Reporting only the record counts hid it.
        println!(
            "dry run: {} object(s) evaluated ({} unrecognized, {} failed), nothing written",
            objects.len(),
            snap.unrecognized_objects,
            failures.len()
        );
    } else {
        println!(
            "processed {} object(s): {written} written, {fully_dropped} fully dropped, \
             {copied} copied verbatim, {skipped} skipped, {} failed",
            objects.len(),
            failures.len()
        );
    }
    println!(
        "records: {} in, {} kept, {} dropped",
        snap.records_in, snap.records_kept, snap.records_dropped
    );

    if !failures.is_empty() {
        eprintln!("{} object(s) failed:", failures.len());
        for (label, err) in &failures {
            eprintln!("  {label}: {err}");
        }
        anyhow::bail!("{} of {} object(s) failed", failures.len(), objects.len());
    }
    Ok(())
}

/// Loads `path` (or falls back to built-in defaults when `None`) and runs it
/// through `Settings::from_parts` with `std::env::var` as the override
/// source — the identical parse-override-validate path `Settings::load()`
/// uses in production, so `validate-settings` is never a CLI-side
/// reimplementation of the Lambda's validation.
fn load_and_validate_settings(path: Option<&Path>) -> anyhow::Result<Settings> {
    let bytes = match path {
        Some(p) => Some(std::fs::read(p).with_context(|| format!("failed to read {p:?}"))?),
        None => None,
    };
    Ok(Settings::from_parts(bytes.as_deref(), &|key| {
        std::env::var(key).ok()
    })?)
}

fn cmd_validate_settings(path: Option<&Path>) -> anyhow::Result<()> {
    let settings = load_and_validate_settings(path)?;

    println!("settings OK");
    println!(
        "  processing.mode:                   {:?}",
        settings.processing.mode
    );
    println!(
        "  processing.stream_threshold_bytes: {}",
        settings.processing.stream_threshold_bytes
    );
    println!(
        "  processing.max_object_bytes:       {}",
        settings.processing.max_object_bytes
    );
    println!(
        "  processing.multipart_part_bytes:   {}",
        settings.processing.multipart_part_bytes
    );
    println!(
        "  processing.gzip_level:             {}",
        settings.processing.gzip_level
    );
    println!(
        "  destination.bucket:                {}",
        settings.destination.bucket
    );
    println!(
        "  rules.uri:                         {}",
        settings.rules.uri
    );

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Validate { uri, max_unindexed } => cmd_validate(&uri, max_unindexed).await,
        Command::Test { rules, sample } => cmd_test(&rules, &sample).await,
        Command::Filter {
            source,
            dest,
            rules,
            settings,
        } => cmd_filter(&source, &dest, &rules, settings.as_deref()).await,
        Command::ValidateSettings { path } => cmd_validate_settings(path.as_deref()),
    };

    if let Err(e) = result {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `..`-laden `rel` (the shape a crafted local source or a naive S3
    /// key relativization could produce) must be rejected, not silently
    /// escape `root` via `Path::join`.
    #[test]
    fn batch_dest_key_rejects_parent_dir_escape() {
        let root = Location::Local(PathBuf::from("./out"));
        let rel = "../../../../tmp/evil.json.gz";
        let err = batch_dest_key(&root, rel).expect_err("must reject `..` escape");
        assert!(
            err.to_string().contains("escapes the destination root"),
            "unexpected error: {err}"
        );
    }

    /// The more severe escape: no `..` at all, just a `rel` that is itself
    /// absolute. Built through the exact derivation `enumerate`'s
    /// `Location::S3` branch uses (`dir_prefix` then `strip_prefix` on the
    /// listed key) rather than constructing an absolute `rel` by hand, so
    /// this proves the real path — a doubled slash in an S3 key survives
    /// the strip as a leading `/`, and `PathBuf::join` with an absolute
    /// path discards `root` entirely.
    #[test]
    fn batch_dest_key_rejects_absolute_escape_via_doubled_slash() {
        let prefix = "logs/";
        let key = "logs//etc/passwd.json.gz";
        let dir = dir_prefix(prefix);
        let rel = key.strip_prefix(dir.as_str()).unwrap_or(key).to_string();
        assert_eq!(
            rel, "/etc/passwd.json.gz",
            "derivation changed unexpectedly"
        );

        let root = Location::Local(PathBuf::from("./out"));
        let err = batch_dest_key(&root, &rel).expect_err("must reject absolute escape");
        assert!(
            err.to_string().contains("escapes the destination root"),
            "unexpected error: {err}"
        );
    }

    /// A normal nested relative key is unaffected: it still maps under
    /// `root` exactly as before the containment check.
    #[test]
    fn batch_dest_key_accepts_normal_nested_key() {
        let root = Location::Local(PathBuf::from("./out"));
        let dst = batch_dest_key(&root, "normal/a/b.json.gz").expect("normal key must be accepted");
        let expected = PathBuf::from("./out")
            .join("normal/a/b.json.gz")
            .to_string_lossy()
            .into_owned();
        assert_eq!(dst, expected);
    }
}
