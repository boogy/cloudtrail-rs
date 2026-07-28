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
//!   index. Non-zero exit only on a config/build error — the CI gate.
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
use std::path::{Path, PathBuf};

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
use cloudtrail_rs_core::process::{Outcome, buffer_run, stream_run};
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
    /// and warn about every rule that could not be indexed by eventSource.
    Validate {
        /// `ssm://`, `s3://`, `file://`, or a bare local path.
        uri: String,
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
/// could not narrow it to a fixed set of `eventSource` literals — either it
/// has no `eventSource` condition at all, or that condition's pattern is not
/// one of the two conservative shapes `Engine::new`'s index extraction
/// accepts (the rule index).
fn explain_always_rule(rule_set: &RuleSet, rule_idx: usize) -> String {
    let rule = &rule_set.rules[rule_idx];
    match rule.matches.iter().find(|m| m.field_name == "eventSource") {
        Some(m) => format!(
            "warning: rule \"{}\" not indexed by eventSource (pattern \"{}\" could not be \
             reduced to a fixed set of literals): checked against every record",
            rule.name, m.regex
        ),
        None => format!(
            "warning: rule \"{}\" not indexed by eventSource (no eventSource condition): \
             checked against every record",
            rule.name
        ),
    }
}

async fn cmd_validate(uri: &str) -> anyhow::Result<()> {
    let (engine, rule_set) = load_engine(uri).await?;

    let rule_count = rule_set.rules.len();
    let pattern_count: usize = rule_set.rules.iter().map(|r| r.matches.len()).sum();
    println!("{rule_count} rules, {pattern_count} patterns compiled");

    for &rule_idx in engine.always_rules() {
        eprintln!("{}", explain_always_rule(&rule_set, rule_idx));
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

/// The batch destination key for a source object's relative key.
fn batch_dest_key(dst: &Location, rel: &str) -> String {
    match dst {
        Location::Local(root) => root.join(rel).to_string_lossy().into_owned(),
        Location::S3 { prefix, .. } => join_key(prefix, rel),
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

    async fn process(
        &self,
        src_key: &str,
        dst_key: &str,
        size: Option<u64>,
    ) -> anyhow::Result<ObjectOutcome> {
        if self.cfg.dry_run {
            // Mirrors `Pipeline::process_dry_run`: every record is still
            // evaluated (so the record counts report what *would* be
            // filtered) through buffer semantics, and the result is
            // discarded — nothing is written.
            let bytes = self
                .store(&self.src)
                .get(self.src.bucket(), src_key)
                .await?;
            buffer_run(&bytes, &self.engine, &self.cfg.processing, &self.metrics)?;
            return Ok(ObjectOutcome::DryRun);
        }

        match self.cfg.select_mode(size) {
            Mode::Stream => self.process_stream(src_key, dst_key).await,
            Mode::Buffer => {
                let bytes = self
                    .store(&self.src)
                    .get(self.src.bucket(), src_key)
                    .await?;
                let result = buffer_run(&bytes, &self.engine, &self.cfg.processing, &self.metrics);
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
                        self.process_stream(src_key, dst_key).await
                    }
                    Err(e) => Err(e.into()),
                    Ok(Outcome::Written(Some(out))) => {
                        Ok(ObjectOutcome::Written(self.put(dst_key, out).await?))
                    }
                    Ok(Outcome::NothingKept) => Ok(ObjectOutcome::NothingKept),
                    Ok(Outcome::Unrecognized) => self.unrecognized(src_key, dst_key, bytes).await,
                    Ok(Outcome::Written(None)) => {
                        unreachable!("buffer_run returns Written(Some(_)) when it writes")
                    }
                }
            }
        }
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
            Outcome::Unrecognized => {
                // The upload is already aborted, and the policy needs the
                // whole object — re-fetch it, exactly as
                // `Pipeline::process_stream` does.
                let bytes = self
                    .store(&self.src)
                    .get(self.src.bucket(), src_key)
                    .await?;
                self.unrecognized(src_key, dst_key, bytes).await
            }
            Outcome::Written(Some(_)) => {
                unreachable!("stream_run never returns Written(Some(_))")
            }
        }
    }

    /// `behavior.on_unrecognized_object` for an object that parsed as JSON
    /// but carried no `Records` array. The default is `copy` — forward
    /// verbatim, never discard.
    async fn unrecognized(
        &self,
        src_key: &str,
        dst_key: &str,
        bytes: Bytes,
    ) -> anyhow::Result<ObjectOutcome> {
        match self.cfg.on_unrecognized {
            OnUnrecognizedObject::Copy => {
                Ok(ObjectOutcome::Copied(self.put(dst_key, bytes).await?))
            }
            OnUnrecognizedObject::Skip => Ok(ObjectOutcome::Skipped),
            OnUnrecognizedObject::Error => anyhow::bail!(
                "{src_key}: no Records array, and behavior.on_unrecognized_object is \"error\""
            ),
        }
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
            Some(key) => key.clone(),
            None => batch_dest_key(&f.dst, &obj.rel),
        };
        // The single-file path has no relative key; name the object by what
        // was fetched instead.
        let label = if single_dst.is_some() {
            obj.fetch.as_str()
        } else {
            obj.rel.as_str()
        };

        match f.process(&obj.fetch, &dst_key, obj.size).await {
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
        println!(
            "dry run: {} object(s) evaluated, nothing written",
            objects.len()
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
        Command::Validate { uri } => cmd_validate(&uri).await,
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
