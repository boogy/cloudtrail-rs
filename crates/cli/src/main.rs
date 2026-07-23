//! `cloudtrail-rs` — local/offline CLI companion to the Lambda binaries
//! (task 17, `docs/plans/cloudtrail-rs/SHARED.md`).
//!
//! Depends on `cloudtrail-rs-core` **and** `cloudtrail-rs-aws` so a rules
//! `uri` may be `ssm://`, `s3://`, `file://`, or a bare local path.
//!
//! Three subcommands, all reusing `core`'s existing engine/process logic —
//! nothing here reimplements filtering:
//! - `validate <uri>`: builds the `Engine`, prints rule/pattern counts, and
//!   warns (non-fatally) about every rule `Engine::always_rules()` could not
//!   index. Non-zero exit only on a config/build error — the CI gate.
//! - `test <rules> <sample.json.gz>`: per-record KEEP/DROP against the
//!   compiled ruleset, plus a summary, so dead rules are visible.
//! - `filter <source> <dest> --rules <uri>`: local/backfill filtering, via
//!   `core::process::buffer_run` directly. Each of `source` and `dest` is
//!   auto-detected as a local path or an `s3://bucket/prefix` URI; a local
//!   directory or an `s3://` prefix triggers batch mode (every `.json.gz`
//!   object filtered into a mirrored destination), so filtering is visible
//!   on the local filesystem and the same command works against S3 when AWS
//!   credentials are present.
#![forbid(unsafe_code)]

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Context;
use aws_config::BehaviorVersion;
use bytes::Bytes;
use clap::{Parser, Subcommand};
use cloudtrail_rs_aws::{S3ConfigSource, S3ObjectStore, SsmConfigSource};
use cloudtrail_rs_core::config::{ConfigUri, Processing, RuleSet};
use cloudtrail_rs_core::filter::{Decision, Engine};
use cloudtrail_rs_core::metrics::Metrics;
use cloudtrail_rs_core::model::PutMeta;
use cloudtrail_rs_core::ports::{ConfigSource, ObjectStore};
use cloudtrail_rs_core::process::{Outcome, buffer_run};
use flate2::read::MultiGzDecoder;

/// Object metadata for every gzip object this CLI writes to S3, matching the
/// canonical `PutMeta` the Lambda pipeline uses (`SHARED.md`).
const GZIP_META: PutMeta = PutMeta {
    content_type: "application/x-gzip",
    content_encoding: "gzip",
};

#[derive(Parser)]
#[command(
    name = "cloudtrail-rs",
    about = "Local tooling for cloudtrail-rs exclusion rules"
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
    /// Filter CloudTrail gzip objects through `core::process::buffer_run`.
    ///
    /// `source` and `dest` are each a local path or an `s3://bucket/prefix`
    /// URI. A single local **file** filters that one object to `dest`. A
    /// local **directory** or any `s3://` prefix filters every `.json.gz`
    /// object under it, mirroring the relative path into `dest` (which may
    /// itself be a local directory or an `s3://` prefix). Objects with all
    /// records dropped are not written ("zero empty writes").
    Filter {
        /// Local file/directory, or `s3://bucket/prefix`.
        source: String,
        /// Local file/directory, or `s3://bucket/prefix`.
        dest: String,
        /// `ssm://`, `s3://`, `file://`, or a bare local path.
        #[arg(long)]
        rules: String,
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
}

/// One source object queued for filtering: `fetch` is what reads its bytes
/// (a local path or a full S3 key); `rel` is the path used to mirror it into
/// the destination.
struct SrcObject {
    fetch: String,
    rel: String,
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
            let conf = aws_config::load_defaults(BehaviorVersion::latest()).await;
            let source = S3ConfigSource::new(&conf, bucket, key);
            let (bytes, _version) = source.fetch().await?;
            Ok(bytes)
        }
        ConfigUri::Ssm { path } => {
            let conf = aws_config::load_defaults(BehaviorVersion::latest()).await;
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
/// accepts (see `SHARED.md`, "Rule index").
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

/// Whether a key should be filtered: a `.json.gz` object that is not a
/// CloudTrail digest or Insight file. Mirrors the intent of the pipeline's
/// default `source.include_key_regex`/`exclude_key_regex`, applied here to
/// batch enumeration so digest/Insight objects cost nothing.
fn is_candidate_key(key: &str) -> bool {
    key.ends_with(".json.gz")
        && !key.contains("CloudTrail-Digest")
        && !key.contains("CloudTrail-Insight")
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

/// Recursively collects candidate `.json.gz` objects under `dir`, recording
/// each one's path relative to `root` (with `/` separators) as its `rel`.
fn collect_local(root: &Path, dir: &Path, out: &mut Vec<SrcObject>) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("failed to read dir {dir:?}"))? {
        let path = entry?.path();
        if path.is_dir() {
            collect_local(root, &path, out)?;
        } else {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            if is_candidate_key(&rel) {
                out.push(SrcObject {
                    fetch: path.to_string_lossy().into_owned(),
                    rel,
                });
            }
        }
    }
    Ok(())
}

/// Enumerates every candidate source object under a batch source (a local
/// directory or an `s3://` prefix), sorted by relative key for deterministic
/// output.
async fn enumerate(src: &Location, s3: &Option<S3ObjectStore>) -> anyhow::Result<Vec<SrcObject>> {
    let mut objs = match src {
        Location::Local(root) => {
            let mut objs = Vec::new();
            collect_local(root, root, &mut objs)?;
            objs
        }
        Location::S3 { bucket, prefix } => {
            let store = s3.as_ref().expect("s3 store built when a side is s3");
            let dir = dir_prefix(prefix);
            store
                .list_keys(bucket, prefix)
                .await?
                .into_iter()
                .filter(|k| is_candidate_key(k))
                .map(|k| {
                    let rel = k
                        .strip_prefix(dir.as_str())
                        .unwrap_or(k.as_str())
                        .to_string();
                    SrcObject { fetch: k, rel }
                })
                .collect()
        }
    };
    objs.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(objs)
}

/// Reads a source object's bytes (`fetch` is a local path or a full S3 key).
async fn read_source(
    src: &Location,
    fetch: &str,
    s3: &Option<S3ObjectStore>,
) -> anyhow::Result<Vec<u8>> {
    match src {
        Location::Local(_) => {
            std::fs::read(fetch).with_context(|| format!("failed to read {fetch:?}"))
        }
        Location::S3 { bucket, .. } => {
            let store = s3.as_ref().expect("s3 store built when a side is s3");
            Ok(store.get(bucket, fetch).await?.to_vec())
        }
    }
}

/// Writes `bytes` to the batch destination under relative key `rel`,
/// returning a human-readable location for the progress line.
async fn write_dest(
    dst: &Location,
    rel: &str,
    bytes: &[u8],
    s3: &Option<S3ObjectStore>,
) -> anyhow::Result<String> {
    match dst {
        Location::Local(root) => {
            let path = root.join(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {parent:?}"))?;
            }
            std::fs::write(&path, bytes).with_context(|| format!("failed to write {path:?}"))?;
            Ok(path.display().to_string())
        }
        Location::S3 { bucket, prefix } => {
            let key = join_key(prefix, rel);
            let store = s3.as_ref().expect("s3 store built when a side is s3");
            store
                .put(bucket, &key, Bytes::copy_from_slice(bytes), GZIP_META)
                .await?;
            Ok(format!("s3://{bucket}/{key}"))
        }
    }
}

/// Writes a single-object destination (source was one local file). Local:
/// the exact path given. S3: the prefix is taken as the full object key.
async fn write_single(
    dst: &Location,
    bytes: &[u8],
    s3: &Option<S3ObjectStore>,
) -> anyhow::Result<String> {
    match dst {
        Location::Local(path) => {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {parent:?}"))?;
            }
            std::fs::write(path, bytes).with_context(|| format!("failed to write {path:?}"))?;
            Ok(path.display().to_string())
        }
        Location::S3 { bucket, prefix } => {
            if prefix.is_empty() {
                anyhow::bail!("s3 destination for a single file needs a key, not just a bucket");
            }
            let store = s3.as_ref().expect("s3 store built when a side is s3");
            store
                .put(bucket, prefix, Bytes::copy_from_slice(bytes), GZIP_META)
                .await?;
            Ok(format!("s3://{bucket}/{prefix}"))
        }
    }
}

/// Builds one S3 client (credential chain resolved once) if either side is
/// S3; a purely local run never touches AWS.
async fn build_s3_if_needed(src: &Location, dst: &Location) -> Option<S3ObjectStore> {
    if src.is_s3() || dst.is_s3() {
        let conf = aws_config::load_defaults(BehaviorVersion::latest()).await;
        Some(S3ObjectStore::new(&conf))
    } else {
        None
    }
}

async fn cmd_filter(source: &str, dest: &str, rules_uri: &str) -> anyhow::Result<()> {
    let (engine, _rule_set) = load_engine(rules_uri).await?;
    let cfg = Processing::default();
    let metrics = Metrics::default();

    let src = Location::parse(source)?;
    let dst = Location::parse(dest)?;
    let s3 = build_s3_if_needed(&src, &dst).await;

    // Single local file → filter exactly that object to `dest`.
    if let Location::Local(p) = &src {
        if p.is_file() {
            let input = std::fs::read(p).with_context(|| format!("failed to read {p:?}"))?;
            match buffer_run(&input, &engine, &cfg, &metrics)? {
                Outcome::Written(Some(bytes)) => {
                    let at = write_single(&dst, bytes.as_ref(), &s3).await?;
                    println!("wrote {} bytes to {at}", bytes.len());
                }
                Outcome::Written(None) => {
                    unreachable!("buffer_run returns Written(Some(_)) when it writes")
                }
                Outcome::NothingKept => println!("all records dropped; no output written"),
                Outcome::Unrecognized => {
                    // No `Records` array: default `on_unrecognized_object` is
                    // `copy` (SHARED.md) — forward verbatim, never discard.
                    let at = write_single(&dst, &input, &s3).await?;
                    println!(
                        "object shape not recognized (no Records array); copied verbatim to {at}"
                    );
                }
            }
            return Ok(());
        }
        if !p.exists() {
            anyhow::bail!("source path {p:?} does not exist");
        }
    }

    // Batch: a local directory or an s3:// prefix.
    let objects = enumerate(&src, &s3).await?;
    if objects.is_empty() {
        println!("no .json.gz objects found under {source}");
        return Ok(());
    }

    let (mut written, mut fully_dropped, mut copied) = (0usize, 0usize, 0usize);
    for obj in &objects {
        let input = read_source(&src, &obj.fetch, &s3).await?;
        match buffer_run(&input, &engine, &cfg, &metrics)? {
            Outcome::Written(Some(bytes)) => {
                let at = write_dest(&dst, &obj.rel, bytes.as_ref(), &s3).await?;
                written += 1;
                println!("  {} -> {at}", obj.rel);
            }
            Outcome::Written(None) => {
                unreachable!("buffer_run returns Written(Some(_)) when it writes")
            }
            Outcome::NothingKept => {
                fully_dropped += 1;
                println!("  {} -> (all records dropped, nothing written)", obj.rel);
            }
            Outcome::Unrecognized => {
                let at = write_dest(&dst, &obj.rel, &input, &s3).await?;
                copied += 1;
                println!(
                    "  {} -> {at} (unrecognized shape, copied verbatim)",
                    obj.rel
                );
            }
        }
    }

    let snap = metrics.snapshot_and_reset();
    println!(
        "processed {} object(s): {written} written, {fully_dropped} fully dropped, {copied} copied verbatim",
        objects.len()
    );
    println!(
        "records: {} in, {} kept, {} dropped",
        snap.records_in, snap.records_kept, snap.records_dropped
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
        } => cmd_filter(&source, &dest, &rules).await,
    };

    if let Err(e) = result {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
    Ok(())
}
