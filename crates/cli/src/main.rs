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
//! - `filter <in> <out> --rules <uri>`: local/backfill filtering, via
//!   `core::process::buffer_run` directly.
#![forbid(unsafe_code)]

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Context;
use aws_config::BehaviorVersion;
use clap::{Parser, Subcommand};
use cloudtrail_rs_aws::{S3ConfigSource, SsmConfigSource};
use cloudtrail_rs_core::config::{ConfigUri, Processing, RuleSet};
use cloudtrail_rs_core::filter::{Decision, Engine};
use cloudtrail_rs_core::metrics::Metrics;
use cloudtrail_rs_core::ports::ConfigSource;
use cloudtrail_rs_core::process::{Outcome, buffer_run};
use flate2::read::MultiGzDecoder;

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
    /// Filter one local gzip object through `core::process::buffer_run`.
    Filter {
        /// Local `.json.gz` input object.
        input: PathBuf,
        /// Local `.json.gz` destination. Not written if every record is
        /// dropped ("zero empty writes").
        output: PathBuf,
        /// `ssm://`, `s3://`, `file://`, or a bare local path.
        #[arg(long)]
        rules: String,
    },
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

async fn cmd_filter(input: &Path, output: &Path, rules_uri: &str) -> anyhow::Result<()> {
    let (engine, _rule_set) = load_engine(rules_uri).await?;
    let cfg = Processing::default();
    let metrics = Metrics::default();

    let input_bytes = std::fs::read(input).with_context(|| format!("failed to read {input:?}"))?;

    match buffer_run(&input_bytes, &engine, &cfg, &metrics)? {
        Outcome::Written(Some(bytes)) => {
            std::fs::write(output, &bytes)
                .with_context(|| format!("failed to write {output:?}"))?;
            println!("wrote {} bytes to {}", bytes.len(), output.display());
        }
        Outcome::Written(None) => {
            unreachable!("buffer_run always returns Written(Some(_)) when it writes anything")
        }
        Outcome::NothingKept => {
            println!("all records dropped; no output written");
        }
        Outcome::Unrecognized => {
            // No `Records` array: default `on_unrecognized_object` policy is
            // `copy` (SHARED.md) — forward the object verbatim rather than
            // silently discard an unanticipated shape.
            std::fs::write(output, &input_bytes)
                .with_context(|| format!("failed to write {output:?}"))?;
            println!(
                "object shape not recognized (no Records array); copied input verbatim to {}",
                output.display()
            );
        }
    }

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Validate { uri } => cmd_validate(&uri).await,
        Command::Test { rules, sample } => cmd_test(&rules, &sample).await,
        Command::Filter {
            input,
            output,
            rules,
        } => cmd_filter(&input, &output, &rules).await,
    };

    if let Err(e) = result {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
    Ok(())
}
