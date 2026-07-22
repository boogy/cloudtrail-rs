# cloudtrail-rs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development`. This plan is written to be executed **one task per fresh subagent**. Steps use checkbox (`- [ ]`) syntax for tracking.

## Context

CloudTrail writes gzipped JSON objects to S3. Forwarding all of it to a SIEM is expensive and mostly noise — service-role `AssumeRole`, EKS `Decrypt`, health-check `Describe*` calls dominate the volume and carry almost no detection value.

`cloudtrail-rs` sits between the CloudTrail bucket and the SIEM bucket. It is triggered by an S3 notification (direct, via SNS, via SQS, or via EventBridge), reads the object, evaluates each record in `Records[]` against a YAML exclusion ruleset, and writes the survivors to a destination bucket the SIEM syncs. The source bucket is never modified, so nothing is truly lost — a bad rule is recoverable by reprocessing.

Repo is empty (`LICENSE` + `.gitignore`, one commit `8447c3e`, branch `main`). Greenfield.

**Intended outcome:** a Rust workspace producing four independent Lambda binaries plus a CLI, with a hexagonal core fully testable without AWS.

---

# PART A — Execution model

## Context hygiene (the point of this structure)

The orchestrator must never accumulate implementation detail, and a subagent must never need to read the whole plan to do its task. Both are achieved by splitting this document on disk **before any code is written** (that is Task 00).

```
docs/plans/cloudtrail-rs/
  PLAN.md              <- this document, verbatim. The durable copy; survives session loss.
  SHARED.md            <- constraints + binding interfaces + config schemas. Every subagent reads this.
  STATUS.md            <- one row per task: pending | dispatched | done | blocked + commit sha.
                          The orchestrator's only state. See "Durable state" below.
  task-00..task-19.md  <- one self-contained brief per task.
```

**Orchestrator protocol** — holds only `STATUS.md` and the task index below:

1. Pick the next task whose dependencies are `done`.
2. Dispatch a **fresh** subagent with exactly this prompt: _"Read `docs/plans/cloudtrail-rs/SHARED.md` then `docs/plans/cloudtrail-rs/task-NN-*.md`. Implement it TDD. Do not read other task files. Report: files changed, test names added, commit sha, and any interface deviation."_
3. On return, run `cargo test --workspace --all-features` + `cargo clippy -- -D warnings` **yourself**. Do not re-derive the subagent's work; verify it.
4. Update `STATUS.md`. Discard the subagent's transcript.
5. **If a subagent reports an interface deviation, update `SHARED.md` before dispatching the next task.** `SHARED.md` is the single source of truth for cross-task contracts; drift there is the one failure mode this structure cannot absorb.

**Subagent protocol** — each brief is self-contained. Read `SHARED.md` + your own file, write the failing test, watch it fail, implement minimally, watch it pass, commit. Do **not** read other task files, do not refactor neighbouring tasks' code, and return to the orchestrator rather than expanding scope.

## Durable state — resuming after a timeout, crash, or a multi-hour gap

**Assume this session will be lost.** Nothing about progress may live only in the conversation. Every fact needed to resume is on disk and in git, inside the repo.

**What makes it durable:**

1. **The plan itself is committed.** Task 00 copies this whole document verbatim to `docs/plans/cloudtrail-rs/PLAN.md` alongside the split files. The copy under `~/.claude/plans/` is a working draft, not the source of truth — after Task 00, the repo is.
2. **One commit per task, with a recoverable message.** Every task's work lands as commits whose subject starts `task-NN: ` (e.g. `task-04: field path resolution`). This is the redundancy that matters: `STATUS.md` can be stale if a session died between the commit and the status update, but `git log --grep '^task-'` cannot lie.
3. **`STATUS.md` is the orchestrator's only state**, and is committed with the task it describes.

**`STATUS.md` format** — a header plus one row per task, nothing else:

```markdown
# STATUS
last-dispatched: task-07          # set BEFORE dispatching, cleared on completion
| task | state | commit | note |
|------|-------|--------|------|
| 00 | done    | a1b2c3d | |
| 01 | done    | d4e5f6a | |
| 07 | pending | —       | |
```

`state` ∈ `pending` | `dispatched` | `done` | `blocked`. `note` carries interface deviations and anything a future orchestrator needs (e.g. "Task 13 fell back to `Value` re-serialize in stream mode").

**Resume protocol** — a fresh orchestrator with zero conversation context runs exactly this, in order:

1. `git -C /Users/bogdan/github.com/cloudtrail-rs log --oneline -30` — what actually landed.
2. `git status --short` — **is there uncommitted work?** If yes, a subagent died mid-task. Do **not** discard it (never `git checkout`/`restore`/`stash`/`reset --hard`). Read the diff, decide whether it is a usable partial implementation, and either finish it in place or note it and continue.
3. Read `docs/plans/cloudtrail-rs/STATUS.md`.
4. **Reconcile STATUS against git**, git wins. A task marked `dispatched` with a matching `task-NN:` commit is actually `done`; one with no commit and no uncommitted work never started. Fix `STATUS.md` and commit the fix before doing anything else.
5. `cargo test --workspace --all-features` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` — confirm the tree is green at the last `done` task. A red tree means the previous task did not finish; re-open it rather than stacking on top.
6. Read `docs/plans/cloudtrail-rs/SHARED.md` (contracts, possibly amended since this draft) and the next task's brief. Resume at step 1 of the orchestrator protocol.

Steps 1–5 are cheap and bounded — no need to re-read the whole plan or any completed task brief. **Never re-derive a completed task's work; trust the commit and the green suite.**

**Orchestrator obligations that keep this true:**

- Set `last-dispatched` in `STATUS.md` and commit it **before** dispatching a subagent, so an interrupted dispatch is visible.
- After verifying a task, update its row to `done` with the commit sha and commit that change immediately — not batched at the end of a batch.
- Record every interface deviation in **both** `SHARED.md` and the task's `note` column in the same commit.
- When dispatching a parallel batch, set every member to `dispatched` in one commit up front.

**Model selection:** **every implementation subagent is Sonnet.** No task is dispatched to Haiku or Opus. Max spawn depth 2 — an implementation subagent never spawns further subagents; if a task turns out to need more judgement than its brief carries, it returns to the orchestrator rather than escalating on its own.

The orchestrator (this session, Opus) keeps the work that actually needs judgement: writing and amending `SHARED.md`, resolving interface deviations, verifying each task's tests genuinely fail before the fix and pass after, and running the mutation spot-checks in Part D. Tasks 06, 13, 14 and 16 carry the most design risk, so the orchestrator reviews those diffs line-by-line rather than trusting a green suite.

**Task 00 is done by the orchestrator directly** — it is file I/O against a document already in context, and dispatching it would mean paying to re-read the whole plan.

## Task index and dependency graph

Deps below are authoritative; the diagram is a reading aid.

```
00 split ─> 01 workspace ─> 02 ports ─┬─> 03 rules ──┬─> 05 engine ─> 06 index ─> 12 buffer ─> 13 stream ─┐
                                      ├─> 04 path ───┘                                                   │
                                      ├─> 07 settings ─┐                                                 │
                                      ├─> 09 metrics ──┴─> 08 configstore ──────────────────────────────>┤
                                      ├─> 10 decoders s3/sns                                             │
                                      ├─> 11 decoders sqs/eb ──────────────────────────────────────────>─┤
                                      └─> 15 aws adapters ──────────────────────────────┐                v
                                                                                        ├──────> 14 pipeline
                                                                                        │            │
                                                              16 bins <──────────────────┴────────────┤
                                                                │                                     │
                                                                │            17 cli <──────────────────┘
                                                                └──> 18 ministack ─> 19 docs
```

| Task | Deps       |     | Task | Deps   |
| ---- | ---------- | --- | ---- | ------ |
| 00   | —          |     | 10   | 02     |
| 01   | 00         |     | 11   | 02, 07 |
| 02   | 01         |     | 12   | 06, 07, 09 |
| 03   | 02         |     | 13   | 12     |
| 04   | 02         |     | 14   | 08, 11, 13 |
| 05   | 03, 04     |     | 15   | 02     |
| 06   | 05         |     | 16   | 14, 15 |
| 07   | 02         |     | 17   | 14, 15 |
| 08   | 07, 09     |     | 18   | 16     |
| 09   | 02         |     | 19   | 18     |

Parallelisable batches (dispatch concurrently, one subagent each):
**{02}** → **{03, 04, 07, 09, 10, 15}** → **{05, 08, 11}** → **{06}** → **12** → **13** → **14** → **{16, 17}** → **18** → **19**.

Note 15 (AWS adapters) depends only on the ports from 02 — it is pure adapter code against a fixed trait and does not need the pipeline. Pulling it into the second batch takes it off the critical path.

---

# PART B — `SHARED.md` content

> Task 00 extracts this entire part verbatim into `docs/plans/cloudtrail-rs/SHARED.md`.

## Global constraints

- **Rust, latest stable, edition 2024.** `rust-toolchain.toml` pins `channel = "stable"`; setup runs `rustup update stable` (currently 1.97.1).
- **Lambda target:** `aarch64-unknown-linux-musl`, runtime `provided.al2023`, built with `cargo lambda` (needs `cargo install cargo-lambda`).
- **Four fully independent entrypoints.** Each binary compiles in exactly one decoder via a Cargo feature (`decode-s3` | `decode-sqs` | `decode-sns` | `decode-eventbridge`, all `default = []`). No runtime source sniffing, no decoder registry, no dead decoders in the artifact.
- **Filter semantics:** exclusion only. Within one rule **ALL** `matches[]` must match (AND). Across rules **ANY** match drops the record (OR).
- **Missing field ⇒ condition FALSE** (rule does not fire, record KEPT). Never fail-open on a typo'd `field_name`.
- **Output:** gzip of `{"Records":[<survivors>]}` — identical envelope to input. Destination key = `key_prefix + source key`.
- **Zero empty writes:** all records dropped ⇒ write nothing.
- **Unparseable individual record ⇒ KEPT**, never dropped.
- **Data errors** (S3 failure, bad gzip, bad JSON) ⇒ `Err` ⇒ Lambda retry ⇒ DLQ. Source is untouched, so replay is lossless.
- **Strict config schema:** `#[serde(deny_unknown_fields)]` on all typed structs.
- **No `unsafe`.** `#![forbid(unsafe_code)]` in every crate.
- **`core` must not depend on any `aws-sdk-*` crate.**
- **Nothing expensive runs per invocation** — see "Cold start and init-once".

## Tech stack

`serde` + `serde_json` (`raw_value`) + `serde_yaml_ng`, `regex`, `flate2` (pure-Rust miniz_oxide backend — clean musl cross-compile), `bytes`, `tokio`, `async-trait`, `thiserror` (libs) / `anyhow` (bins), `tracing` + `tracing-subscriber`, `semver`, `percent-encoding`, `lambda_runtime`, `clap` (CLI), `aws-config` + `aws-sdk-s3` + `aws-sdk-ssm` (aws crate only). Dev: `aws-smithy-mocks`, `tokio-test`, `assert_cmd`.

## Architecture

Hexagonal. `cloudtrail-rs-core` owns all logic and defines four ports as object-safe traits; `cloudtrail-rs-aws` implements the AWS-backed ones; each Lambda binary is a thin composition root wiring `Arc<dyn Port>` into a `Pipeline`. Adding a new event source = one new `EventDecoder` impl behind a new feature + one new bin, zero changes to core. The per-record hot path is pure computation with no trait dispatch; dispatch happens per-object or per-invocation only.

```
lambda-s3   (feature decode-s3)   ─┐
lambda-sqs  (feature decode-sqs)  ─┼─ EventDecoder ─> Vec<SourceItem> ─> Pipeline ─> Engine (pure)
lambda-sns  (feature decode-sns)  ─┤     (port)      {ack_id, objects}      │
lambda-eb   (feature decode-eb)   ─┘                                        │
                                          ObjectStore  (port) ──────────────┤
                                          ConfigSource (port) ──────────────┤
                                          MetricsSink  (port) ──────────────┘
prod: S3ObjectStore / SsmConfigSource, S3ConfigSource, FileConfigSource / EmfMetricsSink
test: InMemoryStore / StaticConfigSource                                / RecordingSink
```

## Binding interfaces

**Every task consumes these names and types verbatim. A subagent that needs to change one must report the deviation rather than change it silently.**

```rust
// core/src/model.rs
pub struct ObjectRef { pub bucket: String, pub key: String, pub size: Option<u64> }
pub struct SourceItem { pub ack_id: Option<String>, pub objects: Vec<ObjectRef> }
pub struct PutMeta { pub content_type: &'static str, pub content_encoding: &'static str }
pub enum VersionTag { Etag(String), Version(i64), Mtime(u64), None }

// core/src/ports.rs
pub trait EventDecoder: Send + Sync {
    fn decode(&self, payload: &[u8]) -> Result<Vec<SourceItem>, DecodeError>;
}
#[async_trait] pub trait ObjectStore: Send + Sync {
    async fn get(&self, b: &str, k: &str) -> Result<Bytes, StoreError>;
    async fn get_stream(&self, b: &str, k: &str)
        -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, StoreError>;
    async fn put(&self, b: &str, k: &str, body: Bytes, meta: PutMeta) -> Result<(), StoreError>;
    async fn put_stream(&self, b: &str, k: &str,
        body: Box<dyn tokio::io::AsyncRead + Send + Unpin>, meta: PutMeta)
        -> Result<(), StoreError>;
}
#[async_trait] pub trait ConfigSource: Send + Sync {
    async fn version(&self) -> Result<VersionTag, ConfigError>;
    async fn fetch(&self) -> Result<(Vec<u8>, VersionTag), ConfigError>;
}
pub trait MetricsSink: Send + Sync { fn emit(&self, snapshot: &MetricSnapshot); }
// MetricSnapshot is a plain data struct (all counters as u64 + Vec<(rule_name, count)> + cold_start).
// Task 02 defines it alongside the trait; Task 09 adds Metrics and the sink impls that produce it.

// core/src/error.rs — StoreError MUST carry a distinct NotFound variant (on_missing_object depends on it)
pub enum StoreError { NotFound { bucket: String, key: String }, /* ... */ }

// core/src/filter/
pub fn resolve<'a>(v: &'a serde_json::Value, path: &str) -> Option<std::borrow::Cow<'a, str>>;
pub enum Decision { Keep, Drop { rule_idx: usize } }
impl Engine {
    // ALL compilation happens here: regexes + rule index. Called once, at config load.
    pub fn new(rules: RuleSet) -> Result<Engine, ConfigError>;
    pub fn rule_name(&self, idx: usize) -> &str;                           // for RuleDrops dimension
    pub fn evaluate(&self, record: &serde_json::Value) -> Decision;        // indexed
    pub fn evaluate_linear(&self, record: &serde_json::Value) -> Decision; // oracle, retained permanently
}

// core/src/metrics.rs
// Process-lived (an Arc<Metrics> is held by ConfigStore across invocations), counters are atomics.
// Pipeline::handle calls snapshot_and_reset() once at the end of each invocation and emits it,
// so a per-invocation EMF line is a DELTA, not a running total.
impl Default for Metrics { /* all counters zero, cold_start flag unset */ }
impl Metrics {
    pub fn snapshot_and_reset(&self) -> MetricSnapshot;
}
// EmfMetricsSink takes plain values, NOT &Settings — Task 09 runs in parallel with Task 07 and
// must not depend on it. The binary maps settings.observability onto these arguments.
impl EmfMetricsSink { pub fn new(namespace: String) -> Self; }
pub struct NoopMetricsSink;   // used when observability.metrics == none

// core/src/config/store.rs
// Generic over the compiled artifact + an injected compile fn. Three reasons this is not hardcoded
// to Engine: it decouples Task 08 from Task 06, it lets ConfigStore tests use T = String with no
// ruleset at all, and it makes "compiled exactly once" directly countable — which is the only way
// Task 16's init-once test can be written.
pub type Compile<T> = Arc<dyn Fn(&[u8]) -> Result<T, ConfigError> + Send + Sync>;
impl<T: Clone + Send + Sync> ConfigStore<T> {
    pub fn new(src: Arc<dyn ConfigSource>, ttl: Duration,
               compile: Compile<T>, metrics: Arc<Metrics>) -> Self;
    pub async fn prime(&self);              // init-phase warm; never errors, never panics
    pub async fn get(&self) -> Option<T>;   // None only if never successfully loaded
}
// Production instantiation: ConfigStore<Arc<Engine>> with
//   compile = |b| Ok(Arc::new(Engine::new(RuleSet::parse(b)?)?))

// core/src/process/
pub fn buffer_run(input: &[u8], engine: &Engine, cfg: &Processing, m: &Metrics)
    -> Result<Outcome, CoreError>;
pub async fn stream_run(input: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    engine: &Engine, cfg: &Processing, m: &Metrics,
    store: &dyn ObjectStore, dest_bucket: &str, dest_key: &str) -> Result<Outcome, CoreError>;
pub enum Outcome {
    Written(Option<Bytes>),  // buffer: gzip bytes to put; stream: None, already put via put_stream
    NothingKept,             // all records dropped => caller writes nothing
    Unrecognized,            // parsed as JSON but no `Records` array => caller applies policy
}

// core/src/pipeline.rs
pub struct BatchOutcome { pub failed_ack_ids: Vec<String> }
impl Pipeline {
    pub fn new(settings: Arc<Settings>, decoder: Arc<dyn EventDecoder>,
               store: Arc<dyn ObjectStore>, config: Arc<ConfigStore<Arc<Engine>>>,
               metrics: Arc<Metrics>, sink: Arc<dyn MetricsSink>) -> Self;
    pub async fn handle(&self, payload: &[u8]) -> Result<BatchOutcome, CoreError>;
}
```

## Settings schema

```yaml
version: 1                        # integer, must equal 1 (NOT semver — the rules file uses semver, this does not)
source:
  include_key_regex: "\\.json\\.gz$"
  exclude_key_regex: "(/CloudTrail-Digest/|/CloudTrail-Insight/|/$)"
destination:
  bucket: ct-siem-sync            # required (or CT_DEST_BUCKET)
  key_prefix: ""                  # "" => key identical to source
processing:
  mode: auto                      # auto | buffer | stream
  stream_threshold_bytes: 8388608
  max_object_bytes: 134217728     # BUFFER MODE ONLY — decompressed guard
  multipart_part_bytes: 8388608   # stream mode
  gzip_level: 6
behavior:
  dry_run: false                  # evaluate + count, forward everything
  on_config_error: open           # open | closed   (DEFAULT: open)
  on_missing_object: error        # error | skip
  on_unrecognized_object: copy    # copy | skip | error
  partial_batch_failures: true    # SQS only
sqs:
  body_format: auto               # auto | s3 | sns — set explicitly to skip the sniff
rules:
  uri: s3://sec-config/cloudtrail/rules.yaml
  ttl_seconds: 300
observability:
  metrics: emf                    # emf | none
  namespace: cloudtrail-rs
  log_level: info
```

Env overrides (env always wins): `CT_DEST_BUCKET`, `CT_KEY_PREFIX`, `CT_SOURCE_INCLUDE_KEY_REGEX`, `CT_SOURCE_EXCLUDE_KEY_REGEX`, `CT_PROCESSING_MODE`, `CT_STREAM_THRESHOLD_BYTES`, `CT_MAX_OBJECT_BYTES`, `CT_MULTIPART_PART_BYTES`, `CT_GZIP_LEVEL`, `CT_DRY_RUN`, `CT_ON_CONFIG_ERROR`, `CT_ON_MISSING_OBJECT`, `CT_ON_UNRECOGNIZED_OBJECT`, `CT_PARTIAL_BATCH_FAILURES`, `CT_SQS_BODY_FORMAT`, `CT_RULES_URI`, `CT_RULES_TTL_SECONDS`, `CT_METRICS`, `CT_METRICS_NAMESPACE`, `CT_LOG_LEVEL`. Bootstrap: `SETTINGS_URI` (optional — an env-only deployment is valid).

## Rules schema

Exactly the user's example: `version` (semver), `meta`, `rules[].name`, `rules[].matches[].{field_name, regex}`.

> `meta` is a **free-form mapping** (`Option<serde_yaml_ng::Mapping>`), parsed but not schema-checked. This is required, not laziness: `created_at: 2024-01-01` parses as a YAML **date**, and typing it as `String` fails on the user's own file. `deny_unknown_fields` still applies at top level and to `Rule`/`Match`.

**Validation** (fatal at load): `version` valid semver, MAJOR == 1; every `regex` compiles within `RegexBuilder::size_limit`; rule `name` non-empty and unique (per-rule metric dimensions collide otherwise); **`matches` non-empty** — an empty list vacuously matches every record and would delete the entire log stream. `rules: []` is accepted.

**URI scheme** (both documents): `ssm://path/to/param` | `s3://bucket/key.yaml` | `file:///abs/path.yaml`.

**Caching:** loaded and compiled once per container into an `RwLock`-guarded `ConfigStore`. After `ttl_seconds`, revalidate — **S3: `HeadObject` ETag (cheap, no body). SSM: `GetParameter` is the only option; the fetch is unavoidable, but an unchanged `Version` skips the re-parse and re-compile.** A refresh failure **keeps the cached ruleset** (log + `ConfigLoadErrors`); `on_config_error` applies only when there is no cached ruleset at all.

**Fail-open scope:** `on_config_error` governs **rules** load failure only, and passthrough is a **raw byte copy** — no decompress, no parse, no size check. Settings load failure is always fatal; without a destination bucket there is nothing to fail open to.

## Safety invariants

Enforced in `Pipeline`, each with a dedicated test:

1. **Self-trigger guard.** If computed destination `(bucket, key)` equals source `(bucket, key)`, return `Err` with an explicit message. Otherwise dest == source is an infinite self-triggering loop that bills until someone notices.
2. **Key filtering before fetch.** `include_key_regex`/`exclude_key_regex` applied to the source key _before_ any `GetObject`, so digest files, Insights files and folder markers cost nothing.
3. **Unrecognized shape.** JSON that parses but has no `Records` array is handled per `on_unrecognized_object` (default `copy` — forwarded verbatim, counted). Never DLQ on an unanticipated shape, never silently discard it.
4. **URL decoding is per-decoder, never shared.** S3 notification keys are **form-urlencoded** (`red flower.jpg` → `red+flower.jpg`, content type `application/x-www-form-urlencoded`), so `+` must decode to a space — plain percent-decoding leaves `+` and every such `GetObject` 404s. **EventBridge keys are NOT encoded**; the same decode there corrupts any key containing `+` or `%`.
5. **Missing `size`.** No size in the event ⇒ `auto` picks **buffer** and relies on `max_object_bytes`.

> ⚠️ **SQS deployment warning.** `ReportBatchItemFailures` must be enabled on the event source mapping. If it is not, the returned `batchItemFailures` is ignored **and** the `Ok` return deletes the failed messages — silent data loss. `partial_batch_failures: false` fails the whole batch instead, which is the safe setting when the mapping is unconfigured.

## Performance design

1. **Zero re-serialization.** Buffer mode parses into `{"Records": Vec<&RawValue>}`; survivors are written as their **original byte slices** joined with `,`. No `Value` is ever re-serialized.
2. **Parse lazily.** Each record is first read into a borrowed `RecordPeek` (`eventSource` only — serde_json skips other fields without building a tree). A full `Value` parse happens only if the rule index yields candidates.
   **Honest limit:** this only pays when the `always` bucket is **empty**. The example ruleset puts ~3 of 25 rules in `always`, so every record gets fully parsed anyway and (2) currently buys nothing there. It is kept because it costs almost nothing and becomes a large win for a ruleset where every rule anchors `eventSource`. Do not claim it as a headline optimization, and have `cloudtrail-rs validate` **warn** for each rule that lands in `always`, naming it — that warning is the user's lever to actually get the speedup.
3. **Rule index.** Extract literal alternations from each rule's `eventSource` pattern (`^kms\.amazonaws\.com$` → one literal; `^(cloudwatch|logs|ec2)\.amazonaws\.com$` → three) into `HashMap<String, Vec<usize>>` plus an `always` bucket. Candidates = `index[eventSource] ∪ always`. **Extraction must be conservative** — inline flags like `(?i)`, character classes, quantifiers, nested groups, non-anchored patterns, or no `eventSource` condition all fall into `always`. Over-inclusion is safe; over-exclusion is a silent correctness bug. In the example ruleset ~3 of 25 rules land in `always`.
4. Conditions inside a rule short-circuit on first failure, most-selective-first (exact literals before `.*`-prefixed patterns).
5. Use `MultiGzDecoder`, never `GzDecoder` — concatenated gzip members are otherwise silently truncated.

**Stream mode** trades (1) for constant memory on **both** sides: streaming `MultiGzDecoder` → `serde_json::Deserializer::from_reader` with a `DeserializeSeed` walking `Records` one `Box<RawValue>` at a time, output flushed through `put_stream` (S3 multipart). `max_object_bytes` applies to **buffer mode only** — stream mode has no input size bound, which is its entire purpose.

**Unrecognized objects in stream mode.** Buffer mode can check for a `Records` array before writing anything; stream mode cannot — by the time the key is known to be absent, a multipart upload may already be in flight. Rule: stream mode returns `Outcome::Unrecognized` **only after** `AbortMultipartUpload`, and `Pipeline` then applies `on_unrecognized_object` by re-fetching and raw-copying. This costs a second `GetObject` on an object that should never occur in practice (large, key-filter-passing, non-CloudTrail), which is the right trade against silently truncating it. A dedicated test drives this path.

**How the abort is triggered without a new port method.** `ObjectStore` deliberately has no `abort` — that would leak multipart, an S3-specific concept, into the core port. Instead `stream_run` runs `put_stream` concurrently against the read half of a duplex pipe and writes survivors into the write half. To cancel, it **fails the reader** (drops the writer with an error rather than a clean EOF); `put_stream` propagates that as `Err(StoreError)` after issuing `AbortMultipartUpload`. `stream_run` knows it caused that error and maps it to `Outcome::Unrecognized` or `Outcome::NothingKept` instead of returning `Err`. The same mechanism covers the all-records-dropped case, so stream mode never leaves a zero-record object at the destination.

## Cold start and init-once

Rust has no `init()` like Go, but Lambda gives the same window: **everything in `main()` before `lambda_runtime::run(...)` is the init phase.** It runs on a full-vCPU burst and is skipped on warm invocations and under provisioned concurrency. Work placed in the handler closure instead runs on _every_ invocation. The split is invisible in a passing test, so it is a stated constraint.

```rust
#[tokio::main(flavor = "current_thread")]           // no worker-thread pool to spin up
async fn main() -> anyhow::Result<()> {
    // ---- INIT: once per container ----
    init_tracing();
    let settings  = Arc::new(Settings::load().await?);          // env + SETTINGS_URI parsed once
    let sdk_conf  = aws_config::load_defaults(...).await;       // credential chain resolved once
    let store     = Arc::new(S3ObjectStore::new(&sdk_conf));    // client + TLS pool
    let decoder   = Arc::new(S3EventDecoder::new());            // the ONE compiled-in decoder
    let cfg_src   = build_config_source(&settings, &sdk_conf)?;
    let metrics   = Arc::new(Metrics::default());               // atomic counters, process-lived
    let sink      = build_sink(&settings.observability);         // Emf | Noop, chosen once
    let cfg_store = Arc::new(ConfigStore::new(
        cfg_src,
        Duration::from_secs(settings.rules.ttl_seconds),
        Arc::new(|b| Ok(Arc::new(Engine::new(RuleSet::parse(b)?)?))),  // <- ALL REGEX COMPILATION
        metrics.clone(),
    ));
    cfg_store.prime().await;                                    // fetch + parse + compile, once
    let pipeline  = Arc::new(Pipeline::new(
        settings, decoder, store, cfg_store, metrics, sink));
    // ---- RUN: closure owns only Arc clones ----
    lambda_runtime::run(service_fn(move |e: LambdaEvent<Value>| {
        let p = pipeline.clone();
        async move { p.handle(...).await }
    })).await
}
```

| Moved to init                                    | Per-invocation cost avoided                        |
| ------------------------------------------------ | -------------------------------------------------- |
| Regex compilation (~80 patterns) + index build    | Largest single cost; tens of ms                    |
| Rules fetch (`prime()`)                           | One S3/SSM round trip, ~10–30 ms                   |
| Settings parse + every `CT_*` env read            | `std::env::var` per field per record adds up       |
| `aws_config::load_defaults` credential chain      | Container-credential HTTP call, ~5–20 ms           |
| `aws_sdk_s3::Client` + connection pool            | TLS handshake to S3, ~50–100 ms                    |
| `tracing_subscriber` registry                     | Re-initialising per call panics or double-logs     |
| `EmfMetricsSink` namespace/dimension strings      | Allocation per invocation                          |

Rules that keep it that way:

1. **Ports are constructed in `main`, never inside the closure.** The closure captures `Arc<Pipeline>` and clones the `Arc` — nothing else. A `::new(` for any adapter inside the closure is a bug.
2. **`prime()` must not abort the container on failure.** A hard `?` turns a transient SSM blip into an init crash, which Lambda retries in a tight loop and which under provisioned concurrency permanently poisons the environment. `prime()` records the failure, increments `ConfigLoadErrors`, returns `()`; the first invocation retries and then applies `on_config_error`. A **settings** failure is still fatal — that is a deployment error, not a transient one.
3. **`prime()` seeds the TTL clock**, so the first invocation does not re-fetch what init just loaded.
4. **`current_thread` Tokio flavor.** Lambda handles one invocation at a time; the multi-thread scheduler pays for workers that never get used. Concurrency _within_ an invocation (parallel `GetObject` across an SQS batch) still works — it is concurrency, not parallelism.
5. **No `lazy_static`/`OnceLock` globals for ports.** They defeat DI and make the Task 14/16 tests impossible. Explicit `Arc` ownership gives the same "computed once" guarantee and stays injectable.
6. **Release profile** (workspace root) — binary size is a real fraction of cold start:
   ```toml
   [profile.release]
   opt-level = 3
   lto = "fat"
   codegen-units = 1
   panic = "abort"
   strip = "symbols"
   ```
7. **rustls, not OpenSSL**, in the AWS SDK connector — no dynamic libssl on musl, no dlopen at startup. Select the **`ring`** crypto provider, not the default `aws-lc-rs`: `aws-lc-rs` needs a working C toolchain for the musl cross-build and is the usual cause of a `cargo lambda build --arm64` that fails only in CI.
8. **No cross-invocation buffer pool.** `Pipeline` sizes its output buffer from `ObjectRef.size` instead of growing from zero; a pool behind a lock adds a failure mode for no measured gain.

**Observability:** emit `ColdStart: 1` on a container's first invocation (an `AtomicBool` flipped in `handle`) and log init duration. Without it there is no way to tell a cold start from a large object in a p99 spike.

## Repo layout

```
Cargo.toml                              workspace + [profile.release]
rust-toolchain.toml                     channel = "stable"
crates/core/                            cloudtrail-rs-core — no AWS deps
  src/{error,ports,model,metrics,pipeline}.rs
  src/config/{rules,settings,uri,store,file_source}.rs
  src/filter/{path,index,engine}.rs
  src/decode/{s3,sns,sqs,eventbridge}.rs   each behind its own feature
  src/process/{buffer,stream}.rs
  src/testing.rs                        InMemoryStore, StaticConfigSource, RecordingSink (feature "testing")
  tests/fixtures/                       gz samples + event envelopes (crate-local: CARGO_MANIFEST_DIR)
crates/aws/                             S3ObjectStore, S3ConfigSource, SsmConfigSource
crates/lambda-s3|sqs|sns|eventbridge/   four bins, one decoder feature each
crates/cli/                             cloudtrail-rs — depends on core + aws (for ssm:// and s3://)
examples/{rules,settings}.example.yaml
docker-compose.test.yml                 ministackorg/ministack :4566
```

---

# PART C — Task briefs

Every task is TDD: write the failing test → run it and watch it fail → implement minimally → run it green → commit. Every task ends green on `cargo test --workspace --all-features` and `cargo clippy --workspace --all-targets --all-features -- -D warnings`.

**Commit message subject must start `task-NN: `** — that prefix is how a resumed session reconstructs progress when `STATUS.md` is stale. No co-author or "generated with" trailers.

Each brief lists **Consumes** (what already exists) and **Produces** (what later tasks rely on) so a subagent never needs a neighbouring brief. Every brief is implemented by a **Sonnet** subagent.

- [ ] **Task 00 — Split this plan** · _orchestrator, not a subagent_ · deps: none
      Create `docs/plans/cloudtrail-rs/`. Copy **this whole document** verbatim into `PLAN.md`. Copy **Part B** verbatim into `SHARED.md`. Copy each task brief from Part C into `task-NN-<slug>.md`, prefixing each with a three-line header: `Read docs/plans/cloudtrail-rs/SHARED.md first.`, the task's deps, and `Do not read other task files.` Create `STATUS.md` in the format given in "Durable state", with every task `pending`. Commit as `task-00: split implementation plan`.
      **Done when:** 23 files exist (`PLAN.md` + `SHARED.md` + `STATUS.md` + `task-00`…`task-19`), all committed, and `task-06-rule-index.md` reads standalone — it names `Engine::evaluate_linear` and `Engine::new` without requiring `task-05`. From this commit on, the repo — not `~/.claude/plans/` — is the source of truth.

- [ ] **Task 01 — Toolchain and workspace** · deps: 00
      `rustup update stable`; `rust-toolchain.toml`; edition-2024 workspace with all seven crates as compiling stubs; decoder feature flags declared in `crates/core/Cargo.toml` (`decode-s3`, `decode-sqs`, `decode-sns`, `decode-eventbridge`, `testing`, all `default = []`); `[profile.release]` from SHARED.md; `#![forbid(unsafe_code)]` in every crate.
      **Produces:** a workspace where `cargo build --workspace` and `cargo test --workspace` both succeed with zero tests.
      **Done when:** both commands pass and `cargo tree -p cloudtrail-rs-core` shows no `aws-sdk-*`.

- [ ] **Task 02 — Errors, model, ports** · deps: 01
      Define `error.rs`, `model.rs`, `ports.rs` **verbatim from SHARED.md's Binding Interfaces**. `StoreError::NotFound { bucket, key }` is mandatory. Also define the `MetricSnapshot` **data struct** here (the `MetricsSink` trait signature needs it, and Task 09 — which adds `Metrics` and the sinks — runs in parallel with three other tasks that would otherwise be blocked on it).
      **Test:** a throwaway struct implements `ObjectStore` and is stored as `Arc<dyn ObjectStore>` — proves object-safety across all four methods including `put_stream`. Same for `ConfigSource` and `MetricsSink`.
      **Produces:** every trait and type all later tasks depend on.

- [ ] **Task 03 — Rules: parse and validate** · deps: 02 · ∥ with 04, 07, 09
      **Consumes:** `ConfigError`. **Produces:** `RuleSet`, `Rule`, `Match`, `RuleSet::parse(&[u8]) -> Result<RuleSet, ConfigError>`. **This task does not compile regexes** — that is `Engine::new` in Task 05/06. It parses and structurally validates only; regex *compilability* is checked here by a throwaway compile in the validator, but no compiled artifact is produced or stored.
      Commit the user's 25-rule example verbatim to **both** `crates/core/tests/fixtures/rules.example.yaml` **and** `examples/rules.example.yaml` — Task 17's CLI tests reference the `examples/` path and run before the docs task. `deny_unknown_fields` on `RuleSet`/`Rule`/`Match`; `meta` free-form.
      **Tests:** parses to 25 rules with expected `matches` counts; **`created_at: 2024-01-01` does not break parsing**; rejects `field_names:` typo, `regexp:` typo, `version: 2.0.0`, uncompilable regex, oversized regex (`size_limit`), duplicate `name`, empty `matches`, empty `name`; accepts `rules: []`.

- [ ] **Task 04 — Field path resolution** · deps: 02 · ∥ with 03, 07, 09
      **Produces:** `pub fn resolve<'a>(v: &'a Value, path: &str) -> Option<Cow<'a, str>>`.
      Dot-path traversal + scalar coercion. **Table-driven test:** string borrowed (assert `Cow::Borrowed`); nested `userIdentity.sessionContext.sessionIssuer.arn`; `readOnly: true` → `"true"`; number → literal; missing → `None`; `null` → `None`; object leaf → `None`; array leaf → `None`; path through a non-object → `None`; **`resources[0].ARN` → `None`** (documented v1 limitation, not a crash).

- [ ] **Task 05 — Rule engine, linear** · deps: 03, 04
      **Consumes:** `RuleSet`, `resolve`. **Produces:** `Decision`, `Engine::new(RuleSet) -> Result<Engine, ConfigError>` (compiles all regexes with `RegexBuilder::size_limit`, no index yet), `Engine::rule_name(idx)`, `Engine::evaluate_linear`.
      AND across `matches`, OR across `rules`, short-circuit on first failing condition, returns the first matching rule index. Conditions ordered most-selective-first (exact literals before `.*`-prefixed patterns).
      **Tests from real records:** EKS KMS `Decrypt` drops via "EKS KMS Operations"; the same record with a different `sourceIPAddress` is KEPT; a `ConsoleLogin` record survives all 25 rules; a record missing `userIdentity.invokedBy` is KEPT by "AWS Config Recorder".

- [ ] **Task 06 — Rule index** · deps: 05
      **Consumes:** `Engine::new`, `Engine::evaluate_linear`. **Produces:** `RuleIndex` built inside `Engine::new` (so it is paid at config load, never per invocation), `Engine::evaluate` (indexed) with semantics identical to `evaluate_linear`, and `Engine::always_rules() -> &[usize]` for the CLI warning in Task 17.
      Conservative literal extraction from anchored `eventSource` patterns; everything uncertain → `always`.
      **Deliverable is the equivalence test:** over the full example ruleset and a ≥500-record fixture corpus, `evaluate` returns `Decision`s identical to `evaluate_linear`. Also assert: "AWS Config Recorder" (`.*\.amazonaws\.com$`) lands in `always`; a `(?i)`-flagged pattern lands in `always`; a record with **no `eventSource`** is evaluated against `always` only and still drops correctly under "IAM Session Renewals".
      `evaluate_linear` stays in the codebase permanently as the oracle.

- [ ] **Task 07 — Settings** · deps: 02 · ∥ with 03, 04, 09
      **Produces:** `Settings` + nested `Source`, `Destination`, `Processing`, `Behavior`, `Sqs`, `Rules`, `Observability`, **plus the enums later tasks match on**: `ProcessingMode {Auto, Buffer, Stream}`, `OnConfigError {Open, Closed}`, `OnMissingObject {Error, Skip}`, `OnUnrecognizedObject {Copy, Skip, Error}`, `SqsBodyFormat {Auto, S3, Sns}`, `MetricsMode {Emf, None}` — and `Settings::load()`. Write `examples/settings.example.yaml` matching SHARED.md exactly.
      **Note:** `SqsBodyFormat` lives here, not in `decode`, so the settings module has no dependency on the decoders (Task 11 depends on this task, not the reverse).
      **Tests:** parses the example; every documented default holds (including both source key regexes); **every** `CT_*` var overrides its file value; loads with **no file** when `CT_DEST_BUCKET` is set; missing destination bucket is a hard error; `version` is an **integer** and anything other than `1` is a hard error (unlike the rules file, this is not semver).

- [ ] **Task 08 — URI, FileConfigSource, ConfigStore, `prime()`** · deps: 07, 09
      **Consumes:** `ConfigSource`, `ConfigError`, `Metrics`. **Produces:** `ConfigUri`, `FileConfigSource`, `Compile<T>`, `ConfigStore<T>::{new, prime, get}` — **generic over the compiled artifact with an injected compile fn**, exactly as in SHARED.md. This task must not reference `RuleSet` or `Engine` at all; its tests instantiate `ConfigStore<String>` with a counting compile closure. That is what makes "compiled exactly once" countable in Task 16.
      **Tests** with a call-counting `StaticConfigSource`: three schemes parse, unknown rejected; within TTL ⇒ zero `version()` calls; past TTL unchanged ⇒ one `version()`, zero re-compiles; past TTL changed ⇒ re-fetch + re-compile; **refresh failure after a successful load ⇒ cached ruleset retained, `ConfigLoadErrors` incremented, no passthrough**; successful `prime()` seeds the TTL clock so an immediate `get()` makes **zero** further calls; **failing `prime()` returns `()`** (no panic, no `Err`), increments `ConfigLoadErrors`, leaves the store empty so the next `get()` retries.

- [ ] **Task 09 — Metrics and EMF** · deps: 02 · ∥ with 03, 04, 07
      **Produces:** `Metrics` (atomic counters, process-lived, `Default`, `snapshot_and_reset()`), `MetricSnapshot`, `EmfMetricsSink::new(namespace: String)` (in **`core`** — needs no AWS SDK), `NoopMetricsSink`, `RecordingSink` (in `testing`).
      `EmfMetricsSink::new` takes plain values, **not `&Settings`** — this task runs in parallel with Task 07 and must not depend on it. The Lambda binary does the mapping.
      `Metrics` is shared by `Arc` across invocations (`ConfigStore` holds one), so each EMF line must be a **delta**: `Pipeline::handle` calls `snapshot_and_reset()` once at the end and emits the result. A test asserts two successive invocations emit independent counts, not a running total — otherwise every CloudWatch number is silently cumulative and unusable.
      One EMF line per invocation on stdout. **Tests:** exact `_aws.CloudWatchMetrics` structure; metric names `ObjectsProcessed`, `ObjectsSkipped`, `UnrecognizedObjects`, `RecordsIn`, `RecordsKept`, `RecordsDropped`, `BytesIn`, `BytesOut`, `ConfigLoadErrors`, `ParseErrors`, `ColdStart`, and per-rule `RuleDrops` with a `Rule` dimension; `ColdStart` is `1` on a process's first emit and `0` thereafter.

- [ ] **Task 10 — S3 and SNS decoders** · deps: 02 · ∥ with 11
      Features `decode-s3`, `decode-sns`. **Produces:** `S3EventDecoder`, `SnsEventDecoder`. Golden tests against verbatim AWS payloads committed as fixtures.
      **Critical test — form-urlencoded keys:** `my+file%3Da.json.gz` → `my file=a.json.gz`; assert both the `+`→space and the `%XX` case. This is the single most common bug in this class of tool.
      Also: `s3:TestEvent` (the flat `{"Service":"Amazon S3","Event":"s3:TestEvent",...}` shape) decodes to an **empty** `Vec<SourceItem>`, not an error. Do not pin `eventVersion` (now unified at 2.5). SNS unwraps `.Records[].Sns.Message` and parses it as an S3 event.

- [ ] **Task 11 — SQS and EventBridge decoders** · deps: 02, 07 · ∥ with 10
      Features `decode-sqs`, `decode-eventbridge`. **Produces:** `SqsEventDecoder::new(body_format)`, `EventBridgeDecoder`.
      SQS: `body_format` `auto` sniffs `"Type":"Notification"` to unwrap SNS; `s3`/`sns` skip the sniff entirely. Each message is one `SourceItem` with `ack_id = messageId`. Golden tests: raw-S3-in-SQS, SNS-in-SQS, and a 3-message batch where message 2 is garbage (only that item errors, siblings decode).
      EventBridge: accept **only `detail-type: "Object Created"`** — `Object Deleted`, `Object Restore Completed`, `Object Annotation Created` decode to **empty, not errors**. Read `detail.bucket.name`, `detail.object.key`, `detail.object.size`; check `detail.event-version` MAJOR == 1. **Assert the key is used verbatim** — a key containing `+` must NOT be decoded (opposite of Task 10).

- [ ] **Task 12 — Buffer processor** · deps: 06, 07, 09 (07 for the `Processing` settings struct)
      **Produces:** `buffer_run(input, engine, cfg, metrics) -> Result<Outcome, CoreError>` — signature and `Outcome` variants exactly as in SHARED.md.
      `MultiGzDecoder` → `Vec<&RawValue>` → peek `eventSource` → `Engine::evaluate` → write surviving **raw slices** → gzip out as `Outcome::Written(Some(bytes))`.
      **Tests:** a kept record's bytes appear **verbatim** in the output; output re-parses to the expected set; `max_object_bytes` exceeded ⇒ `Err`, not OOM; all-dropped ⇒ `Outcome::NothingKept`; empty `Records: []` ⇒ `NothingKept`, not an error; **valid JSON with no `Records` key ⇒ `Outcome::Unrecognized`** (the policy itself lives in Task 14); unparseable record ⇒ kept + `ParseErrors` incremented; a concatenated multi-member gzip is fully read (this test fails with `GzDecoder` and passes with `MultiGzDecoder`).

- [ ] **Task 13 — Stream processor** · deps: 12
      **Produces:** `stream_run(input, engine, cfg, metrics, store, dest_bucket, dest_key) -> Result<Outcome, CoreError>` — signature exactly as in SHARED.md; writes via `ObjectStore::put_stream` and returns `Outcome::Written(None)` because the put already happened.
      Streaming `MultiGzDecoder` + `DeserializeSeed` over `Records`, output flushed incrementally.
      **Deliverable test: byte-for-byte equivalence with buffer mode** on the same fixture (`buffer_run` returns `Written(Some(b))`; `stream_run` into an `InMemoryStore` must leave exactly `b` at the destination key). Plus a large synthetic object asserting **peak buffer size** stays bounded on both input and output — not merely that it succeeds.
      **Unrecognized-shape test:** an object with no `Records` key ⇒ the multipart upload is **aborted** (assert `InMemoryStore` holds nothing at the destination key) and `Outcome::Unrecognized` is returned. All-dropped ⇒ same abort + `NothingKept`; stream mode must never leave a zero-record object behind.
      _Risk:_ if `Box<RawValue>` proves unreliable from a reader-backed deserializer, fall back to `Value` + re-serialize **in stream mode only**; buffer mode (the 99% path) is unaffected. Report the fallback to the orchestrator if taken.

- [ ] **Task 14 — Pipeline** · deps: 08, 11, 13
      **Produces:** `Pipeline::new(settings, decoder, store, config, metrics, sink)` and `Pipeline::handle(&self, payload: &[u8]) -> Result<BatchOutcome, CoreError>` — exactly as in SHARED.md. `handle` decodes the payload through the injected `EventDecoder`, so a test can drive the full path with any decoder (Task 11's SQS decoder is used for the `ack_id` tests).
      Wires the ports and owns the whole policy matrix. All tests use `InMemoryStore` + `StaticConfigSource` + `RecordingSink` — **no AWS**.
      **One test each:** key `include`/`exclude` filtering happens **before** any `get()` (assert zero store calls); **self-trigger guard** errors when dest == source; mode selection from `ObjectRef.size`, absent size ⇒ buffer; `dry_run` forwards everything but still counts drops; all-dropped ⇒ no `put`; dest key = `key_prefix + source key`; `on_unrecognized_object` × {copy, skip, error} in **buffer** mode; **`Outcome::Unrecognized` returned from stream mode ⇒ `on_unrecognized_object: copy` re-fetches the object and raw-copies it** (assert exactly two `get`s and destination bytes equal source bytes); `on_missing_object` × {error, skip} on `StoreError::NotFound`; rules-load failure with `on_config_error: open` ⇒ **raw byte copy** (assert destination bytes equal source bytes exactly, un-decompressed) and with `closed` ⇒ `Err`; one failing `SourceItem` collects its `ack_id` without failing siblings; `partial_batch_failures: false` converts any failure into a whole-batch `Err`.
      **Delta-metrics test:** `handle` calls `Metrics::snapshot_and_reset()` once at the end and emits it to the sink — run two invocations against the same `Pipeline` and assert `RecordsIn` on the second `RecordingSink` line is that invocation's count, not the cumulative total.

- [ ] **Task 15 — AWS adapters** · deps: 02 · ∥ with 05, 08, 10, 11
      **Produces:** `S3ObjectStore`, `S3ConfigSource`, `SsmConfigSource` in `crates/aws`.
      All take an already-built `SdkConfig`/`Client` — **no adapter calls `aws_config::load_defaults` itself**. rustls connector with the **`ring`** crypto provider, not the default `aws-lc-rs`: `aws-lc-rs` needs a C toolchain for the musl cross-build and is the usual cause of a `cargo lambda build --arm64` that works locally and fails in CI. `put_stream` = `CreateMultipartUpload` → `UploadPart`\* (`multipart_part_bytes`) → `Complete`, with **`AbortMultipartUpload` on any error — including an error surfaced by the body reader** so failures leave no billable orphan parts and Task 13 can cancel an upload in flight by failing its reader. `content_type: application/x-gzip`, `content_encoding: gzip`, bucket-default SSE (no hardcoded KMS key). `S3ConfigSource::version` = `HeadObject` ETag; `SsmConfigSource` uses `WithDecryption` + `Version`. Map `NoSuchKey`/404 → `StoreError::NotFound`.
      **Tests** with `aws-smithy-mocks`, including the multipart **abort** path.

- [ ] **Task 16 — Four Lambda binaries** · deps: 14, 15
      Each ≈45 lines, structured **strictly** as the init → run skeleton in SHARED.md — including `#[tokio::main(flavor = "current_thread")]`, `ConfigStore::prime()` before `lambda_runtime::run`, and the production `ConfigStore<Arc<Engine>>` instantiation with `compile = |b| Ok(Arc::new(Engine::new(RuleSet::parse(b)?)?))`. One decoder feature each. SQS bin returns `{"batchItemFailures":[...]}` built from `BatchOutcome::failed_ack_ids`; the others return `()` and propagate `Err`.
      **Init-once test (the deliverable):** build a `Pipeline` over a call-counting `StaticConfigSource` and a `ConfigStore` whose injected compile fn increments an `AtomicUsize`, invoke `handle` **three times**, assert the compile fn ran **exactly once**, `fetch()` was called **exactly once** (by `prime()`), and no adapter was constructed after init. The generic `Compile<T>` from Task 08 exists precisely so this count is observable. Without this, "we build it once" silently regresses the first time someone moves a line into the closure.
      **Feature-isolation test:** `cargo tree -p cloudtrail-rs-lambda-s3 -e features` contains no `decode-sqs`/`decode-sns`/`decode-eventbridge`.
      Plus one golden-payload handler test per binary with fake ports.

- [ ] **Task 17 — CLI** · deps: 14, 15 · ∥ with 16
      `cloudtrail-rs validate <uri>` (build the `Engine`, print rule/pattern counts, non-zero exit on error — the CI gate); `test <rules> <sample.json.gz>` (per-record KEEP/DROP with rule name + summary percentages — also how dead rules get spotted); `filter <in> <out> --rules <uri>` (local/backfill, reuses `buffer_run`). Depends on `core` **and `aws`** so `ssm://` and `s3://` URIs resolve.
      **`validate` must also print a warning line per rule returned by `Engine::always_rules()`**, naming the rule and why it could not be indexed (no `eventSource` condition, or a pattern too complex to extract literals from). That warning is the user's only lever on the index optimization; without it the `always` bucket grows silently and the tool gets slower with no signal. It is a warning, not an error — exit code stays 0.
      **Tests:** `assert_cmd` exit codes on a good config and a deliberately broken copy; `validate examples/rules.example.yaml` warns about "AWS Config Recorder" (`.*\.amazonaws\.com$`) and still exits 0.

- [ ] **Task 18 — MiniStack integration tests** · deps: 16
      `docker-compose.test.yml` running `ministackorg/ministack` on `:4566` (endpoint `http://localhost:4566`, creds `test`/`test`). `crates/aws/tests/ministack.rs`, all `#[ignore]`d. Create source + dest buckets and an SSM parameter, upload a real gz fixture, run the full pipeline through the **real** `S3ObjectStore`/`SsmConfigSource`, assert destination bytes. Cover a small (buffer) **and** a large (stream/multipart) object.
      **Done when:** `cargo test --workspace -- --ignored` passes with the container up and the suite is skipped cleanly without it.

- [ ] **Task 19 — Docs and examples** · deps: 18
      `README.md`: architecture diagram, the four trigger topologies, full env var table, required IAM actions, `cargo lambda build --release --arm64`, rollout guidance (`CT_DRY_RUN=true` → watch `RecordsDropped` → enable).
      **Must include:** the prominent SQS `ReportBatchItemFailures` data-loss warning; a cold-start section (what init does, init vs warm duration, why `ColdStart` is emitted, when provisioned concurrency pays, and the rule that new adapters go in `main` never in the closure); a note that `validate`'s `always`-bucket warnings are worth acting on and how (anchor `eventSource` with a literal alternation); and the **YAML quoting trap** — in double quotes `"\\d"` becomes `\d` (correct), in single quotes or a plain scalar `\\d` stays a literal backslash-backslash-d and will never match.
      `examples/rules.example.yaml` and `examples/settings.example.yaml` already exist (Tasks 03 and 07); verify they still match `crates/core/tests/fixtures/rules.example.yaml` and SHARED.md rather than re-copying.

---

# PART D — Non-goals and verification

## Explicit v1 non-goals

Deferred deliberately — say so if any should move in:

- **Terraform module** (Lambda, IAM, SQS+DLQ with `ReportBatchItemFailures`, S3/EventBridge notifications, DLQ + `ConfigLoadErrors` alarms). Without it, deploying this correctly is a half-day of hand-written IAM — and the SQS setting is a data-loss trap.
- **GitHub Actions CI** (build, clippy, fmt, `validate` the example config, release artifacts).
- **Criterion benchmarks** — "blazingly fast" stays an adjective rather than a tracked number.
- **Array indexing / wildcards** in `field_name` (`resources[*].ARN` unreachable in v1).
- **Regex over object/array subtrees.**
- **Archiving dropped records** for post-hoc audit.
- **Whole-object aho-corasick literal prescan.**

## Verification

**Offline — no AWS, no Docker (the orchestrator runs this after every task):**

```
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --check
```

Green after Task 16 means: the example config parses (dates included) and every rejection case is rejected; the path/coercion table passes; indexed and linear evaluation agree over the corpus; buffer and stream modes emit identical bytes; all four decoders produce correct `SourceItem`s with correct **per-decoder** key handling; the pipeline honours key filters, the self-trigger guard, dry-run, skip-empty, fail-open and partial-batch failure; and three consecutive invocations compile the ruleset once and fetch config once.

**Feature isolation:**

```
cargo tree -p cloudtrail-rs-lambda-s3 -e features | grep -c decode-sqs   # expect 0
```

**CLI:**

```
cargo run -p cloudtrail-rs -- validate file://$PWD/examples/rules.example.yaml
cargo run -p cloudtrail-rs -- test examples/rules.example.yaml crates/core/tests/fixtures/sample.json.gz
```

Expect `ok: 25 rules, N patterns compiled`, non-zero exit on a deliberately broken copy, and a KEEP/DROP breakdown with rule names.

**End-to-end against real AWS APIs:**

```
docker compose -f docker-compose.test.yml up -d
cargo test --workspace -- --ignored
docker compose -f docker-compose.test.yml down
```

Expect the destination bucket to hold an object at the same key whose decompressed body is `{"Records":[...]}` with exactly the expected survivors, for both the buffer and the multipart/stream path.

**Build artifacts:**

```
cargo install cargo-lambda
cargo lambda build --release --arm64
```

Expect four `bootstrap` binaries under `target/lambda/`.

**Proving the tests protect behavior** (a passing suite alone proves nothing — the orchestrator should spot-check these):

- Remove the `+`→space handling in the S3 decoder ⇒ Task 10's key test must fail.
- Make `resolve()` return `Some` for a missing path ⇒ Task 04's fail-safe test must fail.
- Delete the self-trigger guard ⇒ Task 14's loop test must fail.
- Apply S3-style decoding in the EventBridge decoder ⇒ Task 11's verbatim-key test must fail.
- Swap `MultiGzDecoder` for `GzDecoder` ⇒ Task 12's concatenated-member test must fail.
- Move ruleset compilation from init into `Pipeline::handle` ⇒ Task 16's init-once test must fail.
- Let stream mode complete (rather than abort) the multipart upload on an unrecognized object ⇒ Task 13's abort test must fail.
- Replace `snapshot_and_reset()` with a plain `snapshot()` ⇒ Task 09's and Task 14's delta tests must fail.
