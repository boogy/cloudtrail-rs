# SHARED — cloudtrail-rs binding contracts

**Read this file before your task brief. Every task consumes these names and types
verbatim. If your task cannot be implemented without changing one of them, stop and
report the deviation to the orchestrator instead of changing it silently.**


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

// core/src/error.rs — CoreError is the pipeline/process error type used by the
// buffer_run / stream_run / Pipeline::handle signatures below. Task 02 does NOT
// define it (it has no consumers yet and its variants depend on gzip/json errors
// that only arrive with the processors). **Task 12 defines it**, in the same
// error.rs, and it MUST be able to carry a StoreError and a ConfigError without
// losing the NotFound distinction — Task 14 dispatches on_missing_object off it:
//   pub enum CoreError { Store(StoreError), Config(ConfigError), /* ... */ }
// Tasks 13 and 14 consume it as-is and must not redefine or shadow it.

// core/src/filter/
pub fn resolve<'a>(v: &'a serde_json::Value, path: &str) -> Option<std::borrow::Cow<'a, str>>;
pub enum Decision { Keep, Drop { rule_idx: usize } }
impl Engine {
    // ALL compilation happens here: regexes + rule index. Called once, at config load.
    // MUST compile with RegexBuilder::size_limit(crate::config::rules::REGEX_SIZE_LIMIT)
    // — the same 1 MiB constant RuleSet::parse validates against. A different limit here
    // lets a ruleset pass validation and then fail to build, which at runtime degrades to
    // on_config_error instead of being caught at load. Do not redefine the value locally.
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
    // Increment API (Task 09; consumed verbatim by Tasks 12/13/14 — do NOT invent new names).
    // Each add_* takes a count; record_rule_drop adds 1 for the named rule per call.
    pub fn add_objects_processed(&self, n: u64);
    pub fn add_objects_skipped(&self, n: u64);
    pub fn add_unrecognized_objects(&self, n: u64);
    pub fn add_records_in(&self, n: u64);
    pub fn add_records_kept(&self, n: u64);
    pub fn add_records_dropped(&self, n: u64);
    pub fn add_bytes_in(&self, n: u64);
    pub fn add_bytes_out(&self, n: u64);
    pub fn add_config_load_errors(&self, n: u64);
    pub fn add_parse_errors(&self, n: u64);
    pub fn record_rule_drop(&self, rule_name: &str);
}
// EmfMetricsSink takes plain values, NOT &Settings — Task 09 runs in parallel with Task 07 and
// must not depend on it. The binary maps settings.observability onto these arguments.
// EMF line count: ONE aggregate line per invocation (all counters except RuleDrops) PLUS one
// extra line per distinct rule that dropped records — a flat EMF document holds only one value
// per `Rule` dimension, so 2+ dropping rules cannot share a line without losing per-rule data.
// With 0–1 dropping rules (the common case) this is the single line the plan describes.
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

> **`SETTINGS_URI` scheme resolution (Task 07 → Task 16 contract).** `Settings::load()`
> lives in `core`, which has no `aws-sdk-*` dependency, so it resolves **`file://` only**;
> an `s3://`/`ssm://` `SETTINGS_URI` returns `Err(ConfigError::Source(_))`. The composition
> root (Task 16 bins / Task 17 CLI, which do link `aws`) is responsible for the AWS schemes:
> fetch the settings bytes itself and hand them to a bytes-accepting entry point. Task 07
> exposes the parse/override/validate logic as a private `Settings::from_parts(Option<&[u8]>,
> &dyn Fn(&str)->Option<String>)`; **Task 16 must request it be made `pub` (or a thin public
> wrapper added)** rather than duplicating the env-merge. The `Settings::load()` signature in
> the `main()` skeleton is unchanged for the `file://`/env-only path.

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
