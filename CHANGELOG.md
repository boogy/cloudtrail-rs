# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-09-03

### Added
- **`behavior.on_parse_error` (`CT_ON_PARSE_ERROR`), default `copy`.** An
  object whose bytes will not parse at all — bad gzip, truncated, or not JSON —
  is now forwarded to the destination byte-for-byte instead of failing the
  object, so a downstream SIEM never loses a log to a parse failure. Set it to
  `error` for the previous behavior (fail the object, DLQ it, alert). Copies
  are counted by the new `ObjectsCopiedUnparsed` metric; the object arrives
  unfiltered, so a non-zero count means exclusion rules did not apply to it.
  The policy deliberately does not cover `ObjectTooLarge` (that is
  `on_object_too_large`'s job, and copying such an object would forward it
  unfiltered) or destination-store failures (those must retry). Individual
  malformed _records_ were already kept in both modes and are unaffected.
- **`behavior.on_object_too_large` (`CT_ON_OBJECT_TOO_LARGE`), default
  `stream`.** An object whose body exceeds `processing.max_object_bytes` is now
  retried through stream mode in **every** `processing.mode`, not only `auto`.
  The cap bounds buffer-mode memory, so exceeding it says the path was wrong,
  not the object; stream mode has no size cap and filters it to byte-identical
  output. Previously an explicit `mode: buffer` turned such an object into a
  deterministic poison pill: it failed, was re-driven, failed again, and its
  records reached the SIEM only if someone worked the DLQ. Set it to `error`
  to keep that hard ceiling.

- **`processing.object_concurrency` (`CT_OBJECT_CONCURRENCY`), default `1`.**
  Bounds how many of a batch's objects are fetched, filtered and written at
  once. The default is fully sequential, so behavior and output bytes are
  unchanged unless an operator opts in. Results are adjudicated in submission
  order regardless of completion order, so the failed-ack-id set, its order and
  the error chosen under `partial_batch_failures: false` are identical at every
  concurrency. Each in-flight object holds its own decompressed body, so the
  setting multiplies peak memory by up to `processing.max_object_bytes` per
  slot and is capped at `64`.
- **`processing.gzip_chunks` (`CT_GZIP_CHUNKS`), default `1`.** Buffer mode
  only: splits the output into that many independently-deflated gzip members,
  compressed on that many threads. A gzip stream decompresses to the
  concatenation of its members, so the decompressed payload is byte-identical
  at every chunk count and only the framing and the compressed size change.
  `gzip`/`zcat`, Python's `gzip` module, Node's `zlib.gunzipSync` and Go's
  `compress/gzip` all read it in full, but a strict single-member decoder
  (Python `zlib.decompress(data, 31)`, Rust `flate2::read::GzDecoder`) silently
  returns only the first member — check the downstream reader before enabling. Measured **1.94x** compression speed at `2`
  for **+1.73%** object size, **3.54x** at `4` for **+5.28%**. The chunk count
  is capped so the split is sized around a 64 KiB floor, so a small object
  stays a single member, and the setting is capped at `16`. It only pays above ~1769 MB of Lambda memory,
  where the function has more than one vCPU; the default emits exactly the
  bytes the unchunked encoder did.
- **Operator guidance for both new settings** in `docs/configuration.md`:
  "Choosing an `object_concurrency`" (which triggers can carry more than one
  object, a measured scaling table, and the memory arithmetic) and "Choosing a
  `gzip_chunks`" (the time/size frontier and a verified reader-compatibility
  matrix).
- **`h2 >=0.4.0, <0.4.16` banned** in `deny.toml`, so the shipped HTTP/2 stack
  can never slide back below the RUSTSEC-2026-0258 fix.
- **Two MiniStack integration tests** covering the new settings against a real
  S3: `chunked_gzip_survives_a_real_s3_round_trip` and
  `concurrent_objects_all_land_correctly_in_real_s3`.
- **`deny.toml` pins the compressor backend.** `libz-sys`, `libz-ng-sys`,
  `zlib-ng-sys`, `cloudflare-zlib-sys` and `zlib-rs` join the ban list. The
  first four would put a C toolchain in the graph and break the static-musl /
  ARM64 Lambda cross-build; `zlib-rs` is pure Rust and reaches the shipped
  graph through flate2's own feature, but changes every output object's bytes.
  The parity oracle cannot catch a backend swap, because it compares buffer
  against stream and never against golden bytes.
- **flate2 pinned to `rust_backend` in the four Lambda crates.** They declared
  a bare `flate2 = "1"`, leaning on the default feature happening to mean
  `rust_backend`; the other four crates already pinned it. These are
  dev-dependencies and never reached a shipped binary — the pins are hygiene,
  and `deny.toml` is what actually enforces the backend.
- **A per-object cost profile in `docs/architecture.md`.** Stage timings for
  one 4.5 MB / 4,000-record object: compression at 13.42 ms dominates filtering
  at 5.97 ms, so any optimization that does not touch compression is bounded by
  what is left.
- **A measured `gzip_level` time/size frontier in `docs/configuration.md`**,
  scoped to filter-core CPU and excluding S3 network I/O, so the time column
  reads as an upper bound on what lowering the level saves end-to-end.

### Changed
- **Zero-copy scalar capture in the projected parse.** Captured JSON scalars
  are held as `Cow<'de, str>`: an escape-free scalar borrows a slice of the
  record instead of allocating a `String` per captured field per record.
  `evaluate_raw` improved **14.44%** (p<0.05) on `crates/core/benches/filter.rs`
  (500 scaled records). A separate 4,000-record fixture with realistic entropy
  measured 5.97 ms -> 4.88 ms (-19.7%); that fixture is not in the repo.
- **Buffer-mode decompression buffer pre-sized from gzip's ISIZE trailer.**
  The hint is attacker-controlled, so it is clamped by both
  `processing.max_object_bytes` and DEFLATE's 1032:1 maximum expansion ratio; a
  wrong hint costs a realloc, never correctness, and a lying trailer is still
  rejected by the decoder's own checksum. Decompression measured
  2.5145 ms -> 2.1976 ms (**-12.6%**) on a 4,000-record fixture with realistic
  entropy; output bytes are unchanged.
- **The self-trigger guard now runs before the first `get`.** It was already a
  hard error; it is now raised while building the work list, so a
  misconfigured destination writes nothing at all instead of writing the
  objects that preceded the offending one.
- **Buffer-mode output body assembled in one allocation.** The previous
  `join` + `format!` held two full copies of the body; one `Vec` pre-sized from
  the survivors' lengths holds one. Throughput is unchanged — compression
  dominates the per-object cost — so this is a peak-memory fix, not a speedup.
- **Comments trimmed to the project standard across all eight crates.** 2,408
  comment lines removed, 1,094 added, 31 non-comment lines touched.
- `docs/configuration.md` no longer claims compression is "roughly 77% of
  per-object CPU". That figure divided a whole-body compress by an end-to-end
  run, and the stage shares it implied summed to 126%.

### Fixed
- **A failing object no longer cancels its in-flight siblings.** Under
  `partial_batch_failures: false` the batch's first failure is now held, the
  batch's remaining objects are processed, and only then is it returned.
  Dropping the in-flight futures cancelled them before they reached
  `put_stream`'s own multipart abort, leaving billable orphan parts, and made
  `ObjectsProcessed` depend on `object_concurrency`. The batch now does its
  full work before failing, on the first attempt and on every retry; the writes
  are idempotent, so that is wasted work rather than corruption.
- **An undecodable message no longer withholds its siblings' data.** With
  `partial_batch_failures: false`, one poison message used to abort the batch
  before any object was fetched, so the other messages' objects went unwritten
  on every redrive until the poison message was finally DLQ'd. The batch still
  fails; the siblings' objects are written first.

### Security
- **`h2` bumped 0.4.15 -> 0.4.19** (RUSTSEC-2026-0258, unbounded empty DATA
  frames). The remaining `h2 0.3.27` in the graph is reached only through
  `aws-smithy-http-client`'s `hyper-014` / `legacy-test-util` features, which
  `deny.toml`'s `all-features = true` forces on; `cargo tree -e normal --target
aarch64-unknown-linux-musl` finds zero of it in any of the four Lambdas or the
  CLI. The advisory is ignored for that test-only edge and the ban above keeps
  the shipped line patched.

### Testing
- Two tests pin the `GzEncoder` byte-identity rules: `flush()` inserts a
  DEFLATE sync-flush marker and changes the output bytes, while write
  granularity does not. The no-flush invariant was documented but unenforced —
  a `BufWriter` whose `flush()` forwarded to the encoder would silently break
  buffer/stream byte parity.

## [0.5.0] - 2026-08-06

Two changes to the filtering core, developed together because the second
depends on the first: a **v2 rules schema** that can express matches v1 could
not, and a **projected JSON parse** that makes per-record cost scale with the
fields a ruleset actually reads rather than with the size of the record.

Filtering a record now costs **~1.5 µs** — about **679k records/s** on one core,
roughly **792 MB/s** of decompressed CloudTrail JSON, against 3.2 µs / 314k /
366 MB/s for the full-parse path this replaces. Scope: filter core only. It
excludes gzip decompression, S3 I/O and cold start, which dominate real
wall-clock time.

**v1 rulesets (`version: 1.x`, `field_name`/`regex`) keep working unchanged.
Migrating is optional.**

### Added

- **Rules schema v2.** A condition is now `field` plus exactly one of `regex`,
  `equals`, `any_of` or `absent`, with an optional `negate`, and field paths
  take array subscripts (`resources[0].ARN`, `resources[*].ARN`). Zero
  operators, or two, is a load-time error rather than something resolved by
  precedence. `absent` is the only way to express "this field was never set",
  which v1 could not say at all — the idiom it replaces (a regex that matches
  everything, negated) could not distinguish a missing key from an empty one.
- **`cloudtrail-rs validate --max-unindexed <PERCENT>`.** An opt-in CI gate that
  fails when too large a fraction of a ruleset lands in the catch-all `always`
  bucket, where conditions run against every record instead of being skipped by
  a bit test. The percentage rounds **up**: 1 unindexed rule out of 3 reports
  34% and fails `--max-unindexed 33`.
- **`examples/rules.v2.example.yaml`**, a complete worked reference — 17
  annotated rules over realistic CloudTrail noise covering every v2 option:
  each operator, both `absent` polarities, `negate` paired with all four, fixed
  and wildcard subscripts, deep nested paths, single-dimension rules, and
  scalar coercion (`readOnly: true` matched as `equals: "true"`). The shipped
  `examples/rules.example.yaml` could not absorb these: it is byte-pinned to a
  core test fixture and doubles as the benchmark corpus. Two tests stop the new
  file rotting — it is compiled and checked three ways against the corpus, and
  a second test asserts it still contains every operator, both subscript forms
  and a deep path, so an option cannot be dropped without failing CI.
- **A tuning section in `docs/rules.md`** for the configuration choices that
  decide throughput, written from the semantics they follow from: a matching
  rule DROPS, so a dropped record short-circuits at the first rule that fires
  while a _kept_ record is the expensive case — "no rule matched" can only be
  established by running every candidate rule to completion. The records
  costing the most are therefore the ones being kept, and no rule-writing makes
  them cheaper; only keeping them away from rules does, which is the index.
- **A "three evaluators" section in `docs/architecture.md`.** `Engine` exposes
  three and nothing in prose said why: only `evaluate_raw` filters in
  production; `evaluate` and `evaluate_linear` exist so it can be checked.
- A Performance section in `README.md` with the measured per-record cost, each
  optimization's individual contribution, and a methodology block stating what
  the benchmark excludes.

### Changed

- **Projected JSON parse (~2.16x).** A projection trie built from the ruleset's
  field paths drives a `serde` deserializer that walks and discards untouched
  subtrees instead of materialising a full `Value`. Discarded subtrees are
  still _validated_ — the skip type is a hand-written `Skip` rather than
  `serde::de::IgnoredAny`, so escapes and surrogates in a subtree no rule reads
  still fail the parse exactly as a full parse would. That is load-bearing, not
  incidental: `project()` must return `Err` in exactly the cases
  `serde_json::from_str::<Value>` does, because an `Err` makes the record
  **kept**.
- **The rule index is now two-dimensional (~2.13x)** — `eventSource` _and_
  `eventName` — and takes literals from `equals` and `any_of`, not just from
  anchored regex alternations. Selection is bitset-based: one hash lookup per
  dimension per record, two bit tests per rule, no per-record allocation.
- **`Engine::new` interns duplicate field paths into one projection slot.**
  Every match condition previously got its own slot even when several named the
  same path — the shipped example ruleset has 81 match paths but only 16
  distinct ones, `eventName` alone appearing 25 times. The trie already merged
  them structurally, but the duplicate terminals made the capture step clone
  the captured `String` once per occurrence, per record. Interning by path
  equality is worth **-38.9%** on the projected path, measured back-to-back
  with the two unaffected evaluators as controls.
- `examples/rules.example.yaml` migrated to the v2 schema.
- 17 transitive dependencies updated, including `rustls` 0.23.42 -> 0.23.43.
  `aws-lc-rs`/`aws-lc-sys` remain absent from the lockfile and `ring` stays at
  0.17.14, so the rustls bump did not drag the banned backend in.

### Fixed

- **v1 field paths are lowered literally, so v1 rulesets evaluate unchanged.**
  Development had `Engine::new` compiling _every_ field path through the new
  subscript-aware parser, v1 included — but v1 resolution splits on `.` and
  does literal object-key lookup only, with no subscript syntax. An unchanged
  v1 rule therefore changed meaning: `field_name: "requestParameters.tag[0]"`
  stopped matching the literal key `tag[0]` and started matching the first
  element of an array named `tag`, silently dropping records a deployed ruleset
  used to keep. v1 paths now go through an infallible literal lowering. Never
  released, but the shape is worth recording: it was caught by review, not by
  the suite.
- An inverted describe rule in the shipped example ruleset.

### Testing

- **Three evaluators must agree on every record, permanently.**
  `evaluate_linear` (no index, full `Value`) is the oracle, `evaluate` adds the
  index, `evaluate_raw` adds the projection. Each rung adds exactly one
  optimization, so a disagreement localizes the defect. Over-inclusion by the
  index is safe; **over-exclusion is silent data loss**, which for a CloudTrail
  filter means destroyed audit evidence. Enforced in `crates/core/tests/oracle.rs`,
  including a proptest generator.
- Two blind spots were found by _neutralisation_ — removing a behaviour and
  confirming a test fails — rather than by a green suite. The parity suites are
  differential, comparing buffer against stream, so they go quiet when both
  modes are wrong together: nothing had asserted that an unparseable record
  inside a **successfully written** object survives verbatim with
  `parse_errors: 1`. Separately, the oracle passed 10/10 with a genuine index
  over-exclusion bug injected, because no fixture constructed a record that
  reached it. Both now have permanent fixtures.
- `cargo bench` inherits `profile.release`, which is deliberately lean
  (`opt-level = 1`) for CI smoke builds, while shipped binaries use
  `profile.dist` (`opt-level = 3`, thin LTO). A plain `cargo bench` reports
  ~20% slower than what actually deploys; the README documents the env-var
  override that reproduces the published numbers.

## [0.4.0] - 2026-07-31

Round five: a full-codebase review rather than a diff review, run across
parallel reviewers and then re-verified finding by finding against the source.
Ten candidate findings went in; four were refuted outright (an SNS sibling-loss
claim that turns out to be a _visible_ failure and arguably correct as written,
a retryable/permanent error split with no consumer, a missing-timeout claim
where the SDK defaults do in fact apply, and a test-coverage gap whose fix would
have restructured a composition root for no behavioral gain), one was
downgraded, and the rest are below. Every fix here carries a test that was
proven to fail without it.

### Changed

- **The S3/SNS/SQS decoders now skip notification records that are not
  `ObjectCreated:*`.** `S3RecordEnvelope` carried no `eventName`, and
  `S3Object.size` is optional, so an `ObjectRemoved:*` notification
  deserialized cleanly and became a `GetObject` for a key that had just been
  deleted — a `NotFound`, which `behavior.on_missing_object` turns into a hard
  failure by default. A bulk delete or a lifecycle expiry on the source bucket
  therefore became a storm of invocation failures. The `EventBridge` decoder
  already gated on `detail-type`; the other three now match it. The gate is
  deliberately conservative: a record whose `eventName` is **absent** is still
  kept, because treating a missing field as "drop" would reintroduce exactly
  the silent-loss shape that `S3Notification::records` was made non-defaulting
  to prevent. Both the bare (`ObjectCreated:Put`) and `s3:`-prefixed spellings
  are recognised. Scoping the bucket notification to `s3:ObjectCreated:*` is no
  longer required for correctness, but still avoids the wasted invocation.
- **CI's `security` job is no longer advisory in its entirety.** A job-level
  `continue-on-error: true` made every check in it non-blocking — including
  cargo-deny's `bans` check, which is the third of the three enforcement layers
  the `ring`-not-`aws-lc-rs` decision claims to stand on. A layer that cannot
  fail a build is not a layer. The job is now split by what each check depends
  on: `cargo deny check bans licenses sources` is **blocking**, because it is
  fully determined by `Cargo.lock` and so can never break an unrelated PR;
  `cargo deny check advisories`, `cargo audit` and the Trivy scan stay advisory
  per-step, because they are backed by external databases that update without
  any change to this repository — blocking on those would let an overnight CVE
  disclosure fail every open PR, which is the pressure that produced the
  blanket flag in the first place. `make deny` still runs the full set locally.
- **Releases are tagged on merged `main`, via `make tag`.** The GitHub Release
  already asked for auto-generated notes (`generate_release_notes: true` plus
  the categories in `.github/release.yml`), but v0.2.0 shipped with an empty
  "What's Changed": it was tagged on the PR branch before the squash-merge, and
  GitHub builds that section from the pull requests merged inside the tag's
  commit range — a branch head has none. `make tag` now refuses to tag off
  `main`, on a dirty tree, or when local `main` has drifted from `origin/main`.
  The version bump goes through a PR like any other change.
- `.github/workflows/pr-label.yml` labels each PR from its conventional-commit
  title prefix (`fix:`, `feat:`, `docs:`, `ci:`, `build:`), so it files under
  the right release-notes heading instead of "Other Changes".

### Added

- `make core-no-aws`, wired into CI's lint job: proves `cloudtrail-rs-core` has
  zero AWS dependencies. The hexagonal boundary is the first cross-cutting
  invariant in `CLAUDE.md`, and it was the one with no enforcement behind it —
  `deny.toml` can ban crate _names_, but it cannot express "not reachable from
  this crate". Like `make tree-features` it only resolves the dependency graph
  and builds nothing.

### Fixed

- **A failed `CompleteMultipartUpload` left every uploaded part orphaned in
  S3.** `put_stream` states directly above the call that any failure past that
  point must abort the upload so no billable orphan parts remain, and the
  error arm honoured it — but the success arm reached `CompleteMultipartUpload`
  through `?`, so a transient 5xx or throttle there returned early with no
  abort. The parts stay billed indefinitely and are invisible to `ListObjects`,
  so nothing surfaces them. Both failure sources now flow through a single
  abort call site; the abort stays best-effort and the caller still sees the
  original error.
- **`max_object_bytes` set to `u64::MAX` disabled processing instead of
  disabling the cap.** Both the buffered and streaming read paths computed
  `max_object_bytes + 1` to make an over-cap object detectable without holding
  more than one byte past it. `overflow-checks` is set in neither the `release`
  nor the `dist` profile, so at `u64::MAX` that addition wrapped silently to
  `0` and `take(0)` made every object read zero bytes — failing as a gzip or
  JSON error rather than `ObjectTooLarge`, which in turn meant `mode: auto`
  never fell back to streaming, because that fallback triggers on
  `ObjectTooLarge` alone. Both sites now use `saturating_add(1)`, which leaves
  the cap unsatisfiable at `u64::MAX` — that is, disabled, which is what
  setting it there was meant to express.

### Security

- **The CLI's `filter` batch mode could write outside the destination
  directory.** With an S3 source and a local destination, the relative key was
  derived by a plain `strip_prefix` on the object key and then handed to
  `Path::join`, and `LocalObjectStore::put` creates parent directories before
  writing. Neither `..` components nor absolute paths were rejected, and the
  default `include_key_regex` (`\.json\.gz$`) does not exclude them, so an
  object key controlled by anyone with `s3:PutObject` on the source bucket
  could place a file anywhere the operator running the backfill could write.
  The absolute-path variant needs no `..` at all: a **doubled slash** in the
  key survives the prefix strip as an absolute path, and `Path::join` discards
  its receiver entirely when given one. The fix whitelists
  `std::path::Component::Normal` rather than blacklisting `..`, so both
  variants — and `.`, and Windows prefixes — are rejected by one check. An
  unsafe key fails that object like any other failure: the batch continues, the
  summary still prints, and the exit code is non-zero. The S3-destination path
  is untouched, since `..` in an S3 key is a literal key character and not
  traversal. Lambda deployments were never affected — they write through
  `S3ObjectStore` and never touch a filesystem.

## [0.3.0] - 2026-07-28

Rounds two and three of the data-loss audit: the remaining findings from the
same review — including two more silent-loss paths and the CLI's divergence
from production — followed by a critical re-verification pass focused on
observability, on the principle that a silent failure is only silent because no
metric names it. Round four then swept the result for contradictions, data loss
and metric correctness: most of what it found was in the CLI — the parts of it
that had drifted from the `Pipeline` they are supposed to mirror — plus four
places where the documentation and the code disagreed about what the code does.

### Changed

- **A payload that is valid JSON but carries no `Records` array is now a decode
  failure.** `S3Notification::records` was `#[serde(default)]`, so any JSON
  object whatsoever deserialized to zero objects: an SNS topic carrying
  something that is not an S3 notification, or a notification shape AWS changes
  under us, produced no `SourceItem` at all on the S3/SNS paths and a clean ack
  on SQS — 100% loss with no error, no log and no metric. Such payloads now
  fail (SQS → DLQ, S3/SNS → invocation error). The two legitimate zero-object
  payloads are unaffected: `s3:TestEvent` short-circuits earlier, and an
  explicit `{"Records":[]}` still decodes to an empty list. One operational
  consequence to plan for: an SNS **`SubscriptionConfirmation`** delivered to an
  SQS queue now DLQs rather than being acked silently — only
  `Type: "Notification"` is unwrapped as an SNS envelope.
- **`sqs.body_format: s3` now fails a message whose body is an SNS
  `Notification` envelope** instead of acking it. This is a behavior change
  operators must know about: on a queue actually fed through an SNS topic, that
  misconfiguration used to ack every message with zero objects fetched — 100%
  silent loss, no error, no metric. Such messages are now redelivered and land
  in the DLQ, with an error naming the setting to change (to `sns` or `auto`).
  A correctly configured queue is unaffected.
- **`dry_run` selects the destination, not the mode.** Both the pipeline and the
  CLI short-circuited to a buffer-mode evaluation before consulting
  `select_mode`, so an object large enough to stream in a real run was previewed
  through buffer mode instead, and an object over `max_object_bytes` failed the
  preview outright — the `mode: auto` retry through stream mode never ran,
  because the retry lives on the path the short-circuit skipped. A preview that
  fails an object the real run would have processed is worse than no preview: it
  argues against a ruleset that works. Dry run now picks the same mode the real
  run would pick and executes the real `stream_run` against a new
  `DiscardStore` — a destination that drains the reader to EOF and propagates
  its errors — so the preview's verdict, counters and failure classification are
  the real run's.

### Fixed

- **Stream mode never verified the gzip trailer.** A truncated final gzip member
  or trailing garbage produced a short object that was written and acked as
  complete. The JSON deserializer is now ended before the stream is reported
  finished, so those objects fail instead.
- **A failed object took its siblings down with it.** When one object in an SQS
  message failed, the remaining objects in the same message were skipped; on
  redelivery the poison pill failed first again, so they were never processed.
  Every object in an item is now attempted.
- **Only the first S3 notification record in an SQS body was processed.** A
  message body naming several objects had all but the first dropped, and the
  message acked. All objects are now returned.
- **Duplicate `Records` keys are classified identically in both modes.** Buffer
  mode rejected the object as unrecognized while stream mode streamed both
  arrays. Both now report unrecognized, so `on_unrecognized_object` (default
  `copy`) decides, and the two modes cannot disagree on the same bytes.
- **`BytesOut` counted bytes that never reached the destination.** Three of the
  four counting sites incremented before the write, so a failed `put` /
  `put_stream` still billed its bytes. All four now count after the write
  succeeds.
- **The CLI diverged from production.** `filter` ignored the settings document
  entirely, reimplemented the source-key filter with a hardcoded pattern, and
  buffered every object with one bad object aborting the batch. It now loads
  settings through the production `Settings::from_parts`, shares the single
  `KeyFilter` definition with `Settings::validate` and `Pipeline`, selects
  buffer vs. stream per object exactly as the Lambda does, and accumulates
  per-object failures instead of stopping at the first.
- **Two stream-mode error paths could commit a truncated object.** Returning
  early on a gzip write failure, or on the record producer vanishing, dropped
  the output channel without the abort sentinel — a clean EOF, which
  `put_stream` commits. Both paths now send the sentinel so the multipart
  upload aborts and nothing lands at the destination key.
- **A whole-payload decode failure moved no counter.** Only per-item (SQS
  message body) decode failures incremented `DecodeErrors`, even though a
  whole-payload failure loses every object the invocation carried. Both now
  count.
- **`RecordsIn` diverged between the two modes on failure.** Stream mode
  counted records read before a parse failure; buffer mode counted none. That
  made `RecordsIn == RecordsKept + RecordsDropped` not an invariant, so it
  could not be alarmed on. `RecordsIn` is now counted only alongside
  `RecordsKept`/`RecordsDropped`, and the parity harness asserts both the
  cross-mode equality and the balance itself.
- **`RuleDrops` and `ParseErrors` were published for work that was thrown
  away.** Stream mode counted them as records streamed past, so an object that
  failed _after_ some of its records had been evaluated left drops attributed
  to a rule, and parse errors attributed to records, that were never dropped,
  never kept and never written — and re-counted them on every redelivery of an
  object that kept failing, while `RecordsDropped` for the same snapshot stayed
  at zero. Buffer mode reported nothing for the same bytes. Both counters are
  now tallied locally and committed alongside
  `RecordsIn`/`RecordsKept`/`RecordsDropped`, only once the object has
  succeeded. This makes `sum(RuleDrops) == RecordsDropped` a second
  reconciliation identity, asserted for both modes on every parity case.
- **Record counters were published before the object's write was confirmed.**
  `RuleDrops`/`ParseErrors` had already been deferred to the end of the object,
  but the commit itself still ran before the destination write was checked:
  stream mode committed before `put_stream`'s result was inspected, and buffer
  mode committed inside `buffer_run`, before `Pipeline` had even attempted the
  `put`. A failed write therefore left `RecordsIn`/`RecordsKept`/
  `RecordsDropped`/`ParseErrors`/`RuleDrops` already counted for records that
  never reached the destination — and counted them again on every redelivery,
  since a failed object is re-driven and re-evaluated whole. Both modes now
  accumulate into a shared `RecordTally` and commit it as one unit only past
  every `?`, alongside `BytesOut`: stream mode after `put_stream` returns,
  buffer mode after the `put`. Sharing one tally type is what keeps the two
  modes' arithmetic identical rather than merely similar. Dry-run commits
  immediately (nothing is written, so the fate is decided at once), and stream
  mode's unrecognized path discards the tally, since buffer mode never sees
  those records. Guarded in both modes by a test that fails if the commit moves
  back ahead of the write.
- **`BytesIn` was billed twice for an unrecognized object in stream mode.**
  `on_unrecognized_object: copy` re-reads the object (once to discover it has
  no `Records`, once to copy it) and counted both reads, so the same bytes
  reported double the `BytesIn` above `stream_threshold_bytes` and single
  below it. The copy no longer re-bills what the filtering read already
  counted — the same rule the `ObjectTooLarge` auto-retry already followed.
- **A self-trigger moved no counter.** Refusing to reprocess our own output is
  a hard, whole-batch failure by design, but it returned without touching a
  single metric, so its only trace was the AWS `Errors` metric — which cannot
  distinguish it from a timeout, an OOM, or a permissions failure. It now
  counts as `ObjectsFailed` and logs the source and destination it refused.
- **`dry_run` never reported `UnrecognizedObjects`.** It discarded
  `buffer_run`'s `Outcome`, so the mode meant for previewing a ruleset before
  enabling it was blind to the one outcome `on_unrecognized_object` acts on.
- **Three paths fetched a whole object into memory with no size cap.** The
  `on_config_error: open` passthrough, stream mode's unrecognized-object
  branch, and buffer mode's own fetch all read the entire object before any
  limit applied — `max_object_bytes` was enforced only on the decompressed
  side, reached after the compressed object was already resident. With
  `panic = "abort"`, an OOM kills the container, and on the S3-direct topology
  an async invocation is retried twice and then discarded with no DLQ unless an
  on-failure destination is configured. The passthrough and the
  unrecognized-object copy now stream source to destination (peak memory: one
  multipart part, whatever the object weighs); stream mode's unrecognized
  branch consults `on_unrecognized_object` **before** fetching, so `skip` and
  `error` — which never look at the bytes — do no I/O at all; and buffer mode's
  fetch stops one byte past `max_object_bytes`, raising the same
  `ObjectTooLarge` that `mode: auto` already recovers by retrying through
  stream mode. Capping the compressed read rejects nothing that would have
  survived: gzip output is never meaningfully larger than its input.
- **The CLI had the same two uncapped/eager-fetch bugs, in its own copy of those
  paths.** Its buffer fetch was uncapped although its own comment and
  [`docs/cli.md`](docs/cli.md) both claimed `max_object_bytes` bounded the
  compressed read, so a backfill pointed at an unexpectedly large object could
  exhaust memory on a workstation; and its stream-mode unrecognized branch
  re-fetched the whole object before asking `on_unrecognized_object` what to do
  with it, so `skip` and `error` paid for a full read they never look at. The
  fetch now stops one byte past the cap and raises the same `ObjectTooLarge`
  that `mode: auto` recovers through stream mode, the policy is consulted before
  any I/O, and `copy` streams source to destination.
- **The CLI would filter an object over its own source.** With source and
  destination resolving to the same S3 key or the same local path, `filter`
  wrote the filtered object onto its own original — an unrecoverable destructive
  write, and the one thing the pipeline's self-trigger guard exists to prevent.
  Both sides are now compared (S3 by bucket and key, local by canonicalized
  path) and the run is refused before anything is written; `dry_run` writes
  nothing, so it is exempt.
- **The CLI's dry-run summary never reported unrecognized objects either.** It
  discarded the `Outcome` exactly as `Pipeline::process_dry_run` did. The
  summary now names them, from the metrics snapshot rather than a second,
  re-derived count.
- **`BytesIn` was billed twice for an over-cap object in a dry run.** Once the
  preview gained the `auto` retry, an `ObjectTooLarge` from the buffer attempt
  was billed by `process_dry_run` and again by the stream preview that reads the
  object itself. Dry run now applies the same one-object-one-`BytesIn` rule
  `process_buffer` does.
- **`docs/metrics.md` named the metrics-mode environment variable
  `CT_METRICS_MODE`.** It is `CT_METRICS`; the documented name silently did
  nothing.
- **`docs/metrics.md` and `RecordTally` documented
  `sum(RuleDrops) <= RecordsDropped`.** The relation is `==` — a dropped record
  always names the rule that dropped it — and the weaker claim would have
  admitted exactly the accounting bug the invariant exists to catch.
- **`pipeline.rs` described `max_object_bytes` as a _decompressed_-size cap**, in
  a comment left over from before the fetch itself was capped.

### Removed

- `Metrics::record_rule_drop`, which had no production callers. Every rule drop
  reaches the counters through `RecordTally`, which commits per-rule and
  aggregate drops as one unit after the object's write is confirmed; a second,
  uncommitted path to the same counter could only ever break the
  `sum(RuleDrops) == RecordsDropped` identity.

### Added

- **`ObjectsFailed`.** Under the default `partial_batch_failures: true` a failed
  object returns `Ok` from the handler — the failure travels via
  `batchItemFailures` — so AWS's own `Errors` metric stays at zero and every
  other counter is about objects that succeeded. "Objects are failing and
  heading for the DLQ" previously had no metric at all, only a log line.
- **`ObjectsExcludedByKey`.** A wrong `include_key_regex`/`exclude_key_regex`
  rejects every delivery, and without this counter that state is byte-for-byte
  identical in metrics to a function receiving no traffic at all.
- **[`docs/metrics.md`](docs/metrics.md)** — the full metric reference: every
  counter, both reconciliation invariants, a prioritised alarm table, the
  silent-failure states each counter closes, and the known limitations (no
  `FunctionName` dimension, no snapshot on panic, sparse `RuleDrops`).
- A buffer/stream parity harness (`crates/core/tests/mode_parity.rs`) asserting
  the two modes agree on survivors, counts, and failure classification for the
  same input. The mode is chosen by object **size**, so a disagreement means an
  object silently changes meaning at `stream_threshold_bytes`; the harness is
  now the required home for any change to either processing module.
- `docs/deployment.md` documents that `processing.max_object_bytes` is a
  buffer-mode cap, not an object-size limit — the operational ceiling is the
  function timeout — and the S3-direct topology's residual risk (an async
  invocation that keeps timing out is discarded without an on-failure
  destination).
- `docs/metrics.md` documents that the two modes bill `BytesIn` differently on a
  **failed** object, deliberately: buffer mode has the whole compressed object in
  hand before it filters anything and bills the full length, while stream mode
  bills only what it had read when it aborted. A successful object bills the same
  either way. Alarms on `BytesIn` should expect it to dip when a large object
  fails in stream mode.

## [0.2.0] - 2026-07-28

A workspace-wide test-coverage audit, prioritising anything that could lose a
CloudTrail record silently. Ten findings, plus two the verification itself
surfaced; the suite goes 166 → 200 tests.

### Fixed

- **SQS deleted messages it could not decode.** A message whose body failed to
  decode never became a `SourceItem`, so its `messageId` never reached
  `failed_ack_ids`, so `batchItemFailures` omitted it, so SQS deleted it — the
  referenced S3 object was never processed and never retried. Undecodable
  records now surface as `SourceItem::undecodable`, land in the batch-failure
  list, and are redelivered.
- **A wrong `sqs.body_format` discarded 100% of traffic in silence.** Valid
  JSON of the wrong shape decoded to zero objects, acked clean, and emitted
  neither an error nor a metric. Now counted as `ItemsWithoutObjects`, with a
  documented alarm.
- **Stream mode never reported `BytesIn`/`BytesOut`.** Every object above
  `processing.stream_threshold_bytes` contributed zero to both counters —
  under-reporting on exactly the large objects operators reconcile
  input-vs-output volume on. `BytesOut` is committed only when the multipart
  upload commits, so an aborted upload bills nothing.
- **The self-trigger guard missed same-bucket destinations with a prefix.**
  Only exact source/destination key equality was caught, so a destination in
  the source bucket under a `key_prefix` re-triggered the Lambda on its own
  output — unbounded recursion. The guard is now prefix-aware.
- `processing.multipart_part_bytes` was dead in production: every Lambda
  composition root built the store with the default part size, so the
  configured value was parsed and then ignored. Now wired through
  `S3ObjectStore::from_settings`.
- The stream reader reported EOF on a zero-capacity read, which would silently
  truncate an object; both the sync and async readers now answer a
  no-capacity read without consuming from the channel.
- Key regexes compiled in `Pipeline::new` skipped the `REGEX_SIZE_LIMIT`
  applied to rule patterns.
- `make tree-features`, which proves the one-decoder-per-binary invariant,
  failed the build precisely when the invariant _held_ (`grep -c` exits 1 on
  zero matches) and ran in neither `make ci` nor CI — so the invariant was
  enforced nowhere. Rewritten, and now enforced in both.

### Added

- `cloudtrail-rs validate-settings [path]` — runs a settings document through
  the exact `Settings::from_parts` the Lambda binaries run at cold start,
  `CT_*` overrides included, so bad config is caught pre-deploy instead of on
  the first invocation. Omit `path` to validate the built-in defaults plus the
  current environment.
- One workspace version, inherited by all eight crates via
  `version.workspace = true`, with `make bump VERSION=x.y.z` and
  `make version-check`. `release.yml`'s `setup` job gates every other job on
  it, so a tag that disagrees with the workspace version fails the release
  before a single binary is built.

### Changed

- **Settings that previously loaded may now be rejected.** The release profile
  sets `panic = "abort"`, so a bad config value is not a bad object but a
  poison pill — the process dies on every invocation until the DLQ or the
  retention window absorbs the backlog. These are now validated once, at load:
  `processing.gzip_level` must be `0`–`9` (flate2 panics above 9);
  `source.include_key_regex` / `source.exclude_key_regex` must compile;
  `processing.max_object_bytes` must be `>=
processing.stream_threshold_bytes`; `processing.multipart_part_bytes` must
  be at least S3's 5 MiB minimum. Run `validate-settings` against your
  deployment before upgrading.
- In `auto` mode, an object that exceeds `max_object_bytes` in buffer mode is
  now retried through stream mode instead of failing permanently.

## [0.1.1] - 2026-07-24

### Fixed

- Release signing failed under cosign v4, which defaults to `--new-bundle-format`
  and ignores `--output-signature`/`--output-certificate`. `sign-blob` now emits a
  single `checksums.txt.cosign.bundle` (signature + certificate).

### Changed

- Bump `actions/upload-artifact` v4.6.2 → v7.0.1 and `actions/download-artifact`
  v4.3.0 → v8.0.1, moving both off the deprecated Node 20 runtime.

## [0.1.0] - 2026-07-24

### Added

- Initial release. Filters AWS CloudTrail logs in flight: reads a `.json.gz`
  CloudTrail object, drops `Records` matching configured exclusion rules, and
  re-packs the survivors into the same `gzip({"Records":[...]})` envelope in a
  destination bucket.
- Hexagonal core (`cloudtrail-rs-core`) with zero AWS dependencies; every crate is
  `#![forbid(unsafe_code)]`.
- Four independent Lambda binaries — S3, SNS, SQS, EventBridge — each compiling in
  exactly one event decoder behind a Cargo feature.
- Local/offline CLI (`cloudtrail-rs`) with `validate`, `test`, and `filter`
  (single file, folder, and `s3://` batch mode).
- Rule engine with `eventSource`-anchored literal indexing; buffered and
  constant-memory streaming processing modes (`auto` by object size).
- AWS adapters: `S3ObjectStore`, `S3ConfigSource`, and `SsmConfigSource`; a Settings
  schema with `CT_*` environment overrides.
- Metrics with EMF and Noop sinks.
- Release pipeline: multi-arch musl + native darwin builds, `checksums.txt`, cosign
  keyless signing, build-provenance attestation, multi-arch container images to
  GHCR + Docker Hub, Trivy image scans, and a published Homebrew cask.
- MiniStack integration tests for the S3/SSM adapters.

[Unreleased]: https://github.com/boogy/cloudtrail-rs/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/boogy/cloudtrail-rs/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/boogy/cloudtrail-rs/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/boogy/cloudtrail-rs/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/boogy/cloudtrail-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/boogy/cloudtrail-rs/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/boogy/cloudtrail-rs/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/boogy/cloudtrail-rs/releases/tag/v0.1.0
