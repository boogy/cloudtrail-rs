# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-07-28

Rounds two and three of the data-loss audit: the remaining findings from the
same review — including two more silent-loss paths and the CLI's divergence
from production — followed by a critical re-verification pass focused on
observability, on the principle that a silent failure is only silent because no
metric names it.

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

[Unreleased]: https://github.com/boogy/cloudtrail-rs/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/boogy/cloudtrail-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/boogy/cloudtrail-rs/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/boogy/cloudtrail-rs/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/boogy/cloudtrail-rs/releases/tag/v0.1.0
