# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  neither an error nor a metric. Now counted as `ItemsWithNoObjects`, with a
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

[Unreleased]: https://github.com/boogy/cloudtrail-rs/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/boogy/cloudtrail-rs/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/boogy/cloudtrail-rs/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/boogy/cloudtrail-rs/releases/tag/v0.1.0
