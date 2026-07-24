# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/boogy/cloudtrail-rs/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/boogy/cloudtrail-rs/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/boogy/cloudtrail-rs/releases/tag/v0.1.0
