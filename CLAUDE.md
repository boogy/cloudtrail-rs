# CLAUDE.md — cloudtrail-rs

Root guide and index. This file holds workspace-wide invariants and points into
per-folder `CLAUDE.md` files for local detail. When working inside a crate, read
that crate's `CLAUDE.md` too — it overrides/extends anything here for that folder.

## What this is

`cloudtrail-rs` filters AWS CloudTrail `.json.gz` logs in flight: drop the
`Records` entries matching an exclusion rule, re-pack survivors into the same
`gzip({"Records":[...]})` envelope, write to a destination bucket. Ships as
**four independent Lambda binaries** (one per trigger topology) plus a
local/offline **CLI**, on a hexagonal core. Every crate is `#![forbid(unsafe_code)]`.

## Workspace map

| Folder                      | Crate                   | Local guide                                      | Purpose                                                                         |
| --------------------------- | ----------------------- | ------------------------------------------------ | ------------------------------------------------------------------------------- |
| `crates/core`               | `cloudtrail-rs-core`    | [CLAUDE.md](crates/core/CLAUDE.md)               | Hexagonal core: filtering engine, ports, decoders, pipeline. **Zero AWS deps.** |
| `crates/aws`                | `cloudtrail-rs-aws`     | [CLAUDE.md](crates/aws/CLAUDE.md)                | AWS adapters (S3/SSM) behind core's ports. Owns the **ring TLS** decision.      |
| `crates/cli`                | `cloudtrail-rs`         | [CLAUDE.md](crates/cli/CLAUDE.md)                | Local/offline CLI: `validate` / `validate-settings` / `test` / `filter`.        |
| `crates/lambda-s3`          | —                       | [CLAUDE.md](crates/lambda-s3/CLAUDE.md)          | Composition root, `decode-s3`.                                                  |
| `crates/lambda-sns`         | —                       | [CLAUDE.md](crates/lambda-sns/CLAUDE.md)         | Composition root, `decode-sns`.                                                 |
| `crates/lambda-sqs`         | —                       | [CLAUDE.md](crates/lambda-sqs/CLAUDE.md)         | Composition root, `decode-sqs`. **Batch-failure invariant.**                    |
| `crates/lambda-eventbridge` | —                       | [CLAUDE.md](crates/lambda-eventbridge/CLAUDE.md) | Composition root, `decode-eventbridge`.                                         |
| `crates/testkit`            | `cloudtrail-rs-testkit` | [CLAUDE.md](crates/testkit/CLAUDE.md)            | Test-only: fake Lambda Runtime API, MiniStack clients, fixtures.                |

Prose docs live in [`docs/`](docs/README.md): architecture, configuration, rules,
deployment, cli, development. The root [`README.md`](README.md) is the user-facing intro.

## Cross-cutting invariants (do not break)

1. **Hexagonal boundary.** `core` has **zero AWS dependencies**. AWS is reached
   only through the four object-safe ports in `crates/core/src/ports.rs`
   (`EventDecoder`, `ObjectStore`, `ConfigSource`, `MetricsSink`). New AWS code
   goes in `crates/aws`, never in `core`.
2. **One decoder per binary.** Each Lambda compiles in exactly one `EventDecoder`
   via a `decode-*` Cargo feature — no runtime source sniffing, no dead decoder
   code in the artifact. `make tree-features` proves `lambda-s3` pulls in no other
   decoder (expect 0).
3. **Cold-start init-once.** Every port is constructed once in each Lambda `main`
   before `lambda_runtime::run`; the handler closure captures only `Arc<Pipeline>`
   and never constructs an adapter. Per-record work is pure computation.
4. **ring, never aws-lc-rs.** The TLS crypto backend is `rustls` + `ring`;
   `aws-lc-rs`/`aws-lc-sys` are banned in `deny.toml`. See the decision record
   below and [`crates/aws/CLAUDE.md`](crates/aws/CLAUDE.md).
5. **SQS = `ReportBatchItemFailures` mandatory.** Without it a partial batch
   failure is silent, unrecoverable data loss. See
   [`crates/lambda-sqs/CLAUDE.md`](crates/lambda-sqs/CLAUDE.md).
6. **One version, and it equals the tag.** No crate carries its own `version` —
   all eight inherit `[workspace.package] version` via `version.workspace = true`.
   Release = `make bump VERSION=x.y.z` → commit → `git tag vx.y.z`.
   `make version-check` (release.yml's `setup` job, which gates every other
   job) fails the release if a crate breaks inheritance or the tag disagrees.
   The tag is what `crates/core/build.rs` bakes into the binaries.

## Build / test

Stable toolchain (`rust-toolchain.toml`). Common `make` targets:

- `make check` — fast type-check.
- `make test` — full suite, all features.
- `make ci` — what CI enforces: `fmt-check` + `clippy` (warnings = errors) + tests + `audit`.
- `make deny` — licenses/bans/advisories/sources (enforces the ring ban).
- `make release` — fast lean `release` build (verify it builds/links).
- `make lambda-build` — cross-compile the four `bootstrap` binaries, `dist` profile (needs `cargo-lambda`).
- `make ministack-up` then `make ministack-test` — `#[ignore]`d local S3/SSM integration tests.
- `make bump VERSION=x.y.z` / `make version-check` — the release version gate (invariant 6).

Two profiles in root `Cargo.toml`: `release` (lean, CI smoke — proves static-musl

- ring links) and `dist` (shipped artifacts, thin LTO).

## Decision record: ring vs aws-lc-rs

**Choice:** standardize on `rustls` + `ring`; ban `aws-lc-rs`/`aws-lc-sys`
(`deny.toml`). Enforced in three layers — Cargo features (`rustls-ring` on
`aws-smithy-http-client`, `aws-config` with `default-features = false`), the
explicit client wiring in `crates/aws/src/http_client.rs`, and the cargo-deny ban.

**Why:** `aws-lc-rs` compiles a BoringSSL-derived C library (`aws-lc-sys`) from
source via CMake. That breaks — or slows and destabilizes — the static-musl /
ARM64 Lambda cross-build (the classic "works locally, fails in CI"). `ring` is
pre-generated asm + minimal C and cross-compiles with just the Rust target.

**Cost of the current choice:** we're on the non-default path (both the AWS SDK
and rustls 0.23+ default to `aws-lc-rs`), so we carry the `http_client.rs`
workaround and the `default-features = false` dance permanently, and each SDK
upgrade is a place that can re-break (e.g. the IMDS-panic fix documented in that
module).

**Future risk of staying on ring:** single-maintainer project with slower CVE
turnaround; growing config drift as the ecosystem leans into `aws-lc-rs`.
`deny.toml` mitigates via `unmaintained = "workspace"` (warn) and `yanked = "deny"`.

**The one-way door — FIPS.** `aws-lc-rs` has a FIPS 140-3 validated mode; `ring`
does not and cannot. If FIPS (GovCloud / FedRAMP / regulated) becomes a
requirement, we are forced onto `aws-lc-rs`. That is the decisive question.

**Reversibility:** the choice is isolated behind `http_client.rs` + two feature
flags + `deny.toml`. No data/wire/API coupling, no migration, runtime behavior
identical. Reversible either way anytime — **if** you (a) add the C cross-toolchain
to CI _and_ (b) lift the `deny.toml` bans in the _same_ change, or `cargo deny`
and the release build fail. FIPS is the only thing that makes it one-way.
Full breakdown in [`crates/aws/CLAUDE.md`](crates/aws/CLAUDE.md).
