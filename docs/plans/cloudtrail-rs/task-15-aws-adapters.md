# Task 15 — AWS adapters

**Read `docs/plans/cloudtrail-rs/SHARED.md` first.**
**Depends on:** 02
**Do not read other task files.**

---

## Brief

**Produces:** `S3ObjectStore`, `S3ConfigSource`, `SsmConfigSource` in `crates/aws`.
All take an already-built `SdkConfig`/`Client` — **no adapter calls `aws_config::load_defaults` itself**. rustls connector with the **`ring`** crypto provider, not the default `aws-lc-rs`: `aws-lc-rs` needs a C toolchain for the musl cross-build and is the usual cause of a `cargo lambda build --arm64` that works locally and fails in CI. `put_stream` = `CreateMultipartUpload` → `UploadPart`\* (`multipart_part_bytes`) → `Complete`, with **`AbortMultipartUpload` on any error — including an error surfaced by the body reader** so failures leave no billable orphan parts and Task 13 can cancel an upload in flight by failing its reader. `content_type: application/x-gzip`, `content_encoding: gzip`, bucket-default SSE (no hardcoded KMS key). `S3ConfigSource::version` = `HeadObject` ETag; `SsmConfigSource` uses `WithDecryption` + `Version`. Map `NoSuchKey`/404 → `StoreError::NotFound`.
**Tests** with `aws-smithy-mocks`, including the multipart **abort** path.

---

## How to work this task

- **TDD, strictly.** Write the failing test first, run it and watch it fail for the
  right reason, implement the minimum that makes it pass, run it green, commit.
- **Stay in scope.** Do not read other task files. Do not refactor code belonging to
  other tasks. If this brief cannot be implemented as written, stop and report to the
  orchestrator rather than expanding scope or inventing an interface.
- **Green before you commit:** `cargo test --workspace --all-features` and
  `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- **Commit message subject must start `task-NN: `.** No co-author or "generated with"
  trailers. One task, one logical commit.
- **Never undo your own edits with git** (`checkout`/`restore`/`stash`/`reset --hard`) —
  it destroys uncommitted work. Reverse the edit the same way you made it.

## Report back

Files changed, test names added, commit sha, and **any interface deviation** from
`SHARED.md`.
