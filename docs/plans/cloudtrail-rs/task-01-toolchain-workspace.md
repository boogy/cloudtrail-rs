# Task 01 — Toolchain and workspace

**Read `docs/plans/cloudtrail-rs/SHARED.md` first.**
**Depends on:** 00
**Do not read other task files.**

---

## Brief

`rustup update stable`; `rust-toolchain.toml`; edition-2024 workspace with all seven crates as compiling stubs; decoder feature flags declared in `crates/core/Cargo.toml` (`decode-s3`, `decode-sqs`, `decode-sns`, `decode-eventbridge`, `testing`, all `default = []`); `[profile.release]` from SHARED.md; `#![forbid(unsafe_code)]` in every crate.
**Produces:** a workspace where `cargo build --workspace` and `cargo test --workspace` both succeed with zero tests.
**Done when:** both commands pass and `cargo tree -p cloudtrail-rs-core` shows no `aws-sdk-*`.

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
