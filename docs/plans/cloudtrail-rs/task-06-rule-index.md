# Task 06 — Rule index

**Read `docs/plans/cloudtrail-rs/SHARED.md` first.**
**Depends on:** 05
**Do not read other task files.**

---

## Brief

**Consumes:** `Engine::new`, `Engine::evaluate_linear`. **Produces:** `RuleIndex` built inside `Engine::new` (so it is paid at config load, never per invocation), `Engine::evaluate` (indexed) with semantics identical to `evaluate_linear`, and `Engine::always_rules() -> &[usize]` for the CLI warning in Task 17.
Conservative literal extraction from anchored `eventSource` patterns; everything uncertain → `always`.
**Deliverable is the equivalence test:** over the full example ruleset and a ≥500-record fixture corpus, `evaluate` returns `Decision`s identical to `evaluate_linear`. Also assert: "AWS Config Recorder" (`.*\.amazonaws\.com$`) lands in `always`; a `(?i)`-flagged pattern lands in `always`; a record with **no `eventSource`** is evaluated against `always` only and still drops correctly under "IAM Session Renewals".
`evaluate_linear` stays in the codebase permanently as the oracle.

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
