# Task 05 — Rule engine, linear

**Read `docs/plans/cloudtrail-rs/SHARED.md` first.**
**Depends on:** 03, 04
**Do not read other task files.**

---

## Brief

**Consumes:** `RuleSet`, `resolve`. **Produces:** `Decision`, `Engine::new(RuleSet) -> Result<Engine, ConfigError>` (compiles all regexes with `RegexBuilder::size_limit(crate::config::rules::REGEX_SIZE_LIMIT)` — reuse that existing `pub(crate)` constant from Task 03, do not define your own value; no index yet), `Engine::rule_name(idx)`, `Engine::evaluate_linear`.
AND across `matches`, OR across `rules`, short-circuit on first failing condition, returns the first matching rule index. Conditions ordered most-selective-first (exact literals before `.*`-prefixed patterns).
**Tests from real records:** EKS KMS `Decrypt` drops via "EKS KMS Operations"; the same record with a different `sourceIPAddress` is KEPT; a `ConsoleLogin` record survives all 25 rules; a record missing `userIdentity.invokedBy` is KEPT by "AWS Config Recorder".

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
