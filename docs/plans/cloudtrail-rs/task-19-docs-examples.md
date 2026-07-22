# Task 19 — Docs and examples

**Read `docs/plans/cloudtrail-rs/SHARED.md` first.**
**Depends on:** 18
**Do not read other task files.**

---

## Brief

`README.md`: architecture diagram, the four trigger topologies, full env var table, required IAM actions, `cargo lambda build --release --arm64`, rollout guidance (`CT_DRY_RUN=true` → watch `RecordsDropped` → enable).
      **Must include:** the prominent SQS `ReportBatchItemFailures` data-loss warning; a cold-start section (what init does, init vs warm duration, why `ColdStart` is emitted, when provisioned concurrency pays, and the rule that new adapters go in `main` never in the closure); a note that `validate`'s `always`-bucket warnings are worth acting on and how (anchor `eventSource` with a literal alternation); and the **YAML quoting trap** — in double quotes `"\\d"` becomes `\d` (correct), in single quotes or a plain scalar `\\d` stays a literal backslash-backslash-d and will never match.
      `examples/rules.example.yaml` and `examples/settings.example.yaml` already exist (Tasks 03 and 07); verify they still match `crates/core/tests/fixtures/rules.example.yaml` and SHARED.md rather than re-copying.

---

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
