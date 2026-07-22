# Task 00 — Split this plan

**Read `docs/plans/cloudtrail-rs/SHARED.md` first.**
**Depends on:** none
**Do not read other task files.**

---

## Brief

Create `docs/plans/cloudtrail-rs/`. Copy **this whole document** verbatim into `PLAN.md`. Copy **Part B** verbatim into `SHARED.md`. Copy each task brief from Part C into `task-NN-<slug>.md`, prefixing each with a three-line header: `Read docs/plans/cloudtrail-rs/SHARED.md first.`, the task's deps, and `Do not read other task files.` Create `STATUS.md` in the format given in "Durable state", with every task `pending`. Commit as `task-00: split implementation plan`.
**Done when:** 23 files exist (`PLAN.md` + `SHARED.md` + `STATUS.md` + `task-00`…`task-19`), all committed, and `task-06-rule-index.md` reads standalone — it names `Engine::evaluate_linear` and `Engine::new` without requiring `task-05`. From this commit on, the repo — not `~/.claude/plans/` — is the source of truth.

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
