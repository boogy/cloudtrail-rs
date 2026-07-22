# Task 12 — Buffer processor

**Read `docs/plans/cloudtrail-rs/SHARED.md` first.**
**Depends on:** 06, 07, 09 (07 for the `Processing` settings struct)
**Do not read other task files.**

---

## Brief

**Produces:** `buffer_run(input, engine, cfg, metrics) -> Result<Outcome, CoreError>` — signature and `Outcome` variants exactly as in SHARED.md.
`MultiGzDecoder` → `Vec<&RawValue>` → peek `eventSource` → `Engine::evaluate` → write surviving **raw slices** → gzip out as `Outcome::Written(Some(bytes))`.
**Tests:** a kept record's bytes appear **verbatim** in the output; output re-parses to the expected set; `max_object_bytes` exceeded ⇒ `Err`, not OOM; all-dropped ⇒ `Outcome::NothingKept`; empty `Records: []` ⇒ `NothingKept`, not an error; **valid JSON with no `Records` key ⇒ `Outcome::Unrecognized`** (the policy itself lives in Task 14); unparseable record ⇒ kept + `ParseErrors` incremented; a concatenated multi-member gzip is fully read (this test fails with `GzDecoder` and passes with `MultiGzDecoder`).

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
