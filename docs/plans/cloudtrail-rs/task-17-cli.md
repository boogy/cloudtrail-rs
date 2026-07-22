# Task 17 — CLI

**Read `docs/plans/cloudtrail-rs/SHARED.md` first.**
**Depends on:** 14, 15
**Do not read other task files.**

---

## Brief

`cloudtrail-rs validate <uri>` (build the `Engine`, print rule/pattern counts, non-zero exit on error — the CI gate); `test <rules> <sample.json.gz>` (per-record KEEP/DROP with rule name + summary percentages — also how dead rules get spotted); `filter <in> <out> --rules <uri>` (local/backfill, reuses `buffer_run`). Depends on `core` **and `aws`** so `ssm://` and `s3://` URIs resolve.
**`validate` must also print a warning line per rule returned by `Engine::always_rules()`**, naming the rule and why it could not be indexed (no `eventSource` condition, or a pattern too complex to extract literals from). That warning is the user's only lever on the index optimization; without it the `always` bucket grows silently and the tool gets slower with no signal. It is a warning, not an error — exit code stays 0.
**Tests:** `assert_cmd` exit codes on a good config and a deliberately broken copy; `validate examples/rules.example.yaml` warns about "AWS Config Recorder" (`.*\.amazonaws\.com$`) and still exits 0.

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
