# Task 07 — Settings

**Read `docs/plans/cloudtrail-rs/SHARED.md` first.**
**Depends on:** 02
**Do not read other task files.**

---

## Brief

**Produces:** `Settings` + nested `Source`, `Destination`, `Processing`, `Behavior`, `Sqs`, `Rules`, `Observability`, **plus the enums later tasks match on**: `ProcessingMode {Auto, Buffer, Stream}`, `OnConfigError {Open, Closed}`, `OnMissingObject {Error, Skip}`, `OnUnrecognizedObject {Copy, Skip, Error}`, `SqsBodyFormat {Auto, S3, Sns}`, `MetricsMode {Emf, None}` — and `Settings::load()`. Write `examples/settings.example.yaml` matching SHARED.md exactly.
**Note:** `SqsBodyFormat` lives here, not in `decode`, so the settings module has no dependency on the decoders (Task 11 depends on this task, not the reverse).
**Tests:** parses the example; every documented default holds (including both source key regexes); **every** `CT_*` var overrides its file value; loads with **no file** when `CT_DEST_BUCKET` is set; missing destination bucket is a hard error; `version` is an **integer** and anything other than `1` is a hard error (unlike the rules file, this is not semver).

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
