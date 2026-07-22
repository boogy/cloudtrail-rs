# Task 10 — S3 and SNS decoders

**Read `docs/plans/cloudtrail-rs/SHARED.md` first.**
**Depends on:** 02
**Do not read other task files.**

---

## Brief

Features `decode-s3`, `decode-sns`. **Produces:** `S3EventDecoder`, `SnsEventDecoder`. Golden tests against verbatim AWS payloads committed as fixtures.
**Critical test — form-urlencoded keys:** `my+file%3Da.json.gz` → `my file=a.json.gz`; assert both the `+`→space and the `%XX` case. This is the single most common bug in this class of tool.
Also: `s3:TestEvent` (the flat `{"Service":"Amazon S3","Event":"s3:TestEvent",...}` shape) decodes to an **empty** `Vec<SourceItem>`, not an error. Do not pin `eventVersion` (now unified at 2.5). SNS unwraps `.Records[].Sns.Message` and parses it as an S3 event.

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
