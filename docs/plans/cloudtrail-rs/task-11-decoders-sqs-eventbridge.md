# Task 11 — SQS and EventBridge decoders

**Read `docs/plans/cloudtrail-rs/SHARED.md` first.**
**Depends on:** 02, 07
**Do not read other task files.**

---

## Brief

Features `decode-sqs`, `decode-eventbridge`. **Produces:** `SqsEventDecoder::new(body_format)`, `EventBridgeDecoder`.
SQS: `body_format` `auto` sniffs `"Type":"Notification"` to unwrap SNS; `s3`/`sns` skip the sniff entirely. Each message is one `SourceItem` with `ack_id = messageId`. Golden tests: raw-S3-in-SQS, SNS-in-SQS, and a 3-message batch where message 2 is garbage (only that item errors, siblings decode).
EventBridge: accept **only `detail-type: "Object Created"`** — `Object Deleted`, `Object Restore Completed`, `Object Annotation Created` decode to **empty, not errors**. Read `detail.bucket.name`, `detail.object.key`, `detail.object.size`; check `detail.event-version` MAJOR == 1. **Assert the key is used verbatim** — a key containing `+` must NOT be decoded (opposite of Task 10).

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
