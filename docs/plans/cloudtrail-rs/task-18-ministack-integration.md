# Task 18 — MiniStack integration tests

**Read `docs/plans/cloudtrail-rs/SHARED.md` first.**
**Depends on:** 16
**Do not read other task files.**

---

## Brief

`docker-compose.test.yml` running `ministackorg/ministack` on `:4566` (endpoint `http://localhost:4566`, creds `test`/`test`). `crates/aws/tests/ministack.rs`, all `#[ignore]`d. Create source + dest buckets and an SSM parameter, upload a real gz fixture, run the full pipeline through the **real** `S3ObjectStore`/`SsmConfigSource`, assert destination bytes. Cover a small (buffer) **and** a large (stream/multipart) object.
**Done when:** `cargo test --workspace -- --ignored` passes with the container up and the suite is skipped cleanly without it.

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
