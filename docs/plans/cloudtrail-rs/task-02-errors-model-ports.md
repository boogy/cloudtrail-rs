# Task 02 — Errors, model, ports

**Read `docs/plans/cloudtrail-rs/SHARED.md` first.**
**Depends on:** 01
**Do not read other task files.**

---

## Brief

Define `error.rs`, `model.rs`, `ports.rs` **verbatim from SHARED.md's Binding Interfaces**. `StoreError::NotFound { bucket, key }` is mandatory. Also define the `MetricSnapshot` **data struct** here (the `MetricsSink` trait signature needs it, and Task 09 — which adds `Metrics` and the sinks — runs in parallel with three other tasks that would otherwise be blocked on it).
**Test:** a throwaway struct implements `ObjectStore` and is stored as `Arc<dyn ObjectStore>` — proves object-safety across all four methods including `put_stream`. Same for `ConfigSource` and `MetricsSink`.
**Produces:** every trait and type all later tasks depend on.

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
