# Task 14 — Pipeline

**Read `docs/plans/cloudtrail-rs/SHARED.md` first.**
**Depends on:** 08, 11, 13
**Do not read other task files.**

---

## Brief

**Produces:** `Pipeline::new(settings, decoder, store, config, metrics, sink)` and `Pipeline::handle(&self, payload: &[u8]) -> Result<BatchOutcome, CoreError>` — exactly as in SHARED.md. `handle` decodes the payload through the injected `EventDecoder`, so a test can drive the full path with any decoder (Task 11's SQS decoder is used for the `ack_id` tests).
Wires the ports and owns the whole policy matrix. All tests use `InMemoryStore` + `StaticConfigSource` + `RecordingSink` — **no AWS**.
**One test each:** key `include`/`exclude` filtering happens **before** any `get()` (assert zero store calls); **self-trigger guard** errors when dest == source; mode selection from `ObjectRef.size`, absent size ⇒ buffer; `dry_run` forwards everything but still counts drops; all-dropped ⇒ no `put`; dest key = `key_prefix + source key`; `on_unrecognized_object` × {copy, skip, error} in **buffer** mode; **`Outcome::Unrecognized` returned from stream mode ⇒ `on_unrecognized_object: copy` re-fetches the object and raw-copies it** (assert exactly two `get`s and destination bytes equal source bytes); `on_missing_object` × {error, skip} on `StoreError::NotFound`; rules-load failure with `on_config_error: open` ⇒ **raw byte copy** (assert destination bytes equal source bytes exactly, un-decompressed) and with `closed` ⇒ `Err`; one failing `SourceItem` collects its `ack_id` without failing siblings; `partial_batch_failures: false` converts any failure into a whole-batch `Err`.
**Delta-metrics test:** `handle` calls `Metrics::snapshot_and_reset()` once at the end and emits it to the sink — run two invocations against the same `Pipeline` and assert `RecordsIn` on the second `RecordingSink` line is that invocation's count, not the cumulative total.

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
