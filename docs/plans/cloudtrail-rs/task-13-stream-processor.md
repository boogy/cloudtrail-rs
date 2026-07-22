# Task 13 — Stream processor

**Read `docs/plans/cloudtrail-rs/SHARED.md` first.**
**Depends on:** 12
**Do not read other task files.**

---

## Brief

**Produces:** `stream_run(input, engine, cfg, metrics, store, dest_bucket, dest_key) -> Result<Outcome, CoreError>` — signature exactly as in SHARED.md; writes via `ObjectStore::put_stream` and returns `Outcome::Written(None)` because the put already happened.
Streaming `MultiGzDecoder` + `DeserializeSeed` over `Records`, output flushed incrementally.
**Deliverable test: byte-for-byte equivalence with buffer mode** on the same fixture (`buffer_run` returns `Written(Some(b))`; `stream_run` into an `InMemoryStore` must leave exactly `b` at the destination key). Plus a large synthetic object asserting **peak buffer size** stays bounded on both input and output — not merely that it succeeds.
**Unrecognized-shape test:** an object with no `Records` key ⇒ the multipart upload is **aborted** (assert `InMemoryStore` holds nothing at the destination key) and `Outcome::Unrecognized` is returned. All-dropped ⇒ same abort + `NothingKept`; stream mode must never leave a zero-record object behind.
_Risk:_ if `Box<RawValue>` proves unreliable from a reader-backed deserializer, fall back to `Value` + re-serialize **in stream mode only**; buffer mode (the 99% path) is unaffected. Report the fallback to the orchestrator if taken.

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
