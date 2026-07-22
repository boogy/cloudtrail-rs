# Task 16 — Four Lambda binaries

**Read `docs/plans/cloudtrail-rs/SHARED.md` first.**
**Depends on:** 14, 15
**Do not read other task files.**

---

## Brief

Each ≈45 lines, structured **strictly** as the init → run skeleton in SHARED.md — including `#[tokio::main(flavor = "current_thread")]`, `ConfigStore::prime()` before `lambda_runtime::run`, and the production `ConfigStore<Arc<Engine>>` instantiation with `compile = |b| Ok(Arc::new(Engine::new(RuleSet::parse(b)?)?))`. One decoder feature each. SQS bin returns `{"batchItemFailures":[...]}` built from `BatchOutcome::failed_ack_ids`; the others return `()` and propagate `Err`.
**Init-once test (the deliverable):** build a `Pipeline` over a call-counting `StaticConfigSource` and a `ConfigStore` whose injected compile fn increments an `AtomicUsize`, invoke `handle` **three times**, assert the compile fn ran **exactly once**, `fetch()` was called **exactly once** (by `prime()`), and no adapter was constructed after init. The generic `Compile<T>` from Task 08 exists precisely so this count is observable. Without this, "we build it once" silently regresses the first time someone moves a line into the closure.
**Feature-isolation test:** `cargo tree -p cloudtrail-rs-lambda-s3 -e features` contains no `decode-sqs`/`decode-sns`/`decode-eventbridge`.
Plus one golden-payload handler test per binary with fake ports.

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
