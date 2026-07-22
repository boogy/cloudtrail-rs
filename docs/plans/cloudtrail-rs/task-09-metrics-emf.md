# Task 09 — Metrics and EMF

**Read `docs/plans/cloudtrail-rs/SHARED.md` first.**
**Depends on:** 02
**Do not read other task files.**

---

## Brief

**Produces:** `Metrics` (atomic counters, process-lived, `Default`, `snapshot_and_reset()`), `MetricSnapshot`, `EmfMetricsSink::new(namespace: String)` (in **`core`** — needs no AWS SDK), `NoopMetricsSink`, `RecordingSink` (in `testing`).
`EmfMetricsSink::new` takes plain values, **not `&Settings`** — this task runs in parallel with Task 07 and must not depend on it. The Lambda binary does the mapping.
`Metrics` is shared by `Arc` across invocations (`ConfigStore` holds one), so each EMF line must be a **delta**: `Pipeline::handle` calls `snapshot_and_reset()` once at the end and emits the result. A test asserts two successive invocations emit independent counts, not a running total — otherwise every CloudWatch number is silently cumulative and unusable.
One EMF line per invocation on stdout. **Tests:** exact `_aws.CloudWatchMetrics` structure; metric names `ObjectsProcessed`, `ObjectsSkipped`, `UnrecognizedObjects`, `RecordsIn`, `RecordsKept`, `RecordsDropped`, `BytesIn`, `BytesOut`, `ConfigLoadErrors`, `ParseErrors`, `ColdStart`, and per-rule `RuleDrops` with a `Rule` dimension; `ColdStart` is `1` on a process's first emit and `0` thereafter.

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
