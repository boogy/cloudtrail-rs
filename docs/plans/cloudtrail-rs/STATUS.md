# STATUS — cloudtrail-rs

Orchestrator state. See PLAN.md > "Durable state" for the resume protocol.
Git is the authority: every task commits with subject `task-NN: `, so
`git log --grep '^task-'` reconstructs progress if this file is stale.

last-dispatched: none (batch aborted on session usage limit 2026-07-22 ~22:30 UTC)

| task | name | deps | state | commit | note |
|------|------|------|-------|--------|------|
| 00 | Split this plan | none | done | ffdac64 | |
| 01 | Toolchain and workspace | 00 | done | 37d5349 | rustc 1.97.1; lambda pkgs renamed to cloudtrail-rs-lambda-* by orchestrator |
| 02 | Errors, model, ports | 01 | done | f708c67 | `CoreError` deferred to task-12 by design; recorded in SHARED.md. `MetricSnapshot` carries only the fields SHARED names; task-09 extends it |
| 03 | Rules: parse and validate | 02 | pending | — | aborted by session usage limit before producing code; re-dispatch |
| 04 | Field path resolution | 02 | done | a5ad6e7 | |
| 05 | Rule engine, linear | 03, 04 | pending | — | |
| 06 | Rule index | 05 | pending | — | |
| 07 | Settings | 02 | pending | — | aborted by session usage limit before producing code; re-dispatch (its worktree held only uncommitted Cargo.toml dep lines, no source; discarded in cleanup) |
| 08 | URI, FileConfigSource, ConfigStore, `prime()` | 07, 09 | pending | — | |
| 09 | Metrics and EMF | 02 | pending | — | aborted by session usage limit before producing code; re-dispatch |
| 10 | S3 and SNS decoders | 02 | pending | — | aborted by session usage limit before producing code; re-dispatch |
| 11 | SQS and EventBridge decoders | 02, 07 | pending | — | |
| 12 | Buffer processor | 06, 07, 09 (07 for the `Processing` settings struct) | pending | — | |
| 13 | Stream processor | 12 | pending | — | |
| 14 | Pipeline | 08, 11, 13 | pending | — | |
| 15 | AWS adapters | 02 | pending | — | aborted by session usage limit before producing code; re-dispatch |
| 16 | Four Lambda binaries | 14, 15 | pending | — | |
| 17 | CLI | 14, 15 | pending | — | |
| 18 | MiniStack integration tests | 16 | pending | — | |
| 19 | Docs and examples | 18 | pending | — | |

`state` ∈ `pending` | `dispatched` | `done` | `blocked`.

## Orchestrator notes (2026-07-22)

**Worktree dispatch hazard — read before dispatching a parallel batch.** Agent
worktrees are not guaranteed to branch from current `main`; in the {03,04,07,09,10,15}
batch, four of six were created at `8447c3e` (the initial commit) and were missing
tasks 00-02 entirely. Every worktree brief must therefore start with: run
`git log --oneline -1`, and if it is not at the expected base, `git merge --ff-only <sha>`
to sync. That fast-forward is authorized and is NOT one of the forbidden undo commands.

**Stale worktrees: cleaned up 2026-07-23.** All six leftovers from the aborted batch
were removed along with their `worktree-agent-*` branches; each was verified to be at or
behind `main` with zero commits ahead first. `main` is now the only tree. If you ever
remove a worktree again, read the diff before forcing — do not discard uncommitted work
sight-unseen.

**Dispatch mode: sequential, in the main tree.** The parallel-worktree experiment cost
more than it bought (base-commit hazard above, plus six concurrent cold-start compiles
that exhausted the session budget). Dispatch one task at a time into `/Users/bogdan/github.com/cloudtrail-rs`
on `main`, verify, update this file, then dispatch the next. Tell each agent to stage
only its own paths (`git add <explicit paths>`, never `git add -A`).


Parallelisable batches: **{02}** → **{03, 04, 07, 09, 10, 15}** → **{05, 08, 11}**
→ **{06}** → **12** → **13** → **14** → **{16, 17}** → **18** → **19**.
