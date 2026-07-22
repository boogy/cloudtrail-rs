# STATUS — cloudtrail-rs

Orchestrator state. See PLAN.md > "Durable state" for the resume protocol.
Git is the authority: every task commits with subject `task-NN: `, so
`git log --grep '^task-'` reconstructs progress if this file is stale.

last-dispatched: task-03, task-04, task-07, task-09, task-10, task-15

| task | name | deps | state | commit | note |
|------|------|------|-------|--------|------|
| 00 | Split this plan | none | done | ffdac64 | |
| 01 | Toolchain and workspace | 00 | done | 37d5349 | rustc 1.97.1; lambda pkgs renamed to cloudtrail-rs-lambda-* by orchestrator |
| 02 | Errors, model, ports | 01 | done | f708c67 | `CoreError` deferred to task-12 by design; recorded in SHARED.md. `MetricSnapshot` carries only the fields SHARED names; task-09 extends it |
| 03 | Rules: parse and validate | 02 | dispatched | — | |
| 04 | Field path resolution | 02 | dispatched | — | |
| 05 | Rule engine, linear | 03, 04 | pending | — | |
| 06 | Rule index | 05 | pending | — | |
| 07 | Settings | 02 | dispatched | — | |
| 08 | URI, FileConfigSource, ConfigStore, `prime()` | 07, 09 | pending | — | |
| 09 | Metrics and EMF | 02 | dispatched | — | |
| 10 | S3 and SNS decoders | 02 | dispatched | — | |
| 11 | SQS and EventBridge decoders | 02, 07 | pending | — | |
| 12 | Buffer processor | 06, 07, 09 (07 for the `Processing` settings struct) | pending | — | |
| 13 | Stream processor | 12 | pending | — | |
| 14 | Pipeline | 08, 11, 13 | pending | — | |
| 15 | AWS adapters | 02 | dispatched | — | |
| 16 | Four Lambda binaries | 14, 15 | pending | — | |
| 17 | CLI | 14, 15 | pending | — | |
| 18 | MiniStack integration tests | 16 | pending | — | |
| 19 | Docs and examples | 18 | pending | — | |

`state` ∈ `pending` | `dispatched` | `done` | `blocked`.

Parallelisable batches: **{02}** → **{03, 04, 07, 09, 10, 15}** → **{05, 08, 11}**
→ **{06}** → **12** → **13** → **14** → **{16, 17}** → **18** → **19**.
