# STATUS — cloudtrail-rs

Orchestrator state. See PLAN.md > "Durable state" for the resume protocol.
Git is the authority: every task commits with subject `task-NN: `, so
`git log --grep '^task-'` reconstructs progress if this file is stale.

last-dispatched: none

| task | name | deps | state | commit | note |
|------|------|------|-------|--------|------|
| 00 | Split this plan | none | done | (this commit) | |
| 01 | Toolchain and workspace | 00 | pending | — | |
| 02 | Errors, model, ports | 01 | pending | — | |
| 03 | Rules: parse and validate | 02 | pending | — | |
| 04 | Field path resolution | 02 | pending | — | |
| 05 | Rule engine, linear | 03, 04 | pending | — | |
| 06 | Rule index | 05 | pending | — | |
| 07 | Settings | 02 | pending | — | |
| 08 | URI, FileConfigSource, ConfigStore, `prime()` | 07, 09 | pending | — | |
| 09 | Metrics and EMF | 02 | pending | — | |
| 10 | S3 and SNS decoders | 02 | pending | — | |
| 11 | SQS and EventBridge decoders | 02, 07 | pending | — | |
| 12 | Buffer processor | 06, 07, 09 (07 for the `Processing` settings struct) | pending | — | |
| 13 | Stream processor | 12 | pending | — | |
| 14 | Pipeline | 08, 11, 13 | pending | — | |
| 15 | AWS adapters | 02 | pending | — | |
| 16 | Four Lambda binaries | 14, 15 | pending | — | |
| 17 | CLI | 14, 15 | pending | — | |
| 18 | MiniStack integration tests | 16 | pending | — | |
| 19 | Docs and examples | 18 | pending | — | |

`state` ∈ `pending` | `dispatched` | `done` | `blocked`.

Parallelisable batches: **{02}** → **{03, 04, 07, 09, 10, 15}** → **{05, 08, 11}**
→ **{06}** → **12** → **13** → **14** → **{16, 17}** → **18** → **19**.
