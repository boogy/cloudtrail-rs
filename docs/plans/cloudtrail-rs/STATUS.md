# STATUS — cloudtrail-rs

Orchestrator state. See PLAN.md > "Durable state" for the resume protocol.
Git is the authority: every task commits with subject `task-NN: `, so
`git log --grep '^task-'` reconstructs progress if this file is stale.

last-dispatched: task-18

| task | name | deps | state | commit | note |
|------|------|------|-------|--------|------|
| 00 | Split this plan | none | done | ffdac64 | |
| 01 | Toolchain and workspace | 00 | done | 37d5349 | rustc 1.97.1; lambda pkgs renamed to cloudtrail-rs-lambda-* by orchestrator |
| 02 | Errors, model, ports | 01 | done | f708c67 | `CoreError` deferred to task-12 by design; recorded in SHARED.md. `MetricSnapshot` carries only the fields SHARED names; task-09 extends it |
| 03 | Rules: parse and validate | 02 | done | 96006f9 | canonical ruleset is **25** rules not 24 (plan error, corrected in 5c02999). `REGEX_SIZE_LIMIT` is `pub(crate)` in config/rules.rs; task-05 must reuse it |
| 04 | Field path resolution | 02 | done | a5ad6e7 | |
| 05 | Rule engine, linear | 03, 04 | done | ab784b7 | reuses REGEX_SIZE_LIMIT; within-rule matches sorted most-selective-first (AND order-independent). evaluate_linear is the permanent oracle for task-06 |
| 06 | Rule index | 05 | done | 4563d68 | line-by-line reviewed: extraction conservative (bails on `(?`, requires `^…$`, one flat alt group max, `\w`/`\d` → always); 3/25 in always (AWS Config Recorder, IAM Session Renewals, Automated Tool Describe Ops). Part D check PASSED: dropping always-bucket broke corpus equivalence + always tests |
| 07 | Settings | 02 | done | 0ebf734 | env-override via injected closure (no env mutation). `SETTINGS_URI` resolves `file://` only in core; s3/ssm deferred to task-16 (see SHARED note). `rules.uri` default is the example literal |
| 08 | URI, FileConfigSource, ConfigStore, `prime()` | 07, 09 | done | 9b32336 | store.rs verified generic (no RuleSet/Engine refs). NOTE: persistent version() failure retries every get() (no backoff) — acceptable v1, fail-open serves cached rules. StaticConfigSource now in testing.rs |
| 09 | Metrics and EMF | 02 | done | fecaeef | MetricSnapshot extended with 9 counters; increment API + EMF N+1-line-for-RuleDrops convention pinned in SHARED. testing.rs holds only RecordingSink (InMemoryStore/StaticConfigSource still owed by task-08/14) |
| 10 | S3 and SNS decoders | 02 | done | 5397de1 | +percent-encoding dep. Part D `+`→space mutation spot-check PASSED (removed handling → test failed). shared S3 parse helper gated for both features so sns-only build carries no S3EventDecoder |
| 11 | SQS and EventBridge decoders | 02, 07 | done | 196235d | reuses task-10 parse_s3_notification; SQS SNS-envelope unwrap self-contained (bare Notification, not Records[].Sns). EB field is `detail.event-version`. Part D verbatim-key mutation check PASSED |
| 12 | Buffer processor | 06, 07, 09 (07 for the `Processing` settings struct) | done | 67185e3 | `CoreError` added here (Store/Config/Gzip/Json/ObjectTooLarge{limit}), as SHARED deferred. MultiGzDecoder verified; verbatim raw-slice output (no re-serialize); decompress cap via take(max+1). Part D check PASSED: GzDecoder swap broke concatenated-member test. +flate2 (rust_backend), serde_json raw_value |
| 13 | Stream processor | 12 | done | 18723ad | line-by-line reviewed. Box<RawValue> from reader-backed deserializer worked (no Value fallback). Byte-for-byte equivalence with buffer_run verified; abort-via-fail-the-reader for Unrecognized/NothingKept; never flushes (drains sink via mem::take). **Interface fix:** subagent hardcoded PutMeta content_type `application/json`; orchestrator changed to `application/x-gzip` to match task-15 adapter + pinned canonical output PutMeta in SHARED. Part D check PASSED: completing (not aborting) the upload broke the unrecognized-abort test |
| 14 | Pipeline | 08, 11, 13 | done | d24f987 | line-by-line reviewed. handle→handle_inner; snapshot_and_reset emitted once per handle even on failure (delta). Key filter before get; self-trigger guard returns Err (not partial-batch). CANONICAL_META (application/x-gzip) at all 4 put sites. Fail-open raw_copy bypasses decompress/parse; stream Unrecognized re-fetches (2nd get) + raw-copies. Additive CoreError variants (Decode/SelfTrigger/UnrecognizedObject) recorded in SHARED. Part D PASSED: neutralizing self-trigger broke loop test; swap→load in snapshot_and_reset broke delta test |
| 15 | AWS adapters | 02 | done | 5c4c679 | ring-only verified (no aws-lc in tree); core still aws-free. Adapters: prod `new(&SdkConfig)`, test `from_client(Client)`; S3ObjectStore `with_multipart_part_bytes` override |
| 16 | Four Lambda binaries | 14, 15 | done | 463e8cf | line-by-line reviewed (orchestrator wrote it after the dispatched subagent hit a session limit with only lambda-s3 partial). All four bins strict init→run skeleton; s3/sns/eb return () + propagate Err, sqs returns batchItemFailures from BatchOutcome. Init-once deliverable test: 3× handle ⇒ compile once + fetch once. Golden-payload handler test per bin via real decoder. Feature isolation verified (lambda-s3 tree: 0 decode-sqs/sns/eb). Part D PASSED: forcing per-invocation recompile in ConfigStore broke init-once test (4 vs 1), reverted |
| 17 | CLI | 14, 15 | done | 3bdbeb1 (base) + follow-on | base CLI (validate/test/filter single-file) via subagent. FOLLOW-ON done (orchestrator): `filter <source> <dest>` now auto-detects local-file / local-dir / `s3://` prefix on each side; single local file = one object, dir or s3:// prefix = batch with relative-path mirroring; gzip-faithful `.json.gz` output (canonical GZIP_META); zero-empty-writes preserved; +`S3ObjectStore::list_keys` (paginated, inherent method not on port) with mock test; +6th cli test `filter_directory_mirrors_relative_paths_and_skips_all_dropped`. Verified: full workspace tests green, clippy -D warnings clean, fmt clean |
| 18 | MiniStack integration tests | 16 | done | c5677e6 | Sonnet subagent, orchestrator-verified. docker-compose.test.yml (ministack :4566) + crates/aws/tests/ministack.rs (2 #[ignore] tests: small→buffer, large 20k-rec→stream/multipart). Drives real Pipeline::handle via real S3ObjectStore/SsmConfigSource; path-style S3 via public from_client escape hatch (no src/ touched); exact decompressed-survivor byte assertions. +dev-deps: core[decode-s3], flate2. Verified: compiles + 2 ignored/0 run, clippy -D + fmt clean. NOT executed against a live container here (needs `docker compose -f docker-compose.test.yml up -d` then `cargo test --workspace -- --ignored`) |
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
