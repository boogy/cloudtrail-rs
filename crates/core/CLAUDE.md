# crates/core — `cloudtrail-rs-core`

The hexagonal core: all filtering logic, **zero AWS dependencies**. `#![forbid(unsafe_code)]`.

## Rule: keep AWS out

`core` must never depend on any AWS crate. AWS is reached only through the object-safe **ports** in `ports.rs`:

- `EventDecoder` — trigger payload → S3 object references (one impl per `decode-*` feature).
- `ObjectStore` — get/put CloudTrail objects.
- `ConfigSource` — load rules/settings from a URI.
- `MetricsSink` — emit metrics (EMF or noop).

Adapters live in `crates/aws`. If you reach for an AWS type here, it belongs in `aws` behind a port instead.

## Layout

| Module        | Role                                                                                            |
| ------------- | ----------------------------------------------------------------------------------------------- |
| `filter/`     | `Engine`: compiles rules, indexes by `eventSource`/`eventName`, evaluates AND-within/OR-across. |
| `decode/`     | Per-trigger `EventDecoder`s, each gated behind a `decode-*` feature.                            |
| `process/`    | `buffer_run` / streaming record processing (buffer vs stream by size).                          |
| `pipeline.rs` | `Pipeline`: wires the four ports + `Settings`; the composition target.                          |
| `config/`     | `Settings`, `CT_*` env overlay, `ConfigUri`, `RuleSet`, `FileConfigSource`.                     |
| `model.rs`    | CloudTrail record/envelope types.                                                               |
| `metrics.rs`  | `Metrics`, `EmfMetricsSink`, `NoopMetricsSink`.                                                 |
| `testing/`    | Port doubles + `corpus` (realistic CloudTrail records), `testing` feature.                      |

## Invariants

- **Warm path is pure computation.** Per-record work does no trait dispatch — dispatch happens once per object/invocation. Keep it that way.
- **Rule indexing.** A record only checks rules that could apply (indexed by `eventSource` and `eventName` literals), plus the `always` bucket for un-indexable rules. `cli validate` warns about rules that fall into `always`, and `--max-unindexed <PERCENT>` can gate on the fraction that do.
- **Feature-gated decoders.** Adding a source = one decoder behind one `decode-*` feature; zero changes to the rest of core.
- **Buffer/stream parity.** The mode is chosen by object **size**, so the two must agree on survivors, output bytes, failure classification and every counter — otherwise an object changes meaning at `stream_threshold_bytes`. `gzip_chunks > 1` is the one carved-out exception: it reaches buffer mode only, so the framing bytes diverge while the decompressed payload and the counters still match (`gzip_chunks_changes_the_framing_but_not_the_payload`). Enforced by one oracle in `tests/common/mod.rs`, driven from two files: `tests/mode_parity.rs` (minimal envelopes, one structural property each) and `tests/corpus_parity.rs` (realistic records from `testing::corpus`). A change to either mode belongs in the first; a change to record _interpretation_ (dot-path resolution, indexing, verbatim survival) belongs in the second.
- **Survivors are copied, never re-serialized.** A kept record is emitted as its original bytes (`RawValue::get()`). `testing::corpus` deliberately holds records serde would re-render differently (escapes, `1.0`, `1.5e-7`, `9007199254740993`); do not "tidy" them — that is what makes the claim falsifiable.
- **Nothing is published or committed before the object's fate is decided.** Record counters are committed as one unit only after the object succeeds (a failed object is re-driven and re-evaluated whole); `BytesOut` is counted only after the write returns; `BytesIn` is counted once per object per invocation even on the paths that read it twice.
- **A stream-mode error must fail the reader, never just return.** The error goes into the output channel so `put_stream`'s reader errors and the upload aborts. Dropping the channel is a clean EOF, and a clean EOF commits a truncated object.

See [`docs/architecture.md`](../../docs/architecture.md) and [`docs/rules.md`](../../docs/rules.md) for the full model.
