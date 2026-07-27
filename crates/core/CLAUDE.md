# crates/core — `cloudtrail-rs-core`

The hexagonal core: all filtering logic, **zero AWS dependencies**.
`#![forbid(unsafe_code)]`.

## Rule: keep AWS out

`core` must never depend on any AWS crate. AWS is reached only through the
object-safe **ports** in `ports.rs`:

- `EventDecoder` — trigger payload → S3 object references (one impl per `decode-*` feature).
- `ObjectStore` — get/put CloudTrail objects.
- `ConfigSource` — load rules/settings from a URI.
- `MetricsSink` — emit metrics (EMF or noop).

Adapters live in `crates/aws`. If you reach for an AWS type here, it belongs in
`aws` behind a port instead.

## Layout

| Module        | Role                                                                                |
| ------------- | ----------------------------------------------------------------------------------- |
| `filter/`     | `Engine`: compiles rules, indexes by `eventSource`, evaluates AND-within/OR-across. |
| `decode/`     | Per-trigger `EventDecoder`s, each gated behind a `decode-*` feature.                |
| `process/`    | `buffer_run` / streaming record processing (buffer vs stream by size).              |
| `pipeline.rs` | `Pipeline`: wires the four ports + `Settings`; the composition target.              |
| `config/`     | `Settings`, `CT_*` env overlay, `ConfigUri`, `RuleSet`, `FileConfigSource`.         |
| `model.rs`    | CloudTrail record/envelope types.                                                   |
| `metrics.rs`  | `Metrics`, `EmfMetricsSink`, `NoopMetricsSink`.                                     |
| `testing.rs`  | In-crate test helpers (`testing` feature).                                          |

## Invariants

- **Warm path is pure computation.** Per-record work does no trait dispatch —
  dispatch happens once per object/invocation. Keep it that way.
- **Rule indexing.** A record only checks rules that could apply (indexed by
  `eventSource` literal), plus the `always` bucket for un-indexable rules.
  `cli validate` warns about rules that fall into `always`.
- **Feature-gated decoders.** Adding a source = one decoder behind one
  `decode-*` feature; zero changes to the rest of core.

See [`docs/architecture.md`](../../docs/architecture.md) and
[`docs/rules.md`](../../docs/rules.md) for the full model.
