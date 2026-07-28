# Metrics

Every invocation emits exactly one metric snapshot, whether it succeeded or
failed. This page is the full reference: what each metric means, the invariants
that hold between them, and what to alarm on.

## How they are emitted

`Pipeline::handle` calls `Metrics::snapshot_and_reset()` and hands the result to
the `MetricsSink` **before returning — success or failure**. Two sinks exist,
selected by `observability.metrics` (`CT_METRICS_MODE`):

| Mode   | Sink              | Behaviour                                    |
| ------ | ----------------- | -------------------------------------------- |
| `emf`  | `EmfMetricsSink`  | CloudWatch EMF JSON on stdout (the default). |
| `none` | `NoopMetricsSink` | Nothing emitted. Counters still accumulate.  |

The EMF sink writes **one aggregate line** carrying every metric below except
`RuleDrops`, plus **one extra line per rule that dropped records this
invocation**. `RuleDrops` needs its own lines because a flat EMF document holds
only one value per dimension name, so the `Rule` dimension cannot vary within a
single line.

Namespace: `observability.namespace` (`CT_METRICS_NAMESPACE`), default
`cloudtrail-rs`.

**Values are deltas, not running totals.** `snapshot_and_reset` swaps every
counter back to zero, so each snapshot covers exactly one invocation. Sum them
over a window in CloudWatch; do not treat them as gauges.

## The reconciliation invariants

```
RecordsIn      == RecordsKept + RecordsDropped
sum(RuleDrops) == RecordsDropped
```

Both hold per invocation, in **both** buffer and stream mode, and both are
asserted on every case in `crates/core/tests/mode_parity.rs` (the first also by
`MetricSnapshot::records_balance()`). The first is the single strongest
data-loss check available from outside the process: if it breaks, records
entered the pipeline and were neither written nor accounted for as filtered.
The second says the same thing one level down — every drop is attributable to
the rule that caused it.

`RecordsIn` is counted only once an object's `Records` array has actually been
recognised — an object that fails to parse contributes to `ParseErrors` /
`UnrecognizedObjects` / `ObjectsFailed`, never to a lopsided balance.

## Metric reference

### Object-level

| Metric                 | Unit  | Meaning                                                                                                                                                                                                                                                                                |
| ---------------------- | ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ObjectsProcessed`     | Count | Objects fully handled (written, nothing-kept, or unrecognized-policy applied).                                                                                                                                                                                                         |
| `ObjectsSkipped`       | Count | Source object was missing (`404`) and `behavior.on_missing_object` is `skip`. Only counted on a path that actually opens the object — `on_unrecognized_object: skip`/`error` in stream mode return without a second read, so a source deleted mid-invocation is not re-detected there. |
| `ObjectsFailed`        | Count | An object errored. Counted **before** the `partial_batch_failures` branch, so it moves on both paths.                                                                                                                                                                                  |
| `ObjectsExcludedByKey` | Count | Object rejected by `source.include_key_regex` / `exclude_key_regex`, before any `GetObject`.                                                                                                                                                                                           |
| `UnrecognizedObjects`  | Count | Object was valid gzip+JSON but had no `Records` array; `behavior.on_unrecognized_object` decides what happened to it.                                                                                                                                                                  |

### Record-level

| Metric           | Unit  | Meaning                                                                                            |
| ---------------- | ----- | -------------------------------------------------------------------------------------------------- |
| `RecordsIn`      | Count | Records read out of recognised CloudTrail envelopes.                                               |
| `RecordsKept`    | Count | Records written to the destination (or, in `dry_run`, that would have been).                       |
| `RecordsDropped` | Count | Records excluded by a rule.                                                                        |
| `RuleDrops`      | Count | Per-rule drop count. **Dimension: `Rule`** (the rule's `name`). Only emitted for rules that fired. |

All five are published **per object, as one unit, only once that object has
succeeded** — never as the records stream past. An object that fails partway is
re-driven and re-evaluated whole, so counting its records as they were seen
attributed drops to a rule and parse errors to records that were never dropped,
never kept, and never written, and re-counted them on every retry. Buffer mode
gets this for free (it decides the object's fate before it touches a counter);
stream mode defers explicitly. The consequence is a second identity worth
alarming on:

```
sum(RuleDrops) == RecordsDropped
```

A record is dropped only ever by exactly one rule, so the per-rule breakdown
sums to the total — including for objects where every record was dropped and
nothing was written. Asserted for both modes on every case in
`crates/core/tests/mode_parity.rs`. A `RuleDrops` sum that exceeds
`RecordsDropped` means drops are being reported for work that was thrown away.

### Bytes

| Metric     | Unit  | Meaning                                                                                                   |
| ---------- | ----- | --------------------------------------------------------------------------------------------------------- |
| `BytesIn`  | Bytes | Compressed source bytes ingested.                                                                         |
| `BytesOut` | Bytes | Compressed bytes that **reached** the destination — always counted after the `put` returns, never before. |

**`BytesIn` is counted once per object per invocation**, even on the two paths
that read an object twice:

- An `ObjectTooLarge` in `mode: auto` is retried through stream mode. The
  buffer attempt does not count; the stream attempt does.
- An `on_unrecognized_object: copy` in stream mode re-reads the object (once to
  discover it has no `Records`, once to copy it). The filtering read counts; the
  copy does not.

Without that rule the same object reports double the `BytesIn` on one side of
`stream_threshold_bytes` and single on the other, for reasons unrelated to what
was written.

The two byte-for-byte copy paths — the `on_config_error: open` passthrough and
an `on_unrecognized_object: copy` in stream mode — stream source to destination
rather than buffering. `BytesOut` is billed only once the upload has committed,
so a copy that fails midway reports its `BytesIn` and a `BytesOut` of zero. That
asymmetry is the signal, not a bug: bytes were read and none were delivered.

### Errors

| Metric                | Unit  | Meaning                                                                                                                                                 |
| --------------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DecodeErrors`        | Count | A trigger payload failed to decode — either the whole payload, or one SQS message body.                                                                 |
| `ParseErrors`         | Count | An individual record failed to parse. **The record is kept, never dropped**, in both modes. Fail-safe by design.                                        |
| `ConfigLoadErrors`    | Count | Fetching or compiling the rules document failed. `behavior.on_config_error` decides whether the batch proceeds unfiltered (`open`) or fails (`closed`). |
| `ItemsWithoutObjects` | Count | A decoded item referenced zero objects.                                                                                                                 |

### Lifecycle

| Metric      | Unit  | Meaning                                                                           |
| ----------- | ----- | --------------------------------------------------------------------------------- |
| `ColdStart` | Count | `1` on the first invocation of a container, `0` after. A non-zero rate is normal. |

## What to alarm on

| Priority     | Condition                                                                                      | What it means                                                                                                                                                                                                                        |
| ------------ | ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Critical** | `RecordsIn != RecordsKept + RecordsDropped` over any window                                    | The reconciliation invariant broke. Records are unaccounted for.                                                                                                                                                                     |
| **Critical** | `sum(RuleDrops) != RecordsDropped` over any window                                             | The per-rule breakdown no longer accounts for the drops. Most likely drops are being published for objects that then failed and were re-driven, inflating a rule's apparent effect.                                                  |
| **Critical** | Lambda `Errors > 0` with `ObjectsFailed == 0`                                                  | A failure before any object was attempted: a decode error, `on_config_error: closed` with no cached ruleset, or a panic. A self-trigger (destination bucket == source bucket) shows up as `Errors > 0` **with** `ObjectsFailed > 0`. |
| **Critical** | `ObjectsFailed > 0`                                                                            | Objects are erroring. Under the default `partial_batch_failures: true` the handler returns **`Ok`**, so AWS's own `Errors` metric stays at **zero** — this counter is the only signal that messages are heading for the DLQ.         |
| **Critical** | `DecodeErrors > 0`                                                                             | Trigger payloads are not the shape this binary was built for. On SQS the message goes to the DLQ; on S3/SNS/EventBridge the invocation fails.                                                                                        |
| **High**     | `ObjectsProcessed == 0` while `ObjectsExcludedByKey > 0`                                       | The key filter is rejecting everything. Almost always a bad `include_key_regex`/`exclude_key_regex`.                                                                                                                                 |
| **High**     | `ObjectsProcessed == 0` and `ObjectsExcludedByKey == 0` for a period where traffic is expected | The function is not being triggered at all.                                                                                                                                                                                          |
| **High**     | `ConfigLoadErrors > 0`                                                                         | Rules are stale or, under `on_config_error: open`, records are passing through unfiltered.                                                                                                                                           |
| **Medium**   | `RecordsDropped / RecordsIn` deviating sharply from its baseline                               | A rule change did more or less than intended. Cross-check per-rule `RuleDrops`.                                                                                                                                                      |
| **Medium**   | `UnrecognizedObjects > 0`                                                                      | Objects that are not CloudTrail are arriving. Confirm `on_unrecognized_object` is what you want for them.                                                                                                                            |
| **Medium**   | `ParseErrors > 0`                                                                              | Malformed individual records. They are kept, so this is a data-quality signal, not a loss signal.                                                                                                                                    |
| **Low**      | `ObjectsSkipped > 0`                                                                           | Source objects are missing and `on_missing_object: skip` is discarding them.                                                                                                                                                         |
| **Low**      | `ItemsWithoutObjects > 0`                                                                      | Events carrying no object references.                                                                                                                                                                                                |

Also alarm on the AWS-provided Lambda metrics: `Errors`, `Throttles`,
`Duration` approaching the configured timeout, and — for SQS —
`ApproximateAgeOfOldestMessage` and the DLQ's `ApproximateNumberOfMessagesVisible`.

## Silent-failure states these counters close

Each of these was, at some point, a state in which the pipeline discarded data
while every metric read as a healthy idle function:

- **Key filter rejects everything.** Without `ObjectsExcludedByKey`, the
  snapshot is all-zero and byte-for-byte identical to one from an invocation
  that received no traffic.
- **Objects failing under `partial_batch_failures`.** The handler returns `Ok`,
  so AWS reports no error; without `ObjectsFailed`, only a log line existed.
- **A payload that is valid JSON but not an S3 notification.** It now fails to
  decode (`DecodeErrors`) instead of decoding to zero objects and vanishing.
- **`dry_run` hiding unrecognized objects.** The mode meant for pre-flight
  checks discarded its own classification; `UnrecognizedObjects` now moves in
  dry run too.
- **A self-trigger.** Refusing to reprocess our own output failed the
  invocation without touching a counter, so the only trace was the AWS `Errors`
  metric — indistinguishable from a timeout or an OOM. It counts as
  `ObjectsFailed`.

And one that was the inverse — a counter reporting work that did not happen:

- **Drops attributed to a rule for records that were never dropped.** Stream
  mode published `RuleDrops`/`ParseErrors` as records streamed past, so an
  object that failed midway inflated a rule's apparent effect and did so again
  on every retry. Both are now committed only once the object has succeeded.

## Known limitations

- **No `FunctionName` dimension.** The aggregate line is published with an empty
  dimension set, so several functions sharing one `CT_METRICS_NAMESPACE`
  aggregate together. Give each deployed function its own
  `CT_METRICS_NAMESPACE` if you need to tell them apart.
- **A panic emits nothing.** The binaries build with `panic = "abort"`; a panic
  skips the snapshot entirely. Alarm on the AWS `Errors` metric to cover that
  gap.
- **`RuleDrops` is sparse.** Only rules that dropped at least one record this
  invocation produce a line, so a rule that stops firing goes to _no data_
  rather than to zero. Alarm with "treat missing data as breaching" if you
  depend on a rule firing.

---

See also: [Deployment](deployment.md) · [Configuration](configuration.md) · [Rules](rules.md)
