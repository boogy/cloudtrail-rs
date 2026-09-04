# Configuration

Every runtime knob has a default, an optional settings-file field, and (almost always) a `CT_*` environment override. **Environment always wins over the file.**

- [Where settings come from](#where-settings-come-from)
- [Precedence](#precedence)
- [The settings file](#the-settings-file)
- [Environment variable reference](#environment-variable-reference)
- [Validation constraints](#validation-constraints)
- [Pre-deploy validation: `validate-settings`](#pre-deploy-validation-validate-settings)
- [The YAML quoting trap](#the-yaml-quoting-trap)

## Where settings come from

`SETTINGS_URI` is read at process start to locate an optional settings document:

- `file://…` — resolved by `core` directly (no AWS link needed).
- `s3://…` / `ssm://…` — resolved by the composition root, which links `cloudtrail-rs-aws`.

An **env-only deployment — no `SETTINGS_URI` at all — is valid**: every field below has a default and/or a `CT_*` override. Only `CT_DEST_BUCKET` (`destination.bucket`) is mandatory, here or in the file.

## Precedence

```mermaid
flowchart LR
    D["Built-in default"] --> F["settings file<br/>(SETTINGS_URI)"]
    F --> E["CT_* env var"]
    E --> V(["Effective value"])
    style E fill:#2d6,stroke:#161,color:#000
    style V fill:#39f,stroke:#036,color:#fff
```

For any given field: start from the built-in default, override with the settings file if present, then override with the `CT_*` env var if present. The right-most source that sets a value wins, so an env var overrides the file, and the file overrides the default.

## The settings file

`SETTINGS_URI` points at a YAML document shaped like [`examples/settings.example.yaml`](../examples/settings.example.yaml):

```yaml
version: 1 # integer schema marker — must equal 1 (see note below)
source:
  include_key_regex: "\\.json\\.gz$"
  exclude_key_regex: "(/CloudTrail-Digest/|/CloudTrail-Insight/|/$)"
destination:
  bucket: ct-siem-sync # required (or CT_DEST_BUCKET)
  key_prefix: "" # "" => key identical to source
processing:
  mode: auto # auto | buffer | stream
  stream_threshold_bytes: 8388608
  max_object_bytes: 134217728 # BUFFER MODE ONLY — memory guard
  multipart_part_bytes: 8388608 # stream mode
  gzip_level: 6
  object_concurrency: 1 # objects in flight per batch — multiplies peak memory
  gzip_chunks: 1 # BUFFER MODE ONLY — parallel gzip members; 1 = single member
behavior:
  dry_run: false # evaluate + count, write nothing to the destination
  on_config_error: open # open | closed   (DEFAULT: open)
  on_missing_object: error # error | skip
  on_unrecognized_object: copy # copy | skip | error
  on_parse_error: copy # copy | error — an object that will not parse at all
  on_object_too_large: stream # stream | error — an object over max_object_bytes
  partial_batch_failures: true # SQS only
sqs:
  body_format: auto # auto | s3 | sns — set explicitly to skip the sniff
rules:
  uri: s3://sec-config/cloudtrail/rules.yaml
  ttl_seconds: 300
observability:
  metrics: emf # emf | none
  namespace: cloudtrail-rs
  log_level: info
```

> **`version: 1` here is an integer schema marker, not semver.** It is the only settings field with no env override. Do not confuse it with the **rules** file's `version: 1.0.0`, which _is_ semver — see [rules.md](rules.md). The two `version:` fields are unrelated and follow different rules.

## Environment variable reference

| Variable                      | Settings path                       | Meaning                                                                                                                                                                                                                                            | Default                                 |
| ----------------------------- | ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| `SETTINGS_URI`                | — (bootstrap only)                  | `file://`, `s3://`, or `ssm://` location of the optional settings YAML document.                                                                                                                                                                   | none (env-only deployment)              |
| `CT_DEST_BUCKET`              | `destination.bucket`                | Destination bucket for filtered output. **Required** (here or in the file).                                                                                                                                                                        | —                                       |
| `CT_KEY_PREFIX`               | `destination.key_prefix`            | Prefix prepended to the source key for the destination key. `""` = identical key.                                                                                                                                                                  | `""`                                    |
| `CT_SOURCE_INCLUDE_KEY_REGEX` | `source.include_key_regex`          | Source key must match this to be processed.                                                                                                                                                                                                        | `\.json\.gz$`                           |
| `CT_SOURCE_EXCLUDE_KEY_REGEX` | `source.exclude_key_regex`          | Source key matching this is skipped (digests, Insights, folder markers).                                                                                                                                                                           | `(/CloudTrail-Digest/                   | /CloudTrail-Insight/ | /$)` |
| `CT_PROCESSING_MODE`          | `processing.mode`                   | `auto` \| `buffer` \| `stream`.                                                                                                                                                                                                                    | `auto`                                  |
| `CT_STREAM_THRESHOLD_BYTES`   | `processing.stream_threshold_bytes` | `auto` mode switches to streaming above this object size.                                                                                                                                                                                          | `8388608`                               |
| `CT_MAX_OBJECT_BYTES`         | `processing.max_object_bytes`       | Buffer-mode-only memory guard: caps the fetch and the decompressed body.                                                                                                                                                                           | `134217728`                             |
| `CT_MULTIPART_PART_BYTES`     | `processing.multipart_part_bytes`   | Stream-mode S3 multipart part size.                                                                                                                                                                                                                | `8388608`                               |
| `CT_GZIP_LEVEL`               | `processing.gzip_level`             | Output gzip compression level.                                                                                                                                                                                                                     | `6`                                     |
| `CT_OBJECT_CONCURRENCY`       | `processing.object_concurrency`     | How many of a batch's objects are fetched, filtered and written concurrently. `1` is fully sequential. Does nothing unless one invocation carries several objects — see [Choosing an `object_concurrency`](#choosing-an-object_concurrency).       | `1`                                     |
| `CT_GZIP_CHUNKS`              | `processing.gzip_chunks`            | Buffer mode only: how many independently-deflated gzip members the output is split into, compressed on that many threads. `1` emits a single member. See [Choosing a `gzip_chunks`](#choosing-a-gzip_chunks) — check your downstream reader first. | `1`                                     |
| `CT_DRY_RUN`                  | `behavior.dry_run`                  | Evaluate and count what would be dropped, but write nothing to the destination.                                                                                                                                                                    | `false`                                 |
| `CT_ON_CONFIG_ERROR`          | `behavior.on_config_error`          | `open` \| `closed` when the rules doc has never loaded successfully.                                                                                                                                                                               | `open`                                  |
| `CT_ON_MISSING_OBJECT`        | `behavior.on_missing_object`        | `error` \| `skip` when the source object is gone.                                                                                                                                                                                                  | `error`                                 |
| `CT_ON_UNRECOGNIZED_OBJECT`   | `behavior.on_unrecognized_object`   | `copy` \| `skip` \| `error` for JSON with no `Records` array.                                                                                                                                                                                      | `copy`                                  |
| `CT_ON_PARSE_ERROR`           | `behavior.on_parse_error`           | `copy` \| `error` for an object that will not parse at all. See [Fail-open: what happens to an object that will not parse](#fail-open-what-happens-to-an-object-that-will-not-parse).                                                              | `copy`                                  |
| `CT_ON_OBJECT_TOO_LARGE`      | `behavior.on_object_too_large`      | `stream` \| `error` for an object whose body exceeds `processing.max_object_bytes`.                                                                                                                                                                | `stream`                                |
| `CT_PARTIAL_BATCH_FAILURES`   | `behavior.partial_batch_failures`   | SQS only — `true` returns `batchItemFailures` for just the failed items; `false` fails the whole batch. See the [SQS warning](deployment.md#sqs-reportbatchitemfailures-is-not-optional).                                                          | `true`                                  |
| `CT_SQS_BODY_FORMAT`          | `sqs.body_format`                   | `auto` \| `s3` \| `sns` — set explicitly to skip the SQS body-shape sniff. A body that does not match the format you declared fails the message (it is redelivered, then DLQ'd) rather than acking with zero objects.                              | `auto`                                  |
| `CT_RULES_URI`                | `rules.uri`                         | `ssm://` \| `s3://` \| `file://` location of the exclusion-rules document.                                                                                                                                                                         | `s3://sec-config/cloudtrail/rules.yaml` |
| `CT_RULES_TTL_SECONDS`        | `rules.ttl_seconds`                 | Cache TTL before revalidating the rules document.                                                                                                                                                                                                  | `300`                                   |
| `CT_METRICS`                  | `observability.metrics`             | `emf` \| `none`.                                                                                                                                                                                                                                   | `emf`                                   |
| `CT_METRICS_NAMESPACE`        | `observability.namespace`           | CloudWatch EMF namespace.                                                                                                                                                                                                                          | `cloudtrail-rs`                         |
| `CT_LOG_LEVEL`                | `observability.log_level`           | Log verbosity.                                                                                                                                                                                                                                     | `info`                                  |

### Behavior knobs worth understanding

- **`on_config_error`** (`open` \| `closed`) — only applies when the rules document has _never_ loaded successfully. `open` forwards everything unfiltered (fail-open, no data loss, no filtering); `closed` errors out. A successful earlier load followed by a transient failure keeps using the last good ruleset until TTL forces a revalidate.
- **`on_missing_object`** (`error` \| `skip`) — the source object named by the event no longer exists. `error` surfaces it (and, on SQS, re-drives); `skip` treats it as a no-op.
- **`on_unrecognized_object`** (`copy` \| `skip` \| `error`) — JSON with no `Records` array. `copy` forwards it verbatim to the destination, `skip` drops it, `error` fails.
- **`on_parse_error`** (`copy` \| `error`) — the object's bytes will not parse at all: bad gzip, truncated, or not JSON. `copy` forwards it verbatim, `error` fails the object. See below.
- **`on_object_too_large`** (`stream` \| `error`) — the object's body exceeds `processing.max_object_bytes`. `stream` re-runs it through stream mode, which has no size cap and filters it normally; `error` fails the object. See below.
- **`processing.mode`** — see [buffer vs stream](architecture.md#processing-modes-buffer-vs-stream).

> **SQS: a message that is not an S3 notification now fails.** A body that is valid JSON but carries no `Records` array used to decode to zero objects and ack clean. It is now a decode error, so the message is redelivered and lands in the DLQ. That is the correct outcome for a real S3 notification whose shape changed under us, but it also means an **SNS `SubscriptionConfirmation` delivered to the queue will DLQ**: only `Type: "Notification"` is unwrapped as an SNS envelope. Confirm subscriptions out of band, and expect DLQ traffic on a queue that receives them.

#### Fail-open: what happens to an object that will not parse

The filter is fail-open by default at every level, because a SIEM missing a log is worse than a SIEM holding one it cannot use.

| Failure                                      | Default       | What lands at the destination                     |
| -------------------------------------------- | ------------- | ------------------------------------------------- |
| A single record fails to parse               | always kept   | the record, verbatim, inside the rewritten object |
| Object is valid JSON with no `Records` array | `copy`        | the source object, verbatim                       |
| Object will not parse at all (gzip or JSON)  | `copy`        | the source object, verbatim                       |
| Rules document has never loaded              | `open`        | the source object, verbatim, unfiltered           |
| Source object is missing (`404`)             | `error`       | nothing — the event is re-driven                  |
| `GetObject` / `PutObject` failed             | error, always | nothing — the event is re-driven                  |

A **record** that fails to parse is never dropped, in either processing mode, and no setting can change that. It is copied into the output and counted in `ParseErrors`. This includes a record that is a well-formed JSON span but fails a full decode — a lone UTF-16 surrogate escape, say.

An **object** that fails to parse is the case `on_parse_error` governs. Under the `copy` default the source bytes are written to the destination key unchanged, `ObjectsCopiedUnparsed` is incremented, and the object is not failed; under `error` the object fails, and on SQS the message is re-driven and eventually DLQ'd. `copy` means a corrupt or non-CloudTrail object reaches the SIEM as-is rather than being held in a DLQ nobody reads; `error` means it never reaches the SIEM but is never silently accepted either. Choose `error` only if you actively work the DLQ.

Three things `on_parse_error` deliberately does not cover, because none is a parse failure:

- **`ObjectTooLarge`** — that is `on_object_too_large`'s business, below. Copying such an object verbatim would forward it _unfiltered_; streaming it filters it properly, so `on_parse_error` would be the worse tool.
- **Store failures.** A failed `GetObject` or `PutObject` must retry. Copying on a destination outage would report success for a write that never landed.
- **Internal failures** — a compression or worker-task failure (`CoreError::Internal`). The object may already have been decompressed, parsed and filtered, so copying its source verbatim would forward every record the rules dropped.

#### An object bigger than `max_object_bytes`

`processing.max_object_bytes` bounds what buffer mode holds in memory. It says nothing about whether an object is acceptable — an object over the cap is fine, the path picked for it is not. So the default, `on_object_too_large: stream`, re-runs that object through stream mode, which has no size cap and filters it exactly as buffer mode would; the output is byte-identical. The cost is a second `GetObject`, logged at `warn`.

This applies in every `processing.mode`, including an explicit `mode: buffer`. That mode is a routing preference, and honouring it to the point of dropping an object would lose data the SIEM needs. A recurring warn is the signal to raise `max_object_bytes` or the function's memory, not something to leave running.

Set `on_object_too_large: error` to fail the object instead. That is the right choice only if you want a hard size ceiling on ingest and you work the DLQ: the failure is deterministic, so the object fails on every redrive and its records never arrive.

Watch `ObjectsCopiedUnparsed`: a non-zero rate means objects are arriving that this filter cannot read at all. It is doing the safe thing with them, but the cause — a truncated upload, a non-CloudTrail file matching the key filter — is worth finding.

#### Choosing a `gzip_level`

Compression is the largest single stage of per-object CPU — 13.42 ms against 5.97 ms for filtering — so this setting is the biggest lever available. Measured on a 4.5 MB / 4,000-record CloudTrail object with the `rust_backend` (miniz_oxide) compressor:

| level           | time         | output size   | vs. default           |
| --------------- | ------------ | ------------- | --------------------- |
| 1               | 7.09 ms      | 745,560 B     | −47% time, +276% size |
| 2               | 7.32 ms      | 346,027 B     | −45% time, +75% size  |
| 3               | 9.17 ms      | 224,915 B     | −32% time, +14% size  |
| 4               | 8.63 ms      | 232,167 B     | −36% time, +17% size  |
| **6 (default)** | **13.42 ms** | **198,063 B** | —                     |
| 9               | 17.78 ms     | 189,557 B     | +33% time, −4% size   |

This measures filter-core CPU only and excludes S3 network I/O, which likely dominates real wall-clock time, so the time column is an upper bound on what lowering the level saves end-to-end. The default of 6 optimises for storage, on the assumption that S3 storage and downstream read costs recur while compression CPU is paid once. Lower it to 4 only if Lambda duration is the binding cost; level 9 is not worth it.

**miniz_oxide is not monotonic in level.** Level 3 produces _smaller and slower_ output than level 4 — neither dominates the other. Do not assume a lower level is always faster and larger; re-measure on your own data before tuning.

#### Choosing an `object_concurrency`

**It only does something when one invocation carries more than one object.** Objects come from the decoder, so the trigger decides the ceiling:

| Trigger       | Objects per invocation                    | Useful range           |
| ------------- | ----------------------------------------- | ---------------------- |
| `eventbridge` | always exactly 1                          | none — leave it at `1` |
| `s3`          | the notification's `Records` (usually 1)  | rarely worth raising   |
| `sns`         | one item per SNS record                   | up to the fan-out      |
| `sqs`         | one item per message = **the batch size** | up to the batch size   |

Anything above the object count is dead configuration: the extra slots never fill. **If you run the `eventbridge` binary, this setting can do nothing at all.** The setting that governs how many objects arrive together is the SQS event source's batch size, not this one.

Where it does apply, it overlaps S3 round-trips — it does **not** add CPU parallelism, because every binary runs a `current_thread` Tokio runtime. So the win is bounded by the share of wall clock spent waiting on S3, and the floor is the serialized CPU cost of the whole batch. Measured on 16 objects of 4,000 records each, with a 30 ms simulated latency on every `get`:

| `object_concurrency` | wall clock | vs. `1` |
| -------------------- | ---------- | ------- |
| **1 (default)**      | 846.8 ms   | —       |
| 2                    | 521.0 ms   | 1.65x   |
| 4                    | 375.4 ms   | 2.28x   |
| 8                    | 303.8 ms   | 2.82x   |
| 16                   | 264.9 ms   | 3.24x   |
| 32                   | 270.1 ms   | 3.17x   |

Two things to read off it. Returns fall away well before the cap: `4` captures 70% of the win that `16` does. And `32` is no faster than `16` — there were only 16 objects, so the extra slots did nothing. The 265 ms plateau is the CPU floor: re-run with zero latency and every concurrency lands within noise of 234 ms, because there is no I/O left to hide.

**Practical guidance.** Leave it at `1` unless you are on the SQS binary with a batch size above 1. There, start at `4`, and never set it above your batch size. Then check `max_object_bytes`: each in-flight object holds its own compressed fetch _and_ its own decompressed body, so peak memory scales with the setting. Buffer mode already peaks at roughly two object-sized buffers, so at the 128 MiB `max_object_bytes` default, `object_concurrency: 4` can put ~1 GB in flight in the worst case. Raise Lambda memory or lower `max_object_bytes` to match, or the function OOMs on a batch of large objects — a failure the default never has.

Behavior does not change with the value. Results are adjudicated in submission order no matter what order they complete in, so the destination bytes, the counters, the failed-message set and its order are identical at every setting.

This holds on the abort path too — `partial_batch_failures: false` plus an object that fails. The failure is held rather than returned immediately: the batch's **remaining objects are all processed**, not merely the ones already in flight, and only then is that first failure in submission order returned. Draining everything is what keeps the counters value-independent, and it stops a cancelled upload from leaving orphan multipart parts behind. The cost is that a batch containing one doomed object still pays for the whole batch, on the first attempt and on every retry; the writes are idempotent, so the repetition is wasted work rather than corruption. Under the default `partial_batch_failures: true` the batch runs to completion anyway and only the failing messages are redriven.

#### Choosing a `gzip_chunks`

**Buffer mode only** — stream mode ignores it. Above `1`, the survivors are split at byte offsets, each part is deflated on its own thread, and the members are concatenated. A gzip stream decompresses to the concatenation of its members, so the payload is byte-identical at every chunk count; only the framing and the compressed size change.

| `gzip_chunks`   | time     | vs. `1`   | output size |
| --------------- | -------- | --------- | ----------- |
| **1 (default)** | 14.25 ms | —         | —           |
| 2               | 7.34 ms  | **1.94x** | +1.73%      |
| 4               | 4.02 ms  | **3.54x** | +5.28%      |

Each member after the first starts with an empty back-reference window, which is where the size increase comes from. The chunk count is capped so the split is sized around a 64 KiB floor (the trailing member can land a few bytes under it), so a small object silently stays a single member and pays nothing.

**It needs more than one vCPU to do anything.** Lambda allocates vCPU in proportion to memory: below ~1769 MB the function has less than one full vCPU, the threads contend for it, and you pay the size increase for no speedup. Leave it at `1` on a small function.

> **Check your downstream reader before enabling this.** Multi-member gzip is valid per RFC 1952 and every mainstream reader handles it — verified on an 8-member object from this tool:
>
> | Reader                             | Reads all 8 members        |
> | ---------------------------------- | -------------------------- |
> | `gzip -dc` / `zcat` / `gzip -t`    | yes                        |
> | Python `gzip` module               | yes                        |
> | Node `zlib.gunzipSync`             | yes                        |
> | Go `compress/gzip`                 | yes                        |
> | Python `zlib.decompress(data, 31)` | **no — first member only** |
> | Rust `flate2::read::GzDecoder`     | **no — first member only** |
>
> The two that fail do so **silently**: no error, just a short read. On that 8-member object `zlib.decompress(data, 31)` returned 370,002 of 2,960,013 bytes and reported success. If anything downstream uses a single-member decoder, leave `gzip_chunks` at `1`; the default emits exactly the bytes the unchunked encoder always did.

## Validation constraints

`panic = "abort"` is set in the release profile, so a bad config value that panics at runtime kills the whole Lambda process — a poison pill that retries until DLQ/expiry. These constraints are checked once, at settings load, so a bad value is a clear load-time error instead:

| Field                             | Constraint                             | Why                                                                                                                                                                                                                                                                    |
| --------------------------------- | -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `processing.gzip_level`           | `0`–`9`                                | `flate2`'s `rust_backend` panics on any level above 9 (`9` = best compression), on the first object processed — not at startup.                                                                                                                                        |
| `source.include_key_regex`        | must compile                           | An uncompilable pattern otherwise panics inside `Pipeline::new` at cold start (a crash loop), not at settings load.                                                                                                                                                    |
| `source.exclude_key_regex`        | must compile                           | Same as above.                                                                                                                                                                                                                                                         |
| `processing.max_object_bytes`     | `>= processing.stream_threshold_bytes` | `stream_threshold_bytes` is a **compressed**-size estimate that picks buffer vs. stream mode; `max_object_bytes` is buffer mode's memory cap, applied to the compressed fetch **and** the decompressed body. If it's smaller, buffer-mode objects always blow the cap. |
| `processing.multipart_part_bytes` | `>= 5 * 1024 * 1024` (S3's minimum)    | A smaller part size fails `CompleteMultipartUpload` with `EntityTooSmall` mid-object, after bytes are already uploaded.                                                                                                                                                |
| `processing.object_concurrency`   | `1`–`64`                               | Each in-flight object holds its own decompressed body, so this multiplies peak memory by up to `max_object_bytes` per slot. `0` would process nothing; past `64` the memory multiplier dominates any latency win.                                                      |
| `processing.gzip_chunks`          | `1`–`16`                               | Each member above the first loses the previous chunk's back-reference window, so the object grows. `0` would emit nothing; past `16` the per-member framing and ratio loss outgrow the parallelism.                                                                    |

## Pre-deploy validation: `validate-settings`

`cloudtrail-rs validate-settings [path]` runs a settings document through the exact same `Settings::from_parts` validation the Lambda binaries run at cold start — including every constraint above — so a bad settings file or a bad `CT_*` override is caught before it ships, not on the first invocation.

```sh
cloudtrail-rs validate-settings examples/settings.example.yaml
# settings OK
#   processing.mode:                   Auto
#   processing.stream_threshold_bytes: 8388608
#   processing.max_object_bytes:       134217728
#   processing.multipart_part_bytes:   8388608
#   processing.gzip_level:             6
#   destination.bucket:                ct-siem-sync
#   rules.uri:                         s3://sec-config/cloudtrail/rules.yaml
echo $?   # 0
```

`path` is optional — omit it to validate the built-in defaults (plus any `CT_*` overrides already in the environment), the env-only deployment case. `CT_*` env vars are honoured exactly as in production, so the same command also doubles as a way to sanity-check a deployment's actual environment before it goes live. Exit code is non-zero, with the offending key named in the error, on any validation failure.

## The YAML quoting trap

Rules and settings are YAML, and YAML's escaping rules depend on the scalar style. This bites hardest with `\d`, `\.`, and friends inside a rule `regex`:

```yaml
# CORRECT — double-quoted scalar: YAML unescapes \\ to \, giving the
# 2-character regex \d (Rust regex: "a digit").
- field_name: requestParameters.roleSessionName
  regex: "^session-\\d+$"

# WRONG — single-quoted (or a bare/plain) scalar: YAML does NOT interpret
# backslash escapes here, so the regex engine receives the 4 literal
# characters \\d — which matches a literal backslash followed by "d", never
# a digit. This rule will never fire on real session names.
- field_name: requestParameters.roleSessionName
  regex: '^session-\\d+$'
```

Rule of thumb: write regex patterns in **double-quoted** YAML scalars and double every backslash you want the regex engine to see once (`\\.` → `\.`, `\\d` → `\d`). [`cloudtrail-rs test`](cli.md#test-rules-samplejsongz) against a real sample is the fastest way to catch a rule that silently never matches.

---

See also: [Rules](rules.md) · [CLI](cli.md) · [Architecture](architecture.md)
