# Configuration

Every runtime knob has a default, an optional settings-file field, and (almost
always) a `CT_*` environment override. **Environment always wins over the file.**

- [Where settings come from](#where-settings-come-from)
- [Precedence](#precedence)
- [The settings file](#the-settings-file)
- [Environment variable reference](#environment-variable-reference)
- [The YAML quoting trap](#the-yaml-quoting-trap)

## Where settings come from

`SETTINGS_URI` is read at process start to locate an optional settings document:

- `file://…` — resolved by `core` directly (no AWS link needed).
- `s3://…` / `ssm://…` — resolved by the composition root, which links `cloudtrail-rs-aws`.

An **env-only deployment — no `SETTINGS_URI` at all — is valid**: every field
below has a default and/or a `CT_*` override. Only `CT_DEST_BUCKET`
(`destination.bucket`) is mandatory, here or in the file.

## Precedence

```mermaid
flowchart LR
    D["Built-in default"] --> F["settings file<br/>(SETTINGS_URI)"]
    F --> E["CT_* env var"]
    E --> V(["Effective value"])
    style E fill:#2d6,stroke:#161,color:#000
    style V fill:#39f,stroke:#036,color:#fff
```

For any given field: start from the built-in default, override with the settings
file if present, then override with the `CT_*` env var if present. The
right-most source that sets a value wins, so an env var overrides the file, and
the file overrides the default.

## The settings file

`SETTINGS_URI` points at a YAML document shaped like
[`examples/settings.example.yaml`](../examples/settings.example.yaml):

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
  max_object_bytes: 134217728 # BUFFER MODE ONLY — decompressed guard
  multipart_part_bytes: 8388608 # stream mode
  gzip_level: 6
behavior:
  dry_run: false # evaluate + count, forward everything
  on_config_error: open # open | closed   (DEFAULT: open)
  on_missing_object: error # error | skip
  on_unrecognized_object: copy # copy | skip | error
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

> **`version: 1` here is an integer schema marker, not semver.** It is the only
> settings field with no env override. Do not confuse it with the **rules**
> file's `version: 1.0.0`, which _is_ semver — see [rules.md](rules.md). The two
> `version:` fields are unrelated and follow different rules.

## Environment variable reference

| Variable                      | Settings path                       | Meaning                                                                                                                                                                                   | Default                                 |
| ----------------------------- | ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| `SETTINGS_URI`                | — (bootstrap only)                  | `file://`, `s3://`, or `ssm://` location of the optional settings YAML document.                                                                                                          | none (env-only deployment)              |
| `CT_DEST_BUCKET`              | `destination.bucket`                | Destination bucket for filtered output. **Required** (here or in the file).                                                                                                               | —                                       |
| `CT_KEY_PREFIX`               | `destination.key_prefix`            | Prefix prepended to the source key for the destination key. `""` = identical key.                                                                                                         | `""`                                    |
| `CT_SOURCE_INCLUDE_KEY_REGEX` | `source.include_key_regex`          | Source key must match this to be processed.                                                                                                                                               | `\.json\.gz$`                           |
| `CT_SOURCE_EXCLUDE_KEY_REGEX` | `source.exclude_key_regex`          | Source key matching this is skipped (digests, Insights, folder markers).                                                                                                                  | `(/CloudTrail-Digest/                   | /CloudTrail-Insight/ | /$)` |
| `CT_PROCESSING_MODE`          | `processing.mode`                   | `auto` \| `buffer` \| `stream`.                                                                                                                                                           | `auto`                                  |
| `CT_STREAM_THRESHOLD_BYTES`   | `processing.stream_threshold_bytes` | `auto` mode switches to streaming above this object size.                                                                                                                                 | `8388608`                               |
| `CT_MAX_OBJECT_BYTES`         | `processing.max_object_bytes`       | Buffer-mode-only guard on decompressed size.                                                                                                                                              | `134217728`                             |
| `CT_MULTIPART_PART_BYTES`     | `processing.multipart_part_bytes`   | Stream-mode S3 multipart part size.                                                                                                                                                       | `8388608`                               |
| `CT_GZIP_LEVEL`               | `processing.gzip_level`             | Output gzip compression level.                                                                                                                                                            | `6`                                     |
| `CT_DRY_RUN`                  | `behavior.dry_run`                  | Evaluate and count, but forward every record untouched.                                                                                                                                   | `false`                                 |
| `CT_ON_CONFIG_ERROR`          | `behavior.on_config_error`          | `open` \| `closed` when the rules doc has never loaded successfully.                                                                                                                      | `open`                                  |
| `CT_ON_MISSING_OBJECT`        | `behavior.on_missing_object`        | `error` \| `skip` when the source object is gone.                                                                                                                                         | `error`                                 |
| `CT_ON_UNRECOGNIZED_OBJECT`   | `behavior.on_unrecognized_object`   | `copy` \| `skip` \| `error` for JSON with no `Records` array.                                                                                                                             | `copy`                                  |
| `CT_PARTIAL_BATCH_FAILURES`   | `behavior.partial_batch_failures`   | SQS only — `true` returns `batchItemFailures` for just the failed items; `false` fails the whole batch. See the [SQS warning](deployment.md#sqs-reportbatchitemfailures-is-not-optional). | `true`                                  |
| `CT_SQS_BODY_FORMAT`          | `sqs.body_format`                   | `auto` \| `s3` \| `sns` — set explicitly to skip the SQS body-shape sniff.                                                                                                                | `auto`                                  |
| `CT_RULES_URI`                | `rules.uri`                         | `ssm://` \| `s3://` \| `file://` location of the exclusion-rules document.                                                                                                                | `s3://sec-config/cloudtrail/rules.yaml` |
| `CT_RULES_TTL_SECONDS`        | `rules.ttl_seconds`                 | Cache TTL before revalidating the rules document.                                                                                                                                         | `300`                                   |
| `CT_METRICS`                  | `observability.metrics`             | `emf` \| `none`.                                                                                                                                                                          | `emf`                                   |
| `CT_METRICS_NAMESPACE`        | `observability.namespace`           | CloudWatch EMF namespace.                                                                                                                                                                 | `cloudtrail-rs`                         |
| `CT_LOG_LEVEL`                | `observability.log_level`           | Log verbosity.                                                                                                                                                                            | `info`                                  |

### Behavior knobs worth understanding

- **`on_config_error`** (`open` \| `closed`) — only applies when the rules
  document has _never_ loaded successfully. `open` forwards everything
  unfiltered (fail-open, no data loss, no filtering); `closed` errors out. A
  successful earlier load followed by a transient failure keeps using the last
  good ruleset until TTL forces a revalidate.
- **`on_missing_object`** (`error` \| `skip`) — the source object named by the
  event no longer exists. `error` surfaces it (and, on SQS, re-drives); `skip`
  treats it as a no-op.
- **`on_unrecognized_object`** (`copy` \| `skip` \| `error`) — JSON with no
  `Records` array. `copy` forwards it verbatim to the destination, `skip` drops
  it, `error` fails.
- **`processing.mode`** — see
  [buffer vs stream](architecture.md#processing-modes-buffer-vs-stream).

## The YAML quoting trap

Rules and settings are YAML, and YAML's escaping rules depend on the scalar
style. This bites hardest with `\d`, `\.`, and friends inside a rule `regex`:

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

Rule of thumb: write regex patterns in **double-quoted** YAML scalars and double
every backslash you want the regex engine to see once (`\\.` → `\.`, `\\d` →
`\d`). [`cloudtrail-rs test`](cli.md#test-rules-samplejsongz) against a real
sample is the fastest way to catch a rule that silently never matches.

---

See also: [Rules](rules.md) · [CLI](cli.md) · [Architecture](architecture.md)
