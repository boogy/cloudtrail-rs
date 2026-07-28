# crates/cli — `cloudtrail-rs` (binary)

Local/offline companion to the Lambda binaries. Depends on `core` **and** `aws`
so a rules `uri` may be `ssm://`, `s3://`, `file://`, or a bare local path.
`#![forbid(unsafe_code)]`.

## Subcommands (all reuse `core`'s engine — never reimplement filtering)

- `validate <uri>` — build the `Engine`, print rule/pattern counts, warn
  (non-fatally) about rules that couldn't be indexed (`always` bucket). Non-zero
  exit only on a config/build error — this is the CI gate.
- `validate-settings [path]` — run a settings document through the same
  `Settings::from_parts` the Lambdas run at cold start (`CT_*` overrides
  honoured), so a config value that would panic mid-invocation under
  `panic = "abort"` is caught pre-deploy. Path optional: omit to validate
  defaults + env. Never reimplement the validation here — call `from_parts`.
- `test <rules> <sample.json.gz>` — per-record KEEP/DROP against the compiled
  ruleset + summary, so dead rules are visible.
- `filter <source> <dest> --rules <uri> [--settings <path>]` — local/backfill
  filtering via `core::process::{buffer_run, stream_run}`. `source`/`dest`
  auto-detect local path vs `s3://bucket/prefix`; a directory or `s3://` prefix
  triggers batch mode. `--settings` makes a backfill select and process what
  the deployment does: `source.*` decides scope via the shared
  `core::config::KeyFilter` (never re-derive the key filter here — that type is
  the one `Settings::validate` and `Pipeline` use), `processing.*` decides
  buffer vs. stream per object including the `auto` `ObjectTooLarge` → stream
  retry, `behavior.dry_run` / `behavior.on_unrecognized_object` decide what is
  written. Both sides are addressed through `core`'s `ObjectStore` port —
  `LocalObjectStore` is the filesystem impl, and its `put_stream` writes
  through a temp sibling so an aborted stream leaves nothing behind. A batch
  never stops at the first bad object: failures accumulate, the summary still
  prints, then the failed objects are listed and the exit code is non-zero.

Uses `load_aws_config()` from `crates/aws` (ring TLS) when `s3://`/`ssm://` is
involved. See [`docs/cli.md`](../../docs/cli.md).
