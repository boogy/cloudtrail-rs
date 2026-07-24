# crates/cli — `cloudtrail-rs` (binary)

Local/offline companion to the Lambda binaries. Depends on `core` **and** `aws`
so a rules `uri` may be `ssm://`, `s3://`, `file://`, or a bare local path.
`#![forbid(unsafe_code)]`.

## Subcommands (all reuse `core`'s engine — never reimplement filtering)

- `validate <uri>` — build the `Engine`, print rule/pattern counts, warn
  (non-fatally) about rules that couldn't be indexed (`always` bucket). Non-zero
  exit only on a config/build error — this is the CI gate.
- `test <rules> <sample.json.gz>` — per-record KEEP/DROP against the compiled
  ruleset + summary, so dead rules are visible.
- `filter <source> <dest> --rules <uri>` — local/backfill filtering via
  `core::process::buffer_run`. `source`/`dest` auto-detect local path vs
  `s3://bucket/prefix`; a directory or `s3://` prefix triggers batch mode.

Uses `load_aws_config()` from `crates/aws` (ring TLS) when `s3://`/`ssm://` is
involved. See [`docs/cli.md`](../../docs/cli.md).
