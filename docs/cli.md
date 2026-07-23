# CLI (`cloudtrail-rs`)

Local/offline companion to the Lambda binaries — the same `Engine` and
`core::process::buffer_run`, no Lambda runtime involved. Lives in `crates/cli`,
package name `cloudtrail-rs`.

- [Building](#building)
- [URIs](#uris)
- [`validate <uri>`](#validate-uri)
- [`test <rules> <sample.json.gz>`](#test-rules-samplejsongz)
- [`filter <source> <dest> --rules <uri>`](#filter-source-dest---rules-uri)

## Building

```sh
cargo build --release -p cloudtrail-rs
# binary at target/release/cloudtrail-rs
```

Or pull the container image:

```sh
docker run --rm ghcr.io/boogy/cloudtrail-rs:cli-latest --help
```

## URIs

A rules/config `uri` accepts `ssm://`, `s3://`, `file://`, or a **bare local
path** (no `scheme://` at all — read straight off disk, the ergonomic case for
`examples/rules.example.yaml`). Any S3/SSM path needs AWS credentials resolved the
normal SDK way (env, profile, instance role, …).

## `validate <uri>`

Builds the `Engine` from the rules document, prints rule/pattern counts, and
warns (to stderr, non-fatally) about every rule the index could not anchor by
`eventSource` (see [the `always` bucket](rules.md#the-rule-index-and-the-always-bucket)).
Exit code is non-zero **only** on an actual config/build error (bad YAML, invalid
semver, unresolvable regex, duplicate rule name, empty `matches`, etc.) — this is
what CI should gate on.

```sh
cloudtrail-rs validate examples/rules.example.yaml
# 25 rules, 81 patterns compiled
# warning: rule "IAM Session Renewals" not indexed by eventSource (no eventSource condition): checked against every record
# warning: rule "AWS Config Recorder" not indexed by eventSource (pattern ".*\.amazonaws\.com$" could not be reduced to a fixed set of literals): checked against every record
# warning: rule "Automated Tool Describe Operations" not indexed by eventSource (no eventSource condition): checked against every record
echo $?   # 0
```

## `test <rules> <sample.json.gz>`

Evaluates every record in a decompressed CloudTrail sample against the compiled
ruleset and reports KEEP/DROP (with the dropping rule's name) per record, plus a
kept/dropped summary — useful for spotting a rule that never fires (a YAML-quoting
bug, a typo'd `field_name`, etc.) before it ships.

```sh
cloudtrail-rs test examples/rules.example.yaml sample-cloudtrail-log.json.gz
# KEEP  record 1
# DROP  record 2 (rule: "EKS KMS Operations")
# ...
# summary: 500 records, 420 kept (84.0%), 80 dropped (16.0%)
```

## `filter <source> <dest> --rules <uri>`

Filters CloudTrail gzip objects through the exact same `buffer_run` the Lambda
binaries use. `source` and `dest` are each independently auto-detected:

- a **local file** — `source` filters that one object to `dest` (a file path);
- a **local directory** — every `.json.gz` under it is filtered, mirroring each
  object's relative path into `dest` (a directory, created as needed);
- an **`s3://bucket/prefix`** — every `.json.gz` under that prefix is filtered,
  batch-style, same as a local directory.

Output is always gzip-faithful `.json.gz` with the canonical
`application/x-gzip` / `gzip` content-type and content-encoding. Objects where
every record is dropped are **not written** ("zero empty writes") — neither
locally nor to S3. Any S3-side `source`/`dest` needs AWS credentials resolved the
normal SDK way (env, profile, instance role, …).

**Local → local (see filtering happen with plain folders, no AWS needed):**

```sh
mkdir -p in out
cp cloudtrail-sample-*.json.gz in/
cloudtrail-rs filter in/ out/ --rules examples/rules.example.yaml
#   a.json.gz -> out/a.json.gz
#   b.json.gz -> (all records dropped, nothing written)
# processed 2 object(s): 1 written, 1 fully dropped, 0 copied verbatim
# records: 4 in, 2 kept, 2 dropped
```

**Local → S3:**

```sh
cloudtrail-rs filter in/ s3://ct-siem-sync/backfill/ --rules examples/rules.example.yaml
```

**S3 → local** (pull, filter, and inspect a prefix without writing back to AWS):

```sh
cloudtrail-rs filter s3://raw-cloudtrail-bucket/AWSLogs/ ./filtered/ \
  --rules ssm:///cloudtrail-rs/rules
```

**Single file → single file:**

```sh
cloudtrail-rs filter sample.json.gz filtered.json.gz --rules examples/rules.example.yaml
```

---

See also: [Rules](rules.md) · [Configuration](configuration.md)
