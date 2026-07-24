# cloudtrail-rs documentation

`cloudtrail-rs` filters CloudTrail S3 logs in flight: read a `.json.gz`
CloudTrail object, drop noisy `Records` entries that match a configured exclusion
rule, write the survivors to a destination bucket with the same
`gzip({"Records":[...]})` envelope. It ships as four independent Lambda binaries
(one per trigger topology) plus a local/offline CLI, built on a hexagonal core.

## Start here

- **New to the project?** Read [Architecture](architecture.md), then
  [Deployment](deployment.md).
- **Configuring a deployment?** [Configuration](configuration.md) +
  [Rules](rules.md).
- **Working locally?** [CLI](cli.md) + [Development](development.md).

## Contents

| Doc                                  | What's in it                                                                                              |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------- |
| [architecture.md](architecture.md)   | Hexagonal core, crate graph, the four ports, per-record hot path, buffer-vs-stream, cold-start/init-once. |
| [configuration.md](configuration.md) | `SETTINGS_URI`, precedence, the settings file, full `CT_*` env-var reference, the YAML quoting trap.      |
| [rules.md](rules.md)                 | Rules schema, AND-within/OR-across evaluation, the rule index and the `always` bucket, validation.        |
| [deployment.md](deployment.md)       | Four trigger topologies, building zips and container images, IAM, the SQS data-loss warning, rollout.     |
| [cli.md](cli.md)                     | `validate` / `test` / `filter` reference with examples.                                                   |
| [development.md](development.md)     | Everyday commands, Makefile targets, MiniStack tests, CI, the release pipeline, repo secrets.  |

---

Back to the [project README](../README.md).
