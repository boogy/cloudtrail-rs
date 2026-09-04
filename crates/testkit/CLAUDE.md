# crates/testkit — `cloudtrail-rs-testkit`

Test support only. Consumed from `[dev-dependencies]`, never linked into a shipped binary. It's a real crate (not a `#[path]` module) because the four lambda crates plus `aws` all share these helpers. `#![forbid(unsafe_code)]`.

| Module           | Role                                                                                                                                                                                               |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `runtime_api.rs` | `FakeRuntimeApi`, `LambdaProcess`, `Outcome` — a fake Lambda Runtime API for driving handlers end-to-end.                                                                                          |
| `ministack.rs`   | rustls+**ring** S3/SSM client set pointed at the local MiniStack (`:4566`). Mirrors `crates/aws/src/http_client.rs` — keep the `CryptoMode::Ring` here in sync if the crypto backend ever changes. |
| `fixtures.rs`    | CloudTrail fixture builders (`gzip({"Records":[...]})`) — _minimal_ 3-field records.                                                                                                               |
| `corpus`         | Re-export of `cloudtrail_rs_core::testing::corpus`: realistic, production-shaped CloudTrail records.                                                                                               |

`fixtures` vs `corpus`: use `fixtures` when the subject is the trigger payload or the S3 round trip and record content is noise; use `corpus` when the subject _is_ the record (dot paths, unresolvable leaves, byte-exact survival). The corpus lives in `core` — not here — because core's own integration tests need it and core must not dev-depend on this crate; that would pull the AWS SDK into the dependency graph of the one crate defined by not having it.

MiniStack tests are `#[ignore]`d; run via `make ministack-up` then `make ministack-test`.
