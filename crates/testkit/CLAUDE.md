# crates/testkit — `cloudtrail-rs-testkit`

Test support only. Consumed from `[dev-dependencies]`, never linked into a
shipped binary. It's a real crate (not a `#[path]` module) because the four
lambda crates plus `aws` all share these helpers. `#![forbid(unsafe_code)]`.

| Module           | Role                                                                                                                                                                                               |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `runtime_api.rs` | `FakeRuntimeApi`, `LambdaProcess`, `Outcome` — a fake Lambda Runtime API for driving handlers end-to-end.                                                                                          |
| `ministack.rs`   | rustls+**ring** S3/SSM client set pointed at the local MiniStack (`:4566`). Mirrors `crates/aws/src/http_client.rs` — keep the `CryptoMode::Ring` here in sync if the crypto backend ever changes. |
| `fixtures.rs`    | CloudTrail fixture builders (`gzip({"Records":[...]})`).                                                                                                                                           |

MiniStack tests are `#[ignore]`d; run via `make ministack-up` then
`make ministack-test`.
