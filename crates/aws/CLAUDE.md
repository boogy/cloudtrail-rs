# crates/aws — `cloudtrail-rs-aws`

AWS adapters implementing `core`'s ports. Nothing here belongs in `core` (keeps the hexagonal boundary: `core` has zero AWS deps). `#![forbid(unsafe_code)]`.

## Layout

| File             | Role                                                                                             |
| ---------------- | ------------------------------------------------------------------------------------------------ |
| `http_client.rs` | The one shared rustls+**ring** HTTP client; `load_aws_config`. Owns the crypto-backend decision. |
| `s3_store.rs`    | `ObjectStore` adapter (get/put, multipart; `DEFAULT_MULTIPART_PART_BYTES`).                      |
| `s3_config.rs`   | `ConfigSource` for `s3://` rules/settings.                                                       |
| `ssm_config.rs`  | `ConfigSource` for `ssm://` rules/settings.                                                      |

Every SDK `Client` in this crate is built with `ring_http_client()`. Adapters never call `aws_config::load_defaults` — always `load_aws_config()` (see below).

## Crypto backend: ring, not aws-lc-rs — the full record

**Standardize on `rustls` + `ring`. `aws-lc-rs`/`aws-lc-sys` are banned** in `deny.toml`. Enforced in three layers:

1. **Cargo features** — `aws-smithy-http-client` uses `default-features = false, features = ["rustls-ring"]`; `aws-config` uses `default-features = false` (its `default-https-client` feature would pull in `aws-lc-rs`).
2. **Explicit wiring** — `ring_http_client()` builds every client with `Provider::Rustls(CryptoMode::Ring)`. `load_aws_config()` exists because `aws_config::load_defaults` eagerly builds an IMDS client that panics without a supplied `http_client` once defaults are off — so we inject the ring client up front. Test helpers in `testkit`/`tests` mirror this.
3. **cargo-deny** — bans `aws-lc-rs`, `aws-lc-sys`, `openssl-sys`; allows `ring`'s BoringSSL (`OpenSSL`) license blob.

### Why

`aws-lc-rs` compiles a BoringSSL-derived C library (`aws-lc-sys`) from source via CMake. On the static-musl / ARM64 Lambda cross-build that means: a full C-library compile on the serial critical path; a CMake configure/probe step; a `build.rs` artifact Rust's incremental cache can't absorb (rebuilt on every target/flag change → paid in full on cold CI caches); a cross C compiler + sysroot instead of Rust's `rustup target add`; possibly libclang/bindgen. Net: a large fixed compile cost plus fragile cross-compile detection that turns some builds into retry loops — the classic "works locally, fails in CI." `ring` is pre-generated asm + minimal C, so none of that applies.

### Tradeoffs if we switched to the aws-lc-rs default

- **Gain:** ecosystem alignment (AWS SDK _and_ rustls 0.23+ default to `aws-lc-rs`), so the `http_client.rs` workaround + `default-features = false` dance disappear; AWS-backed maintenance/CVE response; **FIPS capability**; marginally faster crypto (irrelevant — this workload is I/O-bound).
- **Cost:** a C cross-toolchain (clang + CMake) in the release pipeline, larger binaries, slower/more fragile cross-builds.

### Future risk of staying on ring

Single-maintainer project, slower CVE turnaround, past stagnation; growing config drift as the ecosystem leans into `aws-lc-rs` (expect more `default-features` breakage like the IMDS panic). Mitigated by `deny.toml`: `unmaintained = "workspace"` (warn), `yanked = "deny"`.

**FIPS is the one-way door.** `aws-lc-rs` has a FIPS 140-3 validated mode; `ring` does not and cannot. A FIPS requirement (GovCloud / FedRAMP / regulated) forces `aws-lc-rs`. That single question decides the long-term choice.

### How to switch (if ever)

Reversible anytime — no data/wire/API coupling, no migration, identical runtime behavior. Do all of this in **one atomic change** or CI breaks:

1. Features: `rustls-ring` → `rustls-aws-lc` on `aws-smithy-http-client` in `crates/aws/Cargo.toml` **and** `crates/testkit/Cargo.toml`; re-enable `aws-config` defaults.
2. Wiring — either minimal (`CryptoMode::Ring` → `CryptoMode::AwsLc` in `http_client.rs` + the two `ministack.rs` helpers) or clean (delete `http_client.rs`, replace `load_aws_config()` with `aws_config::load_defaults` at the 6 call sites, drop the `.http_client(ring_http_client())` calls in `s3_store`/`s3_config`/`ssm_config` — the IMDS-panic reason vanishes).
3. `deny.toml`: remove the `aws-lc-rs`/`aws-lc-sys` bans (leaving them → `cargo deny` hard-fails on the new deps).
4. **CI: add the C cross-toolchain** (clang + CMake for `aws-lc-sys`) on the musl/ARM64 path _before or with_ the change, or `make lambda-build` / `release-musl` break.
