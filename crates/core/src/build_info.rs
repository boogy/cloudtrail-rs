//! Version and commit metadata baked in at compile time by `build.rs`.
//!
//! Each binary logs [`LONG`] once at cold start so the running build is visible
//! in CloudWatch; the CLI exposes it via `--version`.

/// Release version — a git tag like `v1.2.3` on shipped builds, a `git
/// describe` string locally, or the crate semver as a last resort.
pub const VERSION: &str = env!("CLOUDTRAIL_RS_BUILD_VERSION");

/// Short (12-char) git commit SHA the binary was built from, or `"unknown"`
/// when git was unavailable at build time.
pub const GIT_SHA: &str = env!("CLOUDTRAIL_RS_BUILD_GIT_SHA");

/// One-line banner, e.g. `v1.2.3 (a1b2c3d4e5f6)` — used for `--version` and the
/// cold-start log line.
pub const LONG: &str = env!("CLOUDTRAIL_RS_BUILD_LONG");
