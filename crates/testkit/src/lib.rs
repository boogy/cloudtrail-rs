//! Shared test support: a fake Lambda Runtime API, a MiniStack client set, and
//! CloudTrail fixture builders.
//!
//! Consumed only from `[dev-dependencies]`, never linked into a shipped
//! binary. It exists as a crate rather than an included module because the
//! four lambda crates and the `aws` crate all need the same helpers, and a
//! dev-dependency is the only way to share code across crate boundaries.
#![forbid(unsafe_code)]

pub mod fixtures;
pub mod ministack;
pub mod runtime_api;

/// Realistic CloudTrail records, re-exported from `core` so consumers reach
/// them as `testkit::corpus` alongside [`fixtures`].
///
/// The two are complementary, not competing. [`fixtures`] builds *minimal*
/// records (`{"eventName":…,"eventSource":…,"eventID":…}`) — the right thing
/// for an end-to-end test whose subject is the trigger payload or the S3
/// round trip, where a 1 KB record per line would bury the signal. `corpus`
/// carries production-shaped records, for tests whose subject is the record
/// content itself: deep dot paths, unresolvable leaves, byte-exact survival.
pub use cloudtrail_rs_core::testing::corpus;

pub use runtime_api::{FakeRuntimeApi, LambdaProcess, Outcome};
