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

pub use runtime_api::{FakeRuntimeApi, LambdaProcess, Outcome};
