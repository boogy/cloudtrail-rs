//! Rule-matching support: field path resolution, rule indexing, and the
//! evaluation engine.

pub mod engine;
pub mod path;

pub use engine::{Decision, Engine};
pub use path::resolve;
