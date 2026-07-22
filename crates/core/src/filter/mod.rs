//! Rule-matching support: field path resolution, rule indexing, and the
//! evaluation engine.

pub mod engine;
mod index;
pub mod path;

pub use engine::{Decision, Engine};
pub use path::resolve;
