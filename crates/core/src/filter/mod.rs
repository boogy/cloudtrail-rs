//! Rule-matching support: field path resolution, rule indexing, and the
//! evaluation engine.

pub mod engine;
mod index;
pub mod path;
mod project;

pub use engine::{Decision, Engine};
pub use path::{Path, PathParseError, Segment, literal_path, parse_path, resolve, visit_values};
