//! Config document types and loading: the exclusion rules document (this
//! module tree) and, from later tasks, settings, URI resolution, and the
//! caching `ConfigStore`.

pub mod rules;

pub use rules::{Match, Rule, RuleSet};
