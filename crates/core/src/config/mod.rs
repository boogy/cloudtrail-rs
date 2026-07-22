//! Config document types and loading: the exclusion rules document (this
//! module tree) and, from later tasks, settings, URI resolution, and the
//! caching `ConfigStore`.

pub mod rules;
pub mod settings;

pub use rules::{Match, Rule, RuleSet};
pub use settings::{
    Behavior, Destination, MetricsMode, Observability, OnConfigError, OnMissingObject,
    OnUnrecognizedObject, Processing, ProcessingMode, Rules, Settings, Source, Sqs, SqsBodyFormat,
};
