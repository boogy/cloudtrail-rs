//! Config document types and loading: the exclusion rules document, settings,
//! URI resolution, the `file://` source, and the caching `ConfigStore`.

pub mod file_source;
pub mod rules;
pub mod settings;
pub mod store;
pub mod uri;

pub use file_source::FileConfigSource;
pub use rules::{Match, Rule, RuleSet};
pub use settings::{
    Behavior, Destination, MetricsMode, Observability, OnConfigError, OnMissingObject,
    OnUnrecognizedObject, Processing, ProcessingMode, Rules, Settings, Source, Sqs, SqsBodyFormat,
};
pub use store::{Compile, ConfigStore};
pub use uri::ConfigUri;
