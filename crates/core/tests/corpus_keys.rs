//! The **key filter** against real CloudTrail key layouts.
//!
//! Selection happens before any of the processing in `corpus_parity.rs`: an
//! object the filter rejects is never read, so a mistake here is invisible in
//! every downstream test. Both failure directions are bad — rejecting real trail
//! objects silently stops filtering, while accepting digest or Insights objects
//! feeds the pipeline valid `.json.gz` of a different schema.
//!
//! [`corpus::KEYS`] carries the layouts AWS produces, each with the verdict the
//! **default** filter must reach. Needs the `testing` feature.
#![cfg(feature = "testing")]

use cloudtrail_rs_core::config::{KeyFilter, Source};
use cloudtrail_rs_core::testing::corpus;

#[test]
fn the_default_filter_classifies_every_corpus_key_as_declared() {
    let filter = KeyFilter::compile(&Source::default()).expect("default regexes must compile");

    for key in corpus::KEYS {
        assert_eq!(
            filter.allows(key.key),
            key.accepted_by_default,
            "default key filter disagrees with the corpus for {:?} — {}",
            key.key,
            key.notes
        );
    }
}

/// Pinned by name rather than trusting the table to keep containing one of each:
/// a corpus edit dropping the digest key would leave this file testing nothing.
#[test]
fn digest_and_insight_objects_are_excluded_despite_matching_the_include() {
    let filter = KeyFilter::compile(&Source::default()).expect("default regexes must compile");

    let excluded: Vec<&str> = corpus::KEYS
        .iter()
        .filter(|k| !k.accepted_by_default && k.key.ends_with(".json.gz"))
        .map(|k| k.key)
        .collect();

    assert!(
        excluded.iter().any(|k| k.contains("/CloudTrail-Digest/")),
        "the corpus must carry a digest key: it matches the include regex and \
         is rejected only by the exclude"
    );
    assert!(
        excluded.iter().any(|k| k.contains("/CloudTrail-Insight/")),
        "the corpus must carry an Insights key, for the same reason"
    );

    for key in excluded {
        assert!(
            !filter.allows(key),
            "{key} matches the include regex and must be rejected by the exclude"
        );
    }
}

/// Organization trails insert an `o-*` segment and custom prefixes prepend path
/// components; a filter recognizing only the single-account layout drops them.
#[test]
fn organization_and_prefixed_trail_objects_are_accepted() {
    let filter = KeyFilter::compile(&Source::default()).expect("default regexes must compile");

    let org = corpus::KEYS
        .iter()
        .find(|k| k.key.contains("/o-"))
        .expect("the corpus must carry an organization-trail key");
    assert!(
        filter.allows(org.key),
        "organization trail key: {}",
        org.key
    );

    let prefixed = corpus::KEYS
        .iter()
        .find(|k| !k.key.starts_with("AWSLogs/") && k.key.contains("/AWSLogs/"))
        .expect("the corpus must carry a custom-prefix key");
    assert!(
        filter.allows(prefixed.key),
        "custom-prefix key: {}",
        prefixed.key
    );
}
