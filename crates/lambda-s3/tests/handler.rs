//! Integration tests for the S3 Lambda's composition: the init-once
//! guarantee (SHARED "Cold start and init-once") and a golden-payload run
//! of a real `S3EventDecoder` through the `Pipeline` to its destination.
//!
//! These build the same `Pipeline` the binary's `main` builds, but wire
//! `InMemoryStore`/`StaticConfigSource`/`RecordingSink` in place of the AWS
//! adapters so the whole path runs without AWS.

use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use cloudtrail_rs_core::config::RuleSet;
use cloudtrail_rs_core::config::{
    Behavior, ConfigStore, Destination, Observability, Processing, Rules, Settings, Source, Sqs,
};
use cloudtrail_rs_core::decode::s3::S3EventDecoder;
use cloudtrail_rs_core::filter::Engine;
use cloudtrail_rs_core::metrics::Metrics;
use cloudtrail_rs_core::model::VersionTag;
use cloudtrail_rs_core::pipeline::Pipeline;
use cloudtrail_rs_core::testing::{InMemoryStore, RecordingSink, StaticConfigSource};
use flate2::Compression;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;

const DROP_DECRYPT_RULES: &[u8] = b"version: 1.0.0\nrules:\n  - name: Drop Decrypt\n    matches:\n      - field_name: eventName\n        regex: \"^Decrypt$\"\n";

fn gzip(body: &[u8]) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::new(6));
    e.write_all(body).unwrap();
    e.finish().unwrap()
}

fn gunzip(input: &[u8]) -> Vec<u8> {
    let mut d = MultiGzDecoder::new(input);
    let mut out = Vec::new();
    d.read_to_end(&mut out).unwrap();
    out
}

fn settings() -> Settings {
    Settings {
        source: Source::default(),
        destination: Destination {
            bucket: "dest-bucket".to_string(),
            key_prefix: String::new(),
        },
        processing: Processing::default(),
        behavior: Behavior::default(),
        sqs: Sqs::default(),
        rules: Rules::default(),
        observability: Observability::default(),
    }
}

/// A real S3 notification pointing at `src-bucket/logs/test.json.gz`.
fn s3_payload() -> Vec<u8> {
    br#"{"Records":[{"s3":{"bucket":{"name":"src-bucket"},"object":{"key":"logs/test.json.gz","size":64}}}]}"#.to_vec()
}

/// The deliverable init-once test: three `handle` invocations against one
/// `Pipeline` must compile the ruleset exactly once (in `prime`) and fetch
/// config exactly once. A regression that moves compilation into the
/// per-invocation path makes this fail. `Compile<T>`'s injected closure is
/// what makes the count observable (SHARED task-16 rationale).
#[tokio::test]
async fn ruleset_compiles_once_across_three_invocations() {
    let compiles = Arc::new(AtomicUsize::new(0));
    let compiles_in_fn = compiles.clone();
    let compile = Arc::new(move |b: &[u8]| {
        compiles_in_fn.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(Engine::new(RuleSet::parse(b)?)?))
    });

    let src = Arc::new(StaticConfigSource::new(
        DROP_DECRYPT_RULES.to_vec(),
        VersionTag::Version(1),
    ));
    let metrics = Arc::new(Metrics::default());
    let cfg_store = Arc::new(ConfigStore::new(
        src.clone(),
        Duration::from_secs(300),
        compile,
        metrics.clone(),
    ));
    cfg_store.prime().await;

    let store = Arc::new(InMemoryStore::new());
    store.seed(
        "src-bucket",
        "logs/test.json.gz",
        gzip(br#"{"Records":[{"eventName":"ConsoleLogin"}]}"#),
    );
    let pipeline = Pipeline::new(
        Arc::new(settings()),
        Arc::new(S3EventDecoder::new()),
        store,
        cfg_store,
        metrics,
        Arc::new(RecordingSink::new()),
    );

    let payload = s3_payload();
    for _ in 0..3 {
        pipeline
            .handle(&payload)
            .await
            .expect("handle must succeed");
    }

    assert_eq!(
        compiles.load(Ordering::SeqCst),
        1,
        "ruleset must compile exactly once (in prime), not per invocation"
    );
    assert_eq!(
        src.fetch_calls(),
        1,
        "config must be fetched exactly once (by prime)"
    );
}

/// Golden-payload handler test: a real `S3EventDecoder` drives a two-record
/// object through the pipeline; the dropped record is gone and the survivor
/// is written verbatim to the destination key.
#[tokio::test]
async fn golden_s3_payload_filters_and_writes_survivors() {
    let src = Arc::new(StaticConfigSource::new(
        DROP_DECRYPT_RULES.to_vec(),
        VersionTag::Version(1),
    ));
    let metrics = Arc::new(Metrics::default());
    let cfg_store = Arc::new(ConfigStore::new(
        src,
        Duration::from_secs(300),
        Arc::new(|b: &[u8]| Ok(Arc::new(Engine::new(RuleSet::parse(b)?)?))),
        metrics.clone(),
    ));
    cfg_store.prime().await;

    let store = Arc::new(InMemoryStore::new());
    store.seed(
        "src-bucket",
        "logs/test.json.gz",
        gzip(br#"{"Records":[{"eventName":"Decrypt"},{"eventName":"ConsoleLogin"}]}"#),
    );
    let pipeline = Pipeline::new(
        Arc::new(settings()),
        Arc::new(S3EventDecoder::new()),
        store.clone(),
        cfg_store,
        metrics,
        Arc::new(RecordingSink::new()),
    );

    pipeline
        .handle(&s3_payload())
        .await
        .expect("handle must succeed");

    let written = store
        .object("dest-bucket", "logs/test.json.gz")
        .expect("survivor object must be written to the destination");
    assert_eq!(
        gunzip(&written),
        br#"{"Records":[{"eventName":"ConsoleLogin"}]}"#
    );
}
