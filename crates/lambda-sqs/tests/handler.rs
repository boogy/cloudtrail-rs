//! Golden-payload integration test for the SQS Lambda: a real
//! `SqsEventDecoder` drives an S3-in-SQS message through the `Pipeline`,
//! wired to in-memory doubles in place of the AWS adapters.

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use cloudtrail_rs_core::config::{
    Behavior, ConfigStore, Destination, Observability, OnMissingObject, Processing, RuleSet, Rules,
    Settings, Source, Sqs,
};
use cloudtrail_rs_core::decode::sqs::SqsEventDecoder;
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

#[tokio::test]
async fn golden_sqs_payload_filters_and_writes_survivors() {
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
    // An S3 notification embedded in an SQS message body (the raw-S3 shape).
    let payload = br#"{"Records":[{"messageId":"m-1","body":"{\"Records\":[{\"s3\":{\"bucket\":{\"name\":\"src-bucket\"},\"object\":{\"key\":\"logs/test.json.gz\",\"size\":64}}}]}"}]}"#.to_vec();

    let pipeline = Pipeline::new(
        Arc::new(settings()),
        Arc::new(SqsEventDecoder::new(settings().sqs.body_format)),
        store.clone(),
        cfg_store,
        metrics,
        Arc::new(RecordingSink::new()),
    );

    let outcome = pipeline
        .handle(&payload)
        .await
        .expect("handle must succeed");
    assert!(
        outcome.failed_ack_ids.is_empty(),
        "the message must ack cleanly"
    );

    let written = store
        .object("dest-bucket", "logs/test.json.gz")
        .expect("survivor object must be written to the destination");
    assert_eq!(
        gunzip(&written),
        br#"{"Records":[{"eventName":"ConsoleLogin"}]}"#
    );
}

/// Fix 5(a): end-to-end proof that a missing object still reaches
/// `batchItemFailures` — the first message's referenced object was never
/// seeded in the store (`on_missing_object: error`), the second message's
/// object was. Only the first message's id may appear in `failed_ack_ids`,
/// and the second message's object must still land at the destination.
#[tokio::test]
async fn missing_object_fails_only_its_own_message_and_lets_the_sibling_through() {
    let src = Arc::new(StaticConfigSource::new(
        b"version: 1.0.0\nrules: []\n".to_vec(),
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
    // "logs/missing.json.gz" is deliberately not seeded.
    store.seed(
        "src-bucket",
        "logs/present.json.gz",
        gzip(br#"{"Records":[{"eventName":"ConsoleLogin"}]}"#),
    );

    let payload = br#"{"Records":[
        {"messageId":"m-missing","body":"{\"Records\":[{\"s3\":{\"bucket\":{\"name\":\"src-bucket\"},\"object\":{\"key\":\"logs/missing.json.gz\",\"size\":64}}}]}"},
        {"messageId":"m-present","body":"{\"Records\":[{\"s3\":{\"bucket\":{\"name\":\"src-bucket\"},\"object\":{\"key\":\"logs/present.json.gz\",\"size\":64}}}]}"}
    ]}"#.to_vec();

    let mut cfg = settings();
    cfg.behavior.on_missing_object = OnMissingObject::Error;
    cfg.behavior.partial_batch_failures = true;

    let pipeline = Pipeline::new(
        Arc::new(cfg.clone()),
        Arc::new(SqsEventDecoder::new(cfg.sqs.body_format)),
        store.clone(),
        cfg_store,
        metrics,
        Arc::new(RecordingSink::new()),
    );

    let outcome = pipeline
        .handle(&payload)
        .await
        .expect("partial_batch_failures=true must not fail the whole invocation");

    assert_eq!(outcome.failed_ack_ids, vec!["m-missing".to_string()]);
    assert!(
        store.contains("dest-bucket", "logs/present.json.gz"),
        "the sibling message's object must still have been written"
    );
}

/// Fix 5(b): end-to-end proof that an undecodable message body (Fix 1)
/// reaches `batchItemFailures` rather than being silently dropped and
/// acked clean.
/// A batch that decodes to zero messages would be acked whole; a payload
/// without `Records` is malformed, so the invocation must fail instead.
#[tokio::test]
async fn an_sqs_payload_without_records_fails_the_invocation_instead_of_acking_it() {
    let src = Arc::new(StaticConfigSource::new(
        b"version: 1.0.0\nrules: []\n".to_vec(),
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

    let cfg = settings();
    let pipeline = Pipeline::new(
        Arc::new(cfg.clone()),
        Arc::new(SqsEventDecoder::new(cfg.sqs.body_format)),
        Arc::new(InMemoryStore::new()),
        cfg_store,
        metrics,
        Arc::new(RecordingSink::new()),
    );

    let err = pipeline
        .handle(br#"{"Type":"Notification","Message":"not an SQS batch"}"#)
        .await
        .expect_err("a payload with no Records must not be a successful empty batch");
    assert!(
        err.to_string().contains("Records"),
        "the error must name the missing field, got: {err}"
    );
}

#[tokio::test]
async fn undecodable_message_body_fails_only_its_own_message() {
    let src = Arc::new(StaticConfigSource::new(
        b"version: 1.0.0\nrules: []\n".to_vec(),
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
        "logs/present.json.gz",
        gzip(br#"{"Records":[{"eventName":"ConsoleLogin"}]}"#),
    );

    let payload = br#"{"Records":[
        {"messageId":"m-garbage","body":"this is not json at all {{{"},
        {"messageId":"m-present","body":"{\"Records\":[{\"s3\":{\"bucket\":{\"name\":\"src-bucket\"},\"object\":{\"key\":\"logs/present.json.gz\",\"size\":64}}}]}"}
    ]}"#.to_vec();

    let cfg = settings();

    let pipeline = Pipeline::new(
        Arc::new(cfg.clone()),
        Arc::new(SqsEventDecoder::new(cfg.sqs.body_format)),
        store.clone(),
        cfg_store,
        metrics,
        Arc::new(RecordingSink::new()),
    );

    let outcome = pipeline
        .handle(&payload)
        .await
        .expect("partial_batch_failures=true must not fail the whole invocation");

    assert_eq!(outcome.failed_ack_ids, vec!["m-garbage".to_string()]);
    assert!(
        store.contains("dest-bucket", "logs/present.json.gz"),
        "the sibling message's object must still have been written"
    );
}
