//! Golden-payload integration test for the SNS Lambda: a real
//! `SnsEventDecoder` unwraps an S3 event from `.Records[].Sns.Message` and
//! drives it through the `Pipeline`, wired to in-memory doubles.

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use cloudtrail_rs_core::config::{
    Behavior, ConfigStore, Destination, Observability, Processing, RuleSet, Rules, Settings,
    Source, Sqs,
};
use cloudtrail_rs_core::decode::sns::SnsEventDecoder;
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
async fn golden_sns_payload_filters_and_writes_survivors() {
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
    // An S3 notification stringified into `.Records[].Sns.Message`.
    let payload = br#"{"Records":[{"Sns":{"Message":"{\"Records\":[{\"s3\":{\"bucket\":{\"name\":\"src-bucket\"},\"object\":{\"key\":\"logs/test.json.gz\",\"size\":64}}}]}"}}]}"#.to_vec();

    let pipeline = Pipeline::new(
        Arc::new(settings()),
        Arc::new(SnsEventDecoder::new()),
        store.clone(),
        cfg_store,
        metrics,
        Arc::new(RecordingSink::new()),
    );

    pipeline
        .handle(&payload)
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
