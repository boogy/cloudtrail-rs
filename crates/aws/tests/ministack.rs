//! Integration tests against a real MiniStack container (`docker-compose.test.yml`,
//! `ministackorg/ministack` on `:4566`), driving the **real** `S3ObjectStore` and
//! `SsmConfigSource` adapters through the full `Pipeline::handle` path: real S3
//! `GetObject`/`PutObject`/multipart, real SSM `GetParameter` for the ruleset.
//!
//! Every test is `#[ignore]` so `cargo test --workspace` skips this suite (it
//! must still *compile*, per SHARED.md); run it with the container up via
//! `cargo test --workspace -- --ignored`.
//!
//! Bring the container up with `docker compose -f docker-compose.test.yml up -d`.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use aws_config::{BehaviorVersion, Region, SdkConfig};
use aws_sdk_s3::config::Credentials as S3Credentials;
use aws_sdk_ssm::config::Credentials as SsmCredentials;
use aws_smithy_http_client::Builder as HttpClientBuilder;
use aws_smithy_http_client::tls::Provider;
use aws_smithy_http_client::tls::rustls_provider::CryptoMode;
use aws_smithy_runtime_api::client::http::SharedHttpClient;
use flate2::Compression;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;
use std::io::{Read, Write};

use cloudtrail_rs_aws::{S3ObjectStore, SsmConfigSource};
use cloudtrail_rs_core::config::rules::RuleSet;
use cloudtrail_rs_core::config::store::Compile;
use cloudtrail_rs_core::config::{
    Behavior, ConfigStore, Destination, Observability, Processing, Rules, Settings, Source, Sqs,
};
use cloudtrail_rs_core::decode::s3::S3EventDecoder;
use cloudtrail_rs_core::filter::Engine;
use cloudtrail_rs_core::metrics::{Metrics, NoopMetricsSink};
use cloudtrail_rs_core::pipeline::Pipeline;

const ENDPOINT: &str = "http://localhost:4566";
const SRC_BUCKET: &str = "ct-ministack-src";
const DEST_BUCKET: &str = "ct-ministack-dest";
const RULES_PARAM: &str = "/cloudtrail-rs-tests/rules";

/// The one HTTP client every SDK client in this test file is built with:
/// rustls terminated by the `ring` crypto provider (mirrors
/// `crates/aws/src/http_client.rs`, which is private to that crate).
fn ring_http_client() -> SharedHttpClient {
    HttpClientBuilder::new()
        .tls_provider(Provider::Rustls(CryptoMode::Ring))
        .build_https()
}

/// The `SdkConfig` every adapter under test is built from: static `test`/`test`
/// credentials, `us-east-1`, and MiniStack's endpoint.
fn ministack_sdk_config() -> SdkConfig {
    SdkConfig::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .endpoint_url(ENDPOINT)
        .build()
}

/// Builds a path-style S3 client directly (bypassing `S3ObjectStore::new`,
/// which builds a virtual-hosted-style client suited to real AWS).
/// `S3ObjectStore::from_client` accepts an already-built client for exactly
/// this reason — see the report for why this doesn't require touching
/// `crates/aws/src/`.
fn s3_client(conf: &SdkConfig) -> aws_sdk_s3::Client {
    let s3_conf = aws_sdk_s3::config::Builder::from(conf)
        .credentials_provider(S3Credentials::new(
            "test",
            "test",
            None,
            None,
            "ministack-test",
        ))
        .http_client(ring_http_client())
        .force_path_style(true)
        .build();
    aws_sdk_s3::Client::from_conf(s3_conf)
}

/// A plain SSM client for test setup (writing the ruleset parameter).
/// `SsmConfigSource::new`/`from_client` cover reading it in the pipeline
/// itself.
fn ssm_client(conf: &SdkConfig) -> aws_sdk_ssm::Client {
    let ssm_conf = aws_sdk_ssm::config::Builder::from(conf)
        .credentials_provider(SsmCredentials::new(
            "test",
            "test",
            None,
            None,
            "ministack-test",
        ))
        .http_client(ring_http_client())
        .build();
    aws_sdk_ssm::Client::from_conf(ssm_conf)
}

/// Creates `bucket` if it does not already exist — idempotent so the suite
/// is self-contained given only a bare MiniStack.
async fn ensure_bucket(client: &aws_sdk_s3::Client, bucket: &str) {
    use aws_sdk_s3::operation::create_bucket::CreateBucketError;

    match client.create_bucket().bucket(bucket).send().await {
        Ok(_) => {}
        Err(err) => match err.into_service_error() {
            CreateBucketError::BucketAlreadyOwnedByYou(_) => {}
            CreateBucketError::BucketAlreadyExists(_) => {}
            #[allow(deprecated)]
            other => panic!("create_bucket({bucket}) failed: {other:?}"),
        },
    }
}

/// Writes (or overwrites) the ruleset SSM parameter used by the pipeline's
/// `SsmConfigSource`.
async fn ensure_rules_param(client: &aws_sdk_ssm::Client, name: &str, value: &str) {
    client
        .put_parameter()
        .name(name)
        .value(value)
        .r#type(aws_sdk_ssm::types::ParameterType::String)
        .overwrite(true)
        .send()
        .await
        .unwrap_or_else(|e| panic!("put_parameter({name}) failed: {e:?}"));
}

/// The ruleset used by every test in this file: drops any record whose
/// `eventName` is exactly `Decrypt`.
const DROP_DECRYPT_RULES: &str = r#"
version: 1.0.0
rules:
  - name: Drop Decrypt
    matches:
      - field_name: eventName
        regex: "^Decrypt$"
"#;

fn compile_engine() -> Compile<Arc<Engine>> {
    Arc::new(|b: &[u8]| Ok(Arc::new(Engine::new(RuleSet::parse(b)?)?)))
}

fn gzip_bytes(body: &[u8], level: u32) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(level));
    encoder.write_all(body).unwrap();
    encoder.finish().unwrap()
}

fn gunzip(input: &[u8]) -> Vec<u8> {
    let mut decoder = MultiGzDecoder::new(input);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).unwrap();
    out
}

/// One CloudTrail-shaped record. `idx` gives each record distinct content so
/// gzip cannot compress the large-object fixture down to a handful of bytes.
fn record_json(idx: usize, event_name: &str) -> String {
    format!(
        r#"{{"eventName":"{event_name}","eventSource":"signin.amazonaws.com","eventID":"{idx:010}"}}"#
    )
}

/// Builds a `{"Records":[...]}` body of `count` records, every fifth one
/// `Decrypt` (dropped by `DROP_DECRYPT_RULES`), the rest `ConsoleLogin`
/// (kept). Returns the body bytes plus the expected survivor body — computed
/// the same way `buffer_run`/`stream_run` build it (raw slices joined by
/// `,`), so the comparison is exact, not a re-parse.
fn cloudtrail_body(count: usize) -> (Vec<u8>, Vec<u8>) {
    let mut records = Vec::with_capacity(count);
    let mut survivors = Vec::new();
    for i in 0..count {
        let name = if i % 5 == 0 {
            "Decrypt"
        } else {
            "ConsoleLogin"
        };
        let record = record_json(i, name);
        if name != "Decrypt" {
            survivors.push(record.clone());
        }
        records.push(record);
    }
    let body = format!(r#"{{"Records":[{}]}}"#, records.join(","));
    let expected = format!(r#"{{"Records":[{}]}}"#, survivors.join(","));
    (body.into_bytes(), expected.into_bytes())
}

/// The S3 bucket-notification JSON payload `S3EventDecoder` expects, naming
/// exactly one object. `size` drives `Pipeline`'s auto buffer/stream
/// decision (`SHARED.md` safety invariant 5) — it need not equal the
/// object's real byte count (S3 always sends the true size; here we control
/// it directly to deterministically select a processing mode).
fn s3_event_payload(bucket: &str, key: &str, size: u64) -> Vec<u8> {
    format!(
        r#"{{"Records":[{{"s3":{{"bucket":{{"name":"{bucket}"}},"object":{{"key":"{key}","size":{size}}}}}}}]}}"#
    )
    .into_bytes()
}

fn base_settings(dest_bucket: &str, rules_uri: String) -> Settings {
    Settings {
        source: Source::default(),
        destination: Destination {
            bucket: dest_bucket.to_string(),
            key_prefix: String::new(),
        },
        processing: Processing::default(),
        behavior: Behavior::default(),
        sqs: Sqs::default(),
        rules: Rules {
            uri: rules_uri,
            ttl_seconds: 300,
        },
        observability: Observability::default(),
    }
}

#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn small_object_buffer_mode_round_trips_through_real_s3_and_ssm() {
    let conf = ministack_sdk_config();
    let s3 = s3_client(&conf);
    let ssm = ssm_client(&conf);

    ensure_bucket(&s3, SRC_BUCKET).await;
    ensure_bucket(&s3, DEST_BUCKET).await;
    ensure_rules_param(&ssm, RULES_PARAM, DROP_DECRYPT_RULES).await;

    let key = "ministack-tests/buffer/cloudtrail.json.gz";
    let (body, expected_body) = cloudtrail_body(20);
    let gzipped = gzip_bytes(&body, 6);

    s3.put_object()
        .bucket(SRC_BUCKET)
        .key(key)
        .body(gzipped.clone().into())
        .send()
        .await
        .expect("seed source object");

    let settings = Arc::new(base_settings(DEST_BUCKET, format!("ssm://{RULES_PARAM}")));
    let decoder = Arc::new(S3EventDecoder::new());
    let store = Arc::new(S3ObjectStore::from_client(s3.clone()));
    let config_source = Arc::new(SsmConfigSource::from_client(ssm.clone(), RULES_PARAM));
    let metrics = Arc::new(Metrics::default());
    let sink = Arc::new(NoopMetricsSink);
    let cfg_store = Arc::new(ConfigStore::new(
        config_source,
        Duration::from_secs(300),
        compile_engine(),
        metrics.clone(),
    ));
    cfg_store.prime().await;

    let pipeline = Pipeline::new(settings, decoder, store, cfg_store, metrics, sink);

    // Well under the default 8 MiB stream_threshold_bytes: auto mode must
    // pick buffer.
    let payload = s3_event_payload(SRC_BUCKET, key, gzipped.len() as u64);
    let outcome = pipeline
        .handle(&payload)
        .await
        .expect("pipeline.handle must succeed");
    assert!(outcome.failed_ack_ids.is_empty());

    let written = s3
        .get_object()
        .bucket(DEST_BUCKET)
        .key(key)
        .send()
        .await
        .expect("destination object must exist")
        .body
        .collect()
        .await
        .expect("reading destination body")
        .into_bytes();

    assert_eq!(
        gunzip(&written),
        expected_body,
        "destination bytes must decompress to exactly the surviving Records"
    );
}

#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn large_object_stream_mode_uses_real_multipart_upload() {
    let conf = ministack_sdk_config();
    let s3 = s3_client(&conf);
    let ssm = ssm_client(&conf);

    ensure_bucket(&s3, SRC_BUCKET).await;
    ensure_bucket(&s3, DEST_BUCKET).await;
    ensure_rules_param(&ssm, RULES_PARAM, DROP_DECRYPT_RULES).await;

    let key = "ministack-tests/stream/cloudtrail-large.json.gz";
    // 20_000 distinct records defeats gzip's redundancy compression enough
    // to comfortably clear the lowered stream_threshold_bytes below with a
    // real object, not a fabricated size.
    let (body, expected_body) = cloudtrail_body(20_000);
    let gzipped = gzip_bytes(&body, 6);

    s3.put_object()
        .bucket(SRC_BUCKET)
        .key(key)
        .body(gzipped.clone().into())
        .send()
        .await
        .expect("seed source object");

    let mut settings = base_settings(DEST_BUCKET, format!("ssm://{RULES_PARAM}"));
    // Lowered so the real (compressed) object size above deterministically
    // selects stream mode under `auto`, and so the compressed *output*
    // splits into several real multipart parts instead of just one.
    // MiniStack, unlike real S3, does not enforce the 5 MiB minimum
    // non-final part size, which is what makes a modestly-sized fixture
    // sufficient to exercise genuine multipart upload/complete here.
    settings.processing.stream_threshold_bytes = 50_000;
    let settings = Arc::new(settings);

    let decoder = Arc::new(S3EventDecoder::new());
    let store = Arc::new(S3ObjectStore::from_client(s3.clone()).with_multipart_part_bytes(65_536));
    let config_source = Arc::new(SsmConfigSource::from_client(ssm.clone(), RULES_PARAM));
    let metrics = Arc::new(Metrics::default());
    let sink = Arc::new(NoopMetricsSink);
    let cfg_store = Arc::new(ConfigStore::new(
        config_source,
        Duration::from_secs(300),
        compile_engine(),
        metrics.clone(),
    ));
    cfg_store.prime().await;

    let pipeline = Pipeline::new(settings, decoder, store, cfg_store, metrics, sink);

    let payload = s3_event_payload(SRC_BUCKET, key, gzipped.len() as u64);
    let outcome = pipeline
        .handle(&payload)
        .await
        .expect("pipeline.handle must succeed");
    assert!(outcome.failed_ack_ids.is_empty());

    let written = s3
        .get_object()
        .bucket(DEST_BUCKET)
        .key(key)
        .send()
        .await
        .expect("destination object must exist")
        .body
        .collect()
        .await
        .expect("reading destination body")
        .into_bytes();

    assert_eq!(
        gunzip(&written),
        expected_body,
        "destination bytes must decompress to exactly the surviving Records"
    );
}
