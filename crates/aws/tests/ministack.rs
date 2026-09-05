//! Integration tests against a real MiniStack container, driving the **real**
//! `S3ObjectStore` and `SsmConfigSource` adapters through `Pipeline::handle`.
//!
//! Every test is `#[ignore]` so `cargo test --workspace` skips this suite (it
//! must still compile). Bring the container up with
//! `docker compose -f docker-compose.test.yml up -d`, then run
//! `cargo test --workspace -- --ignored`.

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
use cloudtrail_rs_core::error::StoreError;
use cloudtrail_rs_core::filter::Engine;
use cloudtrail_rs_core::filter::engine::Decision;
use cloudtrail_rs_core::metrics::{Metrics, NoopMetricsSink};
use cloudtrail_rs_core::model::PutMeta;
use cloudtrail_rs_core::pipeline::Pipeline;
use cloudtrail_rs_core::ports::ConfigSource;
use cloudtrail_rs_core::ports::ObjectStore;

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

/// A path-style S3 client, bypassing `S3ObjectStore::new`'s virtual-hosted-style
/// one. `from_client` exists so tests can substitute this without production
/// code learning about test endpoints.
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
/// exactly one object. `size` drives the auto buffer/stream decision; real S3
/// always sends the true size, here it is set explicitly to select a mode.
fn s3_event_payload(bucket: &str, key: &str, size: u64) -> Vec<u8> {
    s3_event_payload_many(bucket, &[(key, size)])
}

fn s3_event_payload_many(bucket: &str, objects: &[(&str, u64)]) -> Vec<u8> {
    let records: Vec<String> = objects
        .iter()
        .map(|(key, size)| {
            format!(
                r#"{{"s3":{{"bucket":{{"name":"{bucket}"}},"object":{{"key":"{key}","size":{size}}}}}}}"#
            )
        })
        .collect();
    format!(r#"{{"Records":[{}]}}"#, records.join(",")).into_bytes()
}

/// Every port wired to the real MiniStack adapters, so a test only has to
/// supply the `Settings` under examination.
async fn ministack_pipeline(
    s3: &aws_sdk_s3::Client,
    ssm: &aws_sdk_ssm::Client,
    settings: Settings,
) -> Pipeline {
    let metrics = Arc::new(Metrics::default());
    let cfg_store = Arc::new(ConfigStore::new(
        Arc::new(SsmConfigSource::from_client(ssm.clone(), RULES_PARAM)),
        Duration::from_secs(300),
        compile_engine(),
        metrics.clone(),
    ));
    cfg_store.prime().await;
    Pipeline::new(
        Arc::new(settings),
        Arc::new(S3EventDecoder::new()),
        Arc::new(S3ObjectStore::from_client(s3.clone())),
        cfg_store,
        metrics,
        Arc::new(NoopMetricsSink),
    )
}

async fn dest_bytes(s3: &aws_sdk_s3::Client, key: &str) -> Vec<u8> {
    s3.get_object()
        .bucket(DEST_BUCKET)
        .key(key)
        .send()
        .await
        .expect("destination object must exist")
        .body
        .collect()
        .await
        .expect("reading destination body")
        .into_bytes()
        .to_vec()
}

/// The destination object's ETag. A multipart-written object's ends in
/// `-<part count>`; a `PutObject`-written one is a bare MD5.
async fn dest_etag(s3: &aws_sdk_s3::Client, key: &str) -> String {
    s3.head_object()
        .bucket(DEST_BUCKET)
        .key(key)
        .send()
        .await
        .expect("destination object must exist")
        .e_tag()
        .expect("HeadObject response must carry an ETag")
        .to_string()
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
    // Distinct records defeat gzip's redundancy compression enough to clear the
    // lowered stream_threshold_bytes with a real object, not a fabricated size.
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
    // Lowered so the real compressed size selects stream mode under `auto` and
    // the output splits into several real multipart parts. MiniStack does not
    // enforce S3's 5 MiB minimum non-final part size, so a modest fixture is
    // enough to exercise a genuine multipart upload.
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

#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn chunked_gzip_survives_a_real_s3_round_trip() {
    let conf = ministack_sdk_config();
    let s3 = s3_client(&conf);
    let ssm = ssm_client(&conf);

    ensure_bucket(&s3, SRC_BUCKET).await;
    ensure_bucket(&s3, DEST_BUCKET).await;
    ensure_rules_param(&ssm, RULES_PARAM, DROP_DECRYPT_RULES).await;

    // Comfortably over 4 x MIN_CHUNK_BYTES (64 KiB), so `gzip_chunks: 4`
    // really emits four members rather than collapsing to one.
    let (body, expected_body) = cloudtrail_body(12_000);
    assert!(body.len() > 4 * 64 * 1024);
    let gzipped = gzip_bytes(&body, 6);

    let mut written = Vec::new();
    for chunks in [1usize, 4] {
        let key = format!("ministack-tests/chunks-{chunks}/cloudtrail.json.gz");
        s3.put_object()
            .bucket(SRC_BUCKET)
            .key(&key)
            .body(gzipped.clone().into())
            .send()
            .await
            .expect("seed source object");

        let mut settings = base_settings(DEST_BUCKET, format!("ssm://{RULES_PARAM}"));
        settings.processing.gzip_chunks = chunks;
        // Force buffer mode: `gzip_chunks` is a buffer-mode setting.
        settings.processing.mode = cloudtrail_rs_core::config::ProcessingMode::Buffer;
        let pipeline = ministack_pipeline(&s3, &ssm, settings).await;

        let payload = s3_event_payload(SRC_BUCKET, &key, gzipped.len() as u64);
        let outcome = pipeline
            .handle(&payload)
            .await
            .expect("pipeline.handle must succeed");
        assert!(outcome.failed_ack_ids.is_empty());

        let bytes = dest_bytes(&s3, &key).await;
        assert_eq!(
            gunzip(&bytes),
            expected_body,
            "chunks={chunks} must decompress to exactly the surviving Records"
        );
        written.push(bytes);
    }

    assert_ne!(
        written[0], written[1],
        "gzip_chunks: 4 must actually change the framing"
    );
}

#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn concurrent_objects_all_land_correctly_in_real_s3() {
    let conf = ministack_sdk_config();
    let s3 = s3_client(&conf);
    let ssm = ssm_client(&conf);

    ensure_bucket(&s3, SRC_BUCKET).await;
    ensure_bucket(&s3, DEST_BUCKET).await;
    ensure_rules_param(&ssm, RULES_PARAM, DROP_DECRYPT_RULES).await;

    let (body, expected_body) = cloudtrail_body(40);
    let gzipped = gzip_bytes(&body, 6);
    let keys: Vec<String> = (0..8)
        .map(|i| format!("ministack-tests/concurrent/obj-{i}.json.gz"))
        .collect();
    for key in &keys {
        s3.put_object()
            .bucket(SRC_BUCKET)
            .key(key)
            .body(gzipped.clone().into())
            .send()
            .await
            .expect("seed source object");
    }

    let mut settings = base_settings(DEST_BUCKET, format!("ssm://{RULES_PARAM}"));
    settings.processing.object_concurrency = 4;
    let pipeline = ministack_pipeline(&s3, &ssm, settings).await;

    let objects: Vec<(&str, u64)> = keys
        .iter()
        .map(|k| (k.as_str(), gzipped.len() as u64))
        .collect();
    let outcome = pipeline
        .handle(&s3_event_payload_many(SRC_BUCKET, &objects))
        .await
        .expect("pipeline.handle must succeed");
    assert!(outcome.failed_ack_ids.is_empty());

    for key in &keys {
        assert_eq!(
            gunzip(&dest_bytes(&s3, key).await),
            expected_body,
            "{key} must decompress to exactly the surviving Records"
        );
    }
}

/// Wraps the real `S3ObjectStore` and cuts the first `get_stream` body short,
/// standing in for the connection reset or throttle that ends a real
/// `GetObject` part-way through. Every other call is passed straight through.
struct ResetFirstGetStream {
    inner: S3ObjectStore,
    reset: std::sync::atomic::AtomicBool,
}

impl ResetFirstGetStream {
    fn new(inner: S3ObjectStore) -> Self {
        Self {
            inner,
            reset: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

/// Yields `prefix`, then fails instead of reporting EOF.
struct ResettingReader {
    prefix: std::io::Cursor<Vec<u8>>,
}

impl tokio::io::AsyncRead for ResettingReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let remaining = self.prefix.get_ref().len() - self.prefix.position() as usize;
        if remaining == 0 {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "connection reset by peer",
            )));
        }
        let take = remaining.min(buf.remaining());
        let start = self.prefix.position() as usize;
        let chunk = self.prefix.get_ref()[start..start + take].to_vec();
        self.prefix.set_position((start + take) as u64);
        buf.put_slice(&chunk);
        std::task::Poll::Ready(Ok(()))
    }
}

#[async_trait::async_trait]
impl ObjectStore for ResetFirstGetStream {
    async fn get(&self, b: &str, k: &str) -> Result<bytes::Bytes, StoreError> {
        self.inner.get(b, k).await
    }

    async fn get_stream(
        &self,
        b: &str,
        k: &str,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, StoreError> {
        let reader = self.inner.get_stream(b, k).await?;
        if self.reset.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return Ok(reader);
        }
        let mut all = Vec::new();
        let mut reader = reader;
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut all)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        all.truncate(all.len() / 2);
        Ok(Box::new(ResettingReader {
            prefix: std::io::Cursor::new(all),
        }))
    }

    async fn put(
        &self,
        b: &str,
        k: &str,
        body: bytes::Bytes,
        meta: PutMeta,
    ) -> Result<(), StoreError> {
        self.inner.put(b, k, body, meta).await
    }

    async fn put_stream(
        &self,
        b: &str,
        k: &str,
        body: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        meta: PutMeta,
    ) -> Result<(), StoreError> {
        self.inner.put_stream(b, k, body, meta).await
    }
}

async fn dest_missing(s3: &aws_sdk_s3::Client, key: &str) -> bool {
    s3.head_object()
        .bucket(DEST_BUCKET)
        .key(key)
        .send()
        .await
        .is_err()
}

/// Falsifiable: classify the reset as `CoreError::Gzip` and `on_parse_error:
/// copy` fails open, landing the full unfiltered source — `Decrypt` included —
/// in the destination bucket.
#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn a_reset_mid_body_never_fails_open_against_real_s3() {
    let conf = ministack_sdk_config();
    let s3 = s3_client(&conf);
    let ssm = ssm_client(&conf);

    ensure_bucket(&s3, SRC_BUCKET).await;
    ensure_bucket(&s3, DEST_BUCKET).await;
    ensure_rules_param(&ssm, RULES_PARAM, DROP_DECRYPT_RULES).await;

    let key = "ministack-tests/reset/cloudtrail.json.gz";
    let (body, _) = cloudtrail_body(20_000);
    let gzipped = gzip_bytes(&body, 6);

    s3.put_object()
        .bucket(SRC_BUCKET)
        .key(key)
        .body(gzipped.clone().into())
        .send()
        .await
        .expect("seed source object");
    let _ = s3.delete_object().bucket(DEST_BUCKET).key(key).send().await;

    let mut settings = base_settings(DEST_BUCKET, format!("ssm://{RULES_PARAM}"));
    settings.processing.stream_threshold_bytes = 50_000;
    settings.behavior.on_parse_error = cloudtrail_rs_core::config::OnParseError::Copy;

    let metrics = Arc::new(Metrics::default());
    let cfg_store = Arc::new(ConfigStore::new(
        Arc::new(SsmConfigSource::from_client(ssm.clone(), RULES_PARAM)),
        Duration::from_secs(300),
        compile_engine(),
        metrics.clone(),
    ));
    cfg_store.prime().await;
    let pipeline = Pipeline::new(
        Arc::new(settings),
        Arc::new(S3EventDecoder::new()),
        Arc::new(ResetFirstGetStream::new(S3ObjectStore::from_client(
            s3.clone(),
        ))),
        cfg_store,
        metrics.clone(),
        Arc::new(NoopMetricsSink),
    );

    let payload = s3_event_payload(SRC_BUCKET, key, gzipped.len() as u64);
    let outcome = pipeline.handle(&payload).await;
    let failed = match outcome {
        Ok(o) => !o.failed_ack_ids.is_empty(),
        Err(_) => true,
    };
    assert!(
        failed,
        "a reset mid-body must surface as a retryable failure"
    );
    assert!(
        dest_missing(&s3, key).await,
        "nothing may land at the destination for an object that never read fully"
    );
    assert_eq!(
        metrics.snapshot_and_reset().objects_copied_unparsed,
        0,
        "a transport failure is not a parse failure"
    );
}

/// The other half of the same policy: a source object that really is corrupt
/// must still be forwarded verbatim.
#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn a_genuinely_corrupt_object_still_fails_open_through_real_s3() {
    let conf = ministack_sdk_config();
    let s3 = s3_client(&conf);
    let ssm = ssm_client(&conf);

    ensure_bucket(&s3, SRC_BUCKET).await;
    ensure_bucket(&s3, DEST_BUCKET).await;
    ensure_rules_param(&ssm, RULES_PARAM, DROP_DECRYPT_RULES).await;

    let key = "ministack-tests/corrupt/cloudtrail.json.gz";
    let (body, _) = cloudtrail_body(20_000);
    let full = gzip_bytes(&body, 6);
    let corrupt = full[..full.len() / 2].to_vec();

    s3.put_object()
        .bucket(SRC_BUCKET)
        .key(key)
        .body(corrupt.clone().into())
        .send()
        .await
        .expect("seed source object");
    let _ = s3.delete_object().bucket(DEST_BUCKET).key(key).send().await;

    let mut settings = base_settings(DEST_BUCKET, format!("ssm://{RULES_PARAM}"));
    settings.processing.stream_threshold_bytes = 50_000;
    settings.behavior.on_parse_error = cloudtrail_rs_core::config::OnParseError::Copy;
    let pipeline = ministack_pipeline(&s3, &ssm, settings).await;

    let payload = s3_event_payload(SRC_BUCKET, key, corrupt.len() as u64);
    let outcome = pipeline
        .handle(&payload)
        .await
        .expect("on_parse_error: copy must absorb a corrupt object");
    assert!(outcome.failed_ack_ids.is_empty());

    assert_eq!(
        dest_bytes(&s3, key).await,
        corrupt,
        "the copy must be the source bytes verbatim"
    );
}

/// A 0-byte source object is the one input multipart cannot express: the
/// fail-open copy must still land it, not fail the invocation.
#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn an_empty_source_object_fails_open_to_a_zero_byte_destination_object() {
    use cloudtrail_rs_core::config::ProcessingMode;

    let conf = ministack_sdk_config();
    let s3 = s3_client(&conf);
    let ssm = ssm_client(&conf);

    ensure_bucket(&s3, SRC_BUCKET).await;
    ensure_bucket(&s3, DEST_BUCKET).await;
    ensure_rules_param(&ssm, RULES_PARAM, DROP_DECRYPT_RULES).await;

    let key = "ministack-tests/empty/cloudtrail.json.gz";
    s3.put_object()
        .bucket(SRC_BUCKET)
        .key(key)
        .body(Vec::new().into())
        .send()
        .await
        .expect("seed empty source object");
    let _ = s3.delete_object().bucket(DEST_BUCKET).key(key).send().await;

    for mode in [ProcessingMode::Buffer, ProcessingMode::Stream] {
        let _ = s3.delete_object().bucket(DEST_BUCKET).key(key).send().await;

        let mut settings = base_settings(DEST_BUCKET, format!("ssm://{RULES_PARAM}"));
        settings.processing.mode = mode;
        settings.behavior.on_parse_error = cloudtrail_rs_core::config::OnParseError::Copy;
        let pipeline = ministack_pipeline(&s3, &ssm, settings).await;

        let payload = s3_event_payload(SRC_BUCKET, key, 0);
        let outcome = pipeline
            .handle(&payload)
            .await
            .unwrap_or_else(|e| panic!("{mode:?}: copy must absorb an empty object: {e:?}"));
        assert!(outcome.failed_ack_ids.is_empty(), "{mode:?}");

        assert!(
            dest_bytes(&s3, key).await.is_empty(),
            "{mode:?}: the copy of an empty source must be an empty destination object"
        );
        // Emptiness alone cannot fail: MiniStack, unlike real S3, accepts a
        // zero-part CompleteMultipartUpload and lands a 0-byte object for it.
        // Its ETag carries the `-0` part-count suffix, so only the absence of
        // a suffix proves `PutObject` — the fix — wrote this object.
        let etag = dest_etag(&s3, key).await;
        assert!(
            !etag.trim_matches('"').contains('-'),
            "{mode:?}: destination ETag {etag} has a multipart suffix, so multipart wrote it"
        );
    }
}

/// Realistic CloudTrail records — the shapes `testing::corpus` keeps verbatim —
/// through real S3 in both modes, which must agree byte for byte after
/// decompression.
#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn the_realistic_corpus_round_trips_identically_in_both_modes() {
    use cloudtrail_rs_core::config::ProcessingMode;
    use cloudtrail_rs_core::testing::corpus;

    let conf = ministack_sdk_config();
    let s3 = s3_client(&conf);
    let ssm = ssm_client(&conf);

    ensure_bucket(&s3, SRC_BUCKET).await;
    ensure_bucket(&s3, DEST_BUCKET).await;
    ensure_rules_param(&ssm, RULES_PARAM, DROP_DECRYPT_RULES).await;

    let bodies = corpus::scale_records(4_000);
    let body = corpus::envelope_of(&bodies).into_bytes();
    let survivors: Vec<&String> = bodies
        .iter()
        .filter(|r| !r.contains(r#""eventName":"Decrypt""#))
        .collect();
    assert!(
        !survivors.is_empty() && survivors.len() < bodies.len(),
        "the corpus must contain both kept and dropped records"
    );
    let expected = corpus::envelope_of(&survivors).into_bytes();
    let gzipped = gzip_bytes(&body, 6);
    assert!(gzipped.len() > 50_000, "fixture must clear the threshold");

    let mut written = Vec::new();
    for mode in [ProcessingMode::Buffer, ProcessingMode::Stream] {
        let key = format!("ministack-tests/corpus-{mode:?}/cloudtrail.json.gz");
        s3.put_object()
            .bucket(SRC_BUCKET)
            .key(&key)
            .body(gzipped.clone().into())
            .send()
            .await
            .expect("seed source object");

        let mut settings = base_settings(DEST_BUCKET, format!("ssm://{RULES_PARAM}"));
        settings.processing.mode = mode;
        settings.processing.stream_threshold_bytes = 50_000;
        let pipeline = ministack_pipeline(&s3, &ssm, settings).await;

        let payload = s3_event_payload(SRC_BUCKET, &key, gzipped.len() as u64);
        let outcome = pipeline
            .handle(&payload)
            .await
            .expect("pipeline.handle must succeed");
        assert!(outcome.failed_ack_ids.is_empty());

        let got = gunzip(&dest_bytes(&s3, &key).await);
        assert_eq!(got, expected, "{mode:?} must emit exactly the survivors");
        written.push(got);
    }

    assert_eq!(written[0], written[1]);
}

// ---- SSM ---------------------------------------------------------------

const SECURE_PARAM: &str = "/cloudtrail-rs-tests/secure-rules";
const RELOAD_PARAM: &str = "/cloudtrail-rs-tests/reload-rules";

const DROP_CONSOLE_LOGIN_RULES: &str = r#"
version: 1.0.0
rules:
  - name: Drop ConsoleLogin
    matches:
      - field_name: eventName
        regex: "^ConsoleLogin$"
"#;

async fn put_secure(client: &aws_sdk_ssm::Client, name: &str, value: &str) -> i64 {
    client
        .put_parameter()
        .name(name)
        .value(value)
        .r#type(aws_sdk_ssm::types::ParameterType::SecureString)
        .overwrite(true)
        .send()
        .await
        .unwrap_or_else(|e| panic!("put_parameter({name}) failed: {e:?}"))
        .version()
}

fn drops(engine: &Engine, event_name: &str) -> bool {
    let decision = engine
        .evaluate_raw(&record_json(0, event_name))
        .expect("the fixture record is valid JSON");
    !matches!(decision, Decision::Keep)
}

/// Falsifiable: read without `with_decryption`, a `SecureString` comes back as
/// its ciphertext blob, which is not a ruleset and does not parse.
#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn a_secure_string_ruleset_is_decrypted_before_it_is_parsed() {
    let conf = ministack_sdk_config();
    let ssm = ssm_client(&conf);
    put_secure(&ssm, SECURE_PARAM, DROP_DECRYPT_RULES).await;

    let src = SsmConfigSource::from_client(ssm, SECURE_PARAM);
    let (bytes, _) = src.fetch().await.expect("fetching a SecureString");

    let rules = RuleSet::parse(&bytes).expect("an undecrypted parameter would not parse");
    let engine = Engine::new(rules).expect("compiling the decrypted ruleset");
    assert!(drops(&engine, "Decrypt"));
}

/// Falsifiable: `ConfigStore::refresh` refetches only when the version tag
/// changes, so a source that reported a constant version would keep serving
/// the first ruleset for the life of the process.
#[tokio::test]
#[ignore = "requires MiniStack up on :4566 (docker-compose.test.yml); run with --ignored"]
async fn a_parameter_version_bump_reloads_the_ruleset() {
    let conf = ministack_sdk_config();
    let ssm = ssm_client(&conf);
    let first_version = put_secure(&ssm, RELOAD_PARAM, DROP_DECRYPT_RULES).await;

    let store = ConfigStore::new(
        Arc::new(SsmConfigSource::from_client(ssm.clone(), RELOAD_PARAM)),
        // Zero TTL: every `get` revalidates, so the test observes the version
        // check rather than the TTL clock.
        Duration::from_secs(0),
        compile_engine(),
        Arc::new(Metrics::default()),
    );
    store.prime().await;

    let before = store.get().await.expect("primed store must hold an engine");
    assert!(drops(&before, "Decrypt"));
    assert!(!drops(&before, "ConsoleLogin"));

    let second_version = put_secure(&ssm, RELOAD_PARAM, DROP_CONSOLE_LOGIN_RULES).await;
    assert_ne!(
        first_version, second_version,
        "SSM must bump the version on overwrite, or there is nothing to detect"
    );

    let after = store.get().await.expect("store must still hold an engine");
    assert!(drops(&after, "ConsoleLogin"));
    assert!(!drops(&after, "Decrypt"));
}
