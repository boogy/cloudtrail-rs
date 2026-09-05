//! Clients and idempotent setup helpers for a live MiniStack container
//! (`docker-compose.test.yml`, `ministackorg/ministack` on `:4566`).

use aws_config::{BehaviorVersion, Region, SdkConfig};
use aws_smithy_http_client::Builder as HttpClientBuilder;
use aws_smithy_http_client::tls::Provider;
use aws_smithy_http_client::tls::rustls_provider::CryptoMode;
use aws_smithy_runtime_api::client::http::SharedHttpClient;

/// MiniStack's endpoint. Addressed by IP, not `localhost`, on purpose: with a
/// bare-IP endpoint the S3 client falls back to path-style addressing on its
/// own, so tests never depend on `<bucket>.localhost` resolving — which works
/// on macOS but is not guaranteed on a Linux CI runner.
pub const ENDPOINT: &str = "http://127.0.0.1:4566";
pub const REGION: &str = "us-east-1";

/// The credentials MiniStack is configured with in `docker-compose.test.yml`.
pub const ACCESS_KEY: &str = "test";
pub const SECRET_KEY: &str = "test";

/// The one HTTP client every SDK client here is built with: rustls terminated
/// by `ring`, mirroring `cloudtrail_rs_aws::ring_http_client` so tests exercise
/// the same TLS stack the binaries ship with.
pub fn ring_http_client() -> SharedHttpClient {
    HttpClientBuilder::new()
        .tls_provider(Provider::Rustls(CryptoMode::Ring))
        .build_https()
}

/// The `SdkConfig` every adapter under test is built from.
pub fn sdk_config() -> SdkConfig {
    SdkConfig::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(REGION))
        .endpoint_url(ENDPOINT)
        .build()
}

/// A path-style S3 client. `S3ObjectStore::new` builds a virtual-hosted-style
/// client suited to real AWS; `from_client` exists so tests can substitute
/// this without production code learning about test endpoints.
pub fn s3_client() -> aws_sdk_s3::Client {
    let conf = aws_sdk_s3::config::Builder::from(&sdk_config())
        .credentials_provider(aws_sdk_s3::config::Credentials::new(
            ACCESS_KEY,
            SECRET_KEY,
            None,
            None,
            "ministack-test",
        ))
        .http_client(ring_http_client())
        .force_path_style(true)
        .build();
    aws_sdk_s3::Client::from_conf(conf)
}

/// An SSM client for test setup (writing the ruleset parameter).
pub fn ssm_client() -> aws_sdk_ssm::Client {
    let conf = aws_sdk_ssm::config::Builder::from(&sdk_config())
        .credentials_provider(aws_sdk_ssm::config::Credentials::new(
            ACCESS_KEY,
            SECRET_KEY,
            None,
            None,
            "ministack-test",
        ))
        .http_client(ring_http_client())
        .build();
    aws_sdk_ssm::Client::from_conf(conf)
}

/// The environment a real deployment sets on a Lambda, minus the variables
/// Lambda itself injects (`LambdaProcess::spawn` supplies those).
///
/// Callers append their own `CT_*` pairs; later entries win, because
/// `Command::env` overwrites.
pub fn lambda_env(dest_bucket: &str, rules_uri: &str) -> Vec<(&'static str, String)> {
    vec![
        ("AWS_ENDPOINT_URL", ENDPOINT.to_string()),
        ("AWS_REGION", REGION.to_string()),
        ("AWS_ACCESS_KEY_ID", ACCESS_KEY.to_string()),
        ("AWS_SECRET_ACCESS_KEY", SECRET_KEY.to_string()),
        // The region is set explicitly above, but without this an IMDS probe
        // against an unreachable 169.254.169.254 still costs the cold start
        // several seconds of connect timeout.
        ("AWS_EC2_METADATA_DISABLED", "true".to_string()),
        ("CT_DEST_BUCKET", dest_bucket.to_string()),
        ("CT_RULES_URI", rules_uri.to_string()),
        ("RUST_LOG", "info".to_string()),
    ]
}

/// Creates `bucket` if it does not already exist — idempotent, so the suite is
/// self-contained given only a bare MiniStack.
pub async fn ensure_bucket(client: &aws_sdk_s3::Client, bucket: &str) {
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

/// Writes (or overwrites) an SSM parameter.
pub async fn put_parameter(client: &aws_sdk_ssm::Client, name: &str, value: &str) {
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

/// Uploads `body` to `bucket`/`key`.
pub async fn put_object(client: &aws_sdk_s3::Client, bucket: &str, key: &str, body: Vec<u8>) {
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(body.into())
        .send()
        .await
        .unwrap_or_else(|e| panic!("put_object({bucket}/{key}) failed: {e:?}"));
}

/// Downloads `bucket`/`key`, panicking if it is absent.
pub async fn get_object(client: &aws_sdk_s3::Client, bucket: &str, key: &str) -> Vec<u8> {
    client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .unwrap_or_else(|e| panic!("get_object({bucket}/{key}) failed: {e:?}"))
        .body
        .collect()
        .await
        .expect("reading object body")
        .into_bytes()
        .to_vec()
}

/// Whether `bucket`/`key` exists. Used to assert the *absence* of an object,
/// e.g. that an aborted multipart upload left no orphan behind.
pub async fn object_exists(client: &aws_sdk_s3::Client, bucket: &str, key: &str) -> bool {
    client
        .head_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .is_ok()
}

/// Deletes `bucket`/`key` if present, so a rerun of the suite starts from a
/// known state rather than inheriting the previous run's output.
pub async fn delete_object(client: &aws_sdk_s3::Client, bucket: &str, key: &str) {
    let _ = client.delete_object().bucket(bucket).key(key).send().await;
}

/// Every key under `bucket`/`prefix`, following continuation tokens.
pub async fn list_keys(client: &aws_sdk_s3::Client, bucket: &str, prefix: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut token = None;
    loop {
        let out = client
            .list_objects_v2()
            .bucket(bucket)
            .prefix(prefix)
            .set_continuation_token(token)
            .send()
            .await
            .unwrap_or_else(|e| panic!("list_objects_v2({bucket}/{prefix}) failed: {e:?}"));
        keys.extend(
            out.contents()
                .iter()
                .filter_map(|o| o.key().map(str::to_string)),
        );
        token = out.next_continuation_token().map(str::to_string);
        if token.is_none() {
            break;
        }
    }
    keys
}

// ---- event-producing services -----------------------------------------
//
// MiniStack emits real S3 notifications into SQS, SNS and EventBridge, so a
// test can drive a Lambda with an event the stack produced rather than one the
// test hand-wrote. Two fidelity gaps bound what may be asserted on them:
// MiniStack emits object keys verbatim where real S3 form-urlencodes them, so
// keys in such tests must be encoding-neutral; and a received message is gone
// (no visibility timeout, no redelivery), so [`drain_queue`] never deletes.

/// An SQS client for test setup (queues, purging, draining).
pub fn sqs_client() -> aws_sdk_sqs::Client {
    let conf = aws_sdk_sqs::config::Builder::from(&sdk_config())
        .credentials_provider(aws_sdk_sqs::config::Credentials::new(
            ACCESS_KEY,
            SECRET_KEY,
            None,
            None,
            "ministack-test",
        ))
        .http_client(ring_http_client())
        .build();
    aws_sdk_sqs::Client::from_conf(conf)
}

/// An SNS client for test setup (topics, subscriptions).
pub fn sns_client() -> aws_sdk_sns::Client {
    let conf = aws_sdk_sns::config::Builder::from(&sdk_config())
        .credentials_provider(aws_sdk_sns::config::Credentials::new(
            ACCESS_KEY,
            SECRET_KEY,
            None,
            None,
            "ministack-test",
        ))
        .http_client(ring_http_client())
        .build();
    aws_sdk_sns::Client::from_conf(conf)
}

/// An EventBridge client for test setup (rules, targets).
pub fn eventbridge_client() -> aws_sdk_eventbridge::Client {
    let conf = aws_sdk_eventbridge::config::Builder::from(&sdk_config())
        .credentials_provider(aws_sdk_eventbridge::config::Credentials::new(
            ACCESS_KEY,
            SECRET_KEY,
            None,
            None,
            "ministack-test",
        ))
        .http_client(ring_http_client())
        .build();
    aws_sdk_eventbridge::Client::from_conf(conf)
}

/// Creates `name` if absent and returns its `(url, arn)`. Idempotent.
pub async fn ensure_queue(client: &aws_sdk_sqs::Client, name: &str) -> (String, String) {
    let url = client
        .create_queue()
        .queue_name(name)
        .send()
        .await
        .unwrap_or_else(|e| panic!("create_queue({name}) failed: {e:?}"))
        .queue_url()
        .expect("CreateQueue must return a URL")
        .to_string();

    let arn = client
        .get_queue_attributes()
        .queue_url(&url)
        .attribute_names(aws_sdk_sqs::types::QueueAttributeName::QueueArn)
        .send()
        .await
        .unwrap_or_else(|e| panic!("get_queue_attributes({name}) failed: {e:?}"))
        .attributes()
        .and_then(|a| a.get(&aws_sdk_sqs::types::QueueAttributeName::QueueArn))
        .expect("queue must have a QueueArn")
        .to_string();

    (url, arn)
}

/// Empties `queue_url`, so what a test drains afterwards is only what its own
/// trigger produced and not a previous run's leftovers.
pub async fn purge_queue(client: &aws_sdk_sqs::Client, queue_url: &str) {
    client
        .purge_queue()
        .queue_url(queue_url)
        .send()
        .await
        .unwrap_or_else(|e| panic!("purge_queue({queue_url}) failed: {e:?}"));
}

/// Long-polls until `expected` message bodies have arrived, in arrival order.
///
/// Panics rather than returning short: a test that got fewer notifications
/// than it triggered has already failed, and saying so here names the cause.
pub async fn drain_queue(
    client: &aws_sdk_sqs::Client,
    queue_url: &str,
    expected: usize,
    timeout: std::time::Duration,
) -> Vec<String> {
    let deadline = std::time::Instant::now() + timeout;
    let mut bodies = Vec::new();

    while bodies.len() < expected && std::time::Instant::now() < deadline {
        let out = client
            .receive_message()
            .queue_url(queue_url)
            .max_number_of_messages(10)
            .wait_time_seconds(2)
            .send()
            .await
            .unwrap_or_else(|e| panic!("receive_message({queue_url}) failed: {e:?}"));
        bodies.extend(
            out.messages()
                .iter()
                .filter_map(|m| m.body().map(str::to_string)),
        );
    }

    assert_eq!(
        bodies.len(),
        expected,
        "expected {expected} message(s) on {queue_url} within {timeout:?}, got {}: {bodies:#?}",
        bodies.len()
    );
    bodies
}

/// Points `bucket`'s `ObjectCreated` notifications at `queue_arn`.
///
/// Re-applying the configuration re-emits `s3:TestEvent`, so a test that wants
/// that event gets it on every run, not only the first.
pub async fn notify_queue(client: &aws_sdk_s3::Client, bucket: &str, queue_arn: &str) {
    use aws_sdk_s3::types::{Event, NotificationConfiguration, QueueConfiguration};

    let cfg = NotificationConfiguration::builder()
        .queue_configurations(
            QueueConfiguration::builder()
                .queue_arn(queue_arn)
                .events(Event::from("s3:ObjectCreated:*"))
                .build()
                .expect("QueueConfiguration requires an ARN and events"),
        )
        .build();

    client
        .put_bucket_notification_configuration()
        .bucket(bucket)
        .notification_configuration(cfg)
        .send()
        .await
        .unwrap_or_else(|e| panic!("notify_queue({bucket}) failed: {e:?}"));
}

/// Points `bucket`'s `ObjectCreated` notifications at `topic_arn`.
pub async fn notify_topic(client: &aws_sdk_s3::Client, bucket: &str, topic_arn: &str) {
    use aws_sdk_s3::types::{Event, NotificationConfiguration, TopicConfiguration};

    let cfg = NotificationConfiguration::builder()
        .topic_configurations(
            TopicConfiguration::builder()
                .topic_arn(topic_arn)
                .events(Event::from("s3:ObjectCreated:*"))
                .build()
                .expect("TopicConfiguration requires an ARN and events"),
        )
        .build();

    client
        .put_bucket_notification_configuration()
        .bucket(bucket)
        .notification_configuration(cfg)
        .send()
        .await
        .unwrap_or_else(|e| panic!("notify_topic({bucket}) failed: {e:?}"));
}

/// Routes `bucket`'s events to the default EventBridge bus.
pub async fn notify_eventbridge(client: &aws_sdk_s3::Client, bucket: &str) {
    use aws_sdk_s3::types::{EventBridgeConfiguration, NotificationConfiguration};

    let cfg = NotificationConfiguration::builder()
        .event_bridge_configuration(EventBridgeConfiguration::builder().build())
        .build();

    client
        .put_bucket_notification_configuration()
        .bucket(bucket)
        .notification_configuration(cfg)
        .send()
        .await
        .unwrap_or_else(|e| panic!("notify_eventbridge({bucket}) failed: {e:?}"));
}

/// Creates `name` if absent and returns its ARN. Idempotent.
pub async fn ensure_topic(client: &aws_sdk_sns::Client, name: &str) -> String {
    client
        .create_topic()
        .name(name)
        .send()
        .await
        .unwrap_or_else(|e| panic!("create_topic({name}) failed: {e:?}"))
        .topic_arn()
        .expect("CreateTopic must return an ARN")
        .to_string()
}

/// Subscribes `queue_arn` to `topic_arn`. `Subscribe` is idempotent for a
/// protocol/endpoint pair, so a rerun does not fan out duplicates.
pub async fn subscribe_queue(client: &aws_sdk_sns::Client, topic_arn: &str, queue_arn: &str) {
    client
        .subscribe()
        .topic_arn(topic_arn)
        .protocol("sqs")
        .endpoint(queue_arn)
        .send()
        .await
        .unwrap_or_else(|e| panic!("subscribe({topic_arn} -> {queue_arn}) failed: {e:?}"));
}

/// Creates or overwrites an EventBridge rule matching `pattern` and targeting
/// `queue_arn`, so a bus event can be observed from a test.
pub async fn ensure_rule_to_queue(
    client: &aws_sdk_eventbridge::Client,
    name: &str,
    pattern: &str,
    queue_arn: &str,
) {
    client
        .put_rule()
        .name(name)
        .event_pattern(pattern)
        .send()
        .await
        .unwrap_or_else(|e| panic!("put_rule({name}) failed: {e:?}"));

    client
        .put_targets()
        .rule(name)
        .targets(
            aws_sdk_eventbridge::types::Target::builder()
                .id("1")
                .arn(queue_arn)
                .build()
                .expect("Target requires an id and an ARN"),
        )
        .send()
        .await
        .unwrap_or_else(|e| panic!("put_targets({name}) failed: {e:?}"));
}

/// Writes (or overwrites) an SSM `SecureString` parameter, returning its new
/// version. Read without decryption such a parameter is `ENCRYPTED:<base64>`,
/// which no ruleset parses — so this is what makes `with_decryption` testable.
pub async fn put_secure_parameter(client: &aws_sdk_ssm::Client, name: &str, value: &str) -> i64 {
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
