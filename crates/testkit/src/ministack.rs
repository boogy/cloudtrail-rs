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
