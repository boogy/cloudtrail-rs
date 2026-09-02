//! Composition root for the S3-notification Lambda (`decode-s3`).
//!
//! Every port is constructed exactly once here, in `main`, before
//! `lambda_runtime::run`; the handler closure captures only an `Arc<Pipeline>`
//! clone and never constructs an adapter.
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use aws_config::BehaviorVersion;
use aws_config::SdkConfig;
use cloudtrail_rs_aws::{S3ConfigSource, S3ObjectStore, SsmConfigSource, load_aws_config};
use cloudtrail_rs_core::config::{
    ConfigStore, ConfigUri, FileConfigSource, MetricsMode, Observability, Processing, RuleSet,
    Settings,
};
use cloudtrail_rs_core::decode::s3::S3EventDecoder;
use cloudtrail_rs_core::filter::Engine;
use cloudtrail_rs_core::metrics::{EmfMetricsSink, Metrics, NoopMetricsSink};
use cloudtrail_rs_core::pipeline::Pipeline;
use cloudtrail_rs_core::ports::{ConfigSource, MetricsSink};
use lambda_runtime::{LambdaEvent, service_fn};
use serde_json::Value;

fn init_tracing() {
    tracing_subscriber::fmt().json().with_target(false).init();
}

/// Picks the `ConfigSource` adapter for `settings.rules.uri`'s scheme
/// (`ssm://` | `s3://` | `file://`).
fn build_config_source(
    settings: &Settings,
    sdk_conf: &aws_config::SdkConfig,
) -> anyhow::Result<Arc<dyn ConfigSource>> {
    Ok(match ConfigUri::parse(&settings.rules.uri)? {
        ConfigUri::Ssm { path } => Arc::new(SsmConfigSource::new(sdk_conf, path)),
        ConfigUri::S3 { bucket, key } => Arc::new(S3ConfigSource::new(sdk_conf, bucket, key)),
        ConfigUri::File { path } => Arc::new(FileConfigSource::new(path)),
    })
}

/// Picks the `MetricsSink` for `observability.metrics`.
fn build_sink(observability: &Observability) -> Arc<dyn MetricsSink> {
    match observability.metrics {
        MetricsMode::Emf => Arc::new(EmfMetricsSink::new(observability.namespace.clone())),
        MetricsMode::None => Arc::new(NoopMetricsSink),
    }
}

/// Builds the `S3ObjectStore`, carrying `processing.multipart_part_bytes` through
/// `S3ObjectStore::from_settings`. Extracted out of `main` so a test can prove
/// this composition root passes the configured value through.
fn build_store(conf: &SdkConfig, processing: &Processing) -> S3ObjectStore {
    S3ObjectStore::from_settings(conf, processing)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    // ---- INIT: once per container ----
    init_tracing();
    tracing::info!(
        version = cloudtrail_rs_core::build_info::VERSION,
        git_sha = cloudtrail_rs_core::build_info::GIT_SHA,
        "cloudtrail-rs starting"
    );
    let settings = Arc::new(Settings::load().await?);
    let sdk_conf = load_aws_config(BehaviorVersion::latest()).await;
    let store = Arc::new(build_store(&sdk_conf, &settings.processing));
    let decoder = Arc::new(S3EventDecoder::new());
    let cfg_src = build_config_source(&settings, &sdk_conf)?;
    let metrics = Arc::new(Metrics::default());
    let sink = build_sink(&settings.observability);
    let cfg_store = Arc::new(ConfigStore::new(
        cfg_src,
        Duration::from_secs(settings.rules.ttl_seconds),
        Arc::new(|b: &[u8]| Ok(Arc::new(Engine::new(RuleSet::parse(b)?)?))),
        metrics.clone(),
    ));
    cfg_store.prime().await;
    let pipeline = Arc::new(Pipeline::new(
        settings, decoder, store, cfg_store, metrics, sink,
    ));

    // ---- RUN: closure owns only Arc clones ----
    lambda_runtime::run(service_fn(move |event: LambdaEvent<Value>| {
        let pipeline = pipeline.clone();
        async move {
            let payload = serde_json::to_vec(&event.payload)?;
            pipeline.handle(&payload).await?;
            Ok::<(), lambda_runtime::Error>(())
        }
    }))
    .await
    .map_err(|e| anyhow::anyhow!("lambda runtime error: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::build_store;
    use aws_config::{BehaviorVersion, Region, SdkConfig};
    use cloudtrail_rs_aws::DEFAULT_MULTIPART_PART_BYTES;
    use cloudtrail_rs_core::config::Processing;

    /// A bare `SdkConfig` is enough: `build_store` only builds a client from
    /// it, no network call happens.
    fn test_sdk_config() -> SdkConfig {
        SdkConfig::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .build()
    }

    // `settings.processing.multipart_part_bytes` must reach the store `main`
    // actually builds, not just `S3ObjectStore::from_settings` in isolation.

    #[test]
    fn build_store_wires_a_non_default_multipart_part_bytes_through() {
        let processing = Processing {
            multipart_part_bytes: 16 * 1024 * 1024,
            ..Processing::default()
        };

        let store = build_store(&test_sdk_config(), &processing);

        assert_eq!(store.multipart_part_bytes(), 16 * 1024 * 1024);
        assert_ne!(store.multipart_part_bytes(), DEFAULT_MULTIPART_PART_BYTES);
    }
}
