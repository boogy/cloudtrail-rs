//! Composition root for the SQS-triggered Lambda (`decode-sqs`).
//!
//! Per `docs/plans/cloudtrail-rs/SHARED.md` ("Cold start and init-once"),
//! every port is constructed exactly once here, in `main`, before
//! `lambda_runtime::run`; the handler closure captures only an
//! `Arc<Pipeline>` clone and never constructs an adapter.
//!
//! Unlike the other three binaries, the SQS handler returns a
//! `{"batchItemFailures":[{"itemIdentifier": id}, ...]}` document built from
//! `BatchOutcome::failed_ack_ids`, so the event source mapping re-drives only
//! the failed messages. **This requires `ReportBatchItemFailures` to be
//! enabled on the mapping** — see the SQS data-loss warning in SHARED.md.
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use aws_config::BehaviorVersion;
use cloudtrail_rs_aws::{S3ConfigSource, S3ObjectStore, SsmConfigSource};
use cloudtrail_rs_core::config::{
    ConfigStore, ConfigUri, FileConfigSource, MetricsMode, Observability, RuleSet, Settings,
};
use cloudtrail_rs_core::decode::sqs::SqsEventDecoder;
use cloudtrail_rs_core::filter::Engine;
use cloudtrail_rs_core::metrics::{EmfMetricsSink, Metrics, NoopMetricsSink};
use cloudtrail_rs_core::pipeline::{BatchOutcome, Pipeline};
use cloudtrail_rs_core::ports::{ConfigSource, MetricsSink};
use lambda_runtime::{LambdaEvent, service_fn};
use serde_json::{Value, json};

fn init_tracing() {
    tracing_subscriber::fmt().json().with_target(false).init();
}

/// Picks the `ConfigSource` adapter for `settings.rules.uri`'s scheme
/// (`ssm://` | `s3://` | `file://`, per `SHARED.md`'s Rules schema).
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

/// The Lambda SQS partial-batch response: `failed_ack_ids` become
/// `itemIdentifier`s so the event source mapping re-drives only those
/// messages. An empty list yields `{"batchItemFailures":[]}`, which deletes
/// the whole (successful) batch.
fn batch_response(outcome: &BatchOutcome) -> Value {
    json!({
        "batchItemFailures": outcome
            .failed_ack_ids
            .iter()
            .map(|id| json!({ "itemIdentifier": id }))
            .collect::<Vec<_>>()
    })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    // ---- INIT: once per container ----
    init_tracing();
    let settings = Arc::new(Settings::load().await?);
    let sdk_conf = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let store = Arc::new(S3ObjectStore::new(&sdk_conf));
    let decoder = Arc::new(SqsEventDecoder::new(settings.sqs.body_format));
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
            let outcome = pipeline.handle(&payload).await?;
            Ok::<Value, lambda_runtime::Error>(batch_response(&outcome))
        }
    }))
    .await
    .map_err(|e| anyhow::anyhow!("lambda runtime error: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::batch_response;
    use cloudtrail_rs_core::pipeline::BatchOutcome;
    use serde_json::json;

    #[test]
    fn empty_failed_ack_ids_yields_empty_batch_item_failures() {
        let outcome = BatchOutcome {
            failed_ack_ids: vec![],
        };
        assert_eq!(batch_response(&outcome), json!({ "batchItemFailures": [] }));
    }

    #[test]
    fn failed_ack_ids_become_item_identifiers() {
        let outcome = BatchOutcome {
            failed_ack_ids: vec!["msg-1".to_string(), "msg-2".to_string()],
        };
        assert_eq!(
            batch_response(&outcome),
            json!({
                "batchItemFailures": [
                    { "itemIdentifier": "msg-1" },
                    { "itemIdentifier": "msg-2" }
                ]
            })
        );
    }
}
