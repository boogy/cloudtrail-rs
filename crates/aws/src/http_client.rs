//! The one HTTP client every adapter's SDK `Client` is built with: rustls
//! terminated by the `ring` crypto provider, never the `aws-lc-rs` default.
//! `aws-lc-rs` needs a working C toolchain for the musl cross-build and is
//! the usual cause of a `cargo lambda build --arm64` that works locally and
//! fails only in CI.

use aws_smithy_http_client::Builder;
use aws_smithy_http_client::tls::Provider;
use aws_smithy_http_client::tls::rustls_provider::CryptoMode;
use aws_smithy_runtime_api::client::http::SharedHttpClient;

pub fn ring_http_client() -> SharedHttpClient {
    Builder::new()
        .tls_provider(Provider::Rustls(CryptoMode::Ring))
        .build_https()
}

/// Loads the default AWS configuration with the ring HTTP client attached.
///
/// `aws_config::load_defaults` cannot be used directly: it builds the default
/// region provider chain, which *eagerly constructs* an IMDS client, and that
/// construction panics with "a http_client is required" because this
/// workspace deliberately builds `aws-config` with `default-features = false`
/// (its `default-https-client` feature would pull in `aws-lc-rs`, which breaks
/// the musl cross-build — see this module's header). Supplying the client up
/// front satisfies IMDS without reintroducing `aws-lc-rs`.
pub async fn load_aws_config(
    behavior_version: aws_config::BehaviorVersion,
) -> aws_config::SdkConfig {
    aws_config::defaults(behavior_version)
        .http_client(ring_http_client())
        .load()
        .await
}
