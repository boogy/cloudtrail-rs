//! The one HTTP client every adapter's SDK `Client` is built with: rustls
//! terminated by the `ring` crypto provider, never the `aws-lc-rs` default.
//! `aws-lc-rs` needs a working C toolchain for the musl cross-build and is
//! the usual cause of a `cargo lambda build --arm64` that works locally and
//! fails only in CI.

use aws_smithy_http_client::Builder;
use aws_smithy_http_client::tls::Provider;
use aws_smithy_http_client::tls::rustls_provider::CryptoMode;
use aws_smithy_runtime_api::client::http::SharedHttpClient;

pub(crate) fn ring_http_client() -> SharedHttpClient {
    Builder::new()
        .tls_provider(Provider::Rustls(CryptoMode::Ring))
        .build_https()
}
