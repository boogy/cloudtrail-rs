# crates/lambda-eventbridge — composition root (`decode-eventbridge`)

Binary for the S3 → EventBridge → Lambda topology. `#![forbid(unsafe_code)]`.

Identical composition-root pattern to `lambda-s3` (init-once in `main`, handler captures only `Arc<Pipeline>`, ring TLS via `load_aws_config`); only the decoder differs — `EventBridgeDecoder`, compiled in via the `decode-eventbridge` feature. See [`crates/lambda-s3/CLAUDE.md`](../lambda-s3/CLAUDE.md) and [`docs/deployment.md`](../../docs/deployment.md).
