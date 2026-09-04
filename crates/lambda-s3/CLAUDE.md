# crates/lambda-s3 — composition root (`decode-s3`)

Binary for the S3-direct-notification topology. `#![forbid(unsafe_code)]`.

**Composition-root pattern (shared by all four lambda crates):** every port is constructed exactly once in `main`, before `lambda_runtime::run`; the handler closure captures only an `Arc<Pipeline>` clone and never constructs an adapter (cold-start init-once). Config/AWS clients come from `cloudtrail-rs-aws` (`load_aws_config`, ring TLS); the decoder is `S3EventDecoder`, compiled in via the `decode-s3` feature — exactly one decoder per binary, no runtime sniffing.

`lambda-sns` and `lambda-eventbridge` mirror this exactly (only the decoder + feature differ). `lambda-sqs` differs — see its `CLAUDE.md`. See [`docs/deployment.md`](../../docs/deployment.md).
