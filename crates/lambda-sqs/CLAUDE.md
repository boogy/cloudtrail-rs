# crates/lambda-sqs — composition root (`decode-sqs`)

Binary for the S3 → SQS → Lambda topology. `#![forbid(unsafe_code)]`.

Same composition-root pattern as `lambda-s3` (init-once in `main`, handler captures only `Arc<Pipeline>`, ring TLS via `load_aws_config`); decoder is compiled in via the `decode-sqs` feature.

## Critical difference — partial batch failure

Unlike the other three binaries, the SQS handler returns a `{"batchItemFailures":[{"itemIdentifier": id}, ...]}` document built from `BatchOutcome::failed_ack_ids`, so the event source mapping re-drives **only** the failed messages.

> ⚠️ **`ReportBatchItemFailures` must be enabled on the event source mapping.** Without it, a partial batch failure means the failed messages are silently deleted — **unrecoverable data loss**. This is a deployment-config invariant, not something the code can enforce.

See [`docs/deployment.md`](../../docs/deployment.md#sqs-reportbatchitemfailures-is-not-optional).
