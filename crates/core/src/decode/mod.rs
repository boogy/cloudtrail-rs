//! Event-source decoders. Each `EventDecoder` impl is gated behind its own
//! Cargo feature so a compiled Lambda binary carries exactly one (SHARED:
//! "four fully independent entrypoints"). `sns` unwraps an SNS message and
//! parses it as an S3 event, so `s3`'s parsing logic also compiles under
//! `decode-sns` alone — but `S3EventDecoder` itself stays behind
//! `decode-s3`, so a `decode-sns`-only binary never carries it. `sqs`
//! reuses the same S3-parsing helpers (an SQS message body carrying a raw
//! S3 event or an SNS-wrapped one is the same JSON shape once unwrapped),
//! so `s3`'s parsing logic also compiles under `decode-sqs` alone.

#[cfg(any(feature = "decode-s3", feature = "decode-sns", feature = "decode-sqs"))]
pub mod s3;

#[cfg(feature = "decode-sns")]
pub mod sns;

#[cfg(feature = "decode-sqs")]
pub mod sqs;

#[cfg(feature = "decode-eventbridge")]
pub mod eventbridge;
