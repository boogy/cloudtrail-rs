//! Event-source decoders. Each `EventDecoder` impl is gated behind its own
//! Cargo feature so a compiled Lambda binary carries exactly one (SHARED:
//! "four fully independent entrypoints"). `sns` unwraps an SNS message and
//! parses it as an S3 event, so `s3`'s parsing logic also compiles under
//! `decode-sns` alone — but `S3EventDecoder` itself stays behind
//! `decode-s3`, so a `decode-sns`-only binary never carries it.

#[cfg(any(feature = "decode-s3", feature = "decode-sns"))]
pub mod s3;

#[cfg(feature = "decode-sns")]
pub mod sns;
