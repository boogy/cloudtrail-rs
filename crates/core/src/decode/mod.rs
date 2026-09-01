//! Event-source decoders. Each `EventDecoder` impl is gated behind its own Cargo
//! feature so a compiled Lambda binary carries exactly one.
//!
//! `sns` and `sqs` both unwrap their envelope and parse the result as an S3
//! event, so `s3`'s parsing helpers compile under `decode-sns` or `decode-sqs`
//! alone — but `S3EventDecoder` itself stays behind `decode-s3`.

#[cfg(any(feature = "decode-s3", feature = "decode-sns", feature = "decode-sqs"))]
pub mod s3;

#[cfg(feature = "decode-sns")]
pub mod sns;

#[cfg(feature = "decode-sqs")]
pub mod sqs;

#[cfg(feature = "decode-eventbridge")]
pub mod eventbridge;
