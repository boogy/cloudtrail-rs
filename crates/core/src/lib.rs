#![forbid(unsafe_code)]

pub mod config;
#[cfg(any(
    feature = "decode-s3",
    feature = "decode-sns",
    feature = "decode-sqs",
    feature = "decode-eventbridge"
))]
pub mod decode;
pub mod error;
pub mod filter;
pub mod metrics;
pub mod model;
pub mod pipeline;
pub mod ports;
pub mod process;

#[cfg(feature = "testing")]
pub mod testing;
