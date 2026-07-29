//! Object-body record processing: decompress the source object, filter its
//! records through the `Engine`, and produce (or, in stream mode, directly
//! write) the survivors.

mod buffer;
mod discard;
mod stream;
mod tally;

pub use buffer::{Outcome, buffer_run};
pub use discard::DiscardStore;
pub use stream::stream_run;
pub use tally::RecordTally;
