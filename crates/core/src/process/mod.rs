//! Object-body record processing: decompress the source object, filter its
//! records through the `Engine`, and produce (or, in stream mode, directly
//! write) the survivors.

mod buffer;
mod stream;

pub use buffer::{Outcome, buffer_run};
pub use stream::stream_run;
