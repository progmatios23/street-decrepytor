//! IDA-shaped session builder. Never panics on bad input — writes gaps instead.

pub mod complete;
pub mod emu;
pub mod flow;
pub mod modules;
pub mod run;

pub use complete::{dump_complete, dump_complete_folder, CompleteReport};
pub use run::{run_session, SessionOptions, SessionReport};
