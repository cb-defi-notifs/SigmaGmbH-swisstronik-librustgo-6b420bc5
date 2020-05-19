mod go;
mod rust;

pub use go::GoResult;
pub use rust::{clear_error, handle_c_error, set_error, EmptyArg, Error, Panic, WasmErr};

pub(crate) use rust::empty_err;
