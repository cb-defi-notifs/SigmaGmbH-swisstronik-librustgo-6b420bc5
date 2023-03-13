mod go;
mod rust;

pub use go::GoError;
pub use rust::{
    handle_c_error_default, RustError as Error,
};
