#![cfg_attr(feature = "backtraces", feature(backtrace))]
#![allow(clippy::not_unsafe_ptr_arg_deref, clippy::missing_safety_doc)]

extern crate alloc;

mod api;
mod args;
mod cache;
mod error;
mod gas_meter;
mod iterator;
mod memory;
mod tests;
mod protobuf_generated;
mod evm;
mod querier;

// We only interact with this crate via `extern "C"` interfaces, not those public
// exports. There are no guarantees those exports are stable.
// We keep them here such that we can access them in the docs (`cargo doc`).
pub use api::GoApi;
pub use error::GoError;
pub use memory::{
    destroy_unmanaged_vector, new_unmanaged_vector, ByteSliceView, U8SliceView, UnmanagedVector,
};

