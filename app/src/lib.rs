extern crate sgx_types;
extern crate sgx_urts;
extern crate errno;
extern crate thiserror;

use sgx_types::*;
use sgx_urts::SgxEnclave;

mod enclave;
mod cache;
mod memory;
mod querier;
mod version;
mod errors;

use enclave::{init_enclave, handle_request};
use querier::GoQuerier;
use std::panic::catch_unwind;

// We only interact with this crate via `extern "C"` interfaces, not those public
// exports. There are no guarantees those exports are stable.
// We keep them here such that we can access them in the docs (`cargo doc`).
pub use memory::{
    destroy_unmanaged_vector, new_unmanaged_vector, ByteSliceView, U8SliceView, UnmanagedVector,
};