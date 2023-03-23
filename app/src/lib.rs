extern crate sgx_types;
extern crate sgx_urts;
extern crate errno;
extern crate thiserror;

mod enclave;
mod cache;
mod memory;
mod version;
mod errors;
mod types;

// We only interact with this crate via `extern "C"` interfaces, not those public
// exports. There are no guarantees those exports are stable.
// We keep them here such that we can access them in the docs (`cargo doc`).
pub use memory::{
    destroy_unmanaged_vector, new_unmanaged_vector, ByteSliceView, U8SliceView, UnmanagedVector,
};