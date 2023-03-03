#![cfg_attr(feature = "backtraces", feature(backtrace))]
#![allow(clippy::not_unsafe_ptr_arg_deref, clippy::missing_safety_doc)]

extern crate alloc;

mod cache;
mod error;
mod memory;
mod protobuf_generated;
mod evm;
mod querier;
mod version;

// We only interact with this crate via `extern "C"` interfaces, not those public
// exports. There are no guarantees those exports are stable.
// We keep them here such that we can access them in the docs (`cargo doc`).
pub use error::GoError;
pub use memory::{
    destroy_unmanaged_vector, new_unmanaged_vector, ByteSliceView, U8SliceView, UnmanagedVector,
};

// TODO: Remove after debugging
// we have a problem with returning error from go
// output is returned correctly, but error is always empty
use crate::querier::GoQuerier;

#[no_mangle]
pub extern "C" fn debug(querier: GoQuerier) {
    let mut output = UnmanagedVector::default();
    let mut error_msg = UnmanagedVector::default();

    let go_result: GoError = (querier.vtable.query_external)(
        querier.state,
        U8SliceView::new(None),
        &mut output as *mut UnmanagedVector,
        &mut error_msg as *mut UnmanagedVector,
    )
    .into();

    let output = output.consume();
    let error_msg = error_msg.consume();

    println!("Output: {:?}", output);
    println!("Error: {:?}", error_msg)
}

