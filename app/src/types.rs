use crate::{UnmanagedVector, U8SliceView, errors::GoError};
use sgx_types::*;

#[repr(C)]
#[derive(Clone)]
pub struct GoQuerier {
    pub state: *const querier_t,
    pub vtable: Querier_vtable,
}

#[repr(C)]
#[derive(Clone)]
pub struct querier_t {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Clone)]
pub struct Querier_vtable {
    // We return errors through the return buffer, but may return non-zero error codes on panic
    pub query_external: extern "C" fn(
        *const querier_t,
        U8SliceView,
        *mut UnmanagedVector, // result output
        *mut UnmanagedVector, // error message output
    ) -> i32,
}

#[repr(C)]
pub struct QueryResult {
    pub output: UnmanagedVector,
    pub error: GoError,
    pub error_message: UnmanagedVector,
}

#[repr(C)]
pub struct Allocation {
    pub result_ptr: *mut u8,
    pub result_len: usize,
}

#[repr(C)]
pub struct AllocationWithResult {
    pub result_ptr: *mut u8,
    pub result_size: usize,
    pub status: sgx_status_t
}

impl Default for AllocationWithResult {
    fn default() -> Self {
        AllocationWithResult { result_ptr: std::ptr::null_mut(), result_size: 0usize, status: sgx_status_t::SGX_ERROR_UNEXPECTED }
    }
}