use std::collections::HashSet;
use std::marker::PhantomData;
use std::panic::catch_unwind;

use crate::memory::{ByteSliceView, UnmanagedVector};
use crate::querier::GoQuerier;
use crate::errors::{handle_c_error_default, Error};
use crate::enclave;

// store some common string for argument names
pub const PB_REQUEST_ARG: &str = "pb_request";

#[repr(C)]
#[allow(dead_code)]
pub struct cache_t {}

#[allow(dead_code)]
pub struct Cache {
    querier: PhantomData<GoQuerier>,
}

pub fn to_cache(ptr: *mut cache_t) -> Option<&'static mut Cache> {
    if ptr.is_null() {
        None
    } else {
        let c = unsafe { &mut *(ptr as *mut Cache) };
        Some(c)
    }
}

#[no_mangle]
pub extern "C" fn make_pb_request(
    querier: GoQuerier,
    request: ByteSliceView,
    error_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {
    let r = catch_unwind(|| {
        // Check if request is correct
        let req_bytes = request
            .read()
            .ok_or_else(|| Error::unset_arg(PB_REQUEST_ARG))?;

        // Initialize enclave
        let evm_enclave = match enclave::init_enclave() {
            Ok(r) => {r},
            Err(err) => { return Err(Error::vm_err("Cannot initialize SGXVM enclave")) },
        };

        // Destory enclave after usage
        evm_enclave.destroy();

        Ok(UnmanagedVector::new(None))
    }).unwrap_or_else(|_| Err(Error::panic()));

    let data = handle_c_error_default(r, error_msg);
    UnmanagedVector::new(None)
}
