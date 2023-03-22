use std::collections::HashSet;
use std::marker::PhantomData;
use std::panic::catch_unwind;

use crate::memory::{ByteSliceView, UnmanagedVector};
use crate::querier::{GoQuerier, self};
use crate::errors::{handle_c_error_default, Error};
use crate::enclave::{self, HandleResult};
use sgx_types::*;

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
            Err(err) => { 
                println!("Got error: {:?}", err.as_str());
                return Err(Error::vm_err("Cannot initialize SGXVM enclave")) 
            },
        };
        
        // Prepare data for the enclave
        let request_vec = Vec::from(req_bytes);
        let mut querier = querier;
        let mut retval = HandleResult {
            result_ptr: std::ptr::null_mut(),
            result_size: 0usize,
            status: sgx_status_t::SGX_ERROR_UNEXPECTED,
        };

        // Call the enclave
        let evm_res = unsafe { 
            enclave::handle_request(
                evm_enclave.geteid(), 
                &mut retval,
                &mut querier as *mut GoQuerier,
                request_vec.as_ptr(),
                request_vec.len(),
            ) 
        };

        // Destory enclave after usage
        evm_enclave.destroy();

        // Parse execution result
        match retval.status {
            sgx_status_t::SGX_SUCCESS => {
                let data = unsafe { std::slice::from_raw_parts(retval.result_ptr, retval.result_size)};
                return Ok(data.to_vec())
            },
            _ => {
                println!("Call failed");
                return Err(Error::vm_err(format!("Call to EVM failed: {:?}", evm_res.as_str())));
            }
        }
    }).unwrap_or_else(|_| Err(Error::panic()));

    let data = handle_c_error_default(r, error_msg);
    UnmanagedVector::new(Some(data))
}
