use std::marker::PhantomData;
use std::panic::catch_unwind;

use crate::memory::{ByteSliceView, UnmanagedVector};
use crate::types::{GoQuerier};
use crate::errors::{handle_c_error_default, Error};
use crate::enclave::{self};
use crate::types::AllocationWithResult;

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
        // Set enclave id to static variable to make it accessible across inner ecalls
        unsafe { enclave::ENCLAVE_ID = Some(evm_enclave.geteid()) };
        
        // Prepare data for the enclave
        let request_vec = Vec::from(req_bytes);
        let mut querier = querier;
        let mut handle_request_result = std::mem::MaybeUninit::<AllocationWithResult>::uninit();

        // Call the enclave
        let evm_res = unsafe { 
            enclave::handle_request(
                evm_enclave.geteid(), 
                handle_request_result.as_mut_ptr(),
                &mut querier as *mut GoQuerier,
                request_vec.as_ptr(),
                request_vec.len(),
            ) 
        };

        let handle_request_result = unsafe { handle_request_result.assume_init() };

        // Destory enclave after usage and set enclave id to None
        evm_enclave.destroy();
        unsafe { enclave::ENCLAVE_ID = None };

        // Parse execution result
        match handle_request_result.status {
            sgx_status_t::SGX_SUCCESS => {
                let data = unsafe { Vec::from_raw_parts(handle_request_result.result_ptr, handle_request_result.result_size, handle_request_result.result_size) };
                return Ok(data)
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
