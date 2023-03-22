/// This file contains signatures of `OCALL` functions

use crate::{querier::GoQuerier, OcallAllocation};
use sgx_types::sgx_status_t;
use std::vec::Vec;

extern {
    #[no_mangle]
    pub fn ocall_query_raw(
        ret_val: *mut sgx_status_t, 
        querier: *mut GoQuerier, 
        request: *const u8, 
        len: usize,
        result: *mut u8,
        result_len: usize,
    ) -> sgx_status_t;

    #[no_mangle]
    pub fn ocall_allocate(
        ret_val: *mut OcallAllocation,
        data: *const u8,
        len: usize
    ) -> sgx_status_t;
}

pub fn make_request(querier: *mut GoQuerier, request: Vec<u8>) -> Option<Vec<u8>> {
    let mut ret_val = sgx_status_t::SGX_SUCCESS;
    let mut result_buffer = Vec::<u8>::with_capacity(crate::MAX_RESULT_LEN);
    let mut result = unsafe {
        ocall_query_raw(
            &mut ret_val, 
            querier, 
            request.as_ptr(), 
            request.len(),
            result_buffer.as_mut_ptr(),
            crate::MAX_RESULT_LEN,
        )
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {
            return Some(result_buffer);
        },
        _ => {
            println!("make_request failed");
            return None;
        }
    };
}