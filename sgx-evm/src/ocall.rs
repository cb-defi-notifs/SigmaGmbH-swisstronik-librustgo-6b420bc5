/// This file contains signatures of `OCALL` functions

use crate::{querier::GoQuerier, Allocation, AllocationWithResult};
use sgx_types::sgx_status_t;
use core::slice;
use std::vec::Vec;

extern {
    #[no_mangle]
    pub fn ocall_query_raw(
        ret_val: *mut AllocationWithResult, 
        querier: *mut GoQuerier, 
        request: *const u8, 
        len: usize,
        result: *mut u8,
        result_len: usize,
    ) -> sgx_status_t;

    #[no_mangle]
    pub fn ocall_allocate(
        ret_val: *mut Allocation,
        data: *const u8,
        len: usize
    ) -> sgx_status_t;
}

pub fn make_request(querier: *mut GoQuerier, request: Vec<u8>) -> Option<Vec<u8>> {
    let mut allocation = std::mem::MaybeUninit::<AllocationWithResult>::uninit();
    let mut buffer = [0u8; crate::MAX_RESULT_LEN];

    let mut result = unsafe {
        ocall_query_raw(
            allocation.as_mut_ptr(), 
            querier, 
            request.as_ptr(), 
            request.len(),
            &mut buffer as *mut u8,
            crate::MAX_RESULT_LEN,
        )
    };

    match result  {
        sgx_status_t::SGX_SUCCESS => {
            let allocation = unsafe { allocation.assume_init() };
            let result_slice = unsafe { slice::from_raw_parts(allocation.result_ptr, allocation.result_len)};
            return Some(result_slice.to_vec());
        },
        _ => {
            println!("make_request failed: Reason: {:?}", result.as_str());
            return None;
        }
    };
}