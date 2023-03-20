/// This file contains signatures of `OCALL` functions

use crate::querier::GoQuerier;
use sgx_types::sgx_status_t;
use std::vec::Vec;

extern {
    #[no_mangle]
    pub fn ocall_query_raw(ret_val: *mut sgx_status_t, request: *const u8, len: usize) -> sgx_status_t;
}

pub fn make_request(querier: *mut GoQuerier, request: Vec<u8>) {
    let mut ret_val = sgx_status_t::SGX_SUCCESS;
    let mut result = unsafe {
        ocall_query_raw(&mut ret_val, request.as_ptr(), request.len())
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {
            println!("make_request succeed!");
        },
        _ => {
            println!("request failed");
        }
    }
}