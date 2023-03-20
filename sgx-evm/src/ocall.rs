/// This file contains signatures of `OCALL` functions

use crate::querier::GoQuerier;
use sgx_types::sgx_status_t;

extern {
    #[no_mangle]
    pub fn ocall_query_raw(ret_val : *mut sgx_status_t, request: *const u8, len: usize) -> sgx_status_t;
}