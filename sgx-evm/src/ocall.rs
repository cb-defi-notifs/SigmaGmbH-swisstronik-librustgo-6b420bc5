/// This file contains signatures of `OCALL` functions

use crate::querier::GoQuerier;
use sgx_types::sgx_status_t;

extern {
    #[no_mangle]
    pub fn ocall_query_raw(
        querier: *mut GoQuerier,
        request: *const u8,
        request_len: usize,
        result: *mut u8,
        max_result_len: usize,
    ) -> sgx_status_t;
}