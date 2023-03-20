use crate::querier::GoQuerier;
use crate::memory::{UnmanagedVector, U8SliceView};
use crate::errors::GoError;

use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::slice;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

extern "C" {
    pub fn handle_request(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        querier: *mut GoQuerier,
        request: *const u8,
        len: usize,
    ) -> sgx_status_t;
}

pub fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    // call sgx_create_enclave to initialize an enclave instance
    let mut launch_token_updated: i32 = 0;
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    )
}

#[no_mangle]
pub extern "C" fn ocall_query_raw(
    querier: *mut GoQuerier,
    request: *const u8,
    len: usize,
) -> sgx_status_t {
    let request = unsafe { slice::from_raw_parts(request, len) };
    let querier = unsafe { &*querier };

    let mut output = UnmanagedVector::default();
    let mut error_msg = UnmanagedVector::default();

    let go_result: GoError = (querier.vtable.query_external)(
        querier.state,
        U8SliceView::new(Some(&request)),
        &mut output as *mut UnmanagedVector,
        &mut error_msg as *mut UnmanagedVector,
    )
    .into();

    println!("Go Result: {:?}", go_result);

    let output = output.consume();
    let error_msg = error_msg.consume();

    match go_result {
        GoError::None => {
            let result = output.unwrap_or_default();
            println!("[OCALL] query_raw: got result: {:?}", result);
            return sgx_status_t::SGX_SUCCESS;
        },
        _ => {
            let err_msg = error_msg.unwrap_or_default();
            println!(
                "[OCALL] query_raw: got error: {:?} with message: {:?}",
                go_result,
                String::from_utf8_lossy(&err_msg)
            );
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };
}
