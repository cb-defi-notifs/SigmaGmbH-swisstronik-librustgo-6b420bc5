use crate::types::{GoQuerier, AllocationWithResult, Allocation};
use crate::memory::{UnmanagedVector, U8SliceView};
use crate::errors::GoError;

use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::slice;

static ENCLAVE_FILE: &'static str = "/tmp/enclave.signed.so";
pub static mut ENCLAVE_ID: Option<sgx_types::sgx_enclave_id_t> = None;

extern "C" {
    pub fn handle_request(
        eid: sgx_enclave_id_t,
        retval: *mut AllocationWithResult,
        querier: *mut GoQuerier,
        request: *const u8,
        len: usize,
    ) -> sgx_status_t;

    pub fn ecall_allocate(
        eid: sgx_enclave_id_t,
        retval: *mut Allocation,
        data: *const u8,
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
    request_len: usize,
) -> AllocationWithResult {
    // Recover request and querier
    let request = unsafe { slice::from_raw_parts(request, request_len) };
    let querier = unsafe { &*querier };

    // Prepare vectors for output and error
    let mut output = UnmanagedVector::default();
    let mut error_msg = UnmanagedVector::default();

    // Make request to GoQuerier (Connector)
    let go_result: GoError = (querier.vtable.query_external)(
        querier.state,
        U8SliceView::new(Some(&request)),
        &mut output as *mut UnmanagedVector,
        &mut error_msg as *mut UnmanagedVector,
    )
    .into();

    // Consume vectors to destroy them
    let output = output.consume();
    let error_msg = error_msg.consume();

    match go_result {
        GoError::None => {
            let output = output.unwrap_or_default();

            let enclave_eid = unsafe { ENCLAVE_ID.expect("Enclave should be already initialized") };
            let mut allocation_result = std::mem::MaybeUninit::<Allocation>::uninit();

            let res = unsafe {
                ecall_allocate(
                    enclave_eid, 
                    allocation_result.as_mut_ptr(), 
                    output.as_ptr(), 
                    output.len(),
                )
            };

            match res {
                sgx_status_t::SGX_SUCCESS => {
                    let allocation_result = unsafe { allocation_result.assume_init() };
                    return AllocationWithResult {
                        result_ptr: allocation_result.result_ptr,
                        result_size: output.len(),
                        status: sgx_status_t::SGX_SUCCESS,
                    };
                },
                _ => {
                    println!("ecall_allocate failed. Reason: {:?}", res.as_str());
                    return AllocationWithResult {
                        result_ptr: std::ptr::null_mut(),
                        result_size: 0usize,
                        status: res,
                    };
                }
            };
        },
        _ => {
            let err_msg = error_msg.unwrap_or_default();
            println!(
                "[OCALL] query_raw: got error: {:?} with message: {:?}",
                go_result,
                String::from_utf8_lossy(&err_msg)
            );
            return AllocationWithResult::default();
        }
    };
}

#[no_mangle]
pub extern "C" fn ocall_allocate(data: *const u8, len: usize) -> Allocation {
    let slice = unsafe { slice::from_raw_parts(data, len) };
    let mut vector_copy = slice.to_vec();

    let ptr = vector_copy.as_mut_ptr();
    let len = vector_copy.len();
    std::mem::forget(vector_copy);

    Allocation { result_ptr: ptr, result_len: len }
}