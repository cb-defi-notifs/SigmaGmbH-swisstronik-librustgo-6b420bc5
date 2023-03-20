use sgx_types::*;
use sgx_urts::SgxEnclave;

use crate::querier::GoQuerier;

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
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr
    )
}

#[no_mangle]
pub extern "C" fn ocall_query_raw(request: *const u8, len: usize) -> sgx_status_t {
    println!("HELLO FROM OCALL. SIZE: {:?}", len);
    sgx_status_t::SGX_SUCCESS
}