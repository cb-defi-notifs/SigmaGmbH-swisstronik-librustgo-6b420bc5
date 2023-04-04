use crate::errors::GoError;
use crate::memory::{U8SliceView, UnmanagedVector};
use crate::types::{Allocation, AllocationWithResult, GoQuerier};

use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::io::IntoRawFd;
use std::slice;

static ENCLAVE_FILE: &'static str = "/tmp/enclave.signed.so";
pub static mut ENCLAVE_ID: Option<sgx_types::sgx_enclave_id_t> = None;

#[allow(dead_code)]
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

    pub fn ecall_init_seed_node(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
    ) -> sgx_status_t;

    pub fn ecall_init_node(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
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