use sgx_types::*;
use std::slice;
use sgx_tse::rsgx_self_report;

pub mod cert;
pub mod hex;
pub mod keychain;
pub mod seed_server;
pub mod seed_client;
pub mod utils;
pub mod consts;
pub mod report;
pub mod types;

pub fn get_mr_enclave() -> [u8; 32] {
    rsgx_self_report().body.mr_enclave.m
}

#[no_mangle]
/// Handles initialization of a new seed node.
/// If seed is already sealed, it will reset it
pub unsafe extern "C" fn ecall_init_seed_node() -> sgx_status_t {
    println!("Start seed node");
    match keychain::new_node_seed() {
        Ok(_) => sgx_status_t::SGX_SUCCESS,
        Err(err) => err,
    }
}

#[no_mangle]
/// Initializes regular node
pub unsafe extern "C" fn ecall_init_node() -> sgx_status_t {
    println!("Start regular node");
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
/// Creates attestation certificate and saves it to unprotected memory
pub unsafe extern "C" fn ecall_create_report(api_key: *const u8) -> sgx_status_t {
    println!("Creating attestation report");

    // Read API key for IAS from slice
    let api_key_slice = slice::from_raw_parts(api_key, 32usize);

    sgx_status_t::SGX_SUCCESS
}