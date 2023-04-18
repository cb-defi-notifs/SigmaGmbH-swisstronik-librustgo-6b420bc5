use sgx_types::*;
use std::slice;

pub mod cert;
pub mod hex;
pub mod keychain;
pub mod seed_server;
pub mod seed_client;
pub mod utils;
pub mod consts;
pub mod report;
pub mod types;

#[no_mangle]
/// Handles initialization of a new seed node.
/// If seed is already sealed, it will reset it
pub unsafe extern "C" fn ecall_init_master_key(reset_flag: i32) -> sgx_status_t {
    println!("[Enclave] Initialize master key");
    
    match keychain::new_node_seed() {
        Ok(_) => sgx_status_t::SGX_SUCCESS,
        Err(err) => err,
    }
}