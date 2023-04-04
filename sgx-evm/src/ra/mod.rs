
use sgx_types::*;

pub mod keychain;

#[no_mangle]
/// Initializes seed node
pub unsafe extern "C" fn ecall_init_seed_node() -> sgx_status_t {
    println!("Start seed node");
    match keychain::new_node_seed() {
        Ok(_) => sgx_status_t::SGX_SUCCESS,
        Err(err) => err
    }
}

#[no_mangle]
/// Initializes regular node
pub unsafe extern "C" fn ecall_init_node() -> sgx_status_t {
    println!("Start regular node");
    sgx_status_t::SGX_SUCCESS
}