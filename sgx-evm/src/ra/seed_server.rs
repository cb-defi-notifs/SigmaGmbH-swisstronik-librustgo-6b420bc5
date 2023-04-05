use sgx_types::*;

#[no_mangle]
pub unsafe extern "C" fn ecall_start_seed_server(
    socket_fd: c_int, 
    sign_type: sgx_quote_sign_type_t
) {
    println!("Starting seed server...");
}