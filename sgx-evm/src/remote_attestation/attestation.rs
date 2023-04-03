use sgx_types::*;
use std::slice;
use super::keychain::{*, self};

#[no_mangle]
/// Generates attestation report and writes it to untrusted memory
pub unsafe extern "C" fn ecall_create_attestation_report(
    api_key: *const u8,
    api_key_len: usize,
) -> sgx_status_t {
    let api_key_slice = slice::from_raw_parts(api_key, api_key_len);
    let registration_key = match keychain::new_registration_key() {
        Ok(key) => key,
        Err(err) => { return err; }
    };

    sgx_status_t::SGX_SUCCESS
}