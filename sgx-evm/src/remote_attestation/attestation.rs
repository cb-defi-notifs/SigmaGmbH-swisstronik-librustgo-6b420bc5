use sgx_types::*;
use std::slice;
use std::vec::Vec;
use super::keychain::{*, self};

pub const SIGNATURE_TYPE: sgx_quote_sign_type_t = sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE;

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
    let (_, cert) = match create_attestation_certificate(SIGNATURE_TYPE, api_key_slice, None) {
        Ok(res) => res,
        Err(err) => {
            println!("Cannot create attestation certificate: {:?}", err.as_str());
            return err;
        }
    };

    sgx_status_t::SGX_SUCCESS
}

fn create_attestation_certificate(
    sign_type: sgx_quote_sign_type_t,
    api_key: &[u8],
    challenge: Option<&[u8]>
) -> Result<(Vec<u8>, Vec<u8>), sgx_status_t> {
    Err(sgx_status_t::SGX_SUCCESS)
}