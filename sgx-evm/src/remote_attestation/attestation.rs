use sgx_types::*;
use std::slice;
use std::vec::Vec;
use std::string::String;
use super::keychain::{*, self};

use sgx_tcrypto::SgxEccHandle;

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
    let (_, cert) = match create_attestation_certificate(registration_key, SIGNATURE_TYPE, api_key_slice, None) {
        Ok(res) => res,
        Err(err) => {
            println!("Cannot create attestation certificate: {:?}", err.as_str());
            return err;
        }
    };

    sgx_status_t::SGX_SUCCESS
}

fn create_attestation_certificate(
    registration_key: keychain::RegistrationKey,
    sign_type: sgx_quote_sign_type_t,
    api_key: &[u8],
    challenge: Option<&[u8]>
) -> Result<(Vec<u8>, Vec<u8>), sgx_status_t> {
    // extract private key from KeyPair
    let ecc_handle = SgxEccHandle::new();
    let _result = ecc_handle.open();

    // use ephemeral key
    let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();
    // call create_report using the secp256k1 public key, and __not__ the P256 one
    let signed_report =
        match super::create_attestation_report(&registration_key.public_key().to_bytes(), sign_type, api_key, challenge) {
            Ok(r) => r,
            Err(e) => {
                error!("Error creating attestation report");
                return Err(e);
            }
        };

    let payload: String = serde_json::to_string(&signed_report).map_err(|_| {
        error!("Error serializing report. May be malformed, or badly encoded");
        sgx_status_t::SGX_ERROR_UNEXPECTED
    })?;
    let (key_der, cert_der) = super::cert::gen_ecc_cert(payload, &prv_k, &pub_k, &ecc_handle)?;
    let _result = ecc_handle.close();

    Err(sgx_status_t::SGX_SUCCESS)
}