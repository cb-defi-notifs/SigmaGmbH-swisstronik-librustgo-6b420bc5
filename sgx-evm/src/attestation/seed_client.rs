use sgx_tcrypto::*;
use sgx_types::*;

use rustls;
use std::io;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::prelude::v1::*;
use std::str;
use std::sync::Arc;
use std::vec::Vec;

use crate::attestation::consts::{ENCRYPTED_KEY_SIZE, PUBLIC_KEY_SIZE, QUOTE_SIGNATURE_TYPE};
use crate::key_manager::{KeyManager, RegistrationKey};

#[no_mangle]
pub extern "C" fn ecall_request_seed(socket_fd: c_int) -> sgx_status_t {
    request_seed_inner(socket_fd)
}

#[cfg(feature = "hardware_mode")]
fn request_seed_inner(socket_fd: c_int) -> sgx_status_t {
    let cfg = match get_client_configuration() {
        Ok(cfg) => cfg,
        Err(err) => {
            println!(
                "[Enclave] Seed Client. Cannot construct client config. Reason: {}",
                err
            );
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let dns_name = match webpki::DNSNameRef::try_from_ascii_str("localhost") {
        Ok(dns_name) => dns_name,
        Err(err) => {
            println!("[Enclave] Seed Client: wrong host. Reason: {:?}", err);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };
    let mut sess = rustls::ClientSession::new(&Arc::new(cfg), dns_name);
    let mut conn = match TcpStream::new(socket_fd) {
        Ok(conn) => conn,
        Err(err) => {
            println!(
                "[Enclave] Seed Client: cannot establish tcp connection. Reason: {:?}",
                err
            );
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let mut tls = rustls::Stream::new(&mut sess, &mut conn);

    // Generate temporary registration key used for seed encryption during transfer
    let registration_key = match RegistrationKey::random() {
        Ok(key) => key,
        Err(err) => return err,
    };

    // Send client public key to the seed exchange server
    if let Err(err) = tls.write(registration_key.public_key().as_bytes()) {
        println!(
            "[Enclave] Seed Client: cannot send public key to server. Reason: {:?}",
            err
        );
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    let mut plaintext = Vec::new();
    match tls.read_to_end(&mut plaintext) {
        Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
            println!("[Enclave] Seed Client: connection aborted");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
        Err(e) => {
            println!("[Enclave] Seed Client: error in read_to_end: {:?}", e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
        _ => {}
    };

    // Check size of response. It should be equal or more 90 bytes
    // 32 public key | 16 nonce | ciphertext
    if plaintext.len() < ENCRYPTED_KEY_SIZE {
        println!("[Enclave] Seed Client: wrong response size");
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    // Extract public key and nonce + ciphertext
    let public_key = &plaintext[..PUBLIC_KEY_SIZE];
    let encrypted_seed = &plaintext[PUBLIC_KEY_SIZE..];

    // Construct key manager
    let key_manager = KeyManager::from_encrypted_seed(
        &registration_key,
        public_key.to_vec(),
        encrypted_seed.to_vec(),
    );
    let key_manager = match key_manager {
        Ok(key_manager) => key_manager,
        Err(err) => {
            println!(
                "[Enclave] Seed Client: cannot construct key manager. Reason: {:?}",
                err
            );
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    // Seal master key
    if let Err(error_status) = key_manager.seal() {
        println!(
            "[Enclave] Seed Client: cannot seal master key. Reason: {:?}",
            error_status.as_str()
        );
        return error_status;
    }

    sgx_status_t::SGX_SUCCESS
}

#[cfg(not(feature = "hardware_mode"))]
fn request_seed_inner(socket_fd: c_int) -> sgx_status_t {
    let mut conn = TcpStream::new(socket_fd).unwrap();

    // Generate temporary registration key used for seed encryption during transfer
    let registration_key = match RegistrationKey::random() {
        Ok(key) => key,
        Err(err) => return err,
    };

    // Send client public key to the seed exchange server
    if let Err(err) = conn.write(registration_key.public_key().as_bytes()) {
        println!(
            "[Enclave] Seed Client: cannot send public key to server. Reason: {:?}",
            err
        );
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    let mut plaintext = Vec::new();
    match conn.read_to_end(&mut plaintext) {
        Ok(_) => {
            // TODO: Server should return encrypted seed
            println!("Server replied: {}", str::from_utf8(&plaintext).unwrap());
        }
        Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
            println!("EOF (tls)");
        }
        Err(e) => println!("Error in read_to_end: {:?}", e),
    }

    // TODO: Decrypt seed and seal it

    sgx_status_t::SGX_SUCCESS
}

#[cfg(feature = "hardware_mode")]
fn get_client_configuration() -> Result<rustls::ClientConfig, String> {
    // Generate Keypair
    let ecc_handle = SgxEccHandle::new();
    ecc_handle.open().unwrap();
    let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();

    let signed_report = match super::utils::create_attestation_report(&pub_k, QUOTE_SIGNATURE_TYPE)
    {
        Ok(r) => r,
        Err(e) => {
            return Err(format!("Error creating attestation report"));
        }
    };

    let payload: String = match serde_json::to_string(&signed_report) {
        Ok(payload) => payload,
        Err(err) => {
            return Err(format!(
                "Error serializing report. May be malformed, or badly encoded: {:?}",
                err
            ));
        }
    };
    let (key_der, cert_der) = match super::cert::gen_ecc_cert(payload, &prv_k, &pub_k, &ecc_handle)
    {
        Ok(r) => r,
        Err(e) => {
            return Err(format!("Error in gen_ecc_cert: {:?}", e));
        }
    };
    ecc_handle.close().unwrap();

    let mut cfg = rustls::ClientConfig::new();
    let mut certs = Vec::new();
    certs.push(rustls::Certificate(cert_der));
    let privkey = rustls::PrivateKey(key_der);

    cfg.set_single_client_cert(certs, privkey).unwrap();
    cfg.dangerous()
        .set_certificate_verifier(Arc::new(super::utils::ServerAuth::new(true)));
    cfg.versions.clear();
    cfg.versions.push(rustls::ProtocolVersion::TLSv1_2);

    Ok(cfg)
}
