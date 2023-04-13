use sgx_tcrypto::*;
use sgx_types::*;

use rustls;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::prelude::v1::*;
use std::str;
use std::sync::Arc;
use std::vec::Vec;

#[no_mangle]
pub unsafe extern "C" fn ecall_share_seed(
    socket_fd: c_int,
    sign_type: sgx_quote_sign_type_t,
) {
    share_seed_inner(socket_fd, sign_type);
}

#[cfg(feature = "hardware_mode")]
fn share_seed_inner(socket_fd: c_int, sign_type: sgx_quote_sign_type_t) {
    let cfg = match get_server_configuration(sign_type) {
        Ok(cfg) => cfg,
        Err(err) => {
            println!("{}", err);
            return;
        }
    };

    let mut sess = rustls::ServerSession::new(&Arc::new(cfg));
    let mut conn = TcpStream::new(socket_fd).unwrap();

    let mut tls = rustls::Stream::new(&mut sess, &mut conn);
    let mut plaintext = [0u8; 1024]; //Vec::new();
    match tls.read(&mut plaintext) {
        Ok(_) => {
            /*
                TODO:
                1. Get public key from client
                2. Create encryption key 
                3. Encrypt seed
                4. Send to client
             */
            println!("Client said: {}", str::from_utf8(&plaintext).unwrap())
        },
        Err(e) => {
            println!("Error in read_to_end: {:?}", e);
            return;
        }
    };

    tls.write("hello back".as_bytes()).unwrap();
}

#[cfg(not(feature = "hardware_mode"))]
fn share_seed_inner(socket_fd: c_int, sign_type: sgx_quote_sign_type_t) {
    let mut conn = TcpStream::new(socket_fd).unwrap();

    let mut plaintext = [0u8; 1024]; //Vec::new();
    match conn.read(&mut plaintext) {
        Ok(_) => {
            /*
                TODO:
                1. Get public key from client
                2. Create encryption key 
                3. Encrypt seed
                4. Send to client
             */
            println!("Client said: {}", str::from_utf8(&plaintext).unwrap())
        },
        Err(e) => {
            println!("Error in read_to_end: {:?}", e);
            return;
        }
    };

    conn.write("hello back".as_bytes()).unwrap();
}

#[cfg(feature = "hardware_mode")]
fn get_server_configuration(sign_type: sgx_quote_sign_type_t) -> Result<rustls::ServerConfig, String> {
    // Generate Keypair
    let ecc_handle = SgxEccHandle::new();
    let _result = ecc_handle.open();
    let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();

    let signed_report = match super::utils::create_attestation_report(&pub_k, sign_type) {
        Ok(r) => r,
        Err(e) => {
            return Err(format!("Error creating attestation report"));
        }
    };

    let payload: String = match serde_json::to_string(&signed_report) {
        Ok(payload) => payload,
        Err(err) => {
            return Err(format!("Error serializing report. May be malformed, or badly encoded: {:?}", err));
        }
    };
    let (key_der, cert_der) = match super::cert::gen_ecc_cert(payload, &prv_k, &pub_k, &ecc_handle)
    {
        Ok(r) => r,
        Err(e) => {
            return Err(format!("Error in gen_ecc_cert: {:?}", e));
        }
    };
    let _result = ecc_handle.close();

    let mut cfg = rustls::ServerConfig::new(Arc::new(super::utils::ClientAuth::new(true)));
    let mut certs = Vec::new();
    certs.push(rustls::Certificate(cert_der));
    let privkey = rustls::PrivateKey(key_der);

    cfg.set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![])
        .unwrap();

    Ok(cfg)
}
