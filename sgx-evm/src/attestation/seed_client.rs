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

#[no_mangle]
pub extern "C" fn ecall_request_seed(socket_fd: c_int, sign_type: sgx_quote_sign_type_t) {
    request_seed_inner(socket_fd, sign_type);
}

#[cfg(feature = "hardware_mode")]
fn request_seed_inner(socket_fd: c_int, sign_type: sgx_quote_sign_type_t) {
    let cfg = match get_client_configuration(sign_type) {
        Ok(cfg) => cfg,
        Err(err) => {
            println!("{}", err);
            return;
        }
    };

    let dns_name = webpki::DNSNameRef::try_from_ascii_str("localhost").unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(cfg), dns_name);
    let mut conn = TcpStream::new(socket_fd).unwrap();

    let mut tls = rustls::Stream::new(&mut sess, &mut conn);

    // TODO: Send registration public key
    tls.write("hello".as_bytes()).unwrap();

    let mut plaintext = Vec::new();
    match tls.read_to_end(&mut plaintext) {
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
}

#[cfg(not(feature = "hardware_mode"))] 
fn request_seed_inner(socket_fd: c_int, _sign_type: sgx_quote_sign_type_t) {
    let mut conn = TcpStream::new(socket_fd).unwrap();
    // TODO: Send registration public key
    conn.write("hello".as_bytes()).unwrap();

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
}

#[cfg(feature = "hardware_mode")]
fn get_client_configuration(sign_type: sgx_quote_sign_type_t) -> Result<rustls::ClientConfig, String> {
    // Generate Keypair
    let ecc_handle = SgxEccHandle::new();
    ecc_handle.open().unwrap();
    let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();

    let signed_report =
        match super::utils::create_attestation_report(&pub_k, sign_type) {
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
