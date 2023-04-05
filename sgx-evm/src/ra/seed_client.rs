use sgx_rand::*;
use sgx_tcrypto::*;
use sgx_tse::*;
use sgx_types::*;
use std::backtrace::{self, PrintFormat};

use itertools::Itertools;
use rustls;
use std::io;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::prelude::v1::*;
use std::ptr;
use std::str;
use std::string::String;
use std::sync::Arc;
use std::untrusted::fs;
use std::vec::Vec;

#[no_mangle]
pub extern "C" fn ecall_request_seed(socket_fd: c_int, sign_type: sgx_quote_sign_type_t) {
    // Generate Keypair
    let ecc_handle = SgxEccHandle::new();
    ecc_handle.open().unwrap();
    let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();

    let (attn_report, sig, cert) = match super::utils::create_attestation_report(&pub_k, sign_type)
    {
        Ok(r) => r,
        Err(e) => {
            println!("Error in create_attestation_report: {:?}", e);
            return;
        }
    };

    let payload = attn_report + "|" + &sig + "|" + &cert;

    let (key_der, cert_der) = match super::cert::gen_ecc_cert(payload, &prv_k, &pub_k, &ecc_handle)
    {
        Ok(r) => r,
        Err(e) => {
            println!("Error in gen_ecc_cert: {:?}", e);
            return;
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

    let dns_name = webpki::DNSNameRef::try_from_ascii_str("localhost").unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(cfg), dns_name);
    let mut conn = TcpStream::new(socket_fd).unwrap();

    let mut tls = rustls::Stream::new(&mut sess, &mut conn);

    tls.write("hello".as_bytes()).unwrap();

    let mut plaintext = Vec::new();
    match tls.read_to_end(&mut plaintext) {
        Ok(_) => {
            println!("Server replied: {}", str::from_utf8(&plaintext).unwrap());
        }
        Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
            println!("EOF (tls)");
        }
        Err(e) => println!("Error in read_to_end: {:?}", e),
    }
}
