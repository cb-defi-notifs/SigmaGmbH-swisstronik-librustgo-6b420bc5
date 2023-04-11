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
    println!("Sharing seed...");

    // Generate Keypair
    let ecc_handle = SgxEccHandle::new();
    let _result = ecc_handle.open();
    let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();

    let signed_report = match super::utils::create_attestation_report(&pub_k, sign_type) {
        Ok(r) => r,
        Err(e) => {
            println!("Error creating attestation report");
            return;
        }
    };

    let payload: String = match serde_json::to_string(&signed_report) {
        Ok(payload) => payload,
        Err(err) => {
            println!(
                "Error serializing report. May be malformed, or badly encoded: {:?}",
                err
            );
            return;
        }
    };
    let (key_der, cert_der) = match super::cert::gen_ecc_cert(payload, &prv_k, &pub_k, &ecc_handle)
    {
        Ok(r) => r,
        Err(e) => {
            println!("Error in gen_ecc_cert: {:?}", e);
            return;
        }
    };
    let _result = ecc_handle.close();

    let mut cfg = rustls::ServerConfig::new(Arc::new(super::utils::ClientAuth::new(true)));
    let mut certs = Vec::new();
    certs.push(rustls::Certificate(cert_der));
    let privkey = rustls::PrivateKey(key_der);

    cfg.set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![])
        .unwrap();

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
