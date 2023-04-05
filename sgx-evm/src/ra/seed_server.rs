use sgx_rand::*;
use sgx_tcrypto::*;
use sgx_tse::*;
use sgx_types::*;
use std::backtrace::{self, PrintFormat};

use itertools::Itertools;
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

struct ClientAuth {
    outdated_ok: bool,
}

impl ClientAuth {
    fn new(outdated_ok: bool) -> ClientAuth {
        ClientAuth{ outdated_ok : outdated_ok }
    }
}

impl rustls::ClientCertVerifier for ClientAuth {
    fn client_auth_root_subjects(&self, _sni: Option<&webpki::DNSName>) -> Option<rustls::DistinguishedNames> {
        Some(rustls::DistinguishedNames::new())
    }

    fn verify_client_cert(&self, _certs: &[rustls::Certificate], _sni: Option<&webpki::DNSName>)
    -> Result<rustls::ClientCertVerified, rustls::TLSError> {
        println!("client cert: {:?}", _certs);
            // This call will automatically verify cert is properly signed
            match super::cert::verify_mra_cert(&_certs[0].0) {
                Ok(()) => {
                    return Ok(rustls::ClientCertVerified::assertion());
                }
                Err(sgx_status_t::SGX_ERROR_UPDATE_NEEDED) => {
                    if self.outdated_ok {
                        println!("outdated_ok is set, overriding outdated error");
                        return Ok(rustls::ClientCertVerified::assertion());
                    } else {
                        return Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid));
                    }
                }
                Err(_) => {
                    return Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid));
                }
            }
    }
}

struct ServerAuth {
    outdated_ok: bool
}

impl ServerAuth {
    fn new(outdated_ok: bool) -> ServerAuth {
        ServerAuth{ outdated_ok : outdated_ok }
    }
}

impl rustls::ServerCertVerifier for ServerAuth {
    fn verify_server_cert(&self,
              _roots: &rustls::RootCertStore,
              _certs: &[rustls::Certificate],
              _hostname: webpki::DNSNameRef,
              _ocsp: &[u8]) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
    println!("server cert: {:?}", _certs);
        // This call will automatically verify cert is properly signed
        match super::cert::verify_mra_cert(&_certs[0].0) {
            Ok(()) => {
                return Ok(rustls::ServerCertVerified::assertion());
            }
            Err(sgx_status_t::SGX_ERROR_UPDATE_NEEDED) => {
                if self.outdated_ok {
                    println!("outdated_ok is set, overriding outdated error");
                    return Ok(rustls::ServerCertVerified::assertion());
                } else {
                    return Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid));
                }
            }
            Err(_) => {
                return Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid));
            }
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn ecall_start_seed_server(
    socket_fd: c_int, 
    sign_type: sgx_quote_sign_type_t
) {
    println!("Starting seed server...");
    
    // Generate Keypair
    let ecc_handle = SgxEccHandle::new();
    let _result = ecc_handle.open();
    let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();

    let (attn_report, sig, cert) = match super::utils::create_attestation_report(&pub_k, sign_type) {
        Ok(r) => r,
        Err(e) => {
            println!("Error in create_attestation_report: {:?}", e);
            return;
        }
    };

    let payload = attn_report + "|" + &sig + "|" + &cert;
    let (key_der, cert_der) = match super::cert::gen_ecc_cert(payload, &prv_k, &pub_k, &ecc_handle) {
        Ok(r) => r,
        Err(e) => {
            println!("Error in gen_ecc_cert: {:?}", e);
            return;
        }
    };
    let _result = ecc_handle.close();


    let mut cfg = rustls::ServerConfig::new(Arc::new(ClientAuth::new(true)));
    let mut certs = Vec::new();
    certs.push(rustls::Certificate(cert_der));
    let privkey = rustls::PrivateKey(key_der);

    cfg.set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![]).unwrap();

    let mut sess = rustls::ServerSession::new(&Arc::new(cfg));
    let mut conn = TcpStream::new(socket_fd).unwrap();

    let mut tls = rustls::Stream::new(&mut sess, &mut conn);
    let mut plaintext = [0u8;1024]; //Vec::new();
    match tls.read(&mut plaintext) {
        Ok(_) => println!("Client said: {}", str::from_utf8(&plaintext).unwrap()),
        Err(e) => {
            println!("Error in read_to_end: {:?}", e);
            return;
        }
    };

    tls.write("hello back".as_bytes()).unwrap();
}