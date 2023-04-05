use crate::errors::GoError;
use crate::errors::{handle_c_error_default, Error};
use crate::memory::{ByteSliceView, U8SliceView, UnmanagedVector};
use crate::protobuf_generated::{self, node};
use crate::types::{Allocation, AllocationWithResult, GoQuerier};

use protobuf::Message;
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::io::{AsRawFd, IntoRawFd};
use std::panic::catch_unwind;
use std::slice;

static ENCLAVE_FILE: &'static str = "/tmp/enclave.signed.so";
pub static mut ENCLAVE_ID: Option<sgx_types::sgx_enclave_id_t> = None;

pub const API_KEY_SIZE: usize = 32;

#[allow(dead_code)]
extern "C" {
    pub fn handle_request(
        eid: sgx_enclave_id_t,
        retval: *mut AllocationWithResult,
        querier: *mut GoQuerier,
        request: *const u8,
        len: usize,
    ) -> sgx_status_t;

    pub fn ecall_allocate(
        eid: sgx_enclave_id_t,
        retval: *mut Allocation,
        data: *const u8,
        len: usize,
    ) -> sgx_status_t;

    pub fn ecall_init_seed_node(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;

    pub fn ecall_init_node(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;

    pub fn ecall_create_report(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        api_key: *const u8,
    ) -> sgx_status_t;

    pub fn ecall_start_seed_server(
        eid: sgx_enclave_id_t,
        socket_fd: c_int,
        sign_type: sgx_quote_sign_type_t,
    ) -> sgx_status_t;

    pub fn ecall_request_seed(
        eid: sgx_enclave_id_t,
        socket_fd: c_int,
        sign_type: sgx_quote_sign_type_t,
    ) -> sgx_status_t;
}

pub fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    // call sgx_create_enclave to initialize an enclave instance
    let mut launch_token_updated: i32 = 0;
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    )
}

#[no_mangle]
/// Handles all incoming protobuf-encoded requests related to node setup
/// such as generating of attestation certificate, keys, etc.
pub unsafe extern "C" fn handle_initialization_request(
    request: ByteSliceView,
    error_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {
    let r = catch_unwind(|| {
        // Check if request is correct
        let req_bytes = request
            .read()
            .ok_or_else(|| Error::unset_arg(crate::cache::PB_REQUEST_ARG))?;

        // Initialize enclave
        let evm_enclave = match crate::enclave::init_enclave() {
            Ok(r) => r,
            Err(err) => {
                println!("Got error: {:?}", err.as_str());
                return Err(Error::vm_err("Cannot initialize SGXVM enclave"));
            }
        };
        // Set enclave id to static variable to make it accessible across inner ecalls
        crate::enclave::ENCLAVE_ID = Some(evm_enclave.geteid());

        let request = match protobuf::parse_from_bytes::<node::SetupRequest>(req_bytes) {
            Ok(request) => request,
            Err(e) => {
                return Err(Error::protobuf_decode(e.to_string()));
            }
        };

        let result = match request.req {
            Some(req) => {
                match req {
                    node::SetupRequest_oneof_req::setupSeedNode(req) => {
                        let mut retval = sgx_status_t::SGX_SUCCESS;
                        let res = ecall_init_seed_node(evm_enclave.geteid(), &mut retval);

                        match res {
                            sgx_status_t::SGX_SUCCESS => {}
                            _ => {
                                return Err(Error::enclave_error(res.as_str()));
                            }
                        };

                        match retval {
                            sgx_status_t::SGX_SUCCESS => {}
                            _ => {
                                return Err(Error::enclave_error(res.as_str()));
                            }
                        }

                        // Create response, convert it to bytes and return
                        let mut response = node::SetupSeedNodeRequest::new();
                        let response_bytes = match response.write_to_bytes() {
                            Ok(res) => res,
                            Err(_) => {
                                return Err(Error::protobuf_decode("Response encoding failed"));
                            }
                        };

                        Ok(response_bytes)
                    }
                    node::SetupRequest_oneof_req::setupRegularNode(req) => {
                        let mut retval = sgx_status_t::SGX_SUCCESS;
                        let res = ecall_init_node(evm_enclave.geteid(), &mut retval);

                        match res {
                            sgx_status_t::SGX_SUCCESS => {}
                            _ => {
                                return Err(Error::enclave_error(res.as_str()));
                            }
                        };

                        match retval {
                            sgx_status_t::SGX_SUCCESS => {}
                            _ => {
                                return Err(Error::enclave_error(res.as_str()));
                            }
                        }

                        // Create response, convert it to bytes and return
                        let mut response = node::SetupRegularNodeResponse::new();
                        let response_bytes = match response.write_to_bytes() {
                            Ok(res) => res,
                            Err(_) => {
                                return Err(Error::protobuf_decode("Response encoding failed"));
                            }
                        };

                        Ok(response_bytes)
                    }
                    node::SetupRequest_oneof_req::createAttestationReport(req) => {
                        let api_key = req.apiKey;
                        if api_key.len() != API_KEY_SIZE {
                            return Err(Error::enclave_error("Wrong length of api key"));
                        }

                        let mut retval = sgx_status_t::SGX_SUCCESS;
                        let res = ecall_create_report(
                            evm_enclave.geteid(),
                            &mut retval,
                            api_key.as_ptr(),
                        );

                        match res {
                            sgx_status_t::SGX_SUCCESS => {}
                            _ => {
                                return Err(Error::enclave_error(res.as_str()));
                            }
                        };

                        match retval {
                            sgx_status_t::SGX_SUCCESS => {}
                            _ => {
                                return Err(Error::enclave_error(res.as_str()));
                            }
                        }

                        // Create response, convert it to bytes and return
                        let mut response = node::CreateAttestationReportResponse::new();
                        let response_bytes = match response.write_to_bytes() {
                            Ok(res) => res,
                            Err(_) => {
                                return Err(Error::protobuf_decode("Response encoding failed"));
                            }
                        };

                        Ok(response_bytes)
                    }
                    node::SetupRequest_oneof_req::startSeedServer(req) => {
                        println!("SGX_WRAPPER: starting seed server");
                        let sign_type = sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE;
                        let listener = TcpListener::bind("0.0.0.0:3443").unwrap();
                        match listener.accept() {
                            Ok((socket, addr)) => {
                                println!("Got new connection {:?}", addr);
                                let res = ecall_start_seed_server(
                                    evm_enclave.geteid(),
                                    socket.as_raw_fd(),
                                    sign_type,
                                );

                                match res {
                                    sgx_status_t::SGX_SUCCESS => {}
                                    _ => {
                                        return Err(Error::enclave_error(res.as_str()));
                                    }
                                };

                                // Create response, convert it to bytes and return
                                let mut response = node::StartSeedServerResponse::new();
                                let response_bytes = match response.write_to_bytes() {
                                    Ok(res) => res,
                                    Err(_) => {
                                        return Err(Error::protobuf_decode(
                                            "Response encoding failed",
                                        ));
                                    }
                                };

                                Ok(response_bytes)
                            }
                            Err(e) => Err(Error::enclave_error(
                                "Cannot establish connection with client",
                            )),
                        }
                    }
                    node::SetupRequest_oneof_req::nodeSeed(req) => {
                        println!("Trying to get seed...");
                        let socket = TcpStream::connect("localhost:3443").unwrap();
                        let sign_type = sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE;
                        let res = ecall_request_seed(
                            evm_enclave.geteid(), 
                            socket.as_raw_fd(), 
                            sign_type
                        );

                        match res {
                            sgx_status_t::SGX_SUCCESS => {}
                            _ => {
                                return Err(Error::enclave_error(res.as_str()));
                            }
                        };

                        // Create response, convert it to bytes and return
                        let mut response = node::NodeSeedResponse::new();
                        let response_bytes = match response.write_to_bytes() {
                            Ok(res) => res,
                            Err(_) => {
                                return Err(Error::protobuf_decode("Response encoding failed"));
                            }
                        };

                        Ok(response_bytes)
                    }
                }
            }
            None => Err(Error::protobuf_decode("Request unwrapping failed")),
        };

        // Destroy enclave after usage and set enclave id to None
        evm_enclave.destroy();
        crate::enclave::ENCLAVE_ID = None;

        result
    })
    .unwrap_or_else(|_| Err(Error::panic()));

    let data = handle_c_error_default(r, error_msg);
    UnmanagedVector::new(Some(data))
}
