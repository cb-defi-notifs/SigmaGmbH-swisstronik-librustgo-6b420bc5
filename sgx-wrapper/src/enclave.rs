use crate::errors::GoError;
use crate::memory::{U8SliceView, UnmanagedVector, ByteSliceView};
use crate::types::{Allocation, AllocationWithResult, GoQuerier};
use crate::errors::{handle_c_error_default, Error};
use crate::protobuf_generated::{self, node};

use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::io::IntoRawFd;
use std::slice;
use std::panic::catch_unwind;
use protobuf::Message;

static ENCLAVE_FILE: &'static str = "/tmp/enclave.signed.so";
pub static mut ENCLAVE_ID: Option<sgx_types::sgx_enclave_id_t> = None;

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

    pub fn ecall_init_seed_node(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
    ) -> sgx_status_t;

    pub fn ecall_init_node(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
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
            Ok(r) => {r},
            Err(err) => { 
                println!("Got error: {:?}", err.as_str());
                return Err(Error::vm_err("Cannot initialize SGXVM enclave")) 
            },
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
                            sgx_status_t::SGX_SUCCESS => {},
                            _ => { 
                                return Err(Error::enclave_error(res.as_str()));
                            }
                        };

                        match retval {
                            sgx_status_t::SGX_SUCCESS => {},
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
                    },
                    node::SetupRequest_oneof_req::setupRegularNode(req) => {
                        let mut retval = sgx_status_t::SGX_SUCCESS;
                        let res = ecall_init_node(evm_enclave.geteid(), &mut retval);
                        
                        match res {
                            sgx_status_t::SGX_SUCCESS => {},
                            _ => { 
                                return Err(Error::enclave_error(res.as_str()));
                            }
                        };

                        match retval {
                            sgx_status_t::SGX_SUCCESS => {},
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
                } 
            },
            None => {
                Err(Error::protobuf_decode("Request unwrapping failed"))
            }
        };

        // Destroy enclave after usage and set enclave id to None
        evm_enclave.destroy();
        crate::enclave::ENCLAVE_ID = None;

        // TODO: Decode protobuf
        result
    })
    .unwrap_or_else(|_| Err(Error::panic()));

    let data = handle_c_error_default(r, error_msg);
    UnmanagedVector::new(Some(data))
}