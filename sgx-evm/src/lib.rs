#![no_std]
#![feature(slice_as_chunks)]

#[macro_use]
extern crate sgx_tstd as std;
extern crate rustls;

extern crate sgx_types;
use sgx_types::sgx_status_t;

use internal_types::ExecutionResult;
use protobuf::Message;
use protobuf::RepeatedField;
use sgxvm::primitive_types::{H160, H256, U256};
use sgxvm::{self, Vicinity};
// use std::panic::catch_unwind;
// use std::ptr;
use std::slice;
use std::vec::Vec;

// use crate::error::{handle_c_error_default, Error};
// use crate::memory::{ByteSliceView, UnmanagedVector};
use crate::protobuf_generated::ffi::{
    AccessListItem, FFIRequest, FFIRequest_oneof_req, HandleTransactionResponse, Log,
    SGXVMCallRequest, SGXVMCreateRequest, Topic, TransactionContext as ProtoTransactionContext, NodePublicKeyResponse,
};
use crate::querier::GoQuerier;

mod backend;
mod coder;
mod error;
mod memory;
mod ocall;
mod protobuf_generated;
mod querier;
mod storage;
mod encryption;
mod attestation;
mod key_manager;

pub const MAX_RESULT_LEN: usize = 4096;

#[repr(C)]
pub struct AllocationWithResult {
    pub result_ptr: *mut u8,
    pub result_len: usize,
    pub status: sgx_status_t
}

impl Default for AllocationWithResult {
    fn default() -> Self {
        AllocationWithResult {
            result_ptr: std::ptr::null_mut(),
            result_len: 0,
            status: sgx_status_t::SGX_ERROR_UNEXPECTED,
        }
    }
}

#[repr(C)]
pub struct Allocation {
    pub result_ptr: *mut u8,
    pub result_size: usize,
}

#[no_mangle]
/// Checks if there is already sealed master key
pub unsafe extern "C" fn ecall_is_initialized() -> i32 {
    if let Err(err) = key_manager::KeyManager::unseal() {
        println!("[Enclave] Cannot restore master key. Reason: {:?}", err.as_str());
        return false as i32
    }
    true as i32
} 

#[no_mangle]
pub extern "C" fn ecall_allocate(
    data: *const u8,
    len: usize,
) -> Allocation {
    // TODO: In case of any errors check: https://github.com/scrtlabs/SecretNetwork/blob/8e157399de55c8e9c3f9a05d2d23e259dae24095/cosmwasm/enclaves/shared/contract-engine/src/external/ecalls.rs#L41
    let slice = unsafe { slice::from_raw_parts(data, len) };
    let mut vector_copy = slice.to_vec();

    let ptr = vector_copy.as_mut_ptr();
    let size = vector_copy.len();
    std::mem::forget(vector_copy); // TODO: Need to clean that memory

    Allocation { result_ptr: ptr, result_size: size }
}

#[no_mangle]
/// Handles incoming protobuf-encoded request
pub extern "C" fn handle_request(
    querier: *mut GoQuerier,
    request_data: *const u8,
    len: usize,
) -> AllocationWithResult {
    let request_slice = unsafe { slice::from_raw_parts(request_data, len) };

    let ffi_request = match protobuf::parse_from_bytes::<FFIRequest>(request_slice) {
        Ok(ffi_request) => ffi_request,
        Err(err) => {
            println!("Got error during protobuf decoding: {:?}", err);
            return AllocationWithResult::default();
        }
    };

    match ffi_request.req {
        Some(req) => {
            match req {
                FFIRequest_oneof_req::callRequest(data) => {
                    let res = handle_call_request(querier, data);
                    post_transaction_handling(res)
                },
                FFIRequest_oneof_req::createRequest(data) => {
                    let res = handle_create_request(querier, data);
                    post_transaction_handling(res)
                },
                FFIRequest_oneof_req::publicKeyRequest(_) => {
                    let res = encryption::x25519_get_public_key();
                    match res {
                        Ok(res) => {
                            let mut response = NodePublicKeyResponse::new();
                            response.set_publicKey(res);

                            let encoded_response = match response.write_to_bytes() {
                                Ok(res) => res,
                                Err(err) => {
                                    println!("Cannot encode protobuf result");
                                    return AllocationWithResult::default();
                                }
                            };
                            
                            let mut ocall_result = std::mem::MaybeUninit::<Allocation>::uninit();
                            let sgx_result = unsafe { 
                                ocall::ocall_allocate(
                                    ocall_result.as_mut_ptr(),
                                    encoded_response.as_ptr(),
                                    encoded_response.len()
                                ) 
                            };
                            match sgx_result {
                                sgx_status_t::SGX_SUCCESS => {
                                    let ocall_result = unsafe { ocall_result.assume_init() };
                                    AllocationWithResult {
                                        result_ptr: ocall_result.result_ptr,
                                        result_len: encoded_response.len(),
                                        status: sgx_status_t::SGX_SUCCESS
                                    }
                                },
                                _ => {
                                    println!("ocall_allocate failed: {:?}", sgx_result.as_str());
                                    AllocationWithResult::default()
                                }
                            }
                        },
                        Err(err) => {
                            println!("Cannot obtain node public key. Reason: {:?}", err);
                            return AllocationWithResult::default();
                        }
                    }
                }
            }
        }
        None => {
            println!("Got empty request during protobuf decoding");
            AllocationWithResult::default()
        }
    }
}

fn post_transaction_handling(execution_result: ExecutionResult) -> AllocationWithResult {
    let mut response = HandleTransactionResponse::new();
    response.set_gas_used(execution_result.gas_used);
    response.set_vm_error(execution_result.vm_error);
    response.set_ret(execution_result.data);

    // Convert logs into proper format
    let converted_logs = execution_result
        .logs
        .into_iter()
        .map(|log| {
            let mut proto_log = Log::new();
            proto_log.set_address(log.address.as_fixed_bytes().to_vec());
            proto_log.set_data(log.data);

            let converted_topics: Vec<Topic> =
                log.topics.into_iter().map(convert_topic_to_proto).collect();
            proto_log.set_topics(converted_topics.into());

            proto_log
        })
        .collect();

    response.set_logs(converted_logs);

    let encoded_response = match response.write_to_bytes() {
        Ok(res) => res,
        Err(err) => {
            println!("Cannot encode protobuf result");
            return AllocationWithResult::default();
        }
    };
    
    let mut ocall_result = std::mem::MaybeUninit::<Allocation>::uninit();
    let sgx_result = unsafe { 
        ocall::ocall_allocate(
            ocall_result.as_mut_ptr(),
            encoded_response.as_ptr(),
            encoded_response.len()
        ) 
    };
    match sgx_result {
        sgx_status_t::SGX_SUCCESS => {
            let ocall_result = unsafe { ocall_result.assume_init() };
            AllocationWithResult {
                result_ptr: ocall_result.result_ptr,
                result_len: encoded_response.len(),
                status: sgx_status_t::SGX_SUCCESS
            }
        },
        _ => {
            println!("ocall_allocate failed: {:?}", sgx_result.as_str());
            AllocationWithResult::default()
        }
    }
}

fn handle_call_request(querier: *mut GoQuerier, data: SGXVMCallRequest) -> ExecutionResult {
    let params = data.params.unwrap();
    let context = data.context.unwrap();

    let vicinity = Vicinity {
        origin: H160::from_slice(&params.from),
    };
    let mut storage = crate::storage::FFIStorage::new(querier);
    let mut backend = backend::FFIBackend::new(
        querier,
        &mut storage,
        vicinity,
        build_transaction_context(context),
    );

    sgxvm::handle_sgxvm_call(
        &mut backend,
        params.gasLimit,
        H160::from_slice(&params.from),
        H160::from_slice(&params.to),
        U256::from_big_endian(&params.value),
        params.data,
        parse_access_list(params.accessList),
        params.commit,
    )
}

fn handle_create_request(querier: *mut GoQuerier, data: SGXVMCreateRequest) -> ExecutionResult {
    let params = data.params.unwrap();
    let context = data.context.unwrap();

    let vicinity = Vicinity {
        origin: H160::from_slice(&params.from),
    };
    let mut storage = crate::storage::FFIStorage::new(querier);
    let mut backend = backend::FFIBackend::new(
        querier,
        &mut storage,
        vicinity,
        build_transaction_context(context),
    );

    sgxvm::handle_sgxvm_create(
        &mut backend,
        params.gasLimit,
        H160::from_slice(&params.from),
        U256::from_big_endian(&params.value),
        params.data,
        parse_access_list(params.accessList),
        params.commit,
    )
}

fn parse_access_list(data: RepeatedField<AccessListItem>) -> Vec<(H160, Vec<H256>)> {
    let mut access_list = Vec::default();
    for access_list_item in data.to_vec() {
        let address = H160::from_slice(&access_list_item.address);
        let slots = access_list_item
            .storageSlot
            .to_vec()
            .into_iter()
            .map(|item| H256::from_slice(&item))
            .collect();

        access_list.push((address, slots));
    }

    access_list
}

fn build_transaction_context(context: ProtoTransactionContext) -> backend::TxContext {
    backend::TxContext {
        chain_id: U256::from(context.chain_id),
        gas_price: U256::from_big_endian(&context.gas_price),
        block_number: U256::from(context.block_number),
        timestamp: U256::from(context.timestamp),
        block_gas_limit: U256::from(context.block_gas_limit),
        block_base_fee_per_gas: U256::from_big_endian(&context.block_base_fee_per_gas),
        block_coinbase: H160::from_slice(&context.block_coinbase),
    }
}

fn convert_topic_to_proto(topic: H256) -> Topic {
    let mut protobuf_topic = Topic::new();
    protobuf_topic.set_inner(topic.as_fixed_bytes().to_vec());

    protobuf_topic
}
