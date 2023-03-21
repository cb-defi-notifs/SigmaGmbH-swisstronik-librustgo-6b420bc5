#![no_std]

#[macro_use]
extern crate sgx_tstd as std;

extern crate sgx_types;
use sgx_types::sgx_status_t;

use internal_types::ExecutionResult;
use protobuf::Message;
use protobuf::RepeatedField;
use sgxvm::{self, Vicinity};
use sgxvm::primitive_types::{H160, H256, U256};
use std::panic::catch_unwind;
use std::vec::Vec;
use std::slice;
use std::ptr;

use crate::error::{handle_c_error_default, Error};
use crate::protobuf_generated::ffi::{
    AccessListItem, FFIRequest, FFIRequest_oneof_req, HandleTransactionResponse, Log,
    SGXVMCallRequest, SGXVMCreateRequest, Topic, TransactionContext as ProtoTransactionContext,
};
use crate::memory::{ByteSliceView, UnmanagedVector};
use crate::querier::GoQuerier;

mod error;
mod protobuf_generated;
mod backend;
mod coder;
mod storage;
mod memory;
mod querier;
mod ocall;

pub const MAX_RESULT_LEN: usize = 4096;

#[no_mangle]
/// Handles incoming protobuf-encoded request for transaction handling
pub extern "C" fn handle_request(
    querier: *mut GoQuerier,
    request_data: *const u8,
    len: usize,
    output: *mut u8,
    _: usize,
    actual_output_len: *mut u32,
) -> sgx_types::sgx_status_t {
    let request_slice = unsafe { slice::from_raw_parts(request_data, len) }; 

    let ffi_request = match protobuf::parse_from_bytes::<FFIRequest>(request_slice) {
        Ok(ffi_request) => ffi_request,
        Err(err) => {
            println!("Got error during protobuf decoding: {:?}", err);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    match ffi_request.req {
        Some(req) => {
            let execution_result = match req {
                FFIRequest_oneof_req::callRequest(data) => {
                    println!("Got call request");
                    handle_call_request(querier, data)
                },
                FFIRequest_oneof_req::createRequest(data) => {
                    println!("Got create request");
                    handle_create_request(querier, data)
                }
            };

            let response = HandleTransactionResponse::new();
            response.set_gas_used(execution_result.gas_used);
            response.set_vm_error(execution_result.vm_error);
            response.set_ret(execution_result.data);
            response.set_logs(execution_result.logs);
            let encoded_response = match response.write_to_bytes() {
                Ok(res) => res,
                Err(err) => {
                    println!("Cannot encode protobuf result");
                    return sgx_status_t::SGX_ERROR_UNEXPECTED;
                }
            };

            unsafe {
                ptr::copy_nonoverlapping(encoded_response.as_ptr(), output, encoded_response.len());
            };
        },
        None => {
            println!("Got empty request during protobuf decoding");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    }
    
    sgx_status_t::SGX_SUCCESS
}

fn handle_call_request(querier: *mut GoQuerier, data: SGXVMCallRequest) -> ExecutionResult {
    let params = data.params.unwrap();
    let context = data.context.unwrap();

    let vicinity = Vicinity { origin: H160::from_slice(&params.from) };
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

    let vicinity = Vicinity { origin: H160::from_slice(&params.from) };
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
        let slots = access_list_item.storageSlot
            .to_vec()
            .into_iter()
            .map(|item| { H256::from_slice(&item) })
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
