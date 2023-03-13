use internal_types::ExecutionResult;
use protobuf::Message;
use protobuf::RepeatedField;
use sgxvm::{self, Vicinity};
use sgxvm::primitive_types::{H160, H256, U256};
use std::panic::catch_unwind;

use crate::error::{handle_c_error_default, Error};
use crate::protobuf_generated::ffi::{
    AccessListItem, FFIRequest, FFIRequest_oneof_req, HandleTransactionResponse, Log,
    SGXVMCallRequest, SGXVMCreateRequest, Topic, TransactionContext as ProtoTransactionContext,
};
use crate::memory::{ByteSliceView, UnmanagedVector};

mod error;
mod protobuf_generated;
mod backend;
mod ocall;
mod coder;
mod storage;
mod memory;
mod querier;

// store some common string for argument names
pub const PB_REQUEST_ARG: &str = "pb_request";

#[no_mangle]
// TODO: Remove after debugging
pub fn handle_debug(_: Vec<u8>) -> Vec<u8> {
    vec![1, 2, 3, 4]
}

#[no_mangle]
/// Handles incoming protobuf-encoded request for transaction handling
pub fn handle_request(
    // q: querier::GoQuerier,
    request: ByteSliceView,
    error_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {
    let r = catch_unwind(|| {
        let req_bytes = request
            .read()
            .ok_or_else(|| Error::unset_arg(PB_REQUEST_ARG))?;

        match FFIRequest::parse_from_bytes(&req_bytes) {
            Ok(request) => {
                if let Some(req) = request.req {
                    match req {
                        FFIRequest_oneof_req::callRequest(req) => {
                            let execution_result = handle_call_request(req);

                            // Create protobuf-encoded response
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

                                    let converted_topics: Vec<Topic> = log
                                        .topics
                                        .into_iter()
                                        .map(convert_topic_to_proto)
                                        .collect();
                                    proto_log.set_topics(converted_topics.into());

                                    proto_log
                                })
                                .collect();

                            response.set_logs(converted_logs);

                            // Convert to bytes and return it
                            let response_bytes = match response.write_to_bytes() {
                                Ok(res) => res,
                                Err(_) => {
                                    return Err(Error::protobuf_decode("Response encoding failed"));
                                }
                            };

                            let response_bytes = Vec::<u8>::new();
                            Ok(response_bytes)
                        }
                        FFIRequest_oneof_req::createRequest(req) => {
                            let execution_result = handle_create_request(req);

                            // Create protobuf-encoded response
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

                                    let converted_topics: Vec<Topic> = log
                                        .topics
                                        .into_iter()
                                        .map(convert_topic_to_proto)
                                        .collect();
                                    proto_log.set_topics(converted_topics.into());

                                    proto_log
                                })
                                .collect();

                            response.set_logs(converted_logs);

                            // Convert to bytes and return it
                            let response_bytes = match response.write_to_bytes() {
                                Ok(res) => res,
                                Err(_) => {
                                    return Err(Error::protobuf_decode("Response encoding failed"));
                                }
                            };

                            let response_bytes = Vec::<u8>::new();
                            Ok(response_bytes)
                        }
                    }
                } else {
                    Err(Error::protobuf_decode("Request unwrapping failed"))
                }
            }
            Err(e) => Err(Error::protobuf_decode(e.to_string())),
        }
    }).unwrap_or_else(|_| Err(Error::panic()));

    let data = handle_c_error_default(r, error_msg);
    UnmanagedVector::new(Some(data))
}

fn handle_call_request(data: SGXVMCallRequest) -> ExecutionResult {
    let params = data.params.unwrap();
    let context = data.context.unwrap();

    let vicinity = Vicinity { origin: H160::from_slice(&params.from) };
    let mut storage = crate::storage::FFIStorage::new();
    let mut backend = backend::FFIBackend::new(
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

fn handle_create_request(data: SGXVMCreateRequest) -> ExecutionResult {
    let params = data.params.unwrap();
    let context = data.context.unwrap();

    let vicinity = Vicinity { origin: H160::from_slice(&params.from) };
    let mut storage = crate::storage::FFIStorage::new();
    let mut backend = backend::FFIBackend::new(
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
