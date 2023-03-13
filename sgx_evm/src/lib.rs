use std::panic::catch_unwind;
use crate::error::{Error};
use crate::protobuf_generated::ffi::{
    FFIRequest, FFIRequest_oneof_req, HandleTransactionResponse, Log, Topic,
};
use protobuf::Message;

mod error;
mod protobuf_generated;

#[no_mangle]
/// Handles incoming protobuf-encoded request for transaction handling
pub fn handle_request(req_bytes: Vec<u8>) {
    let result = match FFIRequest::parse_from_bytes(&req_bytes) {
        Ok(request) => {
            if let Some(req) = request.req {
                match req {
                    FFIRequest_oneof_req::callRequest(req) => {
                        // let execution_result = evm::handle_sgxvm_call(querier, req);
                        //
                        // // Create protobuf-encoded response
                        // let mut response = HandleTransactionResponse::new();
                        // response.set_gas_used(execution_result.gas_used);
                        // response.set_vm_error(execution_result.vm_error);
                        // response.set_ret(execution_result.data);
                        //
                        // // Convert logs into proper format
                        // let converted_logs = execution_result
                        //     .logs
                        //     .into_iter()
                        //     .map(|log| {
                        //         let mut proto_log = Log::new();
                        //         proto_log.set_address(log.address.as_fixed_bytes().to_vec());
                        //         proto_log.set_data(log.data);
                        //
                        //         let converted_topics: Vec<Topic> = log
                        //             .topics
                        //             .into_iter()
                        //             .map(convert_topic_to_proto)
                        //             .collect();
                        //         proto_log.set_topics(converted_topics.into());
                        //
                        //         proto_log
                        //     })
                        //     .collect();
                        //
                        // response.set_logs(converted_logs);
                        //
                        // // Convert to bytes and return it
                        // let response_bytes = match response.write_to_bytes() {
                        //     Ok(res) => res,
                        //     Err(_) => {
                        //         return Err(Error::protobuf_decode("Response encoding failed"));
                        //     }
                        // };

                        let response_bytes = Vec::<u8>::new();
                        Ok(response_bytes)
                    }
                    FFIRequest_oneof_req::createRequest(req) => {
                        // let execution_result = evm::handle_sgxvm_create(querier, req);
                        //
                        // // Create protobuf-encoded response
                        // let mut response = HandleTransactionResponse::new();
                        // response.set_gas_used(execution_result.gas_used);
                        // response.set_vm_error(execution_result.vm_error);
                        // response.set_ret(execution_result.data);
                        //
                        // // Convert logs into proper format
                        // let converted_logs = execution_result
                        //     .logs
                        //     .into_iter()
                        //     .map(|log| {
                        //         let mut proto_log = Log::new();
                        //         proto_log.set_address(log.address.as_fixed_bytes().to_vec());
                        //         proto_log.set_data(log.data);
                        //
                        //         let converted_topics: Vec<Topic> = log
                        //             .topics
                        //             .into_iter()
                        //             .map(convert_topic_to_proto)
                        //             .collect();
                        //         proto_log.set_topics(converted_topics.into());
                        //
                        //         proto_log
                        //     })
                        //     .collect();
                        //
                        // response.set_logs(converted_logs);
                        //
                        // // Convert to bytes and return it
                        // let response_bytes = match response.write_to_bytes() {
                        //     Ok(res) => res,
                        //     Err(_) => {
                        //         return Err(Error::protobuf_decode("Response encoding failed"));
                        //     }
                        // };

                        let response_bytes = Vec::<u8>::new();
                        Ok(response_bytes)
                    }
                }
            } else {
                Err(Error::protobuf_decode("Request unwrapping failed"))
            }
        }
        Err(e) => Err(Error::protobuf_decode(e.to_string())),
    };
}

#[no_mangle]
/// Debug function that used to check if data was passed correctly via FFI
pub fn handle_debug(_: Vec<u8>) -> Vec<u8> {
    vec![1, 2, 3, 4]
}
