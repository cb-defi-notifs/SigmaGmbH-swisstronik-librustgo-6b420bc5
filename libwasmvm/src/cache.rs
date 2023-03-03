use std::collections::HashSet;
use std::marker::PhantomData;
use std::panic::catch_unwind;

// use cosmwasm_vm::{capabilities_from_csv, Cache, CacheOptions, Checksum, Size};

use protobuf::Message;
use sgx_evm::primitive_types::H256;

use crate::error::{handle_c_error_default, Error};
use crate::evm;
use crate::memory::{ByteSliceView, UnmanagedVector};
use crate::protobuf_generated::ffi::{
    FFIRequest, FFIRequest_oneof_req, HandleTransactionResponse, Log, Topic,
};
use crate::querier::GoQuerier;

// store some common string for argument names
pub const PB_REQUEST_ARG: &str = "pb_request";

#[repr(C)]
#[allow(dead_code)]
pub struct cache_t {}

#[allow(dead_code)]
pub struct Cache {
    querier: PhantomData<GoQuerier>,
}

pub fn to_cache(ptr: *mut cache_t) -> Option<&'static mut Cache> {
    if ptr.is_null() {
        None
    } else {
        let c = unsafe { &mut *(ptr as *mut Cache) };
        Some(c)
    }
}

#[no_mangle]
pub extern "C" fn make_pb_request(
    querier: GoQuerier,
    request: ByteSliceView,
    error_msg: Option<&mut UnmanagedVector>,
) -> UnmanagedVector {
    let r = catch_unwind(|| {
        let req_bytes = request
            .read()
            .ok_or_else(|| Error::unset_arg(PB_REQUEST_ARG))?;
        match FFIRequest::parse_from_bytes(req_bytes) {
            Ok(request) => {
                if let Some(req) = request.req {
                    match req {
                        FFIRequest_oneof_req::callRequest(req) => {
                            let execution_result = evm::handle_sgxvm_call(querier, req);

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

                            Ok(response_bytes)
                        },
                        FFIRequest_oneof_req::createRequest(req) => {
                            let execution_result = evm::handle_sgxvm_create(querier, req);

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

                            Ok(response_bytes)
                        },
                    }
                } else {
                    Err(Error::protobuf_decode("Request unwrapping failed"))
                }
            }
            Err(e) => Err(Error::protobuf_decode(e.to_string())),
        }
    })
    .unwrap_or_else(|_| Err(Error::panic()));

    let data = handle_c_error_default(r, error_msg);
    UnmanagedVector::new(Some(data))
}

fn convert_topic_to_proto(topic: H256) -> Topic {
    let mut protobuf_topic = Topic::new();
    protobuf_topic.set_inner(topic.as_fixed_bytes().to_vec());

    protobuf_topic
}

fn _set_to_csv(set: HashSet<String>) -> String {
    let mut list: Vec<String> = set.into_iter().collect();
    list.sort_unstable();
    list.join(",")
}

/// frees a cache reference
///
/// # Safety
///
/// This must be called exactly once for any `*cache_t` returned by `init_cache`
/// and cannot be called on any other pointer.
// #[no_mangle]
// pub extern "C" fn release_cache(cache: *mut cache_t) {
//     if !cache.is_null() {
//         // this will free cache when it goes out of scope
//         let _ = unsafe { Box::from_raw(cache as *mut Cache<GoApi, GoStorage, GoQuerier>) };
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use std::iter::FromIterator;

    #[test]
    fn set_to_csv_works() {
        assert_eq!(_set_to_csv(HashSet::new()), "");
        assert_eq!(
            _set_to_csv(HashSet::from_iter(vec!["foo".to_string()])),
            "foo",
        );
        assert_eq!(
            _set_to_csv(HashSet::from_iter(vec![
                "foo".to_string(),
                "bar".to_string(),
                "baz".to_string(),
            ])),
            "bar,baz,foo",
        );
        assert_eq!(
            _set_to_csv(HashSet::from_iter(vec![
                "a".to_string(),
                "aa".to_string(),
                "b".to_string(),
                "c".to_string(),
                "A".to_string(),
                "AA".to_string(),
                "B".to_string(),
                "C".to_string(),
            ])),
            "A,AA,B,C,a,aa,b,c",
        );
    }
}
