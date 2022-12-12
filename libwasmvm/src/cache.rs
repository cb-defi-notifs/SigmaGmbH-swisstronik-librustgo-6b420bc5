use std::collections::HashSet;
use std::marker::PhantomData;
use std::panic::{catch_unwind};

// use cosmwasm_vm::{capabilities_from_csv, Cache, CacheOptions, Checksum, Size};

use protobuf::Message;

use crate::evm;
use crate::args::{PB_REQUEST_ARG};
use crate::error::{ handle_c_error_default, handle_c_error_ptr, Error};
use crate::memory::{ByteSliceView, UnmanagedVector};
use crate::protobuf_generated::ffi::{FFIRequest, FFIRequest_oneof_req, HandleTransactionResponse, self};
use crate::storage::GoQuerier;


#[repr(C)]
pub struct cache_t {}

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

// pub fn to_cache(ptr: *mut cache_t) -> Option<&'static mut Cache<GoApi, GoStorage, GoQuerier>> {
//     if ptr.is_null() {
//         None
//     } else {
//         let c = unsafe { &mut *(ptr as *mut Cache<GoApi, GoStorage, GoQuerier>) };
//         Some(c)
//     }
// }

#[no_mangle]
pub extern "C" fn make_pb_request(
    querier: GoQuerier, // TODO: Will be used soon
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
                        FFIRequest_oneof_req::handleTransaction(tx) => {
                            // Execute provided transaction
                            let execution_result = evm::handle_transaction(tx);

                            // Create protobuf-encoded response
                            let mut response = HandleTransactionResponse::new();
                            response.set_gas_used(execution_result.gas_used);
                            response.set_vm_error(execution_result.vm_error);
                            response.set_ret(execution_result.data);

                            // Convert logs into proper format
                            let converted_logs = execution_result.logs
                                .into_iter()
                                .map(|log| {
                                    let mut proto_log = ffi::Log::new();
                                    proto_log.set_address(log.address.to_string());
                                    proto_log.set_data(log.data);

                                    let converted_topics: Vec<String> = log.topics.into_iter().map(|topic| topic.to_string()).collect();
                                    proto_log.set_topics(converted_topics.into());

                                    return proto_log
                                }).collect();

                            response.set_logs(converted_logs);

                            // Convert to bytes and return it
                            let response_bytes = match response.write_to_bytes() {
                                Ok(res) => res,
                                Err(_) => {
                                    return Err(Error::protobuf_decode("Response encoding failed"));
                                }
                            };
                            
                            let request = [1u8; 32];
                            let gas_limit = 1000;
                            querier.query_raw(&request, gas_limit);

                            return Ok(response_bytes)
                        }
                    }
                } else {
                    return Err(Error::protobuf_decode("Request unwrapping failed"));
                }
            },
            Err(e) => {
                return Err(Error::protobuf_decode(e.to_string()))
            }
        }
    }).unwrap_or_else(|_| Err(Error::panic()));

    let data = handle_c_error_default(r, error_msg);
    UnmanagedVector::new(Some(data))
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
