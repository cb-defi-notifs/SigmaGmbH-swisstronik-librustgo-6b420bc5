use std::collections::HashSet;
use std::panic::{catch_unwind};

// use cosmwasm_vm::{capabilities_from_csv, Cache, CacheOptions, Checksum, Size};

use protobuf::Message;

use crate::evm;
use crate::args::{PB_REQUEST_ARG};
use crate::error::{ handle_c_error_default, Error};
use crate::memory::{ByteSliceView, UnmanagedVector};
use crate::protobuf_generated::ffi::{FFIRequest, FFIRequest_oneof_req, HandleTransactionResponse};

//
// #[repr(C)]
// pub struct cache_t {}
//
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
                            println!("RUST: handleTransaction invoked");

                            let execution_result = evm::handle_transaction_mocked(tx);
                            println!("RUST: handleTransaction result: {:?}", execution_result);

                            let mut response = HandleTransactionResponse::new();
                            response.set_hash("0x12341234".to_string());

                            let response_bytes = match response.write_to_bytes() {
                                Ok(res) => res,
                                Err(_) => {
                                    return Err(Error::protobuf_decode("Response encoding failed"));
                                }
                            };

                            println!("RUST: handleTransaction trying to return unmanaged vector");

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

//
// #[no_mangle]
// pub extern "C" fn init_cache(
//     data_dir: ByteSliceView,
//     available_capabilities: ByteSliceView,
//     cache_size: u32,            // in MiB
//     instance_memory_limit: u32, // in MiB
//     error_msg: Option<&mut UnmanagedVector>,
// ) -> *mut cache_t {
//     let r = catch_unwind(|| {
//         do_init_cache(
//             data_dir,
//             available_capabilities,
//             cache_size,
//             instance_memory_limit,
//         )
//     })
//     .unwrap_or_else(|_| Err(Error::panic()));
//     handle_c_error_ptr(r, error_msg) as *mut cache_t
// }
//
// fn do_init_cache(
//     data_dir: ByteSliceView,
//     available_capabilities: ByteSliceView,
//     cache_size: u32,            // in MiB
//     instance_memory_limit: u32, // in MiB
// ) -> Result<*mut Cache<GoApi, GoStorage, GoQuerier>, Error> {
//     let dir = data_dir
//         .read()
//         .ok_or_else(|| Error::unset_arg(DATA_DIR_ARG))?;
//     let dir_str = String::from_utf8(dir.to_vec())?;
//     // parse the supported features
//     let capabilities_bin = available_capabilities
//         .read()
//         .ok_or_else(|| Error::unset_arg(AVAILABLE_CAPABILITIES_ARG))?;
//     let capabilities = capabilities_from_csv(from_utf8(capabilities_bin)?);
//     let memory_cache_size = Size::mebi(
//         cache_size
//             .try_into()
//             .expect("Cannot convert u32 to usize. What kind of system is this?"),
//     );
//     let instance_memory_limit = Size::mebi(
//         instance_memory_limit
//             .try_into()
//             .expect("Cannot convert u32 to usize. What kind of system is this?"),
//     );
//     let options = CacheOptions {
//         base_dir: dir_str.into(),
//         available_capabilities: capabilities,
//         memory_cache_size,
//         instance_memory_limit,
//     };
//     let cache = unsafe { Cache::new(options) }?;
//     let out = Box::new(cache);
//     Ok(Box::into_raw(out))
// }

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
