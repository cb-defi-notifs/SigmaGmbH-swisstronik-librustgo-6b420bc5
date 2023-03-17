use std::collections::HashSet;
use std::marker::PhantomData;
use std::panic::catch_unwind;

use crate::memory::{ByteSliceView, UnmanagedVector};
use crate::querier::GoQuerier;

// store some common string for argument names
pub const PB_REQUEST_ARG: &str = "pb_request";

extern "C" {
    fn handle_request(querier: *mut GoQuerier, request: ByteSliceView, error_msg: Option<&mut UnmanagedVector>) -> UnmanagedVector;
}

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
    let querier_boxed: Box<GoQuerier> = Box::new(querier);
    unsafe { handle_request(Box::into_raw(querier_boxed), request, error_msg) }
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
