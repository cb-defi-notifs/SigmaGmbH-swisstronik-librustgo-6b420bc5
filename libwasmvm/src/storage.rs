use std::collections::HashMap;

// use cosmwasm_std::{Order, Record};
// use cosmwasm_vm::{BackendError, BackendResult, GasInfo, Storage};

use crate::db::Db;
use crate::error::Error;
use crate::iterator::GoIter;
use crate::protobuf_generated::ffi;
use crate::{UnmanagedVector, U8SliceView, GoError}; 
use protobuf::Message;
use sgx_evm::primitive_types::{U256, H160};

pub struct GoStorage {
    db: Db,
    iterators: HashMap<u32, GoIter>,
}

impl GoStorage {
    pub fn new(db: Db) -> Self {
        GoStorage {
            db,
            iterators: HashMap::new(),
        }
    }
}

// impl Storage for GoStorage {
//     fn get(&self, key: &[u8]) -> BackendResult<Option<Vec<u8>>> {
//         let mut output = UnmanagedVector::default();
//         let mut error_msg = UnmanagedVector::default();
//         let mut used_gas = 0_u64;
//         let go_error: GoError = (self.db.vtable.read_db)(
//             self.db.state,
//             self.db.gas_meter,
//             &mut used_gas as *mut u64,
//             U8SliceView::new(Some(key)),
//             &mut output as *mut UnmanagedVector,
//             &mut error_msg as *mut UnmanagedVector,
//         )
//         .into();
//         // We destruct the UnmanagedVector here, no matter if we need the data.
//         let output = output.consume();
//
//         let gas_info = GasInfo::with_externally_used(used_gas);
//
//         // return complete error message (reading from buffer for GoError::Other)
//         let default = || {
//             format!(
//                 "Failed to read a key in the db: {}",
//                 String::from_utf8_lossy(key)
//             )
//         };
//         unsafe {
//             if let Err(err) = go_error.into_result(error_msg, default) {
//                 return (Err(err), gas_info);
//             }
//         }
//
//         (Ok(output), gas_info)
//     }
//
//     fn scan(
//         &mut self,
//         start: Option<&[u8]>,
//         end: Option<&[u8]>,
//         order: Order,
//     ) -> BackendResult<u32> {
//         let mut error_msg = UnmanagedVector::default();
//         let mut iter = GoIter::new(self.db.gas_meter);
//         let mut used_gas = 0_u64;
//         let go_error: GoError = (self.db.vtable.scan_db)(
//             self.db.state,
//             self.db.gas_meter,
//             &mut used_gas as *mut u64,
//             U8SliceView::new(start),
//             U8SliceView::new(end),
//             order.into(),
//             &mut iter as *mut GoIter,
//             &mut error_msg as *mut UnmanagedVector,
//         )
//         .into();
//         let gas_info = GasInfo::with_externally_used(used_gas);
//
//         // return complete error message (reading from buffer for GoError::Other)
//         let default = || {
//             format!(
//                 "Failed to read the next key between {:?} and {:?}",
//                 start.map(String::from_utf8_lossy),
//                 end.map(String::from_utf8_lossy),
//             )
//         };
//         unsafe {
//             if let Err(err) = go_error.into_result(error_msg, default) {
//                 return (Err(err), gas_info);
//             }
//         }
//
//         let next_id: u32 = self
//             .iterators
//             .len()
//             .try_into()
//             .expect("Iterator count exceeded uint32 range. This is a bug.");
//         self.iterators.insert(next_id, iter); // This moves iter. Is this okay?
//         (Ok(next_id), gas_info)
//     }
//
//     fn next(&mut self, iterator_id: u32) -> BackendResult<Option<Record>> {
//         let iterator = match self.iterators.get_mut(&iterator_id) {
//             Some(i) => i,
//             None => {
//                 return (
//                     Err(BackendError::iterator_does_not_exist(iterator_id)),
//                     GasInfo::free(),
//                 )
//             }
//         };
//         iterator.next()
//     }
//
//     fn set(&mut self, key: &[u8], value: &[u8]) -> BackendResult<()> {
//         let mut error_msg = UnmanagedVector::default();
//         let mut used_gas = 0_u64;
//         let go_error: GoError = (self.db.vtable.write_db)(
//             self.db.state,
//             self.db.gas_meter,
//             &mut used_gas as *mut u64,
//             U8SliceView::new(Some(key)),
//             U8SliceView::new(Some(value)),
//             &mut error_msg as *mut UnmanagedVector,
//         )
//         .into();
//         let gas_info = GasInfo::with_externally_used(used_gas);
//         // return complete error message (reading from buffer for GoError::Other)
//         let default = || {
//             format!(
//                 "Failed to set a key in the db: {}",
//                 String::from_utf8_lossy(key),
//             )
//         };
//         unsafe {
//             if let Err(err) = go_error.into_result(error_msg, default) {
//                 return (Err(err), gas_info);
//             }
//         }
//         (Ok(()), gas_info)
//     }
//
//     fn remove(&mut self, key: &[u8]) -> BackendResult<()> {
//         let mut error_msg = UnmanagedVector::default();
//         let mut used_gas = 0_u64;
//         let go_error: GoError = (self.db.vtable.remove_db)(
//             self.db.state,
//             self.db.gas_meter,
//             &mut used_gas as *mut u64,
//             U8SliceView::new(Some(key)),
//             &mut error_msg as *mut UnmanagedVector,
//         )
//         .into();
//         let gas_info = GasInfo::with_externally_used(used_gas);
//         let default = || {
//             format!(
//                 "Failed to delete a key in the db: {}",
//                 String::from_utf8_lossy(key),
//             )
//         };
//         unsafe {
//             if let Err(err) = go_error.into_result(error_msg, default) {
//                 return (Err(err), gas_info);
//             }
//         }
//         (Ok(()), gas_info)
//     }
// }

// this represents something passed in from the caller side of FFI
#[repr(C)]
#[derive(Clone)]
pub struct querier_t {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Clone)]
pub struct Querier_vtable {
    // We return errors through the return buffer, but may return non-zero error codes on panic
    pub query_external: extern "C" fn(
        u64,
        *mut u64,
        U8SliceView,
        *mut UnmanagedVector, // result output
        *mut UnmanagedVector, // error message output
    ) -> i32,
}

#[repr(C)]
#[derive(Clone)]
pub struct GoQuerier {
    // pub state: *const querier_t,
    pub vtable: Querier_vtable,
}

impl GoQuerier {
    pub fn query_account(&self, account_address: &H160) -> (U256, U256) {
        let mut output = UnmanagedVector::default();
        let mut error_msg = UnmanagedVector::default();
        
        // Used gas and gas limit will be removed in the nearest future
        let mut used_gas = 0_u64;
        let gas_limit = 1000_u64;

        // Encode request
        let mut request = ffi::QueryGetAccount::new();
        request.set_address(account_address.as_bytes().to_vec());
        let request_bytes = request.write_to_bytes().unwrap();

        let go_result: GoError = (self.vtable.query_external)(
            gas_limit,
            &mut used_gas as *mut u64,
            U8SliceView::new(Some(request_bytes.as_slice())),
            &mut output as *mut UnmanagedVector,
            &mut error_msg as *mut UnmanagedVector,
        ).into();

        println!("Request `GetAccount` sent");

        (U256::default(), U256::default())
    }

    pub fn query_raw(
        &self,
        request: &[u8],
        gas_limit: u64,
    ) {
        let mut output = UnmanagedVector::default();
        let mut error_msg = UnmanagedVector::default();
        let mut used_gas = 0_u64;
        let go_result: GoError = (self.vtable.query_external)(
            gas_limit,
            &mut used_gas as *mut u64,
            U8SliceView::new(Some(request)),
            &mut output as *mut UnmanagedVector,
            &mut error_msg as *mut UnmanagedVector,
        )
        .into();

        println!("RUST: query called");
        // // We destruct the UnmanagedVector here, no matter if we need the data.
        // let output = output.consume();

        // let gas_info = GasInfo::with_externally_used(used_gas);

        // // return complete error message (reading from buffer for GoError::Other)
        // let default = || {
        //     format!(
        //         "Failed to query another contract with this request: {}",
        //         String::from_utf8_lossy(request)
        //     )
        // };
        // unsafe {
        //     if let Err(err) = go_result.into_result(error_msg, default) {
        //         return (Err(err), gas_info);
        //     }
        // }

        // let bin_result: Vec<u8> = output.unwrap_or_default();
        // let result = serde_json::from_slice(&bin_result).or_else(|e| {
        //     Ok(SystemResult::Err(SystemError::InvalidResponse {
        //         error: format!("Parsing Go response: {}", e),
        //         response: bin_result.into(),
        //     }))
        // });
        // (result, gas_info)
    }
}