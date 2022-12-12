use sgx_evm::primitive_types::{H160, U256};
use protobuf::Message;

use crate::{UnmanagedVector, U8SliceView, GoError}; 
use crate::protobuf_generated::ffi;

#[repr(C)]
#[derive(Clone)]
pub struct GoQuerier {
    // pub state: *const querier_t,
    pub vtable: Querier_vtable,
}

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

impl GoQuerier {
    pub fn query_account(&self, account_address: &H160) -> (U256, U256) {
        println!("RUST: Query account for {:?}", account_address);

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

        println!("RUST: Request `GetAccount` sent");

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