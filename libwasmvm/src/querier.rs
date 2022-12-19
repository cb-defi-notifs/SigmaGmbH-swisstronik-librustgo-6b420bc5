use sgx_evm::primitive_types::{H160, U256};
use protobuf::Message;

use crate::{UnmanagedVector, U8SliceView, GoError}; 
use crate::protobuf_generated::ffi;

#[repr(C)]
#[derive(Clone)]
pub struct GoQuerier {
    pub state: *const querier_t,
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
        *const querier_t,
        U8SliceView,
        *mut UnmanagedVector, // result output
        *mut UnmanagedVector, // error message output
    ) -> i32,
}

impl GoQuerier {
    /// Queries account balance and nonce from the network
    /// * account_address - 20-bytes ethereum account address
    pub fn query_account(&self, account_address: &H160) -> (U256, U256) {        
        let mut request = ffi::QueryGetAccount::new();
        request.set_address(account_address.as_bytes().to_vec());
        let request_bytes = request.write_to_bytes().unwrap();

        let query_result = self.query_raw(request_bytes);
        match query_result {
            Ok(raw_result) => {
                match ffi::QueryGetAccountResponse::parse_from_bytes(&raw_result) {
                    Ok(result) => {
                        let balance = U256::from_big_endian(result.get_balance());
                        let nonce = U256::from_big_endian(result.get_nonce());
                        println!("[Rust] query_account: got balance: {:?}, nonce: {:?}", balance, nonce);
                        return (balance, nonce)
                    },
                    Err(err) => {
                        println!("[Rust] query_account: cannot decode protobuf: {:?}", err);
                        return(U256::default(), U256::default());
                    }
                }
            },
            Err(err) => {
                println!("[Rust] query_account: got error: {:?}", err);
                return(U256::default(), U256::default())
            }
        }
    }

    fn query_raw(
        &self,
        request: Vec<u8>,
    ) -> Result<Vec<u8>, GoError> {
        let mut output = UnmanagedVector::default();
        let mut error_msg = UnmanagedVector::default();

        let go_result: GoError = (self.vtable.query_external)(
            self.state,
            U8SliceView::new(Some(&request)),
            &mut output as *mut UnmanagedVector,
            &mut error_msg as *mut UnmanagedVector,
        )
        .into();

        let output = output.consume();
        let error_msg = error_msg.consume();

        match go_result {
            GoError::None => {
                Ok(output.unwrap_or_default())
            },
            _ => {
                let err_msg = error_msg.unwrap_or_default();
                println!(
                    "[Rust] query_raw: got error: {:?} with message: {:?}", 
                    go_result, 
                    String::from_utf8_lossy(&err_msg)
                );
                Err(go_result)
            }
        }
    }
}