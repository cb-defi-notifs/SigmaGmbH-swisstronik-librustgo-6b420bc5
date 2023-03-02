#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate sgx_tstd as std;

use ethereum::Log;
use std::{vec::Vec, string::String};
use rlp_derive::{RlpEncodable, RlpDecodable};

pub mod ffi;

#[derive(Clone, Debug, RlpEncodable, RlpDecodable, PartialEq)]
pub struct ExecutionResult {
    pub logs: Vec<Log>,
    pub data: Vec<u8>,
    pub gas_used: u64,
    pub vm_error: String
}

impl ExecutionResult {
    /// Creates execution result that only contains error reason and possible amount of used gas
    pub fn from_error(reason: String, data: Vec<u8>, gas_used: Option<u64>) -> Self {
        Self {
            logs: Vec::default(),
            data: data,
            gas_used: gas_used.unwrap_or(21000), // This is minimum gas fee to apply the transaction
            vm_error: reason
        }
    }
}

#[cfg(test)]
mod tests {
    use ethereum::Log;
    use primitive_types::{H160, H256};
    use rlp::Encodable;
    use crate::ExecutionResult;

    #[test]
    fn exec_result_encoding_and_decoding() {    
        // Prepare execution result
        let log = Log {
            address: H160::default(),
            data: vec![1u8, 1u8, 1u8],
            topics: vec![H256::default()],
        };

        let execution_result = ExecutionResult {
            logs: vec![log],
            gas_used: 1000u64,
            data: vec![255u8],
            vm_error: "reverted".to_string(),
        };

        // Encode and decode
        let encoded_data = execution_result.rlp_bytes().to_vec();
        let decoded_execution_result: ExecutionResult = rlp::decode(encoded_data.as_slice())
            .expect("Cannot decode encoded execution result");

        assert_eq!(execution_result, decoded_execution_result);
        println!("decoded: {:?}", decoded_execution_result);
    }
}