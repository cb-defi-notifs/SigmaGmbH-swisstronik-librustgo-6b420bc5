use sgx_types::sgx_status_t;
use sgxvm::evm::backend::Basic;
use sgxvm::primitive_types::{H160, H256, U256};
use sgxvm::storage::Storage;
use std::vec::Vec;

use crate::protobuf_generated::ffi;
use crate::querier::GoQuerier;
use crate::ocall;
use crate::coder;

/// This struct allows us to obtain state from keeper
/// that is located outside of Rust code
pub struct FFIStorage {
    pub querier: *mut GoQuerier,
}

impl Storage for FFIStorage {
    fn contains_key(&self, key: &H160) -> bool {
        // TODO: Get data using OCALL
        // self.querier.query_contains_key(key)
        false
    }

    fn get_account_storage_cell(&self, key: &H160, index: &H256) -> Option<H256> {
        // TODO: Get data using OCALL
        // self.querier.query_account_storage_cell(key, index)
        None
    }

    fn get_account_code(&self, key: &H160) -> Option<Vec<u8>> {
        // TODO: Get data using OCALL
        // self.querier.query_account_code(key)
        None
    }

    fn get_account(&self, key: &H160) -> Basic {
        println!("Get account called");

        let encoded_request = coder::encode_get_account(key);
        if let Some(result) = ocall::make_request(self.querier, encoded_request) {
            // Decode protobuf
            let decoded_result = match protobuf::parse_from_bytes::<ffi::QueryGetAccountResponse>(result.as_slice()) {
                Ok(res) => res,
                Err(err) => {
                    println!("Cannot decode protobuf response: {:?}", err);
                    return Basic {
                        balance: U256::default(),
                        nonce: U256::default(),
                    };
                }
            };
            return Basic {
                balance: U256::from_big_endian(decoded_result.balance.as_slice()),
                nonce: U256::from(decoded_result.nonce),
            };
        } else {
            return Basic {
                balance: U256::default(),
                nonce: U256::default(),
            };
        }
    }

    fn insert_account(&mut self, key: H160, data: Basic) {
        // TODO: Get data using OCALL
        // self.querier.insert_account(key, data);
    }

    fn insert_account_code(&mut self, key: H160, code: Vec<u8>) {
        // TODO: Get data using OCALL
        // self.querier.insert_account_code(key, code);
    }

    fn insert_storage_cell(&mut self, key: H160, index: H256, value: H256) {
        // TODO: Get data using OCALL
        // self.querier.insert_storage_cell(key, index, value);
    }

    fn remove(&mut self, key: &H160) {
        // TODO: Get data using OCALL
        // self.querier.remove(key);
    }

    fn remove_storage_cell(&mut self, key: &H160, index: &H256) {
        // TODO: Get data using OCALL
        // self.querier.remove_storage_cell(key, index);
    }
}

impl FFIStorage {
    pub fn new(querier: *mut GoQuerier) -> Self {
        Self {querier}
    }
}
