use sgx_evm::evm::backend::Basic;
use sgx_evm::primitive_types::{H160, U256, H256};
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

fn u256_to_vec(value: U256) -> Vec<u8> {
    let mut buffer = [0u8; 32];
    value.to_big_endian(&mut buffer);
    buffer.to_vec()
}

impl GoQuerier {

    pub fn query_block_hash(&self, number: U256) -> H256 {
        println!("[Rust] query block hash");
        let mut cosmos_request = ffi::CosmosRequest::new();
        let mut request = ffi::QueryBlockHash::new();
        request.set_number(u256_to_vec(number));
        cosmos_request.set_blockHash(request);
        let request_bytes = cosmos_request.write_to_bytes().unwrap();

        let query_result = self.query_raw(request_bytes);
        match query_result {
            Ok(raw_result) => {
                match ffi::QueryBlockHashResponse::parse_from_bytes(&raw_result) {
                    Ok(result) => {
                        return match result.get_hash().is_empty() {
                            true => {
                                println!("[Rust] query_block_hash: hash is empty");
                               H256::default()
                            }
                            false => H256::from_slice(result.get_hash())
                        }
                    },
                    Err(err) => {
                        println!("[Rust] query_block_hash: cannot decode protobuf: {:?}", err);
                        return H256::default()
                    }
                }
            },
            Err(err) => {
                println!("[Rust] query_block_hash: got error: {:?}", err);
                return H256::default()
            }
        }

    }
    pub fn query_block_number(&self) -> U256 {
        println!("[Rust] query block number");
        U256::default()
    }

    pub fn query_block_timestamp(&self) -> U256 {
        println!("[Rust] query block timestamp");
        U256::default()
    }

    pub fn query_chain_id(&self) -> U256 {
        println!("[Rust] query chain id");
        U256::default()
    }


    /// Queries account balance and nonce from the network
    /// * account_address - 20-bytes ethereum account address
    pub fn query_account(&self, account_address: &H160) -> (U256, U256) {
        println!("[Rust] query account");
        let mut cosmos_request = ffi::CosmosRequest::new();
        let mut request = ffi::QueryGetAccount::new();
        request.set_address(account_address.as_bytes().to_vec());
        cosmos_request.set_getAccount(request);
        let request_bytes = cosmos_request.write_to_bytes().unwrap();

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

    /// Checks if DB contains provided address
    /// * account_address - 20-bytes ethereum account address
    pub fn query_contains_key(&self, account_address: &H160) -> bool {
        println!("[Rust] query contains key");
        let mut cosmos_request = ffi::CosmosRequest::new();
        let mut request = ffi::QueryContainsKey::new();
        request.set_key(account_address.as_bytes().to_vec());
        cosmos_request.set_containsKey(request);
        let request_bytes = cosmos_request.write_to_bytes().unwrap();

        let query_result = self.query_raw(request_bytes);
        match query_result {
            Ok(raw_result) => {
                match ffi::QueryContainsKeyResponse::parse_from_bytes(&raw_result) {
                    Ok(result) => return result.contains,
                    Err(err) => {
                        println!("[Rust] query_contains_key: cannot decode protobuf: {:?}", err);
                        return false;
                    }
                }
            },
            Err(err) => {
                println!("[Rust] query_contains_key: got error: {:?}", err);
                return false;
            }
        }
    }

    /// Queries value contained in specific storage cell
    /// * account_address – 20-bytes ethereum account address
    /// * index – 32-bytes index of a slot, where value is stored
    pub fn query_account_storage_cell(&self, account_address: &H160, index: &H256) -> Option<H256> {
        println!("[Rust] query storage cell");
        let mut cosmos_request = ffi::CosmosRequest::new();
        let mut request = ffi::QueryGetAccountStorageCell::new();
        request.set_address(account_address.as_bytes().to_vec());
        request.set_index(index.as_bytes().to_vec());
        cosmos_request.set_storageCell(request);
        let request_bytes = cosmos_request.write_to_bytes().unwrap();

        let query_result = self.query_raw(request_bytes);
        match query_result {
            Ok(raw_result) => {
                match ffi::QueryGetAccountStorageCellResponse::parse_from_bytes(&raw_result) {
                    Ok(result) => {
                        match result.get_value().is_empty() {
                            true => return None,
                            false => return Some(H256::from_slice(result.get_value()))
                        }
                    },
                    Err(err) => {
                        println!("[Rust] query_account_storage_cell: cannot decode protobuf: {:?}", err);
                        return None;
                    }
                }
            },
            Err(err) => {
                println!("[Rust] query_account_storage_cell: got error: {:?}", err);
                return None;
            }
        }
    }

    pub fn query_account_code(&self, account_address: &H160) -> Option<Vec<u8>> {
        println!("[Rust] query account code");
        let mut cosmos_request = ffi::CosmosRequest::new();
        let mut request = ffi::QueryGetAccountCode::new();
        request.set_address(account_address.as_bytes().to_vec());
        cosmos_request.set_accountCode(request);
        let request_bytes = cosmos_request.write_to_bytes().unwrap();

        let query_result = self.query_raw(request_bytes);
        match query_result {
            Ok(raw_result) => {
                match ffi::QueryGetAccountCodeResponse::parse_from_bytes(&raw_result) {
                    Ok(result) => {
                        match result.get_code().is_empty() {
                            true => return None,
                            false => return Some(result.get_code().to_vec())
                        }
                    },
                    Err(err) => {
                        println!("[Rust] query_account_code: cannot decode protobuf: {:?}", err);
                        return None;
                    }
                }
            },
            Err(err) => {
                println!("[Rust] query_account_code: got error: {:?}", err);
                return None;
            }
        }
    }

    pub fn insert_account(&self, account_address: H160, data: Basic) {
        println!("[Rust] query insert account");
        let mut cosmos_request = ffi::CosmosRequest::new();
        let mut request = ffi::QueryInsertAccount::new();
        request.set_address(account_address.as_bytes().to_vec());
        request.set_balance(u256_to_vec(data.balance));
        request.set_nonce(u256_to_vec(data.nonce));
        cosmos_request.set_insertAccount(request);
        let request_bytes = cosmos_request.write_to_bytes().unwrap();

        let query_result = self.query_raw(request_bytes);
        match query_result {
            Ok(raw_result) => {
                match ffi::QueryInsertAccountResponse::parse_from_bytes(&raw_result) {
                    Err(err) => {
                        println!("[Rust] insert_account: cannot decode protobuf: {:?}", err);
                    },
                    _ => {}
                }
            },
            Err(err) => {
                println!("[Rust] insert_account: got error: {:?}", err);
            }
        }
    }

    pub fn insert_account_code(&self, account_address: H160, code: Vec<u8>) {
        println!("[Rust] query insert account code");
        let mut cosmos_request = ffi::CosmosRequest::new();
        let mut request = ffi::QueryInsertAccountCode::new();
        request.set_address(account_address.as_bytes().to_vec());
        request.set_code(code);
        cosmos_request.set_insertAccountCode(request);
        let request_bytes = cosmos_request.write_to_bytes().unwrap();

        let query_result = self.query_raw(request_bytes);
        match query_result {
            Ok(raw_result) => {
                match ffi::QueryInsertAccountCodeResponse::parse_from_bytes(&raw_result) {
                    Err(err) => {
                        println!("[Rust] insert_account_code: cannot decode protobuf: {:?}", err);
                    },
                    _ => {}
                }
            },
            Err(err) => {
                println!("[Rust] insert_account_code: got error: {:?}", err);
            }
        }
    }

    pub fn insert_storage_cell(&self, account_address: H160, index: H256, value: H256) {
        println!("[Rust] query insert storage cell");
        let mut cosmos_request = ffi::CosmosRequest::new();
        let mut request = ffi::QueryInsertStorageCell::new();
        request.set_address(account_address.as_bytes().to_vec());
        request.set_index(index.as_bytes().to_vec());
        request.set_value(value.as_bytes().to_vec());
        cosmos_request.set_insertStorageCell(request);
        let request_bytes = cosmos_request.write_to_bytes().unwrap();

        let query_result = self.query_raw(request_bytes);
        match query_result {
            Ok(raw_result) => {
                match ffi::QueryInsertStorageCellResponse::parse_from_bytes(&raw_result) {
                    Err(err) => {
                        println!("[Rust] insert_storage_cell: cannot decode protobuf: {:?}", err);
                    },
                    _ => {}
                }
            },
            Err(err) => {
                println!("[Rust] insert_storage_cell: got error: {:?}", err);
            }
        }
    }

    pub fn remove(&self, account_address: &H160) {
        println!("[Rust] query remove");
        let mut cosmos_request = ffi::CosmosRequest::new();
        let mut request = ffi::QueryRemove::new();
        request.set_address(account_address.as_bytes().to_vec());
        cosmos_request.set_remove(request);
        let request_bytes = cosmos_request.write_to_bytes().unwrap();

        let query_result = self.query_raw(request_bytes);
        match query_result {
            Ok(raw_result) => {
                match ffi::QueryRemoveResponse::parse_from_bytes(&raw_result) {
                    Err(err) => {
                        println!("[Rust] remove: cannot decode protobuf: {:?}", err);
                    },
                    _ => {}
                }
            },
            Err(err) => {
                println!("[Rust] remove: got error: {:?}", err);
            }
        }
    }

    pub fn remove_account_code(&self, account_address: &H160) {
        println!("[Rust] query account code");
        let mut cosmos_request = ffi::CosmosRequest::new();
        let mut request = ffi::QueryRemoveAccountCode::new();
        request.set_address(account_address.as_bytes().to_vec());
        cosmos_request.set_removeAccountCode(request);
        let request_bytes = cosmos_request.write_to_bytes().unwrap();

        let query_result = self.query_raw(request_bytes);
        match query_result {
            Ok(raw_result) => {
                match ffi::QueryRemoveAccountCodeResponse::parse_from_bytes(&raw_result) {
                    Err(err) => {
                        println!("[Rust] remove_account_code: cannot decode protobuf: {:?}", err);
                    },
                    _ => {}
                }
            },
            Err(err) => {
                println!("[Rust] remove_account_code: got error: {:?}", err);
            }
        }
    }

    pub fn remove_storage_cell(&self, account_address: &H160, index: &H256) {
        println!("[Rust] query remove storage cell");
        let mut cosmos_request = ffi::CosmosRequest::new();
        let mut request = ffi::QueryRemoveStorageCell::new();
        request.set_address(account_address.as_bytes().to_vec());
        request.set_index(index.as_bytes().to_vec());
        cosmos_request.set_removeStorageCell(request);
        let request_bytes = cosmos_request.write_to_bytes().unwrap();

        let query_result = self.query_raw(request_bytes);
        match query_result {
            Ok(raw_result) => {
                match ffi::QueryRemoveStorageCellResponse::parse_from_bytes(&raw_result) {
                    Err(err) => {
                        println!("[Rust] remove_storage_cell: cannot decode protobuf: {:?}", err);
                    },
                    _ => {}
                }
            },
            Err(err) => {
                println!("[Rust] remove_storage_cell: got error: {:?}", err);
            }
        }
    }

    pub fn remove_storage(&self, account_address: &H160) {
        println!("[Rust] query remove storage");
        let mut cosmos_request = ffi::CosmosRequest::new();
        let mut request = ffi::QueryRemoveStorage::new();
        request.set_address(account_address.as_bytes().to_vec());
        cosmos_request.set_removeStorage(request);
        let request_bytes = cosmos_request.write_to_bytes().unwrap();

        let query_result = self.query_raw(request_bytes);
        match query_result {
            Ok(raw_result) => {
                match ffi::QueryRemoveStorageResponse::parse_from_bytes(&raw_result) {
                    Err(err) => {
                        println!("[Rust] remove_storage_cell: cannot decode protobuf: {:?}", err);
                    },
                    _ => {}
                }
            },
            Err(err) => {
                println!("[Rust] remove_storage_cell: got error: {:?}", err);
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
