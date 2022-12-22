use sgx_evm::evm::backend::Basic;
use sgx_evm::primitive_types::{H160, H256, U256};
use sgx_evm::storage::Storage;
use std::{collections::BTreeMap, str::FromStr};

use crate::querier::GoQuerier;

/// This struct allows us to obtain state from keeper
/// that is located outside of Rust code
pub struct FFIStorage<'a> {
    querier: &'a GoQuerier,
}

impl Storage for FFIStorage {
    fn contains_key(&self, key: &H160) -> bool {
        self.querier.query_contains_key(key)
    }

    fn get_account_storage_cell(&self, key: &H160, index: &H256) -> Option<H256> {
        self.querier.query_account_storage_cell(key, index)
    }

    fn get_account_code(&self, key: &H160) -> Option<Vec<u8>> {
        self.querier.query_account_code(key)
    }

    fn get_account(&self, key: &H160) -> Basic {
        let (balance, nonce) = self.querier.query_account(key);
        Basic { balance, nonce }
    }

    fn insert_account(&mut self, key: H160, data: Basic) {
        self.querier.insert_account(key, data);
    }

    fn insert_account_code(&mut self, key: H160, code: Vec<u8>) {
        self.querier.insert_account_code(key, code);
    }

    fn insert_storage_cell(&mut self, key: H160, index: H256, value: H256) {
        self.querier.insert_storage_cell(key, index, value);
    }

    fn remove(&mut self, key: &H160) {
        self.querier.remove(key);
    }

    fn remove_account_code(&mut self, key: &H160) {
        self.querier.remove_account_code(key);
    }

    fn remove_storage_cell(&mut self, key: &H160, index: &H256) {
        self.querier.remove_storage_cell(key, index);
    }

    fn remove_storage(&mut self, key: &H160) {
        self.querier.remove_storage(key);
    }
}

impl FFIStorage{
    pub fn new(querier: &GoQuerier) -> Self {
        Self { querier }
    }
}
