use sgxvm::evm::backend::Basic;
use sgxvm::primitive_types::{H160, H256, U256};
use sgxvm::storage::Storage;
use crate::querier::GoQuerier;

/// This struct allows us to obtain state from keeper
/// that is located outside of Rust code
pub struct FFIStorage<'a> {
    pub querier: &'a GoQuerier,
}

impl<'a> Storage for FFIStorage<'a> {
    fn contains_key(&self, key: &H160) -> bool {
        // TODO: Remove usage of querier
        // self.querier.query_contains_key(key)
        false
    }

    fn get_account_storage_cell(&self, key: &H160, index: &H256) -> Option<H256> {
        // self.querier.query_account_storage_cell(key, index)
        None
    }

    fn get_account_code(&self, key: &H160) -> Option<Vec<u8>> {
        // TODO: Remove usage of querier
        // self.querier.query_account_code(key)
        None
    }

    fn get_account(&self, key: &H160) -> Basic {
        // TODO: Remove usage of querier
        // let (balance, nonce) = self.querier.query_account(key);
        let balance = U256::default();
        let nonce = U256::default();
        Basic { balance, nonce }
    }

    fn insert_account(&mut self, key: H160, data: Basic) {
        // TODO: Remove usage of querier
        // self.querier.insert_account(key, data);
    }

    fn insert_account_code(&mut self, key: H160, code: Vec<u8>) {
        // TODO: Remove usage of querier
        // self.querier.insert_account_code(key, code);
    }

    fn insert_storage_cell(&mut self, key: H160, index: H256, value: H256) {
        // TODO: Remove usage of querier
        // self.querier.insert_storage_cell(key, index, value);
    }

    fn remove(&mut self, key: &H160) {
        // TODO: Remove usage of querier
        // self.querier.remove(key);
    }

    fn remove_storage_cell(&mut self, key: &H160, index: &H256) {
        // TODO: Remove usage of querier
        // self.querier.remove_storage_cell(key, index);
    }
}

impl<'a> FFIStorage<'a> {
    pub fn new(querier: &'a GoQuerier) -> Self {
        Self {querier}
    }
}
