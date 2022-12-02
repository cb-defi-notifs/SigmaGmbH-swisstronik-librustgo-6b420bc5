use sgx_evm::evm::backend::Basic;
use sgx_evm::primitive_types::{H160, H256, U256};
use sgx_evm::storage::Storage;
use std::{collections::BTreeMap, str::FromStr};

/// This struct allows us to obtain state from keeper
/// that is located outside of Rust code
pub struct FFIStorage {
    storage: BTreeMap<H160, BTreeMap<H256, H256>>,
    contracts: BTreeMap<H160, Vec<u8>>,
    accounts: BTreeMap<H160, Basic>,
}

impl Storage for FFIStorage {
    fn contains_key(&self, key: &H160) -> bool {
        self.accounts.contains_key(key)
    }

    fn get_account_storage_cell(&self, key: &H160, index: &H256) -> Option<H256> {
        self.storage.get(key).and_then(|inner| inner.get(index)).copied()
    }

    fn get_account_code(&self, key: &H160) -> Option<Vec<u8>> {
        self.contracts.get(key).cloned()
    }

    fn get_account(&self, key: &H160) -> Basic {
        // TODO: Start from obtaining account balance and nonce from Cosmos side
        self.accounts
            .get(key)
            .map(|v| Basic {
                balance: v.balance,
                nonce: v.nonce,
            })
            .unwrap_or_default()
    }

    fn insert_account(&mut self, key: H160, data: Basic) {
        self.accounts.insert(key, data);
    }

    fn insert_account_code(&mut self, key: H160, code: Vec<u8>) {
        self.contracts.insert(key, code);
    }

    fn insert_storage_cell(&mut self, key: H160, index: H256, value: H256) {
        self.storage.entry(key)
            .and_modify(|inner| { inner.insert(index, value); })
            .or_insert_with(|| {
                let mut default = BTreeMap::new();
                default.insert(index, value);
                default
            });
    }

    fn remove(&mut self, key: &H160) {
        self.accounts.remove(key);
    }

    fn remove_account_code(&mut self, key: &H160) {
        self.contracts.remove(key);
    }

    fn remove_storage_cell(&mut self, key: &H160, index: &H256) {
        self.storage.entry(*key).and_modify(|inner| { inner.remove(index); });
    }

    fn remove_storage(&mut self, key: &H160) {
        self.storage.remove(key);
    }
}

impl Default for FFIStorage {
    fn default() -> Self {
        let mut accounts = BTreeMap::new();

        accounts.insert(
            H160::from_str("0x91e1f4bb1c1895f6c65cd8379de1323a8bf3cf7c").unwrap(),
            Basic {
                nonce: U256::zero(),
                balance: U256::from_dec_str("1000000000000000000000").unwrap(),
            }
        );

        Self {
            storage: BTreeMap::new(),
            contracts: BTreeMap::new(),
            accounts,
        }
    }
}