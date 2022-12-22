use sgx_evm::ethereum::Log;
use crate::querier::GoQuerier;
use sgx_evm::evm::backend::{Backend as EvmBackend, Basic};

use sgx_evm::primitive_types::{H160, H256, U256};
use sgx_evm::storage::Storage;
use sgx_evm::Vicinity;


pub struct FFIBackend<'state> {
    /// This struct allows us to obtain state from keeper
    /// that is located outside of Rust code
    pub querier: &'state GoQuerier,
    // Contains gas price and original sender
    pub vicinity: Vicinity,
    // Accounts state
    pub state: &'state mut dyn Storage,
    // Emitted events
    pub logs: Vec<Log>,
}

impl<'state> EvmBackend for FFIBackend<'state> {
    fn gas_price(&self) -> U256 {
        // TODO: Will obtain that data via ocall
        U256::zero()
    }

    fn origin(&self) -> H160 {
        self.vicinity.origin
    }

    fn block_hash(&self, _number: U256) -> H256 {
       self.querier.query_block_hash(_number)
    }

    fn block_number(&self) -> U256 {
        self.querier.query_block_number()
    }

    fn block_coinbase(&self) -> H160 {
        H160::default()
    }

    fn block_timestamp(&self) -> U256 {
        self.querier.query_block_timestamp()
    }

    fn block_difficulty(&self) -> U256 {
        U256::zero()
    }

    fn block_gas_limit(&self) -> U256 {
        // TODO: Will obtain that data via ocall to make it possible to
        // change via in-built Cosmos SDK's voting
        U256::max_value()
    }

    fn block_base_fee_per_gas(&self) -> U256 {
        // TODO: Will obtain that data via ocall to make it possible to
        // change via in-built Cosmos SDK's voting
        U256::zero()
    }

    fn chain_id(&self) -> U256 {
        // 1 (0x01) is Ethereum mainnet chain id
        self.querier.query_chain_id()
    }

    fn exists(&self, address: H160) -> bool {
        self.state.contains_key(&address)
    }

    fn basic(&self, address: H160) -> Basic {
        self.state.get_account(&address)
    }

    fn code(&self, address: H160) -> Vec<u8> {
        self.state
            .get_account_code(&address)
            .unwrap_or_default()
    }

    fn storage(
        &self,
        address: H160,
        index: H256,
    ) -> H256 {
        self.state
            .get_account_storage_cell(&address, &index)
            .unwrap_or_default()
    }

    fn original_storage(&self, _address: H160, _index: H256) -> Option<H256> {
        None
    }
}
