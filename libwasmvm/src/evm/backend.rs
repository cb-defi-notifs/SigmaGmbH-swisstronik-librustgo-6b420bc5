use sgx_evm::ethereum::Log;
use crate::querier::GoQuerier;
use sgx_evm::backend::ExtendedBackend;
use sgx_evm::evm::backend::{Backend as EvmBackend, ApplyBackend as EvmApplyBackend, Basic, Apply};

use sgx_evm::primitive_types::{H160, H256, U256};
use sgx_evm::storage::Storage;
use sgx_evm::Vicinity;

/// Contains context of the transaction such as gas price, block hash, block timestamp, etc.
pub struct TxContext {
    pub chain_id: U256,
    pub gas_price: U256,
    pub block_number: U256,
    pub timestamp: U256,
    pub block_gas_limit: U256,
    pub block_base_fee_per_gas: U256,
    pub block_coinbase: H160
}

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
    // Transaction context
    pub tx_context: TxContext
}

impl<'state> ExtendedBackend for FFIBackend<'state> {
    fn get_logs(&self) -> Vec<Log> {
        self.logs.clone()
    }
}

impl<'state> EvmBackend for FFIBackend<'state> {
    fn gas_price(&self) -> U256 {
        self.tx_context.gas_price
    }

    fn origin(&self) -> H160 {
        self.vicinity.origin
    }

    fn block_hash(&self, number: U256) -> H256 {
        self.querier.query_block_hash(number)
    }

    fn block_number(&self) -> U256 {
        self.tx_context.block_number
    }

    fn block_coinbase(&self) -> H160 {
        self.tx_context.block_coinbase
    }

    fn block_timestamp(&self) -> U256 {
        self.tx_context.timestamp
    }

    fn block_difficulty(&self) -> U256 {
        // Only applicable for PoW
        U256::zero()
    }

    fn block_gas_limit(&self) -> U256 {
        self.tx_context.block_gas_limit
    }

    fn block_base_fee_per_gas(&self) -> U256 {
        self.tx_context.block_base_fee_per_gas
    }

    fn chain_id(&self) -> U256 {
        self.tx_context.chain_id
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

/// Implementation of trait `Apply` provided by evm crate
/// This trait declares write operations for the backend
impl<'state> EvmApplyBackend for FFIBackend<'state> {
	fn apply<A, I, L>(&mut self, values: A, logs: L, _delete_empty: bool)
	where
		A: IntoIterator<Item = Apply<I>>,
		I: IntoIterator<Item = (H256, H256)>,
		L: IntoIterator<Item = Log>,
	{
        let mut total_supply_add = U256::zero();
        let mut total_supply_sub = U256::zero();

		for apply in values {
			match apply {
				Apply::Modify {
					address,
					basic,
					code,
					storage,
                    ..
				} => {
                    // Reset storage is ignored since storage cannot be efficiently reset as this
                    // would require iterating over all of the storage keys

                    // Update account balance and nonce
                    let previous_account_data = self.state.get_account(&address);

                    if basic.balance > previous_account_data.balance {
                        total_supply_add =
                            total_supply_add.checked_add(basic.balance - previous_account_data.balance).unwrap();
                    } else {
                        total_supply_sub =
                            total_supply_sub.checked_add(previous_account_data.balance - basic.balance).unwrap();
                    }
                    self.state.insert_account(address, basic);

                    // Handle contract updates
                    if let Some(code) = code {
                        self.state.insert_account_code(address, code);
                    }

                    // Handle storage updates
                    for (index, value) in storage {
                        if value == H256::default() {
                            self.state.remove_storage_cell(&address, &index);
                        } else {
                            self.state.insert_storage_cell(address, index, value);
                        }
                    }
				},
                // Used by SELFDESTRUCT opcode
				Apply::Delete { address } => {
					self.state.remove(&address);
				}
			}
		}

        // Used to avoid corrupting state via invariant violation
        assert!(
            total_supply_add == total_supply_sub,
            "evm execution would lead to invariant violation ({} != {})",
            total_supply_add,
            total_supply_sub
        );

		for log in logs {
			self.logs.push(log);
		}
	}
}

impl<'state> FFIBackend<'state> {
    pub fn new(
        querier: &'state GoQuerier, 
        storage: &'state mut dyn Storage, 
        vicinity: Vicinity,
        tx_context: TxContext,
    ) -> Self {
        Self { querier, vicinity, state: storage, logs: vec![], tx_context }
    }
}
