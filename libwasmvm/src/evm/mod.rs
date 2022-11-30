use sgx_evm;
use sgx_evm::primitives::raw_transaction::TransactionData;
use common_types::ExecutionResult;
use sgx_evm::primitive_types::{U256, H160, H256};
use sgx_evm::ethereum::TransactionAction;
use crate::protobuf_generated::ffi::TransactionData as ProtoTransactionData;
use std::str::FromStr;

/// This function creates mocked backend and tries to handle incoming transaction
/// It is stateless and is used just to test broadcasting transaction from devnet to Rust
/// execution layer
pub fn handle_transaction_mocked(data: ProtoTransactionData) -> ExecutionResult {
    // Convert decoded protobuf data into TransactionData
    let tx = parse_protobuf_transaction_data(data);
    // Create mocked storage
    let mut mocked_storage = sgx_evm::storage::mocked_storage::MockedStorage::default();
    // Handle already parsed transaction and return execution result
    sgx_evm::handle_transaction_inner(tx, &mut mocked_storage)
}

/// This function converts decoded protobuf transaction data into a regulat TransactionData struct
fn parse_protobuf_transaction_data(data: ProtoTransactionData) -> TransactionData {
    let action = match data.to.is_empty() {
        true => TransactionAction::Create,
        false => TransactionAction::Call(H160::from_slice(&data.to))
    };

    let gas_price = match data.has_gasPrice() {
        true => Some(U256::from_big_endian(data.get_gasPrice())),
        false => None,
    };

    let max_fee_per_gas = match data.has_maxFeePerGas() {
        true => Some(U256::from_big_endian(data.get_maxFeePerGas())),
        false => None,
    };

    let max_priority_fee_per_gas = match data.has_maxPriorityFeePerGas() {
        true => Some(U256::from_big_endian(data.get_maxPriorityFeePerGas())),
        false => None,
    };

    let chain_id = match data.has_chainId() {
        true => Some(data.get_chainId()),
        false => None,
    };

    let mut access_list = Vec::default();
    for accessListItem in data.accessList.to_vec() {
        let address = H160::from_slice(&accessListItem.address);
        let slots = accessListItem.storageSlot
            .to_vec()
            .into_iter()
            .map(|item| { H256::from_slice(&item) })
            .collect();

        access_list.push((address, slots));
    }

    TransactionData {
        origin: H160::from_slice(&data.from),
        action,
        input: data.data,
        nonce: U256::from_big_endian(&data.nonce),
        gas_limit: U256::from_big_endian(&data.gasLimit),
        gas_price,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        value: U256::from_big_endian(&data.value),
        chain_id,
        access_list,
    }
}
