use sgx_evm;
use sgx_evm::ExecutionData;
use common_types::ExecutionResult;
use sgx_evm::primitive_types::{U256, H160, H256};
use sgx_evm::ethereum::TransactionAction;
use sgx_evm::evm::backend::Backend;

use crate::protobuf_generated::ffi::TransactionData as ProtoTransactionData;
use crate::querier::GoQuerier;

mod storage;
mod backend;

/// This function creates mocked backend and tries to handle incoming transaction
/// It is stateless and is used just to test broadcasting transaction from devnet to Rust
/// execution layer
pub fn handle_transaction(querier: GoQuerier, data: ProtoTransactionData) -> ExecutionResult {
    // Convert decoded protobuf data into TransactionData
    let tx = parse_protobuf_transaction_data(data);
    // Create FFI storage & backend
    let mut storage = crate::evm::storage::FFIStorage::new(&querier);
    let mut backend = backend::FFIBackend::new(&querier, &mut storage);

    // Handle already parsed transaction and return execution result
    sgx_evm::handle_transaction_inner(tx, &mut storage)
}

/// This function converts decoded protobuf transaction data into a regulat TransactionData struct
fn parse_protobuf_transaction_data(data: ProtoTransactionData) -> ExecutionData {
    let action = match data.to.is_empty() {
        true => TransactionAction::Create,
        false => TransactionAction::Call(H160::from_slice(&data.to))
    };

    let mut access_list = Vec::default();
    for access_list_item in data.accessList.to_vec() {
        let address = H160::from_slice(&access_list_item.address);
        let slots = access_list_item.storageSlot
            .to_vec()
            .into_iter()
            .map(|item| { H256::from_slice(&item) })
            .collect();

        access_list.push((address, slots));
    }

    let gas_limit = U256::from(data.get_gasLimit());

    ExecutionData {
        origin: H160::from_slice(&data.from),
        action,
        input: data.data,
        gas_limit: gas_limit,
        value: U256::from_big_endian(&data.value),
        access_list,
    }
}
