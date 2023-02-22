use protobuf::RepeatedField;
use sgx_evm::{self, Vicinity};
use sgx_evm::ExecutionData;
use common_types::ExecutionResult;
use sgx_evm::primitive_types::{U256, H160, H256};
use sgx_evm::ethereum::TransactionAction;


use crate::evm::backend::TxContext;
use crate::protobuf_generated::ffi::{
    SGXVMCallRequest,
    TransactionData as ProtoTransactionData,
    HandleTransactionRequest as ProtoRequest,
    TransactionContext as ProtoTransactionContext, AccessListItem, SGXVMCreateRequest,
};
use crate::querier::GoQuerier;

mod storage;
mod backend;

pub fn handle_sgxvm_call(querier: GoQuerier, data: SGXVMCallRequest) -> ExecutionResult {
    let params = data.params.unwrap();
    let context = data.context.unwrap();

    let vicinity = Vicinity { origin: H160::from_slice(&params.from) };
    let mut storage = crate::evm::storage::FFIStorage::new(&querier);
    let mut backend = backend::FFIBackend::new(
        &querier, 
        &mut storage, 
        vicinity,
        build_transaction_context(context)
    );

    sgx_evm::handle_sgxvm_call(
        &mut backend,
        params.gasLimit,
        H160::from_slice(&params.from),
        H160::from_slice(&params.to),
        U256::from_big_endian(&params.value),
        params.data,
        parse_access_list(params.accessList),
        params.commit,
    )
}

pub fn handle_sgxvm_create(querier: GoQuerier, data: SGXVMCreateRequest) -> ExecutionResult {
    let params = data.params.unwrap();
    let context = data.context.unwrap();

    let vicinity = Vicinity { origin: H160::from_slice(&params.from) };
    let mut storage = crate::evm::storage::FFIStorage::new(&querier);
    let mut backend = backend::FFIBackend::new(
        &querier, 
        &mut storage, 
        vicinity,
        build_transaction_context(context)
    );

    sgx_evm::handle_sgxvm_create(
        &mut backend,
        params.gasLimit,
        H160::from_slice(&params.from),
        U256::from_big_endian(&params.value),
        params.data,
        parse_access_list(params.accessList),
        params.commit,
    )
}

/// This function creates mocked backend and tries to handle incoming transaction
/// It is stateless and is used just to test broadcasting transaction from devnet to Rust
/// execution layer
pub fn handle_transaction(querier: GoQuerier, data: ProtoRequest) -> ExecutionResult {
    // Convert decoded protobuf data into TransactionData
    let (tx, tx_context) = parse_protobuf_transaction_data(data);
    // Create FFI storage & backend
    let vicinity = Vicinity{ origin: tx.origin };
    let mut storage = crate::evm::storage::FFIStorage::new(&querier);
    let mut backend = backend::FFIBackend::new(&querier, &mut storage, vicinity, tx_context);

    // Handle already parsed transaction and return execution result
    sgx_evm::handle_transaction_inner(tx, &mut backend)
}

fn parse_access_list(data: RepeatedField<AccessListItem>) -> Vec<(H160, Vec<H256>)> {
    let mut access_list = Vec::default();
    for access_list_item in data.to_vec() {
        let address = H160::from_slice(&access_list_item.address);
        let slots = access_list_item.storageSlot
            .to_vec()
            .into_iter()
            .map(|item| { H256::from_slice(&item) })
            .collect();

        access_list.push((address, slots));
    }

    access_list
}

/// This function takes protobuf-encoded request for transaction handling and extracts
/// TransactionData and TxContext from it
fn parse_protobuf_transaction_data(request: ProtoRequest) -> (ExecutionData, TxContext) {
    // TODO: Prepare some error handling
    let tx_data = request.tx_data.unwrap();
    let tx_context = build_transaction_context(request.tx_context.unwrap());

    let action = match tx_data.to.is_empty() {
        true => TransactionAction::Create,
        false => TransactionAction::Call(H160::from_slice(&tx_data.to))
    };

    let mut access_list = Vec::default();
    for access_list_item in tx_data.accessList.to_vec() {
        let address = H160::from_slice(&access_list_item.address);
        let slots = access_list_item.storageSlot
            .to_vec()
            .into_iter()
            .map(|item| { H256::from_slice(&item) })
            .collect();

        access_list.push((address, slots));
    }

    let gas_limit = U256::from(tx_data.get_gasLimit());

    let execution_data = ExecutionData {
        origin: H160::from_slice(&tx_data.from),
        action,
        input: tx_data.data,
        gas_limit,
        value: U256::from_big_endian(&tx_data.value),
        access_list,
    };

    (execution_data, tx_context)
}

fn build_transaction_context(context: ProtoTransactionContext) -> TxContext {
    TxContext { 
        chain_id: U256::from(context.chain_id),
        gas_price: U256::from_big_endian(&context.gas_price), 
        block_number: U256::from(context.block_number),
        timestamp: U256::from(context.timestamp),
        block_gas_limit: U256::from(context.block_gas_limit),
        block_base_fee_per_gas: U256::from_big_endian(&context.block_base_fee_per_gas),
        block_coinbase: H160::from_slice(&context.block_coinbase), 
    }
}