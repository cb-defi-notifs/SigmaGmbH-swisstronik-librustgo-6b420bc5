#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate sgx_tstd as std;

use backend::ExtendedBackend;
use common_types::ExecutionResult;
pub use ethereum;
use ethereum::TransactionAction;
pub use evm;
use evm::executor::stack::{MemoryStackState, StackExecutor, StackSubstateMetadata};
use evm::ExitReason;
pub use primitive_types;
use primitive_types::{H160, H256, U256};
use rlp::Encodable;

use std::{collections::BTreeMap, string::String, string::ToString, vec::Vec};

use crate::backend::{Backend, GASOMETER_CONFIG};
pub use crate::backend::Vicinity;
use crate::precompiles::EVMPrecompiles;
use crate::primitives::{QueryData, raw_transaction::FullTransactionData};
use crate::storage::Storage;

pub mod backend;
pub mod primitives;
pub mod storage;

mod errors;
mod precompiles;

/// This struct contaisn all the data that need for execution
pub struct ExecutionData {
    pub origin: H160,
    pub action: TransactionAction,
    pub input: Vec<u8>,
    pub gas_limit: U256,
    pub value: U256,
    pub access_list: Vec<(H160, Vec<H256>)>,
}

impl From<FullTransactionData> for ExecutionData {
    fn from(data: FullTransactionData) -> Self {
        ExecutionData {
            origin: data.origin,
            action: data.action,
            input: data.input,
            gas_limit: data.gas_limit,
            value: data.value,
            access_list: data.access_list,
        }
    }
}

/// Handles incoming request for calling some contract / funds transfer
pub fn handle_sgxvm_call(
    backend: &mut impl ExtendedBackend,
    gas_limit: u64,
    from: H160,
    to: H160,
    value: U256,
    data: Vec<u8>,
    access_list: Vec<(H160, Vec<H256>)>,
    commit: bool,
) -> ExecutionResult {
    let metadata = StackSubstateMetadata::new(gas_limit, &GASOMETER_CONFIG);
    let state = MemoryStackState::new(metadata, backend);
    let precompiles = EVMPrecompiles::<Backend>::new();

    let mut executor = StackExecutor::new_with_precompiles(state, &GASOMETER_CONFIG, &precompiles);
    let (exit_reason, ret) = executor.transact_call(from, to, value, data, gas_limit, access_list);

    let gas_used = executor.used_gas();
    let exit_value = match handle_evm_result(exit_reason, ret) {
        Ok(data) => data,
        Err((err, data)) => {
            return ExecutionResult::from_error(err, data, Some(gas_used))
        }
    };

    if commit {
        let (vals, logs) = executor.into_state().deconstruct();
        backend.apply(vals, logs, false); 
    }

    ExecutionResult {
        logs: backend.get_logs(),
        data: exit_value,
        gas_used,
        vm_error: "".to_string(),
    }
}

/// Handles incoming request for creation of a new contract
pub fn handle_sgxvm_create(
    backend: &mut impl ExtendedBackend,
    gas_limit: u64,
    from: H160,
    value: U256,
    data: Vec<u8>,
    access_list: Vec<(H160, Vec<H256>)>,
    commit: bool,
) -> ExecutionResult {
    let metadata = StackSubstateMetadata::new(gas_limit, &GASOMETER_CONFIG);
    let state = MemoryStackState::new(metadata, backend);
    let precompiles = EVMPrecompiles::<Backend>::new();

    let mut executor = StackExecutor::new_with_precompiles(state, &GASOMETER_CONFIG, &precompiles);
    let (exit_reason, ret) = executor.transact_create(from, value, data, gas_limit, access_list);

    let gas_used = executor.used_gas();
    let exit_value = match handle_evm_result(exit_reason, ret) {
        Ok(data) => data,
        Err((err, data)) => {
            return ExecutionResult::from_error(err, data, Some(gas_used))
        }
    };

    if commit {
        let (vals, logs) = executor.into_state().deconstruct();
        backend.apply(vals, logs, false); 
    }

    ExecutionResult {
        logs: backend.get_logs(),
        data: exit_value,
        gas_used,
        vm_error: "".to_string(),
    }
}

/// Handles an EVM result to return either a successful result or a (readable) error reason.
fn handle_evm_result(exit_reason: ExitReason, data: Vec<u8>) -> Result<Vec<u8>, (String, Vec<u8>)> {
    match exit_reason {
        ExitReason::Succeed(_) => Ok(data),
        ExitReason::Revert(err) => Err((format!("execution reverted: {:?}", err), data)),
        ExitReason::Error(err) => Err((format!("evm error: {:?}", err), data)),
        ExitReason::Fatal(err) => Err((format!("fatal evm error: {:?}", err), data)),
    }
}