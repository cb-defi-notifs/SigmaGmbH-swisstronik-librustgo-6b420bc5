use crate::errors::EvmError;
use crate::primitives::address::public_key_to_address;
use ethereum::{
    EIP1559TransactionMessage, EIP2930TransactionMessage, LegacyTransactionMessage,
    TransactionAction, TransactionV2,
};
use k256::ecdsa::recoverable::{Id, Signature as RecoverableSignature};
use k256::ecdsa::Signature;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{elliptic_curve::IsHigh, PublicKey};
use primitive_types::{H160, H256, U256};
use std::vec::Vec;
use std::string::ToString;

// Recovers verifying key
fn recover_public_key(
    sig: &RecoverableSignature,
    hash: &H256,
) -> Result<PublicKey, EvmError> {
    if sig.s().is_high().into() {
        return Err(EvmError::SignatureRecoveryError("s value is too high".to_string()));
    }
    match sig.recover_verifying_key_from_digest_bytes(hash.as_fixed_bytes().into()) {
        Ok(low) => Ok(PublicKey::from(low)),
        Err(e) => {
            Err(EvmError::SignatureRecoveryError(
                format!("Cannot recover public key: {:?}", e)
            ))
        }
    }
}

// Extracts transaction signature and message hash from transaction data
// This extracted data will be used to derive original sender of transaction
fn recover_origin(
    tx: TransactionV2,
) -> Result<H160, EvmError> {
    // Extract signature, recovery id and message hash
    let (signature, recovery_id, message_hash) = match tx {
        TransactionV2::Legacy(tx) => {
            // Extract signature
            let signature = match Signature::from_scalars(
                tx.signature.r().to_fixed_bytes(),
                tx.signature.s().to_fixed_bytes(),
            ) {
                Ok(sig) => sig,
                Err(e) => {
                    return Err(EvmError::SignatureRecoveryError(
                        format!("Cannot extract signature: {:?}", e)
                    ));
                }
            };

            // Extract recovery id
            let recovery_id = match Id::new(tx.signature.standard_v()) {
                Ok(id) => id,
                Err(e) => {
                    return Err(EvmError::SignatureRecoveryError(
                        format!("Cannot extract recovery param: {:?}", e)
                    ));
                }
            };

            // Extract message hash that can be used to recover signer
            let message = LegacyTransactionMessage::from(tx);

            (signature, recovery_id, message.hash())
        }
        TransactionV2::EIP2930(tx) => {
            // Extract signature
            let signature =
                match Signature::from_scalars(tx.r.to_fixed_bytes(), tx.s.to_fixed_bytes()) {
                    Ok(sig) => sig,
                    Err(e) => {
                        return Err(EvmError::SignatureRecoveryError(
                            format!("Cannot extract signature: {:?}", e)
                        ));
                    }
                };

            // Extract recovery id
            let recovery_id = match Id::new(tx.odd_y_parity.into()) {
                Ok(id) => id,
                Err(e) => {
                    return Err(EvmError::SignatureRecoveryError(
                        format!("Cannot extract recovery param: {:?}", e)
                    ));
                }
            };

            // Extract message hash that can be used to recover signer
            let message = EIP2930TransactionMessage::from(tx);

            (signature, recovery_id, message.hash())
        }
        TransactionV2::EIP1559(tx) => {
            // Extract signature
            let signature =
                match Signature::from_scalars(tx.r.to_fixed_bytes(), tx.s.to_fixed_bytes()) {
                    Ok(sig) => sig,
                    Err(e) => {
                        return Err(EvmError::SignatureRecoveryError(
                            format!("Cannot extract signature: {:?}", e)
                        ));
                    }
                };

            // Extract recovery id
            let recovery_id = match Id::new(tx.odd_y_parity.into()) {
                Ok(id) => id,
                Err(e) => {
                    return Err(EvmError::SignatureRecoveryError(
                        format!("Cannot extract recovery param: {:?}", e)
                    ));
                }
            };

            // Extract message hash that can be used to recover signer
            let message = EIP1559TransactionMessage::from(tx);

            (signature, recovery_id, message.hash())
        }
    };

    // Construct recoverable signature
    let recoverable_signature = match RecoverableSignature::new(&signature, recovery_id) {
        Ok(sig) => sig,
        Err(e) => {
            return Err(EvmError::SignatureRecoveryError(
                format!("Cannot construct recoverable signature: {:?}", e)
            ));
        }
    };

    // Recover origin
    let recovered_key = recover_public_key(&recoverable_signature, &message_hash)?;

    Ok(
        public_key_to_address(
            &recovered_key.to_encoded_point(false).as_bytes()[1..]
        )
    )

}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FullTransactionData {
    pub origin: H160,
    pub action: TransactionAction,
    pub input: Vec<u8>,
    pub nonce: U256,
    pub gas_limit: U256,
    pub gas_price: Option<U256>,
    pub max_fee_per_gas: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
    pub value: U256,
    pub chain_id: Option<u64>,
    pub access_list: Vec<(H160, Vec<H256>)>,
}

impl FullTransactionData {
    pub fn decode_transaction(body: &[u8]) -> Result<Self, EvmError> {
        let transaction_v2 = match rlp::decode::<TransactionV2>(body) {
            Ok(tx) => tx,
            Err(e) => {
                return Err(EvmError::RLPDecodeError(
                    format!("Cannot decode transaction: {:?}", e)
                ));
            }
        };

        // Extract original sender
        let origin = recover_origin(transaction_v2.clone())?;

        // Extract transaction data
        let decoded_tx = match transaction_v2 {
            TransactionV2::Legacy(t) => FullTransactionData {
                origin,
                action: t.action,
                input: t.input.clone(),
                nonce: t.nonce,
                gas_limit: t.gas_limit,
                gas_price: Some(t.gas_price),
                max_fee_per_gas: None,
                max_priority_fee_per_gas: None,
                value: t.value,
                chain_id: t.signature.chain_id(),
                access_list: Vec::new(),
            },
            TransactionV2::EIP2930(t) => FullTransactionData {
                origin,
                action: t.action,
                input: t.input.clone(),
                nonce: t.nonce,
                gas_limit: t.gas_limit,
                gas_price: Some(t.gas_price),
                max_fee_per_gas: None,
                max_priority_fee_per_gas: None,
                value: t.value,
                chain_id: Some(t.chain_id),
                access_list: t
                    .access_list
                    .iter()
                    .map(|d| (d.address, d.storage_keys.clone()))
                    .collect(),
            },
            TransactionV2::EIP1559(t) => FullTransactionData {
                origin,
                action: t.action,
                input: t.input.clone(),
                nonce: t.nonce,
                gas_limit: t.gas_limit,
                gas_price: None,
                max_fee_per_gas: Some(t.max_fee_per_gas),
                max_priority_fee_per_gas: Some(t.max_priority_fee_per_gas),
                value: t.value,
                chain_id: Some(t.chain_id),
                access_list: t
                    .access_list
                    .iter()
                    .map(|d| (d.address, d.storage_keys.clone()))
                    .collect(),
            },
        };

        Ok(decoded_tx)
    }
}
