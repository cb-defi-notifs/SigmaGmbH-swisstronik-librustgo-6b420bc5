use crate::{error::Error, key_manager::PUBLIC_KEY_SIZE};
use std::vec::Vec;

use crate::key_manager::UNSEALED_KEY_MANAGER;

/// Encrypts given storage cell value using sealed master key
pub fn encrypt_storage_cell(contract_address: Vec<u8>, value: Vec<u8>) -> Result<Vec<u8>, Error> {
    let key_manager = match &*UNSEALED_KEY_MANAGER {
        Some(key_manager) => key_manager,
        None => {
            return Err(Error::encryption_err(format!("Cannot unseal master key")));
        }
    };

    key_manager.encrypt_state(contract_address, value)
}

/// Decrypts given storage cell value using sealed master key
pub fn decrypt_storage_cell(contract_address: Vec<u8>, encrypted_value: Vec<u8>) -> Result<Vec<u8>, Error> {
    let key_manager = match &*UNSEALED_KEY_MANAGER {
        Some(key_manager) => key_manager,
        None => {
            return Err(Error::encryption_err(format!("Cannot unseal master key")));
        }
    };

    key_manager.decrypt_state(contract_address, encrypted_value)
}

/// Decrypts transaction data using derived shared secret
pub fn decrypt_transaction_data(encrypted_data: Vec<u8>) -> Result<Vec<u8>, Error> {
    // Extract public key from encrypted data
    if encrypted_data.len() < PUBLIC_KEY_SIZE {
        return Err(Error::ecdh_err("Wrong public key size"));
    }

    let public_key = &encrypted_data[..PUBLIC_KEY_SIZE];
    let ciphertext = &encrypted_data[PUBLIC_KEY_SIZE..];

    let key_manager = match &*UNSEALED_KEY_MANAGER {
        Some(key_manager) => key_manager,
        None => {
            return Err(Error::encryption_err(format!("Cannot unseal master key")));
        }
    };

    key_manager.decrypt_ecdh(public_key.to_vec(), ciphertext.to_vec())
}
