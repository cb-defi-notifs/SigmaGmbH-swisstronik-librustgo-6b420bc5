use crate::error::Error;
use std::vec::Vec;

use crate::key_manager::KeyManager;

/// Encrypts given storage cell value using sealed master key
pub fn encrypt_storage_cell(value: Vec<u8>) -> Result<Vec<u8>, Error> {
    let key_manager = match KeyManager::unseal() {
        Ok(manager) => manager,
        Err(err) => {
            return Err(Error::encryption_err(format!("Cannot unseal master key")));
        }
    };

    key_manager.encrypt(value)
}

/// Decrypts given storage cell value using sealed master key
pub fn decrypt_storage_cell(encrypted_value: Vec<u8>) -> Result<Vec<u8>, Error> {
    let key_manager = match KeyManager::unseal() {
        Ok(manager) => manager,
        Err(err) => {
            return Err(Error::decryption_err(format!("Cannot unseal master key")));
        }
    };

    key_manager.decrypt(encrypted_value)
}
