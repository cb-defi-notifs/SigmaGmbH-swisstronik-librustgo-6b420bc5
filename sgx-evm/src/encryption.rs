use crate::error::Error;
use aes_siv::{
    aead::{Aead, KeyInit},
    Aes128SivAead, Nonce,
};
use x25519_dalek::{StaticSecret, PublicKey};
use sgx_types::*;
use std::vec::Vec;

pub static NODE_PRIVATE_KEY: &str =
    "bf8fca698444afd8b4cd4e851cb58321192a6d8eab503bf17d8be249e767cf3d";

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

/// Returns x25519 public key generated from node private key
pub fn x25519_get_public_key() -> Result<Vec<u8>, Error> {
    // Decode key
    let key = match hex::decode(NODE_PRIVATE_KEY) {
        Ok(key) => key,
        Err(err) => return Err(Error::enclave_err(err)),
    };

    // Construct secret 
    let key_bytes: [u8; 32] = key.try_into().unwrap();
    let secret = StaticSecret::from(key_bytes);

    // Derive public key
    let public_key = PublicKey::from(&secret);
    Ok(public_key.as_bytes().to_vec())
}
