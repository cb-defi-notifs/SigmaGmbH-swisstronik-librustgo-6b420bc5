use crate::error::Error;
use aes_siv::{
    aead::{Aead, KeyInit},
    Aes256SivAead, Nonce,
};
use sgx_types::*;
use std::vec::Vec;

pub static DB_ENCRYPTION_PRIVATE_KEY: &str =
    "bf8fca698444afd8b4cd4e851cb58321192a6d8eab503bf17d8be249e767cf3dcc593d3ca83ef769fb22b281aa446c89b9b5d1ecf4f243c438b01896dba77e28";
pub const NONCE_LEN: usize = 16;

/// Encrypts provided message using AES-SIV
pub fn aes_encrypt(message: &[u8]) -> Result<Vec<u8>, Error> {
    // Decode key
    let key = match hex::decode(DB_ENCRYPTION_PRIVATE_KEY) {
        Ok(key) => key,
        Err(err) => return Err(Error::encryption_err(err)),
    };

    // Prepare cipher
    let cipher = match Aes256SivAead::new_from_slice(&key) {
        Ok(cipher) => cipher,
        Err(err) => return Err(Error::encryption_err(err)),
    };

    // Generate nonce
    let mut buffer = [0u8; NONCE_LEN];
    let result = unsafe { sgx_read_rand(&mut buffer as *mut u8, NONCE_LEN) };
    let nonce = match result {
        sgx_status_t::SGX_SUCCESS => Nonce::from_slice(&buffer),
        _ => {
            return Err(Error::encryption_err(format!(
                "Cannot generate nonce: {:?}",
                result.as_str()
            )))
        }
    };

    // Encrypt message
    match cipher.encrypt(nonce, message) {
        Ok(ciphertext) => {
            // Add nonce to the begging of the ciphertext
            let final_ciphertext = [nonce.as_slice(), ciphertext.as_slice()].concat();
            Ok(final_ciphertext.to_vec())    
        },
        Err(err) => Err(Error::encryption_err(err)),
    }
}

/// Decrypts provided message using AES-SIV
pub fn aes_decrypt(ciphertext: Vec<u8>) -> Result<Vec<u8>, Error> {
    // Decode key
    let key = match hex::decode(DB_ENCRYPTION_PRIVATE_KEY) {
        Ok(key) => key,
        Err(err) => return Err(Error::decryption_err(err)),
    };

    // Prepare cipher
    let cipher = match Aes256SivAead::new_from_slice(&key) {
        Ok(cipher) => cipher,
        Err(err) => return Err(Error::decryption_err(err)),
    };

    // Extract nonce from ciphertext
    let nonce = Nonce::from_slice(&ciphertext[..NONCE_LEN]);

    // Decrypt message
    let ciphertext = &ciphertext[NONCE_LEN..];
    match cipher.decrypt(nonce, ciphertext) {
        Ok(message) => Ok(message),
        Err(err) => Err(Error::decryption_err(err)),
    }
}
