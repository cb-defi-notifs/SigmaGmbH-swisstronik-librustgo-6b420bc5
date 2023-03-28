use crate::error::Error;
use aes_siv::{
    aead::{Aead, KeyInit},
    Aes256SivAead, Nonce,
};
use sgx_types::*;
use std::vec::Vec;

pub static DB_ENCRYPTION_PRIVATE_KEY: &str =
    "8935f44e30b9f58916ff90a9328f10276014fcc1d756f7631d62aabeadb4772d";
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
        Err(err) => return Err(Error::encryption_err(err)),
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
        Err(err) => return Err(Error::decryption_err(err)),
    }
}
