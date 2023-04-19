use aes_siv::{
    aead::{Aead, KeyInit},
    Aes128SivAead, Nonce,
};
use sgx_tstd::sgxfs::SgxFile;
use sgx_types::{sgx_read_rand, sgx_status_t, SgxResult};
use std::io::{Read, Write};
use std::vec::Vec;
use lazy_static::lazy_static;

use crate::error::Error;

pub const REGISTRATION_KEY_SIZE: usize = 32;
pub const SEED_SIZE: usize = 32;
pub const SEED_FILENAME: &str = ".swtr_seed";
pub const NONCE_LEN: usize = 16;
pub const PUBLIC_KEY_SIZE: usize = 32;

lazy_static! {
    pub static ref UNSEALED_KEY_MANAGER: Option<KeyManager> = KeyManager::unseal().ok();
}

#[no_mangle]
/// Handles initialization of a new seed node.
/// If seed is already sealed, it will reset it
pub unsafe extern "C" fn ecall_init_master_key(reset_flag: i32) -> sgx_status_t {
    // Check if master key exists
    let master_key_exists = match KeyManager::exists() {
        Ok(exists) => exists,
        Err(err) => {
            return err;
        }
    };

    // If master key does not exist or reset flag was set, generate random master key and seal it
    if !master_key_exists || reset_flag != 0 {
        // Generate random master key
        let key_manager = match KeyManager::random() {
            Ok(manager) => manager,
            Err(err) => {
                return err;
            }
        };

        // Seal master key
        match key_manager.seal() {
            Ok(_) => {
                return sgx_status_t::SGX_SUCCESS;
            }
            Err(err) => {
                return err;
            }
        };
    }

    sgx_status_t::SGX_SUCCESS
}

/// KeyManager handles keys sealing/unsealing and derivation.
/// * master_key – This key is used to derive keys for transaction and state encryption/decryption
pub struct KeyManager {
    master_key: [u8; 32],
}

impl KeyManager {
    /// Checks if file with sealed master key exists
    pub fn exists() -> SgxResult<bool> {
        match SgxFile::open(SEED_FILENAME) {
            Ok(_) => Ok(true),
            Err(ref err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => {
                println!("[KeyManager] Cannot check if sealed file exists");
                return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
            }
        }
    }

    /// Seals key to protected file, so it will be accessible only for enclave.
    /// For now, enclaves with same MRSIGNER will be able to recover that file, but
    /// we'll use MRENCLAVE since Upgradeability Protocol will be implemented
    pub fn seal(&self) -> SgxResult<()> {
        // Prepare file to write master key
        let mut master_key_file = match SgxFile::create(SEED_FILENAME) {
            Ok(master_key_file) => master_key_file,
            Err(err) => {
                println!(
                    "[KeyManager] Cannot create file for master key. Reason: {:?}",
                    err
                );
                return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
            }
        };

        // Write master key to the file
        if let Err(err) = master_key_file.write(&self.master_key) {
            println!("[KeyManager] Cannot write master key. Reason: {:?}", err);
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        }

        Ok(())
    }

    /// Unseals master key from protected file. If file was not found or unaccessible,
    /// will return SGX_ERROR_UNEXPECTED
    pub fn unseal() -> SgxResult<Self> {
        // Open file with master key
        let mut master_key_file = match SgxFile::open(SEED_FILENAME) {
            Ok(file) => file,
            Err(err) => {
                println!(
                    "[KeyManager] Cannot open file with master key. Reason: {:?}",
                    err
                );
                return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
            }
        };

        // Prepare buffer for seed and read it from file
        let mut master_key = [0u8; SEED_SIZE];
        match master_key_file.read(&mut master_key) {
            Ok(_) => {}
            Err(err) => {
                println!(
                    "[KeyManager] Cannot read file with master key. Reason: {:?}",
                    err
                );
                return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
            }
        };

        Ok(Self { master_key })
    }

    /// Creates new KeyManager with random master key
    pub fn random() -> SgxResult<Self> {
        let mut master_key = [0u8; 32];
        let res = unsafe { sgx_read_rand(&mut master_key as *mut u8, SEED_SIZE) };
        match res {
            sgx_status_t::SGX_SUCCESS => {}
            _ => {
                println!(
                    "[KeyManager] Cannot generate random master key. Reason: {:?}",
                    res.as_str()
                );
                return Err(res);
            }
        };

        Ok(Self { master_key })
    }

    /// Encrypts provided message using Aes128SivAead
    pub fn encrypt(&self, message: Vec<u8>) -> Result<Vec<u8>, Error> {
        // Prepare cipher
        let cipher = match Aes128SivAead::new_from_slice(&self.master_key) {
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
        match cipher.encrypt(nonce, message.as_slice()) {
            Ok(ciphertext) => {
                // Add nonce to the begging of the ciphertext
                let final_ciphertext = [nonce.as_slice(), ciphertext.as_slice()].concat();
                Ok(final_ciphertext.to_vec())
            }
            Err(err) => Err(Error::encryption_err(err)),
        }
    }

    /// Decrypts provided ciphertext using shared encryption key, derived using
    /// master key and provided public key
    pub fn decrypt_ecdh(&self, public_key: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, Error> {
        // Derive transaction encryption key
        let shared_key = self.diffie_hellman(public_key)?;
        
        // Prepare cipher
        let cipher = match Aes128SivAead::new_from_slice(shared_key.as_bytes()) {
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

    /// Decrypts provided ciphertext using Aes128SivAead
    pub fn decrypt(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, Error> {
        // Prepare cipher
        let cipher = match Aes128SivAead::new_from_slice(&self.master_key) {
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

    /// Encrypts master key using shared key
    pub fn to_encrypted_seed(
        &self,
        reg_key: &RegistrationKey,
        public_key: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        // Convert public key to appropriate format
        let public_key: [u8; 32] = match public_key.try_into() {
            Ok(public_key) => public_key,
            Err(err) => {
                return Err(Error::decryption_err(format!(
                    "Public key has wrong length"
                )))
            }
        };
        let public_key = x25519_dalek::PublicKey::from(public_key);

        // Derive shared secret
        let shared_secret = reg_key.diffie_hellman(public_key);

        // Prepare cipher
        let cipher = match Aes128SivAead::new_from_slice(shared_secret.as_bytes()) {
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

        // Encrypt master key
        match cipher.encrypt(nonce, self.master_key.as_slice()) {
            Ok(ciphertext) => {
                let public_key = reg_key.public_key();
                let result_bytes = [
                    public_key.as_bytes(),
                    nonce.as_slice(),
                    ciphertext.as_slice(),
                ]
                .concat();
                Ok(result_bytes)
            }
            Err(err) => Err(Error::encryption_err(err)),
        }
    }

    /// Recovers encrypted master key obtained from seed exchange server
    pub fn from_encrypted_seed(
        reg_key: &RegistrationKey,
        public_key: Vec<u8>,
        encrypted_seed: Vec<u8>,
    ) -> Result<Self, Error> {
        // Convert public key to appropriate format
        let public_key: [u8; 32] = match public_key.try_into() {
            Ok(public_key) => public_key,
            Err(err) => {
                return Err(Error::encryption_err(format!(
                    "Public key has wrong length"
                )))
            }
        };
        let public_key = x25519_dalek::PublicKey::from(public_key);

        // Derive shared secret
        let shared_secret = reg_key.diffie_hellman(public_key);

        // Decrypt seed
        let cipher = match Aes128SivAead::new_from_slice(shared_secret.as_bytes()) {
            Ok(cipher) => cipher,
            Err(err) => return Err(Error::decryption_err(err)),
        };
        let nonce = Nonce::from_slice(&encrypted_seed[..NONCE_LEN]);
        let ciphertext = &encrypted_seed[NONCE_LEN..];
        let master_key = match cipher.decrypt(nonce, ciphertext) {
            Ok(master_key) => master_key,
            Err(err) => return Err(Error::decryption_err(err)),
        };

        // Convert master key to appropriate format
        let master_key: [u8; 32] = match master_key.try_into() {
            Ok(master_key) => master_key,
            Err(err) => {
                return Err(Error::decryption_err(format!(
                    "Master key has wrong length"
                )))
            }
        };

        Ok(Self { master_key })
    }

    /// Return x25519 public key for transaction encryption
    pub fn get_public_key(&self) -> Vec<u8> {
        let secret = x25519_dalek::StaticSecret::from(self.master_key);
        let public_key = x25519_dalek::PublicKey::from(&secret);
        public_key.as_bytes().to_vec()
    }

    /// Performes Diffie-Hellman derivation of encryption key for transaction encryption
    /// * public_key – User public key
    fn diffie_hellman(
        &self,
        public_key: Vec<u8>,
    ) -> Result<x25519_dalek::SharedSecret, Error> {
        let secret = x25519_dalek::StaticSecret::from(self.master_key);

        if public_key.len() != PUBLIC_KEY_SIZE {
            return Err(Error::ecdh_err("Wrong public key size"));
        }

        let public_key: [u8; 32] = match public_key.try_into() {
            Ok(pk) => pk,
            Err(err) => {
                return Err(Error::ecdh_err("Cannot convert public key to proper size"));
            }
        };

        let public_key = x25519_dalek::PublicKey::from(public_key);
        Ok(secret.diffie_hellman(&public_key))
    }
}

/// RegistrationKey handles all operations with registration key such as derivation of public key,
/// derivation of encryption key, etc.
pub struct RegistrationKey {
    inner: [u8; REGISTRATION_KEY_SIZE],
}

impl RegistrationKey {
    /// Generates public key for seed sharing
    pub fn public_key(&self) -> x25519_dalek::PublicKey {
        let secret = x25519_dalek::StaticSecret::from(self.inner);
        x25519_dalek::PublicKey::from(&secret)
    }

    /// Generates random registration key
    pub fn random() -> SgxResult<Self> {
        // Generate random seed
        let mut buffer = [0u8; REGISTRATION_KEY_SIZE];
        let res = unsafe { sgx_read_rand(&mut buffer as *mut u8, REGISTRATION_KEY_SIZE) };

        match res {
            sgx_status_t::SGX_SUCCESS => return Ok(Self { inner: buffer }),
            _ => {
                println!(
                    "[KeyManager] Cannot generate random registration key. Reason: {:?}",
                    res.as_str()
                );
                return Err(res);
            }
        }
    }

    /// Performes Diffie-Hellman derivation of encryption key for master key encryption
    /// * public_key – User public key
    pub fn diffie_hellman(
        &self,
        public_key: x25519_dalek::PublicKey,
    ) -> x25519_dalek::SharedSecret {
        let secret = x25519_dalek::StaticSecret::from(self.inner);
        secret.diffie_hellman(&public_key)
    }
}

