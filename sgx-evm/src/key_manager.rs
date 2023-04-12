use sgx_rand::*;
use sgx_tstd::sgxfs::SgxFile;
use sgx_types::{sgx_read_rand, sgx_status_t, SgxResult};
use std::io::{Read, Write};


pub const REGISTRATION_KEY_SIZE: usize = 32;
pub const SEED_SIZE: usize = 32;
pub const SEED_FILENAME: &str = ".swtr_seed";

/// KeyManager handles keys sealing/unsealing and derivation.
/// * master_key – This key is used to derive keys for transaction and state encryption/decryption
pub struct KeyManager {
    master_key: [u8; 32],
}

impl KeyManager {
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
}

/// RegistrationKey handles all operations with registration key such as derivation of public key,
/// derivation of encryption key, etc.
pub struct RegistrationKey {
    inner: [u8; REG_SIZE]
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
        let res = unsafe {
            sgx_read_rand(&mut buffer as *mut u8, REGISTRATION_KEY_SIZE)
        };

        match res {
            sgx_status_t::SGX_SUCCESS => {
                return Ok(Self {inner: buffer})
            },
            _ => {
                println!("[KeyManager] Cannot generate random registration key. Reason: {:?}", res.as_str());
                return Err(res);
            }
        }
    }

    /// Performes Diffie-Hellman derivation of encryption key for seed encryption
    /// * public_key – User public key
    pub fn diffie_hellman(&self, public_key: x25519_dalek::PublicKey) -> x25519_dalek::SharedSecret {
        let secret = x25519_dalek::StaticSecret::from(self.inner);
        secret.diffie_hellman(&public_key)
    }
}
