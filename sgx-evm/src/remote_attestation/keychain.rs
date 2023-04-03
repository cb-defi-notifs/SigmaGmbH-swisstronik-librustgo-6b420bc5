use std::sgxfs::SgxFile;
use std::io::{Read, Write};
use sgx_types::*;
use std::vec::Vec;

pub const SEED_SIZE: usize = 32;
pub const SEED_FILENAME: &str = ".swtr_seed";
pub const REG_SIZE: usize = 32;
pub const REG_FILENAME: &str = ".reg_seed";

/// Returns node seed. If file with node seed was not found, will return SGX_ERROR_UNEXPECTED
pub unsafe fn get_node_seed() -> Result<Vec<u8>, sgx_status_t> {
    // Open file with node seed
    let mut file = match SgxFile::open(SEED_FILENAME) {
        Ok(file) => file,
        Err(err) => {
            println!("Cannot open file with node seed. Reason: {:?}", err);
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        },
    };

    // Prepare buffer for seed and read it from file
    let mut buffer = [0u8; SEED_SIZE];
    match file.read(&mut buffer) {
        Ok(_) => Ok(buffer.to_vec()),
        Err(err) => {
            println!("Cannot read file with node seed. Reason: {:?}", err);
            Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
        }
    }
}

/// Generates and writes to an encrypted file node seed.
/// If there is already existing node seed, it will rewrite it
pub unsafe fn new_node_seed() -> Result<(), sgx_status_t> {
    // Generate random seed
    let mut buffer = [0u8; 32];
    let res = sgx_read_rand(&mut buffer as *mut u8,SEED_SIZE);
    match res {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("Cannot generate random node seed. Reason: {:?}", res.as_str());
            return Err(res);
        }
    }

    // Prepare file to write node seed
    let mut file = match SgxFile::create(SEED_FILENAME) {
        Ok(file) => file,
        Err(err) => {
            println!("Cannot create file for node seed. Reason: {:?}", err);
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        }
    };

    // Write to the file
    match file.write(&buffer) {
        Ok(_) => Ok(()),
        Err(err) => {
            println!("Cannot write node seed. Reason: {:?}", err);
            Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
        },
    }
}

/// Generates new registration key and seals it to the file
pub unsafe fn new_registration_key() -> Result<Vec<u8>, sgx_status_t> {
    // Generate random seed
    let mut buffer = [0u8; 32];
    let res = sgx_read_rand(&mut buffer as *mut u8, REG_SIZE);
    match res {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("Cannot generate registration key. Reason: {:?}", res.as_str());
            return Err(res);
        }
    }

    // Prepare file to write node seed
    let mut file = match SgxFile::create(REG_FILENAME) {
        Ok(file) => file,
        Err(err) => {
            println!("Cannot create file for registration key. Reason: {:?}", err);
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        }
    };

    // Write to the file
    match file.write(&buffer) {
        Ok(_) => Ok(buffer.to_vec()),
        Err(err) => {
            println!("Cannot write registration key. Reason: {:?}", err);
            Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
        },
    }
}

/// Returns node seed. If file with node seed was not found, will return SGX_ERROR_UNEXPECTED
pub unsafe fn get_registration_key() -> Result<Vec<u8>, sgx_status_t> {
    // Open file with node seed
    let mut file = match SgxFile::open(REG_FILENAME) {
        Ok(file) => file,
        Err(err) => {
            println!("Cannot open file with registration key. Reason: {:?}", err);
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        },
    };

    // Prepare buffer for seed and read it from file
    let mut buffer = [0u8; REG_SIZE];
    match file.read(&mut buffer) {
        Ok(_) => Ok(buffer.to_vec()),
        Err(err) => {
            println!("Cannot read file with registration key. Reason: {:?}", err);
            Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
        }
    }
}