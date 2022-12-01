use primitive_types::{H160, H256};
use sha3::{Digest, Keccak256};

// Converts secp256k1 public key to Ethereum-compatible address
// address = last 20 bytes from `keccak256(uncompressed public key without first byte)`
pub fn public_key_to_address(pubkey: &[u8]) -> H160 {
    let mut hasher = Keccak256::new();
    hasher.update(&pubkey);
    let hash = H256::from_slice(hasher.finalize().as_slice());

    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);

    H160::from_slice(&address)
}