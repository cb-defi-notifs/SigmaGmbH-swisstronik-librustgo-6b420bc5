use crate::protobuf_generated::ffi::{NodePublicKeyResponse};
use crate::{AllocationWithResult, Allocation};
use crate::encryption;
use protobuf::Message;

/// Handles incoming request for node public key
pub fn handle_public_key_request() -> AllocationWithResult {
    let res = encryption::x25519_get_public_key();
    match res {
        Ok(res) => {
            let mut response = NodePublicKeyResponse::new();
            response.set_publicKey(res);

            let encoded_response = match response.write_to_bytes() {
                Ok(res) => res,
                Err(err) => {
                    println!("Cannot encode protobuf result");
                    return AllocationWithResult::default();
                }
            };
            
            super::allocate_inner(encoded_response)
        },
        Err(err) => {
            println!("Cannot obtain node public key. Reason: {:?}", err);
            AllocationWithResult::default()
        }
    }
}