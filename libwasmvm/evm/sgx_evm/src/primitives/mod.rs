use primitive_types::{H160, U256};
use std::vec::Vec;
use rlp::{Decodable, Rlp, DecoderError};

pub mod address;
pub mod raw_transaction;

/// Represents data for gas estimation or static call of contract
#[derive(Clone, Debug)]
pub struct QueryData {
    pub from: H160,
    pub to: H160,
    pub gas: U256,
    pub gas_price: U256,
    pub value: U256,
    pub data: Vec<u8>,
}

impl Decodable for QueryData {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            from: rlp.val_at(0)?,
            to: rlp.val_at(1)?,
            gas: rlp.val_at(2)?,
            gas_price: rlp.val_at(3)?,
            value: rlp.val_at(4)?,
            data: rlp.val_at(5)?
        })
    }
}