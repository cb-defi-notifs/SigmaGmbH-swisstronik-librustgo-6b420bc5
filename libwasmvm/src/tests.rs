#![cfg(test)]

use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct InstantiateMsg {
    pub verifier: String,
    pub beneficiary: String,
}

