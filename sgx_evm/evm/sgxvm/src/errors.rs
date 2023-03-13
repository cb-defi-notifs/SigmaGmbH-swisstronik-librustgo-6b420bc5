use std::string::String;

#[derive(Debug)]
pub enum EvmError {
    // Cannot decode RLP-encoded data
    RLPDecodeError(String),
    // Cannot recover signature
    SignatureRecoveryError(String),
    // EVM cannot properly execute code
    ExecutionError(String),
    // EVM revert
    Reverted(String),
    // Fatal EVM error
    FatalError(String),
}