use derive_more::Display;

#[derive(Debug, Display, PartialEq, Eq)]
pub enum AuthResult {
    #[display(fmt = "Enclave quote is valid")]
    Success,
    #[display(fmt = "Enclave quote status was GROUP_OUT_OF_DATE which is not allowed")]
    GroupOutOfDate,
    #[display(fmt = "Enclave quote status was SIGNATURE_INVALID which is not allowed")]
    SignatureInvalid,
    #[display(fmt = "Enclave quote status was SIGNATURE_REVOKED which is not allowed")]
    SignatureRevoked,
    #[display(fmt = "Enclave quote status was GROUP_REVOKED which is not allowed")]
    GroupRevoked,
    #[display(fmt = "Enclave quote status was KEY_REVOKED which is not allowed")]
    KeyRevoked,
    #[display(fmt = "Enclave quote status was SIGRL_VERSION_MISMATCH which is not allowed")]
    SigrlVersionMismatch,
    #[display(fmt = "Enclave quote status was CONFIGURATION_NEEDED which is not allowed")]
    ConfigurationNeeded,
    #[display(
        fmt = "Enclave quote status was CONFIGURATION_AND_SW_HARDENING_NEEDED which is not allowed"
    )]
    SwHardeningAndConfigurationNeeded,
    #[display(fmt = "Enclave quote status invalid")]
    BadQuoteStatus,
    #[display(fmt = "Enclave version mismatch. Registering enclave had different code signature")]
    MrEnclaveMismatch,
    #[display(fmt = "Enclave version mismatch. Registering enclave had different signer")]
    MrSignerMismatch,
    #[display(fmt = "Enclave received invalid inputs")]
    InvalidInput,
    #[display(fmt = "The provided certificate was invalid")]
    InvalidCert,
    #[display(fmt = "Writing to file system from the enclave failed")]
    CantWriteToStorage,
    #[display(fmt = "The public key in the certificate appears to be malformed")]
    MalformedPublicKey,
    #[display(fmt = "Encrypting the seed failed")]
    SeedEncryptionFailed,
    #[display(fmt = "failed to allocate minimal safety buffer")]
    MemorySafetyAllocationError,
    #[display(
        fmt = "Unexpected panic during node authentication. Certificate may be malformed or invalid"
    )]
    Panic,
}