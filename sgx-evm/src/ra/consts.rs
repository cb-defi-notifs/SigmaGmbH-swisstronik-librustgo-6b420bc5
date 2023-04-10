#[derive(PartialEq, Eq, Debug)]
pub enum SigningMethod {
    MRSIGNER,
    MRENCLAVE,
    NONE,
}

// TODO: Replace with actual MRSIGNER
pub const MRSIGNER: [u8; 32] = [0u8; 32];

pub const DEV_HOSTNAME: &'static str = "api.trustedservices.intel.com";
pub const SIGRL_SUFFIX: &'static str = "/sgx/dev/attestation/v4/sigrl/";
pub const REPORT_SUFFIX: &'static str = "/sgx/dev/attestation/v4/report";
pub const CERTEXPIRYDAYS: i64 = 90i64;

pub const SIGNING_METHOD: SigningMethod = SigningMethod::MRSIGNER;

pub const PUBLIC_KEY_SIZE: usize = 32;