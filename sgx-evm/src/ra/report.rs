use std::array::TryFromSliceError;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::vec::Vec;
use std::string::String;

use serde_json::Value;

#[derive(Debug)]
pub enum Error {
    ReportParseError,
    ReportValidationError,
}

impl From<std::array::TryFromSliceError> for Error {
    fn from(_: TryFromSliceError) -> Self {
        Error::ReportParseError
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(_: serde_json::error::Error) -> Self {
        Error::ReportParseError
    }
}

/// A report that can be signed by Intel EPID (which generates
/// `EndorsedAttestationReport`) and then sent off of the platform to be
/// verified by remote client.
#[derive(Debug)]
pub struct AttestationReport {
    /// The freshness of the report, i.e., elapsed time after acquiring the
    /// report in seconds.
    // pub freshness: Duration,
    /// Quote status
    pub sgx_quote_status: SgxQuoteStatus,
    /// Content of the quote
    pub sgx_quote_body: SgxQuote,
    pub platform_info_blob: Option<Vec<u8>>,
    pub advisory_ids: AdvisoryIDs,
}

impl AttestationReport {
    /// Construct a AttestationReport from a X509 certificate and verify
    /// attestation report with the report_ca_cert which is from the attestation
    /// service provider.
    // just unused in SW mode
    #[allow(dead_code)]
    pub fn from_cert(cert: &[u8]) -> Result<Self, Error> {
        let payload = super::cert::get_netscape_comment(cert).map_err(|_err| {
            error!("Failed to get netscape comment");
            Error::ReportParseError
        })?;

        // Convert to endorsed report
        let report: EndorsedAttestationReport = serde_json::from_slice(&payload)?;

        // Verify report's signature - aka intel's signing cert
        let signing_cert = webpki::EndEntityCert::from(&report.signing_cert).map_err(|_err| {
            error!("Failed to validate signature");
            Error::ReportParseError
        })?;

        let (ias_cert, root_store) = get_ias_auth_config();

        let trust_anchors: Vec<webpki::TrustAnchor> = root_store
            .roots
            .iter()
            .map(|cert| cert.to_trust_anchor())
            .collect();

        let chain: Vec<&[u8]> = vec![&ias_cert];

        // set as 04.11.23(dd.mm.yy) - should be valid for the foreseeable future, and not rely on SystemTime
        let time_stamp = webpki::Time::from_seconds_since_unix_epoch(1_699_088_856);

        // note: there's no way to not validate the time, and we don't want to write this code
        // ourselves. We also can't just ignore the error message, since that means that the rest of
        // the validation didn't happen (time is validated early on)
        match signing_cert.verify_is_valid_tls_server_cert(
            super::cert::SUPPORTED_SIG_ALGS,
            &webpki::TLSServerTrustAnchors(&trust_anchors),
            &chain,
            time_stamp,
        ) {
            Ok(_) => info!("Certificate verified successfully"),
            Err(e) => {
                error!("Certificate verification error {:?}", e);
                return Err(Error::ReportValidationError);
            }
        };

        // Verify the signature against the signing cert
        match signing_cert.verify_signature(
            &webpki::RSA_PKCS1_2048_8192_SHA256,
            &report.report,
            &report.signature,
        ) {
            Ok(_) => info!("Signature verified successfully"),
            Err(e) => {
                warn!("Signature verification error {:?}", e);
                return Err(Error::ReportParseError);
            }
        }

        // Verify and extract information from attestation report
        let attn_report: Value = serde_json::from_slice(&report.report)?;
        trace!("attn_report: {}", attn_report);

        // Verify API version is supported
        let version = attn_report["version"]
            .as_u64()
            .ok_or(Error::ReportParseError)?;

        if version != 4 {
            warn!("API version incompatible");
            return Err(Error::ReportParseError);
        };

        let mut platform_info_blob = None;
        if let Some(blob) = attn_report["platformInfoBlob"].as_str() {
            let as_binary = hex::decode(blob).map_err(|_| {
                warn!("Error parsing platform info");
                Error::ReportParseError
            })?;
            platform_info_blob = Some(as_binary)
        }

        // Get quote status
        let sgx_quote_status = {
            let status_string = attn_report["isvEnclaveQuoteStatus"]
                .as_str()
                .ok_or_else(|| {
                    warn!("Error parsing enclave quote status");
                    Error::ReportParseError
                })?;
            SgxQuoteStatus::from(status_string)
        };

        // Get quote body
        let sgx_quote_body = {
            let quote_encoded = attn_report["isvEnclaveQuoteBody"].as_str().ok_or_else(|| {
                warn!("Error unpacking enclave quote body");
                Error::ReportParseError
            })?;
            let quote_raw = base64::decode(&quote_encoded.as_bytes()).map_err(|_| {
                warn!("Error decoding encoded quote body");
                Error::ReportParseError
            })?;
            SgxQuote::parse_from(quote_raw.as_slice())?
        };

        let advisories: Vec<String> = if let Some(raw) = attn_report.get("advisoryIDs") {
            serde_json::from_value(raw.clone()).map_err(|_| {
                warn!("Failed to decode advisories");
                Error::ReportParseError
            })?
        } else {
            vec![]
        };

        // We don't actually validate the public key, since we use ephemeral certificates,
        // and all we really care about that the report is valid and the key that is saved in the
        // report_data field

        Ok(Self {
            sgx_quote_status,
            sgx_quote_body,
            platform_info_blob,
            advisory_ids: AdvisoryIDs(advisories),
        })
    }
}