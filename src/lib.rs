// Support using this crate without the standard library
#![cfg_attr(not(feature = "std"), no_std)]
// As long as there is a memory allocator, we can still use this crate
// without the rest of the standard library by using the `alloc` crate
#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::string::String;
use serde_json::Value;
#[cfg(feature = "std")]
use std::string::String;

use serde::{Deserialize, Serialize};

mod tee;
#[cfg(feature = "tee-sev")]
pub use tee::sev::{SevChallenge, SevRequest};

#[cfg(feature = "tee-snp")]
pub use tee::snp::{Error as SnpDecodeError, SnpAttestation};

#[derive(Serialize, Clone, Copy, Deserialize, Debug, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Tee {
    AzSnpVtpm,
    AzTdxVtpm,
    Sev,
    Sgx,
    Snp,
    Tdx,
    // Arm Confidential Compute Architecture
    Cca,
    // China Secure Virtualization
    Csv,
    // IBM Z Secure Execution
    Se,

    // This value is only used for testing an attestation server, and should not
    // be used in an actual attestation scenario.
    Sample,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Request {
    pub version: String,
    pub tee: Tee,
    #[serde(rename = "extra-params")]
    pub extra_params: Value,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Challenge {
    pub nonce: String,
    #[serde(rename = "extra-params")]
    pub extra_params: Value,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(tag = "kty")]
pub enum TeePubKey {
    RSA {
        alg: String,
        #[serde(rename = "n")]
        k_mod: String,
        #[serde(rename = "e")]
        k_exp: String,
    },
    /// Elliptic Curve Keys
    /// fields defined in
    /// [RFC 7518 Section 6.1](https://www.rfc-editor.org/rfc/rfc7518.html#page-28)
    EC {
        crv: String,
        alg: String,
        x: String,
        y: String,
    },
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Attestation {
    #[serde(rename = "tee-pubkey")]
    pub tee_pubkey: TeePubKey,
    #[serde(rename = "tee-evidence")]
    pub tee_evidence: Value,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Response {
    pub protected: String,
    pub encrypted_key: String,
    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ErrorInformation {
    #[serde(rename = "type")]
    pub error_type: String,
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn parse_request() {
        let data = r#"
        {
            "version": "0.0.0",
            "tee": "sev",
            "extra-params": ""
        }"#;

        let request: Request = serde_json::from_str(data).unwrap();

        assert_eq!(request.version, "0.0.0");
        assert_eq!(request.tee, Tee::Sev);
        assert_eq!(request.extra_params, "");
    }

    #[test]
    fn parse_challenge() {
        let data = r#"
        {
            "nonce": "42",
            "extra-params": ""
        }"#;

        let challenge: Challenge = serde_json::from_str(data).unwrap();

        assert_eq!(challenge.nonce, "42");
        assert_eq!(challenge.extra_params, "");
    }

    #[test]
    fn parse_response() {
        let data = r#"
        {
            "protected": "fakejoseheader",
            "encrypted_key": "fakekey",
            "iv": "randomdata",
            "ciphertext": "fakeencoutput",
            "tag": "faketag"
        }"#;

        let response: Response = serde_json::from_str(data).unwrap();

        assert_eq!(response.protected, "fakejoseheader");
        assert_eq!(response.encrypted_key, "fakekey");
        assert_eq!(response.iv, "randomdata");
        assert_eq!(response.ciphertext, "fakeencoutput");
        assert_eq!(response.tag, "faketag");
    }

    #[test]
    fn parse_attestation_ec() {
        let data = r#"
        {
            "tee-pubkey": {
                "kty": "EC",
                "crv": "fakecrv",
                "alg": "fakealgorithm",
                "x": "fakex",
                "y": "fakey"
            },
            "tee-evidence": "fakeevidence"
        }"#;

        let attestation: Attestation = serde_json::from_str(data).unwrap();

        let TeePubKey::EC { alg, crv, x, y } = attestation.tee_pubkey else {
            panic!("Must be an EC key");
        };

        assert_eq!(alg, "fakealgorithm");
        assert_eq!(crv, "fakecrv");
        assert_eq!(x, "fakex");
        assert_eq!(y, "fakey");
        assert_eq!(attestation.tee_evidence, "fakeevidence");
    }

    #[test]
    fn parse_attestation_rsa() {
        let data = r#"
        {
            "tee-pubkey": {
                "kty": "RSA",
                "alg": "fakealgorithm",
                "n": "fakemodulus",
                "e": "fakeexponent"
            },
            "tee-evidence": "fakeevidence"
        }"#;

        let attestation: Attestation = serde_json::from_str(data).unwrap();

        let TeePubKey::RSA { alg, k_mod, k_exp } = attestation.tee_pubkey else {
            panic!("Must be a RSA key");
        };

        assert_eq!(alg, "fakealgorithm");
        assert_eq!(k_mod, "fakemodulus");
        assert_eq!(k_exp, "fakeexponent");
        assert_eq!(attestation.tee_evidence, "fakeevidence");
    }

    #[test]
    fn parse_error_information() {
        let data = r#"
        {
            "type": "problemtype",
            "detail": "problemdetail"
        }"#;

        let info: ErrorInformation = serde_json::from_str(data).unwrap();

        assert_eq!(info.error_type, "problemtype");
        assert_eq!(info.detail, "problemdetail");
    }
}
