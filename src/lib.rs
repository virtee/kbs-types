// Support using this crate without the standard library
#![cfg_attr(not(feature = "std"), no_std)]
// As long as there is a memory allocator, we can still use this crate
// without the rest of the standard library by using the `alloc` crate
#[cfg(feature = "alloc")]
extern crate alloc;

mod error;
pub use error::{KbsTypesError, Result};

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::{string::String, vec::Vec};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use serde_json::{Map, Value};
#[cfg(all(feature = "std", not(feature = "alloc")))]
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
pub struct ProtectedHeader {
    /// Enryption algorithm for encrypted key
    pub alg: String,
    /// Encryption algorithm for payload
    pub enc: String,

    /// Other fields of Protected Header
    #[serde(skip_serializing_if = "Map::is_empty", flatten)]
    pub other_fields: Map<String, Value>,
}

impl ProtectedHeader {
    /// The generation of AAD for JWE follows [A.3.5 RFC7516](https://www.rfc-editor.org/rfc/rfc7516#appendix-A.3.5)
    pub fn generate_aad(&self) -> Result<Vec<u8>> {
        let protected_utf8 = serde_json::to_string(&self).map_err(|_| KbsTypesError::Serde)?;
        let aad = BASE64_URL_SAFE_NO_PAD.encode(protected_utf8);
        Ok(aad.into_bytes())
    }
}

fn serialize_base64_protected_header<S>(
    sub: &ProtectedHeader,
    serializer: S,
) -> core::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let protected_header_json = serde_json::to_string(sub).map_err(serde::ser::Error::custom)?;
    let encoded = BASE64_URL_SAFE_NO_PAD.encode(protected_header_json);
    serializer.serialize_str(&encoded)
}

fn deserialize_base64_protected_header<'de, D>(
    deserializer: D,
) -> core::result::Result<ProtectedHeader, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let decoded = BASE64_URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(serde::de::Error::custom)?;
    let protected_header = serde_json::from_slice(&decoded).map_err(serde::de::Error::custom)?;

    Ok(protected_header)
}

fn serialize_base64<S>(sub: &Vec<u8>, serializer: S) -> core::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let encoded = BASE64_URL_SAFE_NO_PAD.encode(sub);
    serializer.serialize_str(&encoded)
}

fn deserialize_base64<'de, D>(deserializer: D) -> core::result::Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let decoded = BASE64_URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(serde::de::Error::custom)?;

    Ok(decoded)
}

fn serialize_base64_vec<S>(
    sub: &Option<Vec<u8>>,
    serializer: S,
) -> core::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match sub {
        Some(value) => {
            let encoded = String::from_utf8(value.clone()).map_err(serde::ser::Error::custom)?;
            serializer.serialize_str(&encoded)
        }
        None => serializer.serialize_none(),
    }
}

fn deserialize_base64_vec<'de, D>(
    deserializer: D,
) -> core::result::Result<Option<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let string = String::deserialize(deserializer)?;
    let bytes = string.into_bytes();

    Ok(Some(bytes))
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Response {
    #[serde(
        serialize_with = "serialize_base64_protected_header",
        deserialize_with = "deserialize_base64_protected_header"
    )]
    pub protected: ProtectedHeader,

    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub encrypted_key: Vec<u8>,

    #[serde(
        skip_serializing_if = "Option::is_none",
        default = "Option::default",
        serialize_with = "serialize_base64_vec",
        deserialize_with = "deserialize_base64_vec"
    )]
    pub aad: Option<Vec<u8>>,

    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub iv: Vec<u8>,

    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub ciphertext: Vec<u8>,

    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub tag: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ErrorInformation {
    #[serde(rename = "type")]
    pub error_type: String,
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::*;

    #[cfg(all(feature = "alloc", not(feature = "std")))]
    use alloc::{collections::btree_map::BTreeMap, string::ToString};

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
    fn protected_header_generate_aad() {
        let protected_header = ProtectedHeader {
            alg: "fakealg".to_string(),
            enc: "fakeenc".to_string(),
            other_fields: Map::new(),
        };

        let aad = protected_header.generate_aad().unwrap();

        assert_eq!(
            aad,
            "eyJhbGciOiJmYWtlYWxnIiwiZW5jIjoiZmFrZWVuYyJ9".as_bytes()
        );
    }

    #[test]
    fn parse_response() {
        let data = r#"
        {
            "protected": "eyJhbGciOiJmYWtlYWxnIiwiZW5jIjoiZmFrZWVuYyJ9",
            "encrypted_key": "ZmFrZWtleQ",
            "iv": "cmFuZG9tZGF0YQ",
            "ciphertext": "ZmFrZWVuY291dHB1dA",
            "tag": "ZmFrZXRhZw"
        }"#;

        let response: Response = serde_json::from_str(data).unwrap();

        assert_eq!(response.protected.alg, "fakealg");
        assert_eq!(response.protected.enc, "fakeenc");
        assert!(response.protected.other_fields.is_empty());
        assert_eq!(response.encrypted_key, "fakekey".as_bytes());
        assert_eq!(response.iv, "randomdata".as_bytes());
        assert_eq!(response.ciphertext, "fakeencoutput".as_bytes());
        assert_eq!(response.tag, "faketag".as_bytes());
        assert_eq!(response.aad, None);
    }

    #[test]
    fn parse_response_nested_protected_header() {
        let data = r#"
        {
            "protected": "eyJhbGciOiJmYWtlYWxnIiwiZW5jIjoiZmFrZWVuYyIsImVwayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ4IjoiaFNEd0NZa3dwMVIwaTMzY3RENzNXZzJfT2cwbU9CcjA2NlNwanFxYlRtbyJ9fQo",
            "encrypted_key": "ZmFrZWtleQ",
            "iv": "cmFuZG9tZGF0YQ",
            "ciphertext": "ZmFrZWVuY291dHB1dA",
            "tag": "ZmFrZXRhZw"
        }"#;

        let response: Response = serde_json::from_str(data).unwrap();

        assert_eq!(response.protected.alg, "fakealg");
        assert_eq!(response.protected.enc, "fakeenc");

        let expected_other_fields = json!({
            "epk": {
                "kty" : "OKP",
                "crv": "X25519",
                "x": "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"
            }
        })
        .as_object()
        .unwrap()
        .clone();

        assert_eq!(response.protected.other_fields, expected_other_fields);
        assert_eq!(response.encrypted_key, "fakekey".as_bytes());
        assert_eq!(response.iv, "randomdata".as_bytes());
        assert_eq!(response.ciphertext, "fakeencoutput".as_bytes());
        assert_eq!(response.tag, "faketag".as_bytes());
        assert_eq!(response.aad, None);
    }

    #[test]
    fn parse_response_with_aad() {
        let data = r#"
        {
            "protected": "eyJhbGciOiJmYWtlYWxnIiwiZW5jIjoiZmFrZWVuYyJ9Cg",
            "encrypted_key": "ZmFrZWtleQ",
            "iv": "cmFuZG9tZGF0YQ",
            "aad": "fakeaad",
            "ciphertext": "ZmFrZWVuY291dHB1dA",
            "tag": "ZmFrZXRhZw"
        }"#;

        let response: Response = serde_json::from_str(data).unwrap();

        assert_eq!(response.protected.alg, "fakealg");
        assert_eq!(response.protected.enc, "fakeenc");
        assert!(response.protected.other_fields.is_empty());
        assert_eq!(response.encrypted_key, "fakekey".as_bytes());
        assert_eq!(response.iv, "randomdata".as_bytes());
        assert_eq!(response.ciphertext, "fakeencoutput".as_bytes());
        assert_eq!(response.tag, "faketag".as_bytes());
        assert_eq!(response.aad, Some("fakeaad".into()));
    }

    #[test]
    fn parse_response_with_protectedheader() {
        let data = r#"
        {
            "protected": "eyJhbGciOiJmYWtlYWxnIiwiZW5jIjoiZmFrZWVuYyIsImZha2VmaWVsZCI6ImZha2V2YWx1ZSJ9",
            "encrypted_key": "ZmFrZWtleQ",
            "iv": "cmFuZG9tZGF0YQ",
            "aad": "fakeaad",
            "ciphertext": "ZmFrZWVuY291dHB1dA",
            "tag": "ZmFrZXRhZw"
        }"#;

        let response: Response = serde_json::from_str(data).unwrap();

        assert_eq!(response.protected.alg, "fakealg");
        assert_eq!(response.protected.enc, "fakeenc");
        assert_eq!(response.protected.other_fields["fakefield"], "fakevalue");
        assert_eq!(response.encrypted_key, "fakekey".as_bytes());
        assert_eq!(response.iv, "randomdata".as_bytes());
        assert_eq!(response.ciphertext, "fakeencoutput".as_bytes());
        assert_eq!(response.tag, "faketag".as_bytes());
        assert_eq!(response.aad, Some("fakeaad".into()));
    }

    #[test]
    fn serialize_response() {
        let response = Response {
            protected: ProtectedHeader {
                alg: "fakealg".into(),
                enc: "fakeenc".into(),
                other_fields: [("fakefield".into(), "fakevalue".into())]
                    .into_iter()
                    .collect(),
            },
            encrypted_key: "fakekey".as_bytes().to_vec(),
            iv: "randomdata".as_bytes().to_vec(),
            aad: Some("fakeaad".into()),
            tag: "faketag".as_bytes().to_vec(),
            ciphertext: "fakeencoutput".as_bytes().to_vec(),
        };

        let expected = json!({
            "protected": "eyJhbGciOiJmYWtlYWxnIiwiZW5jIjoiZmFrZWVuYyIsImZha2VmaWVsZCI6ImZha2V2YWx1ZSJ9",
            "encrypted_key": "ZmFrZWtleQ",
            "iv": "cmFuZG9tZGF0YQ",
            "aad": "fakeaad",
            "ciphertext": "ZmFrZWVuY291dHB1dA",
            "tag": "ZmFrZXRhZw"
        });

        let serialized = serde_json::to_value(&response).unwrap();
        assert_eq!(serialized, expected);
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
