use serde::{Deserialize, Serialize};

mod tee;
#[cfg(feature = "tee-sev")]
pub use tee::sev::{SevChallenge, SevRequest};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Tee {
    Sev,
    Sgx,
    Snp,
    Tdx,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Request {
    version: String,
    tee: Tee,
    emit_token: bool,
    extra_params: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Challenge {
    nonce: String,
    extra_params: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TeePubKey {
    algorithm: String,
    #[serde(rename = "pubkey-length")]
    pubkey_length: String,
    pubkey: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Attestation {
    nonce: String,
    tee: Tee,
    #[serde(rename = "tee-pubkey")]
    tee_pubkey: TeePubKey,
    #[serde(rename = "tee-evidence")]
    tee_evidence: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CryptoAnnotation {
    algorithm: String,
    #[serde(rename = "initialization-vector")]
    initialization_vector: String,
    #[serde(rename = "enc-symkey")]
    enc_symkey: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Response {
    output: String,
    #[serde(rename = "crypto-annotation")]
    crypto_annotation: CryptoAnnotation,
    token: String,
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
            "emit_token": false,
            "extra_params": ""
        }"#;

        let request: Request = serde_json::from_str(data).unwrap();

        assert_eq!(request.version, "0.0.0");
        assert_eq!(request.tee, Tee::Sev);
        assert!(!request.emit_token);
        assert_eq!(request.extra_params, "");
    }

    #[test]
    fn parse_challenge() {
        let data = r#"
        {
            "nonce": "42",
            "extra_params": ""
        }"#;

        let challenge: Challenge = serde_json::from_str(data).unwrap();

        assert_eq!(challenge.nonce, "42");
        assert_eq!(challenge.extra_params, "");
    }

    #[test]
    fn parse_response() {
        let data = r#"
        {
            "output": "fakeoutput",
            "crypto-annotation": {
                "algorithm": "fake-4096",
                "initialization-vector": "randomdata",
                "enc-symkey": "fakesymkey"
            },
            "token": "faketoken"
        }"#;

        let response: Response = serde_json::from_str(data).unwrap();

        assert_eq!(response.output, "fakeoutput");
        assert_eq!(response.crypto_annotation.algorithm, "fake-4096");
        assert_eq!(
            response.crypto_annotation.initialization_vector,
            "randomdata"
        );
        assert_eq!(response.crypto_annotation.enc_symkey, "fakesymkey");
        assert_eq!(response.token, "faketoken");
    }

    #[test]
    fn parse_attesation() {
        let data = r#"
        {
            "nonce": "42",
            "tee": "sev",
            "tee-pubkey": {
                "algorithm": "fake-4096",
                "pubkey-length": "4096",
                "pubkey": "fakepubkey"
            },
            "tee-evidence": "fakeevidence"
        }"#;

        let attestation: Attestation = serde_json::from_str(data).unwrap();

        assert_eq!(attestation.nonce, "42");
        assert_eq!(attestation.tee, Tee::Sev);
        assert_eq!(attestation.tee_pubkey.algorithm, "fake-4096");
        assert_eq!(attestation.tee_pubkey.pubkey_length, "4096");
        assert_eq!(attestation.tee_pubkey.pubkey, "fakepubkey");
        assert_eq!(attestation.tee_evidence, "fakeevidence");
    }
}
