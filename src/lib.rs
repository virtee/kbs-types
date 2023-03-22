use serde::{Deserialize, Serialize};

mod tee;
#[cfg(feature = "tee-sev")]
pub use tee::sev::{SevChallenge, SevRequest};

#[cfg(feature = "tee-snp")]
pub use tee::snp::{SnpAttestation, SnpRequest};

#[derive(Serialize, Clone, Deserialize, Debug, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Tee {
    AzSnpVtpm,
    Sev,
    Sgx,
    Snp,
    Tdx,

    // This value is only used for testing an attestation server, and should not
    // be used in an actual attestation scenario.
    Sample,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Request {
    pub version: String,
    pub tee: Tee,
    #[serde(rename = "extra-params")]
    pub extra_params: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Challenge {
    pub nonce: String,
    #[serde(rename = "extra-params")]
    pub extra_params: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TeePubKey {
    pub alg: String,
    #[serde(rename = "k-mod")]
    pub k_mod: String,
    #[serde(rename = "k-exp")]
    pub k_exp: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Attestation {
    #[serde(rename = "tee-pubkey")]
    pub tee_pubkey: TeePubKey,
    #[serde(rename = "tee-evidence")]
    pub tee_evidence: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Response {
    pub protected: String,
    pub encrypted_key: String,
    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
}

#[derive(Serialize, Deserialize, Debug)]
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
    fn parse_attesation() {
        let data = r#"
        {
            "tee-pubkey": {
                "alg": "fakealgorithm",
                "k-mod": "fakemodulus",
                "k-exp": "fakeexponent"
            },
            "tee-evidence": "fakeevidence"
        }"#;

        let attestation: Attestation = serde_json::from_str(data).unwrap();

        assert_eq!(attestation.tee_pubkey.alg, "fakealgorithm");
        assert_eq!(attestation.tee_pubkey.k_mod, "fakemodulus");
        assert_eq!(attestation.tee_pubkey.k_exp, "fakeexponent");
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
