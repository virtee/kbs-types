use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct SnpRequest {
    pub workload_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct SnpAttestation {
    pub report: String,
    pub cert_chain: String,
    pub gen: String,
}
