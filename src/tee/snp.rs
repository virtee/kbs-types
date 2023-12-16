use serde::{Deserialize, Serialize};

use crate::String;

#[derive(Clone, Serialize, Deserialize)]
pub struct SnpAttestation {
    pub report: String,
    pub gen: String,
}
