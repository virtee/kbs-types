use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct SnpRequest {
    pub workload_id: String,
}
