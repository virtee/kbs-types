use thiserror::Error;

pub type Result<T> = std::result::Result<T, KbsTypesError>;

#[derive(Error, Debug)]
pub enum KbsTypesError {
    #[error("Serialize/Deserialize error")]
    Disconnect(#[from] serde_json::Error),
}
