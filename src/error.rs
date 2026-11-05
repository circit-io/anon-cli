use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("csv error: {0}")]
    Csv(#[from] csv::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("policy error: {0}")]
    Policy(#[from] crate::policy::PolicyError),
    #[error("zip error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("pdf error: {0}")]
    Pdf(String),
    #[error("{0}")]
    Message(String),
}
