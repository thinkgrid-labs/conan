use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConanError {
    #[error("signature parse error: {0}")]
    SignatureParse(String),

    #[error("policy parse error: {0}")]
    PolicyParse(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("network capture error: {0}")]
    NetworkCapture(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(String),
}
