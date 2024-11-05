use thiserror::Error;

#[derive(Error, Debug)]
pub enum AttestError {
    #[error("Failed to initialize guest attestation library")]
    Initialization,
    #[error("Failed to convert endpoint URL to CString")]
    Convertion,
    #[error("CVM guest attestation library returned error: {0}")]
    LibraryError(i32),
}
