use thiserror::Error;

#[derive(Debug, Error)]
#[error("keystore is corrupted")]
pub struct KeystoreCorrupted;

#[derive(Debug, Error)]
#[error("gen missmatch")]
pub struct GenMissmatch;
