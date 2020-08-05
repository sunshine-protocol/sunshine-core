use sp_core::crypto::{PublicError, SecretStringError};
use thiserror::Error;

#[derive(Debug, Error)]
#[error("Mnemonic didn't contain enough entropy.")]
pub struct NotEnoughEntropyError;

#[derive(Debug, Error)]
#[error("Failed to decrypt message.")]
pub struct DecryptError;

#[derive(Debug, Error)]
#[error("Invalid suri encoded key pair: {0:?}")]
pub struct InvalidSuri(pub SecretStringError);

#[derive(Debug, Error)]
#[error("Invalid ss58 encoded public key: {0:?}")]
pub struct InvalidSs58(pub PublicError);
