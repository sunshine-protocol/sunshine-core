pub use sp_core::crypto::{PublicError, SecretStringError};
use thiserror::Error;

#[derive(Debug, Error)]
#[error("Mnemonic didn't contain enough entropy.")]
pub struct NotEnoughEntropyError;

#[derive(Debug, Error)]
#[error("Unsupported junction.")]
pub struct UnsupportedJunction;

#[derive(Debug, Error)]
#[error("Failed to decrypt message.")]
pub struct DecryptError;

#[derive(Debug, Error)]
#[error("Cannot perform a diffie hellman because crypto algorithm of sk and pk don't match")]
pub struct DiffieHellmanError;

#[derive(Debug, Error)]
#[error("Invalid suri encoded key pair: {0:?}")]
pub struct InvalidSuri(pub SecretStringError);

#[derive(Debug, Error)]
#[error("Invalid ss58 encoded public key: {0:?}")]
pub struct InvalidSs58(pub PublicError);

/// Error returned when the keystore is locked.
#[derive(Debug, Error)]
#[error("keystore is locked")]
pub struct KeystoreLocked;

/// Error returned when the keystore is initialized.
#[derive(Debug, Error)]
#[error("keystore is initialized")]
pub struct KeystoreInitialized;

/// Error returned when the keystore is uninitialized.
#[derive(Debug, Error)]
#[error("keystore is uninitialized")]
pub struct KeystoreUninitialized;

/// Error returned when there is a password missmatch.
#[derive(Debug, Error)]
#[error("password missmatch")]
pub struct PasswordMissmatch;
