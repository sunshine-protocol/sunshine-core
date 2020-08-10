pub use anyhow::{Error, Result};
pub use async_trait::async_trait;
pub use sunshine_codec as codec;
pub use sunshine_crypto as crypto;
pub use sunshine_crypto::keystore::{Keystore, KeystoreLocked};
pub use sunshine_crypto::secrecy::SecretString;
pub use sunshine_crypto::signer::Signer;
pub use sunshine_keystore as keystore;
pub use sunshine_pallet_utils::cid;
pub use sunshine_pallet_utils::hasher::Blake2Hasher;

pub mod block;
pub mod client;
mod light;
#[cfg(feature = "mock")]
pub mod mock;

use substrate_subxt::Runtime;
use sunshine_crypto::keychain::{KeyChain, KeyType, TypedPair};
use sunshine_crypto::signer::GenericSubxtSigner;

/// The client trait.
#[async_trait]
pub trait Client<R: Runtime>: Send + Sync {
    /// The key type stored in the keystore.
    type KeyType: KeyType;

    /// The keystore type.
    type Keystore: Keystore<Self::KeyType>;

    /// The offchain client type.
    type OffchainClient: Send + Sync;

    /// Returns a reference to the keystore.
    fn keystore(&self) -> &Self::Keystore;

    /// Returns a mutable reference to the keystore.
    fn keystore_mut(&mut self) -> &mut Self::Keystore;

    /// Returns a reference to the keychain.
    fn keychain(&self) -> &KeyChain;

    /// Returns a mutable reference to the keychain.
    fn keychain_mut(&mut self) -> &mut KeyChain;

    /// Returns a reference to the signer.
    fn signer(&self) -> Result<&dyn Signer<R>>;

    /// Returns a mutable reference to the signer.
    fn signer_mut(&mut self) -> Result<&mut dyn Signer<R>>;

    /// Returns a subxt signer.
    fn chain_signer<'a>(&'a self) -> Result<GenericSubxtSigner<'a, R>> {
        Ok(GenericSubxtSigner(self.signer()?))
    }

    /// Sets the key of the keystore and adds it to the keychain.
    ///
    /// If the force flag is false it will return a `KeystoreInitialized` error
    /// if the keystore is initialized. Otherwise it will overwrite the key.
    async fn set_key(
        &mut self,
        key: TypedPair<Self::KeyType>,
        password: &SecretString,
        force: bool,
    ) -> Result<()>;

    /// Locks the keystore and removes the key from the keychain.
    ///
    /// If the keystore is locked or initialized, this is a noop.
    async fn lock(&mut self) -> Result<()>;

    /// Unlocks the keystore with a password and adds the key to the keychain.
    ///
    /// If the keystore is uninitialized it will return a `KeystoreUninitialized`
    /// error and if the password doesn't match it will return a `PasswordMissmatch`
    /// error.
    async fn unlock(&mut self, password: &SecretString) -> Result<()>;

    /// Returns a reference to the subxt client.
    fn chain_client(&self) -> &substrate_subxt::Client<R>;

    /// Returns a reference to the offchain client.
    fn offchain_client(&self) -> &Self::OffchainClient;
}

pub use sc_service::{
    error::Error as ScServiceError, ChainSpec, Configuration, RpcHandlers, TaskManager,
};
use std::sync::Arc;
use thiserror::Error;

pub trait NodeConfig {
    type ChainSpec: ChainSpec + Clone + 'static;
    type Runtime: Runtime + 'static;
    fn impl_name() -> &'static str;
    fn impl_version() -> &'static str;
    fn author() -> &'static str;
    fn copyright_start_year() -> i32;
    fn chain_spec_dev() -> Self::ChainSpec;
    fn chain_spec_from_json_bytes(
        json: Vec<u8>,
    ) -> std::result::Result<Self::ChainSpec, ChainSpecError>;
    fn new_light(
        config: Configuration,
    ) -> core::result::Result<(TaskManager, Arc<RpcHandlers>), ScServiceError>;
    fn new_full(
        config: Configuration,
    ) -> core::result::Result<(TaskManager, Arc<RpcHandlers>), ScServiceError>;
}

#[derive(Debug, Error)]
#[error("Invalid chain spec: {0}")]
pub struct ChainSpecError(pub String);
