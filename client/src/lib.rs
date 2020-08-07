use anyhow::Result;
use async_trait::async_trait;
use substrate_subxt::Runtime;
use sunshine_crypto::keystore::Keystore;
use sunshine_crypto::signer::Signer;

/// The client trait.
#[async_trait]
pub trait Client<T: Runtime>: Send + Sync {
    /// The keystore type.
    type Keystore: Keystore;

    /// The offchain client type.
    type OffchainClient: Send + Sync;

    /// Returns a reference to the keystore.
    fn keystore(&self) -> &Self::Keystore;

    /// Returns a mutable reference to the keystore.
    fn keystore_mut(&mut self) -> &mut Self::Keystore;

    /// Returns a reference to the signer.
    fn signer(&self) -> Result<&dyn Signer<T>>;

    /// Returns a mutable reference to the signer.
    fn signer_mut(&mut self) -> Result<&mut dyn Signer<T>>;

    /// Returns a reference to the subxt client.
    fn chain_client(&self) -> &substrate_subxt::Client<T>;

    /// Returns a reference to the offchain client.
    fn offchain_client(&self) -> &Self::OffchainClient;
}
