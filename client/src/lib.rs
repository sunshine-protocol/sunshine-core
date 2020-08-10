pub use anyhow::{Error, Result};
pub use async_trait::async_trait;
pub use sunshine_codec as codec;
pub use sunshine_crypto as crypto;
pub use sunshine_pallet_utils::cid;
pub use sunshine_pallet_utils::hasher::Blake2Hasher;

use parity_scale_codec::{Decode, Encode};
use sp_core::Pair;
use sp_runtime::traits::{IdentifyAccount, Verify};
use std::convert::TryInto;
use substrate_subxt::{sp_core, sp_runtime, Runtime, SignedExtension, SignedExtra};
use sunshine_codec::{BlockBuilder, Hasher, OffchainBlock, TreeDecode, TreeEncode};
use sunshine_crypto::keychain::{KeyChain, KeyType, TypedPair};
pub use sunshine_crypto::keystore::{Keystore, KeystoreLocked};
use sunshine_crypto::secrecy::SecretString;
pub use sunshine_crypto::signer::Signer;
use sunshine_crypto::signer::{GenericSigner, GenericSubxtSigner};

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

pub struct GenericClient<R: Runtime, K: KeyType, KS: Keystore<K>, O: Send + Sync> {
    keystore: KS,
    keychain: KeyChain,
    signer: Option<GenericSigner<R, K>>,
    chain_client: substrate_subxt::Client<R>,
    offchain_client: O,
}

#[async_trait]
impl<R, K, KS, O> Client<R> for GenericClient<R, K, KS, O>
where
    R: Runtime,
    R::AccountId: Into<R::Address>,
    <<R::Extra as SignedExtra<R>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    <R::Signature as Verify>::Signer: From<<K::Pair as Pair>::Public>
        + TryInto<<K::Pair as Pair>::Public>
        + IdentifyAccount<AccountId = R::AccountId>
        + Clone
        + Send
        + Sync,
    K: KeyType,
    <K::Pair as Pair>::Signature: Into<R::Signature>,
    KS: Keystore<K>,
    O: Send + Sync,
{
    type Keystore = KS;
    type KeyType = K;
    type OffchainClient = O;

    fn keystore(&self) -> &Self::Keystore {
        &self.keystore
    }

    fn keystore_mut(&mut self) -> &mut Self::Keystore {
        &mut self.keystore
    }

    fn keychain(&self) -> &KeyChain {
        &self.keychain
    }

    fn keychain_mut(&mut self) -> &mut KeyChain {
        &mut self.keychain
    }

    fn signer(&self) -> Result<&dyn Signer<R>> {
        let signer_ref = self.signer.as_ref().ok_or(KeystoreLocked)?;
        Ok(signer_ref as _)
    }

    fn signer_mut(&mut self) -> Result<&mut dyn Signer<R>> {
        let signer_ref = self.signer.as_mut().ok_or(KeystoreLocked)?;
        Ok(signer_ref as _)
    }

    fn chain_signer<'a>(&'a self) -> Result<GenericSubxtSigner<'a, R>> {
        Ok(GenericSubxtSigner(self.signer()?))
    }

    async fn set_key(
        &mut self,
        key: TypedPair<Self::KeyType>,
        password: &SecretString,
        force: bool,
    ) -> Result<()> {
        self.keystore_mut().set_key(&key, password, force).await?;
        self.keychain_mut().insert(key.clone());
        self.signer = Some(GenericSigner::new(key));
        Ok(())
    }

    async fn lock(&mut self) -> Result<()> {
        self.signer = None;
        self.keychain.remove::<Self::KeyType>();
        self.keystore.lock().await?;
        Ok(())
    }

    async fn unlock(&mut self, password: &SecretString) -> Result<()> {
        let key = self.keystore.unlock(password).await?;
        self.keychain.insert(key.clone());
        self.signer = Some(GenericSigner::new(key));
        Ok(())
    }

    fn chain_client(&self) -> &substrate_subxt::Client<R> {
        &self.chain_client
    }

    fn offchain_client(&self) -> &Self::OffchainClient {
        &self.offchain_client
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenericBlock<T, H: Hasher> {
    pub number: u64,
    pub ancestor: Option<H::Out>,
    pub payload: T,
}

impl<T: Encode, H: Hasher> TreeEncode<H> for GenericBlock<T, H>
where
    H::Out: Encode + 'static,
{
    fn encode_tree(&self, block: &mut BlockBuilder<H>, _prefix: &[u8], _proof: bool) {
        block.insert(b"number", &self.number, true);
        block.insert(b"ancestor", &self.ancestor, true);
        block.insert(b"payload", &self.payload, false);
    }
}

impl<T: Decode, H: Hasher> TreeDecode<H> for GenericBlock<T, H>
where
    H::Out: Decode + 'static,
{
    fn decode_tree(block: &OffchainBlock<H>, _prefix: &[u8]) -> Result<Self> {
        Ok(Self {
            number: block.get(b"number")?,
            ancestor: block.get(b"ancestor")?,
            payload: block.get(b"payload")?,
        })
    }
}
