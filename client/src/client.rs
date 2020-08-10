use crate::{Client, NodeConfig};
use anyhow::Result;
use async_trait::async_trait;
use ipfs_embed::{Config, Store};
use sc_service::ChainSpec;
use sp_core::Pair;
use sp_runtime::traits::{IdentifyAccount, Verify};
use std::convert::TryInto;
use std::path::Path;
use substrate_subxt::{sp_core, sp_runtime, ClientBuilder, Runtime, SignedExtension, SignedExtra};
use sunshine_crypto::keychain::{KeyChain, KeyType, TypedPair};
use sunshine_crypto::keystore::{Keystore, KeystoreLocked};
use sunshine_crypto::secrecy::SecretString;
use sunshine_crypto::signer::{GenericSigner, GenericSubxtSigner, Signer};
use sunshine_keystore::Keystore as KeybaseKeystore;

pub struct GenericClient<R: Runtime, K: KeyType, KS: Keystore<K>, O: Send + Sync> {
    pub(crate) keystore: KS,
    pub(crate) keychain: KeyChain,
    pub(crate) signer: Option<GenericSigner<R, K>>,
    pub(crate) chain_client: substrate_subxt::Client<R>,
    pub(crate) offchain_client: O,
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

impl<R, K, O: From<Store>> GenericClient<R, K, KeybaseKeystore<K>, O>
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
    O: Send + Sync,
{
    pub async fn new<N: NodeConfig<Runtime = R>>(
        root: &Path,
        chain_spec: Option<&Path>,
    ) -> Result<Self> {
        let db = sled::open(root.join("db"))?;
        let db_ipfs = db.open_tree("ipfs")?;

        let (chain_client, chain_spec) = if let Some(chain_spec) = chain_spec {
            let db_light = db.open_tree("substrate")?;
            let (light_client, chain_spec) =
                crate::light::build_light_client::<N>(db_light, chain_spec).await?;
            let client = ClientBuilder::new()
                .set_client(light_client)
                .build()
                .await?;
            (client, Some(chain_spec))
        } else {
            let client = ClientBuilder::new().build().await?;
            (client, None)
        };

        let mut config = Config::new(db_ipfs, Default::default());
        if let Some(chain_spec) = chain_spec {
            config.network.boot_nodes = chain_spec
                .boot_nodes()
                .iter()
                .map(|x| (x.multiaddr.clone(), x.peer_id.clone()))
                .collect();
        }
        let store = Store::new(config)?;
        let offchain_client = O::from(store);

        Ok(Self {
            keystore: KeybaseKeystore::new(root.join("keystore")),
            keychain: KeyChain::new(),
            signer: None,
            chain_client,
            offchain_client,
        })
    }
}
