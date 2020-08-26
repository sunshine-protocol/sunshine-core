pub use crate::light::ServiceError;
use crate::node::NodeConfig;
use crate::{Client, OffchainClient};
use anyhow::Result;
use async_trait::async_trait;
use ipfs_embed::{Config as OffchainConfig, PeerId, Store as OffchainStore};
use sc_service::ChainSpec;
use sp_core::Pair;
use sp_runtime::traits::{IdentifyAccount, Verify};
use std::convert::TryInto;
use std::path::Path;
use substrate_subxt::{
    sp_core, sp_runtime, system::System, ClientBuilder, Runtime, SignedExtension, SignedExtra,
};
use sunshine_codec::{Multicodec, Multihash};
use sunshine_crypto::keychain::{KeyChain, KeyType, TypedPair};
use sunshine_crypto::keystore::{Keystore, KeystoreLocked, KeystoreUninitialized};
use sunshine_crypto::secrecy::SecretString;
use sunshine_crypto::signer::{GenericSigner, GenericSubxtSigner, Signer};
use sunshine_keystore::Keystore as KeybaseKeystore;

pub type OffchainStoreImpl = OffchainStore<Multicodec, Multihash>;
pub type KeystoreImpl<K> = sunshine_keystore::Keystore<K>;

pub struct GenericClient<N: NodeConfig, K: KeyType, KS: Keystore<K>, O: Send + Sync> {
    pub(crate) keystore: KS,
    pub(crate) keychain: KeyChain,
    pub(crate) signer: Option<GenericSigner<N::Runtime, K>>,
    pub(crate) chain_client: substrate_subxt::Client<N::Runtime>,
    pub(crate) offchain_client: O,
}

#[async_trait]
impl<N, K, KS, O> Client<N::Runtime> for GenericClient<N, K, KS, O>
where
    N: NodeConfig,
    <N::Runtime as System>::AccountId: Into<<N::Runtime as System>::Address>,
    <<<N::Runtime as Runtime>::Extra as SignedExtra<N::Runtime>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    <<N::Runtime as Runtime>::Signature as Verify>::Signer: From<<K::Pair as Pair>::Public>
        + TryInto<<K::Pair as Pair>::Public>
        + IdentifyAccount<AccountId = <N::Runtime as System>::AccountId>
        + Clone
        + Send
        + Sync,
    K: KeyType,
    <K::Pair as Pair>::Signature: Into<<N::Runtime as Runtime>::Signature>,
    KS: Keystore<K>,
    O: OffchainClient,
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

    fn signer(&self) -> Result<&dyn Signer<N::Runtime>> {
        let signer_ref = self.signer.as_ref().ok_or(KeystoreLocked)?;
        Ok(signer_ref as _)
    }

    fn signer_mut(&mut self) -> Result<&mut dyn Signer<N::Runtime>> {
        let signer_ref = self.signer.as_mut().ok_or(KeystoreLocked)?;
        Ok(signer_ref as _)
    }

    fn chain_signer<'a>(&'a self) -> Result<GenericSubxtSigner<'a, N::Runtime>> {
        Ok(GenericSubxtSigner(self.signer()?))
    }

    #[allow(clippy::type_complexity)]
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

    fn chain_client(&self) -> &substrate_subxt::Client<N::Runtime> {
        &self.chain_client
    }

    fn offchain_client(&self) -> &Self::OffchainClient {
        &self.offchain_client
    }
}

pub enum Config<'a> {
    Rpc { url: &'a str },
    Light { chain_spec: &'a Path },
}

impl<'a> From<&'a str> for Config<'a> {
    fn from(url: &'a str) -> Self {
        Self::Rpc { url }
    }
}

impl<'a> From<&'a Path> for Config<'a> {
    fn from(chain_spec: &'a Path) -> Self {
        Self::Light { chain_spec }
    }
}

impl<N, K, O: From<OffchainStoreImpl>> GenericClient<N, K, KeybaseKeystore<K>, O>
where
    N: NodeConfig,
    <N::Runtime as System>::AccountId: Into<<N::Runtime as System>::Address>,
    <<<N::Runtime as Runtime>::Extra as SignedExtra<N::Runtime>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    <<N::Runtime as Runtime>::Signature as Verify>::Signer: From<<K::Pair as Pair>::Public>
        + TryInto<<K::Pair as Pair>::Public>
        + IdentifyAccount<AccountId = <N::Runtime as System>::AccountId>
        + Clone
        + Send
        + Sync,
    K: KeyType,
    <K::Pair as Pair>::Signature: Into<<N::Runtime as Runtime>::Signature>,
    O: Send + Sync,
{
    pub async fn new<'a, C: Into<Config<'a>>>(
        root: &Path,
        config: C,
    ) -> Result<Self> {
        let db = sled::open(root.join("db"))?;
        let db_ipfs = db.open_tree("ipfs")?;

        let (chain_client, chain_spec) = match config.into() {
            Config::Light { chain_spec } => {
                let db_light = db.open_tree("substrate")?;
                let (light_client, chain_spec) =
                    crate::light::build_light_client::<N>(db_light, chain_spec).await?;
                let client = ClientBuilder::new()
                    .set_client(light_client)
                    .build()
                    .await?;
                (client, Some(chain_spec))
            }
            Config::Rpc { url } => {
                let client = ClientBuilder::new().set_url(url).build().await?;
                (client, None)
            }
        };

        let mut config = OffchainConfig::new(db_ipfs, Default::default());
        if let Some(chain_spec) = chain_spec {
            config.network.boot_nodes = chain_spec
                .boot_nodes()
                .iter()
                // substrate rc6 uses libp2p 0.23, ipfs embed uses libp2p 0.24
                .map(|x| (x.multiaddr.clone(), PeerId::from_bytes(x.peer_id.as_bytes().to_vec()).unwrap()))
                .collect();
        }
        let store = OffchainStore::new(config)?;
        let offchain_client = O::from(store);

        let keystore = KeystoreImpl::<K>::new(root.join("keystore"));
        let mut keychain = KeyChain::new();
        let signer = match keystore.device_key().await {
            Ok(key) => {
                keychain.insert(key.clone());
                Some(GenericSigner::new(key))
            }
            Err(err) => {
                if err.downcast_ref::<KeystoreLocked>().is_some() ||
                    err.downcast_ref::<KeystoreUninitialized>().is_some() {
                    None
                } else {
                    return Err(err);
                }
            }
        };

        Ok(Self {
            keystore,
            keychain,
            signer,
            chain_client,
            offchain_client,
        })
    }
}
