use crate::node::{Network, Node};
use crate::{Client, OffchainClient};
use anyhow::Result;
use async_trait::async_trait;
use ipfs_embed::db::StorageService;
use ipfs_embed::Ipfs;
use libipld::store::StoreParams;
use sp_core::Pair;
use sp_runtime::traits::{Block, IdentifyAccount, Verify};
use std::convert::TryInto;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use substrate_subxt::client::{
    DatabaseConfig, KeystoreConfig, Role, SubxtClient, SubxtClientConfig,
};
use substrate_subxt::{
    sp_core, sp_runtime, system::System, ClientBuilder, Runtime, SignedExtension, SignedExtra,
};
use sunshine_client_net::SubstrateNetwork;
use sunshine_codec::{Multicodec, Multihash};
use sunshine_crypto::keychain::{KeyChain, KeyType, TypedPair};
use sunshine_crypto::keystore::{Keystore, KeystoreLocked, KeystoreUninitialized};
use sunshine_crypto::secrecy::SecretString;
use sunshine_crypto::signer::{GenericSigner, GenericSubxtSigner, Signer};
use sunshine_keystore::Keystore as KeybaseKeystore;
use thiserror::Error;

#[derive(Clone)]
pub struct OffchainParams;

impl StoreParams for OffchainParams {
    const MAX_BLOCK_SIZE: usize = u16::MAX as _;
    type Codecs = Multicodec;
    type Hashes = Multihash;
}

type OffchainNetwork<N> =
    SubstrateNetwork<<N as Node>::Block, <<N as Node>::Block as Block>::Hash, OffchainParams>;
pub type OffchainStoreImpl<N> =
    Ipfs<OffchainParams, StorageService<OffchainParams>, OffchainNetwork<N>>;
pub type KeystoreImpl<K> = sunshine_keystore::Keystore<K>;

#[derive(Debug, Error)]
#[error("{0}")]
pub struct ServiceError(String);

pub struct GenericClient<N: Node, K: KeyType, KS: Keystore<K>, O: Send + Sync> {
    pub(crate) network: Option<Network<N>>,
    pub(crate) keystore: KS,
    pub(crate) keychain: KeyChain,
    pub(crate) signer: Option<GenericSigner<N::Runtime, K>>,
    pub(crate) chain_client: substrate_subxt::Client<N::Runtime>,
    pub(crate) offchain_client: O,
}

#[async_trait]
impl<N, K, KS, O> Client<N> for GenericClient<N, K, KS, O>
where
    N: Node,
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

    fn network(&self) -> Option<&Network<N>> {
        self.network.as_ref()
    }

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

impl<N, K, O: From<OffchainStoreImpl<N>>> GenericClient<N, K, KeybaseKeystore<K>, O>
where
    N: Node,
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
    pub async fn new(
        root: &Path,
        chain_spec: &Path,
    ) -> Result<Self> {
        let bytes = async_std::fs::read(chain_spec).await?;
        let chain_spec = N::chain_spec_from_json_bytes(bytes)?;
        let config = SubxtClientConfig {
            impl_name: N::impl_name(),
            impl_version: N::impl_version(),
            author: N::author(),
            copyright_start_year: N::copyright_start_year(),
            db: DatabaseConfig::ParityDb { path: root.join("light-client") },
            keystore: KeystoreConfig::InMemory,
            role: Role::Light,
            chain_spec,
            telemetry: Some(8000),
        }
        .into_service_config();
        let (task_manager, rpc, network) = N::new_light(config)
            .map_err(|e| ServiceError(format!("{}", e)))?;
        let light_client = SubxtClient::new(task_manager, rpc);
        let chain_client = ClientBuilder::new()
            .set_client(light_client)
            .build()
            .await?;

        let offchain_storage = Arc::new(StorageService::open(root.join("ipfs-embed"))?);
        let offchain_network = Arc::new(SubstrateNetwork::<_, _, OffchainParams>::new(network.clone()));
        let store = Ipfs::new(offchain_storage, offchain_network, Duration::from_secs(5));
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
            network: Some(network),
            keystore,
            keychain,
            signer,
            chain_client,
            offchain_client,
        })
    }
}
