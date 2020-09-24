pub use anyhow::{Error, Result};
pub use async_trait::async_trait;
pub use sc_network;
pub use sc_service;
#[cfg(feature = "mock")]
pub use sp_keyring::AccountKeyring;
pub use sunshine_codec as codec;
pub use sunshine_crypto as crypto;
pub use sunshine_crypto::keystore::{Keystore, KeystoreLocked};
pub use sunshine_crypto::secrecy::SecretString;
pub use sunshine_crypto::signer::Signer;
pub use sunshine_keystore as keystore;

mod block;
mod client;

pub use block::*;
pub use client::*;

use ipfs_embed::db::StorageService;
use ipfs_embed::Ipfs;
use libipld::store::{Store, StoreParams};
use sc_service::{ChainSpec, Configuration, RpcHandlers, TaskManager};
use sp_runtime::traits::Block;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use substrate_subxt::client::{
    DatabaseConfig, KeystoreConfig, Role, SubxtClient, SubxtClientConfig,
};
use substrate_subxt::{sp_runtime, Runtime};
use sunshine_client_net::SubstrateNetwork;
use sunshine_crypto::keychain::{KeyChain, KeyType, TypedPair};
use sunshine_crypto::signer::GenericSubxtSigner;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("Invalid chain spec: {0}")]
pub struct ChainSpecError(pub String);

#[derive(Debug, Error)]
#[error("config dir not found")]
pub struct ConfigDirNotFound;

#[derive(Debug, Error)]
#[error("{0}")]
pub struct ServiceError(String);

pub type Network<N> = Arc<
    sc_network::NetworkService<
        <N as Node>::Block,
        <<N as Node>::Block as Block>::Hash,
        codec::Multihash,
    >,
>;

#[cfg(feature = "mock")]
pub struct MockNode<N: Node> {
    pub client: jsonrpsee::Client,
    pub network: Network<N>,
    pub tmp: tempdir::TempDir,
}

pub trait Node: Clone + Copy + Unpin + Send + Sync + 'static {
    type ChainSpec: ChainSpec + Clone + 'static;
    type Runtime: Runtime + 'static;
    type Block: Block + 'static;
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
    ) -> std::result::Result<(TaskManager, RpcHandlers, Network<Self>), sc_service::Error>;
    fn new_full(
        config: Configuration,
    ) -> std::result::Result<(TaskManager, RpcHandlers, Network<Self>), sc_service::Error>;

    fn new(path: PathBuf, chain_spec: &Path) -> Result<(jsonrpsee::Client, Network<Self>)> {
        let bytes = std::fs::read(chain_spec)?;
        let chain_spec = Self::chain_spec_from_json_bytes(bytes)?;
        let config = SubxtClientConfig {
            impl_name: Self::impl_name(),
            impl_version: Self::impl_version(),
            author: Self::author(),
            copyright_start_year: Self::copyright_start_year(),
            db: DatabaseConfig::ParityDb { path },
            keystore: KeystoreConfig::InMemory,
            role: Role::Light,
            chain_spec,
            telemetry: Some(8000),
        }
        .into_service_config();
        let (task_manager, rpc, network) =
            Self::new_light(config).map_err(|e| ServiceError(format!("{}", e)))?;
        let client = SubxtClient::new(task_manager, rpc).into();
        Ok((client, network))
    }

    #[cfg(feature = "mock")]
    fn new_mock() -> MockNode<Self> {
        use tempdir::TempDir;

        let tmp = TempDir::new("sunshine-core-").expect("failed to create tempdir");
        let config = SubxtClientConfig {
            impl_name: Self::impl_name(),
            impl_version: Self::impl_version(),
            author: Self::author(),
            copyright_start_year: Self::copyright_start_year(),
            db: DatabaseConfig::ParityDb {
                path: tmp.path().into(),
            },
            keystore: KeystoreConfig::InMemory,
            chain_spec: Self::chain_spec_dev(),
            role: Role::Authority(AccountKeyring::Alice),
            telemetry: None,
        }
        .into_service_config();
        let (task_manager, rpc, network) = Self::new_full(config).unwrap();
        let client = SubxtClient::new(task_manager, rpc).into();
        MockNode {
            client,
            network,
            tmp,
        }
    }
}

/// The client trait.
#[async_trait]
pub trait Client<N: Node>: Send + Sync {
    /// The key type stored in the keystore.
    type KeyType: KeyType;

    /// The keystore type.
    type Keystore: Keystore<Self::KeyType>;

    /// The offchain client type.
    type OffchainClient: OffchainClient<OffchainStore<N>>;

    /// Returns the network service.
    fn network(&self) -> &Network<N>;

    /// Returns a reference to the keystore.
    fn keystore(&self) -> &Self::Keystore;

    /// Returns a mutable reference to the keystore.
    fn keystore_mut(&mut self) -> &mut Self::Keystore;

    /// Returns a reference to the keychain.
    fn keychain(&self) -> &KeyChain;

    /// Returns a mutable reference to the keychain.
    fn keychain_mut(&mut self) -> &mut KeyChain;

    /// Returns a reference to the signer.
    fn signer(&self) -> Result<&dyn Signer<N::Runtime>>;

    /// Returns a mutable reference to the signer.
    fn signer_mut(&mut self) -> Result<&mut dyn Signer<N::Runtime>>;

    /// Returns a subxt signer.
    fn chain_signer<'a>(&'a self) -> Result<GenericSubxtSigner<'a, N::Runtime>> {
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
    fn chain_client(&self) -> &substrate_subxt::Client<N::Runtime>;

    /// Returns a reference to the offchain client.
    fn offchain_client(&self) -> &Self::OffchainClient;
}

pub type OffchainNetwork<N> =
    SubstrateNetwork<<N as Node>::Block, <<N as Node>::Block as Block>::Hash, OffchainConfig<N>>;
pub type OffchainStore<N> =
    Ipfs<OffchainConfig<N>, StorageService<OffchainConfig<N>>, OffchainNetwork<N>>;

/// The offchain client trait.
pub trait OffchainClient<S: Store>: Deref<Target = S> + From<S> + Send + Sync {}

#[derive(Clone)]
pub struct OffchainConfig<N: Node> {
    pub db_config: sled::Config,
    pub cache_size: usize,
    pub sweep_interval: Duration,
    pub network_timeout: Duration,
    pub network: Network<N>,
}

impl<N: Node> StoreParams for OffchainConfig<N> {
    const MAX_BLOCK_SIZE: usize = u16::MAX as _;
    type Codecs = codec::Multicodec;
    type Hashes = codec::Multihash;
}

impl<N: Node> OffchainConfig<N> {
    pub fn new(network: Network<N>) -> Self {
        Self {
            db_config: sled::Config::new(),
            cache_size: 1000,
            sweep_interval: Duration::from_secs(30),
            network_timeout: Duration::from_secs(3),
            network,
        }
    }

    pub fn temporary(mut self, temporary: bool) -> Self {
        self.db_config = self.db_config.temporary(temporary);
        self
    }

    pub fn path<T: AsRef<Path>>(mut self, path: T) -> Self {
        self.db_config = self.db_config.path(path);
        self
    }

    pub fn build(self) -> Result<OffchainStore<N>> {
        let offchain_storage = Arc::new(StorageService::open(
            &self.db_config,
            self.cache_size,
            self.sweep_interval,
        )?);
        let offchain_network = Arc::new(SubstrateNetwork::<_, _, Self>::new(self.network));
        Ok(Ipfs::new(
            offchain_storage,
            offchain_network,
            self.network_timeout,
        ))
    }
}
