use crate::client::GenericClient;
use crate::{Client, NodeConfig};
use libipld::mem::MemStore;
use sp_core::Pair;
pub use sp_keyring::AccountKeyring;
use sp_runtime::traits::{IdentifyAccount, Verify};
use std::convert::TryInto;
use substrate_subxt::client::{
    DatabaseConfig, KeystoreConfig, Role, SubxtClient, SubxtClientConfig,
};
use substrate_subxt::{sp_core, sp_runtime, ClientBuilder, Runtime, SignedExtension, SignedExtra};
use sunshine_crypto::keychain::{KeyChain, KeyType, TypedPair};
use sunshine_crypto::keystore::mock::MemKeystore;
use sunshine_crypto::secrecy::SecretString;
pub use tempdir::TempDir;

pub type TestNode = jsonrpsee::Client;

pub fn build_test_node<N: NodeConfig>() -> (TestNode, TempDir) {
    env_logger::try_init().ok();
    let tmp = TempDir::new("sunshine-identity-").expect("failed to create tempdir");
    let config = SubxtClientConfig {
        impl_name: N::impl_name(),
        impl_version: N::impl_version(),
        author: N::author(),
        copyright_start_year: N::copyright_start_year(),
        db: DatabaseConfig::RocksDb {
            path: tmp.path().into(),
            cache_size: 128,
        },
        keystore: KeystoreConfig::InMemory,
        chain_spec: N::chain_spec_dev(),
        role: Role::Authority(AccountKeyring::Alice),
        enable_telemetry: false,
    }
    .to_service_config();
    let (task_manager, rpc) = N::new_full(config).unwrap();
    let client = SubxtClient::new(task_manager, rpc).into();
    (client, tmp)
}

impl<R, K, O: From<MemStore>> GenericClient<R, K, MemKeystore<K>, O>
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
    pub async fn mock(test_node: &TestNode, account: AccountKeyring) -> Self {
        let mut me = Self {
            keystore: MemKeystore::new(),
            keychain: KeyChain::new(),
            signer: None,
            chain_client: ClientBuilder::new()
                .set_client(test_node.clone())
                .build()
                .await
                .unwrap(),
            offchain_client: O::from(MemStore::default()),
        };
        let key = TypedPair::from_suri(&account.to_seed()).unwrap();
        let password = SecretString::new("password".to_string());
        me.set_key(key, &password, false).await.unwrap();
        me
    }
}
