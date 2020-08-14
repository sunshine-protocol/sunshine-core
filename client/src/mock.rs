use crate::client::GenericClient;
use crate::node::NodeConfig;
use crate::Client;
use libipld::mem::MemStore;
use sp_core::Pair;
pub use sp_keyring::AccountKeyring;
use sp_runtime::traits::{IdentifyAccount, Verify};
use std::convert::TryInto;
use substrate_subxt::client::{
    DatabaseConfig, KeystoreConfig, Role, SubxtClient, SubxtClientConfig,
};
use substrate_subxt::{
    sp_core, sp_runtime, system::System, ClientBuilder, Runtime, SignedExtension, SignedExtra,
};
use sunshine_crypto::keychain::{KeyChain, KeyType, TypedPair};
use sunshine_crypto::secrecy::SecretString;
pub use tempdir::TempDir;

pub type OffchainStoreImpl = libipld::mem::MemStore;
pub type KeystoreImpl<K> = sunshine_crypto::keystore::mock::MemKeystore<K>;
pub type TestNode = jsonrpsee::Client;

pub fn build_test_node<N: NodeConfig>() -> (TestNode, TempDir) {
    let tmp = TempDir::new("sunshine-identity-").expect("failed to create tempdir");
    let config = SubxtClientConfig {
        impl_name: N::impl_name(),
        impl_version: N::impl_version(),
        author: N::author(),
        copyright_start_year: N::copyright_start_year(),
        db: DatabaseConfig::ParityDb {
            path: tmp.path().into(),
        },
        keystore: KeystoreConfig::InMemory,
        chain_spec: N::chain_spec_dev(),
        role: Role::Authority(AccountKeyring::Alice),
        telemetry: None,
    }
    .to_service_config();
    let (task_manager, rpc) = N::new_full(config).unwrap();
    let client = SubxtClient::new(task_manager, rpc).into();
    (client, tmp)
}

impl<N, K, O: From<MemStore>> GenericClient<N, K, KeystoreImpl<K>, O>
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
    pub async fn mock(test_node: &TestNode, account: AccountKeyring) -> Self {
        let mut me = Self {
            keystore: KeystoreImpl::<K>::new(),
            keychain: KeyChain::new(),
            signer: None,
            chain_client: ClientBuilder::new()
                .set_client(test_node.clone())
                .build()
                .await
                .unwrap(),
            offchain_client: O::from(OffchainStoreImpl::default()),
        };
        let key = TypedPair::from_suri(&account.to_seed()).unwrap();
        let password = SecretString::new("password".to_string());
        me.set_key(key, &password, false).await.unwrap();
        me
    }
}

impl<N, K, O: From<MemStore>> GenericClient<N, K, crate::client::KeystoreImpl<K>, O>
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
    pub async fn mock_with_keystore(
        test_node: &TestNode,
        account: AccountKeyring,
    ) -> (Self, TempDir) {
        let tmp = TempDir::new("sunshine-keystore").unwrap();
        let mut me = Self {
            keystore: crate::client::KeystoreImpl::<K>::new(tmp.path()),
            keychain: KeyChain::new(),
            signer: None,
            chain_client: ClientBuilder::new()
                .set_client(test_node.clone())
                .build()
                .await
                .unwrap(),
            offchain_client: O::from(OffchainStoreImpl::default()),
        };
        let key = TypedPair::from_suri(&account.to_seed()).unwrap();
        let password = SecretString::new("password".to_string());
        me.set_key(key, &password, false).await.unwrap();
        (me, tmp)
    }
}
