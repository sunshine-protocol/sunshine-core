use crate::{Client, Network, Node, OffchainClient, OffchainConfig};
use anyhow::Result;
use async_trait::async_trait;
use sp_core::Pair;
use sp_runtime::traits::{IdentifyAccount, Verify};
use std::convert::TryInto;
use std::path::Path;
use substrate_subxt::{
    sp_core, sp_runtime, system::System, ClientBuilder, Runtime, SignedExtension, SignedExtra,
};
use sunshine_crypto::keychain::{KeyChain, KeyType, TypedPair};
use sunshine_crypto::keystore::{Keystore, KeystoreLocked, KeystoreUninitialized};
use sunshine_crypto::secrecy::SecretString;
use sunshine_crypto::signer::{GenericSigner, GenericSubxtSigner, Signer};
use sunshine_keystore::Keystore as KeybaseKeystore;

pub struct GenericClient<N: Node, K: KeyType, O: Send + Sync> {
    network: Network<N>,
    keystore: KeybaseKeystore<K>,
    keychain: KeyChain,
    signer: Option<GenericSigner<N::Runtime, K>>,
    chain_client: substrate_subxt::Client<N::Runtime>,
    offchain_client: O,
}

#[async_trait]
impl<N, K, O> Client<N> for GenericClient<N, K, O>
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
    O: OffchainClient<N>,
{
    type KeyType = K;
    type Keystore = KeybaseKeystore<K>;
    type OffchainClient = O;

    fn network(&self) -> &Network<N> {
        &self.network
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

impl<N, K, O> GenericClient<N, K, O>
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
    O: OffchainClient<N>,
{
    pub async fn new(
        root: &Path,
        chain_spec: &Path,
    ) -> Result<Self> {
        let (client, network) = N::new(root.join("light-client"), chain_spec)?;
        let chain_client = ClientBuilder::new()
            .set_client(client)
            .build()
            .await?;

        let store = OffchainConfig::new(network.clone())
            .path(root.join("ipfs-embed"))
            .build()?;
        let offchain_client = O::from(store);

        let keystore = KeybaseKeystore::<K>::new(root.join("keystore"));
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
            network,
            keystore,
            keychain,
            signer,
            chain_client,
            offchain_client,
        })
    }

    #[cfg(feature = "mock")]
    pub async fn mock(
        test_node: &crate::MockNode<N>,
        account: sp_keyring::AccountKeyring,
    ) -> (Self, tempdir::TempDir) {
        let network = test_node.network.clone();
        let chain_client = ClientBuilder::new()
            .set_client(test_node.client.clone())
            .build()
            .await
            .unwrap();

        let store = OffchainConfig::new(network.clone())
            .temporary(true)
            .build()
            .unwrap();
        let offchain_client = O::from(store);

        let tmp = tempdir::TempDir::new("sunshine-keystore-").unwrap();
        let keystore = KeybaseKeystore::<K>::new(tmp.path());

        let mut me = Self {
            network,
            keystore,
            keychain: KeyChain::new(),
            signer: None,
            chain_client,
            offchain_client,
        };
        let key = TypedPair::from_suri(&account.to_seed()).unwrap();
        let password = SecretString::new("password".to_string());
        me.set_key(key, &password, false).await.unwrap();
        (me, tmp)
    }
}
