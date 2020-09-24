use ipfs_embed_core::{Cid, Multiaddr, Network, NetworkEvent, PeerId, StoreParams, Stream};
pub use sc_network;
use sc_network::{BitswapEvent, DhtEvent, Event, ExHashT, Key, NetworkService, NetworkStateInfo};
use sp_runtime::traits::Block;
use std::convert::TryFrom;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

pub struct SubstrateNetwork<B: Block + 'static, H: ExHashT, S: StoreParams + 'static> {
    _marker: PhantomData<S>,
    net: Arc<NetworkService<B, H, S::Hashes>>,
}

impl<B: Block + 'static, H: ExHashT, S: StoreParams + 'static> SubstrateNetwork<B, H, S> {
    pub fn new(net: Arc<NetworkService<B, H, S::Hashes>>) -> Self {
        Self {
            _marker: PhantomData,
            net,
        }
    }
}

impl<B: Block + 'static, H: ExHashT, S: StoreParams + Unpin + 'static> Network<S>
    for SubstrateNetwork<B, H, S>
{
    type Subscription = Subscription;

    fn local_peer_id(&self) -> &PeerId {
        self.net.local_peer_id()
    }

    fn external_addresses(&self) -> Vec<Multiaddr> {
        self.net.external_addresses()
    }

    fn provide(&self, cid: &Cid) {
        let key = Key::new(&cid.to_bytes());
        self.net.provide(key);
    }

    fn unprovide(&self, cid: &Cid) {
        let key = Key::new(&cid.to_bytes());
        self.net.unprovide(key);
    }

    fn providers(&self, cid: &Cid) {
        let key = Key::new(&cid.to_bytes());
        self.net.providers(key);
    }

    fn connect(&self, _peer_id: PeerId) {
        // TODO
    }

    fn want(&self, cid: Cid, priority: i32) {
        self.net.bitswap_want_block(cid, priority)
    }

    fn cancel(&self, cid: Cid) {
        self.net.bitswap_cancel_block(cid)
    }

    fn send_to(&self, peer_id: PeerId, cid: Cid, data: Vec<u8>) {
        self.net
            .bitswap_send_block(peer_id, cid, data.into_boxed_slice())
    }

    fn send(&self, cid: Cid, data: Vec<u8>) {
        self.net
            .bitswap_send_block_all(cid, data.into_boxed_slice())
    }

    fn subscribe(&self) -> Self::Subscription {
        Subscription {
            events: Box::new(self.net.event_stream("ipfs-embed")),
        }
    }
}

pub struct Subscription {
    events: Box<dyn Stream<Item = Event> + Send + Unpin>,
}

impl Stream for Subscription {
    type Item = NetworkEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        loop {
            let ev = match Pin::new(&mut self.events).poll_next(cx) {
                Poll::Ready(Some(ev)) => ev,
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(None),
            };
            let ev = match ev {
                Event::Dht(DhtEvent::Providers(key, providers)) => {
                    if let Ok(cid) = Cid::try_from(key.as_ref()) {
                        NetworkEvent::Providers(cid, providers)
                    } else {
                        continue;
                    }
                }
                Event::Dht(DhtEvent::GetProvidersFailed(key)) => {
                    if let Ok(cid) = Cid::try_from(key.as_ref()) {
                        NetworkEvent::GetProvidersFailed(cid)
                    } else {
                        continue;
                    }
                }
                Event::Dht(DhtEvent::Providing(key)) => {
                    if let Ok(cid) = Cid::try_from(key.as_ref()) {
                        NetworkEvent::Providing(cid)
                    } else {
                        continue;
                    }
                }
                Event::Dht(DhtEvent::StartProvidingFailed(key)) => {
                    if let Ok(cid) = Cid::try_from(key.as_ref()) {
                        NetworkEvent::StartProvidingFailed(cid)
                    } else {
                        continue;
                    }
                }
                Event::Dht(DhtEvent::BootstrapComplete) => NetworkEvent::BootstrapComplete,
                Event::Bitswap(BitswapEvent::ReceivedBlock(peer_id, cid, data)) => {
                    NetworkEvent::ReceivedBlock(peer_id, cid, data.to_vec())
                }
                Event::Bitswap(BitswapEvent::ReceivedWant(peer_id, cid, priority)) => {
                    NetworkEvent::ReceivedWant(peer_id, cid, priority)
                }
                _ => continue,
            };
            return Poll::Ready(Some(ev));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::task;
    use ipfs_embed::db::StorageService;
    use ipfs_embed::Ipfs;
    use libipld::block::Block;
    use libipld::error::BlockNotFound;
    use libipld::multihash::SHA2_256;
    use libipld::raw::RawCodec;
    use libipld::store::{DefaultStoreParams, Store};
    use sc_network::config::{MultiaddrWithPeerId, TransportConfig};
    use sp_runtime::traits::Block as BlockT;
    use std::time::Duration;
    use substrate_subxt::client::{DatabaseConfig, KeystoreConfig, Role, SubxtClientConfig};
    use sunshine_node_utils::mock::{empty_chain_spec, new_light, runtime};
    use tempdir::TempDir;

    type Storage = StorageService<DefaultStoreParams>;
    type Network = SubstrateNetwork<
        runtime::OpaqueBlock,
        <runtime::OpaqueBlock as BlockT>::Hash,
        DefaultStoreParams,
    >;
    type DefaultIpfs = Ipfs<DefaultStoreParams, Storage, Network>;

    fn create_store(bootstrap: Vec<(Multiaddr, PeerId)>, boot: bool) -> (DefaultIpfs, TempDir) {
        let tmp = TempDir::new("").unwrap();
        let mut config = SubxtClientConfig {
            impl_name: "impl_name",
            impl_version: "impl_version",
            author: "author",
            copyright_start_year: 2020,
            db: DatabaseConfig::ParityDb {
                path: tmp.path().join("light-client"),
            },
            keystore: KeystoreConfig::InMemory,
            role: Role::Light,
            chain_spec: empty_chain_spec(),
            telemetry: None,
        }
        .into_service_config();
        if boot {
            config.network.listen_addresses = vec!["/ip4/127.0.0.1/tcp/33333".parse().unwrap()];
            config.network.public_addresses = vec!["/ip4/127.0.0.1/tcp/33333".parse().unwrap()];
        } else {
            config.network.listen_addresses = vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()];
        }
        config.network.transport = TransportConfig::Normal {
            enable_mdns: bootstrap.is_empty(),
            allow_private_ipv4: true,
            wasm_external_transport: None,
            use_yamux_flow_control: false,
        };
        config.network.boot_nodes = bootstrap
            .into_iter()
            .map(|(multiaddr, peer_id)| MultiaddrWithPeerId { multiaddr, peer_id })
            .collect();
        config.network.allow_non_globals_in_dht = true;
        let (mut task_manager, _rpc, network) = new_light(config).unwrap();
        task::spawn(async move { task_manager.future().await });

        let sled_config = sled::Config::new().temporary(true);
        let cache_size = 10;
        let sweep_interval = Duration::from_millis(10000);
        let network_timeout = Duration::from_secs(5);

        let storage =
            Arc::new(StorageService::open(&sled_config, cache_size, sweep_interval).unwrap());
        let network = Arc::new(SubstrateNetwork::new(network));
        let ipfs = Ipfs::new(storage, network, network_timeout);
        (ipfs, tmp)
    }

    fn create_block(bytes: &[u8]) -> Block<DefaultStoreParams> {
        Block::encode(RawCodec, SHA2_256, bytes).unwrap()
    }

    #[async_std::test]
    async fn test_local_store() {
        env_logger::try_init().ok();
        let (store, _tmp) = create_store(vec![], false);
        let block = create_block(b"test_local_store");
        store.insert(&block).await.unwrap();
        let block2 = store.get(block.cid()).await.unwrap();
        assert_eq!(block.data(), block2.data());
    }

    #[async_std::test]
    #[cfg(not(target_os = "macos"))] // mdns doesn't work on macos in github actions
    async fn test_exchange_mdns() {
        env_logger::try_init().ok();
        let (store1, _tmp1) = create_store(vec![], false);
        let (store2, _tmp2) = create_store(vec![], false);
        let block = create_block(b"test_exchange_mdns");
        store1.insert(&block).await.unwrap();
        let block2 = store2.get(block.cid()).await.unwrap();
        assert_eq!(block.data(), block2.data());
    }

    #[async_std::test]
    #[cfg(not(target_os = "macos"))] // mdns doesn't work on macos in github action
    async fn test_received_want_before_insert() {
        env_logger::try_init().ok();
        let (store1, _tmp1) = create_store(vec![], false);
        let (store2, _tmp2) = create_store(vec![], false);
        let block = create_block(b"test_received_want_before_insert");

        let get_cid = *block.cid();
        let get = task::spawn(async move { store2.get(&get_cid).await });

        task::sleep(Duration::from_millis(100)).await;

        store1.insert(&block).await.unwrap();

        let block2 = get.await.unwrap();
        assert_eq!(block.data(), block2.data());
    }

    #[async_std::test]
    async fn test_exchange_kad() {
        env_logger::try_init().ok();
        let (store, _tmp) = create_store(vec![], true);
        // make sure bootstrap node has started
        task::sleep(Duration::from_millis(1000)).await;
        let bootstrap = vec![(
            store.external_addresses()[0].clone(),
            store.local_peer_id().clone(),
        )];
        let (store1, _tmp1) = create_store(bootstrap.clone(), false);
        let (store2, _tmp2) = create_store(bootstrap, false);

        let block = create_block(b"test_exchange_kad");
        store1.insert(&block).await.unwrap();
        // wait for entry to propagate
        task::sleep(Duration::from_millis(1000)).await;
        let block2 = store2.get(block.cid()).await.unwrap();
        assert_eq!(block.data(), block2.data());
    }

    #[async_std::test]
    async fn test_provider_not_found() {
        env_logger::try_init().ok();
        let (store1, _tmp) = create_store(vec![], false);
        let block = create_block(b"test_provider_not_found");
        if store1
            .get(block.cid())
            .await
            .unwrap_err()
            .downcast_ref::<BlockNotFound>()
            .is_none()
        {
            panic!("expected block not found error");
        }
    }
}
