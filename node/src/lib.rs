//! Default node service implementation.

pub use sc_basic_authorship;
pub use sc_client_api;
pub use sc_consensus;
pub use sc_consensus_aura;
pub use sc_finality_grandpa;
pub use sc_network;
pub use sc_service;
pub use sc_transaction_pool;
pub use sp_consensus;
pub use sp_consensus_aura;
pub use sp_core;
pub use sp_finality_grandpa;
pub use sp_inherents;

#[macro_export]
macro_rules! node_service {
    ($block:ty, $api:ty, $executor:ty) => {
        use sc_client_api::{ExecutorProvider, RemoteBackend};
        use sc_network::NetworkService;
        use sc_service::{Configuration, PartialComponents, RpcHandlers, TaskManager};
        use sp_consensus_aura::sr25519::AuthorityPair as AuraPair;
        use sp_runtime::traits::Block;
        use std::sync::Arc;
        use std::time::Duration;
        use tiny_multihash::MultihashDigest;
        use $crate::{
            sc_basic_authorship, sc_client_api, sc_consensus, sc_consensus_aura,
            sc_finality_grandpa, sc_network, sc_service, sc_transaction_pool,
            sp_consensus, sp_consensus_aura, sp_core, sp_finality_grandpa, sp_inherents,
        };

        type FullClient = sc_service::TFullClient<$block, $api, $executor>;
        type FullBackend = sc_service::TFullBackend<$block>;
        type FullSelectChain = sc_consensus::LongestChain<FullBackend, $block>;

        pub type AuraId = sp_consensus_aura::sr25519::AuthorityId;
        pub type GrandpaId = sp_finality_grandpa::AuthorityId;

        pub fn new_partial(
            config: &Configuration,
        ) -> Result<
            sc_service::PartialComponents<
                FullClient,
                FullBackend,
                FullSelectChain,
                sp_consensus::DefaultImportQueue<$block, FullClient>,
                sc_transaction_pool::FullPool<$block, FullClient>,
                (
                    sc_finality_grandpa::GrandpaBlockImport<
                        FullBackend,
                        $block,
                        FullClient,
                        FullSelectChain,
                    >,
                    sc_finality_grandpa::LinkHalf<$block, FullClient, FullSelectChain>,
                ),
            >,
            sc_service::error::Error,
        > {
            let inherent_data_providers = sp_inherents::InherentDataProviders::new();

            let (client, backend, keystore, task_manager) =
                sc_service::new_full_parts::<$block, $api, $executor>(&config)?;
            let client = Arc::new(client);

            let select_chain = sc_consensus::LongestChain::new(backend.clone());

            let transaction_pool = sc_transaction_pool::BasicPool::new_full(
                config.transaction_pool.clone(),
                config.prometheus_registry(),
                task_manager.spawn_handle(),
                client.clone(),
            );

            let (grandpa_block_import, grandpa_link) = sc_finality_grandpa::block_import(
                client.clone(),
                &(client.clone() as Arc<_>),
                select_chain.clone(),
            )?;

            let aura_block_import = sc_consensus_aura::AuraBlockImport::<_, _, _, AuraPair>::new(
                grandpa_block_import.clone(),
                client.clone(),
            );

            let import_queue = sc_consensus_aura::import_queue::<_, _, _, AuraPair, _, _>(
                sc_consensus_aura::slot_duration(&*client)?,
                aura_block_import,
                Some(Box::new(grandpa_block_import.clone())),
                None,
                client.clone(),
                inherent_data_providers.clone(),
                &task_manager.spawn_handle(),
                config.prometheus_registry(),
                sp_consensus::CanAuthorWithNativeVersion::new(client.executor().clone()),
            )?;

            Ok(sc_service::PartialComponents {
                client,
                backend,
                task_manager,
                import_queue,
                keystore,
                select_chain,
                transaction_pool,
                inherent_data_providers,
                other: (grandpa_block_import, grandpa_link),
            })
        }

        /// Builds a new service for a full client.
        pub fn new_full<M: MultihashDigest>(
            config: Configuration,
        ) -> Result<(
            TaskManager,
            RpcHandlers,
            Arc<NetworkService<$block, <$block as Block>::Hash, M>>,
        ), sc_service::error::Error> {
            let PartialComponents {
                client,
                backend,
                mut task_manager,
                import_queue,
                keystore,
                select_chain,
                transaction_pool,
                inherent_data_providers,
                other: (block_import, grandpa_link),
            } = new_partial(&config)?;

            let finality_proof_provider =
                sc_finality_grandpa::FinalityProofProvider::new_for_service(
                    backend.clone(),
                    client.clone(),
                );

            let (network, network_status_sinks, system_rpc_tx, network_starter) =
                sc_service::build_network(sc_service::BuildNetworkParams {
                    config: &config,
                    client: client.clone(),
                    transaction_pool: transaction_pool.clone(),
                    spawn_handle: task_manager.spawn_handle(),
                    import_queue,
                    on_demand: None,
                    block_announce_validator_builder: None,
                    finality_proof_request_builder: None,
                    finality_proof_provider: Some(finality_proof_provider.clone()),
                })?;

            if config.offchain_worker.enabled {
                sc_service::build_offchain_workers(
                    &config,
                    backend.clone(),
                    task_manager.spawn_handle(),
                    client.clone(),
                    network.clone(),
                );
            }

            let role = config.role.clone();
            let force_authoring = config.force_authoring;
            let name = config.network.node_name.clone();
            let enable_grandpa = !config.disable_grandpa;
            let prometheus_registry = config.prometheus_registry().cloned();
            let telemetry_connection_sinks = sc_service::TelemetryConnectionSinks::default();

            let rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
                network: network.clone(),
                client: client.clone(),
                keystore: keystore.clone(),
                task_manager: &mut task_manager,
                transaction_pool: transaction_pool.clone(),
                telemetry_connection_sinks: telemetry_connection_sinks.clone(),
                rpc_extensions_builder: Box::new(|_, _| ()),
                on_demand: None,
                remote_blockchain: None,
                backend,
                network_status_sinks,
                system_rpc_tx,
                config,
            })?;

            if role.is_authority() {
                let proposer = sc_basic_authorship::ProposerFactory::new(
                    client.clone(),
                    transaction_pool,
                    prometheus_registry.as_ref(),
                );

                let can_author_with =
                    sp_consensus::CanAuthorWithNativeVersion::new(client.executor().clone());

                let aura = sc_consensus_aura::start_aura::<_, _, _, _, _, AuraPair, _, _, _>(
                    sc_consensus_aura::slot_duration(&*client)?,
                    client.clone(),
                    select_chain,
                    block_import,
                    proposer,
                    network.clone(),
                    inherent_data_providers.clone(),
                    force_authoring,
                    keystore.clone(),
                    can_author_with,
                )?;

                // the AURA authoring task is considered essential, i.e. if it
                // fails we take down the service with it.
                task_manager
                    .spawn_essential_handle()
                    .spawn_blocking("aura", aura);
            }

            // if the node isn't actively participating in consensus then it doesn't
            // need a keystore, regardless of which protocol we use below.
            let keystore = if role.is_authority() {
                Some(keystore as sp_core::traits::BareCryptoStorePtr)
            } else {
                None
            };

            let grandpa_config = sc_finality_grandpa::Config {
                // FIXME #1578 make this available through chainspec
                gossip_duration: Duration::from_millis(333),
                justification_period: 512,
                name: Some(name),
                observer_enabled: false,
                keystore,
                is_authority: role.is_network_authority(),
            };

            if enable_grandpa {
                // start the full GRANDPA voter
                // NOTE: non-authorities could run the GRANDPA observer protocol, but at
                // this point the full voter should provide better guarantees of block
                // and vote data availability than the observer. The observer has not
                // been tested extensively yet and having most nodes in a network run it
                // could lead to finality stalls.
                let grandpa_config = sc_finality_grandpa::GrandpaParams {
                    config: grandpa_config,
                    link: grandpa_link,
                    network: network.clone(),
                    inherent_data_providers,
                    telemetry_on_connect: Some(telemetry_connection_sinks.on_connect_stream()),
                    voting_rule: sc_finality_grandpa::VotingRulesBuilder::default().build(),
                    prometheus_registry,
                    shared_voter_state: sc_finality_grandpa::SharedVoterState::empty(),
                };

                // the GRANDPA voter task is considered infallible, i.e.
                // if it fails we take down the service with it.
                task_manager.spawn_essential_handle().spawn_blocking(
                    "grandpa-voter",
                    sc_finality_grandpa::run_grandpa_voter(grandpa_config)?,
                );
            } else {
                sc_finality_grandpa::setup_disabled_grandpa(
                    client,
                    &inherent_data_providers,
                    network.clone(),
                )?;
            }

            network_starter.start_network();
            Ok((
                task_manager,
                rpc_handlers,
                network,
            ))
        }

        /// Builds a new service for a light client.
        pub fn new_light<M: MultihashDigest>(
            config: Configuration,
        ) -> Result<(
            TaskManager,
            RpcHandlers,
            Arc<NetworkService<$block, <$block as Block>::Hash, M>>,
        ), sc_service::error::Error> {
            let (client, backend, keystore, mut task_manager, on_demand) =
                sc_service::new_light_parts::<$block, $api, $executor>(&config)?;

            let transaction_pool = Arc::new(sc_transaction_pool::BasicPool::new_light(
                config.transaction_pool.clone(),
                config.prometheus_registry(),
                task_manager.spawn_handle(),
                client.clone(),
                on_demand.clone(),
            ));

            let grandpa_block_import = sc_finality_grandpa::light_block_import(
                client.clone(),
                backend.clone(),
                &(client.clone() as Arc<_>),
                Arc::new(on_demand.checker().clone()) as Arc<_>,
            )?;
            let finality_proof_import = grandpa_block_import.clone();
            let finality_proof_request_builder =
                finality_proof_import.create_finality_proof_request_builder();

            let import_queue = sc_consensus_aura::import_queue::<_, _, _, AuraPair, _, _>(
                sc_consensus_aura::slot_duration(&*client)?,
                grandpa_block_import,
                None,
                Some(Box::new(finality_proof_import)),
                client.clone(),
                sp_inherents::InherentDataProviders::new(),
                &task_manager.spawn_handle(),
                config.prometheus_registry(),
                sp_consensus::NeverCanAuthor,
            )?;

            let finality_proof_provider =
                sc_finality_grandpa::FinalityProofProvider::new_for_service(
                    backend.clone(),
                    client.clone(),
                );

            let (network, network_status_sinks, system_rpc_tx, network_starter) =
                sc_service::build_network(sc_service::BuildNetworkParams {
                    config: &config,
                    client: client.clone(),
                    transaction_pool: transaction_pool.clone(),
                    spawn_handle: task_manager.spawn_handle(),
                    import_queue,
                    on_demand: Some(on_demand.clone()),
                    block_announce_validator_builder: None,
                    finality_proof_request_builder: Some(finality_proof_request_builder),
                    finality_proof_provider: Some(finality_proof_provider),
                })?;

            if config.offchain_worker.enabled {
                sc_service::build_offchain_workers(
                    &config,
                    backend.clone(),
                    task_manager.spawn_handle(),
                    client.clone(),
                    network.clone(),
                );
            }

            let rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
                remote_blockchain: Some(backend.remote_blockchain()),
                transaction_pool,
                task_manager: &mut task_manager,
                on_demand: Some(on_demand),
                rpc_extensions_builder: Box::new(|_, _| ()),
                telemetry_connection_sinks: sc_service::TelemetryConnectionSinks::default(),
                config,
                client,
                keystore,
                backend,
                network: network.clone(),
                network_status_sinks,
                system_rpc_tx,
            })?;

            network_starter.start_network();
            Ok((
                task_manager,
                rpc_handlers,
                network,
            ))
        }
    };
}

#[cfg(any(test, feature = "mock"))]
pub mod mock {
    pub mod runtime {
        use frame_support::weights::{constants, Weight};
        use sp_runtime::traits::Block as BlockT;
        use sp_runtime::Perbill;

        pub type Hasher = sp_runtime::traits::BlakeTwo256;
        pub type Hash = sp_core::H256;
        pub type BlockNumber = u32;
        pub type Header = sp_runtime::generic::Header<BlockNumber, Hasher>;
        pub type SignedExtra = (
            frame_system::CheckSpecVersion<Runtime>,
            frame_system::CheckTxVersion<Runtime>,
            frame_system::CheckGenesis<Runtime>,
            frame_system::CheckEra<Runtime>,
            frame_system::CheckNonce<Runtime>,
            frame_system::CheckWeight<Runtime>,
        );
        pub type UncheckedExtrinsic = sp_runtime::generic::UncheckedExtrinsic<
            sp_runtime::AccountId32,
            Call,
            sp_runtime::MultiSignature,
            SignedExtra,
        >;
        pub type Block = sp_runtime::generic::Block<Header, UncheckedExtrinsic>;
        pub type OpaqueBlock = sp_runtime::generic::Block<Header, sp_runtime::OpaqueExtrinsic>;
        pub type Executive = frame_executive::Executive<
            Runtime,
            Block,
            frame_system::ChainContext<Runtime>,
            Runtime,
            AllModules,
        >;
        pub type AuraId = sp_consensus_aura::sr25519::AuthorityId;
        pub type GrandpaId = sp_finality_grandpa::AuthorityId;

        pub const VERSION: sp_version::RuntimeVersion = sp_version::RuntimeVersion {
            spec_name: sp_runtime::create_runtime_str!("sunshine-node-utils"),
            impl_name: sp_runtime::create_runtime_str!("sunshine-node-utils"),
            authoring_version: 1,
            spec_version: 1,
            impl_version: 1,
            apis: RUNTIME_API_VERSIONS,
            transaction_version: 1,
        };

        pub fn native_version() -> sp_version::NativeVersion {
            sp_version::NativeVersion {
                runtime_version: VERSION,
                can_author_with: Default::default(),
            }
        }

        frame_support::construct_runtime!(
            pub enum Runtime where
                Block = Block,
                NodeBlock = OpaqueBlock,
                UncheckedExtrinsic = UncheckedExtrinsic
            {
                System: frame_system::{Module, Call, Storage, Config, Event<T>},
            }
        );

        frame_support::parameter_types! {
            pub const BlockHashCount: BlockNumber = 2400;
            pub const MaximumBlockWeight: Weight = 2 * constants::WEIGHT_PER_SECOND;
            pub const AvailableBlockRatio: Perbill = Perbill::from_percent(75);
            pub const MaximumBlockLength: u32 = 5 * 1024 * 1024;
            pub const Version: sp_version::RuntimeVersion = VERSION;
        }

        impl frame_system::Trait for Runtime {
            // Generated by construct_runtime!
            type Origin = Origin;
            type Call = Call;
            type Event = Event;
            type Version = Version;
            type ModuleToIndex = ModuleToIndex;

            // Basic types
            type Hashing = Hasher;
            type Hash = Hash;
            type BlockNumber = BlockNumber;
            type Header = Header;
            type AccountId = sp_runtime::AccountId32;
            type Index = u32;
            type AccountData = ();
            type Lookup = sp_runtime::traits::IdentityLookup<Self::AccountId>;

            // Config
            type BaseCallFilter = ();
            type BlockHashCount = BlockHashCount;
            type MaximumBlockWeight = MaximumBlockWeight;
            type AvailableBlockRatio = AvailableBlockRatio;
            type MaximumBlockLength = MaximumBlockLength;
            type MaximumExtrinsicWeight = ();
            type SystemWeightInfo = ();
            type DbWeight = constants::RocksDbWeight;
            type ExtrinsicBaseWeight = constants::ExtrinsicBaseWeight;
            type BlockExecutionWeight = constants::BlockExecutionWeight;

            // Events
            type OnNewAccount = ();
            type OnKilledAccount = ();
        }

        sp_api::impl_runtime_apis! {
            impl sp_api::Core<Block> for Runtime {
                fn version() -> sp_version::RuntimeVersion {
                    VERSION
                }

                fn execute_block(block: Block) {
                    Executive::execute_block(block)
                }

                fn initialize_block(header: &<Block as BlockT>::Header) {
                    Executive::initialize_block(header)
                }
            }

            impl sp_api::Metadata<Block> for Runtime {
                fn metadata() -> sp_core::OpaqueMetadata {
                    Runtime::metadata().into()
                }
            }

            impl sp_block_builder::BlockBuilder<Block> for Runtime {
                fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> sp_runtime::ApplyExtrinsicResult {
                    Executive::apply_extrinsic(extrinsic)
                }

                fn finalize_block() -> <Block as BlockT>::Header {
                    Executive::finalize_block()
                }

                fn inherent_extrinsics(data: sp_inherents::InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
                    data.create_extrinsics()
                }

                fn check_inherents(
                    block: Block,
                    data: sp_inherents::InherentData,
                ) -> sp_inherents::CheckInherentsResult {
                    data.check_extrinsics(&block)
                }

                fn random_seed() -> <Block as BlockT>::Hash {
                    unimplemented!()
                }
            }

            impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
                fn validate_transaction(
                    source: sp_runtime::transaction_validity::TransactionSource,
                    tx: <Block as BlockT>::Extrinsic,
                ) -> sp_runtime::transaction_validity::TransactionValidity {
                    Executive::validate_transaction(source, tx)
                }
            }

            impl sp_offchain::OffchainWorkerApi<Block> for Runtime {
                fn offchain_worker(header: &<Block as BlockT>::Header) {
                    Executive::offchain_worker(header)
                }
            }

            impl sp_consensus_aura::AuraApi<Block, AuraId> for Runtime {
                fn slot_duration() -> u64 {
                    unimplemented!()
                }

                fn authorities() -> Vec<AuraId> {
                    unimplemented!()
                }
            }

            impl sp_session::SessionKeys<Block> for Runtime {
                fn generate_session_keys(_seed: Option<Vec<u8>>) -> Vec<u8> {
                    unimplemented!()
                }

                fn decode_session_keys(
                    _encoded: Vec<u8>,
                ) -> Option<Vec<(Vec<u8>, sp_core::crypto::KeyTypeId)>> {
                    unimplemented!()
                }
            }

            impl sp_finality_grandpa::GrandpaApi<Block> for Runtime {
                fn grandpa_authorities() -> sp_finality_grandpa::AuthorityList {
                    unimplemented!()
                }

                fn submit_report_equivocation_unsigned_extrinsic(
                    _equivocation_proof: sp_finality_grandpa::EquivocationProof<
                        <Block as BlockT>::Hash,
                        sp_api::NumberFor<Block>,
                    >,
                    _key_owner_proof: sp_finality_grandpa::OpaqueKeyOwnershipProof,
                ) -> Option<()> {
                    None
                }

                fn generate_key_ownership_proof(
                    _set_id: sp_finality_grandpa::SetId,
                    _authority_id: GrandpaId,
                ) -> Option<sp_finality_grandpa::OpaqueKeyOwnershipProof> {
                    None
                }
            }
        }
    }

    sc_executor::native_executor_instance!(
        pub Executor,
        runtime::api::dispatch,
        runtime::native_version,
    );

    node_service!(runtime::OpaqueBlock, runtime::RuntimeApi, Executor);
    pub type ChainSpec = sc_service::GenericChainSpec<runtime::GenesisConfig>;

    pub fn empty_chain_spec() -> ChainSpec {
        ChainSpec::from_genesis(
            "empty",
            "empty",
            sc_service::ChainType::Development,
            || {
                runtime::GenesisConfig {
                    frame_system: Some(runtime::SystemConfig {
                        code: Default::default(),
                        changes_trie_config: Default::default(),
                    }),
                }
            },
            vec![],
            None,
            None,
            None,
            None,
        )
    }
}
