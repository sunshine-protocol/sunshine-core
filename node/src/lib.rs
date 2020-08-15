pub use sc_basic_authorship;
pub use sc_client_api;
pub use sc_consensus;
pub use sc_consensus_aura;
pub use sc_finality_grandpa;
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
        use sc_service::{Configuration, RpcHandlers, ServiceComponents, TaskManager};
        use sp_consensus_aura::sr25519::AuthorityPair as AuraPair;
        use std::sync::Arc;
        use std::time::Duration;
        use $crate::{
            sc_basic_authorship, sc_client_api, sc_consensus, sc_consensus_aura,
            sc_finality_grandpa, sc_service, sc_transaction_pool, sp_consensus, sp_consensus_aura,
            sp_core, sp_finality_grandpa, sp_inherents,
        };

        type FullClient = sc_service::TFullClient<$block, $api, $executor>;
        type FullBackend = sc_service::TFullBackend<$block>;
        type FullSelectChain = sc_consensus::LongestChain<FullBackend, $block>;

        pub type AuraId = sp_consensus_aura::sr25519::AuthorityId;
        pub type GrandpaId = sp_finality_grandpa::AuthorityId;

        pub fn new_full_params(
            config: Configuration,
        ) -> Result<
            (
                sc_service::ServiceParams<
                    $block,
                    FullClient,
                    sc_consensus_aura::AuraImportQueue<$block, FullClient>,
                    sc_transaction_pool::FullPool<$block, FullClient>,
                    (),
                    FullBackend,
                >,
                FullSelectChain,
                sp_inherents::InherentDataProviders,
                sc_finality_grandpa::GrandpaBlockImport<
                    FullBackend,
                    $block,
                    FullClient,
                    FullSelectChain,
                >,
                sc_finality_grandpa::LinkHalf<$block, FullClient, FullSelectChain>,
            ),
            sc_service::error::Error,
        > {
            let inherent_data_providers = sp_inherents::InherentDataProviders::new();

            let (client, backend, keystore, task_manager) =
                sc_service::new_full_parts::<$block, $api, $executor>(&config)?;
            let client = Arc::new(client);

            let select_chain = sc_consensus::LongestChain::new(backend.clone());

            let pool_api = sc_transaction_pool::FullChainApi::new(
                client.clone(),
                config.prometheus_registry(),
            );
            let transaction_pool = sc_transaction_pool::BasicPool::new_full(
                config.transaction_pool.clone(),
                Arc::new(pool_api),
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

            let import_queue = sc_consensus_aura::import_queue::<_, _, _, AuraPair, _>(
                sc_consensus_aura::slot_duration(&*client)?,
                aura_block_import,
                Some(Box::new(grandpa_block_import.clone())),
                None,
                client.clone(),
                inherent_data_providers.clone(),
                &task_manager.spawn_handle(),
                config.prometheus_registry(),
            )?;

            let provider =
                client.clone() as Arc<dyn sc_finality_grandpa::StorageAndProofProvider<_, _>>;
            let finality_proof_provider = Arc::new(
                sc_finality_grandpa::FinalityProofProvider::new(backend.clone(), provider),
            );

            let params = sc_service::ServiceParams {
                backend,
                client,
                import_queue,
                keystore,
                task_manager,
                transaction_pool,
                config,
                block_announce_validator_builder: None,
                finality_proof_request_builder: None,
                finality_proof_provider: Some(finality_proof_provider),
                on_demand: None,
                remote_blockchain: None,
                rpc_extensions_builder: Box::new(|_| ()),
            };

            Ok((
                params,
                select_chain,
                inherent_data_providers,
                grandpa_block_import,
                grandpa_link,
            ))
        }

        /// Builds a new service for a full client.
        pub fn new_full(
            config: Configuration,
        ) -> Result<(TaskManager, Arc<RpcHandlers>), sc_service::error::Error> {
            let (params, select_chain, inherent_data_providers, block_import, grandpa_link) =
                new_full_params(config)?;

            let (
                role,
                force_authoring,
                name,
                enable_grandpa,
                prometheus_registry,
                client,
                transaction_pool,
                keystore,
            ) = {
                let sc_service::ServiceParams {
                    config,
                    client,
                    transaction_pool,
                    keystore,
                    ..
                } = &params;

                (
                    config.role.clone(),
                    config.force_authoring,
                    config.network.node_name.clone(),
                    !config.disable_grandpa,
                    config.prometheus_registry().cloned(),
                    client.clone(),
                    transaction_pool.clone(),
                    keystore.clone(),
                )
            };

            let ServiceComponents {
                task_manager,
                rpc_handlers,
                network,
                telemetry_on_connect_sinks,
                ..
            } = sc_service::build(params)?;

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
                    network,
                    inherent_data_providers,
                    telemetry_on_connect: Some(telemetry_on_connect_sinks.on_connect_stream()),
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
                    network,
                )?;
            }

            Ok((task_manager, rpc_handlers))
        }

        /// Builds a new service for a light client.
        pub fn new_light(
            config: Configuration,
        ) -> Result<(TaskManager, Arc<RpcHandlers>), sc_service::error::Error> {
            let (client, backend, keystore, task_manager, on_demand) =
                sc_service::new_light_parts::<$block, $api, $executor>(&config)?;

            let transaction_pool_api = Arc::new(sc_transaction_pool::LightChainApi::new(
                client.clone(),
                on_demand.clone(),
            ));
            let transaction_pool = sc_transaction_pool::BasicPool::new_light(
                config.transaction_pool.clone(),
                transaction_pool_api,
                config.prometheus_registry(),
                task_manager.spawn_handle(),
            );

            let grandpa_block_import = sc_finality_grandpa::light_block_import(
                client.clone(),
                backend.clone(),
                &(client.clone() as Arc<_>),
                Arc::new(on_demand.checker().clone()) as Arc<_>,
            )?;
            let finality_proof_import = grandpa_block_import.clone();
            let finality_proof_request_builder =
                finality_proof_import.create_finality_proof_request_builder();

            let import_queue = sc_consensus_aura::import_queue::<_, _, _, AuraPair, _>(
                sc_consensus_aura::slot_duration(&*client)?,
                grandpa_block_import,
                None,
                Some(Box::new(finality_proof_import)),
                client.clone(),
                sp_inherents::InherentDataProviders::new(),
                &task_manager.spawn_handle(),
                config.prometheus_registry(),
            )?;

            let finality_proof_provider =
                Arc::new(sc_finality_grandpa::FinalityProofProvider::new(
                    backend.clone(),
                    client.clone() as Arc<_>,
                ));

            sc_service::build(sc_service::ServiceParams {
                block_announce_validator_builder: None,
                finality_proof_request_builder: Some(finality_proof_request_builder),
                finality_proof_provider: Some(finality_proof_provider),
                on_demand: Some(on_demand),
                remote_blockchain: Some(backend.remote_blockchain()),
                rpc_extensions_builder: Box::new(|_| ()),
                transaction_pool: Arc::new(transaction_pool),
                config,
                client,
                import_queue,
                keystore,
                backend,
                task_manager,
            })
            .map(
                |ServiceComponents {
                     task_manager,
                     rpc_handlers,
                     ..
                 }| (task_manager, rpc_handlers),
            )
        }
    };
}
