pub use sc_service::{
    error::Error as ScServiceError, ChainSpec, Configuration, RpcHandlers, TaskManager,
};
use sp_runtime::traits::Block;
use std::sync::Arc;
use substrate_subxt::{sp_runtime, Runtime};
use thiserror::Error;

pub type Network<N> = Arc<
    sc_network::NetworkService<
        <N as Node>::Block,
        <<N as Node>::Block as Block>::Hash,
        crate::codec::Multihash,
    >,
>;

pub trait Node: 'static {
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
    ) -> std::result::Result<(TaskManager, RpcHandlers, Network<Self>), ScServiceError>;
    fn new_full(
        config: Configuration,
    ) -> std::result::Result<(TaskManager, RpcHandlers, Network<Self>), ScServiceError>;
}

#[derive(Debug, Error)]
#[error("Invalid chain spec: {0}")]
pub struct ChainSpecError(pub String);
