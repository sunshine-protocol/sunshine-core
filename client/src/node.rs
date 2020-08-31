pub use sc_service::{
    error::Error as ScServiceError, ChainSpec, Configuration, RpcHandlers, TaskManager,
};
use substrate_subxt::Runtime;
use thiserror::Error;

pub trait NodeConfig {
    type ChainSpec: ChainSpec + Clone + 'static;
    type Runtime: Runtime + 'static;
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
    ) -> core::result::Result<(TaskManager, RpcHandlers), ScServiceError>;
    fn new_full(
        config: Configuration,
    ) -> core::result::Result<(TaskManager, RpcHandlers), ScServiceError>;
}

#[derive(Debug, Error)]
#[error("Invalid chain spec: {0}")]
pub struct ChainSpecError(pub String);
