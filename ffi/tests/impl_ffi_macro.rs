use std::ops::Deref;

use ipfs_embed::core::Store;
use substrate_subxt::DefaultNodeRuntime;
use sunshine_client_utils::{GenericClient, Node, OffchainClient, OffchainStore};
use sunshine_crypto::keystore::mock as crypto_mock;
use sunshine_node_utils::mock as node_mock;
#[derive(Copy, Clone)]
struct NopNode;

struct NopOffchainClient<S>(S);

impl<S: Store> From<S> for NopOffchainClient<S> {
    fn from(s: S) -> Self {
        Self(s)
    }
}

impl<S: Store> Deref for NopOffchainClient<S> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S: Store> OffchainClient<S> for NopOffchainClient<S> {}

#[allow(unused)]
impl Node for NopNode {
    type ChainSpec = node_mock::ChainSpec;

    type Runtime = DefaultNodeRuntime;

    type Block = node_mock::runtime::Block;

    fn impl_name() -> &'static str {
        todo!()
    }

    fn impl_version() -> &'static str {
        todo!()
    }

    fn author() -> &'static str {
        todo!()
    }

    fn copyright_start_year() -> i32 {
        todo!()
    }

    fn chain_spec_dev() -> Self::ChainSpec {
        todo!()
    }

    fn chain_spec_from_json_bytes(
        json: Vec<u8>,
    ) -> Result<Self::ChainSpec, sunshine_client_utils::ChainSpecError> {
        todo!()
    }

    fn new_light(
        config: sunshine_client_utils::sc_service::Configuration,
    ) -> Result<
        (
            sunshine_client_utils::sc_service::TaskManager,
            sunshine_client_utils::sc_service::RpcHandlers,
            sunshine_client_utils::Network<Self>,
        ),
        sunshine_client_utils::sc_service::Error,
    > {
        todo!()
    }

    fn new_full(
        config: sunshine_client_utils::sc_service::Configuration,
    ) -> Result<
        (
            sunshine_client_utils::sc_service::TaskManager,
            sunshine_client_utils::sc_service::RpcHandlers,
            sunshine_client_utils::Network<Self>,
        ),
        sunshine_client_utils::sc_service::Error,
    > {
        todo!()
    }
}

type NopClient =
    GenericClient<NopNode, crypto_mock::DeviceKey, NopOffchainClient<OffchainStore<NopNode>>>;

mod ffi {
    #[macro_export]
    macro_rules! impl_ffi {
        (client: $client: ty) => {
            use sunshine_ffi_utils::*;
            gen_ffi!(client = $client);
        };
    }
}

// Test how the macro expands
// cargo expand --package sunshine-ffi-utils --test impl_ffi_macro -- test_impl_ffi_macro
#[test]
fn test_impl_ffi_macro() {
    impl_ffi!(client: NopClient);
}
