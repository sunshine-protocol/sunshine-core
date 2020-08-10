pub use anyhow::{Error, Result};
pub use async_trait::async_trait;
pub use sunshine_codec as codec;
pub use sunshine_crypto as crypto;
pub use sunshine_pallet_utils::cid;
pub use sunshine_pallet_utils::hasher::Blake2Hasher;

use parity_scale_codec::{Decode, Encode};
use substrate_subxt::Runtime;
use sunshine_codec::{BlockBuilder, Hasher, OffchainBlock, TreeDecode, TreeEncode};
pub use sunshine_crypto::keystore::Keystore;
use sunshine_crypto::signer::GenericSubxtSigner;
pub use sunshine_crypto::signer::Signer;

/// The client trait.
#[async_trait]
pub trait Client<R: Runtime>: Send + Sync {
    /// The keystore type.
    type Keystore: Keystore;

    /// The offchain client type.
    type OffchainClient: Send + Sync;

    /// Returns a reference to the keystore.
    fn keystore(&self) -> &Self::Keystore;

    /// Returns a mutable reference to the keystore.
    fn keystore_mut(&mut self) -> &mut Self::Keystore;

    /// Returns a reference to the signer.
    fn signer(&self) -> Result<&dyn Signer<R>>;

    /// Returns a mutable reference to the signer.
    fn signer_mut(&mut self) -> Result<&mut dyn Signer<R>>;

    /// Returns a subxt signer.
    fn chain_signer<'a>(&'a self) -> Result<GenericSubxtSigner<'a, R>> {
        Ok(GenericSubxtSigner(self.signer()?))
    }

    /// Returns a reference to the subxt client.
    fn chain_client(&self) -> &substrate_subxt::Client<R>;

    /// Returns a reference to the offchain client.
    fn offchain_client(&self) -> &Self::OffchainClient;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenericBlock<T, H: Hasher> {
    pub number: u64,
    pub ancestor: Option<H::Out>,
    pub payload: T,
}

impl<T: Encode, H: Hasher> TreeEncode<H> for GenericBlock<T, H>
where
    H::Out: Encode + 'static,
{
    fn encode_tree(&self, block: &mut BlockBuilder<H>, _prefix: &[u8], _proof: bool) {
        block.insert(b"number", &self.number, true);
        block.insert(b"ancestor", &self.ancestor, true);
        block.insert(b"payload", &self.payload, false);
    }
}

impl<T: Decode, H: Hasher> TreeDecode<H> for GenericBlock<T, H>
where
    H::Out: Decode + 'static,
{
    fn decode_tree(block: &OffchainBlock<H>, _prefix: &[u8]) -> Result<Self> {
        Ok(Self {
            number: block.get(b"number")?,
            ancestor: block.get(b"ancestor")?,
            payload: block.get(b"payload")?,
        })
    }
}
