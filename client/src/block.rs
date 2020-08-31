use crate::Result;
use parity_scale_codec::{Decode, Encode};
use sunshine_codec::trie::{BlockBuilder, Hasher, OffchainBlock, TreeDecode, TreeEncode};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenericBlock<T, N, H: Hasher> {
    pub number: N,
    pub ancestor: Option<H::Out>,
    pub payload: T,
}

impl<T: Encode, N: Encode, H: Hasher> TreeEncode<H> for GenericBlock<T, N, H>
where
    H::Out: Encode + 'static,
{
    fn encode_tree(&self, block: &mut BlockBuilder<H>, _prefix: &str, _proof: bool) {
        block.insert("number".into(), &self.number, true);
        block.insert("ancestor".into(), &self.ancestor, true);
        block.insert("payload".into(), &self.payload, false);
    }
}

impl<T: Decode, N: Decode, H: Hasher> TreeDecode<H> for GenericBlock<T, N, H>
where
    H::Out: Decode + 'static,
{
    fn decode_tree(block: &OffchainBlock<H>, _prefix: &str) -> Result<Self> {
        Ok(Self {
            number: block.get("number")?,
            ancestor: block.get("ancestor")?,
            payload: block.get("payload")?,
        })
    }
}
