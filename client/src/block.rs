use crate::Result;
use parity_scale_codec::{Decode, Encode};
use sunshine_codec::{BlockBuilder, Hasher, OffchainBlock, TreeDecode, TreeEncode};

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
