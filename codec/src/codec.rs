use core::convert::TryFrom;
use libipld::cbor::DagCborCodec;
use libipld::cid::Cid;
use libipld::codec::{Codec, Decode, Encode};
use libipld::error::{Result, UnsupportedCodec};
use libipld::ipld::Ipld;
use std::collections::BTreeMap;
use std::io::{Read, Write};

#[derive(Clone, Copy, Debug)]
pub struct TreeCodec;

impl Codec for TreeCodec {}

impl From<TreeCodec> for u64 {
    fn from(_: TreeCodec) -> Self {
        0x01
    }
}

impl TryFrom<u64> for TreeCodec {
    type Error = UnsupportedCodec;

    fn try_from(_: u64) -> core::result::Result<Self, Self::Error> {
        Ok(Self)
    }
}

pub(crate) struct IoReader<R: Read>(pub R);

impl<R: Read> parity_scale_codec::Input for IoReader<R> {
    fn remaining_len(&mut self) -> core::result::Result<Option<usize>, parity_scale_codec::Error> {
        Ok(None)
    }

    fn read(&mut self, into: &mut [u8]) -> core::result::Result<(), parity_scale_codec::Error> {
        self.0.read_exact(into).map_err(Into::into)
    }
}

impl Decode<TreeCodec> for Ipld {
    fn decode<R: Read>(_: TreeCodec, r: &mut R) -> Result<Self> {
        let tree: BTreeMap<String, Vec<u8>> = parity_scale_codec::Decode::decode(&mut IoReader(r))?;
        let tree: BTreeMap<String, Ipld> = tree
            .into_iter()
            .map(|(k, v)| {
                let value = if let Ok(cid) =
                    <Cid as parity_scale_codec::Decode>::decode(&mut v.as_slice())
                {
                    Ipld::Link(cid)
                } else {
                    Ipld::Bytes(v)
                };
                (k, value)
            })
            .collect();
        Ok(Ipld::Map(tree))
    }
}

pub const DAG_CBOR: u64 = libipld::cid::DAG_CBOR; //0x00;
pub const SCALE_TREE: u64 = 0x01;

#[derive(Clone, Copy, Debug)]
pub enum Multicodec {
    DagCbor,
    Tree,
}

impl TryFrom<u64> for Multicodec {
    type Error = UnsupportedCodec;

    fn try_from(ccode: u64) -> core::result::Result<Self, Self::Error> {
        Ok(match ccode {
            DAG_CBOR => Self::DagCbor,
            SCALE_TREE => Self::Tree,
            _ => return Err(UnsupportedCodec(ccode)),
        })
    }
}

impl From<Multicodec> for u64 {
    fn from(mc: Multicodec) -> Self {
        match mc {
            Multicodec::DagCbor => DAG_CBOR,
            Multicodec::Tree => SCALE_TREE,
        }
    }
}

impl From<DagCborCodec> for Multicodec {
    fn from(_: DagCborCodec) -> Self {
        Self::DagCbor
    }
}

impl From<Multicodec> for DagCborCodec {
    fn from(_: Multicodec) -> Self {
        Self
    }
}

impl From<TreeCodec> for Multicodec {
    fn from(_: TreeCodec) -> Self {
        Self::Tree
    }
}

impl From<Multicodec> for TreeCodec {
    fn from(_: Multicodec) -> Self {
        Self
    }
}

impl Codec for Multicodec {}

impl Encode<Multicodec> for Ipld {
    fn encode<W: Write>(&self, c: Multicodec, w: &mut W) -> Result<()> {
        match c {
            Multicodec::DagCbor => self.encode(DagCborCodec, w)?,
            Multicodec::Tree => return Err(UnsupportedCodec(Multicodec::Tree.into()).into()),
        };
        Ok(())
    }
}

impl Decode<Multicodec> for Ipld {
    fn decode<R: Read>(c: Multicodec, r: &mut R) -> Result<Self> {
        Ok(match c {
            Multicodec::DagCbor => Self::decode(DagCborCodec, r)?,
            Multicodec::Tree => Self::decode(TreeCodec, r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::{Multihash, TreeHasherBlake2b256, BLAKE2B_256_TREE};
    use crate::trie::*;
    use libipld::store::StoreParams;

    #[derive(Clone)]
    struct MyStoreParams;

    impl StoreParams for MyStoreParams {
        type Hashes = Multihash;
        type Codecs = Multicodec;
        const MAX_BLOCK_SIZE: usize = u16::MAX as _;
    }
    type IpldBlock = libipld::block::Block<MyStoreParams>;

    struct Block {
        ancestor: Option<Cid>,
        payload: u64,
    }

    impl TreeEncode<TreeHasherBlake2b256> for Block {
        fn encode_tree(
            &self,
            block: &mut BlockBuilder<TreeHasherBlake2b256>,
            _prefix: &str,
            _proof: bool,
        ) {
            block.insert("ancestor".into(), &self.ancestor, true);
            block.insert("payload".into(), &self.payload, false);
        }
    }

    impl TreeDecode<TreeHasherBlake2b256> for Block {
        fn decode_tree(block: &OffchainBlock<TreeHasherBlake2b256>, _prefix: &str) -> Result<Self> {
            Ok(Self {
                ancestor: block.get("ancestor")?,
                payload: block.get("payload")?,
            })
        }
    }

    #[test]
    fn test_refs() {
        let b0 = Block {
            ancestor: None,
            payload: 0,
        };
        let b0o = b0.seal().unwrap().offchain;
        let b0i = IpldBlock::encode(TreeCodec, BLAKE2B_256_TREE, &b0o).unwrap();
        let b0d = Ipld::decode(Multicodec::Tree, &mut b0i.data()).unwrap();
        //println!("{:?}", b0d);
        assert_eq!(b0d.references().len(), 0);

        let b1 = Block {
            ancestor: Some(*b0i.cid()),
            payload: 1,
        };
        let b1o = b1.seal().unwrap().offchain;
        let b1i = IpldBlock::encode(TreeCodec, BLAKE2B_256_TREE, &b1o).unwrap();
        let b1d = Ipld::decode(Multicodec::Tree, &mut b1i.data()).unwrap();
        //println!("{:?}", b1d);
        assert_eq!(b1d.references().len(), 1);

        let b2 = Block {
            ancestor: Some(*b1i.cid()),
            payload: 2,
        };
        let b2o = b2.seal().unwrap().offchain;
        let b2i = IpldBlock::encode(TreeCodec, BLAKE2B_256_TREE, &b2o).unwrap();
        let b2d = Ipld::decode(Multicodec::Tree, &mut b2i.data()).unwrap();
        //println!("{:?}", b2d);
        assert_eq!(b2d.references().len(), 1);
    }
}
