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

impl Codec for TreeCodec {
    fn decode_ipld(&self, mut bytes: &[u8]) -> Result<Ipld> {
        Ipld::decode(*self, &mut bytes)
    }
}

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

impl Encode<TreeCodec> for Ipld {
    fn encode<W: Write>(&self, _: TreeCodec, _w: &mut W) -> Result<()> {
        todo!()
    }
}

impl Decode<TreeCodec> for Ipld {
    fn decode<R: Read>(_: TreeCodec, r: &mut R) -> Result<Self> {
        let tree: BTreeMap<String, Vec<u8>> = parity_scale_codec::Decode::decode(&mut IoReader(r))?;
        let tree: BTreeMap<String, Ipld> = tree
            .into_iter()
            .map(|(k, v)| {
                let value = if let Ok(cid) = Cid::try_from(v.as_slice()) {
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

impl Codec for Multicodec {
    fn decode_ipld(&self, mut bytes: &[u8]) -> Result<Ipld> {
        Ipld::decode(*self, &mut bytes)
    }
}

impl Encode<Multicodec> for Ipld {
    fn encode<W: Write>(&self, c: Multicodec, w: &mut W) -> Result<()> {
        match c {
            Multicodec::DagCbor => self.encode(DagCborCodec, w)?,
            Multicodec::Tree => self.encode(TreeCodec, w)?,
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
