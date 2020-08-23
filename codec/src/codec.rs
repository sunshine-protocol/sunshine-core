

#[derive(Clone, Copy, Debug)]
pub struct OffchainCodec;

impl Codec for OffchainCodec {
    fn encode_ipld(&self, ipld: &Ipld) -> Result<Box<[u8]>> {
        Err(UnsupportedCodec.into())
    }

    fn decode_ipld(&self, mut bytes: &[u8]) -> Result<Ipld> {
        Ipld::decode(*self, &mut bytes)
    }
}

impl From<OffchainCodec> for u64 {
    fn from(_: OffchainCodec) -> Self {
        0
    }
}

impl TryFrom<u64> for OffchainCodec {
    type Error = UnsupportedCodec;

    fn try_from(_: u64) -> core::result::Result<Self, Self::Error> {
        Ok(Self)
    }
}

impl Decode<OffchainCodec> for Ipld {
    fn decode<R: Read>(_: OffchainCodec, r: &mut R) -> Result<Self> {
        todo!()
    }
}
