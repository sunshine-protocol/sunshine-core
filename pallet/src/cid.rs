#[cfg(feature = "std")]
use core::convert::TryFrom;
#[cfg(feature = "std")]
use libipld::cid::{Cid, Error};
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "std")]
use serde::{
    de::{self, Visitor},
    ser::SerializeTuple,
    Deserialize, Deserializer, Serialize, Serializer,
};
#[cfg(feature = "std")]
use std::fmt;

pub const CID_LENGTH: usize = 38;

#[derive(Clone, Decode, Encode)]
pub struct CidBytes([u8; CID_LENGTH]);

#[cfg(feature = "std")]
impl CidBytes {
    pub fn to_cid(&self) -> Result<Cid, Error> {
        Cid::try_from(&self.0[..])
    }
}

#[cfg(feature = "std")]
impl Serialize for CidBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_tuple(self.0.len())?;
        for elem in &self.0[..] {
            seq.serialize_element(elem)?;
        }
        seq.end()
    }
}

#[cfg(feature = "std")]
impl<'de> Deserialize<'de> for CidBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        pub struct CidVisitor;

        impl<'de> Visitor<'de> for CidVisitor {
            type Value = CidBytes;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an array of length 38")
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut arr = [0; CID_LENGTH];
                for i in 0..CID_LENGTH {
                    arr[i] = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                Ok(CidBytes(arr))
            }
        }
        deserializer.deserialize_tuple(CID_LENGTH, CidVisitor)
    }
}

impl core::fmt::Debug for CidBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:?}", self.0.to_vec())
    }
}

impl Default for CidBytes {
    fn default() -> Self {
        Self([0; CID_LENGTH])
    }
}

impl PartialEq for CidBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

impl Eq for CidBytes {}

#[cfg(feature = "std")]
impl<'a> From<&'a Cid> for CidBytes {
    fn from(cid: &'a Cid) -> Self {
        let bytes = cid.to_bytes();
        let mut buf = [0; CID_LENGTH];
        buf.copy_from_slice(&bytes[..]);
        Self(buf)
    }
}

#[cfg(feature = "std")]
impl From<Cid> for CidBytes {
    fn from(cid: Cid) -> Self {
        Self::from(&cid)
    }
}

#[cfg(feature = "std")]
impl TryFrom<CidBytes> for Cid {
    type Error = Error;

    fn try_from(cid: CidBytes) -> Result<Self, Self::Error> {
        cid.to_cid()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libipld::cid::Codec;
    use libipld::multihash::Blake2b256;

    #[test]
    fn test_cid_bytes() {
        let content = b"hello world";
        let hash = Blake2b256::digest(&content[..]);
        let cid = Cid::new_v1(Codec::Raw, hash);
        let bytes = CidBytes::from(&cid);
        let cid2 = bytes.to_cid().unwrap();
        assert_eq!(cid, cid2);
    }

    #[test]
    fn test_serde() {
        let cid = CidBytes::default();
        let bytes = serde_json::to_string(&cid).unwrap();
        let cid2 = serde_json::from_str(&bytes).unwrap();
        assert_eq!(cid, cid2);
    }
}
