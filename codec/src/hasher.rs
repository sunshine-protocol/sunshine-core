use generic_array::typenum::marker_traits::Unsigned;
use generic_array::GenericArray;
use hash256_std_hasher::Hash256StdHasher;
use tiny_multihash::{self as multihash, Digest, Size};

#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct TreeHash<D>(D);

impl<D: AsRef<[u8]>> AsRef<[u8]> for TreeHash<D> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<D: AsMut<[u8]>> AsMut<[u8]> for TreeHash<D> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<S: Size, D: Digest<S>> From<GenericArray<u8, S>> for TreeHash<D> {
    fn from(array: GenericArray<u8, S>) -> Self {
        Self(D::from(array))
    }
}

impl<S: Size, D: Digest<S>> From<TreeHash<D>> for GenericArray<u8, S> {
    fn from(digest: TreeHash<D>) -> Self {
        digest.0.into()
    }
}

impl<S: Size, D: Digest<S>> Digest<S> for TreeHash<D> {}

#[derive(Debug, Default)]
pub struct TreeHasher<H: multihash::Hasher>(H);

impl<H: multihash::Hasher> hash_db::Hasher for TreeHasher<H>
where
    H::Digest: Copy,
{
    type Out = H::Digest;
    type StdHasher = Hash256StdHasher;
    const LENGTH: usize = <H::Size as Unsigned>::USIZE;

    fn hash(data: &[u8]) -> Self::Out {
        H::digest(data)
    }
}

#[cfg(feature = "std")]
impl<H: multihash::Hasher> multihash::Hasher for TreeHasher<H>
where
    H::Digest: Copy,
{
    type Size = H::Size;
    type Digest = TreeHash<H::Digest>;

    fn digest(mut input: &[u8]) -> Self::Digest
    where
        Self: Sized,
    {
        use parity_scale_codec::Decode;
        use sp_trie::{Layout, TrieConfiguration};
        use std::collections::BTreeMap;

        let tree: BTreeMap<Vec<u8>, Vec<u8>> = Decode::decode(&mut input).unwrap_or_default();
        TreeHash(Layout::<Self>::trie_root(&tree))
    }
}

pub const BLAKE2B_256: u64 = 0x00;
pub const BLAKE2B_256_TREE: u64 = 0x01;

pub type TreeHashBlake2b256 = TreeHash<multihash::Blake2bDigest<multihash::U32>>;
pub type TreeHasherBlake2b256 = TreeHasher<multihash::Blake2b256>;

#[cfg(feature = "std")]
use multihash::{derive::Multihash, Hasher, MultihashDigest};

#[derive(Clone, Debug, Eq, Multihash, PartialEq)]
#[cfg(feature = "std")]
pub enum Multihash {
    #[mh(code = BLAKE2B_256, hasher = multihash::Blake2b256)]
    Blake2b256(multihash::Blake2bDigest<multihash::U32>),
    #[mh(code = BLAKE2B_256_TREE, hasher = TreeHasherBlake2b256)]
    Blake2b256Tree(TreeHashBlake2b256),
}
