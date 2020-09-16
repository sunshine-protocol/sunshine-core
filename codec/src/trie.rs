use crate::codec::TreeCodec;
use anyhow::Result;
pub use hash_db::Hasher;
use parity_scale_codec::{Decode, Encode};
use sp_trie::{Layout, MemoryDB, TrieConfiguration, TrieDBMut, TrieHash, TrieMut};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::marker::PhantomData;
use thiserror::Error;

pub type VerifyError<H> = sp_trie::VerifyError<TrieHash<Layout<H>>, sp_trie::Error>;

/// An immutable OffchainBlock.
#[derive(Clone, Debug)]
pub struct OffchainBlock<H: Hasher> {
    /// Hasher.
    _marker: PhantomData<H>,
    /// Tree data of the block.
    tree: BTreeMap<String, Vec<u8>>,
    /// Root hash.
    root: H::Out,
}

impl<H: Hasher> OffchainBlock<H>
where
    H::Out: 'static,
{
    pub fn get<V: Decode>(&self, key: &str) -> Result<V> {
        let bytes = self.tree.get(key).ok_or(TrieError::MissingKey)?;
        Ok(V::decode(&mut &bytes[..])?)
    }

    pub fn tree(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.tree
    }

    pub fn root(&self) -> &H::Out {
        &self.root
    }
}

impl<H: Hasher> PartialEq for OffchainBlock<H> {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
    }
}

impl<H: Hasher> Eq for OffchainBlock<H> {}

impl<H: Hasher> libipld::codec::Encode<TreeCodec> for OffchainBlock<H> {
    fn encode<W: Write>(&self, _: TreeCodec, w: &mut W) -> Result<()> {
        self.tree.encode_to(w);
        Ok(())
    }
}

impl<H: Hasher> libipld::codec::Decode<TreeCodec> for OffchainBlock<H> {
    fn decode<R: Read>(_: TreeCodec, r: &mut R) -> Result<Self> {
        let tree = Decode::decode(&mut crate::codec::IoReader(r))?;
        let root = Layout::<H>::trie_root(&tree);
        Ok(Self {
            _marker: PhantomData,
            tree,
            root,
        })
    }
}

/// An immutable sealed block suitable for insertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedBlock<H: Hasher> {
    /// Offchain block to publish on ipfs.
    pub offchain: OffchainBlock<H>,
    /// Proof that the key value pairs the chain needs to know
    /// about are contained in the OffchainBlock.
    pub proof: Vec<Vec<u8>>,
    /// List of key value pairs the chain needs to know about.
    pub proof_data: Vec<(String, Option<Vec<u8>>)>,
}

impl<H: Hasher> SealedBlock<H> {
    pub fn verify_proof(&self) -> Result<()> {
        Ok(sp_trie::verify_trie_proof::<Layout<H>, _, _, _>(
            &self.offchain.root,
            &self.proof,
            &self.proof_data,
        )
        .map_err(|_| TrieError::InvalidProof)?)
    }
}

pub struct BlockBuilder<H: Hasher> {
    _marker: PhantomData<H>,
    tree: BTreeMap<String, (Option<Vec<u8>>, bool)>,
}

impl<H: Hasher> Default for BlockBuilder<H> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
            tree: Default::default(),
        }
    }
}

impl<H: Hasher> BlockBuilder<H> {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn insert<V: Encode + ?Sized>(&mut self, k: String, v: &V, proof: bool) {
        self.tree.insert(k, (Some(v.encode()), proof));
    }

    pub fn seal(self) -> Result<SealedBlock<H>> {
        let mut db = MemoryDB::default();
        let mut root = TrieHash::<Layout<H>>::default();
        let mut trie = TrieDBMut::<Layout<H>>::new(&mut db, &mut root);
        let mut tree = BTreeMap::new();
        let mut proof_data = Vec::with_capacity(self.tree.len());
        for (k, (v, p)) in self.tree.into_iter() {
            if p {
                proof_data.push((k.clone(), v.clone()));
            }
            if let Some(v) = v {
                trie.insert(k.as_ref(), &v)
                    .map_err(|_| TrieError::InsertionFailure)?;
                tree.insert(k, v);
            }
        }
        drop(trie);

        let proof = sp_trie::generate_trie_proof::<Layout<H>, _, _, _>(
            &db,
            root,
            proof_data.iter().map(|(k, _)| k),
        )
        .expect("provided valid data; qed");

        Ok(SealedBlock {
            offchain: OffchainBlock {
                _marker: PhantomData,
                root,
                tree,
            },
            proof,
            proof_data,
        })
    }
}

#[derive(Debug, Error)]
pub enum TrieError {
    #[error("failed to insert key value pair")]
    InsertionFailure,
    #[error("missing key")]
    MissingKey,
    #[error("root missmatch")]
    RootMissmatch,
    #[error("invalid proof")]
    InvalidProof,
}

pub trait TreeEncode<H: Hasher> {
    fn encode_tree(&self, block: &mut BlockBuilder<H>, prefix: &str, proof: bool);

    fn seal(&self) -> Result<SealedBlock<H>> {
        let mut block = BlockBuilder::new();
        self.encode_tree(&mut block, "", false);
        block.seal()
    }
}

impl<T: Encode, H: Hasher> TreeEncode<H> for T
where
    H::Out: 'static,
{
    fn encode_tree(&self, block: &mut BlockBuilder<H>, prefix: &str, proof: bool) {
        block.insert(prefix.to_string(), self, proof);
    }
}

pub trait TreeDecode<H: Hasher>: Sized {
    fn decode_tree(block: &OffchainBlock<H>, prefix: &str) -> Result<Self>;

    fn decode(block: &OffchainBlock<H>) -> Result<Self> {
        Self::decode_tree(block, "")
    }
}

impl<T: Decode, H: Hasher> TreeDecode<H> for T
where
    H::Out: 'static,
{
    fn decode_tree(block: &OffchainBlock<H>, prefix: &str) -> Result<Self> {
        block.get(prefix)
    }
}

pub struct PrefixIter<'a> {
    prefix: &'a str,
    fields: std::slice::Iter<'a, &'a str>,
}

impl<'a> PrefixIter<'a> {
    pub fn new(prefix: &'a str, fields: &'a [&'a str]) -> Self {
        Self {
            prefix,
            fields: fields.iter(),
        }
    }
}

impl<'a> Iterator for PrefixIter<'a> {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(field) = self.fields.next() {
            let mut prefix = String::with_capacity(self.prefix.len() + field.len());
            prefix.push_str(self.prefix);
            prefix.push_str(field);
            Some(prefix)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Multicodec;
    use crate::hasher::{Multihash, TreeHasherBlake2b256 as TreeHasher, BLAKE2B_256_TREE};
    use libipld::cid::Cid;
    use libipld::mem::MemStore;
    use libipld::store::{Store, StoreParams};
    use sp_core::sr25519;
    use sunshine_crypto::keychain::{KeyChain, KeyType, TypedPair, TypedPublic};
    use sunshine_crypto::secret_box::SecretBox;

    #[derive(Clone)]
    struct MyStoreParams;
    impl StoreParams for MyStoreParams {
        type Hashes = Multihash;
        type Codecs = Multicodec;
        const MAX_BLOCK_SIZE: usize = u16::MAX as _;
    }

    #[derive(Debug, Eq, PartialEq)]
    struct User;
    impl KeyType for User {
        const KEY_TYPE: u8 = 0;
        type Pair = sr25519::Pair;
    }

    #[derive(Debug, Eq, PartialEq)]
    struct UserDevices;
    impl KeyType for UserDevices {
        const KEY_TYPE: u8 = 1;
        type Pair = sr25519::Pair;
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Block {
        //#[offchain(proof)]
        number: u32,
        //#[offchain(proof)]
        prev: Option<Cid>,
        description: String,
        set_user_key: SetUserKey,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct SetUserKey {
        public_key: TypedPublic<User>,
        private_key: SecretBox<UserDevices, TypedPair<User>>,
    }

    impl TreeEncode<TreeHasher> for SetUserKey {
        fn encode_tree(&self, block: &mut BlockBuilder<TreeHasher>, prefix: &str, proof: bool) {
            let mut prefixes = PrefixIter::new(prefix, &[".public_key", ".private_key"]);
            self.public_key
                .encode_tree(block, &prefixes.next().unwrap(), proof);
            self.private_key
                .encode_tree(block, &prefixes.next().unwrap(), proof);
        }
    }

    impl TreeEncode<TreeHasher> for Block {
        fn encode_tree(&self, block: &mut BlockBuilder<TreeHasher>, prefix: &str, proof: bool) {
            let mut prefixes = PrefixIter::new(
                prefix,
                &[".number", ".prev", ".description", ".set_user_key"],
            );
            self.number
                .encode_tree(block, &prefixes.next().unwrap(), proof);
            self.prev
                .encode_tree(block, &prefixes.next().unwrap(), proof);
            self.description
                .encode_tree(block, &prefixes.next().unwrap(), proof);
            self.set_user_key
                .encode_tree(block, &prefixes.next().unwrap(), proof);
        }
    }

    impl TreeDecode<TreeHasher> for SetUserKey {
        fn decode_tree(block: &OffchainBlock<TreeHasher>, prefix: &str) -> Result<Self> {
            let mut prefixes = PrefixIter::new(prefix, &[".public_key", ".private_key"]);
            let public_key = TreeDecode::decode_tree(block, &prefixes.next().unwrap())?;
            let private_key = TreeDecode::decode_tree(block, &prefixes.next().unwrap())?;
            Ok(Self {
                public_key,
                private_key,
            })
        }
    }

    impl TreeDecode<TreeHasher> for Block {
        fn decode_tree(block: &OffchainBlock<TreeHasher>, prefix: &str) -> Result<Self> {
            let mut prefixes = PrefixIter::new(
                prefix,
                &[".number", ".prev", ".description", ".set_user_key"],
            );
            let number = TreeDecode::decode_tree(block, &prefixes.next().unwrap())?;
            let prev = TreeDecode::decode_tree(block, &prefixes.next().unwrap())?;
            let description = TreeDecode::decode_tree(block, &prefixes.next().unwrap())?;
            let set_user_key = TreeDecode::decode_tree(block, &prefixes.next().unwrap())?;
            Ok(Self {
                number,
                prev,
                description,
                set_user_key,
            })
        }
    }

    #[async_std::test]
    async fn test_block() {
        let store = MemStore::<MyStoreParams>::default();

        let device = TypedPair::<UserDevices>::generate().await;
        let user = TypedPair::<User>::generate().await;

        let mut key_chain = KeyChain::new();
        key_chain.insert(device);

        // create a sealed block.
        let block = Block {
            number: 0,
            prev: None,
            description: "the genesis block".into(),
            set_user_key: SetUserKey {
                public_key: user.public(),
                private_key: SecretBox::encrypt(&key_chain, &user).await.unwrap(),
            },
        };
        let sealed_block = block.seal().unwrap();
        sealed_block.verify_proof().unwrap();

        // store a sealead block in ipfs.
        let ipld_block =
            libipld::block::Block::encode(TreeCodec, BLAKE2B_256_TREE, &sealed_block.offchain)
                .unwrap();
        store.insert(ipld_block.clone()).await.unwrap();
        if let Some(ancestor) = block.prev.as_ref() {
            store.unpin(ancestor).await.unwrap();
        }

        // retrive a block from ipfs.
        let ipld_block2 = store.get(ipld_block.cid()).await.unwrap();
        assert_eq!(ipld_block.data(), ipld_block2.data());

        let offchain_block: OffchainBlock<TreeHasher> = ipld_block2.decode().unwrap();
        assert_eq!(sealed_block.offchain, offchain_block);

        let block2 = Block::decode(&offchain_block).unwrap();
        assert_eq!(block, block2);

        let user2 = block2.set_user_key.private_key.decrypt(&key_chain).unwrap();
        assert_eq!(user, user2);
    }

    #[test]
    fn test_trie() {
        let mut db = MemoryDB::default();
        let mut root = Default::default();
        let mut trie = TrieDBMut::<Layout<TreeHasher>>::new(&mut db, &mut root);
        trie.insert(b"prev", b"cid").unwrap();
        trie.insert(b"remove_device_key", b"0").unwrap();
        drop(trie);

        let proof = sp_trie::generate_trie_proof::<Layout<TreeHasher>, _, _, _>(
            &db,
            root,
            &[
                &b"prev"[..],
                &b"remove_device_key"[..],
                &b"add_device_key"[..],
            ],
        )
        .unwrap();

        sp_trie::verify_trie_proof::<Layout<TreeHasher>, _, _, _>(
            &root,
            &proof,
            &[
                (&b"prev"[..], Some(&b"cid"[..])),
                (&b"remove_device_key"[..], Some(&b"0"[..])),
                (&b"add_device_key"[..], None),
            ],
        )
        .unwrap();

        let res = sp_trie::verify_trie_proof::<Layout<TreeHasher>, _, _, _>(
            &root,
            &proof,
            &[
                (&b"prev"[..], Some(&b"wrong"[..])),
                (&b"remove_device_key"[..], Some(&b"0"[..])),
                (&b"add_device_key"[..], None),
            ],
        );
        assert!(res.is_err());
    }
}
