use anyhow::Result;
pub use hash_db::Hasher;
use parity_scale_codec::{Decode, Encode};
use sp_trie::{Layout, MemoryDB, TrieConfiguration, TrieDBMut, TrieHash, TrieMut};
use std::collections::BTreeMap;
use std::marker::PhantomData;
use thiserror::Error;

pub type VerifyError<H> = sp_trie::VerifyError<TrieHash<Layout<H>>, sp_trie::Error>;

/// An immutable OffchainBlock.
#[derive(Clone, Debug)]
pub struct OffchainBlock<H: Hasher> {
    /// Hasher.
    _marker: PhantomData<H>,
    /// Tree data of the block.
    tree: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Root hash.
    root: H::Out,
}

impl<H: Hasher> OffchainBlock<H>
where
    H::Out: 'static,
{
    pub fn encode(&self) -> (&H::Out, Vec<u8>) {
        (&self.root, self.tree.encode())
    }

    pub fn decode(expected: &H::Out, mut bytes: &[u8]) -> Result<Self> {
        let tree = Decode::decode(&mut bytes)?;
        let root = Layout::<H>::trie_root(&tree);
        if root != *expected {
            return Err(TrieError::RootMissmatch.into());
        }
        Ok(Self {
            _marker: PhantomData,
            tree,
            root,
        })
    }

    pub fn get<K: Encode + ?Sized, V: Decode>(&self, k: &K) -> Result<V> {
        let bytes = k
            .using_encoded(|key| self.tree.get(key))
            .ok_or(TrieError::MissingKey)?;
        Ok(V::decode(&mut &bytes[..])?)
    }

    pub fn tree(&self) -> &BTreeMap<Vec<u8>, Vec<u8>> {
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

/// An immutable sealed block suitable for insertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedBlock<H: Hasher> {
    /// Offchain block to publish on ipfs.
    pub offchain: OffchainBlock<H>,
    /// Proof that the key value pairs the chain needs to know
    /// about are contained in the OffchainBlock.
    pub proof: Vec<Vec<u8>>,
    /// List of key value pairs the chain needs to know about.
    pub proof_data: Vec<(Vec<u8>, Option<Vec<u8>>)>,
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
    tree: BTreeMap<Vec<u8>, (Option<Vec<u8>>, bool)>,
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

    pub fn insert<K: Encode + ?Sized, V: Encode + ?Sized>(&mut self, k: &K, v: &V, proof: bool) {
        self.tree.insert(k.encode(), (Some(v.encode()), proof));
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
                trie.insert(&k, &v)
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
    fn encode_tree(&self, block: &mut BlockBuilder<H>, prefix: &[u8], proof: bool);

    fn seal(&self) -> Result<SealedBlock<H>> {
        let mut block = BlockBuilder::new();
        self.encode_tree(&mut block, &[], false);
        block.seal()
    }
}

impl<T: Encode, H: Hasher> TreeEncode<H> for T
where
    H::Out: 'static,
{
    fn encode_tree(&self, block: &mut BlockBuilder<H>, prefix: &[u8], proof: bool) {
        block.insert(prefix, self, proof);
    }
}

pub trait TreeDecode<H: Hasher>: Sized {
    fn decode_tree(block: &OffchainBlock<H>, prefix: &[u8]) -> Result<Self>;

    fn decode(block: &OffchainBlock<H>) -> Result<Self> {
        Self::decode_tree(block, &[])
    }
}

impl<T: Decode, H: Hasher> TreeDecode<H> for T
where
    H::Out: 'static,
{
    fn decode_tree(block: &OffchainBlock<H>, prefix: &[u8]) -> Result<Self> {
        block.get(prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp_core::{sr25519, Blake2Hasher, H256};
    use sunshine_crypto::keychain::{KeyChain, KeyType, TypedPair, TypedPublic};
    use sunshine_crypto::secret_box::SecretBox;

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
        prev: Option<H256>, // TODO Cid
        description: String,
        set_user_key: SetUserKey,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct SetUserKey {
        public_key: TypedPublic<User>,
        private_key: SecretBox<UserDevices, TypedPair<User>>,
    }

    impl TreeEncode<Blake2Hasher> for SetUserKey {
        fn encode_tree(&self, block: &mut BlockBuilder<Blake2Hasher>, prefix: &[u8], proof: bool) {
            (prefix, b"public_key").using_encoded(|prefix| {
                self.public_key.encode_tree(block, prefix, proof);
            });
            (prefix, b"private_key").using_encoded(|prefix| {
                self.private_key.encode_tree(block, prefix, proof);
            });
        }
    }

    impl TreeEncode<Blake2Hasher> for Block {
        fn encode_tree(&self, block: &mut BlockBuilder<Blake2Hasher>, prefix: &[u8], proof: bool) {
            (prefix, b"number").using_encoded(|prefix| {
                self.number.encode_tree(block, prefix, true);
            });
            (prefix, b"prev").using_encoded(|prefix| {
                self.prev.encode_tree(block, prefix, true);
            });
            (prefix, b"description").using_encoded(|prefix| {
                self.description.encode_tree(block, prefix, proof);
            });
            (prefix, b"set_user_key").using_encoded(|prefix| {
                self.set_user_key.encode_tree(block, prefix, proof);
            });
        }
    }

    impl TreeDecode<Blake2Hasher> for SetUserKey {
        fn decode_tree(block: &OffchainBlock<Blake2Hasher>, prefix: &[u8]) -> Result<Self> {
            Ok(Self {
                public_key: (prefix, b"public_key")
                    .using_encoded(|prefix| TreeDecode::decode_tree(block, prefix))?,
                private_key: (prefix, b"private_key")
                    .using_encoded(|prefix| TreeDecode::decode_tree(block, prefix))?,
            })
        }
    }

    impl TreeDecode<Blake2Hasher> for Block {
        fn decode_tree(block: &OffchainBlock<Blake2Hasher>, prefix: &[u8]) -> Result<Self> {
            Ok(Self {
                number: (prefix, b"number")
                    .using_encoded(|prefix| TreeDecode::decode_tree(block, prefix))?,
                prev: (prefix, b"prev")
                    .using_encoded(|prefix| TreeDecode::decode_tree(block, prefix))?,
                description: (prefix, b"description")
                    .using_encoded(|prefix| TreeDecode::decode_tree(block, prefix))?,
                set_user_key: (prefix, b"set_user_key")
                    .using_encoded(|prefix| TreeDecode::decode_tree(block, prefix))?,
            })
        }
    }

    #[async_std::test]
    async fn test_block() {
        let device = TypedPair::<UserDevices>::generate().await;
        let user = TypedPair::<User>::generate().await;

        let mut key_chain = KeyChain::new();
        key_chain.insert(device);

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

        let (root, bytes) = sealed_block.offchain.encode();
        let offchain_block = OffchainBlock::decode(root, &bytes).unwrap();
        assert_eq!(sealed_block.offchain, offchain_block);

        let block2 = Block::decode(&offchain_block).unwrap();
        assert_eq!(block, block2);

        let user2 = block2.set_user_key.private_key.decrypt(&key_chain).unwrap();
        assert_eq!(user, user2);
    }

    #[test]
    fn test_trie() {
        let mut db = MemoryDB::default();
        let mut root = H256::default();
        let mut trie = TrieDBMut::<Layout<Blake2Hasher>>::new(&mut db, &mut root);
        trie.insert(b"prev", b"cid").unwrap();
        trie.insert(b"remove_device_key", b"0").unwrap();
        drop(trie);

        let proof = sp_trie::generate_trie_proof::<Layout<Blake2Hasher>, _, _, _>(
            &db,
            root.clone(),
            &[
                &b"prev"[..],
                &b"remove_device_key"[..],
                &b"add_device_key"[..],
            ],
        )
        .unwrap();

        sp_trie::verify_trie_proof::<Layout<Blake2Hasher>, _, _, _>(
            &root,
            &proof,
            &[
                (&b"prev"[..], Some(&b"cid"[..])),
                (&b"remove_device_key"[..], Some(&b"0"[..])),
                (&b"add_device_key"[..], None),
            ],
        )
        .unwrap();

        let res = sp_trie::verify_trie_proof::<Layout<Blake2Hasher>, _, _, _>(
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
