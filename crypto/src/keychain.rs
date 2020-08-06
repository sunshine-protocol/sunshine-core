use crate::array::CryptoArray;
use crate::dh::DiffieHellman;
use generic_array::typenum::U32;
use sp_core::{Pair, Public};
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::ops::Deref;

pub trait KeyType: Send + Sync {
    const KEY_TYPE: u8;
    type Pair: DiffieHellman<SharedSecret = [u8; 32]> + Pair<Seed = [u8; 32]>;
}

pub struct TypedPair<K: KeyType> {
    _marker: PhantomData<K>,
    pair: K::Pair,
}

impl<K: KeyType> Deref for TypedPair<K> {
    type Target = K::Pair;

    fn deref(&self) -> &Self::Target {
        &self.pair
    }
}

impl<K: KeyType> TypedPair<K> {
    pub fn new(pair: K::Pair) -> Self {
        Self {
            _marker: PhantomData,
            pair,
        }
    }

    pub fn generate() -> Self {
        Self::new(K::Pair::generate().0)
    }

    pub fn public(&self) -> TypedPublic<K> {
        TypedPublic::new(self.pair.public())
    }
}

pub struct TypedPublic<K: KeyType> {
    _marker: PhantomData<K>,
    public: <K::Pair as Pair>::Public,
}

impl<K: KeyType> Deref for TypedPublic<K> {
    type Target = <K::Pair as Pair>::Public;

    fn deref(&self) -> &Self::Target {
        &self.public
    }
}

impl<K: KeyType> TypedPublic<K> {
    pub fn new(public: <K::Pair as Pair>::Public) -> Self {
        Self {
            _marker: PhantomData,
            public,
        }
    }
}

#[derive(Default)]
pub struct KeyChain {
    keys: HashMap<u8, CryptoArray<U32>>,
    public: HashMap<u8, HashSet<Vec<u8>>>,
}

impl KeyChain {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn insert<T: KeyType>(&mut self, seed: CryptoArray<U32>) {
        let public = seed.to_pair::<T::Pair>().public();
        self.keys.insert(T::KEY_TYPE, seed);
        self.insert_public::<T>(public);
    }

    pub fn get<T: KeyType>(&self) -> Option<TypedPair<T>> {
        self.keys.get(&T::KEY_TYPE).map(|bytes| {
            let pair = T::Pair::from_seed_slice(bytes.as_ref()).expect("valid key size; qed");
            TypedPair::new(pair)
        })
    }

    pub fn insert_public<T: KeyType>(&mut self, public: <T::Pair as Pair>::Public) {
        let group = self.public.entry(T::KEY_TYPE).or_default();
        group.insert(public.as_ref().to_vec());
    }

    pub fn get_public<T: KeyType>(&self) -> Vec<TypedPublic<T>> {
        if let Some(set) = self.public.get(&T::KEY_TYPE) {
            set.iter()
                .map(|bytes| {
                    let public = <T::Pair as Pair>::Public::from_slice(bytes.as_ref());
                    TypedPublic::new(public)
                })
                .collect()
        } else {
            Default::default()
        }
    }
}
