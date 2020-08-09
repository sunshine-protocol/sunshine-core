use crate::array::CryptoArray;
use crate::cipher::CipherText;
use crate::dh::DiffieHellman;
use crate::error::{DecryptError, InvalidSuri, NotEnoughEntropy, SecretStringError};
use generic_array::typenum::{U16, U24, U32};
use parity_scale_codec::{Decode, Encode, Input};
use sp_core::{Pair, Public};
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::ops::Deref;
use zeroize::Zeroize;

pub trait KeyType: Send + Sync {
    const KEY_TYPE: u8;
    type Pair: DiffieHellman<SharedSecret = [u8; 32]> + Pair<Seed = [u8; 32]>;
}

pub struct TypedPair<K: KeyType> {
    _marker: PhantomData<K>,
    seed: CryptoArray<U32>,
    pair: K::Pair,
}

impl<K: KeyType> std::fmt::Debug for TypedPair<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", std::any::type_name::<Self>())
    }
}

impl<K: KeyType> Clone for TypedPair<K> {
    fn clone(&self) -> Self {
        Self {
            _marker: self._marker,
            seed: self.seed.clone(),
            pair: self.pair.clone(),
        }
    }
}

impl<K: KeyType> PartialEq for TypedPair<K> {
    fn eq(&self, other: &Self) -> bool {
        self.seed == other.seed
    }
}

impl<K: KeyType> Eq for TypedPair<K> {}

impl<K: KeyType> Deref for TypedPair<K> {
    type Target = K::Pair;

    fn deref(&self) -> &Self::Target {
        &self.pair
    }
}

impl<K: KeyType> Encode for TypedPair<K> {
    fn size_hint(&self) -> usize {
        self.seed.size_hint()
    }

    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.seed.using_encoded(f)
    }
}

impl<K: KeyType> Decode for TypedPair<K> {
    fn decode<R: Input>(value: &mut R) -> Result<Self, parity_scale_codec::Error> {
        let seed = CryptoArray::decode(value)?;
        Ok(Self::from_seed(seed))
    }
}

impl<K: KeyType> TypedPair<K> {
    pub fn from_seed(seed: CryptoArray<U32>) -> Self {
        let pair = K::Pair::from_seed_slice(seed.as_ref()).expect("seed is the correct size; qed");
        Self {
            _marker: PhantomData,
            seed,
            pair,
        }
    }

    pub fn from_suri(suri: &str) -> Result<Self, InvalidSuri> {
        let (_, seed) = K::Pair::from_string_with_seed(suri, None).map_err(InvalidSuri)?;
        let mut seed = seed.ok_or(InvalidSuri(SecretStringError::InvalidPath))?;
        let array = CryptoArray::from_slice(&seed).expect("seed has valid length; qed");
        let me = Self::from_seed(array);
        seed.zeroize();
        Ok(me)
    }

    pub fn from_mnemonic(mnemonic: &bip39::Mnemonic) -> Result<Self, NotEnoughEntropy> {
        Ok(Self::from_seed(CryptoArray::from_mnemonic(mnemonic)?))
    }

    pub async fn generate() -> Self {
        let seed = CryptoArray::random().await;
        Self::from_seed(seed)
    }

    pub async fn encrypt(&self, key: &CryptoArray<U32>) -> CipherText<U32, U32, U24, U16> {
        self.seed.encrypt(key).await
    }

    pub fn decrypt(
        cipher: &CipherText<U32, U32, U24, U16>,
        key: &CryptoArray<U32>,
    ) -> Result<Self, DecryptError> {
        Ok(Self::from_seed(cipher.decrypt(key)?))
    }

    pub fn seed(&self) -> &CryptoArray<U32> {
        &self.seed
    }

    pub fn public(&self) -> TypedPublic<K> {
        TypedPublic::new(self.pair.public())
    }
}

pub struct TypedPublic<K: KeyType> {
    _marker: PhantomData<K>,
    public: <K::Pair as Pair>::Public,
}

impl<K: KeyType> std::fmt::Debug for TypedPublic<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", std::any::type_name::<Self>())
    }
}

impl<K: KeyType> Clone for TypedPublic<K> {
    fn clone(&self) -> Self {
        Self {
            _marker: self._marker,
            public: self.public.clone(),
        }
    }
}

impl<K: KeyType> PartialEq for TypedPublic<K> {
    fn eq(&self, other: &Self) -> bool {
        self.public == other.public
    }
}

impl<K: KeyType> Eq for TypedPublic<K> {}

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

impl<K: KeyType> Encode for TypedPublic<K> {
    fn size_hint(&self) -> usize {
        self.public.as_ref().len()
    }

    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.public.as_ref().using_encoded(f)
    }
}

impl<K: KeyType> Decode for TypedPublic<K> {
    fn decode<R: Input>(value: &mut R) -> Result<Self, parity_scale_codec::Error> {
        let bytes: Vec<u8> = Decode::decode(value)?;
        Ok(Self::new(<K::Pair as Pair>::Public::from_slice(&bytes)))
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

    pub fn insert<T: KeyType>(&mut self, pair: TypedPair<T>) {
        self.keys.insert(T::KEY_TYPE, pair.seed().clone());
        self.insert_public::<T>(pair.public());
    }

    pub fn get<T: KeyType>(&self) -> Option<TypedPair<T>> {
        self.keys
            .get(&T::KEY_TYPE)
            .map(|seed| TypedPair::from_seed(seed.clone()))
    }

    pub fn insert_public<T: KeyType>(&mut self, public: TypedPublic<T>) {
        let group = self.public.entry(T::KEY_TYPE).or_default();
        group.insert(public.encode());
    }

    pub fn get_public<T: KeyType>(&self) -> Vec<TypedPublic<T>> {
        if let Some(set) = self.public.get(&T::KEY_TYPE) {
            set.iter()
                .map(|bytes| Decode::decode(&mut &bytes[..]).expect("valid key size; qed"))
                .collect()
        } else {
            Default::default()
        }
    }
}
