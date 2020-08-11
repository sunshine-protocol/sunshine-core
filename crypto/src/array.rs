use crate::cipher::CipherText;
use crate::error::{KeySizeMissmatch, NotEnoughEntropy};
use crate::rand::random;
use generic_array::{ArrayLength, GenericArray};
use parity_scale_codec::{Decode, Encode, Input};
use secrecy::{ExposeSecret, SecretString, SecretVec};
use std::fmt::Debug;
use strobe_rs::{SecParam, Strobe};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Size marker trait.
pub trait Size: ArrayLength<u8> + Debug + Default + Eq + Send + Sync + 'static {}

impl<T: ArrayLength<u8> + Debug + Default + Eq + Send + Sync + 'static> Size for T {}

/// A wrapper around a generic array providing cryptographic functions.
///
/// Safe to use for secrets. It is zeroized on drop and has a "safe" `Debug` implementation
/// and comparisons happen in constant time.
#[derive(Clone, Default, Hash)]
// partial eq only makes sure the comparison is constant time, it doesn't change
// the semantics.
#[allow(clippy::derive_hash_xor_eq)]
pub struct CryptoArray<S: Size>(GenericArray<u8, S>);

impl<S: Size> core::fmt::Debug for CryptoArray<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", std::any::type_name::<Self>())
    }
}

impl<S: Size> Drop for CryptoArray<S> {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

impl<S: Size> AsRef<[u8]> for CryptoArray<S> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<S: Size> AsMut<[u8]> for CryptoArray<S> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<S: Size> PartialEq for CryptoArray<S> {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref().ct_eq(other.as_ref()).into()
    }
}

impl<S: Size> Eq for CryptoArray<S> {}

impl<S: Size> Encode for CryptoArray<S> {
    fn size_hint(&self) -> usize {
        S::to_usize()
    }

    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        f(self.as_ref())
    }
}

impl<S: Size> Decode for CryptoArray<S> {
    fn decode<R: Input>(value: &mut R) -> Result<Self, parity_scale_codec::Error> {
        let mut me = Self::default();
        value.read(me.as_mut())?;
        Ok(me)
    }
}

impl<S: Size> CryptoArray<S> {
    pub fn new(data: GenericArray<u8, S>) -> Self {
        Self(data)
    }

    pub async fn random() -> Self {
        random().await
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, KeySizeMissmatch> {
        if bytes.len() != S::to_usize() {
            return Err(KeySizeMissmatch);
        }
        let mut me = Self::default();
        me.copy_from_slice(bytes);
        Ok(me)
    }

    pub fn from_mnemonic(mnemonic: &bip39::Mnemonic) -> Result<Self, NotEnoughEntropy> {
        let mut res = Self::default();
        let entropy = mnemonic.to_entropy();
        if entropy.len() < res.size() {
            return Err(NotEnoughEntropy);
        }
        res.copy_from_slice(&entropy[..res.size()]);
        Ok(res)
    }

    pub fn copy_from_slice(&mut self, slice: &[u8]) {
        self.as_mut().copy_from_slice(slice);
    }

    pub fn size(&self) -> usize {
        S::to_usize()
    }

    pub fn xor(&self, other: &Self) -> Self {
        let mut res = Self::default();
        let a = self.as_ref();
        let b = other.as_ref();
        for i in 0..res.size() {
            res.as_mut()[i] = a[i] ^ b[i]
        }
        res
    }

    pub fn kdf(input: &SecretString) -> Self {
        let mut s = Strobe::new(b"DiscoKDF", SecParam::B128);
        s.ad(input.expose_secret().as_bytes(), false);
        let mut res = Self::default();
        s.prf(res.as_mut(), false);
        res
    }

    pub fn hash(input: &[u8]) -> Self {
        let mut s = Strobe::new(b"DiscoHash", SecParam::B128);
        s.ad(input, false);
        let mut res = Self::default();
        s.prf(res.as_mut(), false);
        res
    }

    pub async fn encrypt<K: Size, N: Size, T: Size>(
        &self,
        key: &CryptoArray<K>,
    ) -> CipherText<S, K, N, T> {
        CipherText::encrypt(self, key).await
    }

    pub fn array(&self) -> &GenericArray<u8, S> {
        &self.0
    }

    pub fn to_vec(&self) -> SecretVec<u8> {
        SecretVec::new(self.0.as_ref().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use generic_array::typenum::U32;

    #[async_std::test]
    async fn test_encode_decode() {
        let key = CryptoArray::<U32>::random().await;
        let key2 = CryptoArray::<U32>::decode(&mut &key.encode()[..]).unwrap();
        assert_eq!(key, key2);
    }
}
