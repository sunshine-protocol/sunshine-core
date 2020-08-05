use crate::cipher::CipherText;
use crate::error::NotEnoughEntropyError;
use crate::rand::random;
use generic_array::{ArrayLength, GenericArray};
use secrecy::{ExposeSecret, SecretString};
use std::fmt::Debug;
use strobe_rs::{SecParam, Strobe};
use zeroize::Zeroize;

/// Size marker trait.
pub trait Size: ArrayLength<u8> + Debug + Default + Eq + Send + Sync + 'static {}

impl<T: ArrayLength<u8> + Debug + Default + Eq + Send + Sync + 'static> Size for T {}

/// A wrapper around a generic array providing cryptographic functions.
///
/// Safe to use for secrets. It is zeroized on drop and has a "safe" `Debug` implementation.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct CryptoArray<S: Size>(GenericArray<u8, S>);

impl<S: Size> core::fmt::Debug for CryptoArray<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "[u8; {}]", S::to_u8())
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

impl<S: Size> CryptoArray<S> {
    pub fn new(data: GenericArray<u8, S>) -> Self {
        Self(data)
    }

    pub async fn random() -> Self {
        random().await
    }

    pub fn from_mnemonic(mnemonic: &bip39::Mnemonic) -> Result<Self, NotEnoughEntropyError> {
        let mut res = Self::default();
        let entropy = mnemonic.to_entropy();
        if entropy.len() < res.len() {
            return Err(NotEnoughEntropyError);
        }
        res.copy_from_slice(&entropy[..res.len()]);
        Ok(res)
    }

    pub fn copy_from_slice(&mut self, slice: &[u8]) {
        self.as_mut().copy_from_slice(slice);
    }

    pub fn len(&self) -> usize {
        S::to_usize()
    }

    pub fn xor(&self, other: &Self) -> Self {
        let mut res = Self::default();
        let a = self.as_ref();
        let b = other.as_ref();
        for i in 0..res.len() {
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

    pub fn encrypt(&self, key: &Self) -> Self {
        let mut s = Strobe::new(b"DiscoAEAD", SecParam::B128);
        let mut res = self.clone();
        s.ad(key.as_ref(), false);
        s.send_enc(res.as_mut(), false);
        res
    }

    pub fn decrypt(&self, key: &Self) -> Self {
        let mut s = Strobe::new(b"DiscoAEAD", SecParam::B128);
        let mut res = self.clone();
        s.ad(key.as_ref(), false);
        s.recv_enc(res.as_mut(), false);
        res
    }

    pub async fn encrypt_tagged<N: Size, T: Size>(&self, key: &Self) -> CipherText<S, N, T> {
        CipherText::encrypt(self, key).await
    }
}
