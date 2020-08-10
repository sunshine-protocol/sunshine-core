use parity_scale_codec::{Decode, Encode};
use sunshine_crypto::{
    array::CryptoArray,
    cipher::CipherText,
    secrecy::SecretString,
    typenum::{U0, U32},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoiseHash(CryptoArray<U32>);

impl NoiseHash {
    pub fn new(array: CryptoArray<U32>) -> Self {
        Self(array)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RandomKey(CryptoArray<U32>);

impl RandomKey {
    pub async fn generate() -> Self {
        Self(CryptoArray::random().await)
    }

    pub fn public(&self, pass: &Password) -> PublicDeviceKey {
        PublicDeviceKey(self.0.xor(&pass.0))
    }

    pub fn password(&self, pdk: &PublicDeviceKey) -> Password {
        Password(self.0.xor(&pdk.0))
    }

    pub async fn encrypt(&self, noise: &NoiseHash) -> EncryptedRandomKey {
        EncryptedRandomKey(self.0.encrypt(&noise.0).await)
    }
}

impl AsRef<CryptoArray<U32>> for RandomKey {
    fn as_ref(&self) -> &CryptoArray<U32> {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Decode, Encode)]
pub struct EncryptedRandomKey(CipherText<U32, U32, U0, U0>);

impl EncryptedRandomKey {
    pub fn decrypt(&self, key: &NoiseHash) -> RandomKey {
        RandomKey(self.0.decrypt(&key.0).unwrap())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Decode, Encode)]
pub struct Password(CryptoArray<U32>);

impl Password {
    pub fn new(plain: &SecretString) -> Self {
        Self(CryptoArray::kdf(plain))
    }

    pub async fn generate() -> Self {
        Self(CryptoArray::random().await)
    }

    pub(crate) fn mask(&self, other: &Password) -> Mask {
        Mask(self.0.xor(&other.0), 1)
    }

    pub(crate) fn apply_mask(&self, mask: &Mask) -> Password {
        Password(self.0.xor(&mask.0))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Decode, Encode)]
pub struct PublicDeviceKey(CryptoArray<U32>);

impl PublicDeviceKey {
    pub(crate) fn private(&self, pass: &Password) -> RandomKey {
        RandomKey(self.0.xor(&pass.0))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Default, Decode, Encode)]
pub struct Mask(CryptoArray<U32>, u16);

impl Mask {
    pub fn new(mask: [u8; 32]) -> Self {
        Self(CryptoArray::from_slice(&mask).unwrap(), 1)
    }

    pub fn join(&self, mask: &Mask) -> Self {
        Self(self.0.xor(&mask.0), self.1 + mask.1)
    }

    pub(crate) fn len(&self) -> u16 {
        self.1
    }
}
