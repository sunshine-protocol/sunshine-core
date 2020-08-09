use crate::array::{CryptoArray, Size};
use crate::error::DecryptError;
use parity_scale_codec::{Decode, Encode};
use std::marker::PhantomData;
use strobe_rs::{SecParam, Strobe};

/// Cipher text encrypted with a nonce and a tag.
#[derive(Clone, Debug, Eq, PartialEq, Decode, Encode)]
pub struct CipherText<D: Size, K: Size, N: Size, T: Size> {
    _marker: PhantomData<K>,
    data: CryptoArray<D>,
    nonce: CryptoArray<N>,
    tag: CryptoArray<T>,
}

impl<D: Size, K: Size, N: Size, T: Size> CipherText<D, K, N, T> {
    pub async fn encrypt(data: &CryptoArray<D>, key: &CryptoArray<K>) -> Self {
        let mut data = data.clone();
        let nonce = CryptoArray::random().await;
        let mut tag = CryptoArray::default();

        let mut s = Strobe::new(b"DiscoAEAD", SecParam::B128);
        s.ad(key.as_ref(), false);
        s.ad(nonce.as_ref(), false);
        s.send_enc(data.as_mut(), false);
        s.send_mac(tag.as_mut(), false);
        Self {
            _marker: PhantomData,
            data,
            nonce,
            tag,
        }
    }

    pub fn decrypt(&self, key: &CryptoArray<K>) -> Result<CryptoArray<D>, DecryptError> {
        let mut data = self.data.clone();
        let mut tag = self.tag.clone();

        let mut s = Strobe::new(b"DiscoAEAD", SecParam::B128);
        s.ad(key.as_ref(), false);
        s.ad(self.nonce.as_ref(), false);
        s.recv_enc(data.as_mut(), false);
        s.recv_mac(tag.as_mut(), false).map_err(|_| DecryptError)?;
        Ok(data)
    }
}
