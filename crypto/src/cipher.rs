use crate::array::{CryptoArray, Size};
use crate::error::DecryptError;
use strobe_rs::{SecParam, Strobe};

/// Cipher text encrypted with a nonce and a tag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CipherText<S: Size, N: Size, T: Size> {
    pub data: CryptoArray<S>,
    pub nonce: CryptoArray<N>,
    pub tag: CryptoArray<T>,
}

impl<S: Size, N: Size, T: Size> CipherText<S, N, T> {
    pub async fn encrypt<K: Size>(data: &CryptoArray<S>, key: &CryptoArray<K>) -> Self {
        let mut data = data.clone();
        let nonce = CryptoArray::random().await;
        let mut tag = CryptoArray::default();

        let mut s = Strobe::new(b"DiscoAEAD", SecParam::B128);
        s.ad(key.as_ref(), false);
        s.ad(nonce.as_ref(), false);
        s.send_enc(data.as_mut(), false);
        s.send_mac(tag.as_mut(), false);
        CipherText { data, nonce, tag }
    }

    pub fn decrypt<K: Size>(&self, key: &CryptoArray<K>) -> Result<CryptoArray<S>, DecryptError> {
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
