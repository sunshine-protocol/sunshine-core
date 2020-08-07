use crate::dh::DiffieHellman;
use crate::keychain::{KeyChain, KeyType, TypedPair, TypedPublic};
use parity_scale_codec::{Decode, Encode, Input};
use rand::rngs::OsRng;
use rand::RngCore;
use sp_core::{Pair, Public};
use std::io::Read;
use std::marker::PhantomData;
use strobe_rs::{SecParam, Strobe};
use thiserror::Error;

const X25519_LEN: usize = 32;
const TAG_LEN: usize = 16;

#[derive(Eq, PartialEq)]
pub struct SecretBox<K, T> {
    _marker: PhantomData<(K, T)>,
    secret: Vec<u8>,
}

impl<K, T> Clone for SecretBox<K, T> {
    fn clone(&self) -> Self {
        Self {
            _marker: self._marker,
            secret: self.secret.clone(),
        }
    }
}

impl<K, T> std::fmt::Debug for SecretBox<K, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "SecretBox")
    }
}

impl<K, T> Encode for SecretBox<K, T> {
    fn size_hint(&self) -> usize {
        self.secret.len()
    }

    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.secret.using_encoded(f)
    }
}

impl<K, T> Decode for SecretBox<K, T> {
    fn decode<R: Input>(value: &mut R) -> Result<Self, parity_scale_codec::Error> {
        Ok(Self {
            _marker: PhantomData,
            secret: Decode::decode(value)?,
        })
    }
}

impl<K: KeyType, T: Decode + Encode> SecretBox<K, T> {
    pub async fn encrypt(key_chain: &KeyChain, payload: &T) -> Result<Self, SecretBoxError> {
        let recipients = key_chain.get_public::<K>();
        Self::encrypt_for(payload, &recipients).await
    }

    pub async fn encrypt_for(
        payload: &T,
        recipients: &[TypedPublic<K>],
    ) -> Result<Self, SecretBoxError> {
        if recipients.is_empty() {
            return Err(SecretBoxError::NoRecipients);
        }
        if recipients.len() as u8 as usize != recipients.len() {
            return Err(SecretBoxError::TooManyRecipients);
        }
        // Create a buffer.
        let capacity =
            recipients.len() * (X25519_LEN + TAG_LEN) + X25519_LEN + 1 + payload.size_hint();
        let mut buf = Vec::with_capacity(capacity);

        // Create a payload key.
        let mut payload_key = [0u8; 32];
        OsRng.fill_bytes(&mut payload_key);

        // Write the number of recipients to buffer.
        buf.extend_from_slice(&[recipients.len() as u8]);

        // Compute an ephermal public key and write to buffer.
        let secret = TypedPair::<K>::generate().await;
        let ephemeral = secret.public();
        buf.extend_from_slice(ephemeral.as_ref());

        // For each recipient encrypt the payload key with the
        // diffie_hellman of the ephermal key and the recipients
        // public key and write to buffer.
        for public in recipients {
            let shared_secret = secret.diffie_hellman(&public);
            let mut payload_key = payload_key;

            let mut s = Strobe::new(b"secret-box-key", SecParam::B128);
            s.ad(shared_secret.as_ref(), false);
            s.send_enc(&mut payload_key, false);
            buf.extend_from_slice(&payload_key);

            // Add tag to check if we can unlock the payload key.
            let mut mac = [0u8; TAG_LEN];
            s.send_mac(&mut mac, false);
            buf.extend_from_slice(&mac);
        }

        let mut s = Strobe::new(b"secret-box", SecParam::B128);
        // Absorb shared secret.
        s.ad(&payload_key, false);

        let payload_start = buf.len();
        payload.encode_to(&mut buf);
        s.send_enc(&mut buf[payload_start..], false);
        // don't need a tag as this will go into a content addressed block.

        Ok(Self {
            _marker: PhantomData,
            secret: buf,
        })
    }

    pub fn decrypt(&self, key_chain: &KeyChain) -> Result<T, SecretBoxError> {
        let stream = &mut &self.secret[..];

        let mut len = [0];
        stream.read_exact(&mut len)?;
        let len = len[0] as usize;
        if len == 0 {
            return Err(SecretBoxError::NoRecipients);
        }

        let mut public = [0u8; X25519_LEN];
        stream.read_exact(&mut public)?;
        let ephemeral = <K::Pair as Pair>::Public::from_slice(&public);

        let secret = key_chain
            .get::<K>()
            .ok_or(SecretBoxError::NoDecryptionKey)?;
        let shared_secret = secret.diffie_hellman(&ephemeral);
        let mut payload_key = None;
        for _ in 0..len {
            let mut tmp_payload_key = [0u8; X25519_LEN];
            stream.read_exact(&mut tmp_payload_key)?;
            let mut mac = [0u8; TAG_LEN];
            stream.read_exact(&mut mac)?;

            if payload_key.is_some() {
                continue;
            }

            let mut s = Strobe::new(b"secret-box-key", SecParam::B128);
            s.ad(shared_secret.as_ref(), false);
            s.recv_enc(&mut tmp_payload_key, false);
            if let Ok(()) = s.recv_mac(&mut mac, false) {
                payload_key = Some(tmp_payload_key);
            }
        }
        let payload_key = payload_key.ok_or(SecretBoxError::NoDecryptionKey)?;

        let payload_start = len * (X25519_LEN + TAG_LEN) + X25519_LEN + 1;
        let payload_slice = &self.secret[payload_start..];
        let mut payload = Vec::with_capacity(payload_slice.len());
        payload.extend_from_slice(payload_slice);

        let mut s = Strobe::new(b"secret-box", SecParam::B128);
        s.ad(&payload_key, false);
        s.recv_enc(&mut payload, false);

        Ok(Decode::decode(&mut &payload[..])?)
    }
}

#[derive(Debug, Error)]
pub enum SecretBoxError {
    #[error("no recipients")]
    NoRecipients,
    #[error("too many recipients")]
    TooManyRecipients,
    #[error("no decryption key")]
    NoDecryptionKey,
    #[error(transparent)]
    Scale(#[from] parity_scale_codec::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp_core::sr25519;

    #[derive(Debug, Eq, PartialEq)]
    struct AllDevices;
    impl KeyType for AllDevices {
        const KEY_TYPE: u8 = 1;
        type Pair = sr25519::Pair;
    }

    #[async_std::test]
    async fn test_secret_box() {
        let mut alice = KeyChain::new();
        let mut bob = KeyChain::new();

        let dk = TypedPair::<AllDevices>::generate().await;
        bob.insert_public(dk.public());
        alice.insert(dk);

        let dk = TypedPair::<AllDevices>::generate().await;
        alice.insert_public(dk.public());
        bob.insert(dk);

        let value = "hello world".to_string();

        let secret = SecretBox::<AllDevices, String>::encrypt(&alice, &value)
            .await
            .unwrap();
        let value2 = secret.decrypt(&alice).unwrap();
        assert_eq!(value, value2);
        let value2 = secret.decrypt(&bob).unwrap();
        assert_eq!(value, value2);

        let secret2: SecretBox<AllDevices, String> =
            Decode::decode(&mut &secret.encode()[..]).unwrap();
        assert_eq!(secret, secret2);
    }
}
