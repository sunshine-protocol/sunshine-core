use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek as ed25519;
use schnorrkel as sr25519;
use sha2::{Digest, Sha512};
use sp_core::{ed25519 as sp_ed25519, sr25519 as sp_sr25519, Pair};
use x25519_dalek as x25519;
use zeroize::Zeroize;

pub trait DiffieHellman: Pair {
    type SharedSecret;

    fn diffie_hellman(&self, public: &Self::Public) -> Self::SharedSecret;
}

impl DiffieHellman for sp_sr25519::Pair {
    type SharedSecret = [u8; 32];

    fn diffie_hellman(&self, public: &Self::Public) -> Self::SharedSecret {
        let mut sk_bytes = self.as_ref().secret.to_bytes();
        // Conversion due to incompatible schnorrkel versions.
        let sk =
            sr25519::SecretKey::from_bytes(sk_bytes.as_ref()).expect("key is correct size; qed");
        sk_bytes.zeroize();
        // Conversion due to incompatible schnorrkel versions.
        let pk = sr25519::PublicKey::from_bytes(public.as_ref()).expect("key is correct size; qed");
        sk.aead32_unauthenticated::<ExtractKey>(&pk).0
    }
}

struct ExtractKey([u8; 32]);

impl aead::NewAead for ExtractKey {
    type KeySize = aead::generic_array::typenum::U32;

    fn new(key: aead::generic_array::GenericArray<u8, Self::KeySize>) -> Self {
        Self(key.into())
    }
}

impl DiffieHellman for sp_ed25519::Pair {
    type SharedSecret = [u8; 32];

    fn diffie_hellman(&self, public: &Self::Public) -> Self::SharedSecret {
        let sk = ed25519::SecretKey::from_bytes(self.seed()).expect("key is correct size; qed");
        let pk = ed25519::PublicKey::from_bytes(public.as_ref()).expect("key is correct size; qed");
        let sk = ed25519_to_x25519_sk(&sk);
        let pk = ed25519_to_x25519_pk(&pk);
        *sk.diffie_hellman(&pk).as_bytes()
    }
}

/// Construct a X25519 secret key from a Ed25519 secret key.
///
/// > **Note**: If the Ed25519 secret key is already used in the context
/// > of other cryptographic protocols outside of Noise, e.g. for
/// > signing in the `secio` protocol, it should be preferred to
/// > create a new keypair for use in the Noise protocol.
/// >
/// > See also:
/// >
/// >  * [Noise: Static Key Reuse](http://www.noiseprotocol.org/noise.html#security-considerations)
/// >  * [Ed25519 to Curve25519](https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519)
pub fn ed25519_to_x25519_sk(ed25519_sk: &ed25519::SecretKey) -> x25519::StaticSecret {
    // An Ed25519 public key is derived off the left half of the SHA512 of the
    // secret scalar, hence a matching conversion of the secret key must do
    // the same to yield a Curve25519 keypair with the same public key.
    // let ed25519_sk = ed25519::SecretKey::from(ed);
    let mut curve25519_sk: [u8; 32] = [0; 32];
    let hash = Sha512::digest(ed25519_sk.as_ref());
    curve25519_sk.copy_from_slice(&hash.as_ref()[..32]);
    let sk = x25519::StaticSecret::from(curve25519_sk); // Copy
    curve25519_sk.zeroize();
    sk
}

/// Construct a curve25519 public key from an Ed25519 public key.
pub fn ed25519_to_x25519_pk(pk: &ed25519::PublicKey) -> x25519::PublicKey {
    x25519::PublicKey::from(
        CompressedEdwardsY(pk.to_bytes())
            .decompress()
            .expect("An Ed25519 public key is a valid point by construction.")
            .to_montgomery()
            .0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sr25519_dh() {
        let sk1 = sp_sr25519::Pair::generate().0;
        let sk2 = sp_sr25519::Pair::generate().0;
        let s1 = sk1.diffie_hellman(&sk2.public());
        let s2 = sk2.diffie_hellman(&sk1.public());
        assert_eq!(s1, s2);
    }

    #[test]
    fn ed25519_dh() {
        let sk1 = sp_ed25519::Pair::generate().0;
        let sk2 = sp_ed25519::Pair::generate().0;
        let s1 = sk1.diffie_hellman(&sk2.public());
        let s2 = sk2.diffie_hellman(&sk1.public());
        assert_eq!(s1, s2);
    }
}
