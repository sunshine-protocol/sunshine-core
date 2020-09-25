use crate::array::CryptoArray;
use crate::dh::DiffieHellman;
use crate::error::DiffieHellmanError;
use crate::keychain::{KeyType, TypedPair};
use generic_array::typenum::U32;
use parity_scale_codec::Encode;
use sp_core::Pair;
use sp_runtime::traits::{IdentifyAccount, SignedExtension, Verify};
use std::convert::TryInto;
use std::future::Future;
use std::pin::Pin;
use substrate_subxt::{
    extrinsic::SignedPayload, sp_runtime, Runtime, SignedExtra, UncheckedExtrinsic,
};
use zeroize::Zeroize;

/// Signer.
pub trait Signer<T: Runtime>: Send + Sync {
    /// Returns the public key.
    fn public(&self) -> &<T::Signature as Verify>::Signer;

    /// Returns the account id.
    fn account_id(&self) -> &T::AccountId;

    /// Optionally returns a nonce.
    fn nonce(&self) -> Option<T::Index>;

    /// Sets the nonce.
    fn set_nonce(&mut self, nonce: T::Index);

    /// Increments the nonce.
    fn increment_nonce(&mut self);

    /// Takes an unsigned extrinsic and returns a signed extrinsic.
    fn sign_extrinsic(&self, extrinsic: SignedPayload<T>) -> UncheckedExtrinsic<T>;

    /// Signs an arbitrary payload.
    fn sign(&self, payload: &[u8]) -> T::Signature;

    /// Performs a diffie hellman with a public key.
    ///
    /// Returns a different crypto error if the public key isn't the same type as the
    /// signer.
    fn diffie_hellman(
        &self,
        public: &<T::Signature as Verify>::Signer,
    ) -> Result<CryptoArray<U32>, DiffieHellmanError>;
}

/// Signer using a private key.
pub struct GenericSigner<T: Runtime, K: KeyType> {
    account_id: T::AccountId,
    public: <T::Signature as Verify>::Signer,
    nonce: Option<T::Index>,
    signer: TypedPair<K>,
}

impl<T: Runtime, K: KeyType> GenericSigner<T, K>
where
    <T::Signature as Verify>::Signer:
        From<<K::Pair as Pair>::Public> + IdentifyAccount<AccountId = T::AccountId>,
{
    /// Creates a new `Signer` from a `Pair`.
    pub fn new(signer: TypedPair<K>) -> Self {
        let raw_public = &*signer.public();
        let public = <T::Signature as Verify>::Signer::from(raw_public.clone());
        let account_id = <T::Signature as Verify>::Signer::from(raw_public.clone()).into_account();
        Self {
            signer,
            public,
            account_id,
            nonce: None,
        }
    }
}

impl<T: Runtime, K: KeyType> Signer<T> for GenericSigner<T, K>
where
    T::AccountId: Into<T::Address>,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    <T::Signature as Verify>::Signer: From<<K::Pair as Pair>::Public>
        + TryInto<<K::Pair as Pair>::Public>
        + IdentifyAccount<AccountId = T::AccountId>
        + Clone
        + Send
        + Sync,
    <K::Pair as Pair>::Signature: Into<T::Signature>,
{
    fn public(&self) -> &<T::Signature as Verify>::Signer {
        &self.public
    }

    fn account_id(&self) -> &T::AccountId {
        &self.account_id
    }

    fn nonce(&self) -> Option<T::Index> {
        self.nonce
    }

    fn set_nonce(&mut self, nonce: T::Index) {
        self.nonce = Some(nonce);
    }

    fn increment_nonce(&mut self) {
        self.nonce = self.nonce.map(|nonce| nonce + 1.into());
    }

    fn sign_extrinsic(&self, extrinsic: SignedPayload<T>) -> UncheckedExtrinsic<T> {
        let signature = extrinsic.using_encoded(|payload| self.signer.sign(payload));
        let (call, extra, _) = extrinsic.deconstruct();
        UncheckedExtrinsic::<T>::new_signed(
            call,
            self.account_id.clone().into(),
            signature.into(),
            extra,
        )
    }

    fn sign(&self, payload: &[u8]) -> T::Signature {
        self.signer.sign(payload).into()
    }

    fn diffie_hellman(
        &self,
        public: &<T::Signature as Verify>::Signer,
    ) -> Result<CryptoArray<U32>, DiffieHellmanError> {
        let public = public.clone().try_into().map_err(|_| DiffieHellmanError)?;
        let mut shared_secret = self.signer.diffie_hellman(&public);
        let mut array = CryptoArray::default();
        array.copy_from_slice(&shared_secret);
        shared_secret.zeroize();
        Ok(array)
    }
}

pub struct GenericSubxtSigner<'a, T: Runtime>(pub &'a dyn Signer<T>);

impl<'a, T: Runtime> substrate_subxt::Signer<T> for GenericSubxtSigner<'a, T> {
    fn account_id(&self) -> &T::AccountId {
        self.0.account_id()
    }

    fn nonce(&self) -> Option<T::Index> {
        self.0.nonce()
    }

    fn sign(
        &self,
        extrinsic: SignedPayload<T>,
    ) -> Pin<Box<dyn Future<Output = Result<UncheckedExtrinsic<T>, String>> + Send>> {
        let extrinsic = self.0.sign_extrinsic(extrinsic);
        Box::pin(async move { Ok(extrinsic) })
    }
}
