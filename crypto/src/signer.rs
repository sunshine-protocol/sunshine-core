use parity_scale_codec::Encode;
use sp_core::Pair;
use sp_runtime::traits::{IdentifyAccount, SignedExtension, Verify};
use std::future::Future;
use std::pin::Pin;
use substrate_subxt::{
    extrinsic::SignedPayload, sp_core, sp_runtime, Runtime, SignedExtra, UncheckedExtrinsic,
};

/// Signer.
pub trait Signer<T: Runtime>: substrate_subxt::Signer<T> + Send + Sync {
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
}

/// Signer using a private key.
pub struct GenericSigner<T: Runtime, P: Pair> {
    account_id: T::AccountId,
    public: <T::Signature as Verify>::Signer,
    nonce: Option<T::Index>,
    signer: P,
}

impl<T: Runtime, P: Pair> GenericSigner<T, P>
where
    <T::Signature as Verify>::Signer: From<P::Public> + IdentifyAccount<AccountId = T::AccountId>,
{
    /// Creates a new `Signer` from a `Pair`.
    pub fn new(signer: P) -> Self {
        let public = <T::Signature as Verify>::Signer::from(signer.public());
        let account_id = <T::Signature as Verify>::Signer::from(signer.public()).into_account();
        Self {
            signer,
            public,
            account_id,
            nonce: None,
        }
    }
}

impl<T: Runtime, P: Pair> Signer<T> for GenericSigner<T, P>
where
    T::AccountId: Into<T::Address>,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    <T::Signature as Verify>::Signer:
        From<P::Public> + IdentifyAccount<AccountId = T::AccountId> + Send + Sync,
    P::Signature: Into<T::Signature>,
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
}

impl<T: Runtime, P: Pair> substrate_subxt::Signer<T> for GenericSigner<T, P>
where
    T::AccountId: Into<T::Address>,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    <T::Signature as Verify>::Signer:
        From<P::Public> + IdentifyAccount<AccountId = T::AccountId> + Send + Sync,
    P::Signature: Into<T::Signature>,
{
    fn account_id(&self) -> &T::AccountId {
        Signer::account_id(self)
    }

    fn nonce(&self) -> Option<T::Index> {
        Signer::nonce(self)
    }

    fn sign(
        &self,
        extrinsic: SignedPayload<T>,
    ) -> Pin<Box<dyn Future<Output = Result<UncheckedExtrinsic<T>, String>> + Send + Sync>> {
        let extrinsic = Signer::sign_extrinsic(self, extrinsic);
        Box::pin(async move { Ok(extrinsic) })
    }
}
