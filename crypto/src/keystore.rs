use crate::array::CryptoArray;
pub use crate::error::{
    KeystoreInitialized, KeystoreLocked, KeystoreUninitialized, PasswordMissmatch,
};
use anyhow::Result;
use async_trait::async_trait;
use generic_array::typenum::U32;
use secrecy::SecretString;

/// A generic keystore.
#[async_trait]
pub trait Keystore: Send + Sync {
    /// Returns the key from the keystore.
    ///
    /// If the keystore is locked it will return a `KeystoreLocked` error.
    fn get_key(&self) -> Result<CryptoArray<U32>>;

    /// Sets the key of the keystore.
    ///
    /// If the force flag is false it will return a `KeystoreInitialized` error
    /// if the keystore is initialized. Otherwise it will overwrite the key.
    async fn set_key(
        &mut self,
        key: &CryptoArray<U32>,
        password: &SecretString,
        force: bool,
    ) -> Result<()>;

    /// Locks the keystore.
    ///
    /// If the keystore is locked or initialized, this is a noop.
    async fn lock(&mut self) -> Result<()>;

    /// Unlocks the keystore with a password.
    ///
    /// If the keystore is uninitialized it will return a `KeystoreUninitialized`
    /// error and if the password doesn't match it will return a `PasswordMissmatch`
    /// error.
    async fn unlock(&mut self, password: &SecretString) -> Result<()>;
}

#[cfg(feature = "mock")]
pub mod mock {
    use super::*;
    use secrecy::ExposeSecret;
    use sp_core::sr25519::Pair;
    use sp_keyring::AccountKeyring;

    #[derive(Default)]
    pub struct MemKeystore {
        keystore: Option<(CryptoArray<U32>, SecretString)>,
        key: Option<CryptoArray<U32>>,
    }

    impl MemKeystore {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn from_keyring(account: AccountKeyring) -> Self {
            let key = CryptoArray::from_suri::<Pair>(&account.to_seed())
                .expect("Well formed suri; qed");
            Self {
                keystore: None,
                key: Some(key),
            }
        }
    }

    #[async_trait]
    impl Keystore for MemKeystore {
        fn get_key(&self) -> Result<CryptoArray<U32>> {
            if let Some(key) = self.key.clone() {
                Ok(key)
            } else {
                Err(KeystoreLocked.into())
            }
        }

        async fn set_key(
            &mut self,
            key: &CryptoArray<U32>,
            password: &SecretString,
            force: bool,
        ) -> Result<()> {
            if self.keystore.is_some() && !force {
                Err(KeystoreInitialized.into())
            } else {
                self.keystore = Some((key.clone(), password.clone()));
                Ok(())
            }
        }

        async fn lock(&mut self) -> Result<()> {
            self.key = None;
            Ok(())
        }

        async fn unlock(&mut self, password: &SecretString) -> Result<()> {
            if let Some((key, pass)) = self.keystore.as_ref() {
                if password.expose_secret() == pass.expose_secret() {
                    self.key = Some(key.clone());
                    Ok(())
                } else {
                    Err(PasswordMissmatch.into())
                }
            } else {
                Err(KeystoreUninitialized.into())
            }
        }
    }
}
