pub use crate::error::{
    KeystoreInitialized, KeystoreLocked, KeystoreUninitialized, PasswordMissmatch,
};
use crate::keychain::{KeyType, TypedPair};
use anyhow::Result;
use async_trait::async_trait;
use secrecy::SecretString;

/// A generic keystore.
#[async_trait]
pub trait Keystore<K: KeyType>: Send + Sync {
    /// Checks if the keystore is initialized.
    async fn is_initialized(&self) -> Result<bool>;

    /// Sets the key of the keystore.
    ///
    /// If the force flag is false it will return a `KeystoreInitialized` error
    /// if the keystore is initialized. Otherwise it will overwrite the key.
    async fn set_key(
        &mut self,
        key: &TypedPair<K>,
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
    async fn unlock(&mut self, password: &SecretString) -> Result<TypedPair<K>>;
}

#[cfg(any(test, feature = "mock"))]
pub mod mock {
    use super::*;
    use secrecy::ExposeSecret;

    pub struct MemKeystore<K: KeyType> {
        keystore: Option<(TypedPair<K>, SecretString)>,
        key: Option<TypedPair<K>>,
    }

    impl<K: KeyType> Default for MemKeystore<K> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<K: KeyType> MemKeystore<K> {
        pub fn new() -> Self {
            Self {
                keystore: None,
                key: None,
            }
        }
    }

    #[async_trait]
    impl<K: KeyType> Keystore<K> for MemKeystore<K> {
        async fn is_initialized(&self) -> Result<bool> {
            Ok(self.keystore.is_some())
        }

        async fn set_key(
            &mut self,
            key: &TypedPair<K>,
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

        async fn unlock(&mut self, password: &SecretString) -> Result<TypedPair<K>> {
            if let Some((key, pass)) = self.keystore.as_ref() {
                if password.expose_secret() == pass.expose_secret() {
                    self.key = Some(key.clone());
                    Ok(key.clone())
                } else {
                    Err(PasswordMissmatch.into())
                }
            } else {
                Err(KeystoreUninitialized.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::{KeyChain, KeyType, TypedPublic};
    use crate::secret_box::SecretBox;
    use crate::signer::{GenericSigner, Signer};
    use mock::MemKeystore;
    use sp_core::sr25519;
    use sp_keyring::AccountKeyring;
    use substrate_subxt::DefaultNodeRuntime;

    pub struct DeviceKey;

    impl KeyType for DeviceKey {
        const KEY_TYPE: u8 = 0;
        type Pair = sr25519::Pair;
    }

    #[async_std::test]
    async fn test_flow() {
        let key = TypedPair::<DeviceKey>::generate().await;
        let password = SecretString::new("password".to_string());
        let mut keystore = MemKeystore::new();
        keystore.set_key(&key, &password, false).await.unwrap();

        let mut chain = KeyChain::new();
        chain.insert(key.clone());
        let public = TypedPublic::<DeviceKey>::new(AccountKeyring::Bob.public());
        chain.insert_public(public);

        let signer = GenericSigner::<DefaultNodeRuntime, DeviceKey>::new(key);
        let _secret = signer
            .diffie_hellman(&AccountKeyring::Bob.public().into())
            .unwrap();

        let text = "a string".to_string();
        let secret = SecretBox::<DeviceKey, String>::encrypt(&chain, &text)
            .await
            .unwrap();
        let text2 = secret.decrypt(&chain).unwrap();
        assert_eq!(text, text2);
    }
}
