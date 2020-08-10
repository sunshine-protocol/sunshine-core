mod error;
mod generation;
mod keystore;
mod noise;
mod types;

pub use error::*;
pub use keystore::Keystore;
pub use types::{Mask, Password};

use anyhow::Result;
use sunshine_crypto::keychain::{KeyType, TypedPair};
use sunshine_crypto::secrecy::SecretString;

#[async_trait::async_trait]
impl<K: KeyType> sunshine_crypto::keystore::Keystore<K> for Keystore<K> {
    async fn is_initialized(&self) -> Result<bool> {
        self.is_initialized().await
    }

    async fn set_key(
        &mut self,
        key: &TypedPair<K>,
        password: &SecretString,
        force: bool,
    ) -> Result<()> {
        self.set_device_key(key, password, force).await
    }

    async fn lock(&mut self) -> Result<()> {
        self.lock().await
    }

    async fn unlock(&mut self, password: &SecretString) -> Result<TypedPair<K>> {
        self.unlock(password).await
    }
}
