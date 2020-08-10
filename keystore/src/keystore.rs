use crate::error::{GenMissmatch, KeystoreCorrupted};
use crate::generation::Generation;
use crate::types::*;
use anyhow::Result;
#[cfg(unix)]
use async_std::os::unix::fs::symlink;
#[cfg(windows)]
use async_std::os::windows::fs::symlink_dir as symlink;
use async_std::path::{Path, PathBuf};
use async_std::prelude::*;
use std::ffi::OsString;
use std::marker::PhantomData;
use sunshine_crypto::keychain::{KeyType, TypedPair};
use sunshine_crypto::keystore::KeystoreInitialized;
use sunshine_crypto::secrecy::SecretString;

pub struct Keystore<K> {
    _marker: PhantomData<K>,
    path: PathBuf,
}

impl<K: KeyType> Keystore<K> {
    /// Creates a keystore.
    pub fn new<T: AsRef<Path>>(path: T) -> Self {
        Self {
            _marker: PhantomData,
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Creates a new generation and atomically changes the symlink.
    async fn create_gen(&self, dk: &TypedPair<K>, pass: &Password, gen: u16) -> Result<()> {
        async_std::fs::create_dir_all(&self.path).await?;
        let gen = Generation::new(&self.path, gen);
        gen.initialize(dk, pass).await?;
        let gen_new_link = self.path.join("gen_new");
        symlink(gen.path(), &gen_new_link).await?;
        async_std::fs::rename(&gen_new_link, self.path.join("gen")).await?;
        self.garbage_collect_gens().await.ok();
        Ok(())
    }

    /// Returns the generation.
    async fn read_gen(&self) -> Result<Generation<K>> {
        let gen_link = self.path.join("gen");
        if gen_link.exists().await {
            let gen_dir = async_std::fs::read_link(gen_link).await?;
            let gen: u16 = gen_dir
                .file_name()
                .ok_or(KeystoreCorrupted)?
                .to_str()
                .ok_or(KeystoreCorrupted)?
                .parse()
                .map_err(|_| KeystoreCorrupted)?;
            let gen_path = gen_dir.parent().ok_or(KeystoreCorrupted)?;
            if gen_path != self.path {
                return Err(KeystoreCorrupted.into());
            }
            Ok(Generation::new(&self.path, gen))
        } else {
            Ok(Generation::new(&self.path, 0))
        }
    }

    /// Removes old or failed generations.
    ///
    /// NOTE: since the keystore does not use any file locks this can lead to a race. It is
    /// assumed that a single application uses the keystore and that there is only one application
    /// running.
    async fn garbage_collect_gens(&self) -> Result<()> {
        let gen = self.read_gen().await?;

        let mut dir = async_std::fs::read_dir(&self.path).await?;
        let gen_str = OsString::from(gen.gen().to_string());
        while let Some(entry) = dir.next().await {
            let file_name = entry?.file_name();
            if file_name == "gen" {
                continue;
            }
            if file_name != gen_str.as_os_str() {
                async_std::fs::remove_dir_all(self.path.join(&file_name)).await?;
            }
        }

        Ok(())
    }

    /// Sets the device key.
    pub async fn set_device_key(
        &self,
        device_key: &TypedPair<K>,
        password: &SecretString,
        force: bool,
    ) -> Result<()> {
        if !force && self.read_gen().await?.is_initialized().await {
            return Err(KeystoreInitialized.into());
        }
        self.create_gen(device_key, &Password::new(password), 0)
            .await?;
        Ok(())
    }

    /// Provisions the keystore.
    pub async fn provision_device(&self, password: &Password, gen: u16) -> Result<TypedPair<K>> {
        let device_key = TypedPair::generate().await;
        self.create_gen(&device_key, password, gen).await?;
        Ok(device_key)
    }

    /// Locks the keystore.
    pub async fn lock(&self) -> Result<()> {
        self.read_gen().await?.lock().await
    }

    /// Unlocks the keystore.
    pub async fn unlock(&self, password: &SecretString) -> Result<TypedPair<K>> {
        self.read_gen()
            .await?
            .unlock(&Password::new(password))
            .await
    }

    /// Gets the device key.
    pub async fn device_key(&self) -> Result<TypedPair<K>> {
        self.read_gen().await?.device_key().await
    }

    /// Gets the password and gen to send to a device during provisioning.
    pub async fn password(&self) -> Result<(Password, u16)> {
        let gen = self.read_gen().await?;
        Ok((gen.password().await?, gen.gen()))
    }

    /// Get current password gen.
    pub async fn gen(&self) -> Result<u16> {
        Ok(self.read_gen().await?.gen())
    }

    /// Change password.
    pub async fn change_password_mask(&self, password: &SecretString) -> Result<(Mask, u16)> {
        let gen = self.read_gen().await?;
        let mask = gen.change_password_mask(&Password::new(password)).await?;
        Ok((mask, gen.gen() + 1))
    }

    /// Creates a new generation from a password mask.
    pub async fn apply_mask(&self, mask: &Mask, next_gen: u16) -> Result<()> {
        let gen = self.read_gen().await?;
        if gen.gen() + mask.len() != next_gen {
            return Err(GenMissmatch.into());
        }
        let dk = gen.device_key().await?;
        let pass = gen.password().await?.apply_mask(mask);
        self.create_gen(&dk, &pass, next_gen).await
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use sunshine_crypto::keystore::{KeystoreLocked, PasswordMissmatch};
    use sunshine_crypto::sr25519::Pair;
    use tempdir::TempDir;

    struct Key;

    impl KeyType for Key {
        const KEY_TYPE: u8 = 0;
        type Pair = Pair;
    }

    #[async_std::test]
    async fn test_keystore() {
        let tmp = TempDir::new("keystore-").unwrap();
        let store = Keystore::<Key>::new(tmp.path());

        // generate
        let key = TypedPair::generate().await;
        let p1 = SecretString::new("password".to_string());
        store.set_device_key(&key, &p1, false).await.unwrap();

        // check reading the device key.
        let key2 = store.device_key().await.unwrap();
        assert_eq!(key, key2);

        // check reading the password.
        let (rp1, gen) = store.password().await.unwrap();
        assert_eq!(Password::new(&p1), rp1);
        assert_eq!(gen, 0);

        // make sure key is the same after lock/unlock
        store.lock().await.unwrap();
        store.unlock(&p1).await.unwrap();
        let key2 = store.device_key().await.unwrap();
        assert_eq!(key, key2);

        // change password
        let p2 = SecretString::new("other password".to_string());
        let (mask, gen) = store.change_password_mask(&p2).await.unwrap();
        store.apply_mask(&mask, gen).await.unwrap();

        // make sure key is the same after lock/unlock
        store.lock().await.unwrap();

        let store = Keystore::new(tmp.path());
        store.unlock(&p2).await.unwrap();
        let key2 = store.device_key().await.unwrap();
        assert_eq!(key, key2);

        // make sure unlock fails if password is wrong
        let p3 = SecretString::new("wrong password".to_string());
        store.lock().await.unwrap();
        store
            .unlock(&p3)
            .await
            .unwrap_err()
            .downcast_ref::<PasswordMissmatch>()
            .unwrap();
        store
            .device_key()
            .await
            .unwrap_err()
            .downcast_ref::<KeystoreLocked>()
            .unwrap();
    }
}
