use crate::noise::NoiseFile;
use crate::types::{EncryptedRandomKey, Mask, Password, PublicDeviceKey, RandomKey};
use anyhow::Result;
use async_std::path::{Path, PathBuf};
use std::marker::PhantomData;
use sunshine_crypto::keychain::{KeyType, TypedPair};
use sunshine_crypto::keystore::{KeystoreLocked, KeystoreUninitialized, PasswordMissmatch};
use sunshine_crypto::secret_file::SecretFile;

pub struct Generation<K> {
    _marker: PhantomData<K>,
    gen: u16,
    path: PathBuf,
    edk: SecretFile,
    erk: SecretFile,
    noise: NoiseFile,
    pdk: SecretFile,
}

impl<K: KeyType> Generation<K> {
    /// Creates a generation.
    pub fn new(path: &Path, gen: u16) -> Self {
        let path = path.join(gen.to_string());
        Self {
            _marker: PhantomData,
            gen,
            edk: SecretFile::new(path.join("encrypted_device_key")),
            erk: SecretFile::new(path.join("encrypted_random_key")),
            noise: NoiseFile::new(path.join("noise")),
            pdk: SecretFile::new(path.join("public_device_key")),
            path,
        }
    }

    /// Returns the generation number.
    pub fn gen(&self) -> u16 {
        self.gen
    }

    /// Returns the path of the generation.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Checks if the keystore is initialized.
    pub async fn is_initialized(&self) -> bool {
        self.edk.exists().await
    }

    /// Initializes the keystore.
    pub async fn initialize(&self, dk: &TypedPair<K>, pass: &Password) -> Result<()> {
        let path = self.edk.parent().expect("joined a file name on init; qed");
        async_std::fs::create_dir_all(path).await?;

        let rk = RandomKey::generate().await;

        let edk = dk.encrypt(rk.as_ref()).await;

        let pdk = rk.public(&pass);
        self.pdk.write(&pdk).await?;

        // Unlock
        // So we can delay writing the private key we unlock manually
        self.noise.generate().await?;
        let nk = self.noise.read_secret().await?;

        let erk = rk.encrypt(&nk).await;
        self.erk.write(&erk).await?;
        // End unlock

        // Write private key at the end.
        self.edk.write(&edk).await?;

        // Make sure keystore is in a valid state.
        self.device_key().await?;

        Ok(())
    }

    /// Unlocking the keystore makes the random key decryptable.
    pub async fn unlock(&self, pass: &Password) -> Result<TypedPair<K>> {
        let pdk = self.public().await?;
        let rk = pdk.private(pass);

        self.noise.generate().await?;
        let nk = self.noise.read_secret().await?;

        let erk = rk.encrypt(&nk).await;
        self.erk.write(&erk).await?;

        self.device_key().await.map_err(|err| {
            if err.downcast_ref::<KeystoreLocked>().is_some() {
                PasswordMissmatch.into()
            } else {
                err
            }
        })
    }

    /// Locks the keystore by zeroizing the noise file. This makes the encrypted
    /// random key undecryptable without a password.
    pub async fn lock(&self) -> Result<()> {
        self.noise.zeroize().await?;
        Ok(())
    }

    async fn random_key(&self) -> Result<RandomKey> {
        let nk = self.noise.read_secret().await?;
        let erk: EncryptedRandomKey = self.erk.read().await?;
        Ok(erk.decrypt(&nk))
    }

    /// The random key is used to decrypt the device key.
    ///
    /// NOTE: Only works if the keystore was unlocked.
    pub async fn device_key(&self) -> Result<TypedPair<K>> {
        let rk = self.random_key().await?;
        let edk = self.edk.read().await?;
        let dk = TypedPair::decrypt(&edk, rk.as_ref()).map_err(|_| KeystoreLocked)?;
        Ok(dk)
    }

    /// The random key is used to recover the password.
    ///
    /// NOTE: Only works if the keystore was unlocked.
    pub async fn password(&self) -> Result<Password> {
        let rk = self.random_key().await?;
        let pdk = self.public().await?;
        Ok(rk.password(&pdk))
    }

    /// Returns the public device key.
    pub async fn public(&self) -> Result<PublicDeviceKey> {
        if !self.pdk.exists().await {
            return Err(KeystoreUninitialized.into());
        }
        Ok(self.pdk.read().await?)
    }

    /// Change password.
    pub async fn change_password_mask(&self, password: &Password) -> Result<Mask> {
        let old_password = self.password().await?;
        let mask = old_password.mask(password);
        Ok(mask)
    }
}
