use anyhow::Result;
use async_std::fs::File;
use async_std::path::{Path, PathBuf};
use async_std::prelude::*;
use parity_scale_codec::{Decode, Encode};
use std::ops::Deref;

pub struct SecretFile(PathBuf);

impl SecretFile {
    pub fn new(path: PathBuf) -> Self {
        Self(path)
    }

    pub async fn read<T: Decode>(&self) -> Result<T> {
        let mut file = File::open(&self.0).await?;
        let mut buf = Vec::with_capacity(255);
        file.read_to_end(&mut buf).await?;
        let res = Decode::decode(&mut &buf[..])?;
        Ok(res)
    }

    pub async fn write<T: Encode>(&self, secret: &T) -> Result<()> {
        let mut file = File::create(&self.0).await?;
        #[cfg(unix)]
        {
            use std::fs::Permissions;
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(Permissions::from_mode(0o600)).await?;
        }
        let buf = secret.encode();
        file.write_all(&buf).await?;
        file.sync_all().await?;
        Ok(())
    }
}

impl Deref for SecretFile {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::array::CryptoArray;
    use crate::typenum::U32;

    #[async_std::test]
    async fn test_secret_file() {
        let secret = CryptoArray::<U32>::random().await;
        let mut secret_file = std::env::temp_dir();
        secret_file.push("secret_file");
        let file = SecretFile::new(secret_file.into());
        file.write(&secret).await.unwrap();
        let secret2 = file.read().await.unwrap();
        assert_eq!(secret, secret2);
    }
}
