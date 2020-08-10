use crate::types::NoiseHash;
use async_std::fs::{File, OpenOptions};
use async_std::io::Error;
use async_std::path::{Path, PathBuf};
use async_std::prelude::*;
use async_std::task;
use core::ops::Deref;
use rand::{thread_rng, Rng};
use strobe_rs::{SecParam, Strobe};
use sunshine_crypto::array::CryptoArray;

pub struct NoiseFile(PathBuf);

impl NoiseFile {
    pub fn new(path: PathBuf) -> Self {
        Self(path)
    }

    pub async fn generate(&self) -> Result<(), Error> {
        let path = self.0.clone();
        task::spawn_blocking(|| {
            use std::io::Write;
            let mut file = std::fs::File::create(path)?;
            #[cfg(unix)]
            {
                use std::fs::Permissions;
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(Permissions::from_mode(0o600))?;
            }
            let mut rng = thread_rng();
            let mut buf = [0; 4096];
            for _ in 0..500 {
                rng.fill(&mut buf);
                file.write_all(&buf)?;
            }
            file.sync_all()?;
            Ok(())
        })
        .await
    }

    pub async fn read_secret(&self) -> Result<NoiseHash, Error> {
        let mut file = File::open(&self.0).await?;
        let mut s = Strobe::new(b"DiscoHash", SecParam::B128);
        let mut buf = [0; 4096];
        for i in 0..500 {
            file.read_exact(&mut buf).await?;
            s.ad(&buf, i != 0);
        }
        let mut res = CryptoArray::default();
        s.prf(res.as_mut(), false);
        Ok(NoiseHash::new(res))
    }

    pub async fn zeroize(&self) -> Result<(), Error> {
        let mut file = OpenOptions::new().write(true).open(&self.0).await?;
        for _ in 0..500 {
            let buf = [0; 4096];
            file.write_all(&buf).await?;
        }
        file.sync_all().await?;
        Ok(())
    }
}

impl Deref for NoiseFile {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[async_std::test]
    async fn test_noise_file() {
        let mut noise_file = std::env::temp_dir();
        noise_file.push("noise_file");
        let noise = NoiseFile::new(noise_file.into());
        noise.generate().await.unwrap();
        let n1 = noise.read_secret().await.unwrap();
        let n2 = noise.read_secret().await.unwrap();
        assert_eq!(n1, n2);
        noise.zeroize().await.unwrap();
        let n2 = noise.read_secret().await.unwrap();
        assert_ne!(n1, n2);
    }
}
