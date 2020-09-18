use crate::{ask_for_password, set_key};
use clap::Clap;
use sunshine_client_utils::{Client, Node, Result};

#[derive(Clone, Debug, Clap)]
pub struct KeySetCommand {
    /// Overwrite existing keys.
    #[clap(short = "f", long = "force")]
    pub force: bool,

    /// Suri.
    #[clap(long = "suri")]
    pub suri: Option<String>,

    /// Paperkey.
    #[clap(long = "paperkey")]
    pub paperkey: bool,
}

impl KeySetCommand {
    pub async fn exec<N: Node, C: Client<N>>(&self, client: &mut C) -> Result<()> {
        let account_id = set_key(client, self.paperkey, self.suri.as_deref(), self.force).await?;
        let account_id_str = account_id.to_string();
        println!("Your account id is {}", &account_id_str);
        Ok(())
    }
}

#[derive(Clone, Debug, Clap)]
pub struct KeyLockCommand;

impl KeyLockCommand {
    pub async fn exec<N: Node, C: Client<N>>(&self, client: &mut C) -> Result<()> {
        client.lock().await?;
        Ok(())
    }
}

#[derive(Clone, Debug, Clap)]
pub struct KeyUnlockCommand;

impl KeyUnlockCommand {
    pub async fn exec<N: Node, C: Client<N>>(&self, client: &mut C) -> Result<()> {
        let password = ask_for_password("Please enter your password (8+ characters):\n", 8)?;
        client.unlock(&password).await?;
        Ok(())
    }
}
