use clap::Clap;
use core::fmt::{Debug, Display};
use substrate_subxt::balances::{AccountData, Balances, TransferCallExt, TransferEventExt};
use substrate_subxt::sp_core::crypto::Ss58Codec;
use substrate_subxt::system::{AccountStoreExt, System};
use substrate_subxt::{Runtime, SignedExtension, SignedExtra};
use sunshine_client_utils::crypto::ss58::Ss58;
use sunshine_client_utils::{Client, Node, Result};
use thiserror::Error;

#[derive(Clone, Debug, Clap)]
pub struct WalletBalanceCommand {
    pub identifier: Option<String>,
}

impl WalletBalanceCommand {
    pub async fn exec<N: Node, C: Client<N>>(&self, client: &C) -> Result<()>
    where
        N::Runtime: System<AccountData = AccountData<u128>> + Balances,
        <N::Runtime as System>::AccountId: Ss58Codec,
    {
        let account_id: Ss58<N::Runtime> = if let Some(identifier) = &self.identifier {
            identifier.parse()?
        } else {
            Ss58(client.signer()?.account_id().clone())
        };
        let account = client.chain_client().account(&account_id.0, None).await?;
        println!("{:?}", account.data.free);
        Ok(())
    }
}

#[derive(Clone, Debug, Clap)]
pub struct WalletTransferCommand {
    pub identifier: String,
    pub amount: u128,
}

impl WalletTransferCommand {
    pub async fn exec<N: Node, C: Client<N>>(&self, client: &C) -> Result<()>
    where
        N::Runtime: Balances,
        <N::Runtime as System>::AccountId: Ss58Codec + Into<<N::Runtime as System>::Address>,
        <<<N::Runtime as Runtime>::Extra as SignedExtra<N::Runtime>>::Extra as SignedExtension>::AdditionalSigned:
            Send + Sync,
        <N::Runtime as Balances>::Balance: From<u128> + Display,
    {
        let account_id: Ss58<N::Runtime> = self.identifier.parse()?;
        let signer = client.chain_signer()?;
        let event = client
            .chain_client()
            .transfer_and_watch(&signer, &account_id.0.into(), self.amount.into())
            .await?
            .transfer()
            .map_err(|_| TransferEventDecode)?
            .ok_or(TransferEventFind)?;
        println!("transfered {} to {}", event.amount, event.to.to_string());
        Ok(())
    }
}

#[derive(Debug, Error)]
#[error("Failed to decode transfer event")]
pub struct TransferEventDecode;

#[derive(Debug, Error)]
#[error("Failed to find transfer event")]
pub struct TransferEventFind;
