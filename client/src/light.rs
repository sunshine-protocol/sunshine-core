use crate::node::NodeConfig;
use anyhow::Result;
use sled::transaction::TransactionError;
use sled::Tree;
use sp_database::error::DatabaseError;
use sp_database::{Change, Database, Transaction};
use std::path::Path;
use std::sync::Arc;
use substrate_subxt::client::{
    DatabaseConfig, KeystoreConfig, Role, SubxtClient, SubxtClientConfig,
};
use thiserror::Error;

#[derive(Debug, Error)]
#[error("{0}")]
pub struct ServiceError(String);

pub async fn build_light_client<N: NodeConfig>(
    tree: Tree,
    chain_spec: &Path,
) -> Result<(SubxtClient, N::ChainSpec)> {
    let bytes = async_std::fs::read(chain_spec).await?;
    let chain_spec = N::chain_spec_from_json_bytes(bytes)?;
    let config = SubxtClientConfig {
        impl_name: N::impl_name(),
        impl_version: N::impl_version(),
        author: N::author(),
        copyright_start_year: N::copyright_start_year(),
        db: DatabaseConfig::Custom(Arc::new(SubstrateDb(tree))),
        keystore: KeystoreConfig::InMemory,
        role: Role::Light,
        chain_spec: chain_spec.clone(),
        enable_telemetry: true,
    }
    .to_service_config();
    let (task_manager, rpc) = N::new_light(config).map_err(|e| ServiceError(format!("{}", e)))?;
    Ok((SubxtClient::new(task_manager, rpc), chain_spec))
}

struct Key;

impl Key {
    pub fn key(col: u32, key: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 4 + key.len());
        buf.push(0);
        buf.extend_from_slice(&col.to_be_bytes());
        buf.extend_from_slice(key);
        buf
    }

    pub fn hash_key(hash: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + hash.len());
        buf.push(1);
        buf.extend_from_slice(hash);
        buf
    }
}

struct SubstrateDb(Tree);

impl<H> Database<H> for SubstrateDb
where
    H: Clone + Send + Sync + Eq + PartialEq + Default + AsRef<[u8]>,
{
    fn commit(&self, transaction: Transaction<H>) -> Result<(), DatabaseError> {
        let changes = &transaction.0;
        self.0
            .transaction::<_, _, TransactionError>(|tree| {
                for change in changes.iter() {
                    match change {
                        Change::Set(col, key, value) => {
                            tree.insert(Key::key(*col, key), value.as_slice())?;
                        }
                        Change::Remove(col, key) => {
                            tree.remove(Key::key(*col, key))?;
                        }
                        Change::Store(hash, preimage) => {
                            tree.insert(Key::hash_key(hash.as_ref()), preimage.as_slice())?;
                        }
                        Change::Release(hash) => {
                            tree.remove(Key::hash_key(hash.as_ref()))?;
                        }
                    }
                }
                Ok(())
            })
            .map_err(|err| DatabaseError(Box::new(err)))
    }

    fn get(&self, col: u32, key: &[u8]) -> Option<Vec<u8>> {
        self.0
            .get(Key::key(col, key))
            .ok()
            .unwrap_or_default()
            .map(|ivec| ivec.to_vec())
    }

    fn lookup(&self, hash: &H) -> Option<Vec<u8>> {
        self.0
            .get(Key::hash_key(hash.as_ref()))
            .ok()
            .unwrap_or_default()
            .map(|ivec| ivec.to_vec())
    }
}
