use crate::chain::chain_actor::ChainHandle;
use crate::storage::db::Storage;
use crate::core::address::Address;
use std::sync::Arc;

/// ADIM 6 §6.1: B.U.D. Universal Gateway.
/// Resolves a BNS name (.bud) to content stored in B.U.D.

pub struct BudGateway {
    chain: ChainHandle,
    storage: Option<Storage>,
}

impl BudGateway {
    pub fn new(chain: ChainHandle, storage: Option<Storage>) -> Self {
        Self { chain, storage }
    }

    /// Primary entry point for D-Web resolution.
    /// name: "ayaz.bud" -> Returns raw bytes (HTML/Media).
    pub async fn fetch_name_content(&self, name: &str) -> Result<Vec<u8>, String> {
        // 1. Resolve Name to CID
        let cid = self.chain.bns_resolve_content(name.to_string()).await
            .ok_or_else(|| format!("BNS name '{}' not linked to any content", name))?;

        // 2. Fetch from B.U.D. storage (local or network)
        if let Some(ref store) = self.storage {
            // Local check first
            if let Ok(data) = store.get_content(&cid) {
                return Ok(data);
            }
        }
        
        // 3. If not local, the Gateway would use Bitswap to fetch from network.
        // Placeholder for network fetch integration.
        Err("Content not found in local store. Network fetch pending implementation.".into())
    }
}
