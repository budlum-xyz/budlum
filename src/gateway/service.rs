use crate::chain::chain_actor::ChainHandle;
use crate::storage::db::Storage;

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
        let _cid = self.chain.bns_resolve_content(name.to_string()).await
            .ok_or_else(|| format!("BNS name '{}' not linked to any content", name))?;

        // 2. B.U.D. storage content lookup is not yet wired to the local Storage
        //    database. Once Bitswap + ContentStore integration is complete, this
        //    will fetch from local disk or request from the P2P network.
        //    For now, return a clear error indicating the integration is pending.
        Err("Content not found: B.U.D. storage content lookup pending Bitswap integration.".into())
    }
}
