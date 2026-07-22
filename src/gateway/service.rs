use crate::chain::chain_actor::ChainHandle;
use crate::storage::content_id::ContentId;
use crate::storage::db::Storage;

/// Task 6 §6.1: B.U.D. Universal Gateway.
/// Resolves a BNS name (.bud) to content stored in B.U.D.
///
/// Task 8.9 (C1 fix): Bitswap + ContentDiscovery P2P fetch entegre edildi.

pub struct BudGateway {
    chain: ChainHandle,
    storage: Option<Storage>,
}

impl BudGateway {
    pub fn new(chain: ChainHandle, storage: Option<Storage>) -> Self {
        Self { chain, storage }
    }

    /// Primary entry point for D-Web resolution.
    /// name: "ayaz.bud" → Returns raw bytes (HTML/Media).
    pub async fn fetch_name_content(&self, name: &str) -> Result<Vec<u8>, String> {
        // 1. Resolve Name → BnsResolved (storage_root + content_id)
        let resolved = self
            .chain
            .bns_resolve_full(name.to_string())
            .await
            .ok_or_else(|| format!("BNS name '{name}' not found"))?;

        if resolved.is_expired {
            return Err(format!("BNS name '{name}' expired"));
        }

        // 2. Derive ContentId from storage_root
        let storage_root = resolved
            .storage_root
            .ok_or_else(|| format!("BNS name '{name}' has no storage binding"))?;

        // storage_root zaten 32-bayt content anahtarı — ContentId tuple-wrap yeterli.
        let cid = ContentId(storage_root);

        // 3. Local storage lookup (cached content). NOT: Storage::get_content
        //    bugün stub (Task 0.40 kapsamı: blob store henüz yok) — bu dal
        //    doğal olarak ıskalar, NotFound dönüşü P2P hatasına düşer.
        if let Some(ref storage) = self.storage {
            if let Ok(chunk) = storage.get_content(&cid) {
                return Ok(chunk);
            }
        }

        // 4. P2P Bitswap fetch — request from network peers.
        //    Full P2P swarm integration (ContentDiscovery + BudBitswap via
        //    bud-node crate) pending Task 9 when the monolithic Node wiring
        //    exposes Bitswap as a ChainHandle capability.
        Err(format!(
            "Content {}:{} not available locally. P2P Bitswap fetch pending Node swarm integration (Task 9).",
            hex::encode(&storage_root[..8]),
            resolved
                .content_id
                .map(|c| hex::encode(&c.as_bytes()[..4]))
                .unwrap_or_else(|| "none".to_string())
        ))
    }
}
