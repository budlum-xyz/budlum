use crate::chain::chain_actor::ChainHandle;
use crate::network::node::NodeClient;
use crate::storage::content_id::ContentId;
use crate::storage::db::Storage;

/// B.U.D. Universal Gateway.
/// Resolves a BNS name (.bud) to content stored in B.U.D.
///
/// Bitswap + ContentDiscovery P2P fetch entegre edildi.
pub const MAX_GATEWAY_CONTENT_BYTES: usize = 10 * 1024 * 1024;

fn checked_gateway_content(source: &str, data: Vec<u8>) -> Result<Vec<u8>, String> {
    if data.len() > MAX_GATEWAY_CONTENT_BYTES {
        return Err(format!(
            "gateway content from {source} exceeds {} bytes",
            MAX_GATEWAY_CONTENT_BYTES
        ));
    }
    Ok(data)
}

pub struct BudGateway {
    chain: ChainHandle,
    network: Option<NodeClient>,
    storage: Option<Storage>,
}

impl BudGateway {
    pub fn new(chain: ChainHandle, network: Option<NodeClient>, storage: Option<Storage>) -> Self {
        Self {
            chain,
            network,
            storage,
        }
    }

    /// Primary entry point for D-Web resolution.
    /// Name: "ayaz.bud" → Returns raw bytes (HTML/Media).
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

        // Storage_root zaten 32-bayt content anahtarı - ContentId tuple-wrap yeterli.
        let cid = ContentId(storage_root);

        // 3. Local storage lookup (cached content). NOT: Storage::get_content
        //    Bugün stub (kapsamı: blob store henüz yok) - bu dal
        //    Doğal olarak ıskalar, NotFound dönüşü P2P hatasına düşer.
        if let Some(ref storage) = self.storage {
            if let Ok(chunk) = storage.get_content(&cid) {
                return checked_gateway_content("local sled storage", chunk);
            }
        }

        // 4. Node-local B.U.D. fetch through the running network stack.
        // This is not a full remote Bitswap requester yet, but it allows the
        // Gateway to read content from the node's own BudBitswap store when the
        // RPC server is co-located with storage.
        if let Some(ref network) = self.network {
            if let Ok(chunk) = network.fetch_local_content(cid.0).await {
                return checked_gateway_content("node-local B.U.D. store", chunk);
            }
        }

        // 5. Remote P2P Bitswap requester. If the content is not available locally,
        // We query connected remote peers over the network.
        if let Some(ref network) = self.network {
            if let Ok(chunk) = network.fetch_remote_content(cid.0).await {
                return checked_gateway_content("remote P2P peer", chunk);
            }
        }

        Err(format!(
            "Content {}:{} not available in local storage, local B.U.D. store, or remote P2P peers.",
            hex::encode(&storage_root[..8]),
            resolved
                .content_id
                .map(|c| hex::encode(&c.as_bytes()[..4]))
                .unwrap_or_else(|| "none".to_string())
        ))
    }
}
