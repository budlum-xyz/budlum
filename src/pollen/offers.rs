//! Phase 5 §5.5 AI Data Marketplace — satıcı-teklifi (DataOffer) ekonomisi.
//!
//! C3 kaydı: Phase 10 kategorizasyonunda `src/marketplace` → buraya taşındı
//! (kullanıcı: mkt_migrate). Tipler davranış-değişmeden taşındı; v2
//! AccessGrant (APPROVED RFC) modeliyle birleştirme P1/P2 tasarım konusudur.

use crate::core::address::Address;
use crate::storage::content_id::ContentId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Phase 5 §5.5: AI Data Marketplace — Economic layer for user-to-AI data sales.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataOffer {
    pub id: u64,
    pub seller: Address,
    pub cid: ContentId,
    pub price: u64, // Price in $BUD
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MarketplaceRegistry {
    pub offers: BTreeMap<u64, DataOffer>,
    pub next_offer_id: u64,
}

impl MarketplaceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_offer(
        &mut self,
        seller: Address,
        cid: ContentId,
        price: u64,
    ) -> Result<u64, String> {
        if price == 0 {
            return Err("Price must be greater than zero".into());
        }
        let id = self.next_offer_id;
        let offer = DataOffer {
            id,
            seller,
            cid,
            price,
            active: true,
        };
        self.offers.insert(id, offer);
        self.next_offer_id += 1;
        Ok(id)
    }

    pub fn close_offer(&mut self, id: u64, caller: &Address) -> Result<(), String> {
        let offer = self.offers.get_mut(&id).ok_or("Offer not found")?;
        if &offer.seller != caller {
            return Err("Not the seller".into());
        }
        offer.active = false;
        Ok(())
    }

    pub fn get_offer(&self, id: u64) -> Option<&DataOffer> {
        self.offers.get(&id)
    }
}

impl MarketplaceRegistry {
    pub fn root(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_MARKETPLACE_REGISTRY_V1");
        hasher.update(self.next_offer_id.to_le_bytes());
        for (id, offer) in &self.offers {
            hasher.update(id.to_le_bytes());
            hasher.update(offer.seller.0);
            hasher.update(offer.cid.0);
            hasher.update(offer.price.to_le_bytes());
            hasher.update([offer.active as u8]);
        }
        hasher.finalize().into()
    }
}
