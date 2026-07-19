//! SocialFi modulu — Phase 10 kategorizasyonu (C1): src/nft -> src/socialfi
//! rename'i (kullanici: scope_v1). Yalniz modul yolu degisti; RPC method
//! string'leri ve tipler ayni (kamusal kirilma yok).
pub mod types;

use crate::core::address::Address;
pub use crate::socialfi::types::{Nft, NftError};
use crate::storage::content_id::ContentId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NftRegistry {
    /// id -> nft
    pub nfts: BTreeMap<u64, Nft>,
    /// owner -> set of nft_ids
    pub ownership: BTreeMap<Address, Vec<u64>>,
    pub next_id: u64,
}

impl NftRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mint(
        &mut self,
        owner: Address,
        cid: ContentId,
        epoch: u64,
        name: Option<String>,
    ) -> u64 {
        let id = self.next_id;
        let nft = Nft {
            id,
            owner,
            content_id: cid,
            minted_at_epoch: epoch,
            author_name: name,
            luminance: 1000, // B04: Starts with 1 cd
            tags: Vec::new(),
        };
        self.nfts.insert(id, nft);
        self.ownership.entry(owner).or_default().push(id);
        self.next_id += 1;
        id
    }

    pub fn add_tag(&mut self, id: u64, tag: String) -> Result<(), NftError> {
        let nft = self.nfts.get_mut(&id).ok_or(NftError::NotFound)?;
        if !nft.tags.contains(&tag) {
            nft.tags.push(tag);
        }
        Ok(())
    }

    pub fn update_luminance(&mut self, id: u64, delta_mcd: i64) -> Result<(), NftError> {
        let nft = self.nfts.get_mut(&id).ok_or(NftError::NotFound)?;
        let mut new_val = nft.luminance as i128 + delta_mcd as i128;
        if new_val < 0 {
            new_val = 0;
        }
        nft.luminance = new_val as u64;
        Ok(())
    }

    pub fn transfer(&mut self, id: u64, from: &Address, to: Address) -> Result<(), NftError> {
        let nft = self.nfts.get_mut(&id).ok_or(NftError::NotFound)?;
        if &nft.owner != from {
            return Err(NftError::NotOwner);
        }

        // Update ownership map
        if let Some(list) = self.ownership.get_mut(from) {
            list.retain(|&x| x != id);
        }
        self.ownership.entry(to).or_default().push(id);

        nft.owner = to;
        Ok(())
    }

    pub fn burn(&mut self, id: u64, owner: &Address) -> Result<ContentId, NftError> {
        let nft = self.nfts.get(&id).ok_or(NftError::NotFound)?;
        if &nft.owner != owner {
            return Err(NftError::NotOwner);
        }

        let cid = nft.content_id;

        // Remove from everywhere
        self.nfts.remove(&id);
        if let Some(list) = self.ownership.get_mut(owner) {
            list.retain(|&x| x != id);
        }

        Ok(cid)
    }

    pub fn get_nft(&self, id: u64) -> Option<&Nft> {
        self.nfts.get(&id)
    }
}

impl NftRegistry {
    pub fn root(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_NFT_REGISTRY_V3"); // V23: bumped version for expanded scope
        hasher.update(self.next_id.to_le_bytes());
        for (id, nft) in &self.nfts {
            hasher.update(id.to_le_bytes());
            hasher.update(nft.owner.0);
            hasher.update(nft.content_id.0);
            hasher.update(nft.luminance.to_le_bytes());
            hasher.update(nft.minted_at_epoch.to_le_bytes()); // V23: include minted_at_epoch
            if let Some(ref name) = nft.author_name {
                hasher.update(b"name:");
                hasher.update(name.as_bytes());
            }
            for tag in &nft.tags {
                hasher.update(b"tag:");
                hasher.update(tag.as_bytes());
            }
        }
        hasher.finalize().into()
    }
}
