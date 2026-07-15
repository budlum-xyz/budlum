pub mod types;

use crate::core::address::Address;
use crate::nft::types::{Nft, NftError};
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
        };
        self.nfts.insert(id, nft);
        self.ownership.entry(owner).or_default().push(id);
        self.next_id += 1;
        id
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
