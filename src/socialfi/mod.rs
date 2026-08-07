//! SocialFi modulu - kategorizasyonu: src/nft -> src/socialfi
//! Rename'i (kullanici: scope_v1). Yalniz modul yolu degisti; RPC method
//! String'leri ve tipler ayni (kamusal kirilma yok).
pub mod types;

use crate::core::address::Address;
pub use crate::socialfi::types::{Nft, NftError};
use crate::storage::content_id::ContentId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NftRegistry {
    /// Id -> nft
    pub nfts: BTreeMap<u64, Nft>,
    /// Owner -> set of nft_ids
    pub ownership: BTreeMap<Address, Vec<u64>>,
    pub next_id: u64,
}

impl NftRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint an NFT at the next free id.
    ///
    /// # Errors
    ///
    /// [`NftError::DuplicateId`] when `next_id` already names a live NFT.
    /// That variant existed and nothing ever produced it: `mint` took
    /// `self.next_id`, called `BTreeMap::insert`, and `insert` overwrites.
    /// The overwritten record is the previous owner's: their entry vanishes
    /// from `nfts` while their address keeps the id in `ownership`, so
    /// `get_nft` answers with the new owner and `burn` refuses the old one
    /// as `NotOwner`. The asset is transferred by an id collision, with no
    /// transfer transaction and no event.
    ///
    /// A counter that only ever increments cannot collide on its own, which
    /// is why this was never reached in a single run. `NftRegistry` is
    /// restored wholesale from `StateSnapshotV2`, and `nfts` and `next_id`
    /// are separate fields of that structure: a snapshot whose counter sits
    /// below its highest live id produces exactly this. Refusing here is
    /// cheap; reconciling the two after the fact is not.
    pub fn mint(
        &mut self,
        owner: Address,
        cid: ContentId,
        epoch: u64,
        name: Option<String>,
    ) -> Result<u64, NftError> {
        let id = self.next_id;
        if self.nfts.contains_key(&id) {
            return Err(NftError::DuplicateId);
        }
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
        Ok(id)
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
        // Clamp to u64::MAX - eskiden `as u64` truncate
        // Ediyordu (büyük delta_mcd değerinde sessiz overflow).
        if new_val > u64::MAX as i128 {
            new_val = u64::MAX as i128;
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
    pub fn is_empty(&self) -> bool {
        self.nfts.is_empty() && self.ownership.is_empty() && self.next_id == 0
    }

    pub fn root(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_NFT_REGISTRY_V4");
        hasher.update(self.next_id.to_le_bytes());
        for (id, nft) in &self.nfts {
            hasher.update(id.to_le_bytes());
            hasher.update(nft.owner.0);
            hasher.update(nft.content_id.0);
            hasher.update(nft.luminance.to_le_bytes());
            hasher.update(nft.minted_at_epoch.to_le_bytes());
            if let Some(ref name) = nft.author_name {
                hasher.update(b"name:");
                hasher.update(name.as_bytes());
            }
            for tag in &nft.tags {
                hasher.update(b"tag:");
                hasher.update(tag.as_bytes());
            }
        }
        for (owner, ids) in &self.ownership {
            hasher.update(owner.0);
            for id in ids {
                hasher.update(id.to_le_bytes());
            }
        }
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: luminance overflow to u64::MAX must be clamped.
    #[test]
    fn luminance_overflow_clamped() {
        let mut reg = NftRegistry::new();
        let owner = Address::from([1u8; 32]);
        let cid = crate::storage::content_id::ContentId([0xAB; 32]);
        reg.mint(owner, cid, 0, None).expect("fresh registry");
        let nft_id = 0;
        // Mint starts at luminance=1000. Seed near the top so a modest positive
        // Delta crosses u64::MAX and must clamp (not wrap/truncate).
        // Total: (u64::MAX - 1000) + 2000 = u64::MAX + 1000 > u64::MAX → clamp.
        reg.nfts.get_mut(&nft_id).unwrap().luminance = u64::MAX - 1000;
        reg.update_luminance(nft_id, 2000).unwrap();
        let nft = reg.get_nft(nft_id).unwrap();
        assert_eq!(
            nft.luminance,
            u64::MAX,
            "luminance must clamp to u64::MAX, not truncate"
        );
    }

    #[test]
    fn root_changes_when_ownership_changes() {
        let mut reg = NftRegistry::new();
        let owner = Address::from([1u8; 32]);
        let new_owner = Address::from([2u8; 32]);
        let cid = crate::storage::content_id::ContentId([0xCD; 32]);
        let id = reg
            .mint(owner, cid, 0, Some("alice".into()))
            .expect("fresh registry");
        let root_before = reg.root();
        reg.transfer(id, &owner, new_owner).unwrap();
        assert_ne!(root_before, reg.root());
    }

    /// A counter that disagrees with the map must not overwrite an NFT.
    ///
    /// `NftError::DuplicateId` existed and nothing produced it. `mint` read
    /// `self.next_id` and called `BTreeMap::insert`, which overwrites. The
    /// record replaced is the previous owner's: it disappears from `nfts`
    /// while their address keeps the id in `ownership`, so `get_nft` answers
    /// with the new owner and `burn` refuses the old one as `NotOwner`. An
    /// asset changes hands with no transfer transaction and no event.
    ///
    /// An incrementing counter cannot collide with itself, which is why a
    /// single run never reached it. `NftRegistry` is restored wholesale from
    /// `StateSnapshotV2`, where `nfts` and `next_id` are separate fields, so
    /// a snapshot whose counter sits below its highest live id produces
    /// exactly this state.
    #[test]
    fn minting_onto_a_live_id_is_refused() {
        let mut reg = NftRegistry::new();
        let first = Address::from([1u8; 32]);
        let second = Address::from([2u8; 32]);
        let cid = crate::storage::content_id::ContentId([0xAB; 32]);

        let id = reg.mint(first, cid, 0, None).expect("fresh registry");

        // The shape a restored snapshot can carry: counter behind contents.
        reg.next_id = id;

        let err = reg
            .mint(second, cid, 1, None)
            .expect_err("minting onto a live id must be refused");
        assert!(
            matches!(err, NftError::DuplicateId),
            "the refusal must name the collision, got: {err:?}"
        );

        // And the first owner still holds it. Without the refusal, `get_nft`
        // would name `second` here while `ownership` still lists the id under
        // `first`.
        assert_eq!(
            reg.get_nft(id)
                .expect("the original NFT must survive")
                .owner,
            first,
            "a refused mint must not have replaced the existing record"
        );
        reg.burn(id, &first)
            .expect("the original owner must still be able to burn it");
    }

    /// The refusal must stay narrow, or it is a ban on minting.
    #[test]
    fn consecutive_mints_still_work() {
        let mut reg = NftRegistry::new();
        let owner = Address::from([3u8; 32]);
        let cid = crate::storage::content_id::ContentId([0xCD; 32]);

        let a = reg.mint(owner, cid, 0, None).expect("first mint");
        let b = reg.mint(owner, cid, 1, None).expect("second mint");
        assert_ne!(a, b, "an incrementing counter must keep producing new ids");

        // Burning frees the map entry but not the id: the counter has moved
        // past it, so a later mint does not land there either.
        reg.burn(a, &owner).expect("owner may burn");
        let c = reg.mint(owner, cid, 2, None).expect("mint after burn");
        assert!(c > b, "ids must not be reused after a burn");
    }
}
