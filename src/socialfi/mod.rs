//! The SocialFi module - the categorisation rename from `src/nft` to
//! `src/socialfi` (scope_v1). Only the module path changed; the RPC method
//! strings and the types are the same, so nothing public broke.
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
        // The counter saturates at the terminal id instead of wrapping: at
        // `u64::MAX` the increment stays put, the terminal id remains live
        // in `nfts`, and the duplicate check above refuses every further
        // mint. A wrapping counter would have re-offered burned ids. The
        // exhaustion check sits on the duplicate guard, so no registry
        // mutation can happen that the increment then fails to describe.
        self.next_id = self.next_id.saturating_add(1);
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
        // Clamp to u64::MAX. This used to be an `as u64` truncation, which
        // overflowed silently on a large delta_mcd.
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

        // Update ownership map. An owner whose list becomes empty loses the
        // entry itself: keeping it would grow snapshots and state roots with
        // owners that hold nothing.
        if let Some(list) = self.ownership.get_mut(from) {
            list.retain(|&x| x != id);
            if list.is_empty() {
                self.ownership.remove(from);
            }
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

        // Remove from everywhere; an emptied ownership list drops its key
        // for the same reason `transfer` drops it.
        self.nfts.remove(&id);
        if let Some(list) = self.ownership.get_mut(owner) {
            list.retain(|&x| x != id);
            if list.is_empty() {
                self.ownership.remove(owner);
            }
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
        // V6: collections carry their counts, the record commits its own
        // id next to the map key, and the tag list is counted, so the
        // stream has one parse.
        //
        // Migration policy: see `BnsRegistry::root` (BDLM_BNS_REGISTRY_V2)
        // for the shared rule - the V-bumped roots activate with the USL
        // genesis, there is no pre-launch mainnet state to migrate, and a
        // post-launch bump needs its migration recorded in the same commit.
        hasher.update(b"BDLM_NFT_REGISTRY_V6");
        hasher.update(self.next_id.to_le_bytes());
        hasher.update((self.nfts.len() as u64).to_le_bytes());
        for (id, nft) in &self.nfts {
            hasher.update(id.to_le_bytes());
            hasher.update(nft.id.to_le_bytes());
            hasher.update(nft.owner.0);
            hasher.update(nft.content_id.0);
            hasher.update(nft.luminance.to_le_bytes());
            hasher.update(nft.minted_at_epoch.to_le_bytes());
            // Security review (MEDIUM): a length-unprefixed metadata hash
            // produced ambiguous boundaries, because the name and the label sat
            // adjacent in the byte stream. V5 adds a field marker plus a length
            // prefix, and the None/Some distinction is carried by an explicit
            // marker.
            match nft.author_name.as_ref() {
                Some(name) => {
                    hasher.update(b"name:");
                    // u64, not usize: `usize::to_le_bytes` is four bytes on
                    // a 32-bit target and eight on a 64-bit one, so the two
                    // would hash different roots for the same registry.
                    hasher.update((name.len() as u64).to_le_bytes());
                    hasher.update(name.as_bytes());
                }
                None => hasher.update(b"noname"),
            }
            hasher.update((nft.tags.len() as u64).to_le_bytes());
            for tag in &nft.tags {
                hasher.update(b"tag:");
                hasher.update((tag.len() as u64).to_le_bytes());
                hasher.update(tag.as_bytes());
            }
        }
        hasher.update((self.ownership.len() as u64).to_le_bytes());
        for (owner, ids) in &self.ownership {
            hasher.update(owner.0);
            hasher.update((ids.len() as u64).to_le_bytes());
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

    /// An owner whose last NFT leaves them drops out of the ownership map
    /// entirely; the map never carries an owner with an empty id list.
    #[test]
    fn emptied_ownership_entries_are_removed() {
        let mut reg = NftRegistry::new();
        let alice = Address::from([1u8; 32]);
        let bob = Address::from([2u8; 32]);
        let cid = crate::storage::content_id::ContentId([0xCD; 32]);
        let id = reg.mint(alice, cid, 0, None).expect("mint");
        reg.transfer(id, &alice, bob).expect("transfer");
        assert!(
            !reg.ownership.contains_key(&alice),
            "transfer emptied alice"
        );
        reg.burn(id, &bob).expect("burn");
        assert!(!reg.ownership.contains_key(&bob), "burn emptied bob");
        assert!(reg.ownership.is_empty());
    }

    /// The mint counter saturates at the terminal id: the id itself mints,
    /// the registry stays consistent, and the next mint is refused instead
    /// of wrapping to a reused id.
    #[test]
    fn the_terminal_id_mints_once_and_then_refuses() {
        let mut reg = NftRegistry::new();
        let owner = Address::from([1u8; 32]);
        let cid = crate::storage::content_id::ContentId([0xCD; 32]);
        reg.next_id = u64::MAX;
        let id = reg
            .mint(owner, cid, 0, None)
            .expect("the terminal id mints");
        assert_eq!(id, u64::MAX);
        assert_eq!(
            reg.next_id,
            u64::MAX,
            "the counter saturates, it does not wrap"
        );
        let err = reg
            .mint(owner, cid, 0, None)
            .expect_err("a second mint is refused");
        assert!(matches!(err, NftError::DuplicateId));
    }

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

    /// The ownership section commits each owner's id count, so ids cannot
    /// move between two owners without moving the root; and a record's own
    /// `id` is committed next to its map key.
    #[test]
    fn root_distinguishes_ownership_boundaries() {
        let alice = Address::from([1u8; 32]);
        let bob = Address::from([2u8; 32]);
        let cid = crate::storage::content_id::ContentId([0xCD; 32]);
        let mut a = NftRegistry::new();
        let first = a.mint(alice, cid, 0, None).unwrap();
        let second = a.mint(alice, cid, 0, None).unwrap();
        a.mint(bob, cid, 0, None).unwrap();
        let mut b = a.clone();
        // Same ids, same owners in the map, but the ownership vectors are
        // rearranged so the concatenated id bytes stay identical.
        b.ownership.insert(alice, vec![first]);
        b.ownership.insert(bob, vec![second, 2]);
        assert_ne!(a.root(), b.root(), "id counts per owner are committed");

        let mut c = a.clone();
        c.nfts.get_mut(&first).unwrap().id = 99;
        assert_ne!(a.root(), c.root(), "the record's own id is committed");
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
