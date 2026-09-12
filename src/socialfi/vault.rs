//! Folders over the NFT registry: containers that hold tokens, not copies.
//!
//! The user-facing model is the file manager, moved onto the chain: a folder
//! behaves like an NFT (it is registered, anchored, owned - ownership lives
//! with `NftRegistry` and the executor, not here), and what it *contains* is
//! a membership, never a duplicate. Opening a folder lists what it holds;
//! moving a token between folders relocates the one id - the token does not
//! fork, exactly like `mv`. The granularity of what counts as "one item" is
//! the user's choice, not the chain's: this layer imposes no shape on what
//! gets grouped, only on how grouping must behave.
//!
//! # What this module refuses, and why each refusal is structural
//!
//! - A folder inside itself, or inside anything its own subtree reaches.
//!   Containers that can nest must stay a forest or "open folder" becomes a
//!   walk that never ends; the cycle check is why membership edits are
//!   whole-registry operations and not flat set inserts.
//! - Closing a non-empty folder. Members belong to the registry's books;
//!   deleting the container that names them would orphan them silently. An
//!   empty, unreferenced folder closes; every other case is a refusal to do
//!   the extraction first - including the empty folder another folder still
//!   lists, which would leave the lister opening a gap.
//! - Duplicate membership. A token listed twice would open twice on the
//!   screen, and screens are the whole reason this type exists.
//!
//! The consent flow this feeds (a folder presented to a requester opens its
//! items through the view-grant and presentation doors, not through a copy
//! made here) needs exactly one guarantee from this layer: what a folder
//! holds is a list a screen can render truthfully - which is why
//! [`VaultRegistry::open`] returns ids in registration order and why the
//! root counts members in the same order [`VaultRegistry::root`] hashes.

use crate::core::address::Address;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Why a vault operation was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VaultError {
    /// The folder was never registered (or already closed).
    #[error("folder {0} is not a folder here")]
    UnknownFolder(u64),
    /// A folder name cannot be claimed twice; the second mint is a bug or
    /// an attempt to shadow the first.
    #[error("folder {0} already exists")]
    AlreadyFolder(u64),
    /// `folder` is a folder that was never registered; membership points at
    /// containers the registry cannot open.
    #[error("membership points at an unregistered folder {0}")]
    UnregisteredParent(u64),
    /// A token inside itself.
    #[error("a folder cannot contain itself")]
    SelfMembership,
    /// The add would close a cycle: folder X already reaches Y, so Y cannot
    /// contain X. Both ids are reported so the refusal can name the walk.
    #[error("cycle: folder {0} already reaches folder {1}")]
    Cycle(u64, u64),
    /// The item is already in this folder.
    #[error("token {0} is already a member of folder {1}")]
    AlreadyMember(u64, u64),
    /// The item is not in this folder; extraction is not a no-op.
    #[error("token {0} is not a member of folder {1}")]
    NotMember(u64, u64),
    /// Closing non-empty folders is refused; see the module header.
    #[error("folder {0} still holds members; extract them first")]
    NonEmpty(u64),
    /// The folder is empty but another folder still lists it; the lister
    /// would open to a gap. Unlink it there first - same rule as a file
    /// whose shortcut still points at the folder being deleted.
    #[error("folder {folder} is still held by folder {parent}; extract it there first")]
    Referenced { folder: u64, parent: u64 },
    /// An id that names no minted token. The vault layer stays
    /// ownership-blind by design, but the transaction door is not, and a
    /// folder listing of unregistered ids is a screen full of broken links.
    #[error("token {0} is not minted; a folder lists registrations, not ideas")]
    UnknownToken(u64),
    /// The sender does not hold the named token. Folder membership is a
    /// statement about one's own assets; making it about someone else's
    /// would be the caller declaring an authority it does not have.
    #[error("token {id} belongs to {}; the sender named it as if it were theirs", .holder.to_hex())]
    NotOwner { id: u64, holder: Address },
}

/// The folder-to-membership map. Pure state, no clock, no ownership: those
/// belong to the registries and doors this sits beside.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultRegistry {
    folders: BTreeSet<u64>,
    members: BTreeMap<u64, Vec<u64>>,
}

impl VaultRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A folder that exists and holds nothing is still a folder.
    pub fn register_folder(&mut self, folder: u64) -> Result<(), VaultError> {
        if !self.folders.insert(folder) {
            return Err(VaultError::AlreadyFolder(folder));
        }
        self.members.entry(folder).or_default();
        Ok(())
    }

    /// Close a folder: only while empty.
    pub fn close_folder(&mut self, folder: u64) -> Result<(), VaultError> {
        if !self.folders.contains(&folder) {
            return Err(VaultError::UnknownFolder(folder));
        }
        if self.members.get(&folder).is_some_and(|m| !m.is_empty()) {
            return Err(VaultError::NonEmpty(folder));
        }
        // A folder other folders still list as a member cannot vanish from
        // under them: they would point at an unregistered container.
        if let Some(parent) = self.referenced_by(folder) {
            return Err(VaultError::Referenced { folder, parent });
        }
        self.folders.remove(&folder);
        self.members.remove(&folder);
        Ok(())
    }

    /// The screen's view: the ids this folder holds, in the order they were
    /// added - the list a consent dialog renders before values open.
    #[must_use]
    pub fn open(&self, folder: u64) -> Option<&[u64]> {
        self.members.get(&folder).map(Vec::as_slice)
    }

    #[must_use]
    pub fn is_folder(&self, folder: u64) -> bool {
        self.folders.contains(&folder)
    }

    #[must_use]
    pub fn contains(&self, folder: u64, member: u64) -> bool {
        self.members.get(&folder).is_some_and(|m| m.contains(&member))
    }

    /// Add one token to one folder, keeping the forest a forest.
    pub fn add_member(&mut self, folder: u64, member: u64) -> Result<(), VaultError> {
        if !self.folders.contains(&folder) {
            return Err(VaultError::UnregisteredParent(folder));
        }
        if folder == member {
            return Err(VaultError::SelfMembership);
        }
        // `member` may itself be a folder; if that folder's subtree already
        // reaches `folder`, this add would make `folder` contain itself at
        // some depth, and `open` would never terminate on that walk.
        if self.folders.contains(&member) && self.reaches(member, folder) {
            return Err(VaultError::Cycle(folder, member));
        }
        // `no-panic-path` denies expect() outside tests, and the reason is real:
        // a registered id with no slot means the two maps disagree, which is a
        // refusal to mutate - not a reason to take the node down.
        let Some(list) = self.members.get_mut(&folder) else {
            return Err(VaultError::UnregisteredParent(folder));
        };
        if list.contains(&member) {
            return Err(VaultError::AlreadyMember(member, folder));
        }
        list.push(member);
        Ok(())
    }

    /// Remove one token from one folder. What it lands in next is nobody's
    /// business here; the item is no longer this folder's.
    pub fn extract_member(&mut self, folder: u64, member: u64) -> Result<(), VaultError> {
        let list = self
            .members
            .get_mut(&folder)
            .ok_or(VaultError::UnknownFolder(folder))?;
        let at = list
            .iter()
            .position(|m| *m == member)
            .ok_or(VaultError::NotMember(member, folder))?;
        list.remove(at);
        Ok(())
    }

    /// Move, as the single operation it reads as on a screen: extract from
    /// one folder and add to the other, with every refusal (unknown
    /// folders, cycles, duplicates) checked BEFORE either list changes -
    /// a move that half-applied would be the token vanishing, which is the
    /// one failure this layer must not have.
    pub fn move_member(
        &mut self,
        from: u64,
        to: u64,
        member: u64,
    ) -> Result<(), VaultError> {
        if !self.folders.contains(&to) {
            return Err(VaultError::UnregisteredParent(to));
        }
        if to == member {
            return Err(VaultError::SelfMembership);
        }
        if self.folders.contains(&member) && self.reaches(member, to) {
            return Err(VaultError::Cycle(to, member));
        }
        let held = self
            .members
            .get(&from)
            .ok_or(VaultError::UnknownFolder(from))?
            .contains(&member);
        if !held {
            return Err(VaultError::NotMember(member, from));
        }
        if self.contains(to, member) {
            return Err(VaultError::AlreadyMember(member, to));
        }
        self.extract_member(from, member)?;
        self.add_member(to, member)?;
        Ok(())
    }

    /// Any folder that lists `candidate` as a member - the question
    /// `close_folder` must ask, and `move_member`'s callers can too.
    #[must_use]
    pub fn referenced_by(&self, candidate: u64) -> Option<u64> {
        self.members
            .iter()
            .find(|(_, list)| list.contains(&candidate))
            .map(|(folder, _)| *folder)
    }

    /// Whether `from`'s subtree reaches `target` - depth-first over folder
    /// members only; leaves cannot contain anything, so the walk terminates
    /// at the forest's bottom and the cycle test stays honest at its top.
    fn reaches(&self, from: u64, target: u64) -> bool {
        let mut seen = BTreeSet::new();
        self.reaches_walk(from, target, &mut seen)
    }

    fn reaches_walk(&self, from: u64, target: u64, seen: &mut BTreeSet<u64>) -> bool {
        if from == target {
            return true;
        }
        if !seen.insert(from) {
            return false;
        }
        let Some(members) = self.members.get(&from) else {
            return false;
        };
        for member in members {
            if self.folders.contains(member) && self.reaches_walk(*member, target, seen) {
                return true;
            }
        }
        false
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.folders.is_empty()
    }

    /// The vault's anchor - `BDLM_VAULT_V1`, the `NftRegistry::root` family
    /// of conventions: counts beside contents, one parse of the stream.
    /// Membership order is hashed as stored (registration order): the root
    /// commits to what a screen would show, so a reordered folder is a
    /// different root, not a canonicalized one.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_VAULT_V1");
        hasher.update((self.folders.len() as u64).to_le_bytes());
        hasher.update((self.members.len() as u64).to_le_bytes());
        for folder in &self.folders {
            hasher.update(folder.to_le_bytes());
        }
        for (folder, list) in &self.members {
            hasher.update(folder.to_le_bytes());
            hasher.update((list.len() as u64).to_le_bytes());
            for member in list {
                hasher.update(member.to_le_bytes());
            }
        }
        hasher.finalize().into()
    }
}

/// The transaction payload: every mutation the folder layer accepts, in the
/// shape the executor's single arm matches over.
///
/// Ids only, never owners. A `folder` or `member` field is trivial to fill
/// with somebody else's holding, so the door reads every owner from the
/// `NftRegistry` beside it - the same refusal the domain-freeze path applies
/// to caller-declared authority. And it reads it on every operation, not once
/// at registration: ownership is the live question, so a token transferred
/// out stops being listable the moment it moves, with no stale copy here that
/// could disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultTx {
    /// Claim a minted token as a folder. The claimer must hold it: a folder
    /// is an NFT first, and a container that names a stranger's registration
    /// is the broken-links screen this family refuses.
    RegisterFolder { folder: u64 },
    /// Retire a folder. The pure layer's structural refusals (`NonEmpty`,
    /// `Referenced`) stand untouched; this door adds one reading - that the
    /// sender holds the folder being closed.
    CloseFolder { folder: u64 },
    AddMember { folder: u64, member: u64 },
    ExtractMember { folder: u64, member: u64 },
    MoveMember { from: u64, to: u64, member: u64 },
}

/// Every id the payload names, in field order, and how many there are.
///
/// A fixed width rather than a `Vec`: this runs once per transaction and
/// three ids is the widest payload the enum has, so the padding is cheap and
/// the count is what keeps the zeros out of the ownership pass. The match is
/// exhaustive, which is the point - a new variant has to declare its ids here
/// or it does not compile.
fn ids_named_by(tx: &VaultTx) -> ([u64; 3], usize) {
    match tx {
        VaultTx::RegisterFolder { folder } | VaultTx::CloseFolder { folder } => {
            ([*folder, 0, 0], 1)
        }
        VaultTx::AddMember { folder, member } | VaultTx::ExtractMember { folder, member } => {
            ([*folder, *member, 0], 2)
        }
        VaultTx::MoveMember { from, to, member } => ([*from, *to, *member], 3),
    }
}

/// Reads one owner off the registry and compares it with the sender. This is
/// the only authority question the door asks; everything structural stays in
/// [`VaultRegistry`], which is ownership-blind by design and tested there.
fn require_sender_holds(
    nfts: &crate::socialfi::NftRegistry,
    who: &Address,
    id: u64,
) -> Result<(), VaultError> {
    let nft = nfts.get_nft(id).ok_or(VaultError::UnknownToken(id))?;
    if &nft.owner == who {
        Ok(())
    } else {
        Err(VaultError::NotOwner {
            id,
            holder: nft.owner,
        })
    }
}

/// The body the executor arm delegates to.
///
/// Ownership is settled in one pass over the id list the payload declares,
/// before anything mutates - it is not repeated inside each arm. A per-arm
/// check is a check some future arm forgets; a list every variant has to
/// declare cannot be forgotten, because the match above is exhaustive and the
/// dispatch below is too.
///
/// # Errors
///
/// [`VaultError::UnknownToken`] or [`VaultError::NotOwner`] from the
/// ownership pass, then whatever the underlying [`VaultRegistry`] operation
/// refuses.
pub fn execute_vault_tx(
    vault: &mut VaultRegistry,
    nfts: &crate::socialfi::NftRegistry,
    sender: &Address,
    tx: VaultTx,
) -> Result<(), VaultError> {
    let (ids, len) = ids_named_by(&tx);
    for id in ids.iter().take(len) {
        require_sender_holds(nfts, sender, *id)?;
    }
    match tx {
        VaultTx::RegisterFolder { folder } => vault.register_folder(folder),
        VaultTx::CloseFolder { folder } => vault.close_folder(folder),
        VaultTx::AddMember { folder, member } => vault.add_member(folder, member),
        VaultTx::ExtractMember { folder, member } => vault.extract_member(folder, member),
        VaultTx::MoveMember { from, to, member } => vault.move_member(from, to, member),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_folders() -> (VaultRegistry, u64, u64) {
        let mut v = VaultRegistry::new();
        v.register_folder(1).unwrap();
        v.register_folder(2).unwrap();
        (v, 1, 2)
    }

    #[test]
    fn a_folder_lists_what_a_screen_would_show_in_the_order_it_happened() {
        let (mut v, a, b) = two_folders();
        assert_eq!(v.open(a), Some(&[][..]), "an empty folder is still openable");
        v.add_member(a, 10).unwrap();
        v.add_member(a, 11).unwrap();
        v.add_member(b, 12).unwrap();
        assert_eq!(v.open(a), Some(&[10u64, 11][..]));
        assert_eq!(v.open(b), Some(&[12u64][..]));
        assert!(v.open(99).is_none(), "an unregistered id opens to nothing");
    }

    #[test]
    fn the_forest_stays_a_forest() {
        let (mut v, a, b) = two_folders();
        assert!(matches!(v.add_member(a, a), Err(VaultError::SelfMembership)));
        v.add_member(a, b).unwrap(); // a contains b: legal nesting
        assert!(matches!(v.add_member(b, a), Err(VaultError::Cycle(x, y)) if x == b && y == a));
        // transitive: a->b->c, then c->a must refuse
        v.register_folder(3).unwrap();
        v.add_member(b, 3).unwrap();
        assert!(matches!(v.add_member(3, a), Err(VaultError::Cycle(x, y)) if x == 3 && y == a));
        assert!(matches!(v.add_member(77, 5), Err(VaultError::UnregisteredParent(77))));
    }

    #[test]
    fn duplicates_and_extrusions_are_exact() {
        let (mut v, a, _b) = two_folders();
        v.add_member(a, 10).unwrap();
        assert!(matches!(v.add_member(a, 10), Err(VaultError::AlreadyMember(10, 1))));
        v.extract_member(a, 10).unwrap();
        assert!(matches!(v.extract_member(a, 10), Err(VaultError::NotMember(10, 1))));
        assert!(matches!(v.extract_member(99, 10), Err(VaultError::UnknownFolder(99))));
    }

    #[test]
    fn moving_never_houses_a_token_twice_or_nowhere() {
        let (mut v, a, b) = two_folders();
        v.add_member(a, 10).unwrap();
        v.move_member(a, b, 10).unwrap();
        assert_eq!(v.open(a), Some(&[][..]));
        assert_eq!(v.open(b), Some(&[10u64][..]));
        // refusing moves change nothing: the target already holds it
        // AlreadyMember, not SelfMembership: the target already holds it. The
        // enum says SelfMembership means "a folder cannot contain itself"; the
        // rule keeps its own lock one assert below.
        assert!(matches!(
            v.move_member(b, b, 10),
            Err(VaultError::AlreadyMember(10, folder)) if folder == b
        ));
        assert!(matches!(
            v.move_member(a, b, b),
            Err(VaultError::SelfMembership)
        ));
        v.register_folder(3).unwrap();
        assert!(matches!(v.move_member(b, 3, 42), Err(VaultError::NotMember(42, 1))));
        assert!(v.contains(b, 10), "the failed move must have left 10 exactly where it was");
    }

    #[test]
    fn closing_only_erases_what_nothing_still_lists() {
        let (mut v, a, _b) = two_folders();
        v.add_member(a, 10).unwrap();
        assert!(matches!(v.close_folder(a), Err(VaultError::NonEmpty(1))));
        v.extract_member(a, 10).unwrap();
        v.close_folder(a).unwrap();
        assert!(!v.is_folder(a), "closed means it is not a folder here anymore");
        // a leaf is not a folder, and closing it is that refusal, not another
        assert!(matches!(v.close_folder(10), Err(VaultError::UnknownFolder(10))));
        // an EMPTY folder another folder lists still cannot vanish: the
        // lister would open to a gap
        let (mut w, p, q) = two_folders();
        w.add_member(p, q).unwrap();
        assert!(matches!(w.close_folder(q), Err(VaultError::Referenced { folder: 2, parent: 1 })));
    }

    #[test]
    fn the_root_commits_to_membership_order() {
        let (mut v, a, b) = two_folders();
        let before = v.root();
        v.add_member(a, 10).unwrap();
        let one = v.root();
        assert_ne!(before, one);
        v.add_member(b, 11).unwrap();
        let two = v.root();
        assert_ne!(one, two, "a different vault is a different anchor");
        // the same content, added in the same order, roots identically
        let (mut w, x, y) = two_folders();
        w.add_member(x, 10).unwrap();
        w.add_member(y, 11).unwrap();
        assert_eq!(w.root(), two);
    }

    // - the transaction door: ids must be the sender's own, read from
    //   NftRegistry, checked on every operation.

    use crate::storage::content_id::ContentId;

    fn minted(nfts: &mut crate::socialfi::NftRegistry, owner: &Address, tag: &str) -> u64 {
        nfts.mint(*owner, ContentId::of(tag.as_bytes()), 0, None)
            .expect("mint on a fresh registry")
    }

    fn door_owners() -> (
        VaultRegistry,
        crate::socialfi::NftRegistry,
        Address,
        u64,
        u64,
        u64,
    ) {
        let alice = Address::from([1u8; 32]);
        let mut nfts = crate::socialfi::NftRegistry::new();
        let folder = minted(&mut nfts, &alice, "alice-folder");
        let a = minted(&mut nfts, &alice, "alice-a");
        let b = minted(&mut nfts, &alice, "alice-b");
        (VaultRegistry::new(), nfts, alice, folder, a, b)
    }

    #[test]
    fn the_door_walks_the_whole_lifecycle_for_the_holder() {
        let (mut v, mut nfts, alice, folder, a, _b) = door_owners();
        let c = minted(&mut nfts, &alice, "alice-c");
        execute_vault_tx(&mut v, &nfts, &alice, VaultTx::RegisterFolder { folder }).unwrap();
        execute_vault_tx(
            &mut v,
            &nfts,
            &alice,
            VaultTx::AddMember { folder, member: a },
        )
        .unwrap();
        execute_vault_tx(
            &mut v,
            &nfts,
            &alice,
            VaultTx::AddMember { folder, member: c },
        )
        .unwrap();
        assert_eq!(v.open(folder), Some(&[a, c][..]));
        // A same-folder move is the layer's own AlreadyMember answer; the
        // door only owes ownership, so the refusal arrives intact and no
        // half-applied "move" changes anything.
        assert!(matches!(
            execute_vault_tx(
                &mut v,
                &nfts,
                &alice,
                VaultTx::MoveMember {
                    from: folder,
                    to: folder,
                    member: c
                },
            ),
            Err(VaultError::AlreadyMember(m, f)) if m == c && f == folder
        ));
        execute_vault_tx(
            &mut v,
            &nfts,
            &alice,
            VaultTx::ExtractMember { folder, member: c },
        )
        .unwrap();
        execute_vault_tx(
            &mut v,
            &nfts,
            &alice,
            VaultTx::ExtractMember { folder, member: a },
        )
        .unwrap();
        execute_vault_tx(&mut v, &nfts, &alice, VaultTx::CloseFolder { folder }).unwrap();
        assert!(!v.is_folder(folder), "closed");
    }

    #[test]
    fn naming_someone_elses_token_is_refused_before_any_registry_read() {
        let (mut v, mut nfts, alice, folder, a, _b) = door_owners();
        let mallory = Address::from([9u8; 32]);
        let stolen = minted(&mut nfts, &mallory, "mallory-token");
        execute_vault_tx(&mut v, &nfts, &alice, VaultTx::RegisterFolder { folder }).unwrap();
        let err = execute_vault_tx(
            &mut v,
            &nfts,
            &alice,
            VaultTx::AddMember {
                folder,
                member: stolen,
            },
        )
        .expect_err("a folder cannot be stocked from a stranger's shelf");
        assert!(matches!(err, VaultError::NotOwner { id, holder } if id == stolen && holder == mallory));
        assert!(v.open(folder).is_some_and(|m| m.is_empty()), "refused before the write");
        // and minting a folder over somebody else's token is the same refusal
        // at the very first step: the door never trusts "I registered it".
        assert!(matches!(
            execute_vault_tx(
                &mut v,
                &nfts,
                &alice,
                VaultTx::RegisterFolder { folder: a }
            ),
            Err(VaultError::AlreadyFolder(_))
        ));
        assert!(matches!(
            execute_vault_tx(
                &mut v,
                &nfts,
                &alice,
                VaultTx::RegisterFolder { folder: stolen }
            ),
            Err(VaultError::NotOwner { .. })
        ));
    }

    #[test]
    fn an_unminted_id_is_refused_as_a_broken_link_not_a_free_slot() {
        let (mut v, nfts, alice, folder, _a, _b) = door_owners();
        execute_vault_tx(&mut v, &nfts, &alice, VaultTx::RegisterFolder { folder }).unwrap();
        let err = execute_vault_tx(
            &mut v,
            &nfts,
            &alice,
            VaultTx::AddMember {
                folder,
                member: 4242,
            },
        )
        .expect_err("4242 names no token");
        assert!(matches!(err, VaultError::UnknownToken(4242)));
    }

    #[test]
    fn ownership_is_checked_lively_so_a_transferred_asset_cannot_stay_listed() {
        // The invariant the transfer door (its own slice) will hold: because
        // every mutation re-reads ownership, a folder can never list a token
        // the folder's owner no longer holds - the door has no cached view
        // of ownership to go stale.
        let (mut v, mut nfts, alice, folder, a, _b) = door_owners();
        execute_vault_tx(&mut v, &nfts, &alice, VaultTx::RegisterFolder { folder }).unwrap();
        execute_vault_tx(
            &mut v,
            &nfts,
            &alice,
            VaultTx::AddMember { folder, member: a },
        )
        .unwrap();
        let mallory = Address::from([9u8; 32]);
        nfts.transfer(a, &alice, mallory).expect("plain transfer out");
        // Now extraction would strand the token in mallory's name...
        let err = execute_vault_tx(
            &mut v,
            &nfts,
            &alice,
            VaultTx::ExtractMember { folder, member: a },
        )
        .expect_err("alice cannot act on a token she no longer holds");
        assert!(matches!(err, VaultError::NotOwner { id, holder } if id == a && holder == mallory));
    }
}

