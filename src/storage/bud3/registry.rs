//! The B.U.D. 3.0 chain state: objects, references, shares and audits.
//!
//! This is the state machine behind `StorageTx` v3. Every map is ordered, no
//! step reads a clock (windows are epochs), and every refusal leaves the
//! state unchanged, so two nodes that apply the same transactions reach the
//! same [`Bud3Registry::state_root`].
//!
//! * Dedup: the public index maps a public content digest to the live object
//!   that holds it. Registering public content that is already held stores
//!   nothing new and returns the existing commitment. Sealed content never
//!   reads or writes the public index, so dedup reveals nothing about it.
//! * References: every bound NFT adds one reference. Burning an NFT, or the
//!   expiry of the object, removes references; at zero the object's shares
//!   are released and a tombstone is written. Deletion is final.
//! * Shares: a share starts `Pending` and becomes `Confirmed` with the
//!   holder's ack. Each epoch the audit seed draws audits for confirmed
//!   shares; a valid proof inside the window marks a pass, a closed window
//!   without one marks a miss. A miss withholds the window's reward; it never
//!   slashes.
//!
//! exposed for `Executor::apply_transaction`, `Bud3RpcService`, and maintenance sweeps.

use super::content_id::{ContentId, ContentIdKind};
use super::custody::{
    audit_for, sub_block_count, Audit, CustodyProof, ProofContext, ShareRef, FULL_AUDIT_PPM,
    MOBILE_AUDIT_PPM,
};
use super::dedup_index::DedupIndex;
use super::delete::{check_same_owner_dependency, GrantShredAuth, ShredOutcome};
use super::fees::{
    distribute_object_endowment_epoch, renewal_fee_epochs, split_storage_fee,
    storage_fee_for_epochs, FeeParams, FeeRecord, ObjectEndowment, ShareRewardInput,
    PRESENCE_PPM_SCALE,
};
use super::grants::{GrantBud3Error, GrantRow};
use super::pipeline::ObjectRecord;
use super::placement::{Class, Share};
use super::segment::Segmentation;
use crate::core::hash::hash_fields_bytes;
use std::collections::{BTreeMap, BTreeSet};

/// A Full share is lost after this many missed windows in a row.
pub const FULL_MISSES_TO_LOSS: u64 = 2;
/// A Mobile share is lost after this many missed windows in a row.
pub const MOBILE_MISSES_TO_LOSS: u64 = 3;

/// The state-root tag.
pub const REGISTRY_TAG: &[u8] = b"BDLM_BUD3_REGISTRY_V1";

/// An object is named by its commitment.
pub type ObjectKey = [u8; 32];
/// A validator or account address.
pub type Address = [u8; 32];
/// An NFT id.
pub type NftId = [u8; 32];

/// The life of a share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ShareStatus {
    /// Placed, not yet acknowledged by the holder.
    Pending,
    /// The holder acknowledged it and is audited.
    Confirmed,
}

/// One share as the chain tracks it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShareState {
    /// Segment index.
    pub segment: u64,
    /// Placement.
    pub share: Share,
    /// Status.
    pub status: ShareStatus,
    /// The open audit and the last epoch a proof is accepted.
    pub open_audit: Option<(Audit, u64)>,
    /// Audits passed.
    pub passes: u64,
    /// Audits missed.
    pub misses: u64,
    /// Misses since the last pass.
    pub consecutive_misses: u64,
    /// The share is lost (missed windows or an unseen holder) and waits for
    /// repair.
    pub lost: bool,
    /// Index of the symbol root this share's symbols are under.
    pub root: usize,
}

/// A symbol root and the ESI range it covers. The upload root covers ESI
/// `0..symbols_per_segment`; each repair adds one root over its new ESIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SymbolRoot {
    /// Segment index.
    pub segment: u64,
    /// The root.
    pub root: [u8; 32],
    /// First ESI under it; position = ESI - `first_esi`.
    pub first_esi: u32,
    /// Symbols under it.
    pub count: u32,
}

/// One object.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ObjectEntry {
    /// The record the uploader registered.
    pub record: ObjectRecord,
    /// The uploader.
    pub owner: Address,
    /// Bound NFTs.
    pub references: BTreeSet<NftId>,
    /// The last epoch the object is paid for.
    pub expires_at: u64,
    /// Every share of every segment.
    pub shares: Vec<ShareState>,
    /// The upload roots, then the repair roots.
    pub roots: Vec<SymbolRoot>,
    /// Per segment, the next ESI never yet used. Repair takes new ESIs from
    /// here, so a lost ESI is never produced twice.
    pub next_esi: Vec<u32>,
    /// Custody Endowment accounting for this object.
    #[serde(default)]
    pub endowment: ObjectEndowment,
}

/// Audit windows and probabilities, in epochs and ppm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditParams {
    /// Full window, in epochs.
    pub full_window: u64,
    /// Mobile window, in epochs (24 hours converted to epochs).
    pub mobile_window: u64,
    /// Full audit probability.
    pub full_ppm: u32,
    /// Mobile audit probability.
    pub mobile_ppm: u32,
}

impl AuditParams {
    /// TESTNET-DEFAULT values; `mobile_window` assumes one-hour epochs.
    pub const TESTNET_DEFAULT: Self = Self {
        full_window: 2,
        mobile_window: 24,
        full_ppm: FULL_AUDIT_PPM,
        mobile_ppm: MOBILE_AUDIT_PPM,
    };

    /// Convert an hour window to epochs: `ceil(hours x 3600 / (slot x epoch))`.
    #[must_use]
    pub const fn hours_to_epochs(hours: u64, slot_secs: u64, epoch_slots: u64) -> u64 {
        let per = slot_secs.saturating_mul(epoch_slots);
        if per == 0 {
            return u64::MAX;
        }
        (hours.saturating_mul(3600)).div_ceil(per)
    }
}

/// Why a storage transaction was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// The record is malformed (segment count, roots, lengths).
    BadRecord(&'static str),
    /// The placement does not give distinct ESIs covering `k + 2`.
    BadPlacement(&'static str),
    /// No such object.
    UnknownObject,
    /// The object was deleted.
    Tombstoned,
    /// No such NFT reference.
    UnknownNft,
    /// The NFT is already bound.
    NftAlreadyBound,
    /// The signer is not the one this transaction needs.
    NotAuthorized,
    /// A lifetime of zero, or one that overflows.
    BadLifetime,
    /// The validator declined this content.
    Declined,
    /// The proof answers no open audit, or fails.
    BadProof,
    /// The segment needs no repair, or the repair does not replace the loss.
    BadRepair(&'static str),
    /// The codec is not open: an object carrying it could never produce its
    /// content again on the viewer's device.
    CodecNotOpen(u16),
    /// View-grant issuance or revocation failed validation.
    Grant(GrantBud3Error),
    /// A dependent delta or derived object attempted cross-owner base binding.
    CrossOwnerDependency,
    /// A base object still has live dependent objects and must be detached first.
    HasDependents,
    /// Object replacement failed `ContentId` or placement-group attestation checks.
    BadReplacement(super::replace::ReplaceError),
    /// Mobile custody quota outside `[mobile_quota_min_bytes, mobile_quota_max_bytes]`.
    BadQuota(super::limits::LimitError),
}

impl From<GrantBud3Error> for RegistryError {
    fn from(e: GrantBud3Error) -> Self {
        Self::Grant(e)
    }
}

/// An RPC read of the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bud3Query {
    /// One object by commitment.
    Object(ObjectKey),
    /// The shares one validator holds.
    Custody(Address),
    /// One unlinkable view grant by `grant_tag`.
    Grant([u8; 32]),
}

/// What a registration did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registered {
    /// A new object was stored.
    New(ObjectKey),
    /// The public content is already held; nothing new was stored.
    Deduplicated(ObjectKey),
}

/// The registry. It serializes as flat lists, so a JSON snapshot (which
/// cannot key a map by a byte array) carries it.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(from = "FlatRegistry", into = "FlatRegistry")]
pub struct Bud3Registry {
    objects: BTreeMap<ObjectKey, ObjectEntry>,
    /// Content digest to the live object holding it. Lookups run through the
    /// node-local filter in front of it (the dedup index module).
    public_index: DedupIndex,
    nfts: BTreeMap<NftId, (ObjectKey, Address)>,
    tombstones: BTreeMap<ObjectKey, u64>,
    declines: BTreeSet<([u8; 32], Address)>,
    custody_credits: BTreeMap<Address, u64>,
    presence_ppm: BTreeMap<Address, u32>,
    forfeited_pool_total: u64,
    grants: BTreeMap<[u8; 32], GrantRow>,
    revoked_grants: BTreeSet<[u8; 32]>,
    base_deps: BTreeMap<ObjectKey, BTreeSet<ObjectKey>>,
    validator_quotas: BTreeMap<Address, u64>,
}

/// The serialized form of [`Bud3Registry`].
#[derive(serde::Serialize, serde::Deserialize)]
struct FlatRegistry {
    objects: Vec<(ObjectKey, ObjectEntry)>,
    public_index: Vec<([u8; 32], ObjectKey)>,
    nfts: Vec<(NftId, (ObjectKey, Address))>,
    tombstones: Vec<(ObjectKey, u64)>,
    declines: Vec<([u8; 32], Address)>,
    #[serde(default)]
    custody_credits: Vec<(Address, u64)>,
    #[serde(default)]
    presence_ppm: Vec<(Address, u32)>,
    #[serde(default)]
    forfeited_pool_total: u64,
    #[serde(default)]
    grants: Vec<([u8; 32], GrantRow)>,
    #[serde(default)]
    revoked_grants: Vec<[u8; 32]>,
    #[serde(default)]
    base_deps: Vec<(ObjectKey, Vec<ObjectKey>)>,
    #[serde(default)]
    validator_quotas: Vec<(Address, u64)>,
}

impl From<Bud3Registry> for FlatRegistry {
    fn from(r: Bud3Registry) -> Self {
        Self {
            objects: r.objects.into_iter().collect(),
            public_index: r.public_index.into_iter().collect(),
            nfts: r.nfts.into_iter().collect(),
            tombstones: r.tombstones.into_iter().collect(),
            declines: r.declines.into_iter().collect(),
            custody_credits: r.custody_credits.into_iter().collect(),
            presence_ppm: r.presence_ppm.into_iter().collect(),
            forfeited_pool_total: r.forfeited_pool_total,
            grants: r.grants.into_iter().collect(),
            revoked_grants: r.revoked_grants.into_iter().collect(),
            base_deps: r
                .base_deps
                .into_iter()
                .map(|(k, set)| (k, set.into_iter().collect()))
                .collect(),
            validator_quotas: r.validator_quotas.into_iter().collect(),
        }
    }
}

impl From<FlatRegistry> for Bud3Registry {
    fn from(f: FlatRegistry) -> Self {
        Self {
            objects: f.objects.into_iter().collect(),
            public_index: f.public_index.into_iter().collect(),
            nfts: f.nfts.into_iter().collect(),
            tombstones: f.tombstones.into_iter().collect(),
            declines: f.declines.into_iter().collect(),
            custody_credits: f.custody_credits.into_iter().collect(),
            presence_ppm: f.presence_ppm.into_iter().collect(),
            forfeited_pool_total: f.forfeited_pool_total,
            grants: f.grants.into_iter().collect(),
            revoked_grants: f.revoked_grants.into_iter().collect(),
            base_deps: f
                .base_deps
                .into_iter()
                .map(|(k, v)| (k, v.into_iter().collect()))
                .collect(),
            validator_quotas: f.validator_quotas.into_iter().collect(),
        }
    }
}

fn check_placement(record: &ObjectRecord, shares: &[(u64, Share)]) -> Result<(), RegistryError> {
    let seg = Segmentation::new(record.object_len, &record.profile)
        .ok_or(RegistryError::BadRecord("profile"))?;
    if record.symbol_roots.len() as u64 != seg.count() {
        return Err(RegistryError::BadRecord("one symbol root per segment"));
    }
    for index in 0..seg.count() {
        let k = seg
            .source_symbols(index)
            .ok_or(RegistryError::BadRecord("segment"))?;
        if u64::from(record.symbols_per_segment) < k + 2 {
            return Err(RegistryError::BadPlacement("fewer than k + 2 symbols"));
        }
        let mut ranges: Vec<(u32, u32)> = shares
            .iter()
            .filter(|(s, _)| *s == index)
            .map(|(_, sh)| (sh.first_esi, sh.symbols))
            .collect();
        ranges.sort_unstable();
        let mut next = 0u64;
        let mut covered = 0u64;
        for (first, n) in ranges {
            if n == 0 {
                return Err(RegistryError::BadPlacement("empty share"));
            }
            if u64::from(first) < next {
                return Err(RegistryError::BadPlacement("overlapping ESIs"));
            }
            next = u64::from(first) + u64::from(n);
            if next > u64::from(record.symbols_per_segment) {
                return Err(RegistryError::BadPlacement("ESI past the coded symbols"));
            }
            covered += u64::from(n);
        }
        if covered < k + 2 {
            return Err(RegistryError::BadPlacement("shares hold fewer than k + 2"));
        }
    }
    if shares.iter().any(|(s, _)| *s >= seg.count()) {
        return Err(RegistryError::BadPlacement("share of a missing segment"));
    }
    Ok(())
}

impl Bud3Registry {
    /// A live object.
    #[must_use]
    pub fn object(&self, key: &ObjectKey) -> Option<&ObjectEntry> {
        self.objects.get(key)
    }

    /// Whether `key` was deleted, and when.
    #[must_use]
    pub fn tombstone(&self, key: &ObjectKey) -> Option<u64> {
        self.tombstones.get(key).copied()
    }

    /// `RegisterObject`. Public content already held is deduplicated.
    ///
    /// # Errors
    ///
    /// [`RegistryError`] for a codec that is not open, a malformed record, a
    /// bad placement, a zero or overflowing lifetime, a tombstoned commitment,
    /// or a share on a validator that declined the content.
    pub fn register_object(
        &mut self,
        owner: Address,
        record: ObjectRecord,
        shares: Vec<(u64, Share)>,
        epoch: u64,
        lifetime_epochs: u64,
    ) -> Result<Registered, RegistryError> {
        // An object must be able to produce its content again on the
        // viewer's device. Its codec must be registered, open in the codec
        // crate and open at testnet; anything else is refused here.
        if !super::bof1::codec_is_registered(record.codec)
            || !bud_codec::is_open(record.codec)
            || !super::bof1::codec_is_open_on_testnet(record.codec)
        {
            return Err(RegistryError::CodecNotOpen(record.codec));
        }
        if lifetime_epochs == 0 {
            return Err(RegistryError::BadLifetime);
        }
        let expires_at = epoch
            .checked_add(lifetime_epochs)
            .ok_or(RegistryError::BadLifetime)?;
        let key = record.commitment;
        if self.tombstones.contains_key(&key) {
            return Err(RegistryError::Tombstoned);
        }
        let public = record.content_id.kind == ContentIdKind::Public;
        if public {
            if let Some(existing) = self.public_index.get(&record.content_id.digest) {
                return Ok(Registered::Deduplicated(*existing));
            }
        }
        if self.objects.contains_key(&key) {
            return Ok(Registered::Deduplicated(key));
        }
        check_placement(&record, &shares)?;
        let digest = record.content_id.digest;
        if shares
            .iter()
            .any(|(_, s)| self.declines.contains(&(digest, s.validator)))
        {
            return Err(RegistryError::Declined);
        }
        let fee_record = FeeRecord::from_placed_shares(&record, &shares);
        let initial_fee = storage_fee_for_epochs(
            fee_record.user_physical_bytes,
            lifetime_epochs,
            &FeeParams::TESTNET_DEFAULT,
        )
        .map_err(|_| RegistryError::BadLifetime)?;
        let endowment = ObjectEndowment::new(fee_record, split_storage_fee(initial_fee));
        let shares = shares
            .into_iter()
            .map(|(segment, share)| ShareState {
                segment,
                share,
                status: ShareStatus::Pending,
                open_audit: None,
                passes: 0,
                misses: 0,
                consecutive_misses: 0,
                lost: false,
                root: usize::try_from(segment).unwrap_or(usize::MAX),
            })
            .collect();
        let roots = record
            .symbol_roots
            .iter()
            .enumerate()
            .map(|(i, r)| SymbolRoot {
                segment: i as u64,
                root: *r,
                first_esi: 0,
                count: record.symbols_per_segment,
            })
            .collect();
        let next_esi = vec![record.symbols_per_segment; record.symbol_roots.len()];
        if public {
            self.public_index.insert(digest, key);
        }
        self.objects.insert(
            key,
            ObjectEntry {
                record,
                owner,
                references: BTreeSet::new(),
                expires_at,
                shares,
                roots,
                next_esi,
                endowment,
            },
        );
        Ok(Registered::New(key))
    }

    /// `BindNft`: one more reference to a live object.
    ///
    /// # Errors
    ///
    /// [`RegistryError::UnknownObject`], [`RegistryError::Tombstoned`] or
    /// [`RegistryError::NftAlreadyBound`].
    pub fn bind_nft(
        &mut self,
        nft: NftId,
        holder: Address,
        key: &ObjectKey,
    ) -> Result<(), RegistryError> {
        if self.nfts.contains_key(&nft) {
            return Err(RegistryError::NftAlreadyBound);
        }
        if self.tombstones.contains_key(key) {
            return Err(RegistryError::Tombstoned);
        }
        let obj = self
            .objects
            .get_mut(key)
            .ok_or(RegistryError::UnknownObject)?;
        obj.references.insert(nft);
        self.nfts.insert(nft, (*key, holder));
        Ok(())
    }

    /// The reference count of an object (bound NFTs plus same-owner dependent objects).
    #[must_use]
    pub fn refcount(&self, key: &ObjectKey) -> u64 {
        let nft_refs = self
            .objects
            .get(key)
            .map_or(0, |o| o.references.len() as u64);
        let dep_refs = self
            .base_deps
            .get(key)
            .map_or(0, |d| d.len() as u64);
        nft_refs.saturating_add(dep_refs)
    }

    fn delete(&mut self, key: &ObjectKey, epoch: u64) {
        if let Some(obj) = self.objects.remove(key) {
            // Early burn or replacement never refunds prior storage fees; any
            // undistributed balance enters the Network Security Pool.
            if obj.endowment.remaining_balance > 0 {
                self.forfeited_pool_total = self
                    .forfeited_pool_total
                    .saturating_add(obj.endowment.remaining_balance);
            }
            if obj.record.content_id.kind == ContentIdKind::Public {
                self.public_index.remove(&obj.record.content_id.digest);
            }
            for nft in obj.references {
                self.nfts.remove(&nft);
            }
            self.base_deps.remove(key);
            self.tombstones.insert(*key, epoch);
        }
    }

    /// `BurnReference`. At zero references the object is deleted. Returns
    /// whether it was.
    ///
    /// # Errors
    ///
    /// [`RegistryError::UnknownNft`], [`RegistryError::NotAuthorized`], or
    /// [`RegistryError::HasDependents`] when burning the last NFT of a base
    /// object that still has dependent delta/derived objects.
    pub fn burn_reference(
        &mut self,
        nft: &NftId,
        signer: &Address,
        epoch: u64,
    ) -> Result<bool, RegistryError> {
        let (key, holder) = *self.nfts.get(nft).ok_or(RegistryError::UnknownNft)?;
        if holder != *signer {
            return Err(RegistryError::NotAuthorized);
        }
        let has_deps = self.base_deps.get(&key).is_some_and(|d| !d.is_empty());
        let nft_count = self.objects.get(&key).map_or(0, |o| o.references.len());
        if nft_count <= 1 && has_deps {
            return Err(RegistryError::HasDependents);
        }
        self.nfts.remove(nft);
        let no_nfts = self.objects.get_mut(&key).is_some_and(|o| {
            o.references.remove(nft);
            o.references.is_empty()
        });
        let deleted = no_nfts && !has_deps;
        if deleted {
            self.delete(&key, epoch);
        }
        Ok(deleted)
    }

    /// Register a same-owner dependency (`dependent` relies on `base` via delta or crop).
    ///
    /// # Errors
    ///
    /// [`RegistryError::UnknownObject`] or [`RegistryError::CrossOwnerDependency`].
    pub fn register_dependency(
        &mut self,
        dependent: ObjectKey,
        base: ObjectKey,
    ) -> Result<(), RegistryError> {
        if dependent == base {
            return Err(RegistryError::BadRecord("self dependency"));
        }
        let dep_owner = self
            .objects
            .get(&dependent)
            .ok_or(RegistryError::UnknownObject)?
            .owner;
        let base_owner = self
            .objects
            .get(&base)
            .ok_or(RegistryError::UnknownObject)?
            .owner;
        if !check_same_owner_dependency(&dep_owner, &base_owner) {
            return Err(RegistryError::CrossOwnerDependency);
        }
        self.base_deps.entry(base).or_default().insert(dependent);
        Ok(())
    }

    /// Convenience: detach `dependent` from `base` after standalone rehydration.
    pub fn detach_dependency(&mut self, dependent: &ObjectKey, base: &ObjectKey, epoch: u64) {
        let mut remove_entry = false;
        if let Some(set) = self.base_deps.get_mut(base) {
            set.remove(dependent);
            remove_entry = set.is_empty();
        }
        if remove_entry {
            self.base_deps.remove(base);
            if self
                .objects
                .get(base)
                .is_some_and(|o| o.references.is_empty())
            {
                self.delete(base, epoch);
            }
        }
    }

    /// `IssueViewGrant`: record an unlinkable [`GrantRow`] carrying no `content_id`,
    /// `issuer`, or `grantee`.
    ///
    /// # Errors
    ///
    /// [`RegistryError::Grant`] if the tag is duplicate/revoked, expired, or has
    /// an invalid ML-DSA-65 one-time key or HPKE X-Wing (`0x647a`) package.
    pub fn issue_view_grant(&mut self, row: GrantRow, epoch: u64) -> Result<(), RegistryError> {
        if self.grants.contains_key(&row.grant_tag)
            || self.revoked_grants.contains(&row.grant_tag)
        {
            return Err(RegistryError::Grant(GrantBud3Error::DuplicateOrRevokedTag));
        }
        row.validate_for_issue(epoch)?;
        self.grants.insert(row.grant_tag, row);
        Ok(())
    }

    /// Issue a view grant through the canonical issuance path.
    pub fn issue_grant(&mut self, row: GrantRow, epoch: u64) -> Result<(), RegistryError> {
        self.issue_view_grant(row, epoch)
    }

    /// Return a grant only while it is live at `current_epoch`.
    #[must_use]
    pub fn active_grant(&self, grant_tag: &[u8; 32], current_epoch: u64) -> Option<&GrantRow> {
        self.grant_row(grant_tag)
            .filter(|row| row.expires_at_epoch > current_epoch)
    }

    /// `RevokeViewGrant`: verify the owner's one-time ML-DSA-65 signature and
    /// permanently delete the grant row and its HPKE key package.
    ///
    /// # Errors
    ///
    /// [`RegistryError::Grant`] if the grant is unknown or the signature fails.
    pub fn revoke_view_grant(
        &mut self,
        grant_tag: &[u8; 32],
        one_time_signature: &[u8],
    ) -> Result<(), RegistryError> {
        let row = self
            .grants
            .get(grant_tag)
            .ok_or(RegistryError::Grant(GrantBud3Error::UnknownGrant))?;
        row.verify_revocation(one_time_signature)?;
        self.grants.remove(grant_tag);
        self.revoked_grants.insert(*grant_tag);
        Ok(())
    }

    /// Convenience: read a live grant row by `grant_tag`; returns `None` once
    /// revoked, expired, or shredded so revoked key packages are never served.
    #[must_use]
    pub fn grant_row(&self, grant_tag: &[u8; 32]) -> Option<&GrantRow> {
        self.grants.get(grant_tag)
    }

    /// `SocialDelete`: atomically verify and shred every listed view-grant
    /// capsule (`grant_shreds`), then burn `nft`'s reference and tombstone the
    /// object if zero references remain. All checks run before any state write.
    ///
    /// # Errors
    ///
    /// [`RegistryError`] if `signer` does not own `nft`, a base dependency blocks
    /// deletion, or any grant shred authorization fails verification.
    pub fn social_delete(
        &mut self,
        nft: &NftId,
        signer: &Address,
        grant_shreds: &[GrantShredAuth],
        epoch: u64,
    ) -> Result<ShredOutcome, RegistryError> {
        let (key, holder) = *self.nfts.get(nft).ok_or(RegistryError::UnknownNft)?;
        if holder != *signer {
            return Err(RegistryError::NotAuthorized);
        }
        let has_deps = self.base_deps.get(&key).is_some_and(|d| !d.is_empty());
        let nft_count = self.objects.get(&key).map_or(0, |o| o.references.len());
        if nft_count <= 1 && has_deps {
            return Err(RegistryError::HasDependents);
        }

        let mut seen = BTreeSet::new();
        for auth in grant_shreds {
            if !seen.insert(auth.grant_tag) {
                return Err(RegistryError::Grant(GrantBud3Error::DuplicateOrRevokedTag));
            }
            let row = self
                .grants
                .get(&auth.grant_tag)
                .ok_or(RegistryError::Grant(GrantBud3Error::UnknownGrant))?;
            row.verify_revocation(&auth.one_time_signature)?;
        }

        for auth in grant_shreds {
            self.grants.remove(&auth.grant_tag);
            self.revoked_grants.insert(auth.grant_tag);
        }
        let object_deleted = self.burn_reference(nft, signer, epoch)?;
        Ok(ShredOutcome {
            object: key,
            grants_shredded: grant_shreds.len(),
            object_deleted,
        })
    }

    /// Convenience: DAO governance takedown targeting a public content digest
    /// (Section 6.8.3.5 & 6.21.6.2). Sealed content never enters `public_index`
    /// and cannot be targeted here.
    pub fn dao_delete_public_content(
        &mut self,
        public_digest: &[u8; 32],
        epoch: u64,
    ) -> Option<ObjectKey> {
        let key = *self.public_index.get(public_digest)?;
        self.delete(&key, epoch);
        Some(key)
    }

    /// `RenewObject`: anyone may extend the paid lifetime.
    ///
    /// # Errors
    ///
    /// [`RegistryError::UnknownObject`] or [`RegistryError::BadLifetime`].
    pub fn renew(&mut self, key: &ObjectKey, extra_epochs: u64) -> Result<u64, RegistryError> {
        if extra_epochs == 0 {
            return Err(RegistryError::BadLifetime);
        }
        let obj = self
            .objects
            .get_mut(key)
            .ok_or(RegistryError::UnknownObject)?;
        let new_expires = obj
            .expires_at
            .checked_add(extra_epochs)
            .ok_or(RegistryError::BadLifetime)?;
        if obj.endowment.fee_record.user_physical_bytes > 0 {
            let fee = renewal_fee_epochs(
                obj.endowment.fee_record.user_physical_bytes,
                extra_epochs,
                &FeeParams::TESTNET_DEFAULT,
            )
            .map_err(|_| RegistryError::BadLifetime)?;
            obj.endowment.deposit(split_storage_fee(fee));
        }
        obj.expires_at = new_expires;
        Ok(obj.expires_at)
    }

    /// Admit and record a Mobile validator's declared custody quota under `limits`.
    /// Convenience: exposed for Mobile validator quota updates and RPC admission.
    pub fn set_mobile_custody_quota(
        &mut self,
        validator: Address,
        quota_bytes: u64,
        limits: &super::limits::Bud3Limits,
    ) -> Result<(), RegistryError> {
        limits
            .admit_mobile_quota(quota_bytes)
            .map_err(RegistryError::BadQuota)?;
        self.validator_quotas.insert(validator, quota_bytes);
        Ok(())
    }

    /// `ReplaceObject` (Section 6.14): atomically replace `old_key` with `new_record`
    /// carrying the identical `ContentId`, verified by `>= 3` Full validators from
    /// `old_key`'s placement group. Bound NFTs re-point to `new_record.commitment`;
    /// prior fees are never refunded (`no_refund_on_replace`).
    pub fn replace_object(
        &mut self,
        proposer: (Address, u64),
        old_key: &ObjectKey,
        new_record: ObjectRecord,
        new_shares: Vec<(u64, Share)>,
        attestations: &[super::replace::ReplaceAttestation],
        epoch: u64,
    ) -> Result<ObjectKey, RegistryError> {
        let (sender, proposer_stake) = proposer;
        let old_entry = self.objects.get(old_key).ok_or(RegistryError::UnknownObject)?;
        let pg_full: BTreeSet<Address> = old_entry
            .shares
            .iter()
            .filter(|s| s.share.class == Class::Full)
            .map(|s| s.share.validator)
            .collect();
        super::replace::admit_object_replacement(
            &sender,
            &old_entry.owner,
            proposer_stake,
            &old_entry.record,
            &new_record,
            &pg_full,
            attestations,
        )
        .map_err(RegistryError::BadReplacement)?;

        let new_key = new_record.commitment;
        if self.tombstones.contains_key(&new_key) {
            return Err(RegistryError::Tombstoned);
        }
        check_placement(&new_record, &new_shares)?;

        let owner = old_entry.owner;
        let expires_at = old_entry.expires_at.max(epoch.saturating_add(1));
        let remaining_epochs = expires_at.saturating_sub(epoch).max(1);
        let refs = old_entry.references.clone();
        let digest = new_record.content_id.digest;
        let is_public = new_record.content_id.kind == ContentIdKind::Public;

        let fee_record = FeeRecord::from_placed_shares(&new_record, &new_shares);
        let new_fee = storage_fee_for_epochs(
            fee_record.user_physical_bytes,
            remaining_epochs,
            &FeeParams::TESTNET_DEFAULT,
        )
        .map_err(|_| RegistryError::BadLifetime)?;
        let endowment = ObjectEndowment::new(fee_record, split_storage_fee(new_fee));

        let shares = new_shares
            .into_iter()
            .map(|(segment, share)| ShareState {
                segment,
                share,
                status: ShareStatus::Pending,
                open_audit: None,
                passes: 0,
                misses: 0,
                consecutive_misses: 0,
                lost: false,
                root: usize::try_from(segment).unwrap_or(usize::MAX),
            })
            .collect();
        let roots = new_record
            .symbol_roots
            .iter()
            .enumerate()
            .map(|(i, r)| SymbolRoot {
                segment: i as u64,
                root: *r,
                first_esi: 0,
                count: new_record.symbols_per_segment,
            })
            .collect();
        let next_esi = vec![new_record.symbols_per_segment; new_record.symbol_roots.len()];

        // Forfeit any remaining endowment on the replaced object to the security pool
        // (never refunded) and rebind every NFT reference atomically to `new_key`.
        if let Some(removed) = self.objects.remove(old_key) {
            let forfeited = removed.endowment.remaining_balance;
            self.forfeited_pool_total = self.forfeited_pool_total.saturating_add(forfeited);
        }
        for nft in &refs {
            if let Some((bound_obj, _)) = self.nfts.get_mut(nft) {
                *bound_obj = new_key;
            }
        }
        if is_public {
            self.public_index.insert(digest, new_key);
        }
        self.tombstones.insert(*old_key, epoch);
        self.objects.insert(
            new_key,
            ObjectEntry {
                record: new_record,
                owner,
                references: refs,
                expires_at,
                shares,
                roots,
                next_esi,
                endowment,
            },
        );
        Ok(new_key)
    }

    /// Expire every object and unlinkable view grant past its paid lifetime.
    /// Returns the deleted object keys.
    pub fn expire(&mut self, epoch: u64) -> Vec<ObjectKey> {
        let expired_grants: Vec<[u8; 32]> = self
            .grants
            .iter()
            .filter(|(_, g)| g.expires_at_epoch < epoch)
            .map(|(tag, _)| *tag)
            .collect();
        for tag in expired_grants {
            self.grants.remove(&tag);
            self.revoked_grants.insert(tag);
        }
        let due: Vec<ObjectKey> = self
            .objects
            .iter()
            .filter(|(_, o)| o.expires_at < epoch)
            .map(|(k, _)| *k)
            .collect();
        for k in &due {
            self.delete(k, epoch);
        }
        due
    }

    /// `DeclineContent`: a validator refuses shares of `content`. Any existing
    /// share held by `validator` on an object with `content` enters share-loss
    /// reassignment without penalty (WP-20 item 10).
    pub fn decline(&mut self, validator: Address, content: &ContentId) {
        self.declines.insert((content.digest, validator));
        for obj in self.objects.values_mut() {
            if obj.record.content_id.digest == content.digest {
                for s in obj
                    .shares
                    .iter_mut()
                    .filter(|s| s.share.validator == validator && !s.lost)
                {
                    s.lost = true;
                    s.open_audit = None;
                }
            }
        }
    }

    /// Convenience: set `validator`'s declared custody quota in bytes.
    pub fn set_validator_quota(&mut self, validator: Address, quota_bytes: u64) {
        self.validator_quotas.insert(validator, quota_bytes);
    }

    /// Convenience: read `validator`'s declared custody quota in bytes.
    #[must_use]
    pub fn validator_quota(&self, validator: &Address) -> u64 {
        self.validator_quotas.get(validator).copied().unwrap_or(0)
    }

    /// Look up the live `ObjectKey` indexed under a public content digest.
    /// Convenience: exposed for upload-session deduplication and RPC lookup.
    #[must_use]
    pub fn public_object(&self, public_digest: &[u8; 32]) -> Option<ObjectKey> {
        self.public_index.get(public_digest).copied()
    }

    /// Whether `key` has been deleted and recorded in the tombstone map.
    /// Convenience: exposed for deletion verification and RPC inspection.
    #[must_use]
    pub fn is_tombstoned(&self, key: &ObjectKey) -> bool {
        self.tombstones.contains_key(key)
    }

    /// `ReleaseShares`: `holder` voluntarily releases its share(s) of `key`
    /// (on `segment`, or across all segments when `None`) and lowers its
    /// declared quota by `lower_quota_bytes` without any slash or penalty
    /// (WP-20 item 11). Released shares enter the share-loss reassignment path.
    ///
    /// # Errors
    ///
    /// [`RegistryError::UnknownObject`].
    pub fn release_shares(
        &mut self,
        holder: &Address,
        key: &ObjectKey,
        segment: Option<u64>,
        lower_quota_bytes: u64,
    ) -> Result<usize, RegistryError> {
        let obj = self
            .objects
            .get_mut(key)
            .ok_or(RegistryError::UnknownObject)?;
        let mut released = 0usize;
        for s in &mut obj.shares {
            let seg_matches = segment.is_none_or(|want| s.segment == want);
            if s.share.validator == *holder && seg_matches && !s.lost {
                s.lost = true;
                s.open_audit = None;
                released += 1;
            }
        }
        if lower_quota_bytes > 0 {
            let current = self.validator_quotas.get(holder).copied().unwrap_or(0);
            self.validator_quotas
                .insert(*holder, current.saturating_sub(lower_quota_bytes));
        }
        Ok(released)
    }

    /// `CustodyAck`: the holder confirms its shares of `key`. Returns how many
    /// moved from pending to confirmed.
    ///
    /// # Errors
    ///
    /// [`RegistryError::UnknownObject`].
    pub fn ack(&mut self, key: &ObjectKey, holder: &Address) -> Result<usize, RegistryError> {
        let obj = self
            .objects
            .get_mut(key)
            .ok_or(RegistryError::UnknownObject)?;
        let mut n = 0;
        for s in obj
            .shares
            .iter_mut()
            .filter(|s| s.share.validator == *holder)
        {
            if s.status == ShareStatus::Pending {
                s.status = ShareStatus::Confirmed;
                n += 1;
            }
        }
        Ok(n)
    }

    /// Open this epoch's audits from `seed`. A share with an audit still
    /// open is not drawn again. Returns the number opened.
    pub fn open_audits(&mut self, seed: &[u8; 32], epoch: u64, params: &AuditParams) -> usize {
        let mut opened = 0;
        for obj in self.objects.values_mut() {
            let subs = sub_block_count(usize::from(obj.record.profile.symbol_size));
            for s in &mut obj.shares {
                if s.status != ShareStatus::Confirmed || s.open_audit.is_some() || s.lost {
                    continue;
                }
                let Some(root) = obj.roots.get(s.root) else {
                    continue;
                };
                let (ppm, window) = match s.share.class {
                    Class::Full => (params.full_ppm, params.full_window),
                    Class::Mobile => (params.mobile_ppm, params.mobile_window),
                };
                let r = ShareRef {
                    segment: s.segment,
                    holder: s.share.validator,
                    first_position: u64::from(s.share.first_esi.saturating_sub(root.first_esi)),
                    symbols: u64::from(s.share.symbols),
                };
                if let Some(a) = audit_for(seed, &r, ppm, subs) {
                    s.open_audit = Some((a, epoch.saturating_add(window)));
                    opened += 1;
                }
            }
        }
        opened
    }

    /// Convenience: list every currently open `(object, audit, deadline_epoch)`
    /// assigned to `holder`.
    #[must_use]
    pub fn open_audits_for(
        &self,
        holder: &Address,
    ) -> Vec<(ObjectKey, super::custody::Audit, u64)> {
        let mut out = Vec::new();
        for (key, obj) in &self.objects {
            for s in &obj.shares {
                if s.share.validator == *holder && !s.lost {
                    if let Some((audit, deadline)) = s.open_audit {
                        out.push((*key, audit, deadline));
                    }
                }
            }
        }
        out
    }

    /// `CustodyProofBatch`: check each proof of `holder` against its open
    /// audit. Valid proofs mark a pass; the batch refuses as a whole if any
    /// proof is invalid, so a refused batch changes nothing.
    ///
    /// # Errors
    ///
    /// [`RegistryError::BadProof`] or [`RegistryError::UnknownObject`].
    pub fn submit_proofs(
        &mut self,
        holder: &Address,
        proofs: &[(ObjectKey, CustodyProof)],
        epoch: u64,
    ) -> Result<usize, RegistryError> {
        // Check everything first.
        let mut hits = Vec::new();
        for (key, proof) in proofs {
            let obj = self.objects.get(key).ok_or(RegistryError::UnknownObject)?;
            let idx = obj
                .shares
                .iter()
                .position(|s| {
                    s.share.validator == *holder
                        && s.segment == proof.segment
                        && s.open_audit
                            .is_some_and(|(a, last)| a.position == proof.position && epoch <= last)
                })
                .ok_or(RegistryError::BadProof)?;
            let share = obj.shares.get(idx).ok_or(RegistryError::BadProof)?;
            let (audit, _) = share.open_audit.ok_or(RegistryError::BadProof)?;
            let root = obj.roots.get(share.root).ok_or(RegistryError::BadProof)?;
            let ctx = ProofContext {
                symbol_root: root.root,
                symbol_count: u64::from(root.count),
                sub_blocks: sub_block_count(usize::from(obj.record.profile.symbol_size)),
            };
            proof
                .verify(&audit, &ctx)
                .map_err(|_| RegistryError::BadProof)?;
            if hits.contains(&(*key, idx)) {
                return Err(RegistryError::BadProof);
            }
            hits.push((*key, idx));
        }
        for (key, idx) in &hits {
            if let Some(s) = self
                .objects
                .get_mut(key)
                .and_then(|o| o.shares.get_mut(*idx))
            {
                s.open_audit = None;
                s.passes += 1;
                s.consecutive_misses = 0;
            }
        }
        Ok(hits.len())
    }

    /// Close every audit window that ended before `epoch`: each is a miss,
    /// then settle this epoch's Custody Endowment rewards across live objects.
    /// Missed windows withhold that window's reward and route it to the Network
    /// Security Pool without slashing stake. Returns the number of misses.
    pub fn close_windows(&mut self, epoch: u64) -> usize {
        let mut missed = 0;
        for obj in self.objects.values_mut() {
            for s in &mut obj.shares {
                if s.open_audit.is_some_and(|(_, last)| last < epoch) {
                    s.open_audit = None;
                    s.misses += 1;
                    s.consecutive_misses += 1;
                    missed += 1;
                    let limit = match s.share.class {
                        Class::Full => FULL_MISSES_TO_LOSS,
                        Class::Mobile => MOBILE_MISSES_TO_LOSS,
                    };
                    if s.consecutive_misses >= limit {
                        s.lost = true;
                    }
                }
            }
        }
        self.tick_endowments_at_epoch(epoch);
        missed
    }

    fn tick_endowments_at_epoch(&mut self, epoch: u64) {
        let declines = &self.declines;
        let presence = &self.presence_ppm;
        let credits = &mut self.custody_credits;
        let forfeited_total = &mut self.forfeited_pool_total;
        for obj in self.objects.values_mut() {
            if obj.endowment.remaining_balance == 0 {
                continue;
            }
            let remaining_epochs = obj.expires_at.saturating_sub(epoch).saturating_add(1);
            let symbol_size = u64::from(obj.record.profile.symbol_size);
            let digest = obj.record.content_id.digest;
            let inputs: Vec<ShareRewardInput> = obj
                .shares
                .iter()
                .map(|s| {
                    let declined = declines.contains(&(digest, s.share.validator));
                    let eligible = s.status == ShareStatus::Confirmed
                        && !s.lost
                        && !declined
                        && s.consecutive_misses == 0;
                    let presence_ppm = presence
                        .get(&s.share.validator)
                        .copied()
                        .unwrap_or(PRESENCE_PPM_SCALE);
                    ShareRewardInput {
                        validator: s.share.validator,
                        symbol_bytes: u64::from(s.share.symbols).saturating_mul(symbol_size),
                        eligible,
                        presence_ppm,
                    }
                })
                .collect();
            let settlement =
                distribute_object_endowment_epoch(&mut obj.endowment, remaining_epochs, &inputs, 0);
            for (validator, amount) in settlement.holder_payouts {
                let entry = credits.entry(validator).or_insert(0);
                *entry = entry.saturating_add(amount);
            }
            *forfeited_total =
                forfeited_total.saturating_add(settlement.forfeited_to_security_pool);
        }
    }

    /// Convenience: record a validator's observed presence ratio in parts per
    /// million (`0..=1_000_000`) for subsequent Custody Endowment ticks.
    pub fn set_validator_presence_ppm(&mut self, validator: Address, ppm: u32) {
        self.presence_ppm
            .insert(validator, ppm.min(PRESENCE_PPM_SCALE));
    }

    /// Convenience: read cumulative Custody Endowment rewards earned by `validator`.
    #[must_use]
    pub fn validator_custody_credit(&self, validator: &Address) -> u64 {
        self.custody_credits.get(validator).copied().unwrap_or(0)
    }

    /// Convenience: read cumulative Custody Endowment amounts forfeited to the
    /// Network Security Pool by missed audits, declined shares, or early burns.
    #[must_use]
    pub const fn forfeited_security_pool_total(&self) -> u64 {
        self.forfeited_pool_total
    }

    /// Mark every share of `holder` lost: the holder was unseen for its
    /// class window (one day Full, seven days Mobile). Returns how many.
    pub fn mark_unseen(&mut self, holder: &Address) -> usize {
        let mut n = 0;
        for obj in self.objects.values_mut() {
            for s in obj
                .shares
                .iter_mut()
                .filter(|s| s.share.validator == *holder)
            {
                if !s.lost {
                    s.lost = true;
                    s.open_audit = None;
                    n += 1;
                }
            }
        }
        n
    }

    /// The segments of `key` that need repair. Repair is lazy: a segment is
    /// due once its lost shares reach half its tolerance `f`, where `f` is the
    /// number of its largest shares it can lose and keep `k + 2` symbols.
    #[must_use]
    pub fn repairs_due(&self, key: &ObjectKey) -> Vec<u64> {
        let Some(obj) = self.objects.get(key) else {
            return Vec::new();
        };
        let Some(seg) = Segmentation::new(obj.record.object_len, &obj.record.profile) else {
            return Vec::new();
        };
        (0..seg.count())
            .filter(|&index| {
                let need = seg
                    .source_symbols(index)
                    .unwrap_or(u64::MAX)
                    .saturating_add(2);
                let mut sizes: Vec<u64> = obj
                    .shares
                    .iter()
                    .filter(|s| s.segment == index)
                    .map(|s| u64::from(s.share.symbols))
                    .collect();
                sizes.sort_unstable_by(|a, b| b.cmp(a));
                let total: u64 = sizes.iter().sum();
                let mut f = 0u64;
                let mut left = total;
                for sz in &sizes {
                    if left.saturating_sub(*sz) < need {
                        break;
                    }
                    left -= sz;
                    f += 1;
                }
                let lost = obj
                    .shares
                    .iter()
                    .filter(|s| s.segment == index && s.lost)
                    .count() as u64;
                lost > 0 && lost >= (f / 2).max(1)
            })
            .collect()
    }

    /// `RecordRepair`: a Full repairer decoded the segment and placed new
    /// symbols with new ESIs on new holders. The new shares start pending;
    /// the lost shares they replace stay until every new share is confirmed.
    ///
    /// # Errors
    ///
    /// [`RegistryError::BadRepair`] when the segment needs no repair, the new
    /// ESIs reuse an old one or overlap, or the new symbols do not replace
    /// the lost ones; [`RegistryError::UnknownObject`].
    pub fn record_repair(
        &mut self,
        key: &ObjectKey,
        segment: u64,
        new_shares: Vec<Share>,
        new_root: [u8; 32],
    ) -> Result<(), RegistryError> {
        if !self.repairs_due(key).contains(&segment) {
            return Err(RegistryError::BadRepair("segment needs no repair"));
        }
        let obj = self
            .objects
            .get_mut(key)
            .ok_or(RegistryError::UnknownObject)?;
        let seg_idx = usize::try_from(segment).map_err(|_| RegistryError::BadRepair("segment"))?;
        let first = *obj
            .next_esi
            .get(seg_idx)
            .ok_or(RegistryError::BadRepair("segment"))?;
        let mut sorted = new_shares.clone();
        sorted.sort_by_key(|s| s.first_esi);
        let mut next = u64::from(first);
        for s in &sorted {
            if s.symbols == 0 || u64::from(s.first_esi) != next {
                return Err(RegistryError::BadRepair(
                    "new ESIs must be fresh and contiguous",
                ));
            }
            next += u64::from(s.symbols);
        }
        if next > u64::from(super::fountain::MAX_ESI) {
            return Err(RegistryError::BadRepair("ESI range"));
        }
        let added = next - u64::from(first);
        let lost: u64 = obj
            .shares
            .iter()
            .filter(|s| s.segment == segment && s.lost)
            .map(|s| u64::from(s.share.symbols))
            .sum();
        if added < lost {
            return Err(RegistryError::BadRepair("fewer new symbols than lost"));
        }
        let count = u32::try_from(added).map_err(|_| RegistryError::BadRepair("ESI range"))?;
        obj.roots.push(SymbolRoot {
            segment,
            root: new_root,
            first_esi: first,
            count,
        });
        let root = obj.roots.len() - 1;
        for share in sorted {
            obj.shares.push(ShareState {
                segment,
                share,
                status: ShareStatus::Pending,
                open_audit: None,
                passes: 0,
                misses: 0,
                consecutive_misses: 0,
                lost: false,
                root,
            });
        }
        if let Some(n) = obj.next_esi.get_mut(seg_idx) {
            *n = first.saturating_add(count);
        }
        Ok(())
    }

    /// Drop the lost shares of every segment whose repair shares are all
    /// confirmed. Old shares never go before the new ones hold. Returns how
    /// many were dropped.
    pub fn settle_repairs(&mut self) -> usize {
        let mut dropped = 0;
        for obj in self.objects.values_mut() {
            let upload_roots = obj.record.symbol_roots.len();
            let settled: BTreeSet<u64> = obj
                .roots
                .iter()
                .enumerate()
                .skip(upload_roots)
                .filter(|(i, _)| {
                    obj.shares
                        .iter()
                        .filter(|s| s.root == *i)
                        .all(|s| s.status == ShareStatus::Confirmed)
                })
                .map(|(_, r)| r.segment)
                .collect();
            let before = obj.shares.len();
            obj.shares
                .retain(|s| !(s.lost && settled.contains(&s.segment)));
            dropped += before - obj.shares.len();
        }
        dropped
    }

    /// The RPC read: one object, or one validator's shares.
    #[must_use]
    pub fn query_json(&self, query: &Bud3Query) -> serde_json::Value {
        match query {
            Bud3Query::Object(key) => {
                if let Some(o) = self.objects.get(key) {
                    serde_json::json!({
                        "commitment": hex::encode(key),
                        "status": "live",
                        "content_digest": hex::encode(o.record.content_id.digest),
                        "content_len": o.record.content_id.len,
                        "sealed": o.record.content_id.kind == ContentIdKind::Sealed,
                        "object_len": o.record.object_len,
                        "profile": o.record.profile.id,
                        "codec": o.record.codec,
                        "codec_name": bud_codec::registry::entry(o.record.codec).map_or("unknown", |row| row.name),
                        "symbols_per_segment": o.record.symbols_per_segment,
                        "segments": o.record.symbol_roots.len(),
                        "symbol_roots": o.roots.iter().map(|r| serde_json::json!({
                            "segment": r.segment,
                            "root": hex::encode(r.root),
                            "first_esi": r.first_esi,
                            "count": r.count,
                        })).collect::<Vec<_>>(),
                        "references": o.references.len(),
                        "expires_at_epoch": o.expires_at,
                        "repairs_due": self.repairs_due(key),
                        "endowment": {
                            "user_physical_bytes": o.endowment.fee_record.user_physical_bytes,
                            "decentralization_physical_bytes": o.endowment.fee_record.decentralization_physical_bytes,
                            "total_deposited": o.endowment.total_deposited,
                            "remaining_balance": o.endowment.remaining_balance,
                            "gateway_paid": o.endowment.gateway_paid,
                            "forfeited_to_security_pool": o.endowment.forfeited_to_security_pool,
                        },
                    })
                } else if let Some(epoch) = self.tombstones.get(key) {
                    serde_json::json!({
                        "commitment": hex::encode(key),
                        "status": "deleted",
                        "deleted_at_epoch": epoch,
                    })
                } else {
                    serde_json::Value::Null
                }
            }
            Bud3Query::Custody(validator) => {
                let shares: Vec<serde_json::Value> = self
                    .objects
                    .iter()
                    .flat_map(|(k, o)| {
                        o.shares
                            .iter()
                            .filter(|s| s.share.validator == *validator)
                            .map(move |s| {
                                serde_json::json!({
                                    "commitment": hex::encode(k),
                                    "segment": s.segment,
                                    "first_esi": s.share.first_esi,
                                    "symbols": s.share.symbols,
                                    "confirmed": s.status == ShareStatus::Confirmed,
                                    "lost": s.lost,
                                    "open_audit": s.open_audit.map(|(a, last)| serde_json::json!({
                                        "position": a.position,
                                        "sub_block": a.sub_block,
                                        "last_epoch": last,
                                    })),
                                    "passes": s.passes,
                                    "misses": s.misses,
                                })
                            })
                    })
                    .collect();
                serde_json::json!({
                    "validator": hex::encode(validator),
                    "count": shares.len(),
                    "earned_custody_rewards": self.validator_custody_credit(validator),
                    "shares": shares,
                })
            }
            Bud3Query::Grant(tag) => {
                if let Some(row) = self.grants.get(tag) {
                    serde_json::json!({
                        "grant_tag": hex::encode(row.grant_tag),
                        "status": "active",
                        "one_time_pk": hex::encode(&row.one_time_pk),
                        "sealed_key_package": hex::encode(&row.sealed_key_package),
                        "expires_at_epoch": row.expires_at_epoch,
                    })
                } else if self.revoked_grants.contains(tag) {
                    serde_json::json!({
                        "grant_tag": hex::encode(tag),
                        "status": "revoked",
                    })
                } else {
                    serde_json::Value::Null
                }
            }
        }
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
            && self.tombstones.is_empty()
            && self.declines.is_empty()
            && self.custody_credits.is_empty()
            && self.presence_ppm.is_empty()
            && self.forfeited_pool_total == 0
            && self.grants.is_empty()
            && self.revoked_grants.is_empty()
            && self.base_deps.is_empty()
            && self.validator_quotas.is_empty()
    }

    /// The registry state root over every map, in order.
    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        let mut acc = hash_fields_bytes(&[REGISTRY_TAG, b"empty"]);
        let mut fold = |fields: &[&[u8]]| {
            let mut all: Vec<&[u8]> = vec![REGISTRY_TAG, &acc];
            all.extend_from_slice(fields);
            acc = hash_fields_bytes(&all);
        };
        for (k, o) in &self.objects {
            fold(&[
                b"obj",
                k,
                &o.owner,
                &o.record.content_id.digest,
                &o.record.object_len.to_le_bytes(),
                &o.expires_at.to_le_bytes(),
                &(o.references.len() as u64).to_le_bytes(),
                &o.endowment.fee_record.user_physical_bytes.to_le_bytes(),
                &o.endowment
                    .fee_record
                    .decentralization_physical_bytes
                    .to_le_bytes(),
                &o.endowment.total_deposited.to_le_bytes(),
                &o.endowment.remaining_balance.to_le_bytes(),
                &o.endowment.gateway_paid.to_le_bytes(),
                &o.endowment.forfeited_to_security_pool.to_le_bytes(),
            ]);
            for r in &o.roots {
                fold(&[
                    b"root",
                    &r.segment.to_le_bytes(),
                    &r.root,
                    &r.first_esi.to_le_bytes(),
                    &r.count.to_le_bytes(),
                ]);
            }
            for n in &o.next_esi {
                fold(&[b"next", &n.to_le_bytes()]);
            }
            for nft in &o.references {
                fold(&[b"ref", nft]);
            }
            for s in &o.shares {
                let status = [u8::from(s.status == ShareStatus::Confirmed)];
                let audit = s.open_audit.map_or([0u8; 24], |(a, last)| {
                    let mut b = [0u8; 24];
                    for (d, v) in b.iter_mut().zip(
                        a.position
                            .to_le_bytes()
                            .iter()
                            .chain(a.sub_block.to_le_bytes().iter())
                            .chain(last.to_le_bytes().iter()),
                    ) {
                        *d = *v;
                    }
                    b
                });
                fold(&[
                    b"share",
                    &s.segment.to_le_bytes(),
                    &s.share.validator,
                    &s.share.first_esi.to_le_bytes(),
                    &s.share.symbols.to_le_bytes(),
                    &status,
                    &audit,
                    &s.passes.to_le_bytes(),
                    &s.misses.to_le_bytes(),
                    &s.consecutive_misses.to_le_bytes(),
                    &[u8::from(s.lost)],
                    &(s.root as u64).to_le_bytes(),
                ]);
            }
        }
        for (k, e) in &self.tombstones {
            fold(&[b"tomb", k, &e.to_le_bytes()]);
        }
        for (d, v) in &self.declines {
            fold(&[b"decline", d, v]);
        }
        for (v, amt) in &self.custody_credits {
            fold(&[b"credit", v, &amt.to_le_bytes()]);
        }
        for (v, ppm) in &self.presence_ppm {
            fold(&[b"presence", v, &ppm.to_le_bytes()]);
        }
        if self.forfeited_pool_total > 0 {
            fold(&[b"forfeited", &self.forfeited_pool_total.to_le_bytes()]);
        }
        for (tag, row) in &self.grants {
            fold(&[
                b"grant",
                tag,
                &row.one_time_pk,
                &row.sealed_key_package,
                &row.expires_at_epoch.to_le_bytes(),
            ]);
        }
        for tag in &self.revoked_grants {
            fold(&[b"revoked_grant", tag]);
        }
        for (base, deps) in &self.base_deps {
            for dep in deps {
                fold(&[b"base_dep", base, dep]);
            }
        }
        for (validator, quota) in &self.validator_quotas {
            fold(&[b"quota", validator, &quota.to_le_bytes()]);
        }
        acc
    }
}

#[cfg(test)]
mod tests {
    use super::super::custody::prove;
    use super::super::custody::symbol_leaf;
    use super::super::limits::{Bud3Limits, Profile};
    use super::super::pipeline::{prepare_public_upload, PreparedUpload};
    use super::*;

    const P: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 128,
        fps: 10,
        k_max: 16,
    };

    fn addr(b: u8) -> Address {
        [b; 32]
    }

    /// Upload content and spread each segment's 20 symbols over four
    /// holders of five symbols.
    fn upload(content: &[u8]) -> (PreparedUpload, Vec<(u64, Share)>) {
        let up = prepare_public_upload(content, &P, &Bud3Limits::default(), 20).unwrap();
        let mut shares = Vec::new();
        for seg in 0..up.segments.len() as u64 {
            for h in 0..4u8 {
                shares.push((
                    seg,
                    Share {
                        validator: addr(10 + h),
                        class: if h == 3 { Class::Mobile } else { Class::Full },
                        first_esi: u32::from(h) * 5,
                        symbols: 5,
                    },
                ));
            }
        }
        (up, shares)
    }

    #[test]
    fn register_bind_burn_deletes_at_zero_references() {
        let mut r = Bud3Registry::default();
        let (up, shares) = upload(b"public content");
        let key = up.record.commitment;
        assert_eq!(
            r.register_object(addr(1), up.record.clone(), shares.clone(), 0, 100),
            Ok(Registered::New(key))
        );
        r.bind_nft([1; 32], addr(1), &key).unwrap();
        r.bind_nft([2; 32], addr(2), &key).unwrap();
        assert_eq!(r.refcount(&key), 2);
        assert_eq!(
            r.bind_nft([2; 32], addr(2), &key),
            Err(RegistryError::NftAlreadyBound)
        );
        assert_eq!(
            r.burn_reference(&[1; 32], &addr(2), 5),
            Err(RegistryError::NotAuthorized)
        );
        assert_eq!(r.burn_reference(&[1; 32], &addr(1), 5), Ok(false));
        assert_eq!(r.refcount(&key), 1);
        assert_eq!(r.burn_reference(&[2; 32], &addr(2), 6), Ok(true));
        assert!(r.object(&key).is_none());
        assert_eq!(r.tombstone(&key), Some(6));
        // Deletion is final.
        assert_eq!(
            r.register_object(addr(1), up.record, shares, 7, 100),
            Err(RegistryError::Tombstoned)
        );
        assert_eq!(
            r.bind_nft([3; 32], addr(1), &key),
            Err(RegistryError::Tombstoned)
        );
    }

    #[test]
    fn public_content_is_deduplicated_and_sealed_never_reads_the_index() {
        let mut r = Bud3Registry::default();
        let (up, shares) = upload(b"same bytes");
        let key = up.record.commitment;
        r.register_object(addr(1), up.record.clone(), shares.clone(), 0, 10)
            .unwrap();
        let root = r.state_root();
        // A second upload of the same public content stores nothing.
        let mut again = up.record.clone();
        again.commitment = [0xEE; 32];
        assert_eq!(
            r.register_object(addr(2), again, shares.clone(), 1, 10),
            Ok(Registered::Deduplicated(key))
        );
        assert_eq!(r.state_root(), root, "a dedup writes nothing");
        // Sealed content with the same digest bypasses the public index.
        let mut sealed = up.record;
        sealed.content_id.kind = ContentIdKind::Sealed;
        sealed.commitment = [0xDD; 32];
        assert_eq!(
            r.register_object(addr(3), sealed, shares, 1, 10),
            Ok(Registered::New([0xDD; 32]))
        );
    }

    #[test]
    fn bad_placements_and_lifetimes_are_refused_without_writing() {
        let mut r = Bud3Registry::default();
        let (up, shares) = upload(b"x");
        let empty = r.state_root();
        assert_eq!(
            r.register_object(addr(1), up.record.clone(), shares.clone(), 0, 0),
            Err(RegistryError::BadLifetime)
        );
        assert_eq!(
            r.register_object(addr(1), up.record.clone(), shares.clone(), u64::MAX, 1),
            Err(RegistryError::BadLifetime)
        );
        // One segment of k = 1 needs k + 2 = 3 symbols; one share of 2 is thin.
        let mut thin: Vec<_> = shares.iter().take(1).cloned().collect();
        thin[0].1.symbols = 2;
        assert!(matches!(
            r.register_object(addr(1), up.record.clone(), thin, 0, 10),
            Err(RegistryError::BadPlacement(_))
        ));
        let mut overlap = shares.clone();
        overlap[1].1.first_esi = 3;
        assert!(matches!(
            r.register_object(addr(1), up.record.clone(), overlap, 0, 10),
            Err(RegistryError::BadPlacement("overlapping ESIs"))
        ));
        let mut past = shares.clone();
        past[3].1.symbols = 6;
        assert!(matches!(
            r.register_object(addr(1), up.record.clone(), past, 0, 10),
            Err(RegistryError::BadPlacement(_))
        ));
        let mut roots = up.record.clone();
        roots.symbol_roots.push([0; 32]);
        assert!(matches!(
            r.register_object(addr(1), roots, shares.clone(), 0, 10),
            Err(RegistryError::BadRecord(_))
        ));
        r.decline(addr(12), &up.record.content_id);
        let after_decline = r.state_root();
        assert_eq!(
            r.register_object(addr(1), up.record, shares, 0, 10),
            Err(RegistryError::Declined)
        );
        assert_ne!(empty, after_decline);
        assert_eq!(r.state_root(), after_decline, "refusals write nothing");
    }

    #[test]
    fn expiry_and_renewal() {
        let mut r = Bud3Registry::default();
        let (up, shares) = upload(b"lease");
        let key = up.record.commitment;
        r.register_object(addr(1), up.record, shares, 0, 10)
            .unwrap();
        assert_eq!(r.renew(&key, 5), Ok(15));
        assert!(r.expire(15).is_empty());
        assert_eq!(r.expire(16), vec![key]);
        assert_eq!(r.tombstone(&key), Some(16));
        assert_eq!(r.renew(&key, 1), Err(RegistryError::UnknownObject));
    }

    #[test]
    fn audits_pass_with_a_proof_and_miss_without_one() {
        let mut r = Bud3Registry::default();
        let content: Vec<u8> = (0..5000u32).map(|i| (i % 253) as u8).collect();
        let (up, shares) = upload(&content);
        let key = up.record.commitment;
        r.register_object(addr(1), up.record.clone(), shares, 0, 1000)
            .unwrap();
        for h in 0..4u8 {
            r.ack(&key, &addr(10 + h)).unwrap();
        }
        let params = AuditParams {
            full_ppm: 1_000_000,
            mobile_ppm: 1_000_000,
            ..AuditParams::TESTNET_DEFAULT
        };
        let opened = r.open_audits(&[5; 32], 1, &params);
        assert_eq!(opened, r.object(&key).unwrap().shares.len());
        assert_eq!(
            r.open_audits(&[6; 32], 1, &params),
            0,
            "one open audit per share"
        );

        // Holder 10 answers every audit of its shares.
        let mut proofs = Vec::new();
        for s in r
            .object(&key)
            .unwrap()
            .shares
            .iter()
            .filter(|s| s.share.validator == addr(10))
        {
            let (a, _) = s.open_audit.unwrap();
            let syms = &up.segments[s.segment as usize];
            let leaves: Vec<(u32, [u8; 32])> =
                syms.iter().map(|x| (x.esi, symbol_leaf(&x.data))).collect();
            let pos = a.position as usize;
            proofs.push((
                key,
                prove(
                    s.segment,
                    &leaves,
                    pos,
                    &syms[pos].data,
                    a.sub_block as usize,
                )
                .unwrap(),
            ));
        }
        // A tampered proof refuses the whole batch.
        let mut bad = proofs.clone();
        bad[0].1.bytes[0] ^= 1;
        let before = r.state_root();
        assert_eq!(
            r.submit_proofs(&addr(10), &bad, 2),
            Err(RegistryError::BadProof)
        );
        assert_eq!(r.state_root(), before);
        // Another holder cannot answer for holder 10.
        assert_eq!(
            r.submit_proofs(&addr(11), &proofs, 2),
            Err(RegistryError::BadProof)
        );
        assert_eq!(r.submit_proofs(&addr(10), &proofs, 2), Ok(proofs.len()));

        // Full windows close after 2 epochs; Mobile after 24.
        let missed = r.close_windows(4);
        let obj = r.object(&key).unwrap();
        let full_others = obj
            .shares
            .iter()
            .filter(|s| s.share.class == Class::Full && s.share.validator != addr(10))
            .count();
        assert_eq!(missed, full_others);
        assert!(obj
            .shares
            .iter()
            .filter(|s| s.share.validator == addr(10))
            .all(|s| s.passes == 1 && s.misses == 0));
        assert!(obj
            .shares
            .iter()
            .filter(|s| s.share.class == Class::Mobile)
            .all(|s| s.open_audit.is_some()));
        let mobile = obj
            .shares
            .iter()
            .filter(|s| s.share.class == Class::Mobile)
            .count();
        assert_eq!(r.close_windows(26), mobile);
    }

    #[test]
    fn lost_shares_are_repaired_with_fresh_esis_and_old_ones_go_last() {
        use super::super::custody::symbol_root;
        use super::super::fountain::SegmentEncoder;
        let mut r = Bud3Registry::default();
        let content: Vec<u8> = (0..1500u32).map(|i| (i % 249) as u8).collect();
        let (up, shares) = upload(&content);
        let key = up.record.commitment;
        r.register_object(addr(1), up.record.clone(), shares, 0, 1000)
            .unwrap();
        for h in 0..4u8 {
            r.ack(&key, &addr(10 + h)).unwrap();
        }
        assert!(r.repairs_due(&key).is_empty());
        // k = 12 for this one-segment object; 20 symbols, four shares of 5:
        // tolerance f = 1, so one lost share is due.
        assert_eq!(r.mark_unseen(&addr(13)), 1);
        assert_eq!(r.repairs_due(&key), vec![0]);

        // The repairer decodes the segment and makes repair ESIs 20..25.
        let seg_bytes = super::super::pipeline::view_public(
            &up.record,
            up.segments.concat().into_iter().filter(|s| s.esi < 15),
        )
        .unwrap();
        assert_eq!(seg_bytes, content);
        let obj_bytes = super::super::bof1::Object::raw_public(&content).encode();
        let enc = SegmentEncoder::new(0, &obj_bytes, &P).unwrap();
        let k = enc.k();
        let fresh = enc.repair_symbols(20 - k, 5).unwrap();
        assert_eq!(fresh[0].esi, 20);
        let leaves: Vec<(u32, [u8; 32])> = fresh
            .iter()
            .map(|x| (x.esi, symbol_leaf(&x.data)))
            .collect();
        let new_root = symbol_root(&leaves);
        let new_share = Share {
            validator: addr(20),
            class: Class::Full,
            first_esi: 20,
            symbols: 5,
        };

        // Reusing a lost ESI is refused.
        let reuse = Share {
            first_esi: 15,
            ..new_share
        };
        assert!(matches!(
            r.record_repair(&key, 0, vec![reuse], new_root),
            Err(RegistryError::BadRepair(_))
        ));
        let short = Share {
            symbols: 4,
            ..new_share
        };
        assert!(matches!(
            r.record_repair(&key, 0, vec![short], new_root),
            Err(RegistryError::BadRepair("fewer new symbols than lost"))
        ));
        r.record_repair(&key, 0, vec![new_share], new_root).unwrap();
        assert_eq!(r.object(&key).unwrap().next_esi, vec![25]);

        // The lost share stays until the new one is confirmed.
        assert_eq!(r.settle_repairs(), 0);
        r.ack(&key, &addr(20)).unwrap();
        assert_eq!(r.settle_repairs(), 1);
        assert!(r.object(&key).unwrap().shares.iter().all(|s| !s.lost));
        assert!(r.repairs_due(&key).is_empty());

        // The new share is audited against the repair root.
        let params = AuditParams {
            full_ppm: 1_000_000,
            mobile_ppm: 1_000_000,
            ..AuditParams::TESTNET_DEFAULT
        };
        r.open_audits(&[8; 32], 5, &params);
        let s = r
            .object(&key)
            .unwrap()
            .shares
            .iter()
            .find(|s| s.share.validator == addr(20))
            .unwrap()
            .clone();
        let (a, _) = s.open_audit.unwrap();
        let pos = a.position as usize;
        let proof = prove(0, &leaves, pos, &fresh[pos].data, a.sub_block as usize).unwrap();
        assert_eq!(r.submit_proofs(&addr(20), &[(key, proof)], 6), Ok(1));
    }

    #[test]
    fn missed_windows_in_a_row_lose_a_share() {
        let mut r = Bud3Registry::default();
        let (up, shares) = upload(b"miss");
        let key = up.record.commitment;
        r.register_object(addr(1), up.record, shares, 0, 1000)
            .unwrap();
        r.ack(&key, &addr(10)).unwrap();
        let params = AuditParams {
            full_ppm: 1_000_000,
            ..AuditParams::TESTNET_DEFAULT
        };
        for epoch in [0u64, 10] {
            r.open_audits(&[epoch as u8; 32], epoch, &params);
            r.close_windows(epoch + 3);
        }
        let s = r
            .object(&key)
            .unwrap()
            .shares
            .iter()
            .find(|s| s.share.validator == addr(10))
            .unwrap();
        assert_eq!((s.misses, s.lost), (2, true));
    }

    #[test]
    fn hour_windows_convert_to_epochs() {
        // 24 h with 5 s slots and 720-slot epochs (one hour): 24 epochs.
        assert_eq!(AuditParams::hours_to_epochs(24, 5, 720), 24);
        // 48 h, 6 s slots, 100-slot epochs: ceil(172800 / 600) = 288.
        assert_eq!(AuditParams::hours_to_epochs(48, 6, 100), 288);
        assert_eq!(AuditParams::hours_to_epochs(1, 7, 1000), 1);
    }
}
