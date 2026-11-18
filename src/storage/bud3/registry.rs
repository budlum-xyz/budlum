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
    audit_for, sub_block_count, symbol_leaf, symbol_root, verify_symbol_root_path, Audit,
    CustodyProof, ProofContext, ShareRef, FULL_AUDIT_PPM, MOBILE_AUDIT_PPM,
};
use super::dedup_index::DedupIndex;
use super::delete::{check_same_owner_dependency, GrantShredAuth, ShredOutcome};
use super::fees::{
    distribute_object_endowment_epoch, renewal_fee_epochs, split_storage_fee,
    storage_fee_for_epochs, FeeParams, FeeRecord, ObjectEndowment, ShareRewardInput,
    PRESENCE_PPM_SCALE,
};
use super::fountain::{SegmentDecoder, SegmentEncoder, Symbol};
use super::grants::{GrantBud3Error, GrantRow};
use super::meter::Meter;
use super::pipeline::ObjectRecord;
use super::placement::{Class, Share};
use super::repair::{RepairWitness, MAX_REPAIR_WITNESS_SYMBOLS};
use super::segment::Segmentation;
use super::view::{PaidViewReceipt, MIN_PAID_VIEW_FEE_ATOMS, PAID_VIEW_RETENTION_EPOCHS};
use crate::core::hash::hash_fields_bytes;
use std::collections::{BTreeMap, BTreeSet};

/// A Full share is lost after this many missed windows in a row.
pub const FULL_MISSES_TO_LOSS: u64 = 2;
/// A Mobile share is lost after this many missed windows in a row.
pub const MOBILE_MISSES_TO_LOSS: u64 = 3;
/// Maximum number of bound NFT references tracked on a single B.U.D. 3.0 object.
pub const MAX_OBJECT_REFERENCES: usize = 4096;
/// Maximum concurrent unpruned paid-view receipts across the entire registry.
const MAX_PAID_VIEWS: usize = 65_536;
/// Maximum concurrent unpruned paid-view receipts tracked for one object.
const MAX_PAID_VIEWS_PER_OBJECT: usize = 1024;
/// Maximum concurrent unpruned paid-view receipts one payer may hold per object.
const MAX_PAID_VIEWS_PER_PAYER_OBJECT: usize = 8;

/// The state-root tag. V2 commits every serialized field and exact index.
pub const REGISTRY_TAG: &[u8] = b"BDLM_BUD3_REGISTRY_V2";

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
    /// Epoch when the current holder was assigned this share (for 3-epoch
    /// unacknowledged assignment handover, Section 7.6).
    #[serde(default)]
    pub assigned_epoch: u64,
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
    /// True once all initial shares of this object have confirmed custody via
    /// `ack`. Only custody-confirmed objects earn a deletion tombstone so an
    /// unconfirmed squatter cannot permanently poison a commitment.
    #[serde(default)]
    pub custody_confirmed: bool,
}

/// On-chain record of a paid G8 fallback decode authorization.
/// exposed for paid fallback-view ledger queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PaidViewRecord {
    /// Payer who funded the view.
    pub payer: Address,
    /// Target public object commitment.
    pub object: ObjectKey,
    /// Paid fee in BUD base units (`>= MIN_PAID_VIEW_FEE_ATOMS`).
    pub amount_atoms: u64,
    /// Epoch in which the payment was recorded.
    pub paid_at_epoch: u64,
}

/// One replacement of an object: a second, better representation of the same
/// content (section 6.14).
///
/// The content id never changes. The replacement only moves which object
/// carries the content: the references move at the proposal, the old shares
/// stay until every new share is confirmed, and the old commitment redirects
/// to the new one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Replacement {
    /// The object that carries the content now.
    pub new: ObjectKey,
    /// The proposer: a Full validator of the old placement group, or the
    /// owner when the content is sealed.
    pub proposer: Address,
    /// The content id. It is the same before and after.
    pub content: ContentId,
    /// The replaced object's length in bytes.
    pub old_object_len: u64,
    /// The new object's length in bytes.
    pub new_object_len: u64,
    /// The epoch the replacement was proposed in.
    pub proposed_at: u64,
    /// True once every new share is confirmed and the old shares are
    /// released. A finalized record is the redirect for the old commitment.
    pub finalized: bool,
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
    /// On-chain G8 paid fallback view payment was invalid or already recorded.
    InvalidPaidView(&'static str),
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
    /// Placement, share confirmation, and physical-byte endowment details for one object.
    Placement(ObjectKey),
    /// The shares one validator holds.
    Custody(Address),
    /// One unlinkable view grant by `grant_tag`.
    Grant([u8; 32]),
    /// One unlinkable view grant by `grant_tag` evaluated at `current_epoch`.
    GrantAt([u8; 32], u64),
    /// Resolve an NFT binding (`NftId`) to its live/replaced object metadata.
    Nft(NftId),
}

/// What a registration did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registered {
    /// A new object was stored.
    New(ObjectKey),
    /// The public content is already held; nothing new was stored.
    Deduplicated(ObjectKey),
}

/// Bundled segment repair payload passed to [`Bud3Registry::record_repair_with_validators`].
pub struct SegmentRepair<'a> {
    pub segment: u64,
    pub new_shares: Vec<Share>,
    pub new_symbols: Vec<Symbol>,
    pub new_root: [u8; 32],
    pub witness: &'a RepairWitness,
}

/// The registry. It serializes as flat lists, so a JSON snapshot (which
/// cannot key a map by a byte array) carries it.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(from = "FlatRegistry", into = "FlatRegistry")]
pub struct Bud3Registry {
    #[serde(with = "crate::core::map_keys")]
    objects: BTreeMap<ObjectKey, ObjectEntry>,
    /// Content digest to the live object holding it. Lookups run through the
    /// node-local filter in front of it (the dedup index module).
    public_index: DedupIndex,
    #[serde(with = "crate::core::map_keys")]
    nfts: BTreeMap<NftId, (ObjectKey, Address)>,
    #[serde(with = "crate::core::map_keys")]
    tombstones: BTreeMap<ObjectKey, u64>,
    declines: BTreeSet<([u8; 32], Address)>,
    custody_credits: BTreeMap<Address, u64>,
    presence_ppm: BTreeMap<Address, u32>,
    forfeited_pool_total: u64,
    #[serde(with = "crate::core::map_keys")]
    grants: BTreeMap<[u8; 32], GrantRow>,
    revoked_grants: BTreeSet<[u8; 32]>,
    #[serde(with = "crate::core::map_keys")]
    base_deps: BTreeMap<ObjectKey, BTreeSet<ObjectKey>>,
    validator_quotas: BTreeMap<Address, u64>,
    /// The old commitment to its replacement. A record stays here after it
    /// finalizes: it is the redirect the old commitment answers with.
    #[serde(with = "crate::core::map_keys")]
    replacements: BTreeMap<ObjectKey, Replacement>,
    /// Verified on-chain paid G8 fallback view receipts (`receipt_id -> record`).
    #[serde(with = "crate::core::map_keys")]
    paid_views: BTreeMap<[u8; 32], PaidViewRecord>,
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
    /// Added by the object replacement: a snapshot written before it has no
    /// replacement and reads back as an empty map.
    #[serde(default)]
    replacements: Vec<(ObjectKey, Replacement)>,
    #[serde(default)]
    paid_views: Vec<([u8; 32], PaidViewRecord)>,
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
            replacements: r.replacements.into_iter().collect(),
            paid_views: r.paid_views.into_iter().collect(),
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
            replacements: f.replacements.into_iter().collect(),
            paid_views: f.paid_views.into_iter().collect(),
        }
    }
}

/// The state a record starts with: every share pending, one upload root per
/// segment, and the next unused ESI of every segment.
fn initial_state(
    record: &ObjectRecord,
    shares: Vec<(u64, Share)>,
    epoch: u64,
) -> (Vec<ShareState>, Vec<SymbolRoot>, Vec<u32>) {
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
            assigned_epoch: epoch,
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
    (shares, roots, next_esi)
}

fn check_placement(record: &ObjectRecord, shares: &[(u64, Share)]) -> Result<(), RegistryError> {
    let seg = Segmentation::new(record.object_len, &record.profile)
        .ok_or(RegistryError::BadRecord("profile"))?;
    if record.symbol_roots.len() as u64 != seg.count() {
        return Err(RegistryError::BadRecord("one symbol root per segment"));
    }
    if record.symbol_roots.iter().any(|r| *r == [0u8; 32]) {
        return Err(RegistryError::BadRecord("zero symbol root"));
    }
    for index in 0..seg.count() {
        let k = seg
            .source_symbols(index)
            .ok_or(RegistryError::BadRecord("segment"))?;
        if u64::from(record.symbols_per_segment) < k + 2 {
            return Err(RegistryError::BadPlacement("fewer than k + 2 symbols"));
        }
        let mut ranges: Vec<(u32, u32)> = Vec::new();
        let mut distinct_validators = BTreeSet::new();
        for (s, sh) in shares {
            if *s == index {
                if !distinct_validators.insert(sh.validator) {
                    return Err(RegistryError::BadPlacement(
                        "duplicate validator in segment",
                    ));
                }
                ranges.push((sh.first_esi, sh.symbols));
            }
        }
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
        if distinct_validators.len() < 2 {
            return Err(RegistryError::BadPlacement(
                "each segment requires at least two distinct validators",
            ));
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

    /// Whether `nft` authorizes reads of `object`, accounting for finalized and
    /// pending Section 6.14 `ReplaceObject` redirects (`old -> new` moves
    /// `nfts[nft]` at proposal time while `old` stays live until `new` ACKs).
    #[must_use]
    pub fn nft_matches_object(&self, nft: &NftId, object: &ObjectKey) -> bool {
        let Some((bound_key, _)) = self.nfts.get(nft).copied() else {
            return false;
        };
        if bound_key == *object {
            return true;
        }
        let Some((resolved_key, _)) = self.resolve_live_object(object) else {
            return false;
        };
        if bound_key == resolved_key {
            return true;
        }
        // During a pending (unfinalized) Section 6.14 replacement `old -> new`,
        // `replace_object` moves `nfts[nft]` to `new` immediately while `old`
        // remains live until `new` is ACKed. Walk pending replacement targets
        // so NFT holders keep read access throughout the handover window.
        let mut cur = resolved_key;
        let mut seen = BTreeSet::new();
        for _ in 0..16 {
            if !seen.insert(cur) {
                break;
            }
            let Some(rep) = self.replacements.get(&cur) else {
                break;
            };
            if rep.new == bound_key {
                return true;
            }
            cur = rep.new;
        }
        false
    }

    /// Look up the `(object_key, holder_address)` binding for a bound `NftId`.
    #[must_use]
    pub fn nft_binding(&self, nft: &NftId) -> Option<(ObjectKey, Address)> {
        self.nfts.get(nft).copied()
    }

    /// Whether `key` was deleted, and when.
    #[must_use]
    pub fn tombstone(&self, key: &ObjectKey) -> Option<u64> {
        self.tombstones.get(key).copied()
    }

    /// Iterate tombstoned object keys so node-local symbol caches can purge
    /// deleted payloads even after a restart.
    pub fn tombstone_keys(&self) -> impl Iterator<Item = &ObjectKey> {
        self.tombstones.keys()
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
        super::limits::Bud3Limits::TESTNET_DEFAULT
            .admit_content(record.content_id.len)
            .map_err(|_| RegistryError::BadRecord("content length exceeds testnet ceiling"))?;
        super::limits::Bud3Limits::TESTNET_DEFAULT
            .admit_content(record.object_len)
            .map_err(|_| RegistryError::BadRecord("object length exceeds testnet ceiling"))?;
        if lifetime_epochs == 0 {
            return Err(RegistryError::BadLifetime);
        }
        let expires_at = epoch
            .checked_add(lifetime_epochs)
            .ok_or(RegistryError::BadLifetime)?;
        let raw_key = record.commitment;
        if self.tombstones.contains_key(&raw_key) {
            return Err(RegistryError::Tombstoned);
        }
        let public = record.content_id.kind == ContentIdKind::Public;
        if public {
            if let Some(existing) = self.public_index.get(&record.content_id.digest) {
                if self.objects.get(existing).is_some_and(|entry| {
                    entry.custody_confirmed
                        && entry.record.content_id == record.content_id
                        && !entry.shares.is_empty()
                        && entry
                            .shares
                            .iter()
                            .all(|s| s.status == ShareStatus::Confirmed && !s.lost)
                }) {
                    return Ok(Registered::Deduplicated(*existing));
                }
            }
        }
        // Prevent commitment squatting: if another party holds an unconfirmed
        // entry (or a sealed object) at `raw_key`, admit this claimant under an
        // owner-scoped object key so a front-runner without the actual content
        // cannot block the legitimate uploader or hijack custody.
        let key = if let Some(entry) = self.objects.get(&raw_key) {
            if entry.record.content_id.kind == ContentIdKind::Public
                && entry.custody_confirmed
                && entry.record.content_id == record.content_id
                && !entry.shares.is_empty()
                && entry
                    .shares
                    .iter()
                    .all(|s| s.status == ShareStatus::Confirmed && !s.lost)
            {
                return Ok(Registered::Deduplicated(raw_key));
            }
            if entry.owner == owner {
                if entry.record.content_id.kind == ContentIdKind::Public {
                    return Err(RegistryError::BadRecord("awaiting custody confirmation"));
                }
                return Ok(Registered::Deduplicated(raw_key));
            }
            let scoped = Self::claimant_scoped_key(&raw_key, &owner);
            if self.tombstones.contains_key(&scoped) {
                return Err(RegistryError::Tombstoned);
            }
            if self.replacements.contains_key(&scoped) {
                return Err(RegistryError::BadRecord("commitment was already replaced"));
            }
            if let Some(own_entry) = self.objects.get(&scoped) {
                if own_entry.record.content_id.kind == ContentIdKind::Public {
                    if own_entry.custody_confirmed
                        && !own_entry.shares.is_empty()
                        && own_entry
                            .shares
                            .iter()
                            .all(|s| s.status == ShareStatus::Confirmed && !s.lost)
                    {
                        return Ok(Registered::Deduplicated(scoped));
                    }
                    return Err(RegistryError::BadRecord("awaiting custody confirmation"));
                }
                return Ok(Registered::Deduplicated(scoped));
            }
            scoped
        } else if self.replacements.contains_key(&raw_key) {
            return Err(RegistryError::BadRecord("commitment was already replaced"));
        } else {
            raw_key
        };
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
        let (shares, roots, next_esi) = initial_state(&record, shares, epoch);
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
                custody_confirmed: false,
            },
        );
        Ok(Registered::New(key))
    }

    /// The replacement of `old`, if one was proposed.
    #[must_use]
    pub fn replacement(&self, old: &ObjectKey) -> Option<&Replacement> {
        self.replacements.get(old)
    }

    /// Deterministic owner-scoped object key used when deduplicating/isolating
    /// a claimant registration under a contested raw commitment.
    #[must_use]
    pub(crate) fn claimant_scoped_key(raw_key: &ObjectKey, owner: &Address) -> ObjectKey {
        hash_fields_bytes(&[b"BDLM_BUD3_CLAIMANT_KEY_V1", raw_key, owner])
    }

    fn pending_replacement_sources(&self, key: &ObjectKey) -> Vec<ObjectKey> {
        let mut out = vec![*key];
        let mut cur = *key;
        let mut seen = BTreeSet::from([*key]);
        for _ in 0..16 {
            let Some((old, _)) = self
                .replacements
                .iter()
                .find(|(_, r)| !r.finalized && r.new == cur)
            else {
                break;
            };
            if !seen.insert(*old) {
                break;
            }
            out.push(*old);
            cur = *old;
        }
        out
    }

    fn pending_replacement_leaf(&self, key: &ObjectKey) -> ObjectKey {
        let mut cur = *key;
        let mut seen = BTreeSet::from([*key]);
        for _ in 0..16 {
            let Some(rep) = self.replacements.get(&cur) else {
                break;
            };
            if rep.finalized || !seen.insert(rep.new) {
                break;
            }
            cur = rep.new;
        }
        cur
    }

    /// Return an unfinalized predecessor object whose shares remain confirmed
    /// while `key` is awaiting custody confirmation.
    #[must_use]
    pub(crate) fn pending_confirmed_fallback(&self, key: &ObjectKey) -> Option<ObjectKey> {
        if self
            .objects
            .get(key)
            .is_none_or(|entry| entry.custody_confirmed)
        {
            return None;
        }
        self.replacements
            .iter()
            .find(|(old, r)| {
                !r.finalized
                    && r.new == *key
                    && self.objects.get(*old).is_some_and(|o| o.custody_confirmed)
            })
            .map(|(old, _)| *old)
    }

    /// Resolve `key` to its live [`ObjectEntry`], following finalized Section 6.14
    /// `ReplaceObject` redirects up to 16 hops while rejecting tombstoned,
    /// cyclic, or missing targets.
    #[must_use]
    pub fn resolve_live_object(&self, key: &ObjectKey) -> Option<(ObjectKey, &ObjectEntry)> {
        let mut cur = *key;
        let mut seen = BTreeSet::new();
        for _ in 0..16 {
            if !seen.insert(cur) || self.tombstones.contains_key(&cur) {
                return None;
            }
            if let Some(entry) = self.objects.get(&cur) {
                return Some((cur, entry));
            }
            let rep = self.replacements.get(&cur)?;
            if !rep.finalized {
                return None;
            }
            cur = rep.new;
        }
        None
    }

    /// Record an on-chain G8 paid fallback decode authorization for a public object.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::InvalidPaidView`] when the receipt ID was already
    /// used, the amount is below `MIN_PAID_VIEW_FEE_ATOMS`, the object is missing or
    /// tombstoned, or the object is sealed (G8 validator fallback is strictly forbidden).
    pub fn record_paid_view(
        &mut self,
        payer: Address,
        object: ObjectKey,
        receipt_id: [u8; 32],
        amount_atoms: u64,
        epoch: u64,
    ) -> Result<(), RegistryError> {
        if amount_atoms < MIN_PAID_VIEW_FEE_ATOMS {
            return Err(RegistryError::InvalidPaidView(
                "paid view fee below minimum",
            ));
        }
        if self.paid_views.contains_key(&receipt_id) {
            return Err(RegistryError::InvalidPaidView(
                "duplicate paid view receipt",
            ));
        }
        if self.tombstones.contains_key(&object) {
            return Err(RegistryError::Tombstoned);
        }
        // Reap expired or orphaned receipts before checking capacity so stale
        // entries awaiting the next epoch boundary cannot crowd out new views.
        let objects = &self.objects;
        let tombstones = &self.tombstones;
        self.paid_views.retain(|_, rec| {
            rec.paid_at_epoch.saturating_add(PAID_VIEW_RETENTION_EPOCHS) >= epoch
                && objects.contains_key(&rec.object)
                && !tombstones.contains_key(&rec.object)
        });
        if self.paid_views.len() >= MAX_PAID_VIEWS {
            return Err(RegistryError::InvalidPaidView(
                "global paid view receipt limit reached",
            ));
        }
        let target_object = self
            .resolve_live_object(&object)
            .map(|(k, _)| k)
            .ok_or(RegistryError::UnknownObject)?;
        let mut object_receipts = 0usize;
        let mut payer_object_receipts = 0usize;
        for rec in self.paid_views.values() {
            if rec.object == target_object {
                object_receipts += 1;
                if rec.payer == payer {
                    payer_object_receipts += 1;
                }
            }
        }
        if object_receipts >= MAX_PAID_VIEWS_PER_OBJECT {
            return Err(RegistryError::InvalidPaidView(
                "paid view receipt limit reached for object",
            ));
        }
        if payer_object_receipts >= MAX_PAID_VIEWS_PER_PAYER_OBJECT {
            return Err(RegistryError::InvalidPaidView(
                "paid view receipt limit reached for payer on object",
            ));
        }
        let obj = self
            .objects
            .get_mut(&target_object)
            .ok_or(RegistryError::UnknownObject)?;
        if obj.record.content_id.kind != ContentIdKind::Public {
            return Err(RegistryError::InvalidPaidView(
                "fallback view only allowed for public objects",
            ));
        }
        obj.endowment.deposit(split_storage_fee(amount_atoms));
        self.paid_views.insert(
            receipt_id,
            PaidViewRecord {
                payer,
                object: target_object,
                amount_atoms,
                paid_at_epoch: epoch,
            },
        );
        Ok(())
    }

    /// Verify that `receipt` corresponds to a live on-chain [`PaidViewRecord`].
    #[must_use]
    pub fn verify_paid_view(&self, receipt: &PaidViewReceipt) -> bool {
        receipt.fee_paid_atoms >= MIN_PAID_VIEW_FEE_ATOMS
            && self.paid_views.get(&receipt.receipt_id).is_some_and(|rec| {
                self.resolve_live_object(&receipt.object)
                    .is_some_and(|(resolved, _)| {
                        resolved == rec.object
                            && self.objects.contains_key(&rec.object)
                            && !self.tombstones.contains_key(&rec.object)
                            && rec.payer == receipt.payer
                            && rec.amount_atoms >= receipt.fee_paid_atoms
                            && rec.amount_atoms >= MIN_PAID_VIEW_FEE_ATOMS
                    })
            })
    }

    /// Verify that `receipt` corresponds to an unexpired on-chain [`PaidViewRecord`]
    /// at `current_epoch` (even before `expire` sweeps the epoch boundary).
    #[must_use]
    pub fn verify_paid_view_at(&self, receipt: &PaidViewReceipt, current_epoch: u64) -> bool {
        self.verify_paid_view(receipt)
            && self.paid_views.get(&receipt.receipt_id).is_some_and(|rec| {
                current_epoch <= rec.paid_at_epoch.saturating_add(PAID_VIEW_RETENTION_EPOCHS)
            })
    }

    /// Item 6 of section 6.14: every new share of `key` is confirmed, so every
    /// object it replaced releases its shares. The old commitment keeps
    /// answering, as a redirect to `key`.
    fn release_replaced(&mut self, key: &ObjectKey) {
        if self.replacements.is_empty() {
            return;
        }
        let superseded: Vec<ObjectKey> = self
            .replacements
            .iter()
            .filter(|(_, r)| r.new == *key && !r.finalized)
            .map(|(old, _)| *old)
            .collect();
        for old in superseded {
            if let Some(obj) = self.objects.remove(&old) {
                if obj.record.content_id.kind == ContentIdKind::Public {
                    self.public_index.insert(obj.record.content_id.digest, *key);
                }
                self.forfeited_pool_total = self
                    .forfeited_pool_total
                    .saturating_add(obj.endowment.remaining_balance);
                if let Some(deps) = self.base_deps.remove(&old) {
                    self.base_deps.entry(*key).or_default().extend(deps);
                }
                for dep_set in self.base_deps.values_mut() {
                    if dep_set.remove(&old) {
                        dep_set.insert(*key);
                    }
                }
                for rec in self.paid_views.values_mut() {
                    if rec.object == old {
                        rec.object = *key;
                    }
                }
                for nft in obj.references {
                    if let Some((_, holder)) = self.nfts.get(&nft).copied() {
                        self.nfts.insert(nft, (*key, holder));
                        if let Some(new_obj) = self.objects.get_mut(key) {
                            new_obj.references.insert(nft);
                        }
                    }
                }
            }
            if let Some(r) = self.replacements.get_mut(&old) {
                r.finalized = true;
            }
        }
    }

    /// `BindNft`: one more reference to a live object.
    ///
    /// `nft_owner` is the chain-resolved owner of `nft` from the NFT registry.
    /// Binding is refused unless `nft_owner == Some(holder)` so no account can
    /// squat an unowned or third-party NFT id.
    ///
    /// # Errors
    ///
    /// [`RegistryError::UnknownObject`], [`RegistryError::Tombstoned`],
    /// [`RegistryError::NotAuthorized`], [`RegistryError::NftAlreadyBound`], or
    /// [`RegistryError::BadRecord`] when `key` has a pending replacement or reached
    /// the reference cap.
    pub fn bind_nft(
        &mut self,
        nft: NftId,
        holder: Address,
        nft_owner: Option<Address>,
        key: &ObjectKey,
    ) -> Result<(), RegistryError> {
        if nft_owner != Some(holder) {
            return Err(RegistryError::NotAuthorized);
        }
        if self.nfts.contains_key(&nft) {
            return Err(RegistryError::NftAlreadyBound);
        }
        if self.tombstones.contains_key(key) {
            return Err(RegistryError::Tombstoned);
        }
        if self.replacements.get(key).is_some_and(|r| !r.finalized) {
            return Err(RegistryError::BadRecord(
                "object has pending replacement; bind successor commitment",
            ));
        }
        let obj = self
            .objects
            .get_mut(key)
            .ok_or(RegistryError::UnknownObject)?;
        if obj.record.content_id.kind == ContentIdKind::Sealed && obj.owner != holder {
            return Err(RegistryError::NotAuthorized);
        }
        if obj.references.len() >= MAX_OBJECT_REFERENCES {
            return Err(RegistryError::BadRecord("object reference limit reached"));
        }
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
        let dep_refs = self.base_deps.get(key).map_or(0, |d| d.len() as u64);
        nft_refs.saturating_add(dep_refs)
    }

    fn delete(&mut self, key: &ObjectKey, epoch: u64) {
        self.drop_object(key, epoch);
        // A replacement whose new object is deleted leaves no object that
        // carries the content: the references are already gone (this is the
        // burn of the last one, or expiry), so every chained replaced object
        // goes with it and no orphan redirect stands.
        let mut queue = vec![*key];
        let mut seen = BTreeSet::from([*key]);
        while let Some(target) = queue.pop() {
            let replaced: Vec<ObjectKey> = self
                .replacements
                .iter()
                .filter(|(_, r)| r.new == target)
                .map(|(old, _)| *old)
                .collect();
            for old in replaced {
                self.drop_object(&old, epoch);
                self.replacements.remove(&old);
                if seen.insert(old) {
                    queue.push(old);
                }
            }
        }
    }

    /// Forget one live object: its public-index row, its references and its
    /// shares. The replacement record, if any, is the caller's business.
    fn drop_object(&mut self, key: &ObjectKey, epoch: u64) {
        if let Some(obj) = self.objects.remove(key) {
            // Early burn or replacement never refunds prior storage fees; any
            // undistributed balance enters the Network Security Pool.
            if obj.endowment.remaining_balance > 0 {
                self.forfeited_pool_total = self
                    .forfeited_pool_total
                    .saturating_add(obj.endowment.remaining_balance);
            }
            if obj.record.content_id.kind == ContentIdKind::Public
                && self.public_index.get(&obj.record.content_id.digest) == Some(key)
            {
                self.public_index.remove(&obj.record.content_id.digest);
            }
            for nft in obj.references {
                self.nfts.remove(&nft);
            }
            self.base_deps.remove(key);
            for deps in self.base_deps.values_mut() {
                deps.remove(key);
            }
            self.base_deps.retain(|_, deps| !deps.is_empty());
            self.paid_views.retain(|_, rec| rec.object != *key);
            // Only custody-confirmed objects earn a permanent deletion
            // tombstone: an unconfirmed squatter letting a bogus registration
            // expire or burning its own unacked placeholder cannot lock the
            // commitment out forever.
            if obj.custody_confirmed {
                self.tombstones.insert(*key, epoch);
            }
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
        let owner = self
            .objects
            .get(&key)
            .ok_or(RegistryError::UnknownObject)?
            .owner;
        let has_deps = self
            .pending_replacement_sources(&key)
            .into_iter()
            .any(|k| self.base_deps.get(&k).is_some_and(|d| !d.is_empty()));
        let nft_count = self.objects.get(&key).map_or(0, |o| o.references.len());
        if nft_count <= 1 && has_deps {
            return Err(RegistryError::HasDependents);
        }
        // Emptying the reference set deletes the object and writes a tombstone
        // that keeps its commitment from ever being registered again, so only
        // the object's owner may take that loss. A reference is whatever
        // `BindNft` named, verified against no NFT registry, so holding one is
        // not authority over the object it points at.
        if nft_count <= 1 && !has_deps && owner != *signer {
            return Err(RegistryError::NotAuthorized);
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

    /// Delete an object outright. Only the object's owner may do this, and
    /// only while no dependent delta/derived objects stand on it. Third-party
    /// NFT references do not block the owner: they are unbound along with the
    /// object (their holders keep the NFT itself; only this registry's
    /// reference to it is dropped). The commitment is tombstoned when the
    /// object was custody-confirmed, exactly as on the burn path.
    ///
    /// # Errors
    ///
    /// [`RegistryError::UnknownObject`], [`RegistryError::NotAuthorized`] when
    /// `signer` is not the object's owner, or [`RegistryError::HasDependents`]
    /// when dependent objects still stand on it.
    pub fn delete_object(
        &mut self,
        key: &ObjectKey,
        signer: &Address,
        epoch: u64,
    ) -> Result<(), RegistryError> {
        let owner = self
            .objects
            .get(key)
            .ok_or(RegistryError::UnknownObject)?
            .owner;
        if owner != *signer {
            return Err(RegistryError::NotAuthorized);
        }
        if self.base_deps.get(key).is_some_and(|d| !d.is_empty()) {
            return Err(RegistryError::HasDependents);
        }
        self.delete(key, epoch);
        Ok(())
    }

    /// Check whether a chain-verified NFT transfer (`from -> to`) is permitted
    /// by the B.U.D. 3.0 registry without mutating state.
    ///
    /// Returns `Ok(false)` when `nft` has no B.U.D. 3.0 binding, `Ok(true)` when
    /// bound and transferable, or an error when `from` is not the recorded
    /// holder or a delta/base dependency requires standalone rehydration first.
    ///
    /// # Errors
    ///
    /// [`RegistryError::NotAuthorized`], [`RegistryError::UnknownObject`], or
    /// [`RegistryError::CrossOwnerDependency`].
    pub fn can_transfer_nft_reference(
        &self,
        nft: &NftId,
        from: &Address,
        to: &Address,
    ) -> Result<bool, RegistryError> {
        let Some((key, holder)) = self.nfts.get(nft).copied() else {
            return Ok(false);
        };
        if holder != *from {
            return Err(RegistryError::NotAuthorized);
        }
        let obj = self.objects.get(&key).ok_or(RegistryError::UnknownObject)?;
        if self.tombstones.contains_key(&key) {
            return Err(RegistryError::UnknownObject);
        }
        if from != to && obj.owner == *from {
            let lineage = self.pending_replacement_sources(&key);
            for (base, deps) in &self.base_deps {
                if lineage.iter().any(|k| deps.contains(k)) {
                    let base_live = self.pending_replacement_leaf(base);
                    let conflict = self
                        .objects
                        .get(base)
                        .is_some_and(|base_obj| base_obj.owner != *to)
                        || self
                            .objects
                            .get(&base_live)
                            .is_some_and(|base_obj| base_obj.owner != *to);
                    if conflict {
                        return Err(RegistryError::CrossOwnerDependency);
                    }
                }
            }
            for base_k in &lineage {
                if let Some(deps) = self.base_deps.get(base_k) {
                    for dep in deps {
                        let dep_live = self.pending_replacement_leaf(dep);
                        let conflict = self
                            .objects
                            .get(dep)
                            .is_some_and(|dep_obj| dep_obj.owner != *to)
                            || self
                                .objects
                                .get(&dep_live)
                                .is_some_and(|dep_obj| dep_obj.owner != *to);
                        if conflict {
                            return Err(RegistryError::CrossOwnerDependency);
                        }
                    }
                }
            }
        }
        Ok(true)
    }

    /// Synchronize a chain-verified NFT ownership transfer (`from -> to`) into
    /// [`Bud3Registry`], moving grant/burn authority on `nft` (and updating
    /// `obj.owner` when all live references now belong to `to`).
    ///
    /// # Errors
    ///
    /// [`RegistryError::UnknownNft`], [`RegistryError::NotAuthorized`],
    /// [`RegistryError::UnknownObject`], or [`RegistryError::CrossOwnerDependency`].
    pub fn transfer_nft_reference(
        &mut self,
        nft: &NftId,
        from: &Address,
        to: &Address,
    ) -> Result<(), RegistryError> {
        if !self.can_transfer_nft_reference(nft, from, to)? {
            return Err(RegistryError::UnknownNft);
        }
        let (key, _) = self
            .nfts
            .get(nft)
            .copied()
            .ok_or(RegistryError::UnknownNft)?;
        self.nfts.insert(*nft, (key, *to));
        let all_held_by_to = self.objects.get(&key).is_some_and(|obj| {
            obj.owner == *from
                && !obj.references.is_empty()
                && obj
                    .references
                    .iter()
                    .all(|r| self.nfts.get(r).is_some_and(|(_, h)| h == to))
        });
        if all_held_by_to {
            if let Some(obj) = self.objects.get_mut(&key) {
                obj.owner = *to;
            }
        }
        Ok(())
    }

    /// Check whether a chain-verified `NftBurn` can safely release `nft` without
    /// leaving orphaned base dependencies (`HasDependents`).
    ///
    /// # Errors
    ///
    /// [`RegistryError::NotAuthorized`], [`RegistryError::UnknownObject`], or
    /// [`RegistryError::HasDependents`].
    pub fn can_release_verified_nft_reference(
        &self,
        nft: &NftId,
        signer: &Address,
    ) -> Result<bool, RegistryError> {
        let Some((key, holder)) = self.nfts.get(nft).copied() else {
            return Ok(false);
        };
        if holder != *signer {
            return Err(RegistryError::NotAuthorized);
        }
        let obj = self.objects.get(&key).ok_or(RegistryError::UnknownObject)?;
        let has_deps = self
            .pending_replacement_sources(&key)
            .into_iter()
            .any(|k| self.base_deps.get(&k).is_some_and(|d| !d.is_empty()));
        if obj.references.len() <= 1 && has_deps {
            return Err(RegistryError::HasDependents);
        }
        Ok(true)
    }

    /// Release `nft`'s B.U.D. 3.0 reference after on-chain `NftRegistry::burn`
    /// verified ownership. Deletes and tombstones the object when `signer` owns
    /// the object and zero references remain; if a non-owner bound a third-party
    /// public object and burns their sole NFT, detaches only the NFT reference.
    ///
    /// # Errors
    ///
    /// [`RegistryError::NotAuthorized`], [`RegistryError::UnknownObject`], or
    /// [`RegistryError::HasDependents`].
    pub fn release_verified_nft_reference(
        &mut self,
        nft: &NftId,
        signer: &Address,
        epoch: u64,
    ) -> Result<bool, RegistryError> {
        if !self.can_release_verified_nft_reference(nft, signer)? {
            return Ok(false);
        }
        match self.burn_reference(nft, signer, epoch) {
            Ok(deleted) => Ok(deleted),
            Err(RegistryError::NotAuthorized) => {
                // Chain verified `signer` owns this SocialFi NFT, while the
                // underlying public object is owned by another uploader: detach
                // only the burned NFT reference without tombstoning their object.
                let (key, _) = self.nfts.remove(nft).ok_or(RegistryError::UnknownNft)?;
                if let Some(obj) = self.objects.get_mut(&key) {
                    obj.references.remove(nft);
                }
                Ok(false)
            }
            Err(e) => Err(e),
        }
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
        let dep_keys = self.pending_replacement_sources(dependent);
        let base_keys = self.pending_replacement_sources(base);
        for base_k in base_keys {
            let mut remove_entry = false;
            if let Some(set) = self.base_deps.get_mut(&base_k) {
                for dep_k in &dep_keys {
                    set.remove(dep_k);
                }
                remove_entry = set.is_empty();
            }
            if remove_entry {
                self.base_deps.remove(&base_k);
                let live_k = self.pending_replacement_leaf(&base_k);
                let has_refs = self
                    .objects
                    .get(&base_k)
                    .is_some_and(|o| !o.references.is_empty())
                    || self
                        .objects
                        .get(&live_k)
                        .is_some_and(|o| !o.references.is_empty());
                if !has_refs
                    && self.objects.contains_key(&base_k)
                    && self.replacements.get(&base_k).is_none_or(|r| r.finalized)
                {
                    self.delete(&base_k, epoch);
                }
            }
        }
    }

    /// `IssueViewGrant`: verify the signer holds `nft` and `row.grant_tag` binds to
    /// `(nft, grant_nonce)`, then record an unlinkable [`GrantRow`] carrying no
    /// `content_id`, `issuer`, or `grantee`.
    ///
    /// # Errors
    ///
    /// [`RegistryError::UnknownNft`], [`RegistryError::NotAuthorized`],
    /// [`RegistryError::UnknownObject`], or [`RegistryError::Grant`] if the tag is
    /// mismatched, duplicate/revoked, expired, or has an invalid ML-DSA-65 one-time
    /// key or HPKE X-Wing (`0x647a`) package.
    pub fn issue_view_grant(
        &mut self,
        nft: &NftId,
        grant_nonce: &[u8; 32],
        signer: &Address,
        row: GrantRow,
        epoch: u64,
    ) -> Result<(), RegistryError> {
        self.validate_view_grant(nft, grant_nonce, signer, &row, epoch)?;
        self.grants.insert(row.grant_tag, row);
        Ok(())
    }

    /// Check grant issuance without changing registry state.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] if the NFT, object, signer, tag, or grant row is invalid.
    pub fn validate_view_grant(
        &self,
        nft: &NftId,
        grant_nonce: &[u8; 32],
        signer: &Address,
        row: &GrantRow,
        epoch: u64,
    ) -> Result<(), RegistryError> {
        let (key, holder) = *self.nfts.get(nft).ok_or(RegistryError::UnknownNft)?;
        if holder != *signer {
            return Err(RegistryError::NotAuthorized);
        }
        if self.tombstones.contains_key(&key) || !self.objects.contains_key(&key) {
            return Err(RegistryError::UnknownObject);
        }
        if super::grants::compute_grant_tag(nft, grant_nonce) != row.grant_tag {
            return Err(RegistryError::Grant(GrantBud3Error::InvalidGrantTag));
        }
        if self.grants.contains_key(&row.grant_tag) || self.revoked_grants.contains(&row.grant_tag)
        {
            return Err(RegistryError::Grant(GrantBud3Error::DuplicateOrRevokedTag));
        }
        row.validate_for_issue(epoch).map_err(RegistryError::Grant)
    }

    /// Issue a view grant through the canonical issuance path.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] if [`Self::validate_view_grant`] fails.
    pub fn issue_grant(
        &mut self,
        nft: &NftId,
        grant_nonce: &[u8; 32],
        signer: &Address,
        row: GrantRow,
        epoch: u64,
    ) -> Result<(), RegistryError> {
        self.issue_view_grant(nft, grant_nonce, signer, row, epoch)
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

    /// Read a stored grant row by `grant_tag`. Use [`Self::active_grant`] when
    /// an authorization decision depends on the current epoch.
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
        let owner = self
            .objects
            .get(&key)
            .ok_or(RegistryError::UnknownObject)?
            .owner;
        let has_deps = self.base_deps.get(&key).is_some_and(|d| !d.is_empty());
        let nft_count = self.objects.get(&key).map_or(0, |o| o.references.len());
        if nft_count <= 1 && has_deps {
            return Err(RegistryError::HasDependents);
        }
        if nft_count <= 1 && !has_deps && owner != *signer {
            return Err(RegistryError::NotAuthorized);
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
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::BadQuota`] if `quota_bytes` violates `limits`.
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

    /// `ReplaceObject` (Section 6.14): propose a second representation of the
    /// same content under the canonical attested transaction encoding.
    ///
    /// A public proposal comes from a Full validator holding an old share;
    /// sealed content additionally requires its owner. Three distinct Full
    /// placement-group attestations verify the identical `ContentId`.
    /// References move at proposal, but old shares and their endowment stay
    /// until every new share is acknowledged. The old commitment then remains
    /// as a finalized redirect instead of becoming a deletion tombstone.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] if the object, authorization, shares, or attestations are invalid.
    pub fn replace_object(
        &mut self,
        proposer: (Address, u64),
        old_key: &ObjectKey,
        new_record: ObjectRecord,
        new_shares: Vec<(u64, Share)>,
        attestations: &[super::replace::ReplaceAttestation],
        (chain_id, epoch, validator_keys): (u64, u64, &BTreeMap<Address, Vec<u8>>),
    ) -> Result<ObjectKey, RegistryError> {
        let (sender, proposer_stake) = proposer;
        if self.tombstones.contains_key(old_key) {
            return Err(RegistryError::Tombstoned);
        }
        let old_entry = self
            .objects
            .get(old_key)
            .ok_or(RegistryError::UnknownObject)?
            .clone();
        if self.replacements.get(old_key).is_some_and(|r| !r.finalized) {
            return Err(RegistryError::BadReplacement(
                super::replace::ReplaceError::ReplacementAlreadyPending,
            ));
        }
        if old_entry.record.content_id.kind == ContentIdKind::Sealed {
            if sender != old_entry.owner {
                return Err(RegistryError::NotAuthorized);
            }
        } else if !old_entry
            .shares
            .iter()
            .any(|s| s.share.validator == sender && s.share.class == Class::Full)
        {
            return Err(RegistryError::NotAuthorized);
        }
        let pg_full: BTreeSet<Address> = old_entry
            .shares
            .iter()
            .filter(|s| s.share.class == Class::Full)
            .map(|s| s.share.validator)
            .collect();
        super::replace::admit_object_replacement(
            chain_id,
            (&sender, &old_entry.owner, proposer_stake),
            (&old_entry.record, &new_record),
            &new_shares,
            (&pg_full, validator_keys),
            attestations,
        )
        .map_err(RegistryError::BadReplacement)?;

        let new_key = new_record.commitment;
        super::limits::Bud3Limits::TESTNET_DEFAULT
            .admit_content(new_record.content_id.len)
            .map_err(|_| RegistryError::BadRecord("content length exceeds testnet ceiling"))?;
        super::limits::Bud3Limits::TESTNET_DEFAULT
            .admit_content(new_record.object_len)
            .map_err(|_| RegistryError::BadRecord("object length exceeds testnet ceiling"))?;
        if self.tombstones.contains_key(&new_key) || self.objects.contains_key(&new_key) {
            return Err(RegistryError::BadReplacement(
                super::replace::ReplaceError::CommitmentAlreadyLive,
            ));
        }
        check_placement(&new_record, &new_shares)?;
        let digest = new_record.content_id.digest;
        if new_shares
            .iter()
            .any(|(_, s)| self.declines.contains(&(digest, s.validator)))
        {
            return Err(RegistryError::Declined);
        }

        let expires_at = old_entry.expires_at.max(epoch.saturating_add(1));
        let remaining_epochs = expires_at.saturating_sub(epoch).max(1);
        let fee_record = FeeRecord::from_placed_shares(&new_record, &new_shares);
        let new_fee = storage_fee_for_epochs(
            fee_record.user_physical_bytes,
            remaining_epochs,
            &FeeParams::TESTNET_DEFAULT,
        )
        .map_err(|_| RegistryError::BadLifetime)?;
        let endowment = ObjectEndowment::new(fee_record, split_storage_fee(new_fee));
        let (shares, roots, next_esi) = initial_state(&new_record, new_shares, epoch);
        let references = old_entry.references.clone();
        for nft in &references {
            if let Some((_, holder)) = self.nfts.get(nft).copied() {
                self.nfts.insert(*nft, (new_key, holder));
            }
        }
        let content = old_entry.record.content_id;
        let new_object_len = new_record.object_len;
        self.objects.insert(
            new_key,
            ObjectEntry {
                record: new_record,
                owner: old_entry.owner,
                references,
                expires_at,
                shares,
                roots,
                next_esi,
                endowment,
                custody_confirmed: false,
            },
        );
        if let Some(old) = self.objects.get_mut(old_key) {
            old.references.clear();
        }
        self.replacements.insert(
            *old_key,
            Replacement {
                new: new_key,
                proposer: sender,
                content,
                old_object_len: old_entry.record.object_len,
                new_object_len,
                proposed_at: epoch,
                finalized: false,
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
            .filter(|(_, g)| g.expires_at_epoch <= epoch)
            .map(|(tag, _)| *tag)
            .collect();
        for tag in expired_grants {
            self.grants.remove(&tag);
            self.revoked_grants.insert(tag);
        }
        let due: Vec<ObjectKey> = self
            .objects
            .iter()
            .filter(|(k, o)| {
                o.expires_at < epoch && self.replacements.get(*k).is_none_or(|r| r.finalized)
            })
            .map(|(k, _)| *k)
            .collect();
        // Expiry is not an acknowledgement barrier: pending old objects were
        // excluded from `due`. If their new object is due, `delete(new)`
        // removes both sides and the redirect; otherwise the old shares stay
        // until every new share is acknowledged.
        for k in &due {
            self.delete(k, epoch);
        }
        // A paid view receipt authorizes one decode and is otherwise dead
        // weight in the state root and the snapshot. Drop the ones past the
        // retention window, and the ones whose object is gone, so the map is
        // bounded by the window and the live objects instead of by every
        // receipt ever paid.
        let stale_paid_views: Vec<[u8; 32]> = self
            .paid_views
            .iter()
            .filter(|(_, rec)| {
                rec.paid_at_epoch.saturating_add(PAID_VIEW_RETENTION_EPOCHS) < epoch
                    || !self.objects.contains_key(&rec.object)
            })
            .map(|(receipt_id, _)| *receipt_id)
            .collect();
        for receipt_id in stale_paid_views {
            self.paid_views.remove(&receipt_id);
        }
        due
    }

    /// `DeclineContent`: a validator refuses shares of `content`. Any existing
    /// share held by `validator` on an object with `content` enters share-loss
    /// reassignment without penalty ( item 10).
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
    /// ( item 11). Released shares enter the share-loss reassignment path.
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
        let (n, complete, public_digest) = {
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
            let complete = !obj.shares.is_empty()
                && obj
                    .shares
                    .iter()
                    .all(|s| s.status == ShareStatus::Confirmed && !s.lost);
            if complete {
                obj.custody_confirmed = true;
            }
            let public_digest = (obj.record.content_id.kind == ContentIdKind::Public)
                .then_some(obj.record.content_id.digest);
            (n, complete, public_digest)
        };
        // The new object carries the content from here on, so it enters the
        // public dedup index and any replaced object may let its shares go
        // (section 6.14, item 6).
        if n > 0 && complete {
            if let Some(digest) = public_digest {
                let occupied_live = self
                    .public_index
                    .get(&digest)
                    .is_some_and(|existing| existing != key && self.objects.contains_key(existing));
                if !occupied_live {
                    self.public_index.insert(digest, *key);
                }
            }
            self.release_replaced(key);
        }
        Ok(n)
    }

    /// Convenience: hand over every unacknowledged custody assignment whose
    /// 3-epoch confirmation window (`CUSTODY_ASSIGNMENT_HANDOVER_EPOCHS`) has
    /// elapsed by `current_epoch` to the next eligible candidate in
    /// `candidates`. Returns the number of shares reassigned.
    pub fn handover_unacked_shares(
        &mut self,
        current_epoch: u64,
        candidates: &[(Address, Class)],
    ) -> usize {
        let mut moved = 0;
        for obj in self.objects.values_mut() {
            let digest = obj.record.content_id.digest;
            let len = obj.shares.len();
            for idx in 0..len {
                let Some((segment, current_holder, class, assigned_epoch, confirmed, lost)) =
                    obj.shares.get(idx).map(|s| {
                        (
                            s.segment,
                            s.share.validator,
                            s.share.class,
                            s.assigned_epoch,
                            s.status == ShareStatus::Confirmed,
                            s.lost,
                        )
                    })
                else {
                    continue;
                };
                if lost
                    || !super::custody::assignment_due_for_handover(
                        assigned_epoch,
                        current_epoch,
                        confirmed,
                    )
                {
                    continue;
                }
                let mut excluded: Vec<Address> = obj
                    .shares
                    .iter()
                    .filter(|s| s.segment == segment && !s.lost)
                    .map(|s| s.share.validator)
                    .collect();
                for (declined_digest, validator) in &self.declines {
                    if *declined_digest == digest {
                        excluded.push(*validator);
                    }
                }
                if let Some(next_holder) = super::custody::select_next_custody_holder(
                    &current_holder,
                    &excluded,
                    candidates,
                    class,
                ) {
                    if let Some(slot) = obj.shares.get_mut(idx) {
                        slot.share.validator = next_holder;
                        slot.assigned_epoch = current_epoch;
                        slot.status = ShareStatus::Pending;
                        moved += 1;
                    }
                }
            }
        }
        moved
    }

    /// Convenience: every `(object_key, segment)` pair currently due for lazy
    /// repair across the registry.
    #[must_use]
    pub fn all_repairs_due(&self) -> Vec<(ObjectKey, u64)> {
        let mut out = Vec::new();
        for key in self.objects.keys() {
            for seg in self.repairs_due(key) {
                out.push((*key, seg));
            }
        }
        out
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
            let upload_roots = obj.record.symbol_roots.len();
            // Retire unacknowledged repair shares once their 3-epoch acknowledgment
            // window elapses so a silent recipient cannot freeze future repairs.
            obj.shares.retain(|s| {
                !(s.root >= upload_roots
                    && s.status == ShareStatus::Pending
                    && epoch.saturating_sub(s.assigned_epoch)
                        >= super::custody::SHARE_ASSIGNMENT_ACK_DEADLINE_EPOCHS)
            });
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

    /// Ages of currently open audits, derived without changing consensus state.
    /// The stored deadline is `opened + class_window`, so the opening epoch is
    /// recoverable from the canonical tuple and the same audit parameters used
    /// by the chain.
    #[must_use]
    pub fn open_audit_ages(&self, epoch: u64, params: &AuditParams) -> Vec<u64> {
        let mut ages = Vec::new();
        for object in self.objects.values() {
            for share in &object.shares {
                let Some((_, deadline)) = share.open_audit else {
                    continue;
                };
                let window = match share.share.class {
                    Class::Full => params.full_window,
                    Class::Mobile => params.mobile_window,
                };
                let opened = deadline.saturating_sub(window);
                ages.push(epoch.saturating_sub(opened));
            }
        }
        ages
    }

    /// Segments with at least one lost share. This deterioration signal is
    /// intentionally earlier than the lazy repair threshold.
    #[must_use]
    pub fn segments_at_risk(&self, key: &ObjectKey) -> usize {
        let Some(object) = self.objects.get(key) else {
            return 0;
        };
        object
            .shares
            .iter()
            .filter(|share| share.lost)
            .map(|share| share.segment)
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// Sum of [`Self::segments_at_risk`] over every live object.
    #[must_use]
    pub fn total_segments_at_risk(&self) -> usize {
        self.objects
            .keys()
            .map(|key| self.segments_at_risk(key))
            .sum()
    }

    /// Open repair duties across every live object.
    #[must_use]
    pub fn repair_backlog(&self) -> usize {
        self.objects
            .keys()
            .map(|key| self.repairs_due(key).len())
            .sum()
    }

    /// Physical custody required by the live placement, as `(full, mobile)`.
    /// Lost shares remain included until repair settles because the placement
    /// still requires those bytes; this is not an observation of remote disks.
    #[must_use]
    pub fn custody_bytes_by_class(&self) -> (u64, u64) {
        let mut full = 0u64;
        let mut mobile = 0u64;
        for object in self.objects.values() {
            let symbol_size = u64::from(object.record.profile.symbol_size);
            for share in &object.shares {
                let bytes = u64::from(share.share.symbols).saturating_mul(symbol_size);
                match share.share.class {
                    Class::Full => full = full.saturating_add(bytes),
                    Class::Mobile => mobile = mobile.saturating_add(bytes),
                }
            }
        }
        (full, mobile)
    }

    /// Number of live objects in the rooted registry.
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.objects.len()
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
        let upload_roots = obj.record.symbol_roots.len();
        (0..seg.count())
            .filter(|&index| {
                let need = seg
                    .source_symbols(index)
                    .unwrap_or(u64::MAX)
                    .saturating_add(2);
                // Exclude unacknowledged repair shares from coverage arithmetic so
                // a phantom pending repair cannot mask a real custody loss.
                let mut sizes: Vec<u64> = obj
                    .shares
                    .iter()
                    .filter(|s| {
                        s.segment == index
                            && (s.root < upload_roots || s.status == ShareStatus::Confirmed)
                    })
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
                f > 0 && lost > 0 && lost >= (f / 2).max(1)
            })
            .collect()
    }

    /// `RecordRepair`: a Full repairer decoded the segment and placed new
    /// symbols with new ESIs on new holders. The new shares start pending at
    /// `epoch` (their three-epoch acknowledgment deadline begins here); the
    /// lost shares they replace stay until every new share is confirmed.
    ///
    /// # Errors
    ///
    /// [`RegistryError::BadRepair`] when the segment needs no repair, the new
    /// ESIs reuse an old one or overlap, the new symbols do not replace the
    /// lost ones, or the cryptographic repair witness fails;
    /// [`RegistryError::UnknownObject`].
    pub fn record_repair(
        &mut self,
        key: &ObjectKey,
        repair: SegmentRepair<'_>,
        epoch: u64,
    ) -> Result<(), RegistryError> {
        self.record_repair_with_validators(
            key,
            repair,
            None,
            &BTreeMap::new(),
            (crate::core::transaction::DEFAULT_CHAIN_ID, epoch),
        )
    }

    /// Verify and record a segment repair from Merkle-proven live symbols.
    ///
    /// The legacy validator-attestation witness stays decodable for wire
    /// compatibility, but is refused until it carries a seat- or stake-weighted
    /// quorum certificate. A fixed signature count is not finality.
    ///
    /// Convenience: called by `super::tx::apply_with_validators_and_nft_owner` with the
    /// consensus active Full validator key directory and by direct registry callers.
    ///
    /// A validator attestation is verified against the digest for `chain_id`,
    /// so a quorum signed for one network cannot be replayed on another.
    ///
    /// # Errors
    ///
    /// [`RegistryError::BadRepair`] or [`RegistryError::UnknownObject`].
    pub fn record_repair_with_validators(
        &mut self,
        key: &ObjectKey,
        repair: SegmentRepair<'_>,
        repairer: Option<&Address>,
        validator_keys: &BTreeMap<Address, Vec<u8>>,
        (_chain_id, epoch): (u64, u64),
    ) -> Result<(), RegistryError> {
        let SegmentRepair {
            segment,
            new_shares,
            new_symbols,
            new_root,
            witness,
        } = repair;
        if !self.repairs_due(key).contains(&segment) {
            return Err(RegistryError::BadRepair("segment needs no repair"));
        }
        let obj = self
            .objects
            .get_mut(key)
            .ok_or(RegistryError::UnknownObject)?;
        let upload_roots = obj.record.symbol_roots.len();
        // Refuse overlapping repairs while an earlier repair for this segment
        // still has pending shares inside their 3-epoch acknowledgment window.
        // Once that deadline passes, a silent recipient no longer blocks a fresh
        // repair and its expired pending share is pruned when the new repair lands.
        let is_expired_pending_repair = |s: &ShareState| {
            s.segment == segment
                && s.root >= upload_roots
                && s.status == ShareStatus::Pending
                && epoch.saturating_sub(s.assigned_epoch)
                    >= super::custody::SHARE_ASSIGNMENT_ACK_DEADLINE_EPOCHS
        };
        if obj.shares.iter().any(|s| {
            s.segment == segment
                && s.root >= upload_roots
                && s.status == ShareStatus::Pending
                && !s.lost
                && epoch.saturating_sub(s.assigned_epoch)
                    < super::custody::SHARE_ASSIGNMENT_ACK_DEADLINE_EPOCHS
        }) {
            return Err(RegistryError::BadRepair(
                "segment already has an unsettled repair",
            ));
        }
        let seg_idx = usize::try_from(segment).map_err(|_| RegistryError::BadRepair("segment"))?;
        let seg_layout = Segmentation::new(obj.record.object_len, &obj.record.profile)
            .ok_or(RegistryError::BadRepair("invalid object profile"))?;
        let seg_len = seg_layout
            .len(segment)
            .ok_or(RegistryError::BadRepair("segment out of bounds"))?;
        let k_u64 = seg_layout
            .source_symbols(segment)
            .ok_or(RegistryError::BadRepair("segment out of bounds"))?;
        let k_u32 = u32::try_from(k_u64).map_err(|_| RegistryError::BadRepair("ESI range"))?;
        let first = *obj
            .next_esi
            .get(seg_idx)
            .ok_or(RegistryError::BadRepair("segment"))?;
        if first < k_u32 {
            return Err(RegistryError::BadRepair("repair ESIs must exceed k"));
        }
        let mut sorted = new_shares;
        sorted.sort_by_key(|s| s.first_esi);
        let content_digest = obj.record.content_id.digest;
        let existing_holders: BTreeSet<Address> = obj
            .shares
            .iter()
            .filter(|s| s.segment == segment && !is_expired_pending_repair(s))
            .map(|s| s.share.validator)
            .collect();
        let mut seen_new_holders = BTreeSet::new();
        if let Some(rep) = repairer {
            if !validator_keys.is_empty() && !validator_keys.contains_key(rep) {
                return Err(RegistryError::BadRepair(
                    "repairer is not an active consensus Full validator",
                ));
            }
        }
        let mut next = u64::from(first);
        for s in &sorted {
            if s.symbols == 0 || u64::from(s.first_esi) != next {
                return Err(RegistryError::BadRepair(
                    "new ESIs must be fresh and contiguous",
                ));
            }
            if s.validator == [0u8; 32] {
                return Err(RegistryError::BadRepair(
                    "zero address cannot receive repair share",
                ));
            }
            if self.declines.contains(&(content_digest, s.validator)) {
                return Err(RegistryError::Declined);
            }
            if existing_holders.contains(&s.validator) || !seen_new_holders.insert(s.validator) {
                return Err(RegistryError::BadRepair(
                    "duplicate or already-holding repair validator",
                ));
            }
            if !validator_keys.is_empty()
                && s.class == Class::Full
                && !validator_keys.contains_key(&s.validator)
            {
                return Err(RegistryError::BadRepair(
                    "repair recipient is not an active consensus Full validator",
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
        if added > lost {
            return Err(RegistryError::BadRepair("more new symbols than lost"));
        }
        let count = u32::try_from(added).map_err(|_| RegistryError::BadRepair("ESI range"))?;
        let symbol_bytes = usize::from(obj.record.profile.symbol_size);
        let mut sorted_syms = new_symbols;
        if sorted_syms.len() != count as usize {
            return Err(RegistryError::BadRepair(
                "new symbols count mismatch against shares",
            ));
        }
        sorted_syms.sort_by_key(|s| s.esi);
        let mut leaves = Vec::with_capacity(sorted_syms.len());
        for (idx, sym) in sorted_syms.iter().enumerate() {
            let expected_esi = first.saturating_add(u32::try_from(idx).unwrap_or(u32::MAX));
            if sym.segment != segment || sym.esi != expected_esi || sym.data.len() != symbol_bytes {
                return Err(RegistryError::BadRepair(
                    "repair symbol ESI, segment, or length mismatch",
                ));
            }
            leaves.push((sym.esi, symbol_leaf(&sym.data)));
        }
        if symbol_root(&leaves) != new_root {
            return Err(RegistryError::BadRepair(
                "repair symbol root does not match supplied symbols",
            ));
        }
        match witness {
            RepairWitness::ProvenSymbols(proofs) => {
                if proofs.is_empty() || proofs.len() > MAX_REPAIR_WITNESS_SYMBOLS {
                    return Err(RegistryError::BadRepair(
                        "invalid inline repair symbol witness count",
                    ));
                }
                let mut seen_esis = BTreeSet::new();
                let mut dec = SegmentDecoder::new(segment, seg_len, &obj.record.profile)
                    .map_err(|_| RegistryError::BadRepair("repair decoder init failed"))?;
                let mut meter =
                    Meter::new(seg_len.saturating_mul(4).saturating_add(1 << 20), 1 << 20);
                for p in proofs {
                    let root_entry = obj
                        .roots
                        .get(usize::try_from(p.root_index).unwrap_or(usize::MAX))
                        .ok_or(RegistryError::BadRepair("unknown repair witness root"))?;
                    if root_entry.segment != segment {
                        return Err(RegistryError::BadRepair(
                            "repair witness root belongs to another segment",
                        ));
                    }
                    if p.symbol.segment != segment || p.symbol.data.len() != symbol_bytes {
                        return Err(RegistryError::BadRepair(
                            "repair witness symbol segment or length mismatch",
                        ));
                    }
                    let expected_esi = u64::from(root_entry.first_esi)
                        .checked_add(p.position)
                        .ok_or(RegistryError::BadRepair("repair witness position overflow"))?;
                    if u64::from(p.symbol.esi) != expected_esi {
                        return Err(RegistryError::BadRepair(
                            "repair witness ESI does not match root position",
                        ));
                    }
                    if !seen_esis.insert(p.symbol.esi) {
                        return Err(RegistryError::BadRepair("duplicate ESI in repair witness"));
                    }
                    if !verify_symbol_root_path(
                        root_entry.root,
                        u64::from(root_entry.count),
                        p.position,
                        p.symbol.esi,
                        symbol_leaf(&p.symbol.data),
                        &p.root_path,
                    ) {
                        return Err(RegistryError::BadRepair(
                            "repair witness symbol Merkle proof failed",
                        ));
                    }
                    let _ = dec
                        .push(p.symbol.clone(), &mut meter)
                        .map_err(|_| RegistryError::BadRepair("bad repair witness symbol"))?;
                }
                let seg_bytes = dec.into_bytes().ok_or(RegistryError::BadRepair(
                    "repair witness did not decode segment",
                ))?;
                let enc = SegmentEncoder::new(segment, &seg_bytes, &obj.record.profile)
                    .map_err(|_| RegistryError::BadRepair("repair witness re-encode failed"))?;
                let expected_syms = enc
                    .repair_symbols(first - k_u32, count)
                    .map_err(|_| RegistryError::BadRepair("repair symbol derivation failed"))?;
                if expected_syms != sorted_syms {
                    return Err(RegistryError::BadRepair(
                        "repair symbols do not match reconstructed segment",
                    ));
                }
            }
            RepairWitness::ValidatorAttestations(_) => {
                return Err(RegistryError::BadRepair(
                    "validator repair attestations require a seat- or stake-weighted quorum certificate",
                ));
            }
        }
        // Drop any expired unacknowledged repair shares on this segment only
        // after every validation check above has passed.
        obj.shares.retain(|s| !is_expired_pending_repair(s));
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
                assigned_epoch: epoch,
            });
        }
        if let Some(n) = obj.next_esi.get_mut(seg_idx) {
            *n = first.saturating_add(count);
        }
        Ok(())
    }

    /// Retire pending repair shares that remained unacknowledged past
    /// `SHARE_ASSIGNMENT_ACK_DEADLINE_EPOCHS`. Combined with `settle_repairs`
    /// requiring `confirmed_symbols == r.count`, a partially retired repair
    /// never releases old lost shares while unblocking a fresh replacement repair.
    pub(crate) fn retire_unacknowledged_repairs(&mut self, epoch: u64) -> usize {
        let mut retired = 0;
        for obj in self.objects.values_mut() {
            let upload_roots = obj.record.symbol_roots.len();
            let before = obj.shares.len();
            obj.shares.retain(|s| {
                !(s.root >= upload_roots
                    && s.status == ShareStatus::Pending
                    && !s.lost
                    && epoch.saturating_sub(s.assigned_epoch)
                        >= super::custody::SHARE_ASSIGNMENT_ACK_DEADLINE_EPOCHS)
            });
            retired += before - obj.shares.len();
        }
        retired
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
                .filter(|(i, r)| {
                    r.count > 0 && {
                        let confirmed_symbols: u64 = obj
                            .shares
                            .iter()
                            .filter(|s| {
                                s.root == *i && s.status == ShareStatus::Confirmed && !s.lost
                            })
                            .map(|s| u64::from(s.share.symbols))
                            .sum();
                        confirmed_symbols == u64::from(r.count)
                    }
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
                        "custody_confirmed": o.custody_confirmed,
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
                        "replaced_by": self
                            .replacement(key)
                            .filter(|r| !r.finalized)
                            .map(|r| hex::encode(r.new)),
                        "pending_fallback_commitment": self
                            .pending_confirmed_fallback(key)
                            .map(hex::encode),
                    })
                } else if let Some(r) = self.replacements.get(key) {
                    serde_json::json!({
                        "commitment": hex::encode(key),
                        "status": "replaced",
                        "replaced_by": hex::encode(r.new),
                        "finalized": r.finalized,
                        "content_digest": hex::encode(r.content.digest),
                        "content_len": r.content.len,
                        "old_object_len": r.old_object_len,
                        "new_object_len": r.new_object_len,
                        "proposed_at_epoch": r.proposed_at,
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
            Bud3Query::Placement(key) => {
                if let Some(o) = self.objects.get(key) {
                    let mut n_full: u64 = 0;
                    let mut n_mobile: u64 = 0;
                    let mut total_full_symbols: u64 = 0;
                    let mut total_mobile_symbols: u64 = 0;
                    let mut active_symbols: u64 = 0;
                    let shares: Vec<serde_json::Value> = o
                        .shares
                        .iter()
                        .map(|s| {
                            if !s.lost {
                                active_symbols =
                                    active_symbols.saturating_add(u64::from(s.share.symbols));
                                match s.share.class {
                                    Class::Full => {
                                        n_full = n_full.saturating_add(1);
                                        total_full_symbols = total_full_symbols
                                            .saturating_add(u64::from(s.share.symbols));
                                    }
                                    Class::Mobile => {
                                        n_mobile = n_mobile.saturating_add(1);
                                        total_mobile_symbols = total_mobile_symbols
                                            .saturating_add(u64::from(s.share.symbols));
                                    }
                                }
                            }
                            serde_json::json!({
                                "validator": hex::encode(s.share.validator),
                                "class": match s.share.class {
                                    Class::Full => "Full",
                                    Class::Mobile => "Mobile",
                                },
                                "segment": s.segment,
                                "first_esi": s.share.first_esi,
                                "symbols": s.share.symbols,
                                "root": s.root,
                                "confirmed": s.status == ShareStatus::Confirmed,
                                "lost": s.lost,
                                "passes": s.passes,
                                "misses": s.misses,
                                "assigned_epoch": s.assigned_epoch,
                            })
                        })
                        .collect();
                    serde_json::json!({
                        "commitment": hex::encode(key),
                        "status": "live",
                        "content_digest": hex::encode(o.record.content_id.digest),
                        "content_len": o.record.content_id.len,
                        "sealed": o.record.content_id.kind == ContentIdKind::Sealed,
                        "object_len": o.record.object_len,
                        "symbol_size": o.record.profile.symbol_size,
                        "segments": o.record.symbol_roots.len(),
                        "custody_confirmed": o.custody_confirmed,
                        "expires_at_epoch": o.expires_at,
                        "repairs_due": self.repairs_due(key),
                        "n_full": n_full,
                        "n_mobile": n_mobile,
                        "total_full_symbols": total_full_symbols,
                        "total_mobile_symbols": total_mobile_symbols,
                        "active_symbols": active_symbols,
                        "user_physical_bytes": o.endowment.fee_record.user_physical_bytes,
                        "decentralization_physical_bytes": o.endowment.fee_record.decentralization_physical_bytes,
                        "total_physical_bytes": o.endowment.fee_record.total_physical_bytes(),
                        "symbol_roots": o.roots.iter().map(|r| serde_json::json!({
                            "segment": r.segment,
                            "root": hex::encode(r.root),
                            "first_esi": r.first_esi,
                            "count": r.count,
                        })).collect::<Vec<_>>(),
                        "shares": shares,
                    })
                } else {
                    self.query_json(&Bud3Query::Object(*key))
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
            Bud3Query::GrantAt(tag, current_epoch) => {
                if let Some(row) = self.grants.get(tag) {
                    let expired = row.expires_at_epoch <= *current_epoch;
                    serde_json::json!({
                        "grant_tag": hex::encode(row.grant_tag),
                        "status": if expired { "expired" } else { "active" },
                        "current_epoch": current_epoch,
                        "one_time_pk": hex::encode(&row.one_time_pk),
                        "sealed_key_package": hex::encode(&row.sealed_key_package),
                        "expires_at_epoch": row.expires_at_epoch,
                    })
                } else if self.revoked_grants.contains(tag) {
                    serde_json::json!({
                        "grant_tag": hex::encode(tag),
                        "status": "revoked",
                        "current_epoch": current_epoch,
                    })
                } else {
                    serde_json::Value::Null
                }
            }
            Bud3Query::Nft(nft) => {
                let Some((key, owner)) = self.nfts.get(nft) else {
                    return serde_json::Value::Null;
                };
                let mut obj = self.query_json(&Bud3Query::Object(*key));
                if let Some(map) = obj.as_object_mut() {
                    map.insert("nft_id".to_string(), serde_json::json!(hex::encode(nft)));
                    map.insert(
                        "nft_owner".to_string(),
                        serde_json::json!(hex::encode(owner)),
                    );
                    if let Some((live_key, _)) = self.resolve_live_object(key) {
                        if live_key != *key {
                            map.insert(
                                "resolved_commitment".to_string(),
                                serde_json::json!(hex::encode(live_key)),
                            );
                        }
                    }
                } else {
                    obj = serde_json::json!({
                        "nft_id": hex::encode(nft),
                        "nft_owner": hex::encode(owner),
                        "commitment": hex::encode(key),
                        "status": "missing",
                    });
                }
                obj
            }
        }
    }

    /// Whether the registry is empty, including replacement redirects.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
            && self.public_index.is_empty()
            && self.nfts.is_empty()
            && self.tombstones.is_empty()
            && self.declines.is_empty()
            && self.custody_credits.is_empty()
            && self.presence_ppm.is_empty()
            && self.forfeited_pool_total == 0
            && self.grants.is_empty()
            && self.revoked_grants.is_empty()
            && self.base_deps.is_empty()
            && self.validator_quotas.is_empty()
            && self.replacements.is_empty()
            && self.paid_views.is_empty()
    }

    /// The registry state root over every serialized field, in deterministic order.
    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        let mut acc = hash_fields_bytes(&[REGISTRY_TAG, b"empty"]);
        let mut fold = |fields: &[&[u8]]| {
            let mut all: Vec<&[u8]> = vec![REGISTRY_TAG, &acc];
            all.extend_from_slice(fields);
            acc = hash_fields_bytes(&all);
        };
        for (k, o) in &self.objects {
            let content_kind = match o.record.content_id.kind {
                ContentIdKind::Public => 0u8,
                ContentIdKind::Sealed => 1u8,
            };
            let profile = o.record.profile;
            fold(&[
                b"obj",
                k,
                &o.owner,
                &[content_kind],
                &o.record.content_id.digest,
                &o.record.content_id.len.to_le_bytes(),
                &o.record.object_len.to_le_bytes(),
                &o.record.commitment,
                &profile.id.to_le_bytes(),
                &[profile.qr_version],
                &profile.symbol_size.to_le_bytes(),
                &profile.fps.to_le_bytes(),
                &profile.k_max.to_le_bytes(),
                &o.record.codec.to_le_bytes(),
                &o.record.symbols_per_segment.to_le_bytes(),
                &(o.record.symbol_roots.len() as u64).to_le_bytes(),
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
            for root in &o.record.symbol_roots {
                fold(&[b"record_root", root]);
            }
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
                let class = match s.share.class {
                    Class::Full => 0u8,
                    Class::Mobile => 1u8,
                };
                let (audit_present, audit_segment, audit_position, audit_sub_block, audit_last) = s
                    .open_audit
                    .map_or((0u8, 0u64, 0u64, 0u64, 0u64), |(a, last)| {
                        (1, a.segment, a.position, a.sub_block, last)
                    });
                fold(&[
                    b"share",
                    &s.segment.to_le_bytes(),
                    &s.share.validator,
                    &[class],
                    &s.share.first_esi.to_le_bytes(),
                    &s.share.symbols.to_le_bytes(),
                    &status,
                    &[audit_present],
                    &audit_segment.to_le_bytes(),
                    &audit_position.to_le_bytes(),
                    &audit_sub_block.to_le_bytes(),
                    &audit_last.to_le_bytes(),
                    &s.passes.to_le_bytes(),
                    &s.misses.to_le_bytes(),
                    &s.consecutive_misses.to_le_bytes(),
                    &[u8::from(s.lost)],
                    &(s.root as u64).to_le_bytes(),
                    &s.assigned_epoch.to_le_bytes(),
                ]);
            }
        }
        // The exact index is consensus state after snapshot restoration. The
        // node-local Bloom filter that accelerates it is deliberately excluded.
        for (digest, key) in self.public_index.iter() {
            fold(&[b"public_index", digest, key]);
        }
        for (nft, (key, holder)) in &self.nfts {
            fold(&[b"nft", nft, key, holder]);
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
        for (old, r) in &self.replacements {
            fold(&[
                b"repl",
                old,
                &r.new,
                &r.proposer,
                &r.content.digest,
                &r.content.len.to_le_bytes(),
                &r.old_object_len.to_le_bytes(),
                &r.new_object_len.to_le_bytes(),
                &r.proposed_at.to_le_bytes(),
                b"pub",
                &[u8::from(r.content.kind == ContentIdKind::Public)],
                &[u8::from(r.finalized)],
            ]);
        }
        for (receipt_id, pv) in &self.paid_views {
            fold(&[
                b"paid_view",
                receipt_id,
                &pv.payer,
                &pv.object,
                &pv.amount_atoms.to_le_bytes(),
                &pv.paid_at_epoch.to_le_bytes(),
            ]);
        }
        acc
    }
}

#[cfg(test)]
mod tests {
    use super::super::custody::prove;
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

    fn assert_entry_changes_root(
        label: &str,
        registry: &Bud3Registry,
        key: &ObjectKey,
        change: impl FnOnce(&mut ObjectEntry),
    ) {
        let mut changed = registry.clone();
        change(changed.objects.get_mut(key).unwrap());
        assert_ne!(changed.state_root(), registry.state_root(), "{label}");
    }

    #[test]
    fn registry_root_commits_object_and_share_fields() {
        let (upload, shares) = upload(b"root coverage");
        let key = upload.record.commitment;
        let mut registry = Bud3Registry::default();
        registry
            .register_object(addr(1), upload.record, shares, 0, 10)
            .unwrap();

        assert_entry_changes_root("content kind", &registry, &key, |o| {
            o.record.content_id.kind = ContentIdKind::Sealed;
        });
        assert_entry_changes_root("content length", &registry, &key, |o| {
            o.record.content_id.len += 1;
        });
        assert_entry_changes_root("record commitment", &registry, &key, |o| {
            o.record.commitment[0] ^= 1;
        });
        assert_entry_changes_root("profile id", &registry, &key, |o| {
            o.record.profile.id += 1;
        });
        assert_entry_changes_root("QR version", &registry, &key, |o| {
            o.record.profile.qr_version -= 1;
        });
        assert_entry_changes_root("symbol size", &registry, &key, |o| {
            o.record.profile.symbol_size += 1;
        });
        assert_entry_changes_root("frame rate", &registry, &key, |o| {
            o.record.profile.fps += 1;
        });
        assert_entry_changes_root("maximum source symbols", &registry, &key, |o| {
            o.record.profile.k_max += 1;
        });
        assert_entry_changes_root("codec", &registry, &key, |o| {
            o.record.codec += 1;
        });
        assert_entry_changes_root("symbol count", &registry, &key, |o| {
            o.record.symbols_per_segment += 1;
        });
        assert_entry_changes_root("record symbol root", &registry, &key, |o| {
            o.record.symbol_roots[0][0] ^= 1;
        });
        assert_entry_changes_root("share class", &registry, &key, |o| {
            o.shares[0].share.class = Class::Mobile;
        });
        assert_entry_changes_root("assignment epoch", &registry, &key, |o| {
            o.shares[0].assigned_epoch += 1;
        });
        assert_entry_changes_root("zero-valued audit is present", &registry, &key, |o| {
            o.shares[0].open_audit = Some((
                Audit {
                    segment: 0,
                    position: 0,
                    sub_block: 0,
                },
                0,
            ));
        });
        let mut audited = registry.clone();
        audited.objects.get_mut(&key).unwrap().shares[0].open_audit = Some((
            Audit {
                segment: 0,
                position: 0,
                sub_block: 0,
            },
            0,
        ));
        assert_entry_changes_root("audit segment", &audited, &key, |o| {
            o.shares[0].open_audit.as_mut().unwrap().0.segment = 1;
        });
    }

    #[test]
    fn registry_root_commits_reference_authority_and_exact_index() {
        let (upload, shares) = upload(b"bound reference");
        let key = upload.record.commitment;
        let digest = upload.record.content_id.digest;
        let mut registry = Bud3Registry::default();
        registry
            .register_object(addr(1), upload.record, shares, 0, 10)
            .unwrap();
        for h in [10u8, 11, 12, 13] {
            registry.ack(&key, &addr(h)).unwrap();
        }

        let mut alice = registry.clone();
        let mut bob = registry.clone();
        alice
            .bind_nft([9; 32], addr(1), Some(addr(1)), &key)
            .unwrap();
        bob.bind_nft([9; 32], addr(8), Some(addr(8)), &key).unwrap();
        assert_ne!(alice.state_root(), bob.state_root());
        assert!(alice.burn_reference(&[9; 32], &addr(1), 1).is_ok());
        assert_eq!(
            bob.burn_reference(&[9; 32], &addr(1), 1),
            Err(RegistryError::NotAuthorized)
        );
        assert_eq!(
            bob.burn_reference(&[9; 32], &addr(8), 1),
            Err(RegistryError::NotAuthorized),
            "non-owner cannot tombstone sole reference"
        );

        let mut without_index = registry.clone();
        without_index.public_index.remove(&digest);
        assert_ne!(without_index.state_root(), registry.state_root());

        // Even an inconsistent snapshot must not hide orphaned state.
        let empty = Bud3Registry::default();
        let mut orphan_nft = empty.clone();
        orphan_nft.nfts.insert([9; 32], (key, addr(7)));
        assert!(!orphan_nft.is_empty());
        assert_ne!(orphan_nft.state_root(), empty.state_root());
        let mut orphan_index = empty.clone();
        orphan_index.public_index.insert(digest, key);
        assert!(!orphan_index.is_empty());
        assert_ne!(orphan_index.state_root(), empty.state_root());
    }

    #[test]
    fn registry_root_survives_snapshot_and_index_rebuild() {
        let (upload, shares) = upload(b"snapshot root");
        let key = upload.record.commitment;
        let mut registry = Bud3Registry::default();
        registry
            .register_object(addr(1), upload.record, shares, 0, 10)
            .unwrap();
        registry
            .bind_nft([9; 32], addr(7), Some(addr(7)), &key)
            .unwrap();
        registry.ack(&key, &addr(10)).unwrap();

        let snapshot = serde_json::to_vec(&registry).unwrap();
        let restored: Bud3Registry = serde_json::from_slice(&snapshot).unwrap();
        assert_eq!(registry, restored);
        assert_eq!(registry.state_root(), restored.state_root());
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
        for (_, s) in &shares {
            r.ack(&key, &s.validator).unwrap();
        }
        r.bind_nft([1; 32], addr(1), Some(addr(1)), &key).unwrap();
        r.bind_nft([2; 32], addr(2), Some(addr(2)), &key).unwrap();
        assert_eq!(r.refcount(&key), 2);
        assert_eq!(
            r.bind_nft([2; 32], addr(2), Some(addr(2)), &key),
            Err(RegistryError::NftAlreadyBound)
        );
        assert_eq!(
            r.burn_reference(&[1; 32], &addr(2), 5),
            Err(RegistryError::NotAuthorized)
        );
        assert_eq!(r.burn_reference(&[1; 32], &addr(1), 5), Ok(false));
        assert_eq!(r.refcount(&key), 1);
        // A non-owner holding the last reference cannot delete the object:
        // the reference is self-declared, so it is not authority over it.
        assert_eq!(
            r.burn_reference(&[2; 32], &addr(2), 6),
            Err(RegistryError::NotAuthorized)
        );
        assert_eq!(r.refcount(&key), 1);
        assert!(r.object(&key).is_some());
        assert_eq!(r.tombstone(&key), None);
        // The owner deleting the last reference does delete the object.
        r.bind_nft([3; 32], addr(1), Some(addr(1)), &key).unwrap();
        assert_eq!(r.burn_reference(&[2; 32], &addr(2), 6), Ok(false));
        assert_eq!(r.burn_reference(&[3; 32], &addr(1), 6), Ok(true));
        assert!(r.object(&key).is_none());
        assert_eq!(r.tombstone(&key), Some(6));
        // Deletion is final.
        assert_eq!(
            r.register_object(addr(1), up.record, shares, 7, 100),
            Err(RegistryError::Tombstoned)
        );
        assert_eq!(
            r.bind_nft([3; 32], addr(1), Some(addr(1)), &key),
            Err(RegistryError::Tombstoned)
        );
    }

    #[test]
    fn owner_delete_object_ignores_third_party_nft_references() {
        let mut r = Bud3Registry::default();
        let (up, shares) = upload(b"owner deletable content");
        let key = up.record.commitment;
        r.register_object(addr(1), up.record, shares.clone(), 0, 100)
            .unwrap();
        for (_, s) in &shares {
            r.ack(&key, &s.validator).unwrap();
        }
        // A third party binds its own NFT to the owner's public object.
        r.bind_nft([9; 32], addr(2), Some(addr(2)), &key).unwrap();
        assert_eq!(r.refcount(&key), 1);
        // The third party cannot delete the owner's object.
        assert_eq!(
            r.delete_object(&key, &addr(2), 5),
            Err(RegistryError::NotAuthorized)
        );
        assert!(r.object(&key).is_some());
        // The owner can: the third-party reference is unbound with it.
        r.delete_object(&key, &addr(1), 6).unwrap();
        assert!(r.object(&key).is_none());
        assert_eq!(r.tombstone(&key), Some(6));
        assert_eq!(r.refcount(&key), 0);
        // The NFT itself is untouched; only this registry's reference is gone.
        assert_eq!(
            r.burn_reference(&[9; 32], &addr(2), 7),
            Err(RegistryError::UnknownNft)
        );
        // Deletion is final.
        assert_eq!(
            r.delete_object(&key, &addr(1), 8),
            Err(RegistryError::UnknownObject)
        );
    }

    #[test]
    fn public_content_is_deduplicated_and_sealed_never_reads_the_index() {
        let mut r = Bud3Registry::default();
        let (up, shares) = upload(b"same bytes");
        let key = up.record.commitment;
        r.register_object(addr(1), up.record.clone(), shares.clone(), 0, 10)
            .unwrap();
        // Before custody confirmation, an unacked upload does not hijack public_index.
        assert!(r.public_object(&up.record.content_id.digest).is_none());
        let mut rival = up.record.clone();
        rival.commitment = [0xEF; 32];
        assert_eq!(
            r.register_object(addr(9), rival, shares.clone(), 0, 10),
            Ok(Registered::New([0xEF; 32]))
        );
        for h in [10u8, 11, 12, 13] {
            r.ack(&key, &addr(h)).unwrap();
        }
        assert_eq!(r.public_object(&up.record.content_id.digest), Some(key));
        let root = r.state_root();
        // A second upload of the same confirmed public content stores nothing.
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
        r.register_object(addr(1), up.record, shares.clone(), 0, 10)
            .unwrap();
        for (_, s) in &shares {
            r.ack(&key, &s.validator).unwrap();
        }
        assert_eq!(r.renew(&key, 5), Ok(15));
        assert!(r.expire(15).is_empty());
        assert_eq!(r.expire(16), vec![key]);
        assert_eq!(r.tombstone(&key), Some(16));
        assert_eq!(r.renew(&key, 1), Err(RegistryError::UnknownObject));
    }

    #[test]
    fn unconfirmed_squatter_cannot_block_real_owner_or_poison_tombstone() {
        let mut r = Bud3Registry::default();
        let (up, shares) = upload(b"victim content");
        let raw_key = up.record.commitment;
        let squatter = addr(99);
        let victim = addr(1);

        // Squatter pre-registers the commitment for 1 epoch without ever confirming custody.
        assert_eq!(
            r.register_object(squatter, up.record.clone(), shares.clone(), 0, 1),
            Ok(Registered::New(raw_key))
        );

        // Victim registering the same commitment while squatter is unconfirmed
        // succeeds immediately under a claimant-scoped key instead of being blocked.
        let Registered::New(victim_key) = r
            .register_object(victim, up.record.clone(), shares.clone(), 0, 100)
            .expect("victim must not be blocked by unconfirmed squatter")
        else {
            panic!("expected fresh claimant-scoped registration for victim");
        };
        assert_ne!(victim_key, raw_key);

        // Victim's validators confirm custody; victim wins public_index.
        for (_, s) in &shares {
            r.ack(&victim_key, &s.validator).unwrap();
        }
        assert_eq!(
            r.public_object(&up.record.content_id.digest),
            Some(victim_key)
        );

        // When squatter's unconfirmed registration expires, it writes NO tombstone
        // on `raw_key` so the commitment is never poisoned.
        let expired = r.expire(2);
        assert_eq!(expired, vec![raw_key]);
        assert_eq!(r.tombstone(&raw_key), None);
        assert!(r.object(&victim_key).is_some());
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
        let valid_witness = super::super::repair::RepairWitness::ProvenSymbols(
            super::super::repair::build_repair_proven_witness(0, &up.segments[0], &up.segments[0])
                .unwrap(),
        );
        let reuse = Share {
            first_esi: 15,
            ..new_share
        };
        assert!(matches!(
            r.record_repair(
                &key,
                SegmentRepair {
                    segment: 0,
                    new_shares: vec![reuse],
                    new_symbols: fresh.clone(),
                    new_root,
                    witness: &valid_witness,
                },
                100
            ),
            Err(RegistryError::BadRepair(_))
        ));
        let short = Share {
            symbols: 4,
            ..new_share
        };
        assert!(matches!(
            r.record_repair(
                &key,
                SegmentRepair {
                    segment: 0,
                    new_shares: vec![short],
                    new_symbols: fresh.clone(),
                    new_root,
                    witness: &valid_witness,
                },
                100
            ),
            Err(RegistryError::BadRepair("fewer new symbols than lost"))
        ));
        // Forged or mismatched symbol root is refused.
        assert!(matches!(
            r.record_repair(
                &key,
                SegmentRepair {
                    segment: 0,
                    new_shares: vec![new_share],
                    new_symbols: fresh.clone(),
                    new_root: [0xFF; 32],
                    witness: &valid_witness,
                },
                100
            ),
            Err(RegistryError::BadRepair(_))
        ));
        // Fabricated symbols paired with their own matching root are ALSO refused!
        let mut forged = fresh.clone();
        forged[0].data.fill(0x5A);
        let forged_leaves: Vec<(u32, [u8; 32])> = forged
            .iter()
            .map(|x| (x.esi, symbol_leaf(&x.data)))
            .collect();
        let forged_root = symbol_root(&forged_leaves);
        assert!(matches!(
            r.record_repair(
                &key,
                SegmentRepair {
                    segment: 0,
                    new_shares: vec![new_share],
                    new_symbols: forged,
                    new_root: forged_root,
                    witness: &valid_witness,
                },
                100
            ),
            Err(RegistryError::BadRepair(_))
        ));
        // Empty witness and < 3 validator attestations are refused.
        assert!(matches!(
            r.record_repair(
                &key,
                SegmentRepair {
                    segment: 0,
                    new_shares: vec![new_share],
                    new_symbols: fresh.clone(),
                    new_root,
                    witness: &super::super::repair::RepairWitness::ProvenSymbols(Vec::new()),
                },
                100
            ),
            Err(RegistryError::BadRepair(_))
        ));
        assert!(matches!(
                r.record_repair(
                    &key,
                    SegmentRepair {
                        segment: 0,
                        new_shares: vec![new_share],
                        new_symbols: fresh.clone(),
                        new_root,
                        witness: &super::super::repair::RepairWitness::ValidatorAttestations(
                            Vec::new()
                        ),
                    },
                    100
                ),
                Err(RegistryError::BadRepair(_))
            ));
        assert_eq!(
            super::super::tx::apply(
                &mut r,
                addr(30),
                super::super::tx::StorageTxV3::RecordRepair {
                    object: key,
                    segment: 0,
                    new_shares: vec![new_share],
                    new_symbols: fresh.clone(),
                    new_root,
                    witness: valid_witness,
                },
                100,
            ),
            Ok(super::super::tx::Applied::Repaired)
        );
        assert_eq!(r.object(&key).unwrap().next_esi, vec![25]);

        // Repair placements get their own full three-epoch acknowledgement
        // window; at epoch 100 an old epoch-zero assignment would hand over
        // immediately, even though the replacement has not had time to ack.
        assert_eq!(
            r.object(&key)
                .unwrap()
                .shares
                .iter()
                .find(|s| s.share.validator == addr(20))
                .unwrap()
                .assigned_epoch,
            100
        );
        assert_eq!(
            r.handover_unacked_shares(102, &[(addr(21), Class::Full)]),
            0
        );
        assert!(r
            .object(&key)
            .unwrap()
            .shares
            .iter()
            .any(|s| s.share.validator == addr(20) && s.status == ShareStatus::Pending));
        let mut restored: Bud3Registry =
            serde_json::from_slice(&serde_json::to_vec(&r).unwrap()).unwrap();
        assert_eq!(restored.state_root(), r.state_root());
        assert_eq!(
            restored.handover_unacked_shares(103, &[(addr(21), Class::Full)]),
            1
        );
        assert!(restored
            .object(&key)
            .unwrap()
            .shares
            .iter()
            .any(|s| s.share.validator == addr(21) && s.assigned_epoch == 103));

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

    #[test]
    fn security_gates_enforce_content_ceiling_sealed_bind_nft_grant_signer_and_public_index() {
        use super::super::grants::{compute_grant_tag, seal_grant_key_package, GrantRow};
        use super::super::keys::{derive_grant_one_time_keypair, derive_object_content_key};
        use super::super::pipeline::prepare_sealed_upload;
        use crate::crypto::hpke::HpkeKeyPair;

        let mut r = Bud3Registry::default();
        let (mut big_up, big_shares) = upload(b"ceiling check");
        big_up.record.object_len = Bud3Limits::TESTNET_DEFAULT.max_content_bytes + 1;
        assert!(matches!(
            r.register_object(addr(1), big_up.record, big_shares, 0, 10),
            Err(RegistryError::BadRecord(_))
        ));

        // Non-owner cannot bind an NFT to someone else's sealed object.
        let owner = addr(1);
        let attacker = addr(9);
        let owner_secret = [0x44u8; 32];
        let content_key = derive_object_content_key(&owner_secret, 1);
        let sealed_up = prepare_sealed_upload(
            b"sealed private object",
            &content_key,
            [0x11; 24],
            &P,
            &Bud3Limits::default(),
            20,
        )
        .unwrap();
        let sealed_key = sealed_up.record.commitment;
        let sealed_shares: Vec<(u64, Share)> = (0..sealed_up.segments.len() as u64)
            .flat_map(|seg| {
                (0..4u8).map(move |h| {
                    (
                        seg,
                        Share {
                            validator: addr(10 + h),
                            class: if h == 3 { Class::Mobile } else { Class::Full },
                            first_esi: u32::from(h) * 5,
                            symbols: 5,
                        },
                    )
                })
            })
            .collect();
        r.register_object(owner, sealed_up.record, sealed_shares, 0, 10)
            .unwrap();
        assert_eq!(
            r.bind_nft([0x77; 32], attacker, Some(attacker), &sealed_key),
            Err(RegistryError::NotAuthorized)
        );
        r.bind_nft([0x77; 32], owner, Some(owner), &sealed_key)
            .unwrap();

        // IssueViewGrant refuses non-holder signers and mismatched grant tags.
        let grantee = HpkeKeyPair::from_seed(&[0x55u8; 32]).unwrap();
        let nonce = [0x22u8; 32];
        let tag = compute_grant_tag(&[0x77; 32], &nonce);
        let (_, otpk) = derive_grant_one_time_keypair(&owner_secret, &[0x77; 32], &nonce).unwrap();
        let pkg =
            seal_grant_key_package(grantee.public_key(), &tag, &sealed_key, &content_key).unwrap();
        let row = GrantRow {
            grant_tag: tag,
            one_time_pk: otpk,
            sealed_key_package: pkg,
            expires_at_epoch: 10,
        };
        assert_eq!(
            r.issue_view_grant(&[0x77; 32], &nonce, &attacker, row.clone(), 1),
            Err(RegistryError::NotAuthorized)
        );
        assert_eq!(
            r.issue_view_grant(&[0x77; 32], &[0x23u8; 32], &owner, row.clone(), 1),
            Err(RegistryError::Grant(GrantBud3Error::InvalidGrantTag))
        );
        r.issue_view_grant(&[0x77; 32], &nonce, &owner, row, 1)
            .unwrap();

        // Already-confirmed public_index entry is not hijacked when a second upload confirms.
        let (pub_up, pub_shares) = upload(b"canonical public bytes");
        let first_key = pub_up.record.commitment;
        r.register_object(addr(1), pub_up.record.clone(), pub_shares.clone(), 0, 10)
            .unwrap();
        let mut second = pub_up.record.clone();
        second.commitment = [0x9A; 32];
        r.register_object(addr(2), second, pub_shares, 0, 10)
            .unwrap();
        for h in 10..=13u8 {
            r.ack(&first_key, &addr(h)).unwrap();
        }
        assert_eq!(
            r.public_object(&pub_up.record.content_id.digest),
            Some(first_key)
        );
        for h in 10..=13u8 {
            r.ack(&[0x9A; 32], &addr(h)).unwrap();
        }
        assert_eq!(
            r.public_object(&pub_up.record.content_id.digest),
            Some(first_key),
            "existing confirmed public_index entry must not be overwritten"
        );
    }

    #[test]
    fn bind_nft_refuses_unverified_and_third_party_nft_owners() {
        let mut r = Bud3Registry::default();
        let (up, shares) = upload(b"nft ownership guard");
        let key = up.record.commitment;
        r.register_object(addr(1), up.record, shares, 0, 50)
            .unwrap();

        let root_before = r.state_root();
        let nft_id = [0x44; 32];
        assert_eq!(
            r.bind_nft(nft_id, addr(2), None, &key),
            Err(RegistryError::NotAuthorized),
            "unresolvable NFT id must be refused"
        );
        assert_eq!(
            r.bind_nft(nft_id, addr(2), Some(addr(1)), &key),
            Err(RegistryError::NotAuthorized),
            "non-owner cannot squat another holder's NFT id"
        );
        assert_eq!(r.state_root(), root_before);

        r.bind_nft(nft_id, addr(1), Some(addr(1)), &key).unwrap();
        assert_eq!(r.refcount(&key), 1);
    }

    #[test]
    fn paid_view_receipts_expire_and_drop_with_their_object() {
        let mut r = Bud3Registry::default();
        let (up, shares) = upload(b"paid view pruning");
        let key = up.record.commitment;
        let lifetime = PAID_VIEW_RETENTION_EPOCHS
            .saturating_mul(2)
            .saturating_add(10);
        r.register_object(addr(1), up.record, shares, 1, lifetime)
            .unwrap();

        let receipt_id = [0xA1; 32];
        let receipt = PaidViewReceipt {
            payer: addr(2),
            object: key,
            receipt_id,
            fee_paid_atoms: MIN_PAID_VIEW_FEE_ATOMS,
        };
        r.record_paid_view(addr(2), key, receipt_id, MIN_PAID_VIEW_FEE_ATOMS, 5)
            .unwrap();
        assert!(r.verify_paid_view(&receipt));

        // Still valid at the retention boundary.
        r.expire(5 + PAID_VIEW_RETENTION_EPOCHS);
        assert!(r.verify_paid_view(&receipt));

        // Pruned once past PAID_VIEW_RETENTION_EPOCHS.
        let root_with_receipt = r.state_root();
        r.expire(6 + PAID_VIEW_RETENTION_EPOCHS);
        assert!(!r.verify_paid_view(&receipt));
        assert!(r.paid_views.is_empty());
        assert_ne!(r.state_root(), root_with_receipt);

        // Receipts for a deleted object are dropped immediately on deletion.
        let second_id = [0xA2; 32];
        let second = PaidViewReceipt {
            payer: addr(3),
            object: key,
            receipt_id: second_id,
            fee_paid_atoms: MIN_PAID_VIEW_FEE_ATOMS,
        };
        r.record_paid_view(
            addr(3),
            key,
            second_id,
            MIN_PAID_VIEW_FEE_ATOMS,
            7 + PAID_VIEW_RETENTION_EPOCHS,
        )
        .unwrap();
        assert!(r.verify_paid_view(&second));
        r.expire(1 + lifetime + 1);
        assert!(r.object(&key).is_none());
        assert!(!r.verify_paid_view(&second));
        assert!(r.paid_views.is_empty());
    }

    #[test]
    fn single_validator_placement_is_refused_and_cannot_self_certify_custody() {
        let mut r = Bud3Registry::default();
        let (up, _) = upload(b"single validator cannot self certify custody");
        let syms = up.record.symbols_per_segment;
        let single = vec![(
            0,
            Share {
                validator: addr(9),
                class: Class::Full,
                first_esi: 0,
                symbols: syms,
            },
        )];
        assert_eq!(
            r.register_object(addr(1), up.record.clone(), single, 0, 10),
            Err(RegistryError::BadPlacement(
                "each segment requires at least two distinct validators",
            ))
        );
        // Splitting the same validator into two shares still fails the distinct-validator rule.
        let half = syms / 2;
        let duplicate_same_validator = vec![
            (
                0,
                Share {
                    validator: addr(9),
                    class: Class::Full,
                    first_esi: 0,
                    symbols: half,
                },
            ),
            (
                0,
                Share {
                    validator: addr(9),
                    class: Class::Full,
                    first_esi: half,
                    symbols: syms - half,
                },
            ),
        ];
        assert_eq!(
            r.register_object(addr(1), up.record.clone(), duplicate_same_validator, 0, 10),
            Err(RegistryError::BadPlacement(
                "duplicate validator in segment",
            ))
        );
        // Even with two distinct validators, repeating either holder in the same segment is refused.
        let third = syms / 3;
        let repeated_with_peer = vec![
            (
                0,
                Share {
                    validator: addr(9),
                    class: Class::Full,
                    first_esi: 0,
                    symbols: third,
                },
            ),
            (
                0,
                Share {
                    validator: addr(10),
                    class: Class::Full,
                    first_esi: third,
                    symbols: third,
                },
            ),
            (
                0,
                Share {
                    validator: addr(9),
                    class: Class::Full,
                    first_esi: third * 2,
                    symbols: syms - third * 2,
                },
            ),
        ];
        assert_eq!(
            r.register_object(addr(1), up.record, repeated_with_peer, 0, 10),
            Err(RegistryError::BadPlacement(
                "duplicate validator in segment",
            ))
        );
    }

    /// A fixed three-signature witness is not a finality certificate. Until the
    /// repair path carries a seat- or stake-weighted quorum certificate, the
    /// cryptographic symbol witness is the only fail-closed admission path.
    #[test]
    fn minority_validator_attestations_cannot_authorize_a_segment_repair() {
        let mut r = Bud3Registry::default();
        let content: Vec<u8> = (0u16..1500).map(|i| (i.wrapping_mul(31)) as u8).collect();
        let (up, shares) = upload(&content);
        let key = up.record.commitment;
        r.register_object(addr(1), up.record.clone(), shares, 0, 1_000)
            .unwrap();
        for holder in 10u8..14 {
            r.ack(&key, &addr(holder)).unwrap();
        }
        assert_eq!(r.mark_unseen(&addr(13)), 1);
        assert_eq!(r.repairs_due(&key), vec![0]);

        let object_bytes = super::super::bof1::Object::raw_public(&content).encode();
        let encoder = SegmentEncoder::new(0, &object_bytes, &P).unwrap();
        let k = encoder.k();
        let repaired = encoder.repair_symbols(20 - k, 5).unwrap();
        let new_root = symbol_root(
            &repaired
                .iter()
                .map(|symbol| (symbol.esi, symbol_leaf(&symbol.data)))
                .collect::<Vec<_>>(),
        );
        let new_share = Share {
            validator: addr(21),
            class: Class::Full,
            first_esi: 20,
            symbols: 5,
        };

        let validator_keys: BTreeMap<Address, Vec<u8>> = [13u8, 20, 21, 30, 31, 32, 33, 34]
            .into_iter()
            .map(|id| {
                (
                    addr(id),
                    crate::crypto::pq::ml_dsa_public_key(
                        crate::crypto::scheme::SchemeId::ML_DSA_65,
                        &[id; 32],
                    )
                    .unwrap(),
                )
            })
            .collect();
        let original_root = up.record.symbol_roots[0];
        let claim = super::super::repair::RepairClaim {
            object: &key,
            segment: 0,
            first_esi: 20,
            count: 5,
            new_root: &new_root,
            original_segment_root: &original_root,
        };
        let attestations = [30u8, 31, 32]
            .into_iter()
            .map(|id| {
                super::super::repair::sign_repair_attestation(addr(id), &[id; 32], &claim).unwrap()
            })
            .collect();
        let witness = super::super::repair::RepairWitness::ValidatorAttestations(attestations);

        let result = r.record_repair_with_validators(
            &key,
            SegmentRepair {
                segment: 0,
                new_shares: vec![new_share],
                new_symbols: repaired,
                new_root,
                witness: &witness,
            },
            Some(&addr(20)),
            &validator_keys,
            (crate::core::transaction::DEFAULT_CHAIN_ID, 100),
        );
        assert!(
            result.is_err(),
            "three independent signatures are not a stake- or seat-weighted finality certificate"
        );
    }

    #[test]
    fn unacknowledged_repair_share_expires_after_deadline_and_unblocks_segment() {
        let mut r = Bud3Registry::default();
        let content: Vec<u8> = (0u16..1500).map(|i| (i.wrapping_mul(31)) as u8).collect();
        let (up, shares) = upload(&content);
        let key = up.record.commitment;
        r.register_object(addr(1), up.record.clone(), shares, 0, 1000)
            .unwrap();
        for h in 0..4u8 {
            r.ack(&key, &addr(10 + h)).unwrap();
        }
        assert_eq!(r.mark_unseen(&addr(13)), 1);
        assert_eq!(r.repairs_due(&key), vec![0]);

        let obj_bytes = super::super::bof1::Object::raw_public(&content).encode();
        let enc = SegmentEncoder::new(0, &obj_bytes, &P).unwrap();
        let k = enc.k();
        let witness = super::super::repair::RepairWitness::ProvenSymbols(
            super::super::repair::build_repair_proven_witness(0, &up.segments[0], &up.segments[0])
                .unwrap(),
        );

        let batch1 = enc.repair_symbols(20 - k, 5).unwrap();
        let root1 = symbol_root(
            &batch1
                .iter()
                .map(|x| (x.esi, symbol_leaf(&x.data)))
                .collect::<Vec<_>>(),
        );
        // Repair placed on silent holder addr(20) at epoch 10.
        r.record_repair(
            &key,
            SegmentRepair {
                segment: 0,
                new_shares: vec![Share {
                    validator: addr(20),
                    class: Class::Full,
                    first_esi: 20,
                    symbols: 5,
                }],
                new_symbols: batch1,
                new_root: root1,
                witness: &witness,
            },
            10,
        )
        .unwrap();

        // Phantom unacknowledged share never hides the loss from `repairs_due`.
        assert_eq!(r.repairs_due(&key), vec![0]);

        let batch2 = enc.repair_symbols(25 - k, 5).unwrap();
        let root2 = symbol_root(
            &batch2
                .iter()
                .map(|x| (x.esi, symbol_leaf(&x.data)))
                .collect::<Vec<_>>(),
        );

        // Inside the 3-epoch ack window (epoch 12), overlapping repair is still refused.
        assert_eq!(
            r.record_repair(
                &key,
                SegmentRepair {
                    segment: 0,
                    new_shares: vec![Share {
                        validator: addr(21),
                        class: Class::Full,
                        first_esi: 25,
                        symbols: 5,
                    }],
                    new_symbols: batch2.clone(),
                    new_root: root2,
                    witness: &witness,
                },
                12,
            ),
            Err(RegistryError::BadRepair(
                "segment already has an unsettled repair"
            ))
        );

        // Once the 3-epoch ack window elapses (epoch 13), `close_windows` retires the
        // silent pending share, `settle_repairs` must NOT vacuously drop the lost share,
        // and a replacement repair on responsive holder addr(21) succeeds cleanly.
        r.close_windows(13);
        assert_eq!(r.settle_repairs(), 0);
        assert_eq!(r.repairs_due(&key), vec![0]);

        r.record_repair(
            &key,
            SegmentRepair {
                segment: 0,
                new_shares: vec![Share {
                    validator: addr(21),
                    class: Class::Full,
                    first_esi: 25,
                    symbols: 5,
                }],
                new_symbols: batch2,
                new_root: root2,
                witness: &witness,
            },
            13,
        )
        .unwrap();
        assert_eq!(r.ack(&key, &addr(21)).unwrap(), 1);
        assert_eq!(r.settle_repairs(), 1);
        assert!(r.repairs_due(&key).is_empty());
    }

    #[test]
    fn paid_view_receipts_cap_per_payer_and_reap_stale_entries() {
        let mut r = Bud3Registry::default();
        let (up, shares) = upload(b"payer cap and eager reaping");
        let key = up.record.commitment;
        let lifetime = PAID_VIEW_RETENTION_EPOCHS
            .saturating_mul(2)
            .saturating_add(20);
        r.register_object(addr(1), up.record, shares, 1, lifetime)
            .unwrap();

        for i in 0..MAX_PAID_VIEWS_PER_PAYER_OBJECT {
            let mut rid = [0xC0; 32];
            rid[0] = i as u8;
            r.record_paid_view(addr(7), key, rid, MIN_PAID_VIEW_FEE_ATOMS, 2)
                .unwrap();
        }
        assert_eq!(
            r.record_paid_view(addr(7), key, [0xEE; 32], MIN_PAID_VIEW_FEE_ATOMS, 2),
            Err(RegistryError::InvalidPaidView(
                "paid view receipt limit reached for payer on object"
            ))
        );
        // Once past retention, `record_paid_view` eagerly reaps stale receipts even
        // before `expire` runs.
        r.record_paid_view(
            addr(7),
            key,
            [0xEF; 32],
            MIN_PAID_VIEW_FEE_ATOMS,
            3 + PAID_VIEW_RETENTION_EPOCHS,
        )
        .unwrap();
        assert_eq!(r.paid_views.len(), 1);
    }

    #[test]
    fn verify_paid_view_at_enforces_expiry_and_minimum_fee() {
        let mut r = Bud3Registry::default();
        let (up, shares) = upload(b"paid view at epoch check");
        let key = up.record.commitment;
        let lifetime = PAID_VIEW_RETENTION_EPOCHS.saturating_add(50);
        r.register_object(addr(1), up.record, shares, 1, lifetime)
            .unwrap();

        let receipt_id = [0xD1; 32];
        r.record_paid_view(addr(2), key, receipt_id, MIN_PAID_VIEW_FEE_ATOMS, 5)
            .unwrap();

        let zero_fee = PaidViewReceipt {
            payer: addr(2),
            object: key,
            receipt_id,
            fee_paid_atoms: 0,
        };
        assert!(!r.verify_paid_view(&zero_fee));

        let valid = PaidViewReceipt {
            payer: addr(2),
            object: key,
            receipt_id,
            fee_paid_atoms: MIN_PAID_VIEW_FEE_ATOMS,
        };
        assert!(r.verify_paid_view_at(&valid, 5 + PAID_VIEW_RETENTION_EPOCHS));
        // Expired at `paid_at + retention + 1` even before `expire` runs.
        assert!(!r.verify_paid_view_at(&valid, 6 + PAID_VIEW_RETENTION_EPOCHS));
    }

    #[test]
    fn expire_evicts_and_revokes_grants_at_exact_expiry_epoch() {
        use super::super::grants::{compute_grant_tag, seal_grant_key_package, GrantBud3Error};
        use super::super::keys::{derive_grant_one_time_keypair, derive_object_content_key};
        use crate::crypto::hpke::HpkeKeyPair;

        let mut r = Bud3Registry::default();
        let (up, shares) = upload(b"grant exact expiry");
        let key = up.record.commitment;
        r.register_object(addr(1), up.record, shares, 0, 100)
            .unwrap();
        let nft = [0x31; 32];
        r.bind_nft(nft, addr(1), Some(addr(1)), &key).unwrap();

        let owner_secret = [0x55; 32];
        let nonce = [0x44; 32];
        let tag = compute_grant_tag(&nft, &nonce);
        let (_, otpk) = derive_grant_one_time_keypair(&owner_secret, &nft, &nonce).unwrap();
        let grantee = HpkeKeyPair::from_seed(&[0x66; 32]).unwrap();
        let content_key = derive_object_content_key(&owner_secret, 1);
        let pkg = seal_grant_key_package(grantee.public_key(), &tag, &key, &content_key).unwrap();
        let row = GrantRow {
            grant_tag: tag,
            one_time_pk: otpk,
            sealed_key_package: pkg,
            expires_at_epoch: 10,
        };
        r.issue_view_grant(&nft, &nonce, &addr(1), row.clone(), 1)
            .unwrap();

        r.expire(10);
        assert!(r.active_grant(&tag, 10).is_none());
        assert!(r.grant_row(&tag).is_none());
        assert_eq!(
            r.issue_view_grant(&nft, &nonce, &addr(1), row, 10),
            Err(RegistryError::Grant(GrantBud3Error::DuplicateOrRevokedTag))
        );
    }

    #[test]
    fn bind_nft_refuses_pending_replacement_and_release_replaced_preserves_refs() {
        use super::super::replace::sign_replace_attestation;
        use crate::crypto::pq::ml_dsa_public_key;
        use crate::crypto::scheme::SchemeId;

        let mut r = Bud3Registry::default();
        let (old_up, old_shares) = upload(b"replace reference migration");
        let old_key = old_up.record.commitment;
        r.register_object(addr(1), old_up.record.clone(), old_shares.clone(), 0, 50)
            .unwrap();
        for (_, sh) in &old_shares {
            r.ack(&old_key, &sh.validator).unwrap();
        }
        let existing_nft = [0x61; 32];
        r.bind_nft(existing_nft, addr(1), Some(addr(1)), &old_key)
            .unwrap();

        let mut new_record = old_up.record;
        new_record.codec = if new_record.codec == 0 { 1 } else { 0 };
        new_record.object_len = new_record.object_len.saturating_add(1);
        new_record.commitment = [0xFE; 32];
        let new_shares = old_shares;
        let validator_keys: BTreeMap<Address, Vec<u8>> = [10u8, 11, 12]
            .into_iter()
            .map(|v| {
                (
                    addr(v),
                    ml_dsa_public_key(SchemeId::ML_DSA_65, &[v; 32]).unwrap(),
                )
            })
            .collect();
        let attestations: Vec<_> = [10u8, 11, 12]
            .into_iter()
            .map(|v| {
                sign_replace_attestation(addr(v), &[v; 32], &old_key, &new_record, &new_shares)
                    .unwrap()
            })
            .collect();
        let new_key = r
            .replace_object(
                (addr(10), 10_000),
                &old_key,
                new_record,
                new_shares.clone(),
                &attestations,
                (
                    crate::core::transaction::DEFAULT_CHAIN_ID,
                    1,
                    &validator_keys,
                ),
            )
            .unwrap();

        let late_nft = [0x62; 32];
        assert!(matches!(
            r.bind_nft(late_nft, addr(2), Some(addr(2)), &old_key),
            Err(RegistryError::BadRecord(_))
        ));
        r.bind_nft(late_nft, addr(2), Some(addr(2)), &new_key)
            .unwrap();

        for (_, sh) in &new_shares {
            r.ack(&new_key, &sh.validator).unwrap();
        }
        assert_eq!(r.nft_binding(&existing_nft), Some((new_key, addr(1))));
        assert_eq!(r.nft_binding(&late_nft), Some((new_key, addr(2))));

        let nft_view = r.query_json(&Bud3Query::Nft(existing_nft));
        assert_eq!(nft_view["status"], "live");
        assert_eq!(nft_view["commitment"], hex::encode(new_key));
        assert_eq!(nft_view["nft_id"], hex::encode(existing_nft));
        assert_eq!(nft_view["nft_owner"], hex::encode(addr(1)));
        assert!(r.query_json(&Bud3Query::Nft([0xFE; 32])).is_null());

        let placement_view = r.query_json(&Bud3Query::Placement(new_key));
        assert_eq!(placement_view["status"], "live");
        assert_eq!(placement_view["n_full"], 3);
        assert!(placement_view["shares"]
            .as_array()
            .is_some_and(|s| s.len() == 3));
        assert_eq!(
            r.query_json(&Bud3Query::Placement(old_key))["status"],
            "replaced"
        );
    }

    #[test]
    fn query_json_grant_at_distinguishes_active_expired_and_revoked_grants() {
        use super::super::content_id::ContentKey;
        use super::super::grants::{build_grant_row, grant_revoke_digest};
        use super::super::keys::{
            derive_grant_one_time_keypair, seal_key_package, sign_with_grant_one_time_key,
        };
        use crate::crypto::hpke::HpkeKeyPair;

        let mut r = Bud3Registry::default();
        let owner = addr(1);
        let (up, shares) = upload(b"sealed grant status payload");
        let obj = up.record.commitment;
        r.register_object(owner, up.record, shares, 0, 20).unwrap();
        let nft = [0x91u8; 32];
        r.bind_nft(nft, owner, Some(owner), &obj).unwrap();

        let seed = [0x44u8; 32];
        let nonce = [0x55u8; 32];
        let (otk_seed, otk_pk) = derive_grant_one_time_keypair(&seed, &nft, &nonce).unwrap();
        let grantee = HpkeKeyPair::from_seed(&[0x66u8; 32]).unwrap();
        let tag = super::super::grants::compute_grant_tag(&nft, &nonce);
        let pkg =
            seal_key_package(grantee.public_key(), &tag, &obj, &ContentKey([0x77u8; 32])).unwrap();
        let row = build_grant_row(&nft, &nonce, otk_pk, pkg, 15, 0).unwrap();
        r.issue_view_grant(&nft, &nonce, &owner, row, 0).unwrap();

        let active = r.query_json(&Bud3Query::GrantAt(tag, 14));
        assert_eq!(active["status"], "active");
        assert_eq!(active["current_epoch"], 14);

        let expired = r.query_json(&Bud3Query::GrantAt(tag, 15));
        assert_eq!(expired["status"], "expired");
        assert_eq!(expired["expires_at_epoch"], 15);

        let sig = sign_with_grant_one_time_key(&otk_seed, &grant_revoke_digest(&tag)).unwrap();
        r.revoke_view_grant(&tag, &sig).unwrap();
        let revoked = r.query_json(&Bud3Query::GrantAt(tag, 16));
        assert_eq!(revoked["status"], "revoked");
        assert!(r.query_json(&Bud3Query::GrantAt([0xAA; 32], 16)).is_null());
    }

    #[test]
    fn dropping_expired_or_burned_dependent_clears_base_deps_and_unblocks_base_burn() {
        use super::super::replace::sign_replace_attestation;
        use crate::crypto::pq::ml_dsa_public_key;
        use crate::crypto::scheme::SchemeId;

        let mut r = Bud3Registry::default();
        let owner = addr(1);
        let (base_up, base_shares) = upload(b"base object for dep cleanup test");
        let base_key = base_up.record.commitment;
        r.register_object(owner, base_up.record.clone(), base_shares.clone(), 0, 50)
            .unwrap();
        for (_, sh) in &base_shares {
            r.ack(&base_key, &sh.validator).unwrap();
        }
        let base_nft = [0xD1; 32];
        r.bind_nft(base_nft, owner, Some(owner), &base_key).unwrap();

        let (dep_exp_up, dep_exp_shares) = upload(b"expiring dependent delta object");
        let dep_exp_key = dep_exp_up.record.commitment;
        r.register_object(owner, dep_exp_up.record, dep_exp_shares, 0, 5)
            .unwrap();
        r.register_dependency(dep_exp_key, base_key).unwrap();
        assert_eq!(r.refcount(&base_key), 2);
        assert_eq!(
            r.burn_reference(&base_nft, &owner, 1),
            Err(RegistryError::HasDependents)
        );

        // Expiring the dependent removes it from `base_deps[base_key]` too.
        r.expire(6);
        assert!(r.object(&dep_exp_key).is_none());
        assert_eq!(r.refcount(&base_key), 1);

        // Burning a second dependent also clears `base_deps[base_key]` and unblocks `base_nft` burn.
        let (dep_burn_up, dep_burn_shares) = upload(b"burnable dependent delta object");
        let dep_burn_key = dep_burn_up.record.commitment;
        r.register_object(owner, dep_burn_up.record, dep_burn_shares, 6, 40)
            .unwrap();
        let dep_nft = [0xD2; 32];
        r.bind_nft(dep_nft, owner, Some(owner), &dep_burn_key)
            .unwrap();
        r.register_dependency(dep_burn_key, base_key).unwrap();
        assert_eq!(r.refcount(&base_key), 2);
        assert!(r.burn_reference(&dep_nft, &owner, 7).unwrap());
        assert_eq!(r.refcount(&base_key), 1);
        assert!(r.burn_reference(&base_nft, &owner, 7).unwrap());
        assert!(r.is_tombstoned(&base_key));

        // Chained finalized replacements (`k1 -> k2 -> k3`) leave zero orphan redirects on delete.
        let (k1_up, k1_shares) = upload(b"chained replacement deletion test");
        let k1 = k1_up.record.commitment;
        r.register_object(owner, k1_up.record.clone(), k1_shares.clone(), 10, 50)
            .unwrap();
        for (_, sh) in &k1_shares {
            r.ack(&k1, &sh.validator).unwrap();
        }
        let chain_nft = [0xD3; 32];
        r.bind_nft(chain_nft, owner, Some(owner), &k1).unwrap();
        let validator_keys: BTreeMap<Address, Vec<u8>> = [10u8, 11, 12]
            .into_iter()
            .map(|v| {
                (
                    addr(v),
                    ml_dsa_public_key(SchemeId::ML_DSA_65, &[v; 32]).unwrap(),
                )
            })
            .collect();
        let mut r2 = k1_up.record.clone();
        r2.codec = if r2.codec == 0 { 1 } else { 0 };
        r2.object_len = r2.object_len.saturating_add(1);
        r2.commitment = [0xC2; 32];
        let att2: Vec<_> = [10u8, 11, 12]
            .into_iter()
            .map(|v| sign_replace_attestation(addr(v), &[v; 32], &k1, &r2, &k1_shares).unwrap())
            .collect();
        let k2 = r
            .replace_object(
                (addr(10), 10_000),
                &k1,
                r2.clone(),
                k1_shares.clone(),
                &att2,
                (
                    crate::core::transaction::DEFAULT_CHAIN_ID,
                    11,
                    &validator_keys,
                ),
            )
            .unwrap();
        for (_, sh) in &k1_shares {
            r.ack(&k2, &sh.validator).unwrap();
        }
        assert_eq!(r.resolve_live_object(&k1).map(|(k, _)| k), Some(k2));

        let mut r3 = r2;
        r3.codec = if r3.codec == 0 { 1 } else { 0 };
        r3.object_len = r3.object_len.saturating_add(1);
        r3.commitment = [0xC3; 32];
        let att3: Vec<_> = [10u8, 11, 12]
            .into_iter()
            .map(|v| sign_replace_attestation(addr(v), &[v; 32], &k2, &r3, &k1_shares).unwrap())
            .collect();
        let k3 = r
            .replace_object(
                (addr(10), 10_000),
                &k2,
                r3,
                k1_shares.clone(),
                &att3,
                (
                    crate::core::transaction::DEFAULT_CHAIN_ID,
                    12,
                    &validator_keys,
                ),
            )
            .unwrap();
        for (_, sh) in &k1_shares {
            r.ack(&k3, &sh.validator).unwrap();
        }
        assert_eq!(r.resolve_live_object(&k1).map(|(k, _)| k), Some(k3));
        assert!(r.burn_reference(&chain_nft, &owner, 13).unwrap());
        assert!(r.resolve_live_object(&k1).is_none());
        assert!(r.replacement(&k1).is_none());
        assert!(r.replacement(&k2).is_none());
    }

    #[test]
    fn pending_replacement_enforces_base_dependencies_across_burn_transfer_and_detach() {
        use super::super::replace::sign_replace_attestation;
        use crate::crypto::pq::ml_dsa_public_key;
        use crate::crypto::scheme::SchemeId;

        let mut r = Bud3Registry::default();
        let owner = addr(1);
        let outsider = addr(99);
        let (base_up, base_shares) = upload(b"pending replacement base dependency object");
        let base_old = base_up.record.commitment;
        r.register_object(owner, base_up.record.clone(), base_shares.clone(), 0, 50)
            .unwrap();
        let base_nft = [0xD1; 32];
        r.bind_nft(base_nft, owner, Some(owner), &base_old).unwrap();
        for (_, sh) in &base_shares {
            r.ack(&base_old, &sh.validator).unwrap();
        }

        let (dep_up, dep_shares) = upload(b"dependent child object referencing base");
        let dep_key = dep_up.record.commitment;
        r.register_object(owner, dep_up.record, dep_shares.clone(), 0, 50)
            .unwrap();
        r.register_dependency(dep_key, base_old).unwrap();

        let validator_keys: BTreeMap<Address, Vec<u8>> = [10u8, 11, 12, 13]
            .into_iter()
            .map(|v| {
                (
                    addr(v),
                    ml_dsa_public_key(SchemeId::ML_DSA_65, &[v; 32]).unwrap(),
                )
            })
            .collect();
        let mut base_new_rec = base_up.record;
        base_new_rec.codec = if base_new_rec.codec == 0 { 1 } else { 0 };
        base_new_rec.object_len = base_new_rec.object_len.saturating_add(2);
        base_new_rec.commitment = [0xD2; 32];
        let atts: Vec<_> = [10u8, 11, 12]
            .into_iter()
            .map(|v| {
                sign_replace_attestation(addr(v), &[v; 32], &base_old, &base_new_rec, &base_shares)
                    .unwrap()
            })
            .collect();
        let base_new = r
            .replace_object(
                (addr(10), 10_000),
                &base_old,
                base_new_rec,
                base_shares.clone(),
                &atts,
                (
                    crate::core::transaction::DEFAULT_CHAIN_ID,
                    1,
                    &validator_keys,
                ),
            )
            .unwrap();

        // While replacement is pending, `base_nft` already points at `base_new`
        // while `base_deps` still keys off `base_old`: burn, release, cross-owner
        // transfer, and pending-old deletion via detach must all uphold dependency safety.
        assert_eq!(
            r.can_release_verified_nft_reference(&base_nft, &owner),
            Err(RegistryError::HasDependents)
        );
        assert_eq!(
            r.burn_reference(&base_nft, &owner, 2),
            Err(RegistryError::HasDependents)
        );
        assert_eq!(
            r.can_transfer_nft_reference(&base_nft, &owner, &outsider),
            Err(RegistryError::CrossOwnerDependency)
        );
        r.detach_dependency(&dep_key, &base_old, 2);
        assert!(
            r.object(&base_old).is_some(),
            "pending predecessor must remain intact until new custody confirms"
        );
        assert!(r.resolve_live_object(&base_new).is_some());

        for (_, sh) in &base_shares {
            r.ack(&base_new, &sh.validator).unwrap();
        }
        assert!(r.burn_reference(&base_nft, &owner, 3).unwrap());
    }

    #[test]
    fn pending_replacement_dependent_blocks_cross_owner_transfer() {
        use super::super::replace::sign_replace_attestation;
        use crate::crypto::pq::ml_dsa_public_key;
        use crate::crypto::scheme::SchemeId;

        let mut r = Bud3Registry::default();
        let owner = addr(2);
        let outsider = addr(88);
        let (base_up, base_shares) = upload(b"immutable base object owned by alice");
        let base_key = base_up.record.commitment;
        r.register_object(owner, base_up.record, base_shares.clone(), 0, 50)
            .unwrap();
        for (_, sh) in &base_shares {
            r.ack(&base_key, &sh.validator).unwrap();
        }

        let (dep_up, dep_shares) = upload(b"dependent object slated for replacement");
        let dep_old = dep_up.record.commitment;
        r.register_object(owner, dep_up.record.clone(), dep_shares.clone(), 0, 50)
            .unwrap();
        let dep_nft = [0xD3; 32];
        r.bind_nft(dep_nft, owner, Some(owner), &dep_old).unwrap();
        for (_, sh) in &dep_shares {
            r.ack(&dep_old, &sh.validator).unwrap();
        }
        r.register_dependency(dep_old, base_key).unwrap();

        let validator_keys: BTreeMap<Address, Vec<u8>> = [10u8, 11, 12, 13]
            .into_iter()
            .map(|v| {
                (
                    addr(v),
                    ml_dsa_public_key(SchemeId::ML_DSA_65, &[v; 32]).unwrap(),
                )
            })
            .collect();
        let mut dep_new_rec = dep_up.record;
        dep_new_rec.codec = if dep_new_rec.codec == 0 { 1 } else { 0 };
        dep_new_rec.object_len = dep_new_rec.object_len.saturating_add(3);
        dep_new_rec.commitment = [0xD4; 32];
        let atts: Vec<_> = [10u8, 11, 12]
            .into_iter()
            .map(|v| {
                sign_replace_attestation(addr(v), &[v; 32], &dep_old, &dep_new_rec, &dep_shares)
                    .unwrap()
            })
            .collect();
        let _dep_new = r
            .replace_object(
                (addr(10), 10_000),
                &dep_old,
                dep_new_rec,
                dep_shares,
                &atts,
                (
                    crate::core::transaction::DEFAULT_CHAIN_ID,
                    1,
                    &validator_keys,
                ),
            )
            .unwrap();

        assert_eq!(
            r.can_transfer_nft_reference(&dep_nft, &owner, &outsider),
            Err(RegistryError::CrossOwnerDependency)
        );
    }

    #[test]
    fn finalized_replacement_rejects_reregistration_under_superseded_commitment() {
        use super::super::keys::derive_object_content_key;
        use super::super::pipeline::prepare_sealed_upload;
        use super::super::replace::sign_replace_attestation;
        use crate::crypto::pq::ml_dsa_public_key;
        use crate::crypto::scheme::SchemeId;

        let mut r = Bud3Registry::default();
        let owner = addr(3);
        let ck = derive_object_content_key(&[0x55; 32], 1);
        let up = prepare_sealed_upload(
            b"sealed object replaced and finalized",
            &ck,
            [0x19; 24],
            &P,
            &Bud3Limits::default(),
            20,
        )
        .unwrap();
        let old_key = up.record.commitment;
        let shares = vec![
            (
                0,
                Share {
                    validator: addr(10),
                    class: Class::Full,
                    first_esi: 0,
                    symbols: 6,
                },
            ),
            (
                0,
                Share {
                    validator: addr(11),
                    class: Class::Full,
                    first_esi: 6,
                    symbols: 6,
                },
            ),
            (
                0,
                Share {
                    validator: addr(12),
                    class: Class::Full,
                    first_esi: 12,
                    symbols: 4,
                },
            ),
            (
                0,
                Share {
                    validator: addr(13),
                    class: Class::Mobile,
                    first_esi: 16,
                    symbols: 4,
                },
            ),
        ];
        r.register_object(owner, up.record.clone(), shares.clone(), 0, 50)
            .unwrap();
        for (_, sh) in &shares {
            r.ack(&old_key, &sh.validator).unwrap();
        }

        let validator_keys: BTreeMap<Address, Vec<u8>> = [10u8, 11, 12, 13]
            .into_iter()
            .map(|v| {
                (
                    addr(v),
                    ml_dsa_public_key(SchemeId::ML_DSA_65, &[v; 32]).unwrap(),
                )
            })
            .collect();
        let mut new_rec = up.record.clone();
        new_rec.codec = if new_rec.codec == 0 { 1 } else { 0 };
        new_rec.object_len = new_rec.object_len.saturating_add(4);
        new_rec.commitment = [0xD5; 32];
        let atts: Vec<_> = [10u8, 11, 12]
            .into_iter()
            .map(|v| {
                sign_replace_attestation(addr(v), &[v; 32], &old_key, &new_rec, &shares).unwrap()
            })
            .collect();
        let new_key = r
            .replace_object(
                (addr(10), 10_000),
                &old_key,
                new_rec,
                shares.clone(),
                &atts,
                (
                    crate::core::transaction::DEFAULT_CHAIN_ID,
                    1,
                    &validator_keys,
                ),
            )
            .unwrap();
        for (_, sh) in &shares {
            r.ack(&new_key, &sh.validator).unwrap();
        }
        assert!(r.object(&old_key).is_none());
        assert_eq!(
            r.resolve_live_object(&old_key).map(|(k, _)| k),
            Some(new_key)
        );

        assert_eq!(
            r.register_object(addr(77), up.record, shares, 2, 50),
            Err(RegistryError::BadRecord("commitment was already replaced"))
        );
        assert_eq!(
            r.resolve_live_object(&old_key).map(|(k, _)| k),
            Some(new_key)
        );
    }
}
