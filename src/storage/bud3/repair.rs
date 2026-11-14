//! Lazy segment repair (`f / 2`), rendezvous repairer assignment with 20-block
//! Instant Task Handover, fresh-ESI synthesis, and 1% bad-repair slashing.
//! exposed for maintenance repair sweeps, `HandoverCoordinator`, and RPC repair audit.
//!
//! Per Section 6.10:
//! 1. Repair is lazy: a segment enters repair when lost shares reach `(f / 2).max(1)`.
//! 2. Share loss triggers after 1 day unseen or 2 missed audit windows (Full),
//!    and 7 days unseen or 3 missed audit windows (Mobile).
//! 3. Repair tasks are assigned to Full validators via stake-weighted rendezvous
//!    hashing (`BDLM_BUD3_REPAIR_V1`); if the assignee does not begin within
//!    20 blocks (`REPAIR_HANDOVER_BLOCKS`), the task hands over immediately to
//!    the next ranked Full validator.
//! 4. The repairer decodes the segment from `k + 2` live symbols and generates
//!    fresh contiguous ESIs (`>= next_esi`) for new holders; lost ESIs are never
//!    reused.
//! 5. Random 1%-per-epoch repair audits (`REPAIR_AUDIT_PPM = 10_000`) regenerate
//!    a repaired symbol from source symbols; a mismatch proves a bad repair and
//!    slashes 1% of the repairer's stake (`BAD_REPAIR_SLASH_BPS = 100`).

use super::custody::{prove_symbol_root_path, symbol_leaf, symbol_root, PathStep};
use super::fountain::{FountainError, SegmentDecoder, SegmentEncoder, Symbol};
use super::limits::Profile;
use super::meter::Meter;
use super::placement::{rank, Candidate, Class, Share};
use super::registry::{Address, ObjectKey};
use crate::core::hash::hash_fields_bytes;
use crate::crypto::ctx::STORAGE_V2;
use crate::crypto::pq::{ml_dsa_sign, PqError};
use crate::crypto::scheme::SchemeId;

/// Domain tag for rendezvous repairer assignment and 1% repair-audit draw.
pub const REPAIR_TAG: &[u8] = b"BDLM_BUD3_REPAIR_V1";

/// Domain tag binding independent Full-validator repair attestations.
pub const REPAIR_ATTEST_DOMAIN: &[u8] = b"BDLM_BUD3_REPAIR_ATTEST_V1";

/// Minimum independent active Full-validator attestations required when repair
/// does not carry an inline Merkle-verified symbol witness.
pub const MIN_REPAIR_ATTESTATIONS: usize = 3;

/// Maximum inline Merkle-verified witness symbols accepted in one `RecordRepair` tx.
pub const MAX_REPAIR_WITNESS_SYMBOLS: usize = 256;

/// One symbol proven against an existing on-chain `SymbolRoot` (`obj.roots[root_index]`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RepairSymbolProof {
    /// Index in `obj.roots` whose Merkle root commits to this symbol.
    pub root_index: u32,
    /// Zero-based position of `symbol.esi` under `obj.roots[root_index]`.
    pub position: u64,
    /// Merkle path from `leaf_hash(SYMBOLS_TAG, esi, symbol_leaf)` to `root`.
    pub root_path: Vec<PathStep>,
    /// The verified coded symbol.
    pub symbol: Symbol,
}

/// Independent Full-validator attestation verifying repaired symbols for a segment.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RepairAttestation {
    /// Attesting active `Class::Full` validator address.
    pub validator: Address,
    /// ML-DSA-65 signature over [`repair_attestation_digest`] (`ctx::STORAGE_V2`).
    pub signature: Vec<u8>,
}

/// Cryptographic witness proving `RecordRepair.new_symbols` and `new_root`
/// are derived from the object's committed segment rather than fabricated bytes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RepairWitness {
    /// Merkle-verified live symbols from existing `obj.roots` entries that decode
    /// the segment and deterministically reproduce `new_symbols`.
    ProvenSymbols(Vec<RepairSymbolProof>),
    /// Independent Full-validator ML-DSA-65 attestations over `new_root` bound
    /// to the segment's original committed root (`>= MIN_REPAIR_ATTESTATIONS`).
    ValidatorAttestations(Vec<RepairAttestation>),
}

/// Canonical domain-separated digest signed by each independent Full validator
/// attesting a segment repair.
#[must_use]
pub fn repair_attestation_digest(
    object: &ObjectKey,
    segment: u64,
    first_esi: u32,
    count: u32,
    new_root: &[u8; 32],
    original_segment_root: &[u8; 32],
) -> [u8; 32] {
    hash_fields_bytes(&[
        REPAIR_ATTEST_DOMAIN,
        object,
        &segment.to_le_bytes(),
        &first_esi.to_le_bytes(),
        &count.to_le_bytes(),
        new_root,
        original_segment_root,
    ])
}

/// Sign a [`RepairAttestation`] with `validator`'s ML-DSA-65 seed under `ctx::STORAGE_V2`.
///
/// Convenience: exposed for repair attester daemons and witness tests.
///
/// # Errors
///
/// Returns [`PqError`] if `ml_dsa_seed` fails to sign.
pub fn sign_repair_attestation(
    validator: Address,
    ml_dsa_seed: &[u8; 32],
    object: &ObjectKey,
    segment: u64,
    (first_esi, count): (u32, u32),
    new_root: &[u8; 32],
    original_segment_root: &[u8; 32],
) -> Result<RepairAttestation, PqError> {
    let digest = repair_attestation_digest(
        object,
        segment,
        first_esi,
        count,
        new_root,
        original_segment_root,
    );
    let signature = ml_dsa_sign(
        SchemeId::ML_DSA_65,
        ml_dsa_seed,
        &digest,
        STORAGE_V2,
        &[0u8; 32],
    )?;
    Ok(RepairAttestation {
        validator,
        signature,
    })
}

/// Build `RepairSymbolProof` witnesses for `live_subset` against the full list of
/// symbols committed under `obj.roots[root_index]` (sorted by ESI).
///
/// Convenience: exposed for repairers constructing inline witnesses for `RecordRepair`.
#[must_use]
pub fn build_repair_proven_witness(
    root_index: u32,
    placed_root_symbols: &[Symbol],
    live_subset: &[Symbol],
) -> Option<Vec<RepairSymbolProof>> {
    if placed_root_symbols.is_empty()
        || live_subset.is_empty()
        || live_subset.len() > MAX_REPAIR_WITNESS_SYMBOLS
    {
        return None;
    }
    let first_esi = placed_root_symbols.first()?.esi;
    let seg = placed_root_symbols.first()?.segment;
    for (idx, s) in placed_root_symbols.iter().enumerate() {
        let expected_esi = first_esi.checked_add(u32::try_from(idx).ok()?)?;
        if s.segment != seg || s.esi != expected_esi {
            return None;
        }
    }
    let placed_leaves: Vec<(u32, [u8; 32])> = placed_root_symbols
        .iter()
        .map(|s| (s.esi, symbol_leaf(&s.data)))
        .collect();
    let mut proofs = Vec::with_capacity(live_subset.len());
    for sym in live_subset {
        if sym.segment != seg || sym.esi < first_esi {
            return None;
        }
        let pos = usize::try_from(sym.esi - first_esi).ok()?;
        let root_path = prove_symbol_root_path(&placed_leaves, pos)?;
        proofs.push(RepairSymbolProof {
            root_index,
            position: u64::try_from(pos).ok()?,
            root_path,
            symbol: sym.clone(),
        });
    }
    Some(proofs)
}

/// Blocks before an unstarted repair task hands over to the next Full validator (Section 6.10.3).
pub const REPAIR_HANDOVER_BLOCKS: u64 = 20;

/// Full-class unseen loss window in seconds (1 day, TESTNET-DEFAULT Section 6.10.2).
pub const FULL_UNSEEN_LOSS_SECS: u64 = 86_400;

/// Mobile-class unseen loss window in seconds (7 days, TESTNET-DEFAULT Section 6.10.2).
pub const MOBILE_UNSEEN_LOSS_SECS: u64 = 7 * 86_400;

/// Per-epoch probability in parts per million that a repair batch is audited against source symbols (1%).
pub const REPAIR_AUDIT_PPM: u32 = 10_000;

/// Proven bad-repair slash in basis points of validator stake (1% = 100 bps, Section 6.10.8).
pub const BAD_REPAIR_SLASH_BPS: u64 = 100;

/// Errors building or verifying a segment repair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairError {
    /// No eligible Full validator candidate was available.
    NoEligibleRepairer,
    /// Insufficient live symbols to reconstruct the segment.
    SegmentUnrecoverable,
    /// Fresh starting ESI is below `k` or leaves the RFC 6330 range.
    InvalidFreshEsi,
    /// Replacement candidate list is empty or includes the repairer itself.
    InvalidNewHolders,
    /// Underlying fountain coding error.
    Fountain(FountainError),
}

impl From<FountainError> for RepairError {
    fn from(e: FountainError) -> Self {
        Self::Fountain(e)
    }
}

/// Output of a completed off-chain segment repair ready for `StorageTxV3::RecordRepair`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRepair {
    /// Repaired segment index.
    pub segment: u64,
    /// Fresh shares assigned to replacement holders.
    pub new_shares: Vec<Share>,
    /// Newly generated symbols in contiguous ESI order (`first_esi..first_esi + count`).
    pub new_symbols: Vec<Symbol>,
    /// Merkle symbol root over `new_symbols`.
    pub new_root: [u8; 32],
    /// Inline Merkle-verified symbol proofs (populated when `live_symbols` is a
    /// contiguous `obj.roots[0]` set within `MAX_REPAIR_WITNESS_SYMBOLS`).
    pub witness: Vec<RepairSymbolProof>,
}

/// Whether `unseen_secs` exceeds the class-specific unseen loss window (`T_F = 1d`, `T_M = 7d`).
#[must_use]
pub const fn is_unseen_share_lost(class: Class, unseen_secs: u64) -> bool {
    match class {
        Class::Full => unseen_secs >= FULL_UNSEEN_LOSS_SECS,
        Class::Mobile => unseen_secs >= MOBILE_UNSEEN_LOSS_SECS,
    }
}

/// Deterministic rendezvous key for assigning a segment repair task.
#[must_use]
pub fn repair_task_key(object: &ObjectKey, segment: u64) -> [u8; 32] {
    hash_fields_bytes(&[REPAIR_TAG, object, &segment.to_le_bytes()])
}

/// Pick the active Full-class repairer for `(object, segment)` given `elapsed_blocks`
/// since the repair became due. Every `REPAIR_HANDOVER_BLOCKS` (20 blocks),
/// assignment advances to the next ranked Full validator (Instant Task Handover).
#[must_use]
pub fn assign_repairer(
    object: &ObjectKey,
    segment: u64,
    candidates: &[Candidate],
    elapsed_blocks: u64,
) -> Option<Address> {
    let full_only: Vec<Candidate> = candidates
        .iter()
        .copied()
        .filter(|c| c.class == Class::Full && c.stake > 0)
        .collect();
    if full_only.is_empty() {
        return None;
    }
    let ordered = rank(&repair_task_key(object, segment), &full_only);
    if ordered.is_empty() {
        return None;
    }
    let slot =
        usize::try_from(elapsed_blocks / REPAIR_HANDOVER_BLOCKS).unwrap_or(0) % ordered.len();
    ordered.get(slot).map(|c| c.validator)
}

/// Decode `segment` from live symbols and generate fresh contiguous repair symbols
/// starting at `next_esi` for `holders` (`(validator, class, symbol_count)`).
///
/// # Errors
///
/// [`RepairError`] if the repairer appears in `holders`, `live_symbols` cannot
/// reconstruct the segment, or `next_esi` overflows.
pub fn build_segment_repair<I>(
    repairer: &Address,
    segment: u64,
    segment_len: u64,
    profile: &Profile,
    next_esi: u32,
    holders: &[(Address, Class, u32)],
    live_symbols: I,
) -> Result<PreparedRepair, RepairError>
where
    I: IntoIterator<Item = Symbol>,
{
    if holders.is_empty()
        || holders
            .iter()
            .any(|(v, _, count)| v == repairer || *count == 0)
    {
        return Err(RepairError::InvalidNewHolders);
    }
    let live_vec: Vec<Symbol> = live_symbols.into_iter().collect();
    let mut dec = SegmentDecoder::new(segment, segment_len, profile)?;
    let mut meter = Meter::new(
        segment_len.saturating_mul(4).saturating_add(1 << 20),
        1 << 20,
    );
    for sym in &live_vec {
        if dec.is_done() {
            break;
        }
        let _ = dec.push(sym.clone(), &mut meter);
    }
    let bytes = dec.into_bytes().ok_or(RepairError::SegmentUnrecoverable)?;
    let enc = SegmentEncoder::new(segment, &bytes, profile)?;
    let k = enc.k();
    let witness_need = usize::try_from(k)
        .unwrap_or(MAX_REPAIR_WITNESS_SYMBOLS)
        .saturating_add(2);
    let witness = if live_vec.first().is_some_and(|s| s.esi == 0)
        && witness_need <= MAX_REPAIR_WITNESS_SYMBOLS
    {
        let subset = live_vec
            .get(..live_vec.len().min(witness_need))
            .unwrap_or(&live_vec);
        build_repair_proven_witness(0, &live_vec, subset).unwrap_or_default()
    } else {
        Vec::new()
    };
    if next_esi < k {
        return Err(RepairError::InvalidFreshEsi);
    }
    let total_new: u32 = holders.iter().try_fold(0u32, |acc, (_, _, c)| {
        acc.checked_add(*c).ok_or(RepairError::InvalidFreshEsi)
    })?;
    let repair_offset = next_esi - k;
    let new_symbols = enc.repair_symbols(repair_offset, total_new)?;

    let leaves: Vec<(u32, [u8; 32])> = new_symbols
        .iter()
        .map(|s| (s.esi, symbol_leaf(&s.data)))
        .collect();
    let new_root = symbol_root(&leaves);

    let mut cursor = next_esi;
    let mut new_shares = Vec::with_capacity(holders.len());
    for (validator, class, count) in holders {
        new_shares.push(Share {
            validator: *validator,
            class: *class,
            first_esi: cursor,
            symbols: *count,
        });
        cursor = cursor
            .checked_add(*count)
            .ok_or(RepairError::InvalidFreshEsi)?;
    }

    Ok(PreparedRepair {
        segment,
        new_shares,
        new_symbols,
        new_root,
        witness,
    })
}

/// Deterministic 1%-per-epoch draw deciding whether a repair batch is audited
/// against reconstructed source symbols (Section 6.10.8).
#[must_use]
pub fn should_audit_repair_batch(epoch_seed: &[u8; 32], object: &ObjectKey, segment: u64) -> bool {
    let h = hash_fields_bytes(&[REPAIR_TAG, epoch_seed, object, &segment.to_le_bytes()]);
    let mut b = [0u8; 4];
    if let Some(prefix) = h.get(..4) {
        b.copy_from_slice(prefix);
    }
    let roll = u32::from_le_bytes(b) % 1_000_000;
    roll < REPAIR_AUDIT_PPM
}

/// Verify a claimed repaired symbol (`claimed`) by regenerating its exact ESI
/// from the reconstructed `segment_bytes`. Returns `false` on a fraudulent repair.
///
/// # Errors
///
/// [`RepairError::Fountain`] if `profile` or `claimed.esi` is invalid.
pub fn verify_repaired_symbol(
    segment: u64,
    segment_bytes: &[u8],
    profile: &Profile,
    claimed: &Symbol,
) -> Result<bool, RepairError> {
    if claimed.segment != segment {
        return Ok(false);
    }
    let enc = SegmentEncoder::new(segment, segment_bytes, profile)?;
    let k = enc.k();
    if claimed.esi < k {
        return Err(RepairError::InvalidFreshEsi);
    }
    let expected = enc.repair_symbols(claimed.esi - k, 1)?;
    Ok(expected.first().is_some_and(|s| s.data == claimed.data))
}

/// Calculate the 1% stake slash (`stake / 100`) imposed on a validator that
/// submits a fraudulent repair (`bud3_bad_repair_is_slashed`, Section 6.10.8).
#[must_use]
pub const fn bad_repair_slash_amount(repairer_stake: u64) -> u64 {
    repairer_stake.saturating_mul(BAD_REPAIR_SLASH_BPS) / 10_000
}

/// Blocks an assigned Full validator has to submit `RecordRepair` before
/// Instant Task Handover transfers the task to the next candidate (Section 7.6: 20 blocks).
pub const REPAIR_TASK_HANDOVER_BLOCKS: u64 = 20;

/// Scheduled segment repair duty tracked for 20-block Instant Task Handover (Section 7.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduledRepairDuty {
    pub object: ObjectKey,
    pub segment: u64,
    pub assignee: [u8; 32],
    pub assigned_height: u64,
    pub started: bool,
}

/// Hand over a scheduled repair duty to the next Full candidate if `RecordRepair`
/// was not initiated within `REPAIR_TASK_HANDOVER_BLOCKS` blocks (Section 7.6).
#[must_use]
pub fn handover_expired_repair_duty(
    duty: &ScheduledRepairDuty,
    current_height: u64,
    ordered_full_candidates: &[[u8; 32]],
) -> Option<ScheduledRepairDuty> {
    if duty.started
        || current_height.saturating_sub(duty.assigned_height) < REPAIR_TASK_HANDOVER_BLOCKS
    {
        return None;
    }
    let next_assignee = ordered_full_candidates
        .iter()
        .copied()
        .find(|v| *v != duty.assignee)?;
    Some(ScheduledRepairDuty {
        object: duty.object,
        segment: duty.segment,
        assignee: next_assignee,
        assigned_height: current_height,
        started: false,
    })
}

/// Deterministic lazy repair scheduler used by duty-handover simulations.
pub mod scheduler;
pub use scheduler::{RepairScheduler, RepairTask};

#[cfg(test)]
mod tests {
    use super::*;

    const SMALL: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 128,
        fps: 10,
        k_max: 16,
    };

    #[test]
    fn handover_advances_every_twenty_blocks() {
        let cands: Vec<Candidate> = (1..=4u8)
            .map(|i| Candidate {
                validator: [i; 32],
                account: [i; 32],
                class: Class::Full,
                stake: 1_000,
                free_quota_bytes: u64::MAX,
                network: None,
            })
            .collect();
        let first = assign_repairer(&[9; 32], 0, &cands, 0).unwrap();
        let block_19 = assign_repairer(&[9; 32], 0, &cands, 19).unwrap();
        let block_20 = assign_repairer(&[9; 32], 0, &cands, 20).unwrap();
        assert_eq!(first, block_19);
        assert_ne!(first, block_20);
    }

    #[test]
    fn bud3_bad_repair_is_slashed() {
        let seg_bytes = b"segment payload reconstructed by honest repairer".repeat(12);
        let enc = SegmentEncoder::new(0, &seg_bytes, &SMALL).unwrap();
        let k = enc.k();
        let mut live = enc.source_symbols();
        live.extend(enc.repair_symbols(0, 4).unwrap());

        let repairer = [0xAA; 32];
        let holder = [0xBB; 32];
        let prepared = build_segment_repair(
            &repairer,
            0,
            seg_bytes.len() as u64,
            &SMALL,
            k + 4,
            &[(holder, Class::Full, 3)],
            live,
        )
        .unwrap();
        assert_eq!(prepared.new_symbols.len(), 3);
        assert_eq!(prepared.new_symbols[0].esi, k + 4);
        assert!(verify_repaired_symbol(0, &seg_bytes, &SMALL, &prepared.new_symbols[0]).unwrap());

        let mut forged = prepared.new_symbols[0].clone();
        forged.data[0] ^= 0xFF;
        assert!(!verify_repaired_symbol(0, &seg_bytes, &SMALL, &forged).unwrap());
        assert_eq!(bad_repair_slash_amount(500_000), 5_000);
    }
}
