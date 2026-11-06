//! Lazy segment repair (`f / 2`), rendezvous repairer assignment with 20-block
//! Instant Task Handover, fresh-ESI regeneration, and 1% bad-repair slashing.
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

use super::custody::{symbol_leaf, symbol_root};
use super::fountain::{FountainError, SegmentDecoder, SegmentEncoder, Symbol};
use super::limits::Profile;
use super::meter::Meter;
use super::placement::{rank, Candidate, Class, Share};
use super::registry::{Address, ObjectKey};
use crate::core::hash::hash_fields_bytes;

/// Domain tag for rendezvous repairer assignment and 1% repair-audit draw.
pub const REPAIR_TAG: &[u8] = b"BDLM_BUD3_REPAIR_V1";

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
    let slot = usize::try_from(elapsed_blocks / REPAIR_HANDOVER_BLOCKS).unwrap_or(0) % ordered.len();
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
    let mut dec = SegmentDecoder::new(segment, segment_len, profile)?;
    let mut meter = Meter::new(
        segment_len.saturating_mul(4).saturating_add(1 << 20),
        1 << 20,
    );
    for sym in live_symbols {
        if dec.is_done() {
            break;
        }
        let _ = dec.push(sym, &mut meter);
    }
    let bytes = dec.into_bytes().ok_or(RepairError::SegmentUnrecoverable)?;
    let enc = SegmentEncoder::new(segment, &bytes, profile)?;
    let k = enc.k();
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
