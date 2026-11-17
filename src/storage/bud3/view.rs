//! B.U.D. 3.0 view flow, network reveal sessions, and paid fallback decoding.
//!
//! Covers G1-G8 views (`bud_storageOpenReveal`, `bud_storageRevealFrames`,
//! `bud_storageCloseReveal`) and paid public G8 fallback decoding (Section 6.5).
//! exposed for `Bud3RpcService`, `Bud3ContentGateway`, and BNS/SocialFi viewers.
//!
//! Security invariants enforced here:
//! 1. ** closure**: reveal sessions NEVER accept caller-supplied content bytes.
//!    `open_reveal` fetches `>= k + 2` symbols strictly through [`NetworkSymbolSource`]
//!    (querying Full holders first, then Mobile holders per G3) and verifies the
//!    reconstructed object against `record.commitment` before emitting frames.
//! 2. **G8 Paid Public Fallback (`bud3-paid-view`)**: server-side fallback decoding
//!    (`fallback_decode_public`) requires a [`PaidViewReceipt`] covering at least
//!    `MIN_PAID_VIEW_FEE_ATOMS` and unconditionally refuses `ContentIdKind::Sealed`
//!    (`ViewBud3Error::SealedFallbackForbidden`).

use super::bof1::Object;
use super::content_id::{ContentIdKind, ContentKey};
use super::custody::{symbol_leaf, symbol_root};
use super::fountain::{FountainError, SegmentDecoder, SegmentEncoder, Symbol};
use super::frame::{frames_for_object_bytes, Bud3Frame};
use super::meter::Meter;
use super::pipeline::{view_public, view_sealed, ObjectRecord, PipelineError};
use super::placement::{Class, Share};
use super::registry::{Address, Bud3Registry, ObjectKey};
use super::segment::{commit_object, Segmentation};
use std::collections::{BTreeMap, BTreeSet};

/// Minimum fee in BUD base units required for G8 validator fallback decoding
/// (`0.0001 BUD` = `100` base units at `10^6` scale, Section 6.5 G8).
pub const MIN_PAID_VIEW_FEE_ATOMS: u64 = 100;

/// Epochs a paid view receipt stays in consensus state after payment.
///
/// A receipt authorizes one decode; one that was never presented inside this
/// window is dropped by `Bud3Registry::expire` instead of being folded into the
/// state root, kept in the snapshot and hashed again on every block forever.
pub const PAID_VIEW_RETENTION_EPOCHS: u64 = 30 * super::fees::DEFAULT_EPOCHS_PER_DAY;

/// Maximum concurrent reveal sessions held in memory on one node.
pub const MAX_REVEAL_SESSIONS: usize = 128;

/// Proof of fee payment authorizing a G8 public fallback decode (`bud_storageGetContent`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaidViewReceipt {
    /// Payer account.
    pub payer: Address,
    /// Target object commitment.
    pub object: ObjectKey,
    /// Unique on-chain receipt identifier written by `StorageTxV3::PayFallbackView`.
    pub receipt_id: [u8; 32],
    /// Paid fee in BUD base units (`>= MIN_PAID_VIEW_FEE_ATOMS`).
    pub fee_paid_atoms: u64,
}

/// Abstract network symbol fetcher so reveal sessions and content gateways
/// collect symbols strictly from custody holders (Full first, Mobile second, G3)
/// rather than caller-supplied content bytes.
pub trait NetworkSymbolSource {
    /// Fetch symbols held by `holder` for `(object, segment, first_esi, count)`.
    fn fetch_holder_symbols(
        &self,
        holder: &Address,
        object: &ObjectKey,
        segment: u64,
        first_esi: u32,
        count: u32,
    ) -> Vec<Symbol>;
}

/// In-memory network symbol map for tests and local custody pools.
#[derive(Debug, Default, Clone)]
pub struct MemorySymbolNetwork {
    holders: BTreeMap<(Address, ObjectKey, u64), Vec<Symbol>>,
}

impl MemorySymbolNetwork {
    /// Populate `holder`'s custody symbols for `(object, segment)`.
    pub fn store_holder_share(
        &mut self,
        holder: Address,
        object: ObjectKey,
        segment: u64,
        symbols: Vec<Symbol>,
    ) {
        self.holders.insert((holder, object, segment), symbols);
    }
}

/// Symbol source of a node that holds no symbols and has no symbol transport.
///
/// Convenience: exposed for empty-network test callers and fixture views. Every
/// read comes back empty, so a view through it fails with a missing-symbols
/// error and never returns unverified bytes.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoSymbolsHeld;

impl NetworkSymbolSource for NoSymbolsHeld {
    fn fetch_holder_symbols(
        &self,
        _holder: &Address,
        _object: &ObjectKey,
        _segment: u64,
        _first_esi: u32,
        _count: u32,
    ) -> Vec<Symbol> {
        Vec::new()
    }
}

impl NetworkSymbolSource for MemorySymbolNetwork {
    fn fetch_holder_symbols(
        &self,
        holder: &Address,
        object: &ObjectKey,
        segment: u64,
        first_esi: u32,
        count: u32,
    ) -> Vec<Symbol> {
        let Some(all) = self.holders.get(&(*holder, *object, segment)) else {
            return Vec::new();
        };
        let end = first_esi.saturating_add(count);
        all.iter()
            .filter(|s| s.esi >= first_esi && s.esi < end)
            .cloned()
            .collect()
    }
}

/// Errors during B.U.D. 3.0 view, reveal session, or G8 fallback decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewBud3Error {
    /// Object is unknown or tombstoned in `Bud3Registry`.
    UnknownObject,
    /// Sealed object requires an authorized `ContentKey` / active view grant (G2).
    AccessDenied,
    /// G8 validator fallback decode is strictly forbidden on sealed objects (Section 6.5 G8).
    SealedFallbackForbidden,
    /// G8 fallback decode requires `fee_paid_atoms >= MIN_PAID_VIEW_FEE_ATOMS` for the target object.
    UnpaidFallbackView,
    /// Too many open reveal sessions on this node.
    TooManyRevealSessions,
    /// Unknown reveal session ID.
    UnknownRevealSession,
    /// Network holders did not return `k + 2` valid symbols to rebuild segment `u64`.
    InsufficientNetworkSymbols(u64),
    /// Pipeline commitment or content-id verification failed.
    Pipeline(PipelineError),
}

impl From<PipelineError> for ViewBud3Error {
    fn from(e: PipelineError) -> Self {
        Self::Pipeline(e)
    }
}

fn verify_segment_candidate(
    seg: u64,
    seg_len: u64,
    record: &ObjectRecord,
    candidate_syms: &[Symbol],
    all_share_batches: &[Vec<Symbol>],
) -> Option<Vec<Symbol>> {
    let mut dec = SegmentDecoder::new(seg, seg_len, &record.profile).ok()?;
    let mut meter = Meter::new(
        seg_len.saturating_mul(4).saturating_add(1 << 20),
        u64::from(record.symbols_per_segment)
            .saturating_add(u64::try_from(candidate_syms.len()).unwrap_or(u64::MAX)),
    );
    let mut seen = BTreeSet::new();
    for sym in candidate_syms {
        if !seen.insert(sym.esi) {
            continue;
        }
        if !dec.is_done() {
            let _ = dec.push(sym.clone(), &mut meter);
        }
    }
    let bytes = dec.into_bytes()?;
    if u64::try_from(bytes.len()) != Ok(seg_len) {
        return None;
    }
    let enc = SegmentEncoder::new(seg, &bytes, &record.profile).ok()?;
    let k = enc.k();
    let initial_count = record.symbols_per_segment.max(k);
    let mut initial = enc.source_symbols();
    initial.extend(
        enc.repair_symbols(0, initial_count.saturating_sub(k))
            .ok()?,
    );
    if let Some(expected_root) = usize::try_from(seg)
        .ok()
        .and_then(|idx| record.symbol_roots.get(idx))
    {
        if *expected_root != [0u8; 32] && record.symbols_per_segment >= k {
            let take_n = usize::try_from(record.symbols_per_segment).ok()?;
            let leaves: Vec<(u32, [u8; 32])> = initial
                .iter()
                .take(take_n)
                .map(|s| (s.esi, symbol_leaf(&s.data)))
                .collect();
            if symbol_root(&leaves) != *expected_root {
                return None;
            }
        }
    }
    let mut verified = Vec::new();
    let mut emitted = BTreeSet::new();
    for batch in all_share_batches {
        for sym in batch {
            if !emitted.insert(sym.esi) {
                continue;
            }
            let matches = if let Some(init_sym) = usize::try_from(sym.esi)
                .ok()
                .and_then(|idx| initial.get(idx))
            {
                init_sym.data == sym.data
            } else if sym.esi >= k {
                enc.repair_symbols(sym.esi - k, 1)
                    .ok()
                    .and_then(|mut r| r.pop())
                    .is_some_and(|r| r.data == sym.data)
            } else {
                false
            };
            if matches {
                verified.push(sym.clone());
            }
        }
    }
    Some(verified)
}

fn isolate_verified_segment_symbols(
    seg: u64,
    seg_len: u64,
    record: &ObjectRecord,
    share_batches: &[Vec<Symbol>],
) -> Vec<Symbol> {
    let mut all_flat = Vec::new();
    for b in share_batches {
        all_flat.extend(b.iter().cloned());
    }
    if all_flat.is_empty() {
        return all_flat;
    }
    if let Some(verified) = verify_segment_candidate(seg, seg_len, record, &all_flat, share_batches)
    {
        return verified;
    }
    // Fast leave-one-share-out isolates a single Byzantine holder without failing recovery.
    let m = share_batches.len();
    if m > 1 {
        for skip in 0..m {
            let mut subset = Vec::new();
            for (idx, batch) in share_batches.iter().enumerate() {
                if idx != skip {
                    subset.extend(batch.iter().cloned());
                }
            }
            if let Some(verified) =
                verify_segment_candidate(seg, seg_len, record, &subset, share_batches)
            {
                return verified;
            }
        }
    }
    // Bounded multi-holder fallback (leave-two-out, single shares, then pairs)
    // capped at `budget` evaluations so CWE-400 complexity stays strictly bounded.
    let mut budget = 128usize;
    if m >= 3 {
        for skip_a in 0..m {
            for skip_b in (skip_a + 1)..m {
                if budget == 0 {
                    return Vec::new();
                }
                budget -= 1;
                let mut subset = Vec::new();
                for (idx, batch) in share_batches.iter().enumerate() {
                    if idx != skip_a && idx != skip_b {
                        subset.extend(batch.iter().cloned());
                    }
                }
                if !subset.is_empty() {
                    if let Some(verified) =
                        verify_segment_candidate(seg, seg_len, record, &subset, share_batches)
                    {
                        return verified;
                    }
                }
            }
        }
    }
    for batch in share_batches {
        if budget == 0 {
            return Vec::new();
        }
        budget -= 1;
        if let Some(verified) = verify_segment_candidate(seg, seg_len, record, batch, share_batches)
        {
            return verified;
        }
    }
    for (i, bi) in share_batches.iter().enumerate() {
        for bj in share_batches.iter().skip(i + 1) {
            if budget == 0 {
                return Vec::new();
            }
            budget -= 1;
            let mut pair = Vec::with_capacity(bi.len().saturating_add(bj.len()));
            pair.extend(bi.iter().cloned());
            pair.extend(bj.iter().cloned());
            if let Some(verified) =
                verify_segment_candidate(seg, seg_len, record, &pair, share_batches)
            {
                return verified;
            }
        }
    }
    // Never forward unverified Byzantine symbols when no subset verifies against
    // the segment's symbol root and decoded byte length.
    Vec::new()
}

/// Collect symbols for every segment of `object` from `network`, querying
/// `Class::Full` shares before `Class::Mobile` shares (Section 6.5 G3) and
/// isolating Byzantine holder replies against `record.symbol_roots`.
///
/// # Errors
///
/// [`ViewBud3Error::UnknownObject`] if `object` is not registered.
pub fn collect_symbols_full_then_mobile<N: NetworkSymbolSource>(
    registry: &Bud3Registry,
    object: &ObjectKey,
    network: &N,
) -> Result<(ObjectRecord, Vec<Symbol>), ViewBud3Error> {
    let entry = registry
        .object(object)
        .ok_or(ViewBud3Error::UnknownObject)?;
    let record = entry.record.clone();
    let mut shares_ordered: Vec<(u64, Share)> = entry
        .shares
        .iter()
        .filter(|s| !s.lost)
        .map(|s| (s.segment, s.share))
        .collect();
    // G3: Full class first (0), Mobile class second (1).
    shares_ordered.sort_by_key(|(seg, sh)| {
        let rank = match sh.class {
            Class::Full => 0u8,
            Class::Mobile => 1u8,
        };
        (*seg, rank, sh.first_esi)
    });

    let expected_sym_len = usize::from(record.profile.symbol_size);
    let mut per_segment_batches: BTreeMap<u64, Vec<Vec<Symbol>>> = BTreeMap::new();
    for (seg, sh) in shares_ordered {
        let syms =
            network.fetch_holder_symbols(&sh.validator, object, seg, sh.first_esi, sh.symbols);
        let end_esi = sh.first_esi.saturating_add(sh.symbols);
        let mut seen_esis = BTreeSet::new();
        let clean: Vec<Symbol> = syms
            .into_iter()
            .filter(|s| {
                s.segment == seg
                    && s.esi >= sh.first_esi
                    && s.esi < end_esi
                    && s.data.len() == expected_sym_len
                    && seen_esis.insert(s.esi)
            })
            .collect();
        per_segment_batches.entry(seg).or_default().push(clean);
    }

    let segmentation = Segmentation::new(record.object_len, &record.profile).ok_or(
        ViewBud3Error::Pipeline(PipelineError::Fountain(FountainError::InvalidProfile)),
    )?;
    let mut collected = Vec::new();
    for (seg, batches) in per_segment_batches {
        if let Some(seg_len) = segmentation.len(seg) {
            collected.extend(isolate_verified_segment_symbols(
                seg, seg_len, &record, &batches,
            ));
        }
    }
    Ok((record, collected))
}

/// Client-side logical view (G4): reconstruct and verify public or grant-authorized
/// sealed content from symbols collected over the network.
///
/// # Errors
///
/// [`ViewBud3Error`] if access is missing (`Sealed` without `grant_key`) or verification fails.
pub fn view_from_network<N: NetworkSymbolSource>(
    registry: &Bud3Registry,
    object: &ObjectKey,
    grant_key: Option<&ContentKey>,
    network: &N,
) -> Result<Vec<u8>, ViewBud3Error> {
    let (record, symbols) = collect_symbols_full_then_mobile(registry, object, network)?;
    match record.content_id.kind {
        ContentIdKind::Public => Ok(view_public(&record, symbols)?),
        ContentIdKind::Sealed => {
            let key = grant_key.ok_or(ViewBud3Error::AccessDenied)?;
            Ok(view_sealed(&record, key, symbols)?)
        }
    }
}

/// G8 Validator Fallback Decode (`bud_storageGetContent`): permitted ONLY for
/// `ContentIdKind::Public` and ONLY when accompanied by a valid [`PaidViewReceipt`].
///
/// # Errors
///
/// [`ViewBud3Error::SealedFallbackForbidden`], [`ViewBud3Error::UnpaidFallbackView`],
/// or [`ViewBud3Error::Pipeline`].
pub fn fallback_decode_public<N: NetworkSymbolSource>(
    registry: &Bud3Registry,
    object: &ObjectKey,
    receipt: &PaidViewReceipt,
    network: &N,
) -> Result<Vec<u8>, ViewBud3Error> {
    let entry = registry
        .object(object)
        .ok_or(ViewBud3Error::UnknownObject)?;
    if entry.record.content_id.kind == ContentIdKind::Sealed {
        return Err(ViewBud3Error::SealedFallbackForbidden);
    }
    if receipt.object != *object
        || receipt.fee_paid_atoms < MIN_PAID_VIEW_FEE_ATOMS
        || !registry.verify_paid_view(receipt)
    {
        return Err(ViewBud3Error::UnpaidFallbackView);
    }
    let (record, symbols) = collect_symbols_full_then_mobile(registry, object, network)?;
    Ok(view_public(&record, symbols)?)
}

const MAX_REVEAL_TOTAL_BYTES: usize = 64 * 1024 * 1024;

struct RevealSession {
    object: ObjectKey,
    frames: Vec<Bud3Frame>,
    retained_bytes: usize,
}

/// Node-local reveal session manager (`bud_storageOpenReveal`, `bud_storageRevealFrames`,
/// `bud_storageCloseReveal`). Collects strictly from [`NetworkSymbolSource`].
#[derive(Default)]
pub struct RevealSessionManager {
    next_id: u64,
    sessions: BTreeMap<u64, RevealSession>,
    retained_bytes: usize,
}

impl RevealSessionManager {
    /// `bud_storageOpenReveal`: collect verified symbols from the network,
    /// rebuild the BOF-1 object in memory (without writing to disk, G7), verify
    /// `commit_object == object`, and prepare logical `B3F1` frames for paging.
    ///
    /// # Errors
    ///
    /// [`ViewBud3Error`] if `object` is unknown, session table is full, or
    /// network holders do not supply enough valid symbols.
    pub fn open_reveal<N: NetworkSymbolSource>(
        &mut self,
        registry: &Bud3Registry,
        object: &ObjectKey,
        repair_per_segment: u32,
        network: &N,
    ) -> Result<u64, ViewBud3Error> {
        if self.sessions.len() >= MAX_REVEAL_SESSIONS
            || self.retained_bytes >= MAX_REVEAL_TOTAL_BYTES
        {
            return Err(ViewBud3Error::TooManyRevealSessions);
        }
        let (record, symbols) = collect_symbols_full_then_mobile(registry, object, network)?;
        let seg = Segmentation::new(record.object_len, &record.profile).ok_or(
            ViewBud3Error::Pipeline(PipelineError::Fountain(FountainError::InvalidProfile)),
        )?;
        let seg_count = seg.count();
        let _ = usize::try_from(seg_count)
            .map_err(|_| ViewBud3Error::Pipeline(PipelineError::TooLarge))?;
        let mut decoders: BTreeMap<u64, SegmentDecoder> = BTreeMap::new();
        let mut seen_esis: BTreeSet<(u64, u32)> = BTreeSet::new();
        let step_budget = u64::from(
            record
                .symbols_per_segment
                .saturating_add(super::fountain::MAX_EXTRA_SYMBOLS),
        )
        .saturating_mul(seg_count);
        let byte_budget = step_budget
            .saturating_mul(u64::from(record.profile.symbol_size))
            .max(record.object_len.saturating_mul(4).saturating_add(1 << 20));
        let mut meter = Meter::new(byte_budget, step_budget);
        for sym in symbols {
            if sym.segment >= seg_count || !seen_esis.insert((sym.segment, sym.esi)) {
                continue;
            }
            if let std::collections::btree_map::Entry::Vacant(e) = decoders.entry(sym.segment) {
                let len = seg
                    .len(sym.segment)
                    .ok_or(ViewBud3Error::Pipeline(PipelineError::TooLarge))?;
                let dec = SegmentDecoder::new(sym.segment, len, &record.profile)
                    .map_err(PipelineError::Fountain)?;
                e.insert(dec);
            }
            if let Some(dec) = decoders.get_mut(&sym.segment) {
                if !dec.is_done() {
                    let _ = dec.push(sym, &mut meter);
                }
            }
        }
        let cap = usize::try_from(record.object_len)
            .map_err(|_| ViewBud3Error::Pipeline(PipelineError::TooLarge))?;
        let mut object_bytes = Vec::with_capacity(cap.min(1 << 20));
        for idx in 0..seg_count {
            let dec = decoders
                .remove(&idx)
                .ok_or(ViewBud3Error::InsufficientNetworkSymbols(idx))?;
            let bytes = dec
                .into_bytes()
                .ok_or(ViewBud3Error::InsufficientNetworkSymbols(idx))?;
            object_bytes.extend_from_slice(&bytes);
        }
        if u64::try_from(object_bytes.len()) != Ok(record.object_len)
            || commit_object(&object_bytes, &record.profile) != Some(record.commitment)
        {
            return Err(ViewBud3Error::Pipeline(PipelineError::CommitmentMismatch));
        }
        let mut parse_meter = Meter::for_object(record.object_len);
        let _ = Object::decode(&object_bytes, &mut parse_meter).map_err(PipelineError::Object)?;
        let frames = frames_for_object_bytes(&object_bytes, &record.profile, repair_per_segment)
            .map_err(|_| ViewBud3Error::Pipeline(PipelineError::TooLarge))?;
        let session_bytes = frames.iter().fold(0usize, |acc, f| {
            acc.saturating_add(f.data.len())
                .saturating_add(core::mem::size_of::<Bud3Frame>())
        });
        if self.retained_bytes.saturating_add(session_bytes) > MAX_REVEAL_TOTAL_BYTES {
            return Err(ViewBud3Error::TooManyRevealSessions);
        }

        self.next_id = self.next_id.saturating_add(1);
        let id = self.next_id;
        self.retained_bytes = self.retained_bytes.saturating_add(session_bytes);
        self.sessions.insert(
            id,
            RevealSession {
                object: *object,
                frames,
                retained_bytes: session_bytes,
            },
        );
        Ok(id)
    }

    /// `bud_storageRevealFrames`: read a bounded page of self-describing `B3F1`
    /// frames (`offset..offset + limit`) from an open reveal session.
    ///
    /// # Errors
    ///
    /// [`ViewBud3Error::UnknownRevealSession`].
    pub fn reveal_frames(
        &self,
        session_id: u64,
        offset: usize,
        limit: usize,
    ) -> Result<(ObjectKey, Vec<Bud3Frame>, usize), ViewBud3Error> {
        let s = self
            .sessions
            .get(&session_id)
            .ok_or(ViewBud3Error::UnknownRevealSession)?;
        let capped = limit.min(64);
        let total = s.frames.len();
        let page = s
            .frames
            .get(offset..)
            .map(|tail| tail.iter().take(capped).cloned().collect())
            .unwrap_or_default();
        Ok((s.object, page, total))
    }

    /// `bud_storageCloseReveal`: drop the reveal session from memory immediately.
    ///
    /// # Errors
    ///
    /// [`ViewBud3Error::UnknownRevealSession`].
    pub fn close_reveal(&mut self, session_id: u64) -> Result<(), ViewBud3Error> {
        let removed = self
            .sessions
            .remove(&session_id)
            .ok_or(ViewBud3Error::UnknownRevealSession)?;
        self.retained_bytes = self.retained_bytes.saturating_sub(removed.retained_bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::keys::derive_object_content_key;
    use super::super::limits::{Bud3Limits, Profile};
    use super::super::pipeline::{prepare_public_upload, prepare_sealed_upload};
    use super::*;

    const SMALL: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 128,
        fps: 10,
        k_max: 16,
    };

    #[test]
    fn bud3_e2e_reveal_collects_from_network_and_enforces_paid_public_fallback() {
        let mut reg = Bud3Registry::default();
        let mut net = MemorySymbolNetwork::default();

        // Register public object across 1 Full + 1 Mobile holder.
        let pub_up = prepare_public_upload(
            b"network-collected reveal payload",
            &SMALL,
            &Bud3Limits::default(),
            8,
        )
        .unwrap();
        let pub_key = pub_up.record.commitment;
        let full_h = [10u8; 32];
        let mob_h = [11u8; 32];
        reg.register_object(
            [1; 32],
            pub_up.record.clone(),
            vec![
                (
                    0,
                    Share {
                        validator: full_h,
                        class: Class::Full,
                        first_esi: 0,
                        symbols: 4,
                    },
                ),
                (
                    0,
                    Share {
                        validator: mob_h,
                        class: Class::Mobile,
                        first_esi: 4,
                        symbols: 4,
                    },
                ),
            ],
            0,
            20,
        )
        .unwrap();
        net.store_holder_share(full_h, pub_key, 0, pub_up.segments[0][0..4].to_vec());
        net.store_holder_share(mob_h, pub_key, 0, pub_up.segments[0][4..8].to_vec());

        // Reveal session fails if network has no symbols, succeeds when network holders serve.
        let empty_net = MemorySymbolNetwork::default();
        let mut reveal_mgr = RevealSessionManager::default();
        assert!(matches!(
            reveal_mgr.open_reveal(&reg, &pub_key, 2, &empty_net),
            Err(ViewBud3Error::InsufficientNetworkSymbols(0))
        ));

        let sid = reveal_mgr.open_reveal(&reg, &pub_key, 2, &net).unwrap();
        let (obj, frames, total) = reveal_mgr.reveal_frames(sid, 0, 16).unwrap();
        assert_eq!(obj, pub_key);
        assert!(!frames.is_empty());
        assert_eq!(frames.len(), total);
        reveal_mgr.close_reveal(sid).unwrap();
        assert_eq!(
            reveal_mgr.reveal_frames(sid, 0, 4),
            Err(ViewBud3Error::UnknownRevealSession)
        );

        let receipt_id = [0xA5; 32];
        // Unpaid or unrecorded off-chain G8 fallback is refused; on-chain paid G8 fallback succeeds on public content.
        assert_eq!(
            fallback_decode_public(
                &reg,
                &pub_key,
                &PaidViewReceipt {
                    payer: [2; 32],
                    object: pub_key,
                    receipt_id,
                    fee_paid_atoms: MIN_PAID_VIEW_FEE_ATOMS - 1,
                },
                &net,
            ),
            Err(ViewBud3Error::UnpaidFallbackView)
        );
        assert_eq!(
            fallback_decode_public(
                &reg,
                &pub_key,
                &PaidViewReceipt {
                    payer: [2; 32],
                    object: pub_key,
                    receipt_id,
                    fee_paid_atoms: MIN_PAID_VIEW_FEE_ATOMS,
                },
                &net,
            ),
            Err(ViewBud3Error::UnpaidFallbackView)
        );
        reg.record_paid_view([2; 32], pub_key, receipt_id, MIN_PAID_VIEW_FEE_ATOMS, 1)
            .unwrap();
        let decoded = fallback_decode_public(
            &reg,
            &pub_key,
            &PaidViewReceipt {
                payer: [2; 32],
                object: pub_key,
                receipt_id,
                fee_paid_atoms: MIN_PAID_VIEW_FEE_ATOMS,
            },
            &net,
        )
        .unwrap();
        assert_eq!(decoded, b"network-collected reveal payload");

        // Sealed content NEVER allows G8 validator fallback decode, even when paid!
        let ck = derive_object_content_key(&[0x77; 32], 1);
        let sealed_up = prepare_sealed_upload(
            b"private",
            &ck,
            [0x22; 24],
            &SMALL,
            &Bud3Limits::default(),
            8,
        )
        .unwrap();
        let sealed_key = sealed_up.record.commitment;
        reg.register_object(
            [1; 32],
            sealed_up.record,
            vec![
                (
                    0,
                    Share {
                        validator: full_h,
                        class: Class::Full,
                        first_esi: 0,
                        symbols: 4,
                    },
                ),
                (
                    0,
                    Share {
                        validator: mob_h,
                        class: Class::Mobile,
                        first_esi: 4,
                        symbols: 4,
                    },
                ),
            ],
            0,
            20,
        )
        .unwrap();
        assert_eq!(
            fallback_decode_public(
                &reg,
                &sealed_key,
                &PaidViewReceipt {
                    payer: [2; 32],
                    object: sealed_key,
                    receipt_id: [0xA6; 32],
                    fee_paid_atoms: 10_000,
                },
                &net,
            ),
            Err(ViewBud3Error::SealedFallbackForbidden)
        );
    }

    #[test]
    fn collect_and_reveal_survive_byzantine_full_holder_poisoning() {
        let mut reg = Bud3Registry::default();
        let mut net = MemorySymbolNetwork::default();

        let payload = b"Byzantine holder poisoning must not stop verified recovery".repeat(8);
        let up = prepare_public_upload(&payload, &SMALL, &Bud3Limits::default(), 16).unwrap();
        let key = up.record.commitment;
        let rogue_full = [30u8; 32];
        let honest_full = [31u8; 32];
        let honest_mobile = [32u8; 32];
        reg.register_object(
            [1; 32],
            up.record,
            vec![
                (
                    0,
                    Share {
                        validator: rogue_full,
                        class: Class::Full,
                        first_esi: 0,
                        symbols: 4,
                    },
                ),
                (
                    0,
                    Share {
                        validator: honest_full,
                        class: Class::Full,
                        first_esi: 4,
                        symbols: 6,
                    },
                ),
                (
                    0,
                    Share {
                        validator: honest_mobile,
                        class: Class::Mobile,
                        first_esi: 10,
                        symbols: 6,
                    },
                ),
            ],
            0,
            20,
        )
        .unwrap();

        let mut poisoned_share = up.segments[0][0..4].to_vec();
        poisoned_share[0].data[0] ^= 0xFF;
        net.store_holder_share(rogue_full, key, 0, poisoned_share);
        net.store_holder_share(honest_full, key, 0, up.segments[0][4..10].to_vec());
        net.store_holder_share(honest_mobile, key, 0, up.segments[0][10..16].to_vec());

        assert_eq!(view_from_network(&reg, &key, None, &net).unwrap(), payload);

        let mut reveal_mgr = RevealSessionManager::default();
        let sid = reveal_mgr.open_reveal(&reg, &key, 2, &net).unwrap();
        let (_, frames, _) = reveal_mgr.reveal_frames(sid, 0, 32).unwrap();
        let mut meter = Meter::for_object(1 << 20);
        let extracted = super::super::two_path::extract_object_from_frames(&frames, &mut meter)
            .unwrap()
            .public_content()
            .unwrap();
        assert_eq!(extracted, payload);
    }

    #[test]
    fn collect_survives_two_simultaneous_byzantine_holders_and_refuses_total_poison() {
        let mut reg = Bud3Registry::default();
        let mut net = MemorySymbolNetwork::default();

        // Incompressible 1,536-byte payload => k = 13 > 8 with symbols_per_segment = 20 across
        // 5 shares of 4 symbols each: recovering requires at least 4 or 3 honest shares (> 2 shares),
        // so leave-one-out and pairs both fail when 2 holders are Byzantine, and leave-two-out recovers.
        let payload: Vec<u8> = (0u64..48)
            .flat_map(|i| crate::core::hash::hash_fields_bytes(&[b"BYZ5", &i.to_le_bytes()]))
            .collect();
        let up = prepare_public_upload(&payload, &SMALL, &Bud3Limits::default(), 20).unwrap();
        let key = up.record.commitment;
        let validators = [[40u8; 32], [41u8; 32], [42u8; 32], [43u8; 32], [44u8; 32]];
        let shares: Vec<(u64, Share)> = validators
            .iter()
            .enumerate()
            .map(|(i, v)| {
                (
                    0,
                    Share {
                        validator: *v,
                        class: Class::Full,
                        first_esi: u32::try_from(i).unwrap() * 4,
                        symbols: 4,
                    },
                )
            })
            .collect();
        reg.register_object([1; 32], up.record, shares, 0, 20)
            .unwrap();

        let mut bad0 = up.segments[0][0..4].to_vec();
        bad0[0].data[5] ^= 0xAA;
        let mut bad1 = up.segments[0][4..8].to_vec();
        bad1[1].data[9] ^= 0x55;
        net.store_holder_share(validators[0], key, 0, bad0);
        net.store_holder_share(validators[1], key, 0, bad1);
        net.store_holder_share(validators[2], key, 0, up.segments[0][8..12].to_vec());
        net.store_holder_share(validators[3], key, 0, up.segments[0][12..16].to_vec());
        net.store_holder_share(validators[4], key, 0, up.segments[0][16..20].to_vec());

        assert_eq!(view_from_network(&reg, &key, None, &net).unwrap(), payload);

        // When all shares are poisoned, collect_symbols_full_then_mobile returns zero
        // unverified symbols rather than leaking Byzantine bytes.
        for (i, v) in validators.iter().enumerate() {
            let mut poisoned = up.segments[0][(i * 4)..((i + 1) * 4)].to_vec();
            poisoned[0].data[0] ^= 0xFF;
            net.store_holder_share(*v, key, 0, poisoned);
        }
        let (_, syms) = collect_symbols_full_then_mobile(&reg, &key, &net).unwrap();
        assert!(
            syms.is_empty(),
            "unverified Byzantine symbols must never leak out of collect_symbols_full_then_mobile"
        );
        assert!(matches!(
            view_from_network(&reg, &key, None, &net),
            Err(ViewBud3Error::Pipeline(PipelineError::SegmentMissing(0)))
        ));
    }
}
