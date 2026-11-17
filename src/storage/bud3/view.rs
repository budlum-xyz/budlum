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
use super::fountain::{FountainError, SegmentDecoder, Symbol};
use super::frame::{frames_for_object_bytes, Bud3Frame};
use super::meter::Meter;
use super::pipeline::{view_public, view_sealed, ObjectRecord, PipelineError};
use super::placement::{Class, Share};
use super::registry::{Address, Bud3Registry, ObjectKey};
use super::segment::{commit_object, Segmentation};
use std::collections::BTreeMap;

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
/// Every read comes back empty, so a view through it fails with a
/// missing-symbols error and never returns unverified bytes.
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

/// Collect symbols for every segment of `object` from `network`, querying
/// `Class::Full` shares before `Class::Mobile` shares (Section 6.5 G3).
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

    let mut collected = Vec::new();
    for (seg, sh) in shares_ordered {
        let syms =
            network.fetch_holder_symbols(&sh.validator, object, seg, sh.first_esi, sh.symbols);
        collected.extend(syms);
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
        let mut meter = Meter::new(
            record.object_len.saturating_mul(4).saturating_add(1 << 20),
            u64::from(record.symbols_per_segment).saturating_mul(seg_count),
        );
        for sym in symbols {
            if sym.segment >= seg_count {
                continue;
            }
            if !decoders.contains_key(&sym.segment) {
                let len = seg
                    .len(sym.segment)
                    .ok_or(ViewBud3Error::Pipeline(PipelineError::TooLarge))?;
                let dec = SegmentDecoder::new(sym.segment, len, &record.profile)
                    .map_err(PipelineError::Fountain)?;
                decoders.insert(sym.segment, dec);
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
        if commit_object(&object_bytes, &record.profile) != Some(record.commitment) {
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
}
