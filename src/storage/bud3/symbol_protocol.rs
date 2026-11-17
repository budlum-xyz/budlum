//! B.U.D. 3.0 request-response symbol protocols (`/budlum/bud3/symbols/1` and
//! `/budlum/bud3/custody/1`) and Mobile Wi-Fi-by-default serving policy.
//! exposed for libp2p symbol protocol handlers, `Bud3ContentGateway`, and `Bud3RpcService`.
//!
//! Per Section 6.11.3:
//! * `/budlum/bud3/symbols/1`: client requests an ESI range from a segment
//!   (capped at `64` symbols per request and `16` requests/second per peer);
//!   holder responds with symbols and sub-block/root Merkle proofs.
//! * `/budlum/bud3/custody/1`: gateway or repairer pushes a share's symbols to
//!   a new holder (`1` stream per share, at most `4` concurrent streams per peer).
//! * Mobile validators serve symbols only on unmetered networks (Wi-Fi) by
//!   default; operators may opt into a bounded daily cellular byte ceiling.

use super::custody::{
    prove, sub_block_count, symbol_leaf, verify_symbol_root_path, Audit, CustodyProof, ProofContext,
};
use super::fountain::Symbol;
use super::registry::{Address, Bud3Registry, ObjectEntry, ObjectKey, SymbolRoot};
use std::collections::{BTreeMap, BTreeSet};

/// libp2p protocol identifier for client symbol reads (Section 6.11.3).
pub const SYMBOLS_PROTOCOL_ID: &str = "/budlum/bud3/symbols/1";

/// libp2p protocol identifier for pushing custody shares to holders (Section 6.11.3).
pub const CUSTODY_PROTOCOL_ID: &str = "/budlum/bud3/custody/1";

/// Maximum symbols a peer may request in one `/budlum/bud3/symbols/1` message.
pub const MAX_SYMBOLS_PER_REQUEST: u32 = 64;

/// Maximum `/budlum/bud3/symbols/1` requests permitted per peer per second.
pub const MAX_SYMBOL_REQUESTS_PER_SEC: u32 = 16;

/// Maximum concurrent `/budlum/bud3/custody/1` streams per share.
pub const MAX_STREAMS_PER_SHARE: u32 = 1;

/// Maximum concurrent `/budlum/bud3/custody/1` streams per peer.
pub const MAX_CUSTODY_STREAMS_PER_PEER: u32 = 4;

/// Network link metering classification for Mobile symbol serving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkMetering {
    /// Unmetered link (Wi-Fi / Ethernet): Mobile validators serve by default.
    Unmetered,
    /// Metered cellular link: refused by default unless within the user's daily cap.
    MeteredCellular,
}

/// Mobile validator serving policy (Section 6.11.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MobileServePolicy {
    /// Optional user-configured daily cellular serving cap in bytes (`0` = Wi-Fi only).
    pub daily_cellular_cap_bytes: u64,
    /// Bytes already served over metered cellular during the current UTC day.
    pub served_cellular_today_bytes: u64,
}

impl MobileServePolicy {
    /// Check and account `bytes_to_serve` on `link`. Unmetered Wi-Fi always
    /// passes; cellular passes only when `daily_cellular_cap_bytes` covers it.
    pub fn admit_serve(&mut self, link: LinkMetering, bytes_to_serve: u64) -> bool {
        match link {
            LinkMetering::Unmetered => true,
            LinkMetering::MeteredCellular => {
                let next = self
                    .served_cellular_today_bytes
                    .saturating_add(bytes_to_serve);
                if self.daily_cellular_cap_bytes == 0 || next > self.daily_cellular_cap_bytes {
                    false
                } else {
                    self.served_cellular_today_bytes = next;
                    true
                }
            }
        }
    }
}

/// Request message on `/budlum/bud3/symbols/1`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SymbolRangeRequest {
    /// Target object commitment.
    pub object: ObjectKey,
    /// Segment index.
    pub segment: u64,
    /// First requested ESI.
    pub first_esi: u32,
    /// Number of symbols requested (`1..=64`).
    pub count: u32,
}

/// One symbol accompanied by its sub-block-0 custody proof anchoring it to `symbol_root`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VerifiedSymbolItem {
    /// Coded RFC 6330 symbol.
    pub symbol: Symbol,
    /// Merkle proof of sub-block 0 under the segment's symbol root.
    pub proof: CustodyProof,
}

/// Response message on `/budlum/bud3/symbols/1`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SymbolRangeResponse {
    /// Returned symbols and Merkle proofs.
    pub items: Vec<VerifiedSymbolItem>,
}

/// Push payload on `/budlum/bud3/custody/1`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CustodyPushMessage {
    /// Target object commitment.
    pub object: ObjectKey,
    /// Segment index.
    pub segment: u64,
    /// First ESI of the pushed share.
    pub first_esi: u32,
    /// Contiguous symbols of the share.
    pub symbols: Vec<Symbol>,
}

/// Protocol limit or verification failure on `/budlum/bud3/{symbols,custody}/1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolProtocolError {
    /// `count == 0` or `count > MAX_SYMBOLS_PER_REQUEST` (64).
    InvalidSymbolCount,
    /// Peer exceeded `MAX_SYMBOL_REQUESTS_PER_SEC` (16 req/s).
    RateLimited,
    /// Mobile validator is on metered cellular without available daily allowance.
    MeteredNetworkBlocked,
    /// Peer exceeded `MAX_CUSTODY_STREAMS_PER_PEER` (4) or per-share stream cap (1).
    TooManyCustodyStreams,
    /// Returned symbol failed Merkle proof verification against `symbol_root`.
    BadMerkleProof,
}

/// Per-peer rate and stream limiter enforcing Section 6.11.3 bounds.
#[derive(Debug, Default)]
pub struct SymbolPeerLimiter {
    window_sec: BTreeMap<[u8; 32], (u64, u32)>,
    active_custody_streams: BTreeMap<[u8; 32], u32>,
}

impl SymbolPeerLimiter {
    /// Check and record one `/budlum/bud3/symbols/1` request from `peer` at `now_sec`.
    ///
    /// # Errors
    ///
    /// [`SymbolProtocolError::InvalidSymbolCount`] or [`SymbolProtocolError::RateLimited`].
    pub fn check_symbol_request(
        &mut self,
        peer: &[u8; 32],
        req: &SymbolRangeRequest,
        now_sec: u64,
    ) -> Result<(), SymbolProtocolError> {
        if req.count == 0 || req.count > MAX_SYMBOLS_PER_REQUEST {
            return Err(SymbolProtocolError::InvalidSymbolCount);
        }
        let entry = self.window_sec.entry(*peer).or_insert((now_sec, 0));
        if entry.0 != now_sec {
            *entry = (now_sec, 0);
        }
        if entry.1 >= MAX_SYMBOL_REQUESTS_PER_SEC {
            return Err(SymbolProtocolError::RateLimited);
        }
        entry.1 += 1;
        Ok(())
    }

    /// Open a `/budlum/bud3/custody/1` stream from `peer` (capped at 4 per peer).
    ///
    /// # Errors
    ///
    /// [`SymbolProtocolError::TooManyCustodyStreams`].
    pub fn open_custody_stream(&mut self, peer: &[u8; 32]) -> Result<(), SymbolProtocolError> {
        let count = self.active_custody_streams.entry(*peer).or_insert(0);
        if *count >= MAX_CUSTODY_STREAMS_PER_PEER {
            return Err(SymbolProtocolError::TooManyCustodyStreams);
        }
        *count += 1;
        Ok(())
    }

    /// Close one `/budlum/bud3/custody/1` stream from `peer`.
    pub fn close_custody_stream(&mut self, peer: &[u8; 32]) {
        if let Some(count) = self.active_custody_streams.get_mut(peer) {
            *count = count.saturating_sub(1);
        }
    }
}

/// Build a verified `/budlum/bud3/symbols/1` response for `req` from `placed_leaves`
/// (`(esi, symbol_leaf)` in root order) and the holder's local symbols.
///
/// # Errors
///
/// [`SymbolProtocolError::InvalidSymbolCount`] if `req.count` is outside `1..=64`.
pub fn build_symbol_range_response(
    req: &SymbolRangeRequest,
    placed_leaves: &[(u32, [u8; 32])],
    held_symbols: &[Symbol],
) -> Result<SymbolRangeResponse, SymbolProtocolError> {
    if req.count == 0 || req.count > MAX_SYMBOLS_PER_REQUEST {
        return Err(SymbolProtocolError::InvalidSymbolCount);
    }
    let last_esi = req.first_esi.saturating_add(req.count);
    let mut items = Vec::new();
    for sym in held_symbols {
        if sym.segment != req.segment || sym.esi < req.first_esi || sym.esi >= last_esi {
            continue;
        }
        if let Some(pos) = placed_leaves.iter().position(|(esi, _)| *esi == sym.esi) {
            if let Some(proof) = prove(req.segment, placed_leaves, pos, &sym.data, 0) {
                items.push(VerifiedSymbolItem {
                    symbol: sym.clone(),
                    proof,
                });
            }
        }
    }
    Ok(SymbolRangeResponse { items })
}

/// Verify every item in `resp` against the segment's on-chain `symbol_root`.
///
/// Authenticates the full symbol payload (`symbol_leaf(&item.symbol.data)` via
/// `verify_symbol_root_path`), exact `symbol_size` byte length, matching
/// `(segment, esi)` metadata, bounded item count, duplicate-ESI rejection, and
/// sub-block-0 custody proof consistency.
///
/// # Errors
///
/// [`SymbolProtocolError::InvalidSymbolCount`] if `resp.items` exceeds `MAX_SYMBOLS_PER_REQUEST`,
/// or [`SymbolProtocolError::BadMerkleProof`] if any item fails size, metadata,
/// sub-block 0, or full-symbol Merkle root verification.
pub fn verify_symbol_range_response(
    segment: u64,
    symbol_root: [u8; 32],
    symbol_count: u64,
    symbol_size: u16,
    resp: &SymbolRangeResponse,
) -> Result<(), SymbolProtocolError> {
    if symbol_size == 0 {
        return Err(SymbolProtocolError::BadMerkleProof);
    }
    if usize::try_from(MAX_SYMBOLS_PER_REQUEST).is_ok_and(|max| resp.items.len() > max) {
        return Err(SymbolProtocolError::InvalidSymbolCount);
    }
    let expected_len = usize::from(symbol_size);
    let ctx = ProofContext {
        symbol_root,
        symbol_count,
        sub_blocks: sub_block_count(expected_len),
    };
    let mut seen_esis = BTreeSet::new();
    for item in &resp.items {
        if item.symbol.segment != segment
            || item.symbol.esi != item.proof.esi
            || item.symbol.data.len() != expected_len
            || !seen_esis.insert(item.symbol.esi)
        {
            return Err(SymbolProtocolError::BadMerkleProof);
        }
        let audit = super::custody::Audit {
            segment,
            position: item.proof.position,
            sub_block: 0,
        };
        item.proof
            .verify(&audit, &ctx)
            .map_err(|_| SymbolProtocolError::BadMerkleProof)?;
        let prefix_len = expected_len.min(super::custody::SUB_BLOCK);
        let Some(sym_prefix) = item.symbol.data.get(..prefix_len) else {
            return Err(SymbolProtocolError::BadMerkleProof);
        };
        let Some(proof_prefix) = item.proof.bytes.get(..prefix_len) else {
            return Err(SymbolProtocolError::BadMerkleProof);
        };
        if sym_prefix != proof_prefix {
            return Err(SymbolProtocolError::BadMerkleProof);
        }
        if !verify_symbol_root_path(
            symbol_root,
            symbol_count,
            item.proof.position,
            item.proof.esi,
            symbol_leaf(&item.symbol.data),
            &item.proof.root_path,
        ) {
            return Err(SymbolProtocolError::BadMerkleProof);
        }
    }
    Ok(())
}

/// Maximum verified symbol items retained in node-local memory cache.
const MAX_CACHED_SYMBOL_ITEMS: usize = 65_536;

/// Verify one [`VerifiedSymbolItem`] against a registered [`ObjectEntry`] on-chain.
///
/// Checks that `holder` owns an active (`!lost`) share on `segment` covering
/// `item.symbol.esi`, resolves `entry.roots[share.root]`, and authenticates exact
/// `symbol_size`, `(segment, esi, position = esi - root.first_esi)`, sub-block 0,
/// and the full `symbol_leaf(&item.symbol.data)` Merkle path to `root.root`.
///
/// # Errors
///
/// [`SymbolProtocolError::BadMerkleProof`] if any membership, metadata, length,
/// or Merkle proof check fails.
pub fn verify_item_against_entry(
    entry: &ObjectEntry,
    holder: &Address,
    segment: u64,
    item: &VerifiedSymbolItem,
) -> Result<SymbolRoot, SymbolProtocolError> {
    let symbol_size = entry.record.profile.symbol_size;
    let expected_len = usize::from(symbol_size);
    if symbol_size == 0
        || item.symbol.segment != segment
        || item.symbol.esi != item.proof.esi
        || item.symbol.data.len() != expected_len
    {
        return Err(SymbolProtocolError::BadMerkleProof);
    }
    let Some(share_state) = entry.shares.iter().find(|s| {
        !s.lost
            && s.segment == segment
            && s.share.validator == *holder
            && item.symbol.esi >= s.share.first_esi
            && item.symbol.esi < s.share.first_esi.saturating_add(s.share.symbols)
    }) else {
        return Err(SymbolProtocolError::BadMerkleProof);
    };
    let sym_root = *entry
        .roots
        .get(share_state.root)
        .ok_or(SymbolProtocolError::BadMerkleProof)?;
    if sym_root.segment != segment || sym_root.count == 0 || item.symbol.esi < sym_root.first_esi {
        return Err(SymbolProtocolError::BadMerkleProof);
    }
    let expected_pos = u64::from(item.symbol.esi - sym_root.first_esi);
    if expected_pos >= u64::from(sym_root.count) || item.proof.position != expected_pos {
        return Err(SymbolProtocolError::BadMerkleProof);
    }
    let ctx = ProofContext {
        symbol_root: sym_root.root,
        symbol_count: u64::from(sym_root.count),
        sub_blocks: sub_block_count(expected_len),
    };
    let audit = Audit {
        segment,
        position: expected_pos,
        sub_block: 0,
    };
    item.proof
        .verify(&audit, &ctx)
        .map_err(|_| SymbolProtocolError::BadMerkleProof)?;
    let prefix_len = expected_len.min(super::custody::SUB_BLOCK);
    let sym_prefix = item
        .symbol
        .data
        .get(..prefix_len)
        .ok_or(SymbolProtocolError::BadMerkleProof)?;
    let proof_prefix = item
        .proof
        .bytes
        .get(..prefix_len)
        .ok_or(SymbolProtocolError::BadMerkleProof)?;
    if sym_prefix != proof_prefix {
        return Err(SymbolProtocolError::BadMerkleProof);
    }
    if !verify_symbol_root_path(
        sym_root.root,
        u64::from(sym_root.count),
        expected_pos,
        item.proof.esi,
        symbol_leaf(&item.symbol.data),
        &item.proof.root_path,
    ) {
        return Err(SymbolProtocolError::BadMerkleProof);
    }
    Ok(sym_root)
}

/// Bounded node-local store of verified [`VerifiedSymbolItem`]s indexed by
/// `(holder, object, segment, esi)` (kept outside consensus `AccountState`).
#[derive(Debug, Default, Clone)]
pub struct Bud3SymbolStore {
    slots: BTreeMap<(Address, ObjectKey, u64), BTreeMap<u32, VerifiedSymbolItem>>,
    total_items: usize,
}

impl Bud3SymbolStore {
    /// Verify every item against `registry` and insert into the node-local store.
    /// Refuses the entire batch if the object is unknown/tombstoned, the batch is
    /// empty or exceeds `MAX_SYMBOLS_PER_REQUEST`, contains duplicate ESIs, or any
    /// item fails holder/share/Merkle verification.
    ///
    /// # Errors
    ///
    /// [`SymbolProtocolError::InvalidSymbolCount`] or [`SymbolProtocolError::BadMerkleProof`].
    pub fn insert_verified(
        &mut self,
        registry: &Bud3Registry,
        holder: &Address,
        object: &ObjectKey,
        segment: u64,
        items: &[VerifiedSymbolItem],
    ) -> Result<Vec<VerifiedSymbolItem>, SymbolProtocolError> {
        if items.is_empty()
            || usize::try_from(MAX_SYMBOLS_PER_REQUEST).is_ok_and(|max| items.len() > max)
        {
            return Err(SymbolProtocolError::InvalidSymbolCount);
        }
        let (live_key, entry) = registry
            .resolve_live_object(object)
            .ok_or(SymbolProtocolError::BadMerkleProof)?;
        let mut seen = BTreeSet::new();
        for item in items {
            if !seen.insert(item.symbol.esi) {
                return Err(SymbolProtocolError::BadMerkleProof);
            }
            verify_item_against_entry(entry, holder, segment, item)?;
        }
        let slot = self.slots.entry((*holder, live_key, segment)).or_default();
        for item in items {
            if slot.insert(item.symbol.esi, item.clone()).is_none() {
                self.total_items = self.total_items.saturating_add(1);
            }
        }
        if self.total_items > MAX_CACHED_SYMBOL_ITEMS {
            let _ = self.prune_unregistered(registry);
        }
        while self.total_items > MAX_CACHED_SYMBOL_ITEMS {
            let Some((_, removed)) = self.slots.pop_first() else {
                self.total_items = 0;
                break;
            };
            self.total_items = self.total_items.saturating_sub(removed.len());
        }
        Ok(items.to_vec())
    }

    /// Return verified items for `(holder, object, segment, first_esi..+count)`,
    /// re-verifying every item against live `registry` state on read.
    #[must_use]
    pub fn verified_range(
        &self,
        registry: &Bud3Registry,
        holder: &Address,
        object: &ObjectKey,
        segment: u64,
        first_esi: u32,
        count: u32,
    ) -> SymbolRangeResponse {
        if count == 0 {
            return SymbolRangeResponse { items: Vec::new() };
        }
        let Some((live_key, entry)) = registry.resolve_live_object(object) else {
            return SymbolRangeResponse { items: Vec::new() };
        };
        let Some(slot) = self.slots.get(&(*holder, live_key, segment)) else {
            return SymbolRangeResponse { items: Vec::new() };
        };
        let capped = count.min(MAX_SYMBOLS_PER_REQUEST);
        let last_inclusive = first_esi.saturating_add(capped - 1);
        let items = slot
            .range(first_esi..=last_inclusive)
            .filter_map(|(_, item)| {
                verify_item_against_entry(entry, holder, segment, item)
                    .ok()
                    .map(|_| item.clone())
            })
            .collect();
        SymbolRangeResponse { items }
    }

    /// Remove cached entries whose objects are no longer live in `registry`,
    /// returning the unique removed object keys for backing-store cleanup.
    pub fn prune_unregistered(&mut self, registry: &Bud3Registry) -> Vec<ObjectKey> {
        let stale_keys: Vec<(Address, ObjectKey, u64)> = self
            .slots
            .keys()
            .filter(|(_, obj, _)| registry.object(obj).is_none())
            .copied()
            .collect();
        let mut removed_objects = BTreeSet::new();
        for key in stale_keys {
            if let Some(removed) = self.slots.remove(&key) {
                self.total_items = self.total_items.saturating_sub(removed.len());
                removed_objects.insert(key.1);
            }
        }
        removed_objects.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::custody::{symbol_leaf, symbol_root};
    use super::super::fountain::SegmentEncoder;
    use super::super::limits::{Bud3Limits, Profile};
    use super::super::pipeline::prepare_public_upload;
    use super::super::placement::{Class, Share};
    use super::*;

    #[test]
    fn bud3_symbol_store_verifies_on_store_read_loss_and_tombstone() {
        let profile = Profile {
            id: 0,
            qr_version: 40,
            symbol_size: 128,
            fps: 10,
            k_max: 16,
        };
        let up = prepare_public_upload(
            b"verified symbol store content payload",
            &profile,
            &Bud3Limits::default(),
            8,
        )
        .unwrap();
        let obj = up.record.commitment;
        let holder_a = [0x11u8; 32];
        let holder_b = [0x22u8; 32];
        let nft_id = [0x33u8; 32];
        let mut reg = Bud3Registry::default();
        reg.register_object(
            [0x01u8; 32],
            up.record.clone(),
            vec![
                (
                    0,
                    Share {
                        validator: holder_a,
                        class: Class::Full,
                        first_esi: 0,
                        symbols: 4,
                    },
                ),
                (
                    0,
                    Share {
                        validator: holder_b,
                        class: Class::Full,
                        first_esi: 4,
                        symbols: 4,
                    },
                ),
            ],
            0,
            20,
        )
        .unwrap();
        reg.bind_nft(nft_id, [0x01u8; 32], Some([0x01u8; 32]), &obj)
            .unwrap();

        let leaves: Vec<(u32, [u8; 32])> = up.segments[0]
            .iter()
            .map(|s| (s.esi, symbol_leaf(&s.data)))
            .collect();
        let resp_a = build_symbol_range_response(
            &SymbolRangeRequest {
                object: obj,
                segment: 0,
                first_esi: 0,
                count: 4,
            },
            &leaves,
            &up.segments[0][0..4],
        )
        .unwrap();

        let mut store = Bud3SymbolStore::default();
        // Wrong holder cannot ingest holder_a's ESIs.
        assert_eq!(
            store.insert_verified(&reg, &holder_b, &obj, 0, &resp_a.items),
            Err(SymbolProtocolError::BadMerkleProof)
        );
        // Tampered payload fails verification before insertion.
        let mut forged = resp_a.items.clone();
        forged[0].symbol.data[90] ^= 0xFF;
        assert_eq!(
            store.insert_verified(&reg, &holder_a, &obj, 0, &forged),
            Err(SymbolProtocolError::BadMerkleProof)
        );
        // Valid items store cleanly and re-verify on read.
        assert_eq!(
            store
                .insert_verified(&reg, &holder_a, &obj, 0, &resp_a.items)
                .unwrap()
                .len(),
            4
        );
        assert_eq!(
            store
                .verified_range(&reg, &holder_a, &obj, 0, 0, 4)
                .items
                .len(),
            4
        );

        // Once holder_a's share is lost or the object is burned/tombstoned, reads refuse to serve.
        reg.burn_reference(&nft_id, &[0x01u8; 32], 1).unwrap();
        assert!(store
            .verified_range(&reg, &holder_a, &obj, 0, 0, 4)
            .items
            .is_empty());
        assert_eq!(store.prune_unregistered(&reg), vec![obj]);
    }

    #[test]
    fn symbols_protocol_caps_rate_and_verifies_merkle_paths() {
        let profile = Profile {
            id: 0,
            qr_version: 40,
            symbol_size: 128,
            fps: 10,
            k_max: 16,
        };
        let enc = SegmentEncoder::new(0, &[0x42; 512], &profile).unwrap();
        let syms = enc.source_symbols();
        let leaves: Vec<(u32, [u8; 32])> =
            syms.iter().map(|s| (s.esi, symbol_leaf(&s.data))).collect();
        let root = symbol_root(&leaves);

        let mut limiter = SymbolPeerLimiter::default();
        let peer = [7u8; 32];
        let too_big = SymbolRangeRequest {
            object: [1; 32],
            segment: 0,
            first_esi: 0,
            count: 65,
        };
        assert_eq!(
            limiter.check_symbol_request(&peer, &too_big, 100),
            Err(SymbolProtocolError::InvalidSymbolCount)
        );

        let req = SymbolRangeRequest {
            object: [1; 32],
            segment: 0,
            first_esi: 0,
            count: 4,
        };
        for _ in 0..MAX_SYMBOL_REQUESTS_PER_SEC {
            limiter.check_symbol_request(&peer, &req, 100).unwrap();
        }
        assert_eq!(
            limiter.check_symbol_request(&peer, &req, 100),
            Err(SymbolProtocolError::RateLimited)
        );

        let resp = build_symbol_range_response(&req, &leaves, &syms).unwrap();
        assert_eq!(resp.items.len(), 4);
        verify_symbol_range_response(0, root, syms.len() as u64, profile.symbol_size, &resp)
            .unwrap();
    }

    #[test]
    fn mobile_policy_defaults_to_wifi_only() {
        let mut policy = MobileServePolicy::default();
        assert!(policy.admit_serve(LinkMetering::Unmetered, 1_000_000));
        assert!(!policy.admit_serve(LinkMetering::MeteredCellular, 1));

        policy.daily_cellular_cap_bytes = 4_096;
        assert!(policy.admit_serve(LinkMetering::MeteredCellular, 2_048));
        assert!(!policy.admit_serve(LinkMetering::MeteredCellular, 3_000));
    }

    #[test]
    fn verify_symbol_range_response_rejects_tampered_trailing_bytes_truncated_and_wrong_metadata() {
        let profile = Profile {
            id: 0,
            qr_version: 40,
            symbol_size: 128,
            fps: 10,
            k_max: 16,
        };
        let enc = SegmentEncoder::new(0, &[0x42; 512], &profile).unwrap();
        let syms = enc.source_symbols();
        let leaves: Vec<(u32, [u8; 32])> =
            syms.iter().map(|s| (s.esi, symbol_leaf(&s.data))).collect();
        let root = symbol_root(&leaves);
        let req = SymbolRangeRequest {
            object: [1; 32],
            segment: 0,
            first_esi: 0,
            count: 4,
        };
        let valid_resp = build_symbol_range_response(&req, &leaves, &syms).unwrap();

        // Tampering bytes beyond the 64-byte sub-block 0 prefix must be rejected.
        let mut tampered_tail = valid_resp.clone();
        tampered_tail.items[0].symbol.data[64] ^= 0xFF;
        assert_eq!(
            verify_symbol_range_response(
                0,
                root,
                syms.len() as u64,
                profile.symbol_size,
                &tampered_tail
            ),
            Err(SymbolProtocolError::BadMerkleProof)
        );

        // Truncated or empty symbol payloads cannot bypass the prefix check.
        let mut empty_data = valid_resp.clone();
        empty_data.items[0].symbol.data.clear();
        assert_eq!(
            verify_symbol_range_response(
                0,
                root,
                syms.len() as u64,
                profile.symbol_size,
                &empty_data
            ),
            Err(SymbolProtocolError::BadMerkleProof)
        );

        // Spoofed symbol.segment or symbol.esi with a valid proof must be refused.
        let mut wrong_seg = valid_resp.clone();
        wrong_seg.items[0].symbol.segment = 7;
        assert_eq!(
            verify_symbol_range_response(
                0,
                root,
                syms.len() as u64,
                profile.symbol_size,
                &wrong_seg
            ),
            Err(SymbolProtocolError::BadMerkleProof)
        );
        let mut wrong_esi = valid_resp.clone();
        wrong_esi.items[0].symbol.esi = 99;
        assert_eq!(
            verify_symbol_range_response(
                0,
                root,
                syms.len() as u64,
                profile.symbol_size,
                &wrong_esi
            ),
            Err(SymbolProtocolError::BadMerkleProof)
        );

        // Duplicate ESIs inside one response must be refused.
        let mut dup_esi = valid_resp;
        let first_item = dup_esi.items[0].clone();
        dup_esi.items.push(first_item);
        assert_eq!(
            verify_symbol_range_response(0, root, syms.len() as u64, profile.symbol_size, &dup_esi),
            Err(SymbolProtocolError::BadMerkleProof)
        );
    }

    #[test]
    fn bud3_symbol_store_resolves_finalized_replacement_commitment() {
        use super::super::custody::{symbol_leaf, symbol_root};
        use super::super::pipeline::{prepare_public_upload, ObjectRecord};
        use super::super::placement::{Class, Share};
        use super::super::replace::sign_replace_attestation;
        use crate::crypto::pq::ml_dsa_public_key;
        use crate::crypto::scheme::SchemeId;

        let profile = Profile {
            id: 0,
            qr_version: 40,
            symbol_size: 128,
            fps: 10,
            k_max: 16,
        };
        let old_up = prepare_public_upload(
            b"symbol store replacement payload",
            &profile,
            &Bud3Limits::default(),
            12,
        )
        .unwrap();
        let old_key = old_up.record.commitment;
        let validators = [[10u8; 32], [11u8; 32], [12u8; 32]];
        let shares = vec![
            (
                0,
                Share {
                    validator: validators[0],
                    class: Class::Full,
                    first_esi: 0,
                    symbols: 4,
                },
            ),
            (
                0,
                Share {
                    validator: validators[1],
                    class: Class::Full,
                    first_esi: 4,
                    symbols: 4,
                },
            ),
            (
                0,
                Share {
                    validator: validators[2],
                    class: Class::Full,
                    first_esi: 8,
                    symbols: 4,
                },
            ),
        ];
        let mut reg = Bud3Registry::default();
        reg.register_object([1; 32], old_up.record.clone(), shares.clone(), 0, 50)
            .unwrap();
        for v in &validators {
            reg.ack(&old_key, v).unwrap();
        }

        let new_up = prepare_public_upload(
            b"symbol store replacement payload\0",
            &profile,
            &Bud3Limits::default(),
            12,
        )
        .unwrap();
        let leaves: Vec<(u32, [u8; 32])> = new_up.segments[0]
            .iter()
            .map(|s| (s.esi, symbol_leaf(&s.data)))
            .collect();
        let new_rec = ObjectRecord {
            content_id: old_up.record.content_id,
            object_len: new_up.record.object_len,
            commitment: [0xCA; 32],
            profile,
            codec: 0,
            symbols_per_segment: new_up.record.symbols_per_segment,
            symbol_roots: vec![symbol_root(&leaves)],
        };
        let vkeys: BTreeMap<Address, Vec<u8>> = [10u8, 11, 12]
            .into_iter()
            .map(|v| {
                (
                    [v; 32],
                    ml_dsa_public_key(SchemeId::ML_DSA_65, &[v; 32]).unwrap(),
                )
            })
            .collect();
        let atts: Vec<_> = [10u8, 11, 12]
            .into_iter()
            .map(|v| {
                sign_replace_attestation([v; 32], &[v; 32], &old_key, &new_rec, &shares).unwrap()
            })
            .collect();
        let new_key = reg
            .replace_object(
                (validators[0], 10_000),
                &old_key,
                new_rec,
                shares,
                &atts,
                (crate::core::transaction::DEFAULT_CHAIN_ID, 2, &vkeys),
            )
            .unwrap();
        for v in &validators {
            reg.ack(&new_key, v).unwrap();
        }

        let resp = build_symbol_range_response(
            &SymbolRangeRequest {
                object: new_key,
                segment: 0,
                first_esi: 0,
                count: 4,
            },
            &leaves,
            &new_up.segments[0][0..4],
        )
        .unwrap();
        let mut store = Bud3SymbolStore::default();
        store
            .insert_verified(&reg, &validators[0], &old_key, 0, &resp.items)
            .expect("insert_verified must resolve finalized replacement redirects");
        assert_eq!(
            store
                .verified_range(&reg, &validators[0], &old_key, 0, 0, 4)
                .items
                .len(),
            4
        );
        assert_eq!(
            store
                .verified_range(&reg, &validators[0], &new_key, 0, 0, 4)
                .items
                .len(),
            4
        );
    }
}
