//! B.U.D. 3.0 request-response symbol protocols (`/budlum/bud3/symbols/1` and
//! `/budlum/bud3/custody/1`) and Mobile Wi-Fi-by-default serving policy.
//!
//! Per Section 6.11.3:
//! * `/budlum/bud3/symbols/1`: client requests an ESI range from a segment
//!   (capped at `64` symbols per request and `16` requests/second per peer);
//!   holder responds with symbols and sub-block/root Merkle proofs.
//! * `/budlum/bud3/custody/1`: gateway or repairer pushes a share's symbols to
//!   a new holder (`1` stream per share, at most `4` concurrent streams per peer).
//! * Mobile validators serve symbols only on unmetered networks (Wi-Fi) by
//!   default; operators may opt into a bounded daily cellular byte ceiling.

use super::custody::{prove, sub_block_count, CustodyProof, ProofContext};
use super::fountain::Symbol;
use super::registry::ObjectKey;
use std::collections::BTreeMap;

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
                let next = self.served_cellular_today_bytes.saturating_add(bytes_to_serve);
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
/// # Errors
///
/// [`SymbolProtocolError::BadMerkleProof`] if any item fails sub-block 0 or root verification.
pub fn verify_symbol_range_response(
    segment: u64,
    symbol_root: [u8; 32],
    symbol_count: u64,
    symbol_size: u16,
    resp: &SymbolRangeResponse,
) -> Result<(), SymbolProtocolError> {
    let ctx = ProofContext {
        symbol_root,
        symbol_count,
        sub_blocks: sub_block_count(usize::from(symbol_size)),
    };
    for item in &resp.items {
        let audit = super::custody::Audit {
            segment,
            position: item.proof.position,
            sub_block: 0,
        };
        item.proof
            .verify(&audit, &ctx)
            .map_err(|_| SymbolProtocolError::BadMerkleProof)?;
        let prefix_len = item.symbol.data.len().min(super::custody::SUB_BLOCK);
        let Some(sym_prefix) = item.symbol.data.get(..prefix_len) else {
            return Err(SymbolProtocolError::BadMerkleProof);
        };
        let Some(proof_prefix) = item.proof.bytes.get(..prefix_len) else {
            return Err(SymbolProtocolError::BadMerkleProof);
        };
        if sym_prefix != proof_prefix {
            return Err(SymbolProtocolError::BadMerkleProof);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::custody::{symbol_leaf, symbol_root};
    use super::super::fountain::SegmentEncoder;
    use super::super::limits::Profile;
    use super::*;

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
}
