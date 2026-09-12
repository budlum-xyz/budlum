//! Minimal Ethereum block header decode + chain-link + N-confirmation finality.
//!
//! Sync-committee light-client finality = **F10.3** (PoS, BLS12-381 sync-aggregate).
//! This module provides **bounded k-confirmation** (RFC Q2 = both -> N-conf
//! fallback; the PoS sync committee is added later as an option).
//!
//! # Fork tolerance
//!
//! Ethereum header fields are read in Yellow Paper order at the positions the
//! code expects (front-positioned canonical fields). Fork-specific trailing
//! fields (`baseFeePerGas` EIP-1559, `withdrawalsRoot` Shanghai,
//! `blobGasUsed`/`ExcessBlobGas`/`parentBeaconBlockRoot` Cancun) are not
//! decoded (tail-ignore). They do not weaken security, because they do not
//! affect the `hash = keccak256(rlp(raw_header))` computation: the whole raw
//! byte string is hashed.

use crate::cross_domain::evm::mpt::keccak256;
use crate::cross_domain::evm::rlp::{self, Item, RlpError};

/// Minimal Ethereum header (the fields the bridge verification needs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthHeader {
    /// `parentHash` - the chain link (must match parent.hash).
    pub parent_hash: [u8; 32],
    /// `number` - the block height.
    pub number: u64,
    /// `stateRoot` - the account trie root (informational).
    pub state_root: [u8; 32],
    /// `receiptsRoot` - the receipts trie root (a receipt proof anchors to it).
    pub receipts_root: [u8; 32],
    /// `keccak256(rlp(raw_header))` - the block identity (chain link plus
    /// confirmation depth).
    pub hash: [u8; 32],
}

/// Header decode / chain verification error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderError {
    Rlp(RlpError),
    /// Invalid header structure (missing field / wrong size).
    InvalidHeader,
    /// The chain is broken (parent_hash -> child.hash / number+1 mismatch).
    ChainBroken,
    /// The N-confirmation threshold was not met (too few confirmation
    /// headers).
    InsufficientConfirmations,
    /// The caller demanded zero confirmations. A target with no header above
    /// it can still be reorged away, so a zero window is not a window.
    ZeroConfirmations,
}

impl std::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderError::Rlp(e) => write!(f, "header rlp error: {e}"),
            HeaderError::InvalidHeader => write!(f, "header: invalid structure"),
            HeaderError::ChainBroken => write!(f, "header: chain broken"),
            HeaderError::InsufficientConfirmations => {
                write!(f, "header: insufficient confirmations")
            }
            HeaderError::ZeroConfirmations => write!(f, "header: zero confirmations demanded"),
        }
    }
}

impl std::error::Error for HeaderError {}

impl From<RlpError> for HeaderError {
    fn from(e: RlpError) -> Self {
        HeaderError::Rlp(e)
    }
}

/// Default confirmation depth for the bridge (an upper bound on the reorg
/// window; mainnet is around 64). In production it is settable through
/// governance/config, it is NOT hard-coded (RFC Q2).
pub const DEFAULT_CONFIRMATIONS: u32 = 64;

/// Decode raw RLP header bytes into a minimal `EthHeader`.
///
/// Yellow Paper field order (front canonical):
/// `[parentHash(32), ommersHash(32), coinbase(20), stateRoot(32),
///   TransactionsRoot(32), receiptsRoot(32), logsBloom(256), difficulty, number, ...]`
pub fn decode_header(raw: &[u8]) -> Result<EthHeader, HeaderError> {
    let item = rlp::decode(raw)?;
    let list = match item {
        Item::List(ref l) => l,
        _ => return Err(HeaderError::InvalidHeader),
    };
    if list.len() < 9 {
        return Err(HeaderError::InvalidHeader);
    }
    let parent_hash = arr32(rlp::as_bytes(&list[0])?)?;
    let state_root = arr32(rlp::as_bytes(&list[3])?)?;
    let receipts_root = arr32(rlp::as_bytes(&list[5])?)?;
    let number = rlp::decode_uint(&list[8]).map_err(HeaderError::from)?;
    let hash = keccak256(raw);
    Ok(EthHeader {
        parent_hash,
        number,
        state_root,
        receipts_root,
        hash,
    })
}

/// Helper for a 32-byte hash field (length check).
fn arr32(b: &[u8]) -> Result<[u8; 32], HeaderError> {
    if b.len() != 32 {
        return Err(HeaderError::InvalidHeader);
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(b);
    Ok(a)
}

/// N-confirmation finality: verifies that `required` confirmation headers sit
/// above the target header and that their chain is canonical
/// (parent_hash -> child.hash, number+1). Once the reorg window has passed, the
/// target counts as finalized.
///
/// `required` is the caller's demand and it must be at least one: with zero
/// the loop below runs over nothing and any decodable header "finalises"
/// itself. The adapter holds the configured floor and refuses a proof that
/// demands less than it before this function runs.
///
/// # Errors
///
/// `ZeroConfirmations` for a zero demand, `InsufficientConfirmations` when
/// fewer headers than demanded were supplied, `ChainBroken` when a header
/// does not link to the one below it by hash and by number.
pub fn verify_chain(
    target: &EthHeader,
    confirmations: &[EthHeader],
    required: u32,
) -> Result<(), HeaderError> {
    if required == 0 {
        return Err(HeaderError::ZeroConfirmations);
    }
    if (confirmations.len() as u32) < required {
        return Err(HeaderError::InsufficientConfirmations);
    }
    let mut prev_hash = target.hash;
    let mut prev_number = target.number;
    for hdr in confirmations {
        if hdr.parent_hash != prev_hash {
            return Err(HeaderError::ChainBroken);
        }
        // `number` is decoded from relayer-supplied bytes; at `u64::MAX` a
        // plain `+ 1` overflows, which is a panic on remote input.
        if Some(hdr.number) != prev_number.checked_add(1) {
            return Err(HeaderError::ChainBroken);
        }
        prev_hash = hdr.hash;
        prev_number = hdr.number;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::evm::rlp::{encode, Item};

    /// Test helper: a minimal 9-field header RLP (NO trailing fork fields).
    fn header_bytes(parent: [u8; 32], number: u64, receipts_root: [u8; 32]) -> Vec<u8> {
        let item = Item::List(vec![
            Item::String(parent.to_vec()),        // parentHash
            Item::String(vec![0u8; 32]),          // ommersHash
            Item::String(vec![0u8; 20]),          // coinbase
            Item::String(vec![0u8; 32]),          // stateRoot
            Item::String(vec![0u8; 32]),          // transactionsRoot
            Item::String(receipts_root.to_vec()), // receiptsRoot
            Item::String(vec![0u8; 256]),         // logsBloom
            Item::String(vec![]),                 // difficulty (0)
            Item::String(trim_u64(number)),       // number
        ]);
        encode(&item)
    }

    fn trim_u64(n: u64) -> Vec<u8> {
        if n == 0 {
            return Vec::new();
        }
        let be = n.to_be_bytes();
        let start = be.iter().position(|&b| b != 0).unwrap_or(be.len());
        be[start..].to_vec()
    }

    #[test]
    fn decode_canonical_fields() {
        let parent = [1u8; 32];
        let rroot = [2u8; 32];
        let bytes = header_bytes(parent, 42, rroot);
        let h = decode_header(&bytes).unwrap();
        assert_eq!(h.parent_hash, parent);
        assert_eq!(h.number, 42);
        assert_eq!(h.receipts_root, rroot);
        assert_eq!(h.hash, keccak256(&bytes));
    }

    #[test]
    fn decode_tolerates_trailing_fork_fields() {
        // The EIP-1559 baseFeePerGas extra field -> a 10-item list; the
        // decoder reads the first 9.
        let parent = [3u8; 32];
        let mut nine = match rlp::decode(&header_bytes(parent, 7, [4u8; 32])).unwrap() {
            Item::List(l) => l,
            _ => unreachable!(),
        };
        nine.push(Item::String(vec![0x01; 8])); // baseFeePerGas
        let bytes = encode(&Item::List(nine));
        let h = decode_header(&bytes).unwrap();
        assert_eq!(h.number, 7);
        assert_eq!(h.parent_hash, parent);
    }

    #[test]
    fn verify_chain_happy_path() {
        let mut roots = [0u8; 32];
        let target_bytes = header_bytes([9u8; 32], 100, roots);
        let target = decode_header(&target_bytes).unwrap();

        // 3 confirmation headers: parent = previous hash, number+1.
        let mut confs = Vec::new();
        let mut prev_hash = target.hash;
        let mut prev_num = target.number;
        for i in 0..3 {
            roots[0] = i;
            let bytes = header_bytes(prev_hash, prev_num + 1, roots);
            let h = decode_header(&bytes).unwrap();
            prev_hash = h.hash;
            prev_num = h.number;
            confs.push(h);
        }
        assert!(verify_chain(&target, &confs, 3).is_ok());
    }

    #[test]
    fn verify_chain_broken_parent_link() {
        let target = decode_header(&header_bytes([1u8; 32], 10, [0u8; 32])).unwrap();
        let bad = decode_header(&header_bytes([99u8; 32], 11, [0u8; 32])).unwrap(); // wrong parent
        assert_eq!(
            verify_chain(&target, &[bad], 1).unwrap_err(),
            HeaderError::ChainBroken
        );
    }

    #[test]
    fn verify_chain_broken_number_gap() {
        let target = decode_header(&header_bytes([1u8; 32], 10, [0u8; 32])).unwrap();
        let gap = decode_header(&header_bytes(target.hash, 15, [0u8; 32])).unwrap(); // number jump
        assert_eq!(
            verify_chain(&target, &[gap], 1).unwrap_err(),
            HeaderError::ChainBroken
        );
    }

    #[test]
    fn verify_chain_insufficient_confirmations() {
        let target = decode_header(&header_bytes([1u8; 32], 10, [0u8; 32])).unwrap();
        let one = decode_header(&header_bytes(target.hash, 11, [0u8; 32])).unwrap();
        assert_eq!(
            verify_chain(&target, &[one], 64).unwrap_err(),
            HeaderError::InsufficientConfirmations
        );
    }

    /// A zero demand is refused before any header is looked at. With the
    /// old code `verify_chain(&target, &[], 0)` returned `Ok`, so a proof
    /// that named zero confirmations finalised its own target.
    #[test]
    fn verify_chain_refuses_a_zero_demand() {
        let target = decode_header(&header_bytes([1u8; 32], 10, [0u8; 32])).unwrap();
        let one = decode_header(&header_bytes(target.hash, 11, [0u8; 32])).unwrap();
        assert_eq!(
            verify_chain(&target, &[], 0).unwrap_err(),
            HeaderError::ZeroConfirmations
        );
        assert_eq!(
            verify_chain(&target, std::slice::from_ref(&one), 0).unwrap_err(),
            HeaderError::ZeroConfirmations
        );
        assert!(verify_chain(&target, &[one], 1).is_ok());
    }

    /// A target at `u64::MAX` cannot have a child by number. The old
    /// `prev_number + 1` overflowed here, a panic on relayer bytes.
    #[test]
    fn verify_chain_treats_a_number_at_the_ceiling_as_broken() {
        let target = decode_header(&header_bytes([1u8; 32], u64::MAX, [0u8; 32])).unwrap();
        let child = decode_header(&header_bytes(target.hash, 0, [0u8; 32])).unwrap();
        assert_eq!(
            verify_chain(&target, &[child], 1).unwrap_err(),
            HeaderError::ChainBroken
        );
    }

    #[test]
    fn decode_rejects_too_short_header() {
        // Only 5 fields (< 9 required)
        let item = Item::List(vec![
            Item::String(vec![0u8; 32]),
            Item::String(vec![0u8; 32]),
            Item::String(vec![0u8; 20]),
            Item::String(vec![0u8; 32]),
            Item::String(vec![0u8; 32]),
        ]);
        assert_eq!(
            decode_header(&encode(&item)).unwrap_err(),
            HeaderError::InvalidHeader
        );
    }
}
