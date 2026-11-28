//! Bitcoin SPV finality: the Nakamoto branch of the consensus-of-consensuses.
//!
//! WIRING: `IntakeState::register_domain` constructs `BitcoinSpvAdapter` and the
//! external-domain bridge is the production consumer. The header parser, hash
//! helper and consensus limits are deliberately exposed for the pinned-mainnet
//! test corpus and the canonical spec encoding; those callers do not name every
//! helper in a production `.rs` file yet.
//! WIRING: standalone SPV tx-inclusion and recursive header-STARK
//! verifiers land with the BTC bridge redemption transaction door.
//!
//! # Why this adapter exists
//!
//! The external-domain framework declared [`SecurityBacking::Work`] and the
//! bridge already treats accumulated work as clearing an economic-backing
//! demand, but no adapter ever produced that variant. The probabilistic-PoW
//! branch of the shared attestation model was therefore dead code: every
//! registered family was a signature set or a validity proof. This adapter is
//! the first producer of `Work`, built on the same four-method contract as
//! every other family, so adding it needs no new transaction type and no
//! change to the settlement core.
//!
//! # What it verifies, and what it deliberately does not
//!
//! Evidence is a contiguous run of real 80-byte Bitcoin block headers. The
//! adapter derives, never trusts: the double-SHA256 hash of every header, the
//! parent link back to a *pinned* anchor, the compact `nBits` target, the
//! proof-of-work inequality, the BIP-113 median-time-past timestamp bound, the
//! declared height and the declared root. It refuses an unknown evidence
//! version, a mismatched adapter or network, an unpinned anchor, a truncated
//! payload and a depth below policy.
//!
//! It is a full Nakamoto SPV header-chain and payment verifier: exact 256-bit
//! cumulative chainwork (`floor(2^256 / (target + 1))`), canonical heaviest-chain
//! fork selection, fail-closed 2016-block `[1/4, 4x]` difficulty retargeting,
//! BIP-113 Median-Time-Past (`MTP-11`, exact with 11 known predecessors and a
//! provable lower bound before that), per-header `+2h` future-time
//! enforcement, CVE-2012-2459 and CVE-2017-12842-hardened coinbase/transaction
//! Merkle inclusion with `k`-confirmation depth checks, and 128-bit Plonky3
//! FRI-STARK `BudVM` (`Claim::Prog`) batch header-chain proving and verification.
//!
//! Bitcoin has no state root. The `state_root` slot of
//! [`FinalityAttestation`] is therefore bound to the finalized **block hash**,
//! the only 32-byte value the header commits to; the transaction Merkle root
//! travels separately in `attested_tx_root`. A consumer must not read
//! `state_root` as a UTXO-set commitment.
//!
//! # Determinism and authority
//!
//! The adapter holds no clock: freshness is measured against
//! `VerificationPolicy::now`, supplied by the caller. The anchor is state the
//! adapter HOLDS, registered as data with the domain, never read from the
//! evidence payload - a submitter that could name its own checkpoint could
//! finalise a private low-work chain. There is no admin key, no upgrade
//! switch and no fallback to "assume valid".

#[cfg(test)]
use crate::core::address::Address;
use crate::cross_domain::external::selftest::{
    BytePatch, ExpectedRefusal, FaultProbe, RefusalKind,
};
use crate::cross_domain::external::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, RawConsensusEvidence, SecurityBacking, TimeUnit, TrustModel,
    VerificationPolicy,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Bytes in one Bitcoin block header.
pub const HEADER_LEN: usize = 80;
/// Bounded SPV window (`2_160` headers, `172_800` bytes max).
///
/// Covers a full self-contained 2016-block Bitcoin difficulty epoch plus one
/// 144-block day of confirmations while keeping memory and hashing bounded.
pub const MAX_HEADERS: usize = 2_160;
/// Maximum stripped non-witness Bitcoin transaction size (`1_000_000` bytes).
///
/// WIRING: enforced by [`verify_spv_raw_tx_inclusion`] and [`VerifiedBitcoinChain::verify_confirmed_payment`].
pub const MAX_STRIPPED_TX_BYTES: usize = 1_000_000;
/// Exact 64-byte stripped transaction size forbidden by CVE-2017-12842.
///
/// Prevents masquerading a `left || right` internal Merkle node as a leaf tx.
/// WIRING: enforced by [`verify_spv_raw_tx_inclusion`].
pub const FORBIDDEN_INNER_NODE_TX_BYTES: usize = 64;
/// Maximum headers proven inside one `BudVM` [`crate::aggregation::claim::Claim::Prog`] batch.
///
/// WIRING: enforced by [`compile_bitcoin_header_stark_program`] and [`prove_bitcoin_header_chain_stark`].
pub const MAX_STARK_BATCH_HEADERS: usize = 64;
/// This adapter's evidence format. Only this exact value is accepted.
pub const EVIDENCE_VERSION: u32 = 1;
/// How many headers the evidence must build on the pinned anchor before the
/// tip is called final. Declared in the descriptor so a consumer reads the
/// number before relying on it. This is `required_depth` in the shared model:
/// distance from the trusted checkpoint, not confirmations mined *above* the
/// tip (an SPV proof cannot know those).
pub const REQUIRED_DEPTH: u64 = 6;
/// Maximum seconds a header may be ahead of the policy clock.
pub const MAX_FUTURE_SECONDS: u64 = 2 * 60 * 60;

/// The checkpoint the adapter is pinned to. `block_hash` is in Bitcoin's
/// internal byte order (the raw `SHA256d` output, not the reversed display
/// hex). Stored with the registration, reconstructed on restart, and never
/// supplied by the evidence submitter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedBitcoinAnchor {
    /// Height of the anchor block. Header heights are not in the header, so
    /// every subsequent height is derived by counting from this one.
    pub height: u64,
    pub block_hash: [u8; 32],
    /// `nBits` for the single difficulty epoch this anchor serves.
    pub bits: u32,
}

/// A parsed Bitcoin header in wire order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinHeader {
    pub version: i32,
    pub parent_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u32,
    /// The header's own `SHA256d` digest, internal byte order.
    pub hash: [u8; 32],
}

/// `SHA256(SHA256(bytes))`, in internal byte order.
#[must_use]
pub fn sha256d(bytes: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(bytes);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// Maximum Bitcoin transaction Merkle branch depth (`2^32` transactions).
const MAX_SPV_MERKLE_DEPTH: usize = 32;

/// Verify a Bitcoin SPV transaction inclusion proof against a finalized
/// header's `merkle_root` (`SHA256d` in internal byte order).
///
/// Rejects zero `txid`/`merkle_root`, oversized branches (`> 32`), leftover
/// high index bits above the branch depth, and every `left == right` step an
/// honest tree cannot contain (blocking CVE-2012-2459 odd-leaf duplication
/// malleability). Bitcoin pairs the last node of an odd-width level with
/// itself, so an equal sibling is honest only for a left child that is not the
/// leftmost node of its level.
///
/// Convenience: exposed for external Bitcoin SPV settlement and bridge callers
/// verifying payment inclusion against `FinalityAttestation::attested_tx_root`.
#[must_use]
pub fn verify_spv_tx_inclusion(
    txid: &[u8; 32],
    merkle_root: &[u8; 32],
    tx_index: u32,
    branch: &[[u8; 32]],
) -> bool {
    if *txid == [0u8; 32] || *merkle_root == [0u8; 32] || branch.len() > MAX_SPV_MERKLE_DEPTH {
        return false;
    }
    if branch.len() < 32 && (tx_index >> branch.len()) != 0 {
        return false;
    }
    let mut acc = *txid;
    let mut idx = tx_index;
    let mut pair = Vec::with_capacity(64);
    for sibling in branch {
        // A right child or the leftmost node paired with an equal sibling is
        // the duplicated-tail alias of another index (CVE-2012-2459).
        if acc == *sibling && (idx & 1 == 1 || idx == 0) {
            return false;
        }
        let (left, right) = if idx & 1 == 0 {
            (&acc, sibling)
        } else {
            (sibling, &acc)
        };
        pair.clear();
        pair.extend_from_slice(left);
        pair.extend_from_slice(right);
        acc = sha256d(&pair);
        idx >>= 1;
    }
    acc == *merkle_root
}

/// Verified stripped Bitcoin transaction (or coinbase) inclusion outcome.
///
/// WIRING: returned by [`verify_spv_raw_tx_inclusion`] and [`VerifiedBitcoinChain::verify_confirmed_payment`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedSpvTransaction {
    /// Derived `SHA256d` transaction identifier (internal byte order).
    pub txid: [u8; 32],
    /// Leaf position in the block's transaction Merkle tree (`0` for coinbase).
    pub tx_index: u32,
    /// `true` iff `tx_index == 0` (the block's unique coinbase transaction).
    pub is_coinbase: bool,
    /// Verified confirmations accumulated up to the attested chain tip.
    pub confirmations: u64,
}

#[path = "bitcoin_spv_payment.rs"]
mod payment;

pub use payment::verify_spv_raw_tx_inclusion;

/// Exact unsigned 256-bit Bitcoin cumulative proof-of-work (`nChainWork`).
///
/// Stored as four big-endian `u64` words so `Ord` compares exact integer work.
/// Computes Bitcoin Core's `GetBlockProof`: `(~target / (target + 1)) + 1 ==
/// floor(2^256 / (target + 1))`.
///
/// WIRING: produced by [`BitcoinSpvAdapter::verify_chain`] and consumed by
/// [`select_heaviest_bitcoin_chain`] and the `BudVM` `Claim::Prog` STARK verifier.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct ChainWork256([u64; 4]);

impl ChainWork256 {
    /// Zero accumulated work.
    pub const ZERO: Self = Self([0; 4]);
    /// Maximum representable 256-bit work (`2^256 - 1`).
    pub const MAX: Self = Self([u64::MAX; 4]);

    /// Construct from a 32-byte big-endian unsigned integer.
    ///
    /// Convenience: kept for the CLI and bridge checkpoint decoders.
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; 32]) -> Self {
        let [b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16, b17, b18, b19, b20, b21, b22, b23, b24, b25, b26, b27, b28, b29, b30, b31] =
            bytes;
        Self([
            u64::from_be_bytes([b0, b1, b2, b3, b4, b5, b6, b7]),
            u64::from_be_bytes([b8, b9, b10, b11, b12, b13, b14, b15]),
            u64::from_be_bytes([b16, b17, b18, b19, b20, b21, b22, b23]),
            u64::from_be_bytes([b24, b25, b26, b27, b28, b29, b30, b31]),
        ])
    }

    /// Encode as a 32-byte big-endian unsigned integer.
    #[must_use]
    pub fn to_be_bytes(self) -> [u8; 32] {
        let [w0, w1, w2, w3] = self.0;
        let mut out = [0u8; 32];
        for (chunk, word) in out.as_chunks_mut::<8>().0.iter_mut().zip([w0, w1, w2, w3]) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Return the four little-endian `u64` words `[lo, w1, w2, hi]`.
    #[must_use]
    pub const fn to_le_words(self) -> [u64; 4] {
        let [w0, w1, w2, w3] = self.0;
        [w3, w2, w1, w0]
    }

    /// Return `true` iff accumulated work is zero.
    ///
    /// Convenience: kept for the CLI and bridge inspection helpers.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        let [w0, w1, w2, w3] = self.0;
        w0 == 0 && w1 == 0 && w2 == 0 && w3 == 0
    }

    /// Checked 256-bit unsigned addition.
    #[must_use]
    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        let [a0, a1, a2, a3] = self.0;
        let [b0, b1, b2, b3] = rhs.0;
        let (r3, c3) = a3.overflowing_add(b3);
        let (t2, c2a) = a2.overflowing_add(b2);
        let (r2, c2b) = t2.overflowing_add(c3 as u64);
        let (t1, c1a) = a1.overflowing_add(b1);
        let (r1, c1b) = t1.overflowing_add((c2a || c2b) as u64);
        let (t0, c0a) = a0.overflowing_add(b0);
        let (r0, c0b) = t0.overflowing_add((c1a || c1b) as u64);
        if c0a || c0b {
            None
        } else {
            Some(Self([r0, r1, r2, r3]))
        }
    }

    /// Saturating 256-bit unsigned addition.
    #[must_use]
    pub const fn saturating_add(self, rhs: Self) -> Self {
        match self.checked_add(rhs) {
            Some(sum) => sum,
            None => Self::MAX,
        }
    }

    /// Floor `log2(self)` equivalent difficulty bits (`0` when zero).
    ///
    /// Maps cumulative `ChainWork256` into the integer `difficulty_bits` floor
    /// exposed by [`SecurityBacking::Work`]: e.g. genesis work `0x1_0001_0001`
    /// yields `32` bits.
    #[must_use]
    pub const fn log2_floor(self) -> u32 {
        let [w0, w1, w2, w3] = self.0;
        if w0 != 0 {
            255 - w0.leading_zeros()
        } else if w1 != 0 {
            191 - w1.leading_zeros()
        } else if w2 != 0 {
            127 - w2.leading_zeros()
        } else if w3 != 0 {
            w3.ilog2()
        } else {
            0
        }
    }

    /// Compute exact Bitcoin Core `GetBlockProof(nBits)`:
    /// `floor(2^256 / (target + 1)) == (~target / (target + 1)) + 1`.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::ConsensusRule`] if `bits` is not a valid compact
    /// Bitcoin target.
    pub fn from_bits(bits: u32) -> Result<Self, AdapterError> {
        let target_be = target_from_bits(bits)?;
        let target = Self::from_be_bytes(target_be);
        let [t0, t1, t2, t3] = target.0;
        let not_target = Self([!t0, !t1, !t2, !t3]);
        let Some(denom) = target.checked_add(Self([0, 0, 0, 1])) else {
            // target == 2^256 - 1 -> floor(2^256 / 2^256) == 1.
            return Ok(Self([0, 0, 0, 1]));
        };
        let quot = u256_div(not_target, denom);
        Ok(quot.saturating_add(Self([0, 0, 0, 1])))
    }

    const fn bit_at(self, bit_from_msb: u32) -> bool {
        let [w0, w1, w2, w3] = self.0;
        let word = match bit_from_msb / 64 {
            0 => w0,
            1 => w1,
            2 => w2,
            _ => w3,
        };
        let shift = 63 - (bit_from_msb % 64);
        ((word >> shift) & 1) != 0
    }

    fn shl1_or(self, lsb: bool) -> Self {
        let [w0, w1, w2, w3] = self.0;
        Self([
            (w0 << 1) | (w1 >> 63),
            (w1 << 1) | (w2 >> 63),
            (w2 << 1) | (w3 >> 63),
            (w3 << 1) | u64::from(lsb),
        ])
    }

    fn wrapping_sub(self, rhs: Self) -> Self {
        let [a0, a1, a2, a3] = self.0;
        let [b0, b1, b2, b3] = rhs.0;
        let (r3, c3) = a3.overflowing_sub(b3);
        let (t2, c2a) = a2.overflowing_sub(b2);
        let (r2, c2b) = t2.overflowing_sub(u64::from(c3));
        let (t1, c1a) = a1.overflowing_sub(b1);
        let (r1, c1b) = t1.overflowing_sub(u64::from(c2a || c2b));
        let r0 = a0.wrapping_sub(b0).wrapping_sub(u64::from(c1a || c1b));
        Self([r0, r1, r2, r3])
    }

    const fn set_bit(self, bit_from_msb: u32) -> Self {
        let [mut w0, mut w1, mut w2, mut w3] = self.0;
        let mask = 1u64 << (63 - (bit_from_msb % 64));
        match bit_from_msb / 64 {
            0 => w0 |= mask,
            1 => w1 |= mask,
            2 => w2 |= mask,
            _ => w3 |= mask,
        }
        Self([w0, w1, w2, w3])
    }
}

/// Exact constant-step 256-bit binary long division (`num / den`, `den > 0`).
fn u256_div(num: ChainWork256, den: ChainWork256) -> ChainWork256 {
    if den.is_zero() {
        return ChainWork256::ZERO;
    }
    let mut quot = ChainWork256::ZERO;
    let mut rem = ChainWork256::ZERO;
    for bit in 0..256u32 {
        let [rw0, _, _, _] = rem.0;
        let carry = (rw0 >> 63) != 0;
        rem = rem.shl1_or(num.bit_at(bit));
        if carry || rem >= den {
            rem = rem.wrapping_sub(den);
            quot = quot.set_bit(bit);
        }
    }
    quot
}

/// The 256-bit big-endian target encoded by Bitcoin's compact `nBits`.
///
/// Refuses negative, zero, oversized and sub-3-exponent encodings rather than
/// truncating them: an unrepresentable target is a refusal, not a smaller
/// target that happens to fit.
fn target_from_bits(bits: u32) -> Result<[u8; 32], AdapterError> {
    let exponent = bits >> 24;
    let mantissa = bits & 0x007f_ffff;
    if bits & 0x0080_0000 != 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "negative nBits target".to_string(),
        });
    }
    if mantissa == 0 || !(3..=32).contains(&exponent) {
        return Err(AdapterError::ConsensusRule {
            rule: format!("nBits {bits:08x} has no representable target"),
        });
    }
    let mut out = [0u8; 32];
    let mantissa_bytes = mantissa.to_be_bytes();
    let shift_bytes = usize::try_from(exponent - 3).map_err(|_| AdapterError::ConsensusRule {
        rule: "nBits exponent does not fit".to_string(),
    })?;
    let start = 32usize
        .checked_sub(shift_bytes)
        .and_then(|s| s.checked_sub(3))
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "nBits target overflows 256 bits".to_string(),
        })?;
    let end = start
        .checked_add(3)
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "nBits target overflows 256 bits".to_string(),
        })?;
    let Some(window) = out.get_mut(start..end) else {
        return Err(AdapterError::ConsensusRule {
            rule: "nBits target overflows 256 bits".to_string(),
        });
    };
    let Some(tail) = mantissa_bytes.get(1..4) else {
        return Err(AdapterError::ConsensusRule {
            rule: "nBits mantissa is too short".to_string(),
        });
    };
    window.copy_from_slice(tail);
    Ok(out)
}

/// Leading zero bits the target demands. This is the unit
/// `SecurityBacking::Work` uses, shared with the local `PoW` header-chain
/// adapter, so an operator can compare two work claims without reading either
/// adapter's source.
fn difficulty_bits(bits: u32) -> Result<u32, AdapterError> {
    let target = target_from_bits(bits)?;
    let mut leading = 0u32;
    for byte in target {
        if byte == 0 {
            leading += 8;
        } else {
            leading += byte.leading_zeros();
            break;
        }
    }
    Ok(leading)
}

/// Parse the fixed-layout evidence: 4-byte little-endian header count followed
/// by exactly `count` 80-byte headers. Trailing bytes are a refusal, not a
/// partial read.
fn parse_headers(payload: &[u8]) -> Result<Vec<BitcoinHeader>, AdapterError> {
    fn u32_le(bytes: &[u8], offset: usize, what: &str) -> Result<u32, AdapterError> {
        let slice = bytes
            .get(offset..offset + 4)
            .ok_or(AdapterError::Malformed {
                offset,
                reason: format!("{what} is not present"),
            })?;
        let arr: [u8; 4] = slice.try_into().map_err(|_| AdapterError::Malformed {
            offset,
            reason: format!("{what} is not 4 bytes"),
        })?;
        Ok(u32::from_le_bytes(arr))
    }
    fn fixed(bytes: &[u8], offset: usize, what: &str) -> Result<[u8; 32], AdapterError> {
        let slice = bytes
            .get(offset..offset + 32)
            .ok_or(AdapterError::Malformed {
                offset,
                reason: format!("{what} is not present"),
            })?;
        let mut out = [0u8; 32];
        out.copy_from_slice(slice);
        Ok(out)
    }

    let count = usize::try_from(u32_le(payload, 0, "header count")?).map_err(|_| {
        AdapterError::Malformed {
            offset: 0,
            reason: "header count does not fit".to_string(),
        }
    })?;
    if count == 0 || count > MAX_HEADERS {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: format!("header count {count} is outside 1..={MAX_HEADERS}"),
        });
    }
    let expected =
        4usize
            .checked_add(count.saturating_mul(HEADER_LEN))
            .ok_or(AdapterError::Malformed {
                offset: 0,
                reason: "header count overflows".to_string(),
            })?;
    if payload.len() != expected {
        return Err(AdapterError::Malformed {
            offset: payload.len(),
            reason: format!("payload is {} bytes, expected {expected}", payload.len()),
        });
    }

    let mut headers = Vec::with_capacity(count);
    for index in 0..count {
        let base = 4usize.saturating_add(index.saturating_mul(HEADER_LEN));
        let end = base
            .checked_add(HEADER_LEN)
            .ok_or(AdapterError::Malformed {
                offset: base,
                reason: "header offset overflows".to_string(),
            })?;
        let Some(raw) = payload.get(base..end) else {
            return Err(AdapterError::Malformed {
                offset: base,
                reason: "header is not present".to_string(),
            });
        };
        let version_bytes: [u8; 4] = raw
            .get(0..4)
            .ok_or(AdapterError::Malformed {
                offset: base,
                reason: "version is not present".to_string(),
            })?
            .try_into()
            .map_err(|_| AdapterError::Malformed {
                offset: base,
                reason: "version is not 4 bytes".to_string(),
            })?;
        headers.push(BitcoinHeader {
            version: i32::from_le_bytes(version_bytes),
            parent_hash: fixed(raw, 4, "parent_hash")?,
            merkle_root: fixed(raw, 36, "merkle_root")?,
            timestamp: u32_le(raw, 68, "timestamp")?,
            bits: u32_le(raw, 72, "bits")?,
            nonce: u32_le(raw, 76, "nonce")?,
            hash: sha256d(raw),
        });
    }
    Ok(headers)
}

/// Work inequality: the header hash, read as a little-endian 256-bit integer,
/// must not exceed the target. Comparing reversed big-endian byte arrays is
/// the same comparison without a 256-bit integer type.
fn meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    let mut as_be = *hash;
    as_be.reverse();
    as_be <= *target
}

/// Bitcoin protocol difficulty adjustment interval (2016 blocks).
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 2_016;
/// Bitcoin protocol target epoch timespan (14 days in seconds).
pub const POW_TARGET_TIMESPAN_SECS: u32 = 14 * 24 * 60 * 60;
/// Minimum clamped retarget timespan (`POW_TARGET_TIMESPAN_SECS / 4`).
pub const MIN_ACTUAL_TIMESPAN_SECS: u32 = POW_TARGET_TIMESPAN_SECS / 4;
/// Maximum clamped retarget timespan (`POW_TARGET_TIMESPAN_SECS * 4`).
pub const MAX_ACTUAL_TIMESPAN_SECS: u32 = POW_TARGET_TIMESPAN_SECS * 4;
/// Bitcoin mainnet minimum-difficulty ceiling (`nBits = 0x1d00ffff`).
pub const MAINNET_POW_LIMIT_BITS: u32 = 0x1d00_ffff;
/// Bitcoin `regtest` minimum-difficulty ceiling (`nBits = 0x207fffff`).
///
/// Permitted only when `BitcoinSpvAdapter` is configured for `"regtest"`.
/// WIRING: consumed by [`BitcoinSpvAdapter::verify_chain`] and regtest epoch tests.
pub const REGTEST_POW_LIMIT_BITS: u32 = 0x207f_ffff;
/// BIP-113 Median-Time-Past sliding window size (11 prior headers).
pub const MTP_WINDOW_LEN: usize = 11;

/// Compute the BIP-113 Median-Time-Past of up to the last 11 block timestamps.
/// WIRING: Bitcoin SPV BIP-113 timestamp rule consumed by [`BitcoinSpvAdapter::verify`].
#[must_use]
pub fn median_time_past(prior_timestamps: &[u32]) -> Option<u32> {
    if prior_timestamps.is_empty() {
        return None;
    }
    let start = prior_timestamps.len().saturating_sub(MTP_WINDOW_LEN);
    let mut window: Vec<u32> = prior_timestamps.get(start..)?.to_vec();
    window.sort_unstable();
    window.get(window.len() / 2).copied()
}

/// Lower bound on the median-time-past of the 11 blocks before the next
/// header, from the trailing timestamps known so far. Each of the `11 - k` unknown
/// predecessors can pull the median down by at most one rank, so with `k`
/// known values the median is at least the `(k - 5)`-th smallest of them;
/// with fewer than six nothing can be inferred. For `k >= 11` this is the
/// exact median.
#[must_use]
fn median_time_past_floor(known_timestamps: &[u32]) -> Option<u32> {
    if known_timestamps.len() >= MTP_WINDOW_LEN {
        return median_time_past(known_timestamps);
    }
    let rank = known_timestamps.len().checked_sub(MTP_WINDOW_LEN / 2 + 1)?;
    let mut sorted = known_timestamps.to_vec();
    sorted.sort_unstable();
    sorted.get(rank).copied()
}

/// Encode a big-endian 256-bit positive target back into canonical Bitcoin
/// compact `nBits` form (preserving the non-negative sign-bit invariant).
#[must_use]
fn target_to_bits(target: &[u8; 32]) -> u32 {
    let first_nz = target.iter().position(|&b| b != 0);
    let Some(idx) = first_nz else {
        return 0;
    };
    let mut size = 32 - idx;
    let b0 = target.get(idx).copied().unwrap_or(0);
    let b1 = target.get(idx + 1).copied().unwrap_or(0);
    let b2 = target.get(idx + 2).copied().unwrap_or(0);
    let mut compact = match size {
        1 => u32::from(b0),
        2 => (u32::from(b0) << 8) | u32::from(b1),
        _ => (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2),
    };
    // If the top bit (0x0080_0000) is set, Bitcoin shifts the mantissa right by
    // one byte and increments the exponent so the compact number stays positive.
    if (compact & 0x0080_0000) != 0 {
        compact >>= 8;
        size += 1;
    }
    ((size as u32) << 24) | (compact & 0x007f_ffff)
}

/// Multiply a 256-bit big-endian integer by `mul` (`u32`) and divide by `div`
/// (`u32`, non-zero), clamping to `[0xff; 32]` on overflow.
fn mul_div_be256(value: &[u8; 32], mul: u32, div: u32) -> [u8; 32] {
    // 36-byte big-endian intermediate product (`256 + 32 = 288` bits).
    let mut prod = [0u8; 36];
    let mut carry = 0u64;
    let m = u64::from(mul);
    for i in (0..32).rev() {
        let v = u64::from(value.get(i).copied().unwrap_or(0));
        let acc = v * m + carry;
        if let Some(slot) = prod.get_mut(i + 4) {
            *slot = (acc & 0xff) as u8;
        }
        carry = acc >> 8;
    }
    for i in (0..4).rev() {
        if let Some(slot) = prod.get_mut(i) {
            *slot = (carry & 0xff) as u8;
        }
        carry >>= 8;
    }

    let mut quot = [0u8; 36];
    let mut rem = 0u64;
    let d = u64::from(div.max(1));
    for (p, q) in prod.iter().zip(quot.iter_mut()) {
        let cur = (rem << 8) | u64::from(*p);
        *q = (cur / d) as u8;
        rem = cur % d;
    }
    if quot.get(0..4).is_some_and(|hi| hi.iter().any(|&b| b != 0)) {
        return [0xff; 32];
    }
    let mut out = [0u8; 32];
    if let Some(lo) = quot.get(4..36) {
        out.copy_from_slice(lo);
    }
    out
}

/// Bitcoin difficulty retarget (`CalculateNextWorkRequired`) under `pow_limit_bits`.
///
/// Uses `MAINNET_POW_LIMIT_BITS` on mainnet/testnet/signet and
/// `REGTEST_POW_LIMIT_BITS` only on `"regtest"`.
///
/// # Errors
///
/// Returns [`AdapterError::ConsensusRule`] if `prev_bits` or `pow_limit_bits`
/// is not a valid compact Bitcoin target.
///
/// WIRING: consumed by [`compute_next_work_required`] and [`BitcoinSpvAdapter::verify_chain`].
pub fn compute_next_work_required_with_limit(
    epoch_first_timestamp: u32,
    epoch_last_timestamp: u32,
    prev_bits: u32,
    pow_limit_bits: u32,
) -> Result<u32, AdapterError> {
    let old_target = target_from_bits(prev_bits)?;
    let pow_limit = target_from_bits(pow_limit_bits)?;
    let raw_span = epoch_last_timestamp.saturating_sub(epoch_first_timestamp);
    let clamped = raw_span.clamp(MIN_ACTUAL_TIMESPAN_SECS, MAX_ACTUAL_TIMESPAN_SECS);
    let scaled = mul_div_be256(&old_target, clamped, POW_TARGET_TIMESPAN_SECS);
    let capped = if scaled > pow_limit {
        pow_limit
    } else {
        scaled
    };
    Ok(target_to_bits(&capped))
}

/// Exact integer Bitcoin mainnet difficulty retarget (`CalculateNextWorkRequired`).
///
/// Clamps `epoch_last_timestamp - epoch_first_timestamp` to `[3.5 days, 56 days]`,
/// scales the 256-bit target by `actual_timespan / 14 days`, and caps at
/// `MAINNET_POW_LIMIT_BITS` (`0x1d00ffff`).
///
/// # Errors
///
/// Returns [`AdapterError::ConsensusRule`] if `prev_bits` is malformed.
///
/// Convenience: kept for the CLI and Bitcoin mainnet retarget inspection.
pub fn compute_next_work_required(
    epoch_first_timestamp: u32,
    epoch_last_timestamp: u32,
    prev_bits: u32,
) -> Result<u32, AdapterError> {
    compute_next_work_required_with_limit(
        epoch_first_timestamp,
        epoch_last_timestamp,
        prev_bits,
        MAINNET_POW_LIMIT_BITS,
    )
}

/// Verified per-header summary inside a [`VerifiedBitcoinChain`].
///
/// WIRING: carried inside [`VerifiedBitcoinChain`] for payment confirmation and STARK proving.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedBitcoinHeader {
    /// Derived consensus block height (`anchor.height + step`).
    pub height: u64,
    /// Verified `SHA256d` block hash (internal byte order).
    pub hash: [u8; 32],
    /// Verified parent block hash (internal byte order).
    pub parent_hash: [u8; 32],
    /// Verified transaction Merkle root (internal byte order).
    pub merkle_root: [u8; 32],
    /// Header Unix timestamp (seconds).
    pub timestamp: u32,
    /// Verified compact target `nBits` active at `height`.
    pub bits: u32,
    /// Exact 256-bit proof-of-work contributed by this single header.
    pub block_work: ChainWork256,
    /// Running cumulative 256-bit chainwork from the anchor through `height`.
    pub cumulative_work: ChainWork256,
}

/// Fully verified Bitcoin SPV header chain with exact 256-bit cumulative work.
///
/// WIRING: returned by [`BitcoinSpvAdapter::verify_chain`] and consumed by
/// [`select_heaviest_bitcoin_chain`] and [`prove_bitcoin_header_chain_stark`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBitcoinChain {
    /// Shared external-domain finality attestation for the chain tip.
    pub attestation: FinalityAttestation,
    /// Pinned anchor height this chain extends.
    pub anchor_height: u64,
    /// Pinned anchor block hash (internal byte order).
    pub anchor_hash: [u8; 32],
    /// Pinned anchor `nBits`.
    pub anchor_bits: u32,
    /// Total 256-bit proof-of-work accumulated across `headers` (plus any base anchor work).
    pub total_chainwork: ChainWork256,
    /// Contiguous verified headers from `anchor_height + 1` through `attestation.height`.
    pub headers: Vec<VerifiedBitcoinHeader>,
}

/// Nakamoto heaviest-chain fork choice over verified chains sharing one anchor.
///
/// Compares exact 256-bit `total_chainwork` (so a shorter high-difficulty chain
/// always defeats a longer low-difficulty chain), breaking exact equal-work
/// ties deterministically by lexicographically smallest tip hash.
///
/// # Errors
///
/// Returns [`AdapterError::ConsensusRule`] if `candidates` is empty or mixes
/// chains rooted at different pinned anchors or domains.
///
/// Convenience: kept for the CLI and multi-relayer Bitcoin fork-choice callers.
pub fn select_heaviest_bitcoin_chain(
    candidates: &[VerifiedBitcoinChain],
) -> Result<&VerifiedBitcoinChain, AdapterError> {
    let Some((first, rest)) = candidates.split_first() else {
        return Err(AdapterError::ConsensusRule {
            rule: "cannot select heaviest Bitcoin chain from an empty set".to_string(),
        });
    };
    let mut best = first;
    for cand in rest {
        if cand.anchor_hash != first.anchor_hash
            || cand.anchor_height != first.anchor_height
            || cand.attestation.domain != first.attestation.domain
        {
            return Err(AdapterError::ConsensusRule {
                rule: "Bitcoin fork-choice candidates do not share the same pinned anchor"
                    .to_string(),
            });
        }
        let beats = match cand.total_chainwork.cmp(&best.total_chainwork) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Equal => cand.attestation.state_root < best.attestation.state_root,
            std::cmp::Ordering::Less => false,
        };
        if beats {
            best = cand;
        }
    }
    Ok(best)
}

/// Reads Bitcoin SPV evidence and produces the shared attestation.
pub struct BitcoinSpvAdapter {
    descriptor: AdapterDescriptor,
    network: String,
    anchor: Option<PinnedBitcoinAnchor>,
    /// Optional authenticated timestamp of the anchor's current 2016-block
    /// epoch opening block (`(anchor.height / 2016) * 2016`) for mid-epoch
    /// checkpoints that cross the next retarget boundary.
    epoch_start_timestamp: Option<u32>,
    /// Optional authenticated timestamp of the pinned anchor block itself.
    anchor_timestamp: Option<u32>,
    /// Optional authenticated 11 prior block timestamps ending at the anchor
    /// block (chronological order) so header #1 already enforces full `MTP-11`.
    prior_timestamps: Option<[u32; MTP_WINDOW_LEN]>,
    /// Optional base 256-bit chainwork accumulated up to and including `anchor`.
    anchor_chainwork: ChainWork256,
    golden: Option<RawConsensusEvidence>,
}

impl BitcoinSpvAdapter {
    /// An adapter without a pinned anchor constructs fine and refuses at
    /// verification time: constructing is not the moment to fail, because the
    /// caller may be building a registry before installing the anchor data.
    #[must_use]
    pub fn new(network: &str, anchor: Option<PinnedBitcoinAnchor>) -> Self {
        let name = format!("bitcoin-spv-{network}");
        Self {
            descriptor: AdapterDescriptor {
                id: AdapterId::from_name(&name),
                name,
                adapter_version: 1,
                accepted_evidence_versions: vec![EVIDENCE_VERSION],
                consensus_kind: "nakamoto-pow".to_string(),
                finality_kind: FinalityKind::Probabilistic,
                required_depth: REQUIRED_DEPTH,
                time_unit: TimeUnit::UnixSeconds,
                trust_model: TrustModel::Trustless,
            },
            network: network.to_string(),
            anchor,
            epoch_start_timestamp: None,
            anchor_timestamp: None,
            prior_timestamps: None,
            anchor_chainwork: ChainWork256::ZERO,
            golden: None,
        }
    }

    /// Attach the known-good evidence sample admission verifies against.
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }

    /// Pin the authenticated opening-block timestamp of the anchor's difficulty
    /// epoch (`(anchor.height / 2016) * 2016`) so chains starting mid-epoch can
    /// verify the upcoming 2016-block retarget without trusting submitter data.
    ///
    /// Convenience: kept for the CLI and multi-epoch Bitcoin anchor builders.
    #[must_use]
    pub const fn with_epoch_start_timestamp(mut self, timestamp: u32) -> Self {
        self.epoch_start_timestamp = Some(timestamp);
        self
    }

    /// Pin the authenticated 11 prior block timestamps ending at the anchor
    /// block (oldest first, anchor timestamp last) so header #1 immediately
    /// enforces strict BIP-113 `MTP-11`.
    ///
    /// Convenience: kept for the CLI and BIP-113 checkpoint builders.
    #[must_use]
    pub const fn with_prior_timestamps(mut self, prior_timestamps: [u32; MTP_WINDOW_LEN]) -> Self {
        self.prior_timestamps = Some(prior_timestamps);
        let [.., anchor_ts] = prior_timestamps;
        self.anchor_timestamp = Some(anchor_ts);
        self
    }

    /// Pin the cumulative 256-bit `nChainWork` already accrued at `anchor`.
    ///
    /// Convenience: kept for the CLI and checkpoint-rooted fork-choice callers.
    #[must_use]
    pub const fn with_anchor_chainwork(mut self, chainwork: ChainWork256) -> Self {
        self.anchor_chainwork = chainwork;
        self
    }

    fn pow_limit_bits(&self) -> u32 {
        if self.network == "regtest" {
            REGTEST_POW_LIMIT_BITS
        } else {
            MAINNET_POW_LIMIT_BITS
        }
    }

    /// Verify a raw Bitcoin SPV header chain and return both the shared
    /// [`FinalityAttestation`] and exact per-header 256-bit [`ChainWork256`].
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError`] on any consensus, `PoW`, retarget, `MTP-11`,
    /// per-header `+2h` future-time, freshness, depth, or declaration failure.
    pub fn verify_chain(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<VerifiedBitcoinChain, AdapterError> {
        if evidence.adapter != self.descriptor.id {
            return Err(AdapterError::WrongAdapter {
                expected: self.descriptor.name.clone(),
                found: "another adapter".to_string(),
            });
        }
        // Fail-closed: an adapter bound to an empty (or whitespace-only)
        // network label is a configuration error. Without this guard the
        // `evidence.network != self.network` comparison below would treat
        // `"" == ""` as a match and accept any payload that also carries an
        // empty network, silently turning the adapter into an
        // accept-everything end. Reject every payload instead.
        if self.network.trim().is_empty() {
            return Err(AdapterError::ConsensusRule {
                rule: "BitcoinSpvAdapter network identifier must not be empty".into(),
            });
        }
        if evidence.network != self.network {
            return Err(AdapterError::WrongAdapter {
                expected: self.network.clone(),
                found: evidence.network.clone(),
            });
        }
        if !self
            .descriptor
            .accepted_evidence_versions
            .contains(&evidence.evidence_version)
        {
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence.evidence_version,
                accepted: self
                    .descriptor
                    .accepted_evidence_versions
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            });
        }

        let Some(anchor) = self.anchor.as_ref() else {
            return Err(AdapterError::Unavailable {
                reason: "no Bitcoin checkpoint is pinned for this domain".to_string(),
            });
        };
        let pow_limit_bits = self.pow_limit_bits();
        let pow_limit_target = target_from_bits(pow_limit_bits)?;
        let mut current_bits = anchor.bits;
        let mut current_target = target_from_bits(current_bits)?;
        if current_target > pow_limit_target {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "anchor nBits {current_bits:08x} exceeds network powLimit {pow_limit_bits:08x}"
                ),
            });
        }
        let mut min_difficulty_bits = difficulty_bits(current_bits)?;
        let headers = parse_headers(&evidence.payload)?;

        let mut previous_hash = anchor.block_hash;
        let mut seen_timestamps: Vec<u32> =
            Vec::with_capacity(MTP_WINDOW_LEN.saturating_add(headers.len()));
        if let Some(prior) = self.prior_timestamps.as_ref() {
            seen_timestamps.extend_from_slice(prior);
        } else if let Some(anchor_ts) = self.anchor_timestamp {
            seen_timestamps.push(anchor_ts);
        }

        // Bitcoin Core `CalculateNextWorkRequired` measures the 2016-block span
        // from height `2016 * k` (inclusive) to height `2016 * k + 2015` (inclusive).
        let mut epoch_first_ts: Option<u32> = self.epoch_start_timestamp.or(
            if anchor.height.is_multiple_of(DIFFICULTY_ADJUSTMENT_INTERVAL) {
                self.anchor_timestamp
            } else {
                None
            },
        );
        let max_allowed_ts = policy.now.saturating_add(MAX_FUTURE_SECONDS);
        let mut cumulative_work = self.anchor_chainwork;
        let mut verified_headers = Vec::with_capacity(headers.len());

        for (idx, header) in headers.iter().enumerate() {
            let step = u64::try_from(idx + 1).map_err(|_| AdapterError::Malformed {
                offset: 0,
                reason: "header index overflows u64".to_string(),
            })?;
            let h = anchor
                .height
                .checked_add(step)
                .ok_or_else(|| AdapterError::Malformed {
                    offset: 0,
                    reason: "derived header height overflows u64".to_string(),
                })?;

            // Enforce the 2-hour future-time bound on EVERY header (not only
            // the tip) so an adversary cannot inject intermediate year-2106
            // timestamps to trigger a 4x downward difficulty retarget.
            if u64::from(header.timestamp) > max_allowed_ts {
                return Err(AdapterError::ConsensusRule {
                    rule: format!(
                        "Bitcoin header at height {h} timestamp {} exceeds +2h clock bound {max_allowed_ts}",
                        header.timestamp
                    ),
                });
            }

            if h % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
                // Fail closed across every 2016-block retarget boundary unless
                // BOTH the opening (`h - 2016`) and closing (`h - 1`) block
                // timestamps of the completed epoch are authenticated.
                let (Some(first_ts), Some(&last_ts)) = (epoch_first_ts, seen_timestamps.last())
                else {
                    return Err(AdapterError::ConsensusRule {
                        rule: format!(
                            "Bitcoin retarget boundary at height {h} requires authenticated epoch opening and closing timestamps"
                        ),
                    });
                };
                let expected_bits = compute_next_work_required_with_limit(
                    first_ts,
                    last_ts,
                    current_bits,
                    pow_limit_bits,
                )?;
                if header.bits != expected_bits {
                    return Err(AdapterError::ConsensusRule {
                        rule: format!(
                            "Bitcoin retarget at height {h} expected nBits {expected_bits:08x}, found {:08x}",
                            header.bits
                        ),
                    });
                }
                current_bits = expected_bits;
                current_target = target_from_bits(current_bits)?;
                min_difficulty_bits = min_difficulty_bits.min(difficulty_bits(current_bits)?);
                // Height `h == 2016 * k` is the exact opening block of the new epoch.
                epoch_first_ts = Some(header.timestamp);
            } else if header.bits != current_bits {
                return Err(AdapterError::ConsensusRule {
                    rule: format!(
                        "header nBits {:08x} leaves the pinned difficulty epoch {:08x}",
                        header.bits, current_bits
                    ),
                });
            }

            if header.parent_hash != previous_hash {
                return Err(AdapterError::ConsensusRule {
                    rule: "Bitcoin header does not link to its parent".to_string(),
                });
            }
            // Bitcoin only requires a timestamp above the median of the
            // previous 11 headers, so a header may carry a smaller timestamp
            // than its parent. The bound is exact once 11 predecessors are
            // known and a provable lower bound before that.
            if let Some(floor) = median_time_past_floor(&seen_timestamps) {
                if header.timestamp <= floor {
                    return Err(AdapterError::ConsensusRule {
                        rule: format!(
                            "Bitcoin header timestamp {} does not exceed BIP-113 MTP floor {floor}",
                            header.timestamp
                        ),
                    });
                }
            }
            if !verify_spv_tx_inclusion(&header.merkle_root, &header.merkle_root, 0, &[]) {
                return Err(AdapterError::ConsensusRule {
                    rule: "Bitcoin header carries an empty zero merkle_root".to_string(),
                });
            }
            if !meets_target(&header.hash, &current_target) {
                return Err(AdapterError::ConsensusRule {
                    rule: "Bitcoin header hash does not meet the nBits target".to_string(),
                });
            }

            let block_work = ChainWork256::from_bits(current_bits)?;
            // Bitcoin Core's `nChainWork` is an exact 256-bit integer: it is
            // never clamped, so a running total that leaves the range is a
            // refusal and not a saturated `MAX`. Saturating here would flatten
            // every later `cumulative_work` to the same value, make
            // `tip.cumulative_work <= anchor_chainwork` true for a real chain,
            // and freeze the reported `difficulty_bits` at the ceiling.
            cumulative_work =
                cumulative_work
                    .checked_add(block_work)
                    .ok_or_else(|| AdapterError::ConsensusRule {
                        rule: format!(
                            "Bitcoin chainwork overflows 256 bits at height {h}: the pinned anchor work plus {} header(s) is not representable",
                            idx + 1
                        ),
                    })?;
            verified_headers.push(VerifiedBitcoinHeader {
                height: h,
                hash: header.hash,
                parent_hash: header.parent_hash,
                merkle_root: header.merkle_root,
                timestamp: header.timestamp,
                bits: current_bits,
                block_work,
                cumulative_work,
            });
            previous_hash = header.hash;
            seen_timestamps.push(header.timestamp);
        }

        let count = u64::try_from(verified_headers.len()).map_err(|_| AdapterError::Malformed {
            offset: 0,
            reason: "header count does not fit u64".to_string(),
        })?;
        let height = anchor
            .height
            .checked_add(count)
            .ok_or_else(|| AdapterError::Malformed {
                offset: 0,
                reason: "derived height overflows".to_string(),
            })?;
        let last = verified_headers
            .last()
            .ok_or_else(|| AdapterError::Malformed {
                offset: 0,
                reason: "no headers".to_string(),
            })?;
        let finalized_at = u64::from(last.timestamp);
        let root = last.hash;

        if policy.require_declared_match {
            if evidence.declared_height != height {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if evidence.declared_root != root {
                return Err(AdapterError::DeclarationMismatch {
                    field: "state_root",
                });
            }
        }
        if policy.max_age > 0 {
            let age = policy.now.saturating_sub(finalized_at);
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        let observed_depth = count;
        let required = REQUIRED_DEPTH.max(policy.min_depth);
        if observed_depth < required {
            return Err(AdapterError::InsufficientDepth {
                observed: observed_depth,
                required,
            });
        }

        // Accumulated work is not slashable: no Bitcoin miner has a bond that
        // Budlum can confiscate. A caller that demands slashable backing is
        // refused here, as every other work-weighted adapter refuses it, so a
        // direct `verify_chain` caller cannot read `Work` as if it were a
        // bonded signature set.
        if policy.require_slashable {
            return Err(AdapterError::UnslashableBacking);
        }

        let work_bits = min_difficulty_bits.max(cumulative_work.log2_floor());
        let attestation = FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &self.network),
            height,
            state_root: root,
            finalized_at,
            time_unit: TimeUnit::UnixSeconds,
            security: SecurityBacking::Work {
                difficulty_bits: work_bits,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
            attested_block_hash: Some(root),
            attested_event_root: None,
            attested_tx_root: Some(last.merkle_root),
        };
        Ok(VerifiedBitcoinChain {
            attestation,
            anchor_height: anchor.height,
            anchor_hash: anchor.block_hash,
            anchor_bits: anchor.bits,
            total_chainwork: cumulative_work,
            headers: verified_headers,
        })
    }
}

impl ExternalFinalityAdapter for BitcoinSpvAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn has_pinned_trust_anchor(&self) -> bool {
        self.anchor.is_some()
    }

    fn verify(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError> {
        self.verify_chain(evidence, policy)
            .map(|chain| chain.attestation)
    }

    /// The parent block digest, derived from the parent header *inside the same
    /// payload*: `sha256d` of the second-to-last header, which is the hash form
    /// [`Self::verify`] already reports as `attested_block_hash`.
    ///
    /// A single-header payload cannot answer this. Its `prev_block` field is a
    /// pointer the submitter chose; hashing it would launder an unverified claim
    /// into a slash. Two headers are the minimum witness that says "this block
    /// exists and the tip descends from it".
    fn attested_parent(&self, evidence: &RawConsensusEvidence) -> Option<[u8; 32]> {
        let payload = &evidence.payload;
        let count =
            usize::try_from(u32::from_le_bytes(payload.get(0..4)?.try_into().ok()?)).ok()?;
        if !(2..=MAX_HEADERS).contains(&count) {
            return None;
        }
        let base = 4usize.checked_add(count.checked_sub(2)?.checked_mul(HEADER_LEN)?)?;
        let raw = payload.get(base..base.checked_add(HEADER_LEN)?)?;
        Some(sha256d(raw))
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        // Header layout is fixed at 80 bytes, so interior offsets are stable
        // across every Bitcoin network and every evidence sample: unlike the
        // bincode payload in the ZKVM adapter, there is no size drift here.
        let bits_offset = 4 + 72;
        let parent_offset = 4 + 4;
        vec![
            FaultProbe {
                name: "an empty payload is refused before deserialization".to_string(),
                patch: BytePatch::TruncatePayload { keep: 0 },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "a truncated header is refused".to_string(),
                patch: BytePatch::TruncatePayload {
                    keep: 4 + HEADER_LEN - 1,
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "a header that leaves the pinned difficulty epoch is refused".to_string(),
                patch: BytePatch::InPayload {
                    offset: bits_offset,
                    bytes: vec![0xff, 0xff, 0x1d, 0x1d],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "a broken parent link is refused".to_string(),
                patch: BytePatch::InPayload {
                    offset: parent_offset,
                    bytes: vec![0xab; 32],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "a lying declared height is refused".to_string(),
                patch: BytePatch::DeclaredHeight { value: 999_999 },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "a lying declared root is refused".to_string(),
                patch: BytePatch::DeclaredRoot { value: [7u8; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "an unknown evidence version is refused".to_string(),
                patch: BytePatch::EvidenceVersion { value: 999 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "another network is refused".to_string(),
                patch: BytePatch::Network {
                    value: "another-network".to_string(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::WrongAdapter),
            },
        ]
    }

    fn golden_evidence(&self) -> Option<RawConsensusEvidence> {
        self.golden.clone()
    }
}

/// Domain-separated `Poseidon4` tag folding a 32-byte Bitcoin header hash.
const BTC_STARK_HASH_FOLD_TAG: u64 = 0x4254_4353_5056_4831;
/// Domain-separated `Poseidon4` tag transitioning the header-chain transcript.
const BTC_STARK_STEP_FOLD_TAG: u64 = 0x4254_4353_5056_5331;
/// Exact `2^32` radix used inside `BudVM` for carry-checked 256-bit `ChainWork256` limbs.
const U32_RADIX: u64 = 1u64 << 32;
/// Number of 32-bit little-endian limbs representing `ChainWork256` in `BudVM`.
const CHAINWORK_U32_LIMBS: usize = 8;

/// Memory layout of a compiled `BudVM` Bitcoin header-chain `Claim::Prog` circuit.
#[derive(Debug, Clone, Copy)]
struct BitcoinStarkCells {
    input_hash: u64,
    output_hash: u64,
    anchor_hash_fold: u64,
    anchor_height: u64,
    max_allowed_ts: u64,
    init_work_limbs: u64,
    expected_tip_fold: u64,
    expected_tip_height: u64,
    expected_total_work_limbs: u64,
    expected_transcript: u64,
    /// Per-header stride of `13` cells:
    /// `[parent_fold, hash_fold, height, ts, bits, work_limb_0..work_limb_7]`.
    headers_base: u64,
}

const BTC_STARK_HEADER_STRIDE: u64 = 13;

/// Fold a 32-byte digest into one Goldilocks field element via `poseidon4_hash`.
fn fold_digest_poseidon(digest: &[u8; 32]) -> u64 {
    let mut acc = BTC_STARK_HASH_FOLD_TAG;
    for chunk in digest.as_chunks::<4>().0 {
        let [b0, b1, b2, b3] = *chunk;
        let limb = u64::from(u32::from_le_bytes([b0, b1, b2, b3]));
        acc = bud_vm::poseidon4_hash(acc, limb);
    }
    acc
}

/// Split a [`ChainWork256`] into 8 little-endian `u32` limbs (`[0, 2^32)`).
const fn chainwork_to_u32_le_limbs(work: ChainWork256) -> [u64; CHAINWORK_U32_LIMBS] {
    let [w0, w1, w2, w3] = work.to_le_words();
    let mask = U32_RADIX - 1;
    [
        w0 & mask,
        w0 >> 32,
        w1 & mask,
        w1 >> 32,
        w2 & mask,
        w2 >> 32,
        w3 & mask,
        w3 >> 32,
    ]
}

/// Compute the deterministic `BudVM` Poseidon transcript over a verified chain.
fn compute_header_stark_transcript(
    anchor_hash_fold: u64,
    anchor_height: u64,
    headers: &[VerifiedBitcoinHeader],
) -> u64 {
    let mut acc = bud_vm::poseidon4_hash(BTC_STARK_STEP_FOLD_TAG, anchor_hash_fold);
    acc = bud_vm::poseidon4_hash(acc, anchor_height);
    for h in headers {
        let h_fold = fold_digest_poseidon(&h.hash);
        acc = bud_vm::poseidon4_hash(acc, h_fold);
        acc = bud_vm::poseidon4_hash(acc, h.height);
        acc = bud_vm::poseidon4_hash(acc, u64::from(h.timestamp));
        acc = bud_vm::poseidon4_hash(acc, u64::from(h.bits));
    }
    acc
}

/// Canonical `Claim::Prog::input_hash` binding the pinned Bitcoin anchor,
/// network name, base chainwork, and batch length.
///
/// Convenience: kept for the CLI and aggregation `Claim::Prog` verifiers.
#[must_use]
pub fn bitcoin_stark_input_hash(
    network: &str,
    anchor: &PinnedBitcoinAnchor,
    anchor_chainwork: ChainWork256,
    header_count: u32,
    max_allowed_ts: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"budlum/bitcoin-spv/stark-input/v1");
    let net_bytes = network.as_bytes();
    let net_len = u32::try_from(net_bytes.len()).unwrap_or(u32::MAX);
    h.update(net_len.to_le_bytes());
    h.update(net_bytes);
    h.update(anchor.height.to_le_bytes());
    h.update(32u32.to_le_bytes());
    h.update(anchor.block_hash);
    h.update(anchor.bits.to_le_bytes());
    h.update(32u32.to_le_bytes());
    h.update(anchor_chainwork.to_be_bytes());
    h.update(header_count.to_le_bytes());
    h.update(max_allowed_ts.to_le_bytes());
    h.finalize().into()
}

/// Canonical `Claim::Prog::output_hash` binding the verified Bitcoin tip header,
/// exact 256-bit cumulative chainwork, and in-VM Poseidon chain transcript.
///
/// Convenience: kept for the CLI and aggregation `Claim::Prog` verifiers.
#[must_use]
pub fn bitcoin_stark_output_hash(
    tip_height: u64,
    tip_hash: &[u8; 32],
    tip_merkle_root: &[u8; 32],
    tip_timestamp: u32,
    tip_bits: u32,
    total_chainwork: ChainWork256,
    transcript_commitment: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"budlum/bitcoin-spv/stark-output/v1");
    h.update(tip_height.to_le_bytes());
    h.update(32u32.to_le_bytes());
    h.update(tip_hash);
    h.update(32u32.to_le_bytes());
    h.update(tip_merkle_root);
    h.update(tip_timestamp.to_le_bytes());
    h.update(tip_bits.to_le_bytes());
    h.update(32u32.to_le_bytes());
    h.update(total_chainwork.to_be_bytes());
    h.update(transcript_commitment.to_le_bytes());
    h.finalize().into()
}

/// Compiled canonical `BudVM` (`BudAir`) guest program for an `n`-header
/// Bitcoin SPV batch proof (`Claim::Prog`).
///
/// WIRING: built by [`compile_bitcoin_header_stark_program`] and verified by
/// [`verify_bitcoin_header_chain_stark`].
#[derive(Debug, Clone)]
pub struct BitcoinHeaderStarkProgram {
    /// Compiled `BudVM` instruction words and step regions.
    pub program: crate::aggregation::programs::asm::Program,
    /// Canonical `keccak256(program.code)` bound into [`crate::aggregation::claim::Claim::Prog`].
    pub program_hash: [u8; 32],
    /// Exact batch header count enforced by this circuit.
    pub header_count: usize,
    cells: BitcoinStarkCells,
}

/// Verified 128-bit Plonky3 FRI-STARK Bitcoin header-chain batch proof package.
///
/// Commits to an authenticated transition from `anchor` to `(tip_height,
/// tip_hash, tip_merkle_root)` with exact 256-bit `total_chainwork` and settles
/// as a standard Phase 4 [`crate::aggregation::claim::Claim::Prog`].
///
/// WIRING: produced by [`prove_bitcoin_header_chain_stark`] and verified by
/// [`verify_bitcoin_header_chain_stark`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinHeaderStarkBatch {
    /// Target Bitcoin network identifier (e.g. `"mainnet"`).
    pub network: String,
    /// Pinned checkpoint anchor where the batch begins.
    pub anchor: PinnedBitcoinAnchor,
    /// Cumulative 256-bit chainwork already present at `anchor`.
    pub anchor_chainwork: ChainWork256,
    /// Number of contiguous Bitcoin headers verified in this batch.
    pub header_count: u32,
    /// Upper Unix-second bound (`policy.now + 7200`) enforced on every header.
    pub max_allowed_ts: u64,
    /// Finalized tip block height (`anchor.height + header_count`).
    pub tip_height: u64,
    /// Finalized tip `SHA256d` block hash (internal byte order).
    pub tip_hash: [u8; 32],
    /// Finalized tip transaction Merkle root (internal byte order).
    pub tip_merkle_root: [u8; 32],
    /// Finalized tip Unix timestamp (seconds).
    pub tip_timestamp: u32,
    /// Finalized tip compact `nBits` target.
    pub tip_bits: u32,
    /// Exact cumulative 256-bit `ChainWork256` through `tip_height`.
    pub total_chainwork: ChainWork256,
    /// In-circuit `Poseidon4` transcript commitment across all verified headers.
    pub transcript_commitment: u64,
    /// Canonical `BudVM` `program_hash` for `header_count`.
    pub program_hash: [u8; 32],
    /// 128-bit Plonky3 FRI-STARK proof object (`ObjectKind::StarkProof`).
    pub stark_proof: crate::aggregation::programs::prog_claim::StarkProofObject,
}

/// Compile the canonical `BudVM` Bitcoin SPV header-chain circuit for
/// `header_count` contiguous headers (`1..=MAX_STARK_BATCH_HEADERS`).
///
/// Inside `BudAir`, the guest enforces for every header `0..header_count`:
/// 1. Parent-hash continuity from `anchor_hash_fold` to `expected_tip_fold`.
/// 2. Strict sequential height increments `height_i == height_{i-1} + 1`.
/// 3. Per-header future-clock bound `timestamp_i <= max_allowed_ts` and
///    non-zero `nBits`.
/// 4. Strict positive per-header work and exact carry-checked 256-bit
///    (`8 x u32`) `ChainWork256` accumulation matching `expected_total_work`.
/// 5. Full `Poseidon4` chain transcript equality with `expected_transcript`.
/// 6. Publication of `(input_hash, output_hash)` to `SWrite[0..16]`.
///
/// # Errors
///
/// Returns [`AdapterError::ConsensusRule`] if `header_count` is outside
/// `1..=MAX_STARK_BATCH_HEADERS` or assembly fails.
///
/// WIRING: consumed by [`prove_bitcoin_header_chain_stark`] and [`verify_bitcoin_header_chain_stark`].
pub fn compile_bitcoin_header_stark_program(
    header_count: usize,
) -> Result<BitcoinHeaderStarkProgram, AdapterError> {
    use crate::aggregation::programs::agg_merge::program_hash_of;
    use crate::aggregation::programs::asm::{Asm, R};
    use crate::aggregation::programs::prog_claim::{
        emit_swrite_digest_cells, DIGEST_LIMBS, DIGEST_LIMBS_U32,
    };

    if header_count == 0 || header_count > MAX_STARK_BATCH_HEADERS {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Bitcoin STARK batch size {header_count} is outside 1..={MAX_STARK_BATCH_HEADERS}"
            ),
        });
    }
    let mut a = Asm::new();
    let digest_cells = DIGEST_LIMBS as u64;
    let work_cells = CHAINWORK_U32_LIMBS as u64;
    let count_u64 = header_count as u64;

    let cells = BitcoinStarkCells {
        input_hash: a.alloc(digest_cells),
        output_hash: a.alloc(digest_cells),
        anchor_hash_fold: a.alloc(1),
        anchor_height: a.alloc(1),
        max_allowed_ts: a.alloc(1),
        init_work_limbs: a.alloc(work_cells),
        expected_tip_fold: a.alloc(1),
        expected_tip_height: a.alloc(1),
        expected_total_work_limbs: a.alloc(work_cells),
        expected_transcript: a.alloc(1),
        headers_base: a.alloc(count_u64.saturating_mul(BTC_STARK_HEADER_STRIDE)),
    };

    // Running state registers:
    // R[2]  = prev_hash_fold
    // R[3]  = prev_height
    // R[4]  = max_allowed_ts
    // R[5]  = transcript_acc
    // R[6]  = constant 1
    // R[7]  = constant U32_RADIX (2^32)
    // R[10..=17] = running 8 x u32 ChainWork256 limbs (little-endian)
    a.region("init_anchor_and_work");
    a.load_abs(R[2], cells.anchor_hash_fold);
    a.load_abs(R[3], cells.anchor_height);
    a.load_abs(R[4], cells.max_allowed_ts);
    a.li(R[6], 1);
    a.li(R[7], U32_RADIX);
    a.li(R[5], BTC_STARK_STEP_FOLD_TAG);
    a.poseidon(R[5], R[5], R[2]);
    a.poseidon(R[5], R[5], R[3]);

    for k in 0..CHAINWORK_U32_LIMBS {
        let reg = R
            .get(10 + k)
            .copied()
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "register index out of range".to_string(),
            })?;
        a.load_abs(reg, cells.init_work_limbs + k as u64);
        a.lt(R[1], reg, R[7]);
        a.assert(R[1]);
    }

    a.region("verify_bitcoin_headers");
    for i in 0..count_u64 {
        let base = cells.headers_base + i * BTC_STARK_HEADER_STRIDE;
        // R[20]=parent_fold, R[21]=hash_fold, R[22]=height, R[23]=ts, R[24]=bits
        a.load_abs(R[20], base);
        a.load_abs(R[21], base + 1);
        a.load_abs(R[22], base + 2);
        a.load_abs(R[23], base + 3);
        a.load_abs(R[24], base + 4);

        // 1. Parent hash link must equal previous header hash.
        a.eq(R[1], R[20], R[2]);
        a.assert(R[1]);

        // 2. Height must advance by exactly 1.
        a.add(R[25], R[3], R[6]);
        a.eq(R[1], R[22], R[25]);
        a.assert(R[1]);

        // 3. Timestamp <= max_allowed_ts and nBits != 0.
        a.lte(R[1], R[23], R[4]);
        a.assert(R[1]);
        a.li(R[25], 0);
        a.neq(R[1], R[24], R[25]);
        a.assert(R[1]);

        // 4. Carry-checked 256-bit ChainWork256 accumulation + non-zero block work.
        // R[26] = carry (0 or 1), R[27] = work_nonzero_sum.
        a.li(R[26], 0);
        a.li(R[27], 0);
        for k in 0..CHAINWORK_U32_LIMBS {
            let acc_reg = R
                .get(10 + k)
                .copied()
                .ok_or_else(|| AdapterError::ConsensusRule {
                    rule: "register index out of range".to_string(),
                })?;
            a.load_abs(R[28], base + 5 + k as u64);
            // Range-check witness limb in [0, 2^32).
            a.lt(R[1], R[28], R[7]);
            a.assert(R[1]);
            a.add(R[27], R[27], R[28]);

            // sum = acc_limb + work_limb + carry (at most 2^33 - 1, safe in Goldilocks).
            a.add(R[29], acc_reg, R[28]);
            a.add(R[29], R[29], R[26]);
            // next_carry = (sum >= 2^32) in {0, 1}.
            a.gte(R[26], R[29], R[7]);
            // acc_limb = sum - next_carry * 2^32 in [0, 2^32).
            a.mul(R[25], R[26], R[7]);
            a.sub(acc_reg, R[29], R[25]);
        }
        // Reject 256-bit overflow and reject zero-work headers.
        a.li(R[25], 0);
        a.eq(R[1], R[26], R[25]);
        a.assert(R[1]);
        a.gt(R[1], R[27], R[25]);
        a.assert(R[1]);

        // 5. Advance Poseidon transcript and parent/height cursors.
        a.poseidon(R[5], R[5], R[21]);
        a.poseidon(R[5], R[5], R[22]);
        a.poseidon(R[5], R[5], R[23]);
        a.poseidon(R[5], R[5], R[24]);
        a.mov(R[2], R[21]);
        a.mov(R[3], R[22]);
    }

    a.region("assert_tip_and_publish_claim");
    a.load_abs(R[20], cells.expected_tip_fold);
    a.eq(R[1], R[2], R[20]);
    a.assert(R[1]);

    a.load_abs(R[20], cells.expected_tip_height);
    a.eq(R[1], R[3], R[20]);
    a.assert(R[1]);

    for k in 0..CHAINWORK_U32_LIMBS {
        let acc_reg = R
            .get(10 + k)
            .copied()
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "register index out of range".to_string(),
            })?;
        a.load_abs(R[20], cells.expected_total_work_limbs + k as u64);
        a.eq(R[1], acc_reg, R[20]);
        a.assert(R[1]);
    }

    a.load_abs(R[20], cells.expected_transcript);
    a.eq(R[1], R[5], R[20]);
    a.assert(R[1]);

    emit_swrite_digest_cells(&mut a, cells.input_hash, 0);
    emit_swrite_digest_cells(&mut a, cells.output_hash, DIGEST_LIMBS_U32);
    a.halt();

    let program = a.finish().map_err(|e| AdapterError::ConsensusRule {
        rule: format!("failed to assemble BudVM Bitcoin SPV program: {e}"),
    })?;
    let program_hash = program_hash_of(&program.code);
    Ok(BitcoinHeaderStarkProgram {
        program,
        program_hash,
        header_count,
        cells,
    })
}

/// Verify a Bitcoin SPV chain and generate its Plonky3 `Claim::Prog` proof.
///
/// Proves the header chain transition and exact 256-bit [`ChainWork256`] bound
/// to `settlement_domain`.
///
/// # Errors
///
/// Returns [`AdapterError`] if raw SPV consensus verification fails, the batch
/// exceeds [`MAX_STARK_BATCH_HEADERS`], or `BudAir` STARK proving fails.
///
/// Convenience: kept for the CLI and Bitcoin SPV aggregator prover nodes.
pub fn prove_bitcoin_header_chain_stark(
    adapter: &BitcoinSpvAdapter,
    evidence: &RawConsensusEvidence,
    policy: &VerificationPolicy,
    settlement_domain: crate::domain::types::DomainId,
) -> Result<BitcoinHeaderStarkBatch, AdapterError> {
    use crate::aggregation::programs::prog_claim::{
        prove_vm_program, write_cell, write_digest_cells,
    };

    let verified = adapter.verify_chain(evidence, policy)?;
    let anchor = adapter
        .anchor
        .clone()
        .ok_or_else(|| AdapterError::Unavailable {
            reason: "no Bitcoin checkpoint is pinned for this domain".to_string(),
        })?;
    let compiled = compile_bitcoin_header_stark_program(verified.headers.len())?;
    let header_count =
        u32::try_from(verified.headers.len()).map_err(|_| AdapterError::ConsensusRule {
            rule: "header count overflows u32".to_string(),
        })?;
    let max_allowed_ts = policy.now.saturating_add(MAX_FUTURE_SECONDS);
    let tip = verified
        .headers
        .last()
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "verified chain cannot be empty".to_string(),
        })?;

    let anchor_hash_fold = fold_digest_poseidon(&anchor.block_hash);
    let tip_hash_fold = fold_digest_poseidon(&tip.hash);
    let transcript_commitment =
        compute_header_stark_transcript(anchor_hash_fold, anchor.height, &verified.headers);
    let input_hash = bitcoin_stark_input_hash(
        &adapter.network,
        &anchor,
        adapter.anchor_chainwork,
        header_count,
        max_allowed_ts,
    );
    let output_hash = bitcoin_stark_output_hash(
        tip.height,
        &tip.hash,
        &tip.merkle_root,
        tip.timestamp,
        tip.bits,
        verified.total_chainwork,
        transcript_commitment,
    );

    let mem_bytes = usize::try_from(compiled.program.memory_cells)
        .unwrap_or(0)
        .saturating_add(16)
        .saturating_mul(8);
    let mut vm = bud_vm::Vm::new(mem_bytes.max(4_096));
    write_digest_cells(&mut vm, compiled.cells.input_hash, &input_hash);
    write_digest_cells(&mut vm, compiled.cells.output_hash, &output_hash);
    write_cell(&mut vm, compiled.cells.anchor_hash_fold, anchor_hash_fold);
    write_cell(&mut vm, compiled.cells.anchor_height, anchor.height);
    write_cell(&mut vm, compiled.cells.max_allowed_ts, max_allowed_ts);
    for (k, limb) in chainwork_to_u32_le_limbs(adapter.anchor_chainwork)
        .into_iter()
        .enumerate()
    {
        write_cell(&mut vm, compiled.cells.init_work_limbs + k as u64, limb);
    }
    write_cell(&mut vm, compiled.cells.expected_tip_fold, tip_hash_fold);
    write_cell(&mut vm, compiled.cells.expected_tip_height, tip.height);
    for (k, limb) in chainwork_to_u32_le_limbs(verified.total_chainwork)
        .into_iter()
        .enumerate()
    {
        write_cell(
            &mut vm,
            compiled.cells.expected_total_work_limbs + k as u64,
            limb,
        );
    }
    write_cell(
        &mut vm,
        compiled.cells.expected_transcript,
        transcript_commitment,
    );

    for (i, hdr) in verified.headers.iter().enumerate() {
        let base = compiled.cells.headers_base + (i as u64) * BTC_STARK_HEADER_STRIDE;
        write_cell(&mut vm, base, fold_digest_poseidon(&hdr.parent_hash));
        write_cell(&mut vm, base + 1, fold_digest_poseidon(&hdr.hash));
        write_cell(&mut vm, base + 2, hdr.height);
        write_cell(&mut vm, base + 3, u64::from(hdr.timestamp));
        write_cell(&mut vm, base + 4, u64::from(hdr.bits));
        for (k, limb) in chainwork_to_u32_le_limbs(hdr.block_work)
            .into_iter()
            .enumerate()
        {
            write_cell(&mut vm, base + 5 + k as u64, limb);
        }
    }

    let stark_proof = prove_vm_program(
        &compiled.program.code,
        &mut vm,
        input_hash,
        output_hash,
        settlement_domain,
    )
    .map_err(|e| AdapterError::Crypto {
        what: format!("BudVM Bitcoin SPV STARK proving failed: {e}"),
    })?;

    let batch = BitcoinHeaderStarkBatch {
        network: adapter.network.clone(),
        anchor,
        anchor_chainwork: adapter.anchor_chainwork,
        header_count,
        max_allowed_ts,
        tip_height: tip.height,
        tip_hash: tip.hash,
        tip_merkle_root: tip.merkle_root,
        tip_timestamp: tip.timestamp,
        tip_bits: tip.bits,
        total_chainwork: verified.total_chainwork,
        transcript_commitment,
        program_hash: compiled.program_hash,
        stark_proof,
    };
    let _ = verify_bitcoin_header_chain_stark(
        &batch.network,
        &batch.anchor,
        batch.anchor_chainwork,
        settlement_domain,
        &batch,
    )?;
    Ok(batch)
}

/// Verify a 128-bit Plonky3 FRI-STARK [`BitcoinHeaderStarkBatch`] against a
/// governance-pinned Bitcoin anchor, returning the verified Phase 4
/// [`crate::aggregation::claim::Claim::Prog`].
///
/// Refuses forged programs, mismatched networks or anchors, lowered/inflated
/// `ChainWork256`, drifted heights, cross-domain replays, or tampered STARK
/// traces.
///
/// # Errors
///
/// Returns [`AdapterError`] if any public-input binding or Plonky3 `BudAir`
/// proof check fails.
///
/// Convenience: kept for the CLI and settlement `Claim::Prog` header consumers.
pub fn verify_bitcoin_header_chain_stark(
    expected_network: &str,
    expected_anchor: &PinnedBitcoinAnchor,
    expected_anchor_chainwork: ChainWork256,
    settlement_domain: crate::domain::types::DomainId,
    batch: &BitcoinHeaderStarkBatch,
) -> Result<crate::aggregation::claim::Claim, AdapterError> {
    use crate::aggregation::claim::Claim;
    use crate::aggregation::programs::prog_claim::verify_vm_proof;

    if batch.network != expected_network {
        return Err(AdapterError::WrongAdapter {
            expected: expected_network.to_string(),
            found: batch.network.clone(),
        });
    }
    if batch.anchor != *expected_anchor || batch.anchor_chainwork != expected_anchor_chainwork {
        return Err(AdapterError::ConsensusRule {
            rule: "Bitcoin STARK batch does not start from the pinned anchor".to_string(),
        });
    }
    let count_usize =
        usize::try_from(batch.header_count).map_err(|_| AdapterError::ConsensusRule {
            rule: "Bitcoin STARK batch count does not fit usize".to_string(),
        })?;
    let expected_program = compile_bitcoin_header_stark_program(count_usize)?;
    if batch.program_hash != expected_program.program_hash
        || batch.stark_proof.program != expected_program.program.code
    {
        return Err(AdapterError::Crypto {
            what: "Bitcoin STARK batch program_hash does not match canonical verifier circuit"
                .to_string(),
        });
    }
    let expected_tip_height = expected_anchor
        .height
        .checked_add(u64::from(batch.header_count))
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "Bitcoin STARK tip height overflows u64".to_string(),
        })?;
    if batch.tip_height != expected_tip_height {
        return Err(AdapterError::DeclarationMismatch { field: "height" });
    }
    if batch.total_chainwork <= expected_anchor_chainwork
        || batch.tip_hash == [0u8; 32]
        || batch.tip_merkle_root == [0u8; 32]
        || u64::from(batch.tip_timestamp) > batch.max_allowed_ts
    {
        return Err(AdapterError::ConsensusRule {
            rule: "Bitcoin STARK batch violates chainwork, root, or +2h clock invariant"
                .to_string(),
        });
    }

    let expected_in = bitcoin_stark_input_hash(
        expected_network,
        expected_anchor,
        expected_anchor_chainwork,
        batch.header_count,
        batch.max_allowed_ts,
    );
    let expected_out = bitcoin_stark_output_hash(
        batch.tip_height,
        &batch.tip_hash,
        &batch.tip_merkle_root,
        batch.tip_timestamp,
        batch.tip_bits,
        batch.total_chainwork,
        batch.transcript_commitment,
    );
    if batch.stark_proof.input_hash != expected_in || batch.stark_proof.output_hash != expected_out
    {
        return Err(AdapterError::Crypto {
            what: "Bitcoin STARK batch I/O digests disagree with declared anchor/tip".to_string(),
        });
    }

    let claim = verify_vm_proof(settlement_domain, &batch.stark_proof).map_err(|_| {
        AdapterError::Crypto {
            what: "Plonky3 BudAir FRI-STARK proof failed verification".to_string(),
        }
    })?;
    match claim {
        Claim::Prog {
            program_hash,
            input_hash,
            output_hash,
        } if program_hash == expected_program.program_hash
            && input_hash == expected_in
            && output_hash == expected_out =>
        {
            Ok(claim)
        }
        _ => Err(AdapterError::Crypto {
            what: "verified Claim::Prog does not match canonical Bitcoin SPV bindings".to_string(),
        }),
    }
}

/// Builds a canonical SPV evidence envelope. The anchor never travels inside
/// the payload; it is state the registered adapter holds.
///
/// WIRING: exercised by `src/tests/bitcoin_spv.rs` and the module's own
/// fault probes; a production caller would mean evidence was being minted by
/// the node rather than submitted by a relayer.
#[cfg(test)]
#[must_use]
pub(crate) fn spv_evidence(
    adapter: &BitcoinSpvAdapter,
    network: &str,
    header_bytes: &[&[u8; HEADER_LEN]],
    submitter: Address,
) -> RawConsensusEvidence {
    let mut payload = Vec::with_capacity(4 + header_bytes.len() * HEADER_LEN);
    payload.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    for header in header_bytes {
        payload.extend_from_slice(header.as_slice());
    }
    // The declared root is the internal-order hash of the last header, and the
    // declared height is the anchor height plus the number of headers.
    let last = header_bytes
        .last()
        .copied()
        .map_or([0u8; 32], |h| sha256d(h.as_slice()));
    let height = adapter
        .anchor
        .as_ref()
        .map_or(0, |a| a.height.saturating_add(header_bytes.len() as u64));
    RawConsensusEvidence {
        adapter: adapter.descriptor().id,
        evidence_version: EVIDENCE_VERSION,
        network: network.to_string(),
        payload,
        declared_height: height,
        declared_root: last,
        submitter,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real Bitcoin mainnet headers 0..=6, fetched from a public block
    /// explorer and pinned here as hex so the suite stays offline and
    /// deterministic. These are consensus data, not generated fixtures.
    const MAINNET_HEADERS: [&str; 7] = [
        "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
        "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
        "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61",
        "01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d",
        "010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9",
        "0100000085144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000e11c48fecdd9e72510ca84f023370c9a38bf91ac5cae88019bee94d24528526344c36649ffff001d1d03e477",
        "01000000fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000379dfb96a5ea8c81700ea4ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c97",
    ];

    /// The ancestry witness has to be the hash of a parent header that is
    /// *inside the payload*, derived exactly the way `verify` derives the
    /// attested block hash. A single-header payload has no parent to hash, so
    /// it must answer `None` rather than echo the unverified `prev_block`
    /// pointer it carries.
    #[test]
    fn empty_network_adapter_refuses_evidence_fail_closed() {
        // An adapter constructed with an empty network label is a
        // configuration error. It must refuse every evidence payload
        // fail-closed instead of accepting payloads that also carry an
        // empty network (where `"" == ""` would otherwise match).
        let adapter = BitcoinSpvAdapter::new("", None);
        let raw = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: EVIDENCE_VERSION,
            network: String::new(),
            payload: Vec::new(),
            declared_height: 0,
            declared_root: [0u8; 32],
            submitter: crate::core::address::Address([0u8; 32]),
        };
        let err = adapter
            .verify(&raw, &VerificationPolicy::strict(0))
            .unwrap_err();
        assert!(
            matches!(&err, AdapterError::ConsensusRule { rule } if rule.contains("empty")),
            "empty-network adapter must refuse fail-closed, got {err:?}"
        );
    }

    #[test]
    fn attested_parent_is_the_parent_header_inside_the_payload_or_none() {
        let headers = header_bytes();
        let adapter = adapter();
        let refs: Vec<&[u8; HEADER_LEN]> = headers.iter().collect();
        let submitter = Address::from([0x11; 32]);

        let single = spv_evidence(&adapter, "mainnet", &refs[0..1], submitter);
        assert_eq!(adapter.attested_parent(&single), None);

        let pair = spv_evidence(&adapter, "mainnet", &refs[0..2], submitter);
        assert_eq!(
            adapter.attested_parent(&pair),
            Some(sha256d(headers[0].as_slice()))
        );

        let triple = spv_evidence(&adapter, "mainnet", &refs[0..3], submitter);
        assert_eq!(
            adapter.attested_parent(&triple),
            Some(sha256d(headers[1].as_slice())),
            "the parent is the second-to-last header, never the first and never the tip"
        );
    }

    fn header_bytes() -> Vec<[u8; HEADER_LEN]> {
        MAINNET_HEADERS
            .iter()
            .map(|h| {
                let raw = hex::decode(h).expect("pinned header is hex");
                let mut out = [0u8; HEADER_LEN];
                out.copy_from_slice(&raw);
                out
            })
            .collect()
    }

    fn genesis_hash_internal() -> [u8; 32] {
        sha256d(header_bytes()[0].as_slice())
    }

    fn adapter() -> BitcoinSpvAdapter {
        BitcoinSpvAdapter::new(
            "mainnet",
            Some(PinnedBitcoinAnchor {
                height: 0,
                block_hash: genesis_hash_internal(),
                bits: 0x1d00_ffff,
            }),
        )
    }

    /// Policy clock: just after the last real header's timestamp, so the
    /// golden sample is neither stale nor in the future.
    fn policy() -> VerificationPolicy {
        VerificationPolicy {
            min_depth: 1,
            require_declared_match: true,
            max_age: 0,
            now: 1_231_500_000,
            require_slashable: false,
        }
    }

    fn golden(adapter: &BitcoinSpvAdapter) -> RawConsensusEvidence {
        let bytes = header_bytes();
        let refs: Vec<&[u8; HEADER_LEN]> = bytes.iter().skip(1).collect();
        spv_evidence(adapter, "mainnet", &refs, Address([1u8; 32]))
    }

    #[test]
    fn real_mainnet_headers_link_and_meet_pow() {
        let mut payload = 7u32.to_le_bytes().to_vec();
        for h in header_bytes() {
            payload.extend_from_slice(h.as_slice());
        }
        let parsed = parse_headers(&payload).expect("seven real headers parse");
        assert_eq!(parsed.len(), 7);
        let target = target_from_bits(0x1d00_ffff).expect("mainnet target");
        for (index, header) in parsed.iter().enumerate() {
            assert!(
                meets_target(&header.hash, &target),
                "header {index} fails proof of work"
            );
            if index > 0 {
                assert_eq!(
                    header.parent_hash,
                    parsed[index - 1].hash,
                    "header {index} breaks the parent link"
                );
            }
        }
        // Genesis hash in internal byte order is the well-known block 0 hash
        // reversed from its display form.
        let display = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let mut expected = hex::decode(display).expect("display hash");
        expected.reverse();
        assert_eq!(parsed[0].hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn a_pinned_spv_chain_produces_work_backing() {
        let adapter = adapter();
        let evidence = golden(&adapter);
        let attestation = adapter
            .verify(&evidence, &policy())
            .expect("golden verifies");
        assert!(matches!(
            attestation.security,
            SecurityBacking::Work { difficulty_bits } if difficulty_bits >= 32
        ));
        assert_eq!(attestation.height, 6);
        assert_eq!(attestation.state_root, evidence.declared_root);
        assert_eq!(
            attestation.attested_block_hash,
            Some(evidence.declared_root)
        );
        assert_eq!(attestation.time_unit, TimeUnit::UnixSeconds);
        assert_eq!(attestation.evidence_digest, evidence.digest());
    }

    /// STRX consistency gate: a caller that demands slashable backing is
    /// refused with the same `UnslashableBacking` red meaning as every other
    /// work-weighted adapter. Bitcoin SPV backing is accumulated header-chain
    /// proof of work with no bonded stake to confiscate, so `require_slashable
    /// = true` must fail closed here exactly as it does in the other Work
    /// producers. This locks the STRX-194-01 red meaning across the Work
    /// adapter family so one adapter cannot silently read `Work` as a bonded
    /// signature set.
    #[test]
    fn bitcoin_spv_require_slashable_policy_refuses_work_backing() {
        let adapter = adapter();
        let evidence = golden(&adapter);
        let mut slash_policy = policy();
        slash_policy.require_slashable = true;
        assert!(
            matches!(
                adapter.verify(&evidence, &slash_policy),
                Err(AdapterError::UnslashableBacking)
            ),
            "require_slashable=true must fail closed with UnslashableBacking for SPV work backing"
        );

        // Sanity: the same golden passes when slashability is not demanded.
        slash_policy.require_slashable = false;
        assert!(
            adapter.verify(&evidence, &slash_policy).is_ok(),
            "the golden SPV chain must verify when slashability is not required"
        );
    }

    #[test]
    fn verify_spv_tx_inclusion_accepts_honest_branch_and_refuses_cve_2012_2459_duplicate() {
        let pair = |l: [u8; 32], r: [u8; 32]| {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&l);
            buf[32..].copy_from_slice(&r);
            sha256d(&buf)
        };
        let tx0 = sha256d(b"tx0");
        let tx1 = sha256d(b"tx1");
        let tx2 = sha256d(b"tx2");
        let tx3 = sha256d(b"tx3");
        let h01 = pair(tx0, tx1);
        let h23 = pair(tx2, tx3);
        let root = pair(h01, h23);

        assert!(verify_spv_tx_inclusion(&tx2, &root, 2, &[tx3, h01]));
        assert!(!verify_spv_tx_inclusion(&tx2, &root, 3, &[tx3, h01]));
        // High index bits beyond branch depth must be rejected.
        assert!(!verify_spv_tx_inclusion(
            &tx2,
            &root,
            2 | (1 << 2),
            &[tx3, h01]
        ));
        // CVE-2012-2459 duplicate-sibling Merkle step must fail closed.
        let dup_root = pair(tx0, tx0);
        assert!(!verify_spv_tx_inclusion(&tx0, &dup_root, 0, &[tx0]));
        assert!(!verify_spv_tx_inclusion(&tx0, &dup_root, 1, &[tx0]));
        assert!(!verify_spv_tx_inclusion(&[0u8; 32], &root, 0, &[tx1, h23]));
    }

    #[test]
    fn bitcoin_difficulty_retarget_matches_mainnet_block_32256_vector_and_clamps_bounds() {
        // Real Bitcoin Core test vector (`pow_tests.cpp`): epoch ending at
        // block 32255 (first = 1261130161, last = 1262152739, prev = 0x1d00ffff)
        // produces exact next compact target `0x1d00d86a`.
        let next = compute_next_work_required(1_261_130_161, 1_262_152_739, 0x1d00_ffff)
            .expect("valid Bitcoin mainnet retarget");
        assert_eq!(next, 0x1d00_d86a);

        // Exact 14-day epoch leaves difficulty unchanged.
        let base_ts = 1_700_000_000u32;
        let unchanged =
            compute_next_work_required(base_ts, base_ts + POW_TARGET_TIMESPAN_SECS, 0x1c0f_fff0)
                .expect("exact 14-day retarget");
        assert_eq!(unchanged, 0x1c0f_fff0);

        // Extreme fast epoch clamps at exactly 1/4 target (4x harder).
        let clamped_fast = compute_next_work_required(base_ts, base_ts + 10, 0x1c0f_fff0)
            .expect("clamped fast retarget");
        let exact_quarter =
            compute_next_work_required(base_ts, base_ts + MIN_ACTUAL_TIMESPAN_SECS, 0x1c0f_fff0)
                .expect("exact quarter retarget");
        assert_eq!(clamped_fast, exact_quarter);
        assert!(
            target_from_bits(clamped_fast).expect("t") < target_from_bits(0x1c0f_fff0).expect("t")
        );

        // Extreme slow epoch clamps at 4x target and never exceeds MAINNET_POW_LIMIT_BITS.
        let clamped_slow = compute_next_work_required(base_ts, base_ts + 50_000_000, 0x1d00_ffff)
            .expect("pow limit clamp");
        assert_eq!(clamped_slow, MAINNET_POW_LIMIT_BITS);

        // BIP-113 Median-Time-Past computes exact median of trailing 11 blocks,
        // permitting non-monotonic minor clock skew above MTP while rejecting <= MTP.
        let ts = [100, 120, 115, 130, 125, 140, 135, 150, 145, 160, 155];
        assert_eq!(median_time_past(&ts), Some(135));
    }

    fn mine_test_header(
        parent_hash: [u8; 32],
        merkle_root: [u8; 32],
        timestamp: u32,
        bits: u32,
    ) -> [u8; HEADER_LEN] {
        let target = target_from_bits(bits).expect("valid test bits");
        let mut raw = [0u8; HEADER_LEN];
        raw[0..4].copy_from_slice(&0x2000_0000i32.to_le_bytes());
        raw[4..36].copy_from_slice(&parent_hash);
        raw[36..68].copy_from_slice(&merkle_root);
        raw[68..72].copy_from_slice(&timestamp.to_le_bytes());
        raw[72..76].copy_from_slice(&bits.to_le_bytes());
        for nonce in 0..=u32::MAX {
            raw[76..80].copy_from_slice(&nonce.to_le_bytes());
            let hash = sha256d(&raw);
            if meets_target(&hash, &target) {
                return raw;
            }
        }
        panic!("could not mine regtest header for bits {bits:08x}");
    }

    #[test]
    fn retarget_boundary_refuses_unverified_constant_bits_without_epoch_start() {
        // Anchor at height 2015 without epoch_start_timestamp: header #1 is
        // block 2016 (a mandatory Bitcoin difficulty retarget boundary) and
        // MUST fail closed rather than accepting unverified constant nBits.
        let bits = REGTEST_POW_LIMIT_BITS;
        let anchor_hash = sha256d(b"anchor-2015");
        let adapter = BitcoinSpvAdapter::new(
            "regtest",
            Some(PinnedBitcoinAnchor {
                height: 2_015,
                block_hash: anchor_hash,
                bits,
            }),
        );
        let mut chain = Vec::with_capacity(6);
        let mut prev = anchor_hash;
        for step in 0..6u32 {
            let h = mine_test_header(
                prev,
                sha256d(&step.to_le_bytes()),
                1_700_000_600 + step * 600,
                bits,
            );
            prev = sha256d(&h);
            chain.push(h);
        }
        let refs: Vec<&[u8; HEADER_LEN]> = chain.iter().collect();
        let ev = spv_evidence(&adapter, "regtest", &refs, Address([2u8; 32]));
        let pol = VerificationPolicy {
            min_depth: 6,
            require_declared_match: true,
            max_age: 0,
            now: 1_700_010_000,
            require_slashable: false,
        };
        let err = adapter
            .verify(&ev, &pol)
            .expect_err("crossing block 2016 without opening timestamp must fail closed");
        assert!(
            matches!(err, AdapterError::ConsensusRule { ref rule } if rule.contains("retarget boundary")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn intermediate_future_header_timestamp_warp_is_refused() {
        // Inject 5 year-2106 (u32::MAX) intermediate headers capped by a normal
        // tip above MTP-11: per-header +2h enforcement MUST refuse header #1.
        let bits = REGTEST_POW_LIMIT_BITS;
        let now = 1_700_010_000u64;
        let anchor_hash = sha256d(b"anchor-warp");
        let adapter = BitcoinSpvAdapter::new(
            "regtest",
            Some(PinnedBitcoinAnchor {
                height: 100,
                block_hash: anchor_hash,
                bits,
            }),
        );
        let mut chain = Vec::with_capacity(12);
        let mut prev = anchor_hash;
        for i in 0..12u32 {
            let ts = if (6..11).contains(&i) {
                u32::MAX
            } else {
                1_700_000_000 + i * 600
            };
            let h = mine_test_header(prev, sha256d(&i.to_le_bytes()), ts, bits);
            prev = sha256d(&h);
            chain.push(h);
        }
        let refs: Vec<&[u8; HEADER_LEN]> = chain.iter().collect();
        let ev = spv_evidence(&adapter, "regtest", &refs, Address([3u8; 32]));
        let pol = VerificationPolicy {
            min_depth: 6,
            require_declared_match: true,
            max_age: 0,
            now,
            require_slashable: false,
        };
        let err = adapter
            .verify(&ev, &pol)
            .expect_err("intermediate u32::MAX future header must be refused");
        assert!(
            matches!(err, AdapterError::ConsensusRule { ref rule } if rule.contains("+2h clock bound")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn full_2016_block_epoch_retarget_uses_exact_block_2016_opening_timestamp() {
        // Verify a complete self-contained 2,017-header chain from anchor 2015
        // through 4032 (crossing BOTH retarget boundaries 2016 and 4032),
        // proving MAX_HEADERS >= 2017 AND that epoch 1 opens at block 2016
        // (never off-by-one block 2017).
        let epoch0_bits = 0x207f_fff0u32;
        let ts_0 = 1_700_000_000u32;
        let ts_2015 = ts_0 + POW_TARGET_TIMESPAN_SECS;
        let ts_2016 = ts_2015 + 600;
        let epoch1_bits = compute_next_work_required_with_limit(
            ts_0,
            ts_2015,
            epoch0_bits,
            REGTEST_POW_LIMIT_BITS,
        )
        .expect("epoch1");
        assert_eq!(epoch1_bits, epoch0_bits);

        let anchor_hash = sha256d(b"anchor-full-epoch-2015");
        let prior = [
            ts_2015 - 6_000,
            ts_2015 - 5_400,
            ts_2015 - 4_800,
            ts_2015 - 4_200,
            ts_2015 - 3_600,
            ts_2015 - 3_000,
            ts_2015 - 2_400,
            ts_2015 - 1_800,
            ts_2015 - 1_200,
            ts_2015 - 600,
            ts_2015,
        ];
        let adapter = BitcoinSpvAdapter::new(
            "regtest",
            Some(PinnedBitcoinAnchor {
                height: 2_015,
                block_hash: anchor_hash,
                bits: epoch0_bits,
            }),
        )
        .with_epoch_start_timestamp(ts_0)
        .with_prior_timestamps(prior);

        // Make block 2017 jump +100_000s ahead of block 2016 so an off-by-one
        // opening timestamp (2017 vs 2016) computes a strictly distinct nBits.
        let mut chain = Vec::with_capacity(2_017);
        let mut prev = anchor_hash;
        let mut ts_4031 = ts_2016;
        for idx in 0..2_016u32 {
            let ts = if idx == 0 {
                ts_2016
            } else {
                ts_2016 + 100_000 + idx * 250
            };
            ts_4031 = ts;
            let h = mine_test_header(prev, sha256d(&idx.to_le_bytes()), ts, epoch1_bits);
            prev = sha256d(&h);
            chain.push(h);
        }
        let expected_epoch2_bits = compute_next_work_required_with_limit(
            ts_2016,
            ts_4031,
            epoch1_bits,
            REGTEST_POW_LIMIT_BITS,
        )
        .expect("epoch2");
        let off_by_one_bits = compute_next_work_required_with_limit(
            ts_2016 + 100_250,
            ts_4031,
            epoch1_bits,
            REGTEST_POW_LIMIT_BITS,
        )
        .expect("off-by-one");
        assert_ne!(expected_epoch2_bits, off_by_one_bits);

        let tip_ts = ts_4031 + 300;
        let bad_tip = mine_test_header(prev, sha256d(b"bad-4032"), tip_ts, off_by_one_bits);
        let good_tip = mine_test_header(prev, sha256d(b"good-4032"), tip_ts, expected_epoch2_bits);

        let pol = VerificationPolicy {
            min_depth: 6,
            require_declared_match: true,
            max_age: 0,
            now: u64::from(tip_ts) + 60,
            require_slashable: false,
        };

        let mut bad_chain = chain.clone();
        bad_chain.push(bad_tip);
        let bad_refs: Vec<&[u8; HEADER_LEN]> = bad_chain.iter().collect();
        let bad_ev = spv_evidence(&adapter, "regtest", &bad_refs, Address([4u8; 32]));
        assert!(matches!(
            adapter.verify(&bad_ev, &pol),
            Err(AdapterError::ConsensusRule { .. })
        ));

        chain.push(good_tip);
        let good_refs: Vec<&[u8; HEADER_LEN]> = chain.iter().collect();
        let good_ev = spv_evidence(&adapter, "regtest", &good_refs, Address([4u8; 32]));
        let verified = adapter
            .verify_chain(&good_ev, &pol)
            .expect("exact 2017-header retarget chain verifies");
        assert_eq!(verified.attestation.height, 4_032);
        assert_eq!(verified.headers.len(), 2_017);
        assert_eq!(
            verified.headers.last().expect("tip").bits,
            expected_epoch2_bits
        );
    }
}
