//! Merged-mining Auxiliary Proof-of-Work (`AuxPoW`) and Proof-of-Proof (`PoP`)
//! external finality adapter with exact 256-bit cumulative chainwork,
//! deterministic `chain_id` Merkle-slot uniqueness, CVE-2012-2459 protection,
//! and bonded `PoP` double-anchor slashing.
//!
//! Merged-mining networks (Namecoin 2011, Dogecoin 2014, Rootstock/RSK) and
//! Proof-of-Proof / Proof-of-Transfer layers anchor an auxiliary chain's block
//! hash inside a parent `PoW` chain's coinbase transaction. Accepting an `AuxPoW`
//! commitment safely requires closing four classical attack vectors:
//!
//! 1. **Exact 256-bit parent `PoW` chain & cumulative work**: each 80-byte parent
//!    header must chain onto its predecessor via double-SHA-256
//!    (`prev_block_hash == sha256d(parent[i-1])`), expand a positive,
//!    non-overflowing compact `nBits` target at or below `pinned.max_target_bits`,
//!    satisfy `sha256d(header) <= target` in big-endian 256-bit order, reach at
//!    least `required_depth` parent confirmations on top of the anchor block,
//!    and accumulate `sum(floor((2^256 - 1) / (target + 1))) >=
//!    pinned.min_cumulative_work`.
//! 2. **Coinbase inclusion with CVE-2012-2459 refusal**: the parent coinbase
//!    must sit at Merkle index `0` (`coinbase_index == 0`), carry bounded
//!    depth (`<= 32`), reject self-paired duplicate siblings (`sib == acc`),
//!    and hash via double-SHA-256 directly to `parent_headers[0].merkle_root`.
//! 3. **Single-slot `AuxPoW` commitment binding**: the coinbase must contain
//!    exactly one merged-mining magic marker `0xFABE6D6D` followed by
//!    `(aux_merkle_root: [u8; 32], tree_size: u32_le, merkle_nonce: u32_le)`
//!    where `tree_size == 1 << aux_branch.len()`, and `aux_slot_index` must
//!    equal the deterministic LCG slot for `(pinned.aux_chain_id, merkle_nonce,
//!    aux_branch.len())` so a dishonest parent miner cannot commit two distinct
//!    auxiliary blocks for the same `aux_chain_id` in one parent block.
//! 4. **Bonded `PoP` anchor quorum & double-anchor slashing**: when
//!    `pinned.pop_signers` is non-empty, strictly more than `2/3` of bonded
//!    `PoP` anchor stake must co-sign `(network, aux_chain_id, aux_height,
//!    parent_anchor_hash, aux_block.digest)` with hybrid Ed25519 + mandatory
//!    ML-DSA-65 ([`crate::crypto::ctx::CROSS_DOMAIN_V1`]); anchoring two
//!    distinct auxiliary blocks at the same `aux_height` is slashable through
//!    [`verify_pop_equivocation`].
//!
//! WIRING: implements [`ExternalFinalityAdapter`] and is invoked in production
//! by [`crate::cross_domain::economic_guard`] for `AuxPoW`/`PoP` ceiling checks and
//! double-anchor contradiction slashing.

use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::external::bitcoin_spv::sha256d;
use crate::crypto::facts::{CryptoObserver, ObservedScheme};
use crate::crypto::pq;
use crate::crypto::primitives::verify_signature;
use crate::crypto::scheme::SchemeId;
use crate::domain::types::Hash32;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use subtle::ConstantTimeEq;

use super::selftest::{BytePatch, ExpectedRefusal, FaultProbe, RefusalKind};
use super::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, RawConsensusEvidence, SecurityBacking, TimeUnit, TrustModel,
    VerificationPolicy,
};

const ADAPTER_NAME: &str = "auxpow-pop-v1";
const ADAPTER_VERSION: u32 = 1;
const EVIDENCE_VERSION: u32 = 1;
const PAYLOAD_MAGIC: &[u8; 8] = b"BDLMAUX1";
/// Canonical merged-mining coinbase marker (`0xFA, 0xBE, b'm', b'm'`).
pub const AUXPOW_COINBASE_MAGIC: [u8; 4] = [0xFA, 0xBE, 0x6D, 0x6D];
const DEFAULT_REQUIRED_CONFIRMATIONS: u64 = 6;
const MAX_AUXPOW_PAYLOAD_BYTES: usize = 512 * 1024;
const PARENT_HEADER_LEN: usize = 80;
const MAX_PARENT_HEADERS: usize = 2_016;
const MAX_COINBASE_BYTES: usize = 100_000;
const MAX_MERKLE_DEPTH: usize = 30;
const MAX_POP_COMMITTEE: usize = 1_024;

/// Big-endian 256-bit unsigned integer encoding used for `PoW` targets and
/// cumulative chainwork.
pub type U256Bytes = [u8; 32];

/// One bonded Proof-of-Proof (`PoP`) anchor committee member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PopAnchorSigner {
    /// Classical Ed25519 verifying key (32 bytes, non-zero).
    pub ed25519_pubkey: [u8; 32],
    /// Non-zero slashable `PoP` bond weight.
    pub bond_weight: u64,
    /// Optional ML-DSA-65 public key; when non-empty, ML-DSA-65 co-signatures
    /// under `CROSS_DOMAIN_V1` are mandatory.
    #[serde(default)]
    pub pq_pubkey: Vec<u8>,
}

/// Detached hybrid signature produced by a [`PopAnchorSigner`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PopSignature {
    /// Signer Ed25519 verifying key.
    pub signer_pubkey: [u8; 32],
    /// Detached Ed25519 signature bytes.
    pub ed25519_sig: Vec<u8>,
    /// Mandatory ML-DSA-65 co-signature when `pq_pubkey` is registered.
    #[serde(default)]
    pub pq_sig: Vec<u8>,
}

/// Governance-pinned merged-mining and `PoP` anchor parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedAuxPowAnchor {
    /// Auxiliary chain identifier determining its unique `AuxPoW` Merkle slot (`>= 1`).
    pub aux_chain_id: u32,
    /// Trusted parent-chain block hash (`sha256d`, internal byte order) that
    /// `parent_headers[0].prev_block_hash` must link to.
    pub trusted_parent_hash: Hash32,
    /// Easiest (largest) allowed compact `nBits` target on parent headers.
    pub max_target_bits: u32,
    /// Minimum cumulative 256-bit work across the verified parent header chain.
    pub min_cumulative_work: U256Bytes,
    /// Minimum number of parent headers confirming the `AuxPoW` anchor (`>= 1`).
    pub min_confirmations: u64,
    /// Optional bonded `PoP` co-signer set; when non-empty, `> 2/3` stake must
    /// co-sign the anchored auxiliary block.
    #[serde(default)]
    pub pop_signers: Vec<PopAnchorSigner>,
}

impl PinnedAuxPowAnchor {
    /// Canonical length-prefixed SHA3-256 commitment over every pinned merged-mining
    /// and bonded `PoP` anchor parameter.
    ///
    /// WIRING: checked in constant time by `crate::cross_domain::economic_guard`
    /// on both backing refreshes and contradiction submissions.
    #[must_use]
    pub fn canonical_pin_digest(&self) -> Hash32 {
        let mut acc = crate::core::hash::hash_fields_bytes(&[
            b"BDLM_AUXPOW_PIN_V1",
            &self.aux_chain_id.to_le_bytes(),
            &self.trusted_parent_hash,
            &self.max_target_bits.to_le_bytes(),
            &self.min_cumulative_work,
            &self.min_confirmations.to_le_bytes(),
            &(self.pop_signers.len() as u64).to_le_bytes(),
        ]);
        for signer in &self.pop_signers {
            acc = crate::core::hash::hash_fields_bytes(&[
                b"BDLM_AUXPOW_PIN_V1",
                &[1u8],
                &acc,
                &signer.ed25519_pubkey,
                &signer.bond_weight.to_le_bytes(),
                &signer.pq_pubkey,
            ]);
        }
        acc
    }

    /// Return the bonded `PoP` weight and whether an ML-DSA-65 key is attached
    /// for `pubkey`.
    ///
    /// WIRING: used by `crate::cross_domain::economic_guard` for incremental
    /// per-offender `PoP` slashing accounting.
    #[must_use]
    pub fn pop_member_info(&self, pubkey: &[u8; 32]) -> Option<(u128, bool)> {
        self.pop_signers
            .iter()
            .find(|s| bool::from(s.ed25519_pubkey.ct_eq(pubkey)))
            .map(|s| (u128::from(s.bond_weight), !s.pq_pubkey.is_empty()))
    }
}

/// Self-derived auxiliary block commitment anchored via `AuxPoW`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuxBlockCommitment {
    /// Auxiliary chain identifier (`== pinned.aux_chain_id`).
    pub aux_chain_id: u32,
    /// Auxiliary block height (`>= 1`).
    pub aux_height: u64,
    /// Auxiliary block timestamp in Unix seconds.
    pub timestamp_secs: u64,
    /// Committed post-state root (non-zero).
    pub state_root: Hash32,
    /// Committed transaction root (non-zero).
    pub tx_root: Hash32,
    /// Optional bridge event root (`[0; 32]` when absent).
    pub event_root: Hash32,
    /// Self-derived commitment hash inserted into the `AuxPoW` Merkle tree.
    pub digest: Hash32,
}

impl AuxBlockCommitment {
    /// Compute the canonical domain-separated auxiliary block digest.
    #[must_use]
    pub fn compute_digest(&self, network: &str) -> Hash32 {
        crate::core::hash::hash_fields_bytes(&[
            b"BDLM_AUXPOW_AUX_BLOCK_V1",
            network.as_bytes(),
            &self.aux_chain_id.to_le_bytes(),
            &self.aux_height.to_le_bytes(),
            &self.timestamp_secs.to_le_bytes(),
            &self.state_root,
            &self.tx_root,
            &self.event_root,
        ])
    }
}

/// Canonical `AuxPoW` + `PoP` finality evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuxPowPopEvidence {
    /// Anchored auxiliary block header.
    pub aux_block: AuxBlockCommitment,
    /// Contiguous sequence of 80-byte parent `PoW` headers starting at the
    /// `AuxPoW` carrier block (`parent_headers[0]`) followed by confirmation headers.
    pub parent_headers: Vec<Vec<u8>>,
    /// Raw serialized parent coinbase transaction committing `aux_merkle_root`.
    pub coinbase_tx: Vec<u8>,
    /// Index of `coinbase_tx` in `parent_headers[0]` (must be `0`).
    pub coinbase_index: u32,
    /// Double-SHA-256 Merkle siblings linking `coinbase_tx` to `merkle_root`.
    pub coinbase_branch: Vec<Hash32>,
    /// Deterministic slot index of `aux_block.digest` inside the aux tree.
    pub aux_slot_index: u32,
    /// Double-SHA-256 Merkle siblings linking `aux_block.digest` to `aux_merkle_root`.
    pub aux_branch: Vec<Hash32>,
    /// Bonded `PoP` anchor signatures (`> 2/3` when `pinned.pop_signers` is non-empty).
    #[serde(default)]
    pub pop_sigs: Vec<PopSignature>,
}

/// Slashable double-anchor evidence proving one or more `PoP` signers anchored
/// two distinct auxiliary blocks at the same `aux_height`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PopEquivocationProof {
    /// Auxiliary chain identifier matching [`PinnedAuxPowAnchor::aux_chain_id`].
    pub aux_chain_id: u32,
    /// Conflicting auxiliary block height.
    pub aux_height: u64,
    /// Parent `PoW` block hash referenced by the first anchor vote.
    pub parent_hash_a: Hash32,
    /// First auxiliary block digest.
    pub aux_digest_a: Hash32,
    /// Signatures over the first anchor vote.
    pub sigs_a: Vec<PopSignature>,
    /// Parent `PoW` block hash referenced by the second anchor vote.
    pub parent_hash_b: Hash32,
    /// Second conflicting auxiliary block digest (`!= aux_digest_a`).
    pub aux_digest_b: Hash32,
    /// Signatures over the second anchor vote.
    pub sigs_b: Vec<PopSignature>,
}

/// Verified outcome of [`verify_pop_equivocation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPopSlash {
    /// Canonical domain-separated digest of the proven double-anchor fault.
    pub evidence_digest: Hash32,
    /// Auxiliary block height of the equivocation.
    pub fault_height: u64,
    /// Sorted unique Ed25519 keys of proven equivocating `PoP` signers.
    pub offenders: Vec<[u8; 32]>,
    /// Aggregate slashable `PoP` bond weight of `offenders`.
    pub slashed_bond_weight: u128,
}

/// Deterministic merged-mining LCG slot derivation for `(chain_id, nonce, depth)`.
#[must_use]
pub const fn expected_auxpow_slot(chain_id: u32, nonce: u32, tree_depth: u32) -> u32 {
    if tree_depth == 0 || tree_depth >= 31 {
        return 0;
    }
    let mut rand = nonce;
    rand = rand.wrapping_mul(1_103_515_245).wrapping_add(12_345);
    rand = rand.wrapping_add(chain_id);
    rand = rand.wrapping_mul(1_103_515_245).wrapping_add(12_345);
    rand % (1u32 << tree_depth)
}

/// Expand Bitcoin-style compact `nBits` into a big-endian 256-bit target,
/// rejecting zero mantissa, negative sign bit (`0x0080_0000`), and overflow.
///
/// # Errors
///
/// Returns [`AdapterError::ConsensusRule`] on zero, negative, or overflowing `bits`.
pub fn expand_compact_bits(bits: u32) -> Result<U256Bytes, AdapterError> {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x00ff_ffff;
    if mantissa == 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "auxpow compact target mantissa cannot be zero".into(),
        });
    }
    if (mantissa & 0x0080_0000) != 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "auxpow compact target has negative sign bit set".into(),
        });
    }
    let mut out = [0u8; 32];
    if exponent <= 3 {
        let shift = 8u32.saturating_mul(3u32.saturating_sub(u32::try_from(exponent).unwrap_or(3)));
        let val = mantissa.checked_shr(shift).unwrap_or(0);
        if val == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "auxpow compact target underflows to zero".into(),
            });
        }
        let bytes = val.to_be_bytes();
        if let (Some(dst), Some(src)) = (out.get_mut(28..32), bytes.get(..4)) {
            dst.copy_from_slice(src);
        }
        return Ok(out);
    }
    let b0 = ((mantissa >> 16) & 0xff) as u8;
    let b1 = ((mantissa >> 8) & 0xff) as u8;
    let b2 = (mantissa & 0xff) as u8;
    if exponent > 34 || (exponent == 34 && (b0 != 0 || b1 != 0)) || (exponent == 33 && b0 != 0) {
        return Err(AdapterError::ConsensusRule {
            rule: format!("auxpow compact target 0x{bits:08x} overflows 256 bits"),
        });
    }
    if exponent <= 32 {
        if let Some(slot) = out.get_mut(32usize.saturating_sub(exponent)) {
            *slot = b0;
        }
    }
    if exponent <= 33 {
        if let Some(slot) = out.get_mut(33usize.saturating_sub(exponent)) {
            *slot = b1;
        }
    }
    if let Some(slot) = out.get_mut(34usize.saturating_sub(exponent)) {
        *slot = b2;
    }
    Ok(out)
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct U256Limbs {
    // Big-endian 64-bit limbs: w0 is most significant, w3 is least significant.
    w0: u64,
    w1: u64,
    w2: u64,
    w3: u64,
}

impl U256Limbs {
    const ZERO: Self = Self {
        w0: 0,
        w1: 0,
        w2: 0,
        w3: 0,
    };
    const ONE: Self = Self {
        w0: 0,
        w1: 0,
        w2: 0,
        w3: 1,
    };
    const MAX: Self = Self {
        w0: u64::MAX,
        w1: u64::MAX,
        w2: u64::MAX,
        w3: u64::MAX,
    };

    const fn from_be(b: &U256Bytes) -> Self {
        let (a, rest) = b.split_at(8);
        let (c, rest2) = rest.split_at(8);
        let (d, e) = rest2.split_at(8);
        Self {
            w0: u64_from_be_slice(a),
            w1: u64_from_be_slice(c),
            w2: u64_from_be_slice(d),
            w3: u64_from_be_slice(e),
        }
    }

    const fn to_be(self) -> U256Bytes {
        let [a0, a1, a2, a3, a4, a5, a6, a7] = self.w0.to_be_bytes();
        let [b0, b1, b2, b3, b4, b5, b6, b7] = self.w1.to_be_bytes();
        let [c0, c1, c2, c3, c4, c5, c6, c7] = self.w2.to_be_bytes();
        let [d0, d1, d2, d3, d4, d5, d6, d7] = self.w3.to_be_bytes();
        [
            a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7, c0, c1, c2, c3, c4, c5,
            c6, c7, d0, d1, d2, d3, d4, d5, d6, d7,
        ]
    }

    const fn bitnot(self) -> Self {
        Self {
            w0: !self.w0,
            w1: !self.w1,
            w2: !self.w2,
            w3: !self.w3,
        }
    }

    const fn checked_add(self, rhs: Self) -> Option<Self> {
        let (w3, c3) = self.w3.overflowing_add(rhs.w3);
        let (t2, c2a) = self.w2.overflowing_add(rhs.w2);
        let (w2, c2b) = t2.overflowing_add(c3 as u64);
        let (t1, c1a) = self.w1.overflowing_add(rhs.w1);
        let (w1, c1b) = t1.overflowing_add((c2a || c2b) as u64);
        let (t0, c0a) = self.w0.overflowing_add(rhs.w0);
        let (w0, c0b) = t0.overflowing_add((c1a || c1b) as u64);
        if c0a || c0b {
            None
        } else {
            Some(Self { w0, w1, w2, w3 })
        }
    }

    const fn saturating_add(self, rhs: Self) -> Self {
        match self.checked_add(rhs) {
            Some(v) => v,
            None => Self::MAX,
        }
    }

    const fn wrapping_sub(self, rhs: Self) -> Self {
        let (w3, b3) = self.w3.overflowing_sub(rhs.w3);
        let (t2, b2a) = self.w2.overflowing_sub(rhs.w2);
        let (w2, b2b) = t2.overflowing_sub(b3 as u64);
        let (t1, b1a) = self.w1.overflowing_sub(rhs.w1);
        let (w1, b1b) = t1.overflowing_sub((b2a || b2b) as u64);
        let (t0, _) = self.w0.overflowing_sub(rhs.w0);
        let (w0, _) = t0.overflowing_sub((b1a || b1b) as u64);
        Self { w0, w1, w2, w3 }
    }

    const fn ge(self, rhs: Self) -> bool {
        if self.w0 != rhs.w0 {
            return self.w0 > rhs.w0;
        }
        if self.w1 != rhs.w1 {
            return self.w1 > rhs.w1;
        }
        if self.w2 != rhs.w2 {
            return self.w2 > rhs.w2;
        }
        self.w3 >= rhs.w3
    }

    const fn bit_be(self, idx_from_msb: u32) -> u64 {
        let limb = match idx_from_msb / 64 {
            0 => self.w0,
            1 => self.w1,
            2 => self.w2,
            _ => self.w3,
        };
        let shift = 63 - (idx_from_msb % 64);
        (limb >> shift) & 1
    }

    const fn shl1_or(self, lsb: u64) -> (Self, bool) {
        let carry = (self.w0 >> 63) != 0;
        let w0 = (self.w0 << 1) | (self.w1 >> 63);
        let w1 = (self.w1 << 1) | (self.w2 >> 63);
        let w2 = (self.w2 << 1) | (self.w3 >> 63);
        let w3 = (self.w3 << 1) | (lsb & 1);
        (Self { w0, w1, w2, w3 }, carry)
    }

    const fn div_nonzero(self, denom: Self) -> Self {
        let mut quot = Self::ZERO;
        let mut rem = Self::ZERO;
        let mut i = 0u32;
        while i < 256 {
            let (next_rem, overflowed) = rem.shl1_or(self.bit_be(i));
            if overflowed || next_rem.ge(denom) {
                rem = next_rem.wrapping_sub(denom);
                let (nq, _) = quot.shl1_or(1);
                quot = nq;
            } else {
                rem = next_rem;
                let (nq, _) = quot.shl1_or(0);
                quot = nq;
            }
            i += 1;
        }
        quot
    }

    const fn bit_len(self) -> u32 {
        if self.w0 != 0 {
            256 - self.w0.leading_zeros()
        } else if self.w1 != 0 {
            192 - self.w1.leading_zeros()
        } else if self.w2 != 0 {
            128 - self.w2.leading_zeros()
        } else {
            64 - self.w3.leading_zeros()
        }
    }
}

const fn u64_from_be_slice(s: &[u8]) -> u64 {
    if let [b0, b1, b2, b3, b4, b5, b6, b7] = s {
        u64::from_be_bytes([*b0, *b1, *b2, *b3, *b4, *b5, *b6, *b7])
    } else {
        0
    }
}

/// Compute exact 256-bit block work `floor(2^256 / (target + 1))` via the
/// overflow-free identity `floor(~target / (target + 1)) + 1`.
///
/// WIRING: invoked by `AuxPowPopAdapter` header-chain verification.
#[must_use]
pub const fn work_from_target(target: &U256Bytes) -> U256Bytes {
    let t = U256Limbs::from_be(target);
    let Some(denom) = t.checked_add(U256Limbs::ONE) else {
        return U256Limbs::ONE.to_be();
    };
    t.bitnot()
        .div_nonzero(denom)
        .saturating_add(U256Limbs::ONE)
        .to_be()
}

/// Canonical signing root for bonded `PoP` anchor co-signatures.
#[must_use]
pub fn pop_anchor_sign_bytes(
    network: &str,
    aux_chain_id: u32,
    aux_height: u64,
    parent_hash: &Hash32,
    aux_digest: &Hash32,
) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_AUXPOW_POP_ANCHOR_V1",
        network.as_bytes(),
        &aux_chain_id.to_le_bytes(),
        &aux_height.to_le_bytes(),
        parent_hash,
        aux_digest,
    ])
}

/// Encode an [`AuxPowPopEvidence`] bundle prefixed with its 8-byte magic tag.
///
/// WIRING: used by `AuxPoW` relayers and [`crate::cross_domain::economic_guard`]
/// verification tests.
///
/// # Errors
///
/// Returns [`AdapterError::Malformed`] when serialization fails or overflows
/// the payload ceiling.
pub fn encode_auxpow_evidence(bundle: &AuxPowPopEvidence) -> Result<Vec<u8>, AdapterError> {
    let body = bincode::serialize(bundle).map_err(|e| AdapterError::Malformed {
        offset: 0,
        reason: format!("auxpow-pop encode failed: {e}"),
    })?;
    let total = PAYLOAD_MAGIC.len().saturating_add(body.len());
    if total > MAX_AUXPOW_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_AUXPOW_PAYLOAD_BYTES,
            reason: format!("auxpow-pop payload {total} exceeds {MAX_AUXPOW_PAYLOAD_BYTES}"),
        });
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_auxpow_evidence(payload: &[u8]) -> Result<AuxPowPopEvidence, AdapterError> {
    if payload.len() > MAX_AUXPOW_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_AUXPOW_PAYLOAD_BYTES,
            reason: format!(
                "auxpow-pop payload {} exceeds {MAX_AUXPOW_PAYLOAD_BYTES}",
                payload.len()
            ),
        });
    }
    let Some(magic) = payload.get(..PAYLOAD_MAGIC.len()) else {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "auxpow-pop payload truncated before 8-byte magic header".into(),
        });
    };
    if !bool::from(magic.ct_eq(PAYLOAD_MAGIC)) {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "invalid auxpow-pop payload magic header".into(),
        });
    }
    let body = payload
        .get(PAYLOAD_MAGIC.len()..)
        .ok_or_else(|| AdapterError::Malformed {
            offset: PAYLOAD_MAGIC.len(),
            reason: "missing auxpow-pop payload body".into(),
        })?;
    let decoded: AuxPowPopEvidence =
        crate::network::bounded_bincode::decode_bounded_bincode(body, MAX_AUXPOW_PAYLOAD_BYTES)
            .map_err(|e| AdapterError::Malformed {
                offset: PAYLOAD_MAGIC.len(),
                reason: format!("invalid auxpow-pop evidence body: {e}"),
            })?;
    if bincode::serialized_size(&decoded).ok() != u64::try_from(body.len()).ok() {
        return Err(AdapterError::Malformed {
            offset: PAYLOAD_MAGIC.len(),
            reason: "non-canonical trailing bytes in auxpow-pop evidence".into(),
        });
    }
    Ok(decoded)
}

fn verify_dsha256_branch(
    leaf: &Hash32,
    branch: &[Hash32],
    leaf_index: u32,
    label: &str,
) -> Result<Hash32, AdapterError> {
    if branch.len() > MAX_MERKLE_DEPTH {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "{label} Merkle branch depth {} exceeds {MAX_MERKLE_DEPTH}",
                branch.len()
            ),
        });
    }
    let mut cur = *leaf;
    let mut idx = leaf_index;
    for sibling in branch {
        if bool::from(cur.ct_eq(sibling)) {
            return Err(AdapterError::ConsensusRule {
                rule: format!("{label} contains self-paired duplicate sibling (CVE-2012-2459)"),
            });
        }
        let mut pair = [0u8; 64];
        let (first, second) = pair.split_at_mut(32);
        if (idx & 1) == 0 {
            first.copy_from_slice(&cur);
            second.copy_from_slice(sibling);
        } else {
            first.copy_from_slice(sibling);
            second.copy_from_slice(&cur);
        }
        cur = sha256d(&pair);
        idx >>= 1;
    }
    if idx != 0 {
        return Err(AdapterError::ConsensusRule {
            rule: format!("{label} index {leaf_index} exceeds 2^{}", branch.len()),
        });
    }
    Ok(cur)
}

fn extract_unique_auxpow_commitment(
    coinbase_tx: &[u8],
) -> Result<(Hash32, u32, u32), AdapterError> {
    if coinbase_tx.is_empty() || coinbase_tx.len() > MAX_COINBASE_BYTES {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "auxpow coinbase length {} outside 1..={MAX_COINBASE_BYTES}",
                coinbase_tx.len()
            ),
        });
    }
    let mut found_offset: Option<usize> = None;
    for (idx, win) in coinbase_tx.windows(AUXPOW_COINBASE_MAGIC.len()).enumerate() {
        if bool::from(win.ct_eq(&AUXPOW_COINBASE_MAGIC)) {
            if found_offset.is_some() {
                return Err(AdapterError::ConsensusRule {
                    rule: "auxpow coinbase carries multiple merged-mining magic markers".into(),
                });
            }
            found_offset = Some(idx);
        }
    }
    let Some(marker_pos) = found_offset else {
        return Err(AdapterError::ConsensusRule {
            rule: "auxpow coinbase missing merged-mining magic marker".into(),
        });
    };
    let commit_start = marker_pos.saturating_add(AUXPOW_COINBASE_MAGIC.len());
    let commit_end = commit_start.saturating_add(40);
    let Some(region) = coinbase_tx.get(commit_start..commit_end) else {
        return Err(AdapterError::ConsensusRule {
            rule: "auxpow coinbase truncated inside 40-byte aux commitment".into(),
        });
    };
    let root_slice = region
        .get(..32)
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "auxpow aux_merkle_root slice missing".into(),
        })?;
    let size_slice = region
        .get(32..36)
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "auxpow tree_size slice missing".into(),
        })?;
    let nonce_slice = region
        .get(36..40)
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "auxpow merkle_nonce slice missing".into(),
        })?;
    let aux_root: Hash32 = root_slice
        .try_into()
        .map_err(|_| AdapterError::ConsensusRule {
            rule: "auxpow aux_merkle_root length mismatch".into(),
        })?;
    let tree_size =
        u32::from_le_bytes(
            size_slice
                .try_into()
                .map_err(|_| AdapterError::ConsensusRule {
                    rule: "auxpow tree_size length mismatch".into(),
                })?,
        );
    let merkle_nonce =
        u32::from_le_bytes(
            nonce_slice
                .try_into()
                .map_err(|_| AdapterError::ConsensusRule {
                    rule: "auxpow merkle_nonce length mismatch".into(),
                })?,
        );
    Ok((aux_root, tree_size, merkle_nonce))
}

type IndexedPopSet<'a> = BTreeMap<[u8; 32], (u64, &'a [u8])>;

fn index_pop_signers(
    signers: &[PopAnchorSigner],
) -> Result<(IndexedPopSet<'_>, u128), AdapterError> {
    if signers.is_empty() || signers.len() > MAX_POP_COMMITTEE {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "auxpow PoP committee size {} outside 1..={MAX_POP_COMMITTEE}",
                signers.len()
            ),
        });
    }
    let mut by_key = BTreeMap::new();
    let mut total = 0u128;
    for signer in signers {
        if bool::from(signer.ed25519_pubkey.ct_eq(&[0u8; 32])) {
            return Err(AdapterError::ConsensusRule {
                rule: "auxpow PoP signer pubkey cannot be all-zero".into(),
            });
        }
        if signer.bond_weight == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "auxpow PoP signer bond_weight must be positive".into(),
            });
        }
        if !signer.pq_pubkey.is_empty() {
            pq::validate_public_key(SchemeId::ML_DSA_65, &signer.pq_pubkey).map_err(|_| {
                AdapterError::ConsensusRule {
                    rule: "invalid pinned ML-DSA-65 public key in auxpow PoP committee".into(),
                }
            })?;
        }
        if by_key
            .insert(
                signer.ed25519_pubkey,
                (signer.bond_weight, signer.pq_pubkey.as_slice()),
            )
            .is_some()
        {
            return Err(AdapterError::ConsensusRule {
                rule: "duplicate signer pubkey in auxpow PoP committee".into(),
            });
        }
        total = total
            .checked_add(u128::from(signer.bond_weight))
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "auxpow PoP total bond overflow".into(),
            })?;
    }
    Ok((by_key, total))
}

fn verify_pop_sig(
    ed_pk: &[u8; 32],
    pq_pk: &[u8],
    msg: &Hash32,
    sig: &PopSignature,
) -> Result<bool, AdapterError> {
    verify_signature(msg, &sig.ed25519_sig, ed_pk).map_err(|e| AdapterError::Crypto {
        what: format!("auxpow PoP Ed25519 verification failed: {e}"),
    })?;
    if pq_pk.is_empty() {
        if !sig.pq_sig.is_empty() {
            return Err(AdapterError::Crypto {
                what: "auxpow PoP carries unexpected ML-DSA-65 signature".into(),
            });
        }
        return Ok(false);
    }
    if sig.pq_sig.is_empty() {
        return Err(AdapterError::Crypto {
            what: "auxpow PoP missing mandatory ML-DSA-65 co-signature".into(),
        });
    }
    pq::verify(
        SchemeId::ML_DSA_65,
        pq_pk,
        msg,
        crate::crypto::ctx::CROSS_DOMAIN_V1,
        &sig.pq_sig,
    )
    .map_err(|e| AdapterError::Crypto {
        what: format!("auxpow PoP ML-DSA-65 verification failed: {e}"),
    })?;
    Ok(true)
}

const fn min_pop_supermajority(total: u128) -> u128 {
    (total.saturating_mul(2) / 3).saturating_add(1)
}

/// Verify a [`PopEquivocationProof`] against a governance-pinned `AuxPoW`/`PoP`
/// anchor configuration.
///
/// # Errors
///
/// Returns [`AdapterError`] if no `PoP` committee is pinned, both targets match,
/// any signature or mandatory PQ half fails, or no signer equivocated.
pub fn verify_pop_equivocation(
    network: &str,
    pinned: &PinnedAuxPowAnchor,
    proof: &PopEquivocationProof,
) -> Result<VerifiedPopSlash, AdapterError> {
    if pinned.aux_chain_id == 0 || proof.aux_chain_id != pinned.aux_chain_id {
        return Err(AdapterError::ConsensusRule {
            rule: "auxpow PoP equivocation aux_chain_id mismatch".into(),
        });
    }
    if proof.aux_height == 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "auxpow PoP equivocation aux_height must be positive".into(),
        });
    }
    if bool::from(proof.aux_digest_a.ct_eq(&[0u8; 32]))
        || bool::from(proof.aux_digest_b.ct_eq(&[0u8; 32]))
        || bool::from(proof.parent_hash_a.ct_eq(&[0u8; 32]))
        || bool::from(proof.parent_hash_b.ct_eq(&[0u8; 32]))
        || bool::from(proof.aux_digest_a.ct_eq(&proof.aux_digest_b))
    {
        return Err(AdapterError::ConsensusRule {
            rule: "auxpow PoP equivocation requires two distinct non-zero aux block digests".into(),
        });
    }
    let (pop_idx, _) = index_pop_signers(&pinned.pop_signers)?;
    if proof.sigs_a.is_empty()
        || proof.sigs_b.is_empty()
        || proof.sigs_a.len() > pop_idx.len()
        || proof.sigs_b.len() > pop_idx.len()
    {
        return Err(AdapterError::ConsensusRule {
            rule: "auxpow PoP equivocation signature list empty or oversized".into(),
        });
    }
    let msg_a = pop_anchor_sign_bytes(
        network,
        proof.aux_chain_id,
        proof.aux_height,
        &proof.parent_hash_a,
        &proof.aux_digest_a,
    );
    let msg_b = pop_anchor_sign_bytes(
        network,
        proof.aux_chain_id,
        proof.aux_height,
        &proof.parent_hash_b,
        &proof.aux_digest_b,
    );
    let mut set_a = BTreeSet::new();
    for sig in &proof.sigs_a {
        let Some(&(_, pq_pk)) = pop_idx.get(&sig.signer_pubkey) else {
            return Err(AdapterError::ConsensusRule {
                rule: "auxpow PoP equivocation side A references unknown signer".into(),
            });
        };
        if !set_a.insert(sig.signer_pubkey) {
            return Err(AdapterError::ConsensusRule {
                rule: "duplicate signer in auxpow PoP equivocation side A".into(),
            });
        }
        let _ = verify_pop_sig(&sig.signer_pubkey, pq_pk, &msg_a, sig)?;
    }
    let mut set_b = BTreeSet::new();
    for sig in &proof.sigs_b {
        let Some(&(_, pq_pk)) = pop_idx.get(&sig.signer_pubkey) else {
            return Err(AdapterError::ConsensusRule {
                rule: "auxpow PoP equivocation side B references unknown signer".into(),
            });
        };
        if !set_b.insert(sig.signer_pubkey) {
            return Err(AdapterError::ConsensusRule {
                rule: "duplicate signer in auxpow PoP equivocation side B".into(),
            });
        }
        let _ = verify_pop_sig(&sig.signer_pubkey, pq_pk, &msg_b, sig)?;
    }
    let offenders: Vec<[u8; 32]> = set_a.intersection(&set_b).copied().collect();
    if offenders.is_empty() {
        return Err(AdapterError::ConsensusRule {
            rule: "auxpow PoP equivocation has no overlapping offending signer".into(),
        });
    }
    let mut slashed = 0u128;
    for pk in &offenders {
        if let Some(&(bond, _)) = pop_idx.get(pk) {
            slashed = slashed.saturating_add(u128::from(bond));
        }
    }
    let cid_le = proof.aux_chain_id.to_le_bytes();
    let h_le = proof.aux_height.to_le_bytes();
    // Order conflicting (parent_hash, aux_digest) tuples canonically so a
    // swapped duplicate proof cannot produce a distinct evidence digest.
    let ((lo_parent, lo_aux), (hi_parent, hi_aux)) = if (
        proof.aux_digest_a.as_slice(),
        proof.parent_hash_a.as_slice(),
    ) <= (
        proof.aux_digest_b.as_slice(),
        proof.parent_hash_b.as_slice(),
    ) {
        (
            (&proof.parent_hash_a, &proof.aux_digest_a),
            (&proof.parent_hash_b, &proof.aux_digest_b),
        )
    } else {
        (
            (&proof.parent_hash_b, &proof.aux_digest_b),
            (&proof.parent_hash_a, &proof.aux_digest_a),
        )
    };
    let count_le = u64::try_from(offenders.len())
        .unwrap_or(u64::MAX)
        .to_le_bytes();
    let mut fields: Vec<&[u8]> = Vec::with_capacity(offenders.len().saturating_add(9));
    fields.push(b"BDLM_AUXPOW_POP_SLASH_V1");
    fields.push(network.as_bytes());
    fields.push(&cid_le);
    fields.push(&h_le);
    fields.push(lo_parent);
    fields.push(lo_aux);
    fields.push(hi_parent);
    fields.push(hi_aux);
    fields.push(&count_le);
    for pk in &offenders {
        fields.push(pk);
    }
    Ok(VerifiedPopSlash {
        evidence_digest: hash_fields_bytes(&fields),
        fault_height: proof.aux_height,
        offenders,
        slashed_bond_weight: slashed,
    })
}

/// External finality adapter for merged-mining `AuxPoW` and `PoP` anchored chains.
pub struct AuxPowPopAdapter {
    network: String,
    pinned: Option<PinnedAuxPowAnchor>,
    golden: Option<RawConsensusEvidence>,
    descriptor: AdapterDescriptor,
}

impl AuxPowPopAdapter {
    /// Construct an `AuxPowPopAdapter` bound to `network` and its pinned
    /// parent/`PoP` anchor configuration.
    #[must_use]
    pub fn new(network: impl Into<String>, pinned: Option<PinnedAuxPowAnchor>) -> Self {
        let network = network.into();
        let id = AdapterId::from_name(ADAPTER_NAME);
        let required_depth = pinned.as_ref().map_or(DEFAULT_REQUIRED_CONFIRMATIONS, |p| {
            p.min_confirmations.max(1)
        });
        let (finality_kind, trust_model) = match &pinned {
            Some(p) if !p.pop_signers.is_empty() => (
                FinalityKind::EconomicFinality,
                TrustModel::HonestMajority {
                    set_size: u64::try_from(p.pop_signers.len()).unwrap_or(u64::MAX),
                },
            ),
            _ => (FinalityKind::Probabilistic, TrustModel::Trustless),
        };
        let descriptor = AdapterDescriptor {
            id,
            name: ADAPTER_NAME.into(),
            adapter_version: ADAPTER_VERSION,
            accepted_evidence_versions: vec![EVIDENCE_VERSION],
            consensus_kind: "auxpow-pop-merged-mining".into(),
            finality_kind,
            required_depth,
            time_unit: TimeUnit::Height,
            trust_model,
        };
        Self {
            network,
            pinned,
            golden: None,
            descriptor,
        }
    }

    /// Attach a canonical golden sample for [`super::selftest::admit`].
    ///
    /// WIRING: used during permissionless adapter registration self-tests.
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }

    fn verify_inner(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<(FinalityAttestation, Option<ObservedScheme>), AdapterError> {
        if evidence.adapter != self.descriptor.id {
            return Err(AdapterError::WrongAdapter {
                expected: self.descriptor.name.clone(),
                found: hex::encode(evidence.adapter.as_bytes()),
            });
        }
        if evidence.evidence_version != EVIDENCE_VERSION {
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence.evidence_version,
                accepted: EVIDENCE_VERSION.to_string(),
            });
        }
        if evidence.network != self.network {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "auxpow-pop network mismatch: expected {}, got {}",
                    self.network, evidence.network
                ),
            });
        }
        let Some(pinned) = &self.pinned else {
            return Err(AdapterError::ConsensusRule {
                rule: "no governance-pinned auxpow-pop anchor configured".into(),
            });
        };
        if pinned.aux_chain_id == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned auxpow aux_chain_id must be positive".into(),
            });
        }
        if bool::from(pinned.trusted_parent_hash.ct_eq(&[0u8; 32])) {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned auxpow trusted_parent_hash cannot be all-zero".into(),
            });
        }
        let max_target = U256Limbs::from_be(&expand_compact_bits(pinned.max_target_bits)?);
        let min_work = U256Limbs::from_be(&pinned.min_cumulative_work);
        let pop_indexed = if pinned.pop_signers.is_empty() {
            None
        } else {
            Some(index_pop_signers(&pinned.pop_signers)?)
        };

        let decoded = decode_auxpow_evidence(&evidence.payload)?;
        let aux = &decoded.aux_block;
        if aux.aux_chain_id != pinned.aux_chain_id {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "auxpow aux_chain_id {} does not match pinned {}",
                    aux.aux_chain_id, pinned.aux_chain_id
                ),
            });
        }
        if aux.aux_height == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "auxpow aux_height must be positive".into(),
            });
        }
        if bool::from(aux.state_root.ct_eq(&[0u8; 32])) || bool::from(aux.tx_root.ct_eq(&[0u8; 32]))
        {
            return Err(AdapterError::ConsensusRule {
                rule: "auxpow state_root and tx_root must be non-zero".into(),
            });
        }
        if policy.require_declared_match {
            if evidence.declared_height != aux.aux_height {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if !bool::from(evidence.declared_root.ct_eq(&aux.state_root)) {
                return Err(AdapterError::DeclarationMismatch {
                    field: "state_root",
                });
            }
        }
        if policy.max_age > 0 {
            if aux.aux_height > policy.now {
                return Err(AdapterError::Stale {
                    age: aux.aux_height - policy.now,
                    max_age: policy.max_age,
                });
            }
            let age = policy.now - aux.aux_height;
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        let expected_aux_digest = aux.compute_digest(&self.network);
        if !bool::from(aux.digest.ct_eq(&expected_aux_digest)) {
            return Err(AdapterError::ConsensusRule {
                rule: "auxpow aux_block.digest does not match self-derived fields".into(),
            });
        }

        if decoded.parent_headers.is_empty() || decoded.parent_headers.len() > MAX_PARENT_HEADERS {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "auxpow parent_headers count {} outside 1..={MAX_PARENT_HEADERS}",
                    decoded.parent_headers.len()
                ),
            });
        }
        let confirmations = u64::try_from(decoded.parent_headers.len()).unwrap_or(u64::MAX);
        let required_depth = policy.min_depth.max(pinned.min_confirmations.max(1));
        if confirmations < required_depth {
            return Err(AdapterError::InsufficientDepth {
                observed: confirmations,
                required: required_depth,
            });
        }

        let mut expected_prev = pinned.trusted_parent_hash;
        let mut carrier_parent_hash = [0u8; 32];
        let mut carrier_merkle_root = [0u8; 32];
        let mut cumulative_work = U256Limbs::ZERO;

        for (idx, hdr) in decoded.parent_headers.iter().enumerate() {
            if hdr.len() != PARENT_HEADER_LEN {
                return Err(AdapterError::ConsensusRule {
                    rule: format!(
                        "auxpow parent header {idx} length {} != {PARENT_HEADER_LEN}",
                        hdr.len()
                    ),
                });
            }
            let prev_slice = hdr.get(4..36).ok_or_else(|| AdapterError::ConsensusRule {
                rule: "auxpow parent header prev_hash slice out of bounds".into(),
            })?;
            if !bool::from(prev_slice.ct_eq(&expected_prev)) {
                return Err(AdapterError::ConsensusRule {
                    rule: format!("auxpow parent header {idx} prev_hash breaks header chain"),
                });
            }
            let mr_slice = hdr.get(36..68).ok_or_else(|| AdapterError::ConsensusRule {
                rule: "auxpow parent header merkle_root slice out of bounds".into(),
            })?;
            let bits_slice = hdr.get(72..76).ok_or_else(|| AdapterError::ConsensusRule {
                rule: "auxpow parent header nBits slice out of bounds".into(),
            })?;
            let bits = u32::from_le_bytes(bits_slice.try_into().map_err(|_| {
                AdapterError::ConsensusRule {
                    rule: "auxpow parent header nBits width invalid".into(),
                }
            })?);
            let target_bytes = expand_compact_bits(bits)?;
            let target = U256Limbs::from_be(&target_bytes);
            if !max_target.ge(target) {
                return Err(AdapterError::ConsensusRule {
                    rule: format!(
                        "auxpow parent header {idx} target exceeds pinned max_target_bits"
                    ),
                });
            }
            let raw_hash = sha256d(hdr);
            let mut be_hash = raw_hash;
            be_hash.reverse();
            let hash_num = U256Limbs::from_be(&be_hash);
            if !target.ge(hash_num) {
                return Err(AdapterError::ConsensusRule {
                    rule: format!("auxpow parent header {idx} fails Proof-of-Work target"),
                });
            }
            let block_work = U256Limbs::from_be(&work_from_target(&target_bytes));
            cumulative_work = cumulative_work.saturating_add(block_work);
            if idx == 0 {
                carrier_parent_hash = raw_hash;
                carrier_merkle_root.copy_from_slice(mr_slice);
            }
            expected_prev = raw_hash;
        }

        if !cumulative_work.ge(min_work) {
            return Err(AdapterError::ConsensusRule {
                rule: "auxpow parent chain cumulative 256-bit work below pinned minimum".into(),
            });
        }

        if decoded.coinbase_index != 0 {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "auxpow coinbase transaction index must be 0, got {}",
                    decoded.coinbase_index
                ),
            });
        }
        let coinbase_hash = sha256d(&decoded.coinbase_tx);
        let derived_parent_mr = verify_dsha256_branch(
            &coinbase_hash,
            &decoded.coinbase_branch,
            decoded.coinbase_index,
            "auxpow coinbase",
        )?;
        if !bool::from(derived_parent_mr.ct_eq(&carrier_merkle_root)) {
            return Err(AdapterError::ConsensusRule {
                rule: "auxpow coinbase Merkle proof does not match carrier parent header".into(),
            });
        }

        let (aux_merkle_root, tree_size, merkle_nonce) =
            extract_unique_auxpow_commitment(&decoded.coinbase_tx)?;
        let aux_depth =
            u32::try_from(decoded.aux_branch.len()).map_err(|_| AdapterError::ConsensusRule {
                rule: "auxpow aux_branch depth overflows u32".into(),
            })?;
        if aux_depth > u32::try_from(MAX_MERKLE_DEPTH).unwrap_or(30) {
            return Err(AdapterError::ConsensusRule {
                rule: "auxpow aux_branch exceeds maximum depth".into(),
            });
        }
        let expected_tree_size =
            1u32.checked_shl(aux_depth)
                .ok_or_else(|| AdapterError::ConsensusRule {
                    rule: "auxpow expected tree_size shift overflow".into(),
                })?;
        if tree_size != expected_tree_size {
            return Err(AdapterError::ConsensusRule {
                rule: format!("auxpow coinbase tree_size {tree_size} does not match 2^{aux_depth}"),
            });
        }
        let want_slot = expected_auxpow_slot(pinned.aux_chain_id, merkle_nonce, aux_depth);
        if decoded.aux_slot_index != want_slot {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "auxpow slot index {} does not match deterministic chain_id slot {want_slot}",
                    decoded.aux_slot_index
                ),
            });
        }
        let derived_aux_root = verify_dsha256_branch(
            &aux.digest,
            &decoded.aux_branch,
            decoded.aux_slot_index,
            "auxpow aux-tree",
        )?;
        if !bool::from(derived_aux_root.ct_eq(&aux_merkle_root)) {
            return Err(AdapterError::ConsensusRule {
                rule: "auxpow auxiliary Merkle proof does not match coinbase aux_merkle_root"
                    .into(),
            });
        }

        let (security, observed) = match &pop_indexed {
            None => {
                if !decoded.pop_sigs.is_empty() {
                    return Err(AdapterError::ConsensusRule {
                        rule: "unexpected PoP signatures without pinned PoP committee".into(),
                    });
                }
                if policy.require_slashable {
                    return Err(AdapterError::UnslashableBacking);
                }
                (
                    SecurityBacking::Work {
                        difficulty_bits: cumulative_work.bit_len(),
                    },
                    None,
                )
            }
            Some((pop_idx, pop_total)) => {
                if decoded.pop_sigs.is_empty() || decoded.pop_sigs.len() > pop_idx.len() {
                    return Err(AdapterError::ConsensusRule {
                        rule: "auxpow PoP signature count empty or exceeds pinned committee".into(),
                    });
                }
                let pop_msg = pop_anchor_sign_bytes(
                    &self.network,
                    aux.aux_chain_id,
                    aux.aux_height,
                    &carrier_parent_hash,
                    &aux.digest,
                );
                let mut seen = BTreeSet::new();
                let mut signed_bond = 0u128;
                let mut all_pq = true;
                for sig in &decoded.pop_sigs {
                    let Some(&(bond, pq_pk)) = pop_idx.get(&sig.signer_pubkey) else {
                        return Err(AdapterError::ConsensusRule {
                            rule: "auxpow PoP signer is not in pinned committee".into(),
                        });
                    };
                    if !seen.insert(sig.signer_pubkey) {
                        return Err(AdapterError::ConsensusRule {
                            rule: "duplicate signer in auxpow PoP certificate".into(),
                        });
                    }
                    let has_pq = verify_pop_sig(&sig.signer_pubkey, pq_pk, &pop_msg, sig)?;
                    all_pq &= has_pq;
                    signed_bond = signed_bond.checked_add(u128::from(bond)).ok_or_else(|| {
                        AdapterError::ConsensusRule {
                            rule: "auxpow PoP signed bond overflow".into(),
                        }
                    })?;
                }
                let required_bond = min_pop_supermajority(*pop_total);
                if signed_bond < required_bond {
                    return Err(AdapterError::ConsensusRule {
                        rule: format!(
                            "auxpow PoP signed bond {signed_bond} below >2/3 threshold {required_bond}"
                        ),
                    });
                }
                let shift = 128u32
                    .saturating_sub(pop_total.leading_zeros())
                    .saturating_sub(64);
                let signers = u64::try_from(signed_bond >> shift).unwrap_or(u64::MAX);
                let required = u64::try_from(required_bond >> shift)
                    .unwrap_or(u64::MAX)
                    .max(1);
                let scheme = if all_pq {
                    ObservedScheme::Scheme(SchemeId::ML_DSA_65)
                } else {
                    ObservedScheme::Scheme(SchemeId::ED25519)
                };
                (
                    SecurityBacking::SignatureSet {
                        scheme,
                        signers,
                        required,
                        total_weight: *pop_total,
                        slashable: true,
                    },
                    Some(scheme),
                )
            }
        };

        let attested_event_root =
            (!bool::from(aux.event_root.ct_eq(&[0u8; 32]))).then_some(aux.event_root);
        let attestation = FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &evidence.network),
            height: aux.aux_height,
            state_root: aux.state_root,
            finalized_at: aux.aux_height,
            time_unit: TimeUnit::Height,
            security,
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
            attested_block_hash: Some(aux.digest),
            attested_event_root,
            attested_tx_root: Some(aux.tx_root),
        };
        Ok((attestation, observed))
    }
}

impl ExternalFinalityAdapter for AuxPowPopAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn has_pinned_trust_anchor(&self) -> bool {
        self.pinned.as_ref().is_some_and(|p| {
            p.aux_chain_id >= 1
                && !bool::from(p.trusted_parent_hash.ct_eq(&[0u8; 32]))
                && p.min_confirmations >= 1
                && expand_compact_bits(p.max_target_bits).is_ok()
                && (p.pop_signers.is_empty() || index_pop_signers(&p.pop_signers).is_ok())
        })
    }

    fn verify(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError> {
        self.verify_inner(evidence, policy).map(|(att, _)| att)
    }

    fn verify_observed(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
        observer: &mut dyn CryptoObserver,
    ) -> Result<FinalityAttestation, AdapterError> {
        let (att, observed) = self.verify_inner(evidence, policy)?;
        if let Some(scheme) = observed {
            observer.observe(scheme);
        }
        Ok(att)
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        const PARENT0_MERKLE_ROOT_OFFSET: usize = 208;
        let sig_tail = self
            .golden
            .as_ref()
            .map_or(32, |g| g.payload.len().saturating_sub(16));
        let flipped_chain = self
            .golden
            .as_ref()
            .and_then(|g| g.payload.get(8).copied())
            .map_or(0xFE, |b| b ^ 0xFF);
        let tail_probe = if self
            .pinned
            .as_ref()
            .is_some_and(|p| p.pop_signers.is_empty())
        {
            let flipped_mr = self
                .golden
                .as_ref()
                .and_then(|g| g.payload.get(PARENT0_MERKLE_ROOT_OFFSET).copied())
                .map_or(0xCA, |b| b ^ 0xFF);
            FaultProbe {
                name: "refuses corrupted parent coinbase merkle_root".into(),
                patch: BytePatch::InPayload {
                    offset: PARENT0_MERKLE_ROOT_OFFSET,
                    bytes: vec![flipped_mr],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            }
        } else {
            let flipped_sig = self
                .golden
                .as_ref()
                .and_then(|g| g.payload.get(sig_tail).copied())
                .map_or(0xCA, |b| b ^ 0xFF);
            FaultProbe {
                name: "refuses corrupted PoP anchor signature".into(),
                patch: BytePatch::InPayload {
                    offset: sig_tail,
                    bytes: vec![flipped_sig],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Crypto),
            }
        };
        vec![
            FaultProbe {
                name: "refuses unsupported auxpow-pop evidence version".into(),
                patch: BytePatch::EvidenceVersion { value: 99 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "refuses foreign auxpow-pop network".into(),
                patch: BytePatch::Network {
                    value: format!("{}-foreign", self.network),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses mismatched declared aux height".into(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses mismatched declared aux state root".into(),
                patch: BytePatch::DeclaredRoot { value: [0xEE; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses corrupted auxpow-pop magic header".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: vec![0xFF, 0x00],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses mutated aux_chain_id".into(),
                patch: BytePatch::InPayload {
                    offset: 8,
                    bytes: vec![flipped_chain],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            tail_probe,
            FaultProbe {
                name: "refuses truncated auxpow-pop payload".into(),
                patch: BytePatch::TruncatePayload { keep: 4 },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
        ]
    }

    fn golden_evidence(&self) -> Option<RawConsensusEvidence> {
        self.golden.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::external::bitcoin_spv::sha256d;
    use crate::cross_domain::external::selftest::admit_observed;
    use crate::cross_domain::external::spec::SecurityBacking;
    use crate::crypto::facts::{CryptoFacts, ObservedScheme, QuantumClass};
    use crate::crypto::primitives::{KeyPair, PqKeyPair};
    use crate::crypto::scheme::SchemeId;

    const NET: &str = "doge-pop-mainnet";
    // Easy regtest target: 0x207fffff => 0x7fffff * 2^(8*29), mines in 1-2 hashes.
    const EASY_BITS: u32 = 0x207f_ffff;
    const AUX_CHAIN_ID: u32 = 98;

    fn dsha_pair(left: &Hash32, right: &Hash32) -> Hash32 {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(left);
        buf[32..].copy_from_slice(right);
        sha256d(&buf)
    }

    fn mine_header(prev: Hash32, merkle_root: Hash32, ts: u32, bits: u32) -> (Vec<u8>, Hash32) {
        let target = expand_compact_bits(bits).unwrap_or_else(|_| {
            let mut t = [0u8; 32];
            t[0] = 0x7f;
            t[1] = 0xff;
            t[2] = 0xff;
            t
        });
        let mut hdr = vec![0u8; 80];
        hdr[0..4].copy_from_slice(&2i32.to_le_bytes());
        hdr[4..36].copy_from_slice(&prev);
        hdr[36..68].copy_from_slice(&merkle_root);
        hdr[68..72].copy_from_slice(&ts.to_le_bytes());
        hdr[72..76].copy_from_slice(&bits.to_le_bytes());
        for nonce in 0u32..=u32::MAX {
            hdr[76..80].copy_from_slice(&nonce.to_le_bytes());
            let raw_hash = sha256d(&hdr);
            let mut be_hash = raw_hash;
            be_hash.reverse();
            if be_hash <= target {
                return (hdr, raw_hash);
            }
        }
        panic!("easy target must mine immediately");
    }

    struct PopTestSigner {
        ed: KeyPair,
        pq: PqKeyPair,
        bond: u64,
    }

    impl PopTestSigner {
        fn new(seed: u8, bond: u64) -> Self {
            Self {
                ed: KeyPair::from_seed(&[seed; 32]).unwrap(),
                pq: PqKeyPair::generate(),
                bond,
            }
        }

        fn to_pinned(&self) -> PopAnchorSigner {
            PopAnchorSigner {
                ed25519_pubkey: self.ed.public_key_bytes(),
                bond_weight: self.bond,
                pq_pubkey: self.pq.public_key_bytes().to_vec(),
            }
        }

        fn sign(&self, msg: &Hash32) -> PopSignature {
            PopSignature {
                signer_pubkey: self.ed.public_key_bytes(),
                ed25519_sig: self.ed.sign(msg).to_vec(),
                pq_sig: self
                    .pq
                    .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, msg)
                    .unwrap(),
            }
        }
    }

    fn build_fixture() -> (
        [PopTestSigner; 4],
        PinnedAuxPowAnchor,
        AuxPowPopEvidence,
        RawConsensusEvidence,
    ) {
        let signers = [
            PopTestSigner::new(31, 400),
            PopTestSigner::new(32, 400),
            PopTestSigner::new(33, 400),
            PopTestSigner::new(34, 400),
        ];
        let mut aux_block = AuxBlockCommitment {
            aux_chain_id: AUX_CHAIN_ID,
            aux_height: 88_000,
            timestamp_secs: 1_750_100_000,
            state_root: [0x51; 32],
            tx_root: [0x52; 32],
            event_root: [0x53; 32],
            digest: [0u8; 32],
        };
        aux_block.digest = aux_block.compute_digest(NET);

        // 4-leaf aux tree (depth = 2, tree_size = 4).
        let tree_depth = 2u32;
        let tree_size = 1u32 << tree_depth;
        let merkle_nonce = 7u32;
        let slot = expected_auxpow_slot(AUX_CHAIN_ID, merkle_nonce, tree_depth);
        let mut leaves = [[0x10u8; 32], [0x20u8; 32], [0x30u8; 32], [0x40u8; 32]];
        leaves[slot as usize] = aux_block.digest;
        let sib0 = leaves[(slot ^ 1) as usize];
        let n01 = dsha_pair(&leaves[0], &leaves[1]);
        let n23 = dsha_pair(&leaves[2], &leaves[3]);
        let sib1 = if slot < 2 { n23 } else { n01 };
        let aux_merkle_root = dsha_pair(&n01, &n23);

        // Coinbase with unique AUXPOW_COINBASE_MAGIC + root + tree_size + nonce.
        let mut coinbase_tx = Vec::new();
        coinbase_tx.extend_from_slice(b"\x01\x00\x00\x00coinbase-prefix:");
        coinbase_tx.extend_from_slice(&AUXPOW_COINBASE_MAGIC);
        coinbase_tx.extend_from_slice(&aux_merkle_root);
        coinbase_tx.extend_from_slice(&tree_size.to_le_bytes());
        coinbase_tx.extend_from_slice(&merkle_nonce.to_le_bytes());
        coinbase_tx.extend_from_slice(b":suffix");

        let cb_hash = sha256d(&coinbase_tx);
        let other_tx = [0x99u8; 32];
        let parent_merkle_root = dsha_pair(&cb_hash, &other_tx);

        let trusted_parent_hash = [0x07u8; 32];
        let mut parent_headers = Vec::new();
        let mut prev = trusted_parent_hash;
        let mut first_parent_hash = [0u8; 32];
        for i in 0u8..6 {
            let mr = if i == 0 {
                parent_merkle_root
            } else {
                [0x60 + i; 32]
            };
            let (hdr, h) = mine_header(prev, mr, 1_750_100_000 + u32::from(i) * 60, EASY_BITS);
            if i == 0 {
                first_parent_hash = h;
            }
            parent_headers.push(hdr);
            prev = h;
        }

        let pop_msg = pop_anchor_sign_bytes(
            NET,
            AUX_CHAIN_ID,
            aux_block.aux_height,
            &first_parent_hash,
            &aux_block.digest,
        );
        let pop_sigs = signers[..3].iter().map(|s| s.sign(&pop_msg)).collect();

        // Each header at 0x207fffff contributes >= 2 units of work; require >= 12.
        let mut min_work = [0u8; 32];
        min_work[31] = 12;
        let pinned = PinnedAuxPowAnchor {
            aux_chain_id: AUX_CHAIN_ID,
            trusted_parent_hash,
            max_target_bits: EASY_BITS,
            min_cumulative_work: min_work,
            min_confirmations: 6,
            pop_signers: signers.iter().map(PopTestSigner::to_pinned).collect(),
        };
        let bundle = AuxPowPopEvidence {
            aux_block: aux_block.clone(),
            parent_headers,
            coinbase_tx,
            coinbase_index: 0,
            coinbase_branch: vec![other_tx],
            aux_slot_index: slot,
            aux_branch: vec![sib0, sib1],
            pop_sigs,
        };
        let payload = encode_auxpow_evidence(&bundle).unwrap();
        let raw = RawConsensusEvidence {
            adapter: AdapterId::from_name(ADAPTER_NAME),
            evidence_version: EVIDENCE_VERSION,
            network: NET.into(),
            declared_height: aux_block.aux_height,
            declared_root: aux_block.state_root,
            payload,
            submitter: crate::core::address::Address::from([0x22; 32]),
        };
        (signers, pinned, bundle, raw)
    }

    #[test]
    fn auxpow_pop_admits_all_fault_probes_and_verifies_u256_work_and_slot() {
        let (_, pinned, _, raw) = build_fixture();
        let adapter = AuxPowPopAdapter::new(NET, Some(pinned)).with_golden(raw.clone());
        let policy = VerificationPolicy {
            min_depth: 6,
            max_age: 1_000,
            now: 88_100,
            require_declared_match: true,
            require_slashable: true,
        };
        let mut facts = CryptoFacts::new();
        let att = adapter
            .verify_observed(&raw, &policy, &mut facts)
            .expect("valid AuxPoW + PoP bundle verifies");
        assert_eq!(att.height, 88_000);
        assert_eq!(att.state_root, [0x51; 32]);
        assert_eq!(att.attested_event_root, Some([0x53; 32]));
        assert_eq!(facts.quantum_class(), Some(QuantumClass::Lattice));
        assert!(matches!(
            att.security,
            SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Scheme(SchemeId::ML_DSA_65),
                total_weight: 1_600,
                slashable: true,
                ..
            }
        ));

        let (report, _) = admit_observed(&adapter, &policy);
        assert!(report.admitted, "auxpow selftest must pass: {report:?}");

        crate::domain::finality_proof_model::FinalityProofShape::from_external_attestation(
            &adapter.descriptor(),
            &att,
        )
        .expect("stake-weighted PoP attestation must satisfy FinalityProofShape");
        let mut future_policy = policy.clone();
        future_policy.max_age = 1_000;
        future_policy.now = att.height.saturating_sub(1);
        assert!(
            matches!(
                adapter.verify(&raw, &future_policy),
                Err(AdapterError::Stale { .. })
            ),
            "future-dated aux_height above policy.now must fail closed when max_age > 0"
        );
    }

    #[test]
    fn auxpow_pop_refuses_wrong_slot_duplicate_magic_cve_2012_2459_and_insufficient_work_forgery() {
        let (_, pinned, bundle, raw) = build_fixture();
        let adapter = AuxPowPopAdapter::new(NET, Some(pinned.clone()));
        let policy = VerificationPolicy::strict(88_100);

        // 1. Wrong deterministic chain_id slot fails closed.
        let mut wrong_slot = bundle.clone();
        wrong_slot.aux_slot_index ^= 1;
        let mut r = raw.clone();
        r.payload = encode_auxpow_evidence(&wrong_slot).unwrap();
        assert!(adapter.verify(&r, &policy).is_err());

        // 2. Duplicate AUXPOW_COINBASE_MAGIC inside coinbase fails closed.
        let mut dup_magic = bundle.clone();
        dup_magic
            .coinbase_tx
            .extend_from_slice(&AUXPOW_COINBASE_MAGIC);
        r.payload = encode_auxpow_evidence(&dup_magic).unwrap();
        assert!(adapter.verify(&r, &policy).is_err());

        // 3. CVE-2012-2459 duplicate self-sibling in coinbase branch fails closed.
        let mut dup_sib = bundle.clone();
        let cb_hash = sha256d(&dup_sib.coinbase_tx);
        dup_sib.coinbase_branch = vec![cb_hash];
        let dup_root = dsha_pair(&cb_hash, &cb_hash);
        let (h0, _) = mine_header(
            pinned.trusted_parent_hash,
            dup_root,
            1_750_100_000,
            EASY_BITS,
        );
        dup_sib.parent_headers[0] = h0;
        r.payload = encode_auxpow_evidence(&dup_sib).unwrap();
        let derr = adapter
            .verify(&r, &policy)
            .expect_err("CVE-2012-2459 self-paired sibling must be refused");
        assert!(
            matches!(derr, AdapterError::ConsensusRule { .. }),
            "{derr:?}"
        );

        // 4. Cumulative work below min_cumulative_work fails closed.
        let mut high_work = pinned;
        high_work.min_cumulative_work[30] = 1; // 256 > ~12
        let strict = AuxPowPopAdapter::new(NET, Some(high_work));
        let werr = strict
            .verify(&raw, &policy)
            .expect_err("insufficient cumulative 256-bit work must fail closed");
        assert!(
            matches!(werr, AdapterError::ConsensusRule { .. }),
            "{werr:?}"
        );

        // 5. Negative or zero compact nBits refused.
        assert!(expand_compact_bits(0).is_err());
        assert!(expand_compact_bits(0x1d80_ffff).is_err());
    }

    #[test]
    fn auxpow_pop_equivocation_slashes_double_anchor_and_refuses_identical_or_forged() {
        let (signers, pinned, _, _) = build_fixture();
        let pa = [0xAA; 32];
        let pb = [0xBB; 32];
        let da = [0x11; 32];
        let db = [0x22; 32];
        let ma = pop_anchor_sign_bytes(NET, AUX_CHAIN_ID, 88_000, &pa, &da);
        let mb = pop_anchor_sign_bytes(NET, AUX_CHAIN_ID, 88_000, &pb, &db);

        let proof = PopEquivocationProof {
            aux_chain_id: AUX_CHAIN_ID,
            aux_height: 88_000,
            parent_hash_a: pa,
            aux_digest_a: da,
            sigs_a: vec![signers[0].sign(&ma), signers[3].sign(&ma)],
            parent_hash_b: pb,
            aux_digest_b: db,
            sigs_b: vec![signers[3].sign(&mb)],
        };
        let res = verify_pop_equivocation(NET, &pinned, &proof)
            .expect("double-anchoring PoP signer must be slashed");
        assert_eq!(res.fault_height, 88_000);
        assert_eq!(res.offenders, vec![signers[3].ed.public_key_bytes()]);
        assert_eq!(res.slashed_bond_weight, 400);

        let same = PopEquivocationProof {
            aux_digest_b: da,
            parent_hash_b: pa,
            sigs_b: vec![signers[3].sign(&ma)],
            ..proof
        };
        assert!(verify_pop_equivocation(NET, &pinned, &same).is_err());
    }

    /// STRX consistency gate: on the **non-PoP Work** path (no pinned PoP
    /// committee, no bonded signature set) a caller that demands slashable
    /// backing is refused with the same `UnslashableBacking` red meaning as
    /// every other work-weighted adapter. AuxPoW+PoP without a local Budlum
    /// confiscation arm is accumulated PoW work, so `require_slashable = true`
    /// must fail closed here, locking the STRX-194-01 red meaning across the
    /// Work adapter family so a direct caller cannot read `Work` as if it were
    /// a bonded signature set.
    #[test]
    fn auxpow_pop_work_path_require_slashable_refuses_unslashable_backing() {
        // Build the standard (PoP-pinned) fixture, then strip the PoP
        // committee and its signatures to exercise the pure Work path.
        let (_signers, mut pinned, mut bundle, _raw) = build_fixture();
        pinned.pop_signers.clear();
        bundle.pop_sigs.clear();
        let payload = encode_auxpow_evidence(&bundle).expect("work-only bundle encodes");
        let raw = RawConsensusEvidence {
            adapter: AdapterId::from_name(ADAPTER_NAME),
            evidence_version: EVIDENCE_VERSION,
            network: NET.into(),
            declared_height: bundle.aux_block.aux_height,
            declared_root: bundle.aux_block.state_root,
            payload,
            submitter: crate::core::address::Address::from([0x22; 32]),
        };
        let adapter = AuxPowPopAdapter::new(NET, Some(pinned)).with_golden(raw.clone());
        let policy = VerificationPolicy {
            min_depth: 6,
            max_age: 1_000,
            now: 88_100,
            require_declared_match: true,
            require_slashable: true,
        };
        assert!(
            matches!(
                adapter.verify(&raw, &policy),
                Err(AdapterError::UnslashableBacking)
            ),
            "require_slashable=true must fail closed with UnslashableBacking on the Work path"
        );

        // Sanity: the same work-only evidence verifies when slashability is
        // not demanded, and reports Work (not a slashable signature set).
        let mut work_policy = policy;
        work_policy.require_slashable = false;
        let att = adapter
            .verify(&raw, &work_policy)
            .expect("work-only AuxPoW verifies when slashability is not required");
        assert!(
            matches!(att.security, SecurityBacking::Work { .. }),
            "the non-PoP path must report Work backing, not a bonded signature set"
        );
    }
}
