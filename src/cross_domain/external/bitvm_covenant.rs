//! `BitVM2` / `DisproveScript` optimistic-ZK `PoW` covenant finality adapter
//! and `1-of-N` single-step fraud verifier.
//!
//! Bridges Nakamoto-style cumulative Proof-of-Work chains (which have no native
//! expressive ZK verifier opcode) into Budlum's universal settlement model via
//! a bonded operator claim, SPV covenant inclusion, a mandatory `PoW` challenge
//! maturity window, and deterministic single-step `DisproveScript` refutation:
//!
//! 1. **Pinned `PoW` & Program Anchor ([`PinnedBitVmAnchor`]):** Governance pins
//!    the `PoW` checkpoint `(height, block_hash, bits)`, the verified guest
//!    `program_hash`, minimum `PoW` confirmations (`>= 6`), minimum challenge
//!    maturity (`challenge_blocks >= 1`), and the bonded operator's hybrid
//!    `Ed25519` + FIPS 204 `ML-DSA-65` public keys.
//! 2. **Contiguous 80-Byte `PoW` Header Chain & SPV Inclusion:** Evidence carries
//!    contiguous 80-byte `PoW` headers building directly on `anchor.block_hash`,
//!    checked against compact `nBits` work target (`sha256d(hdr) <= target`),
//!    monotonically non-decreasing timestamps, and a Bitcoin `sha256d` Merkle
//!    branch proving the 96-byte covenant commitment transaction (immune to
//!    64-byte inner-node ambiguity) is included in the claim block header at
//!    `claim_header_index`.
//! 3. **Challenge-Window Maturity:** The `PoW` tip must bury the claim header by
//!    at least `anchor.challenge_blocks` blocks AND reach at least
//!    `anchor.min_pow_confirmations` blocks above the pinned anchor, ensuring
//!    any `1-of-N` honest watcher had full `PoW` horizon to broadcast a
//!    `DisproveScript` transaction before Budlum accepts the peg state.
//! 4. **Single-Step Fraud Refutation ([`verify_disprove_script`]):** Verifies a
//!    signed operator claim, opens the disputed trace chunk `(chunk_index,
//!    pre_state, claimed_post_state, step_opcode, step_witness)` against the
//!    claim's `trace_merkle_root`, re-executes [`evaluate_chunk_transition`],
//!    and proves fraud when `expected_post_state != claimed_post_state`.
//!
//! WIRING: re-exported by `crate::cross_domain::external`, constructible via
//! `AdapterSpec::BitVmCovenant` in `intake.rs`, and verified by `selftest::admit`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::ctx;
use crate::crypto::facts::{CryptoObserver, ObservedScheme};
use crate::crypto::scheme::SchemeId;

use super::selftest::{BytePatch, ExpectedRefusal, FaultProbe, RefusalKind};
use super::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, RawConsensusEvidence, SecurityBacking, TimeUnit, TrustModel,
    VerificationPolicy,
};

/// Canonical adapter identifier for `BitVM2` `PoW` covenant peg finality.
pub const BITVM_COVENANT_ADAPTER_NAME: &str = "bitvm2-pow-covenant-v1";

/// Domain-separation tag for operator covenant peg claims.
pub const BITVM_CLAIM_TAG: &[u8] = b"BDLM_BITVM_CLAIM_V1";

/// Domain-separation tag for `BitVM2` trace chunk Merkle leaves.
pub const BITVM_CHUNK_LEAF_TAG: &[u8] = b"BDLM_BITVM_CHUNK_V1";

/// Domain-separation tag for `BitVM2` trace Merkle internal nodes.
pub const BITVM_CHUNK_NODE_TAG: &[u8] = b"BDLM_BITVM_NODE_V1";

/// Domain-separation tag for deterministic chunk step transitions.
pub const BITVM_STEP_TRANSITION_TAG: &[u8] = b"BDLM_BITVM_STEP_V1";

const ADAPTER_VERSION: u32 = 1;
/// Canonical wire version for `BitVM2` covenant peg bundles.
pub const BITVM_EVIDENCE_VERSION: u32 = 1;
/// Exact Bitcoin-compatible block header length in bytes.
pub const POW_HEADER_LEN: usize = 80;
/// Minimum `PoW` confirmations required for cross-domain value safety.
pub const MIN_SAFE_POW_CONFIRMATIONS: u64 = 6;
const MAX_FUTURE_SECONDS: u64 = 2 * 60 * 60;
const PAYLOAD_MAGIC: &[u8; 8] = b"BDLMBV01";
const MAX_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_POW_HEADERS: usize = 2_160;
const MAX_SPV_MERKLE_DEPTH: usize = 64;
const MAX_TRACE_MERKLE_DEPTH: usize = 32;
const MAX_SIGNATURE_BYTES: usize = 8192;

/// Double-SHA256 helper matching Bitcoin header and SPV Merkle hashing.
#[must_use]
pub fn sha256d(bytes: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(bytes);
    Sha256::digest(first).into()
}

/// Governance-pinned `PoW` checkpoint, guest program hash, and bonded operator keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedBitVmAnchor {
    /// Pinned `PoW` block height.
    pub height: u64,
    /// Pinned `PoW` `sha256d` block header hash (`!= 0`).
    pub block_hash: [u8; 32],
    /// Compact difficulty target `nBits` required across the epoch window.
    pub bits: u32,
    /// Verified guest program hash whose execution trace is committed (`!= 0`).
    pub program_hash: [u8; 32],
    /// Minimum `PoW` blocks above `height` required (`>= 6`).
    pub min_pow_confirmations: u64,
    /// Minimum `PoW` blocks burying the covenant claim header (`>= 1`).
    pub challenge_blocks: u64,
    /// Bonded operator `Ed25519` verifying key (`!= 0`).
    pub operator_ed25519_pubkey: [u8; 32],
    /// Bonded operator FIPS 204 `ML-DSA-65` public key (`1952` bytes when non-empty).
    #[serde(default)]
    pub operator_pq_pubkey: Vec<u8>,
}

impl PinnedBitVmAnchor {
    /// Validate all structural, difficulty, confirmation, and key invariants.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::ConsensusRule`] on zero roots/keys, unsafe confirmation
    /// floors, invalid compact `nBits`, or malformed `ML-DSA-65` operator key.
    pub fn validate(&self) -> Result<Self, AdapterError> {
        if self.block_hash == [0u8; 32]
            || self.program_hash == [0u8; 32]
            || self.operator_ed25519_pubkey == [0u8; 32]
        {
            return Err(AdapterError::ConsensusRule {
                rule: "BitVM2 anchor carries zero block_hash, program_hash, or operator key"
                    .to_string(),
            });
        }
        if self.min_pow_confirmations < MIN_SAFE_POW_CONFIRMATIONS {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "BitVM2 min_pow_confirmations {} < {MIN_SAFE_POW_CONFIRMATIONS}",
                    self.min_pow_confirmations
                ),
            });
        }
        if self.challenge_blocks == 0 || self.challenge_blocks >= self.min_pow_confirmations {
            return Err(AdapterError::ConsensusRule {
                rule: "BitVM2 challenge_blocks must be in 1..min_pow_confirmations".to_string(),
            });
        }
        if expand_compact_bits(self.bits).is_none() {
            return Err(AdapterError::ConsensusRule {
                rule: "BitVM2 anchor carries invalid or zero compact difficulty bits".to_string(),
            });
        }
        if !self.operator_pq_pubkey.is_empty() {
            crate::crypto::primitives::PqKeyPair::validate_public_key(&self.operator_pq_pubkey)
                .map_err(|_| AdapterError::ConsensusRule {
                    rule: "BitVM2 anchor carries malformed operator ML-DSA-65 public key"
                        .to_string(),
                })?;
        }
        Ok(self.clone())
    }
}

/// Expand Bitcoin compact `nBits` (`0xEE_MM_MM_MM`) into a big-endian 32-byte target.
#[must_use]
pub fn expand_compact_bits(bits: u32) -> Option<[u8; 32]> {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x00ff_ffff;
    if mantissa == 0 || (bits & 0x0080_0000) != 0 || exponent > 32 {
        return None;
    }
    let m_bytes = [
        ((mantissa >> 16) & 0xff) as u8,
        ((mantissa >> 8) & 0xff) as u8,
        (mantissa & 0xff) as u8,
    ];
    let mut target = [0u8; 32];
    if exponent <= 3 {
        let shift = 3 - exponent;
        let shifted = mantissa >> (8 * shift);
        if shifted == 0 {
            return None;
        }
        if let Some(tail) = target.get_mut(29..32) {
            tail.copy_from_slice(&[
                ((shifted >> 16) & 0xff) as u8,
                ((shifted >> 8) & 0xff) as u8,
                (shifted & 0xff) as u8,
            ]);
        }
    } else {
        let start = 32 - exponent;
        let slot = target.get_mut(start..start + 3)?;
        slot.copy_from_slice(&m_bytes);
    }
    Some(target)
}

/// Leading-zero target bits plus `floor(log2(confirmations))` cumulative work
/// exposed through [`SecurityBacking::Work`].
#[must_use]
pub fn cumulative_difficulty_bits(bits: u32, confirmations: u64) -> u32 {
    let Some(target) = expand_compact_bits(bits) else {
        return 0;
    };
    let mut leading = 0u32;
    for byte in target {
        if byte == 0 {
            leading += 8;
        } else {
            leading += byte.leading_zeros();
            break;
        }
    }
    let extra = if confirmations > 1 {
        confirmations.ilog2()
    } else {
        0
    };
    leading.saturating_add(extra)
}

/// One step in a binary Merkle inclusion branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleStep {
    /// Sibling node digest (`!= 0`).
    pub sibling: [u8; 32],
    /// `true` when `sibling` is the left child and the running hash is the right child.
    pub sibling_is_left: bool,
}

/// Signed operator covenant peg claim anchored into the `PoW` chain via SPV.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitVmPegClaim {
    /// Post-execution L2/peg state root (`!= 0`).
    pub state_root: [u8; 32],
    /// Executed transaction root (`!= 0`).
    pub tx_root: [u8; 32],
    /// Emitted bridge event root (`!= 0`).
    pub event_root: [u8; 32],
    /// Guest program hash (`must equal anchor.program_hash`).
    pub program_hash: [u8; 32],
    /// Merkle root over the execution trace chunks (`!= 0`).
    pub trace_merkle_root: [u8; 32],
    /// Total execution trace chunk count (`> 0`).
    pub trace_chunk_count: u32,
    /// `PoW` block height containing the covenant commitment transaction.
    pub claim_pow_height: u64,
    /// Operator `Ed25519` signature over [`Self::signing_digest`].
    pub operator_ed25519_sig: Vec<u8>,
    /// Operator `ML-DSA-65` co-signature over [`Self::signing_digest`].
    #[serde(default)]
    pub operator_pq_sig: Vec<u8>,
}

impl BitVmPegClaim {
    /// Network-bound digest signed by the bonded operator and committed into the
    /// covenant transaction script leaf.
    #[must_use]
    pub fn signing_digest(&self, network: &str) -> [u8; 32] {
        let chunks_le = self.trace_chunk_count.to_le_bytes();
        let height_le = self.claim_pow_height.to_le_bytes();
        crate::core::hash::hash_fields_bytes(&[
            BITVM_CLAIM_TAG,
            network.as_bytes(),
            &self.state_root,
            &self.tx_root,
            &self.event_root,
            &self.program_hash,
            &self.trace_merkle_root,
            &chunks_le,
            &height_le,
        ])
    }

    /// Canonical stripped 96-byte covenant transaction payload (`!= 64` bytes to
    /// remain immune to 64-byte inner-node ambiguity) whose `sha256d` is the
    /// transaction ID proven under the claim header's `merkle_root`.
    #[must_use]
    pub fn covenant_tx_bytes(&self, network: &str) -> [u8; 96] {
        let mut tx = [0u8; 96];
        let (ver_slot, rest) = tx.split_at_mut(4);
        ver_slot.copy_from_slice(&2u32.to_le_bytes());
        let (sig_slot, rest) = rest.split_at_mut(32);
        sig_slot.copy_from_slice(&self.signing_digest(network));
        let (trace_slot, rest) = rest.split_at_mut(32);
        trace_slot.copy_from_slice(&self.trace_merkle_root);
        let (state_slot, lock_slot) = rest.split_at_mut(24);
        let (state_prefix, _) = self.state_root.split_at(24);
        state_slot.copy_from_slice(state_prefix);
        lock_slot.copy_from_slice(&0u32.to_le_bytes());
        tx
    }
}

/// Complete `BitVM2` `PoW` covenant finality bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitVmCovenantEvidence {
    /// Contiguous 80-byte `PoW` headers building directly on `anchor.block_hash`.
    pub headers: Vec<[u8; POW_HEADER_LEN]>,
    /// 0-based index into `headers` where the covenant commitment tx was mined.
    pub claim_header_index: u32,
    /// Bitcoin `sha256d` Merkle inclusion path from `sha256d(covenant_tx_bytes)` to `merkle_root`.
    pub spv_merkle_proof: Vec<MerkleStep>,
    /// Operator's signed covenant peg claim.
    pub claim: BitVmPegClaim,
}

/// Single execution trace chunk committed inside `BitVmPegClaim::trace_merkle_root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceChunkStep {
    /// 0-based chunk index (`< claim.trace_chunk_count`).
    pub chunk_index: u32,
    /// Pre-chunk execution state digest (`32` bytes).
    pub pre_state: [u8; 32],
    /// Operator's claimed post-chunk execution state digest (`32` bytes).
    pub claimed_post_state: [u8; 32],
    /// Deterministic chunk transition opcode.
    pub step_opcode: u8,
    /// Witness input for this single chunk step (`32` bytes).
    pub step_witness: [u8; 32],
}

impl TraceChunkStep {
    /// Domain-separated leaf digest committed in `trace_merkle_root`.
    #[must_use]
    pub fn leaf_digest(&self) -> [u8; 32] {
        let idx_le = self.chunk_index.to_le_bytes();
        crate::core::hash::hash_fields_bytes(&[
            BITVM_CHUNK_LEAF_TAG,
            &idx_le,
            &self.pre_state,
            &self.claimed_post_state,
            &[self.step_opcode],
            &self.step_witness,
        ])
    }
}

/// Deterministic chunk step transition function evaluated identically by honest
/// operators and `DisproveScript` fraud verifiers.
#[must_use]
pub fn evaluate_chunk_transition(
    program_hash: &[u8; 32],
    chunk_index: u32,
    pre_state: &[u8; 32],
    step_opcode: u8,
    step_witness: &[u8; 32],
) -> [u8; 32] {
    let idx_le = chunk_index.to_le_bytes();
    crate::core::hash::hash_fields_bytes(&[
        BITVM_STEP_TRANSITION_TAG,
        program_hash,
        &idx_le,
        pre_state,
        &[step_opcode],
        step_witness,
    ])
}

/// Compute the parent node digest in the `BitVM2` trace Merkle tree.
#[must_use]
pub fn hash_trace_merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    crate::core::hash::hash_fields_bytes(&[BITVM_CHUNK_NODE_TAG, left, right])
}

/// Self-contained `1-of-N` single-step `DisproveScript` fraud proof refuting a
/// signed [`BitVmPegClaim`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisproveScriptProof {
    /// Signed operator peg claim being refuted.
    pub claim: BitVmPegClaim,
    /// Disputed execution trace chunk whose `claimed_post_state` diverges from deterministic execution.
    pub disputed_chunk: TraceChunkStep,
    /// Merkle opening from `disputed_chunk.leaf_digest()` to `claim.trace_merkle_root`.
    pub trace_merkle_proof: Vec<MerkleStep>,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], AdapterError> {
        let offset = self.pos;
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| AdapterError::Malformed {
                offset,
                reason: "BitVM payload length overflow".to_string(),
            })?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| AdapterError::Malformed {
                offset,
                reason: "truncated BitVM payload".to_string(),
            })?;
        self.pos = end;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, AdapterError> {
        let offset = self.pos;
        let b = self.take(1)?;
        b.first().copied().ok_or_else(|| AdapterError::Malformed {
            offset,
            reason: "truncated u8".to_string(),
        })
    }

    fn read_u32(&mut self) -> Result<u32, AdapterError> {
        let mut arr = [0u8; 4];
        arr.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(arr))
    }

    fn read_u64(&mut self) -> Result<u64, AdapterError> {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(arr))
    }

    fn read_32(&mut self) -> Result<[u8; 32], AdapterError> {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(self.take(32)?);
        Ok(arr)
    }

    fn read_header(&mut self) -> Result<[u8; POW_HEADER_LEN], AdapterError> {
        let mut arr = [0u8; POW_HEADER_LEN];
        arr.copy_from_slice(self.take(POW_HEADER_LEN)?);
        Ok(arr)
    }

    fn read_sig(&mut self) -> Result<Vec<u8>, AdapterError> {
        let offset = self.pos;
        let len = self.read_u32()? as usize;
        if len > MAX_SIGNATURE_BYTES {
            return Err(AdapterError::Malformed {
                offset,
                reason: "BitVM signature exceeds bound".to_string(),
            });
        }
        Ok(self.take(len)?.to_vec())
    }
}

/// Encode [`BitVmCovenantEvidence`] into canonical wire bytes.
#[must_use]
pub fn encode_bitvm_evidence(ev: &BitVmCovenantEvidence) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&BITVM_EVIDENCE_VERSION.to_le_bytes());
    out.extend_from_slice(
        &u32::try_from(ev.headers.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    for h in &ev.headers {
        out.extend_from_slice(h);
    }
    out.extend_from_slice(&ev.claim_header_index.to_le_bytes());
    out.extend_from_slice(
        &u32::try_from(ev.spv_merkle_proof.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    for step in &ev.spv_merkle_proof {
        out.extend_from_slice(&step.sibling);
        out.push(u8::from(step.sibling_is_left));
    }
    out.extend_from_slice(&ev.claim.state_root);
    out.extend_from_slice(&ev.claim.tx_root);
    out.extend_from_slice(&ev.claim.event_root);
    out.extend_from_slice(&ev.claim.program_hash);
    out.extend_from_slice(&ev.claim.trace_merkle_root);
    out.extend_from_slice(&ev.claim.trace_chunk_count.to_le_bytes());
    out.extend_from_slice(&ev.claim.claim_pow_height.to_le_bytes());
    out.extend_from_slice(
        &u32::try_from(ev.claim.operator_ed25519_sig.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    out.extend_from_slice(&ev.claim.operator_ed25519_sig);
    out.extend_from_slice(
        &u32::try_from(ev.claim.operator_pq_sig.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    out.extend_from_slice(&ev.claim.operator_pq_sig);
    out
}

/// Decode canonical wire bytes into [`BitVmCovenantEvidence`].
///
/// # Errors
///
/// Returns [`AdapterError`] on bad magic, unsupported version, oversized chains
/// or branches, trailing bytes, or truncated reads.
pub fn decode_bitvm_evidence(payload: &[u8]) -> Result<BitVmCovenantEvidence, AdapterError> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "BitVM payload exceeds 512 KiB".to_string(),
        });
    }
    let mut c = Cursor::new(payload);
    if c.take(PAYLOAD_MAGIC.len())? != PAYLOAD_MAGIC {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "bad BitVM payload magic".to_string(),
        });
    }
    let version = c.read_u32()?;
    if version != BITVM_EVIDENCE_VERSION {
        return Err(AdapterError::UnsupportedEvidenceVersion {
            version,
            accepted: BITVM_EVIDENCE_VERSION.to_string(),
        });
    }
    let header_count = c.read_u32()? as usize;
    if header_count == 0 || header_count > MAX_POW_HEADERS {
        return Err(AdapterError::ConsensusRule {
            rule: "BitVM PoW header count out of bounds".to_string(),
        });
    }
    let mut headers = Vec::with_capacity(header_count);
    for _ in 0..header_count {
        headers.push(c.read_header()?);
    }
    let claim_header_index = c.read_u32()?;
    let proof_len = c.read_u32()? as usize;
    if proof_len > MAX_SPV_MERKLE_DEPTH {
        return Err(AdapterError::ConsensusRule {
            rule: "BitVM SPV Merkle proof exceeds max depth".to_string(),
        });
    }
    let mut spv_merkle_proof = Vec::with_capacity(proof_len);
    for _ in 0..proof_len {
        let sibling = c.read_32()?;
        let dir_offset = c.pos;
        let dir = c.read_u8()?;
        if dir > 1 {
            return Err(AdapterError::Malformed {
                offset: dir_offset,
                reason: "non-boolean SPV Merkle direction byte".to_string(),
            });
        }
        spv_merkle_proof.push(MerkleStep {
            sibling,
            sibling_is_left: dir == 1,
        });
    }
    let claim = BitVmPegClaim {
        state_root: c.read_32()?,
        tx_root: c.read_32()?,
        event_root: c.read_32()?,
        program_hash: c.read_32()?,
        trace_merkle_root: c.read_32()?,
        trace_chunk_count: c.read_u32()?,
        claim_pow_height: c.read_u64()?,
        operator_ed25519_sig: c.read_sig()?,
        operator_pq_sig: c.read_sig()?,
    };
    if c.pos != payload.len() {
        return Err(AdapterError::Malformed {
            offset: c.pos,
            reason: "BitVM payload carries trailing bytes".to_string(),
        });
    }
    Ok(BitVmCovenantEvidence {
        headers,
        claim_header_index,
        spv_merkle_proof,
        claim,
    })
}

fn header_prev_hash(hdr: &[u8; POW_HEADER_LEN]) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Some(s) = hdr.get(4..36) {
        out.copy_from_slice(s);
    }
    out
}

fn header_merkle_root(hdr: &[u8; POW_HEADER_LEN]) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Some(s) = hdr.get(36..68) {
        out.copy_from_slice(s);
    }
    out
}

fn header_timestamp(hdr: &[u8; POW_HEADER_LEN]) -> u32 {
    let mut b = [0u8; 4];
    if let Some(s) = hdr.get(68..72) {
        b.copy_from_slice(s);
    }
    u32::from_le_bytes(b)
}

fn header_bits(hdr: &[u8; POW_HEADER_LEN]) -> u32 {
    let mut b = [0u8; 4];
    if let Some(s) = hdr.get(72..76) {
        b.copy_from_slice(s);
    }
    u32::from_le_bytes(b)
}

fn verify_operator_claim_signature(
    network: &str,
    anchor: &PinnedBitVmAnchor,
    claim: &BitVmPegClaim,
) -> Result<bool, AdapterError> {
    if claim.state_root == [0u8; 32]
        || claim.tx_root == [0u8; 32]
        || claim.event_root == [0u8; 32]
        || claim.trace_merkle_root == [0u8; 32]
        || claim.trace_chunk_count == 0
    {
        return Err(AdapterError::ConsensusRule {
            rule: "BitVM2 peg claim has unset root or zero trace_chunk_count".to_string(),
        });
    }
    if claim.program_hash != anchor.program_hash {
        return Err(AdapterError::ConsensusRule {
            rule: "BitVM2 peg claim program_hash does not match pinned guest program".to_string(),
        });
    }
    let digest = claim.signing_digest(network);
    crate::crypto::primitives::verify_signature(
        &digest,
        &claim.operator_ed25519_sig,
        &anchor.operator_ed25519_pubkey,
    )
    .map_err(|_| AdapterError::Crypto {
        what: "invalid BitVM2 operator Ed25519 claim signature".to_string(),
    })?;
    if anchor.operator_pq_pubkey.is_empty() {
        Ok(false)
    } else {
        if claim.operator_pq_sig.is_empty() {
            return Err(AdapterError::Crypto {
                what: "missing BitVM2 operator ML-DSA-65 co-signature".to_string(),
            });
        }
        crate::crypto::primitives::PqKeyPair::verify(
            &anchor.operator_pq_pubkey,
            ctx::CROSS_DOMAIN_V1,
            &digest,
            &claim.operator_pq_sig,
        )
        .map_err(|_| AdapterError::Crypto {
            what: "invalid BitVM2 operator ML-DSA-65 co-signature".to_string(),
        })?;
        Ok(true)
    }
}

/// Verify Bitcoin `sha256d` SPV Merkle inclusion, refusing CVE-2012-2459 equal-sibling
/// malleability on right-child or leftmost steps.
fn verify_spv_merkle_inclusion(
    txid: [u8; 32],
    proof: &[MerkleStep],
    expected_merkle_root: [u8; 32],
) -> Result<(), AdapterError> {
    if proof.len() > MAX_SPV_MERKLE_DEPTH {
        return Err(AdapterError::ConsensusRule {
            rule: "BitVM2 SPV Merkle branch exceeds depth ceiling".to_string(),
        });
    }
    let mut current = txid;
    for step in proof {
        if step.sibling == [0u8; 32] {
            return Err(AdapterError::ConsensusRule {
                rule: "BitVM2 SPV Merkle sibling is zero".to_string(),
            });
        }
        if step.sibling == current {
            return Err(AdapterError::ConsensusRule {
                rule: "BitVM2 SPV Merkle branch hits CVE-2012-2459 equal-sibling malleability"
                    .to_string(),
            });
        }
        let mut pair = [0u8; 64];
        let (left_slot, right_slot) = pair.split_at_mut(32);
        if step.sibling_is_left {
            left_slot.copy_from_slice(&step.sibling);
            right_slot.copy_from_slice(&current);
        } else {
            left_slot.copy_from_slice(&current);
            right_slot.copy_from_slice(&step.sibling);
        }
        current = sha256d(&pair);
    }
    if current != expected_merkle_root {
        return Err(AdapterError::ConsensusRule {
            rule: "BitVM2 covenant transaction SPV Merkle root mismatch".to_string(),
        });
    }
    Ok(())
}

const fn expected_trace_merkle_depth(chunk_count: u32) -> usize {
    if chunk_count <= 1 {
        0
    } else {
        ((chunk_count - 1).ilog2() + 1) as usize
    }
}

/// Verify a `1-of-N` [`DisproveScriptProof`] against a [`PinnedBitVmAnchor`].
///
/// Returns `(chunk_index, expected_post_state, claimed_post_state)` when fraud holds.
///
/// # Errors
///
/// Returns [`AdapterError`] if the anchor or operator signature is invalid, the
/// chunk index or Merkle opening fails, or the chunk transition is honest.
pub fn verify_disprove_script(
    network: &str,
    anchor: &PinnedBitVmAnchor,
    proof: &DisproveScriptProof,
) -> Result<(u32, [u8; 32], [u8; 32]), AdapterError> {
    let validated = anchor.validate()?;
    let _ = verify_operator_claim_signature(network, &validated, &proof.claim)?;

    if proof.claim.claim_pow_height <= validated.height {
        return Err(AdapterError::ConsensusRule {
            rule: "DisproveScript claim_pow_height is not strictly above pinned anchor height"
                .to_string(),
        });
    }
    if proof.disputed_chunk.chunk_index >= proof.claim.trace_chunk_count {
        return Err(AdapterError::ConsensusRule {
            rule: "DisproveScript chunk_index >= claim.trace_chunk_count".to_string(),
        });
    }
    let expected_depth = expected_trace_merkle_depth(proof.claim.trace_chunk_count);
    if expected_depth > MAX_TRACE_MERKLE_DEPTH || proof.trace_merkle_proof.len() != expected_depth {
        return Err(AdapterError::ConsensusRule {
            rule: "DisproveScript trace Merkle branch depth does not match canonical trace_chunk_count depth".to_string(),
        });
    }
    let mut current = proof.disputed_chunk.leaf_digest();
    for (level, step) in proof.trace_merkle_proof.iter().enumerate() {
        if step.sibling == [0u8; 32] || step.sibling == current {
            return Err(AdapterError::ConsensusRule {
                rule: "DisproveScript trace Merkle sibling is zero or duplicates current node"
                    .to_string(),
            });
        }
        let shift = u32::try_from(level).unwrap_or(u32::BITS - 1);
        let expected_sibling_is_left = ((proof.disputed_chunk.chunk_index >> shift) & 1) == 1;
        if step.sibling_is_left != expected_sibling_is_left {
            return Err(AdapterError::ConsensusRule {
                rule: "DisproveScript trace Merkle direction bit disagrees with chunk_index"
                    .to_string(),
            });
        }
        current = if step.sibling_is_left {
            hash_trace_merkle_node(&step.sibling, &current)
        } else {
            hash_trace_merkle_node(&current, &step.sibling)
        };
    }
    if current != proof.claim.trace_merkle_root {
        return Err(AdapterError::ConsensusRule {
            rule: "DisproveScript chunk leaf does not open to claim.trace_merkle_root".to_string(),
        });
    }
    let expected = evaluate_chunk_transition(
        &validated.program_hash,
        proof.disputed_chunk.chunk_index,
        &proof.disputed_chunk.pre_state,
        proof.disputed_chunk.step_opcode,
        &proof.disputed_chunk.step_witness,
    );
    if expected == proof.disputed_chunk.claimed_post_state {
        return Err(AdapterError::ConsensusRule {
            rule: "DisproveScript chunk transition is honest; no fraud proven".to_string(),
        });
    }
    Ok((
        proof.disputed_chunk.chunk_index,
        expected,
        proof.disputed_chunk.claimed_post_state,
    ))
}

/// External finality adapter for `BitVM2` `PoW` covenant peg claims.
pub struct BitVmCovenantAdapter {
    descriptor: AdapterDescriptor,
    network: String,
    anchor: Option<PinnedBitVmAnchor>,
    golden: Option<RawConsensusEvidence>,
}

impl BitVmCovenantAdapter {
    /// Construct a `BitVM2` covenant adapter over an optional pinned anchor.
    #[must_use]
    pub fn new(network: &str, anchor: Option<PinnedBitVmAnchor>) -> Self {
        let validated = anchor.and_then(|a| a.validate().ok());
        let required_depth = validated
            .as_ref()
            .map_or(MIN_SAFE_POW_CONFIRMATIONS, |a| a.min_pow_confirmations);
        let id = AdapterId::from_name(BITVM_COVENANT_ADAPTER_NAME);
        let descriptor = AdapterDescriptor {
            id,
            name: BITVM_COVENANT_ADAPTER_NAME.to_string(),
            adapter_version: ADAPTER_VERSION,
            accepted_evidence_versions: vec![BITVM_EVIDENCE_VERSION],
            consensus_kind: "bitvm2-pow-covenant".to_string(),
            finality_kind: FinalityKind::Probabilistic,
            required_depth,
            time_unit: TimeUnit::UnixSeconds,
            trust_model: TrustModel::Trustless,
        };
        Self {
            descriptor,
            network: network.to_string(),
            anchor: validated,
            golden: None,
        }
    }

    /// Attach a golden sample for `selftest::admit`.
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }

    fn verify_chain_and_claim(
        &self,
        evidence: &RawConsensusEvidence,
    ) -> Result<
        (
            &PinnedBitVmAnchor,
            BitVmCovenantEvidence,
            [u8; 32],
            u64,
            bool,
        ),
        AdapterError,
    > {
        let anchor = self
            .anchor
            .as_ref()
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "BitVM2 covenant adapter has no valid pinned anchor".to_string(),
            })?;
        let target =
            expand_compact_bits(anchor.bits).ok_or_else(|| AdapterError::ConsensusRule {
                rule: "BitVM2 anchor compact bits failed target expansion".to_string(),
            })?;
        let parsed = decode_bitvm_evidence(&evidence.payload)?;
        let header_count = parsed.headers.len() as u64;
        if header_count < anchor.min_pow_confirmations {
            return Err(AdapterError::InsufficientDepth {
                observed: header_count,
                required: anchor.min_pow_confirmations,
            });
        }
        let claim_idx = parsed.claim_header_index as usize;
        if claim_idx >= parsed.headers.len() {
            return Err(AdapterError::ConsensusRule {
                rule: "BitVM2 claim_header_index exceeds header chain length".to_string(),
            });
        }
        let bury_blocks = (parsed.headers.len() - 1 - claim_idx) as u64;
        if bury_blocks < anchor.challenge_blocks {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "BitVM2 claim buried by {bury_blocks} blocks < challenge_blocks {}",
                    anchor.challenge_blocks
                ),
            });
        }

        let mut expected_prev = anchor.block_hash;
        let mut prev_time = 0u32;
        let mut parent_of_claim = anchor.block_hash;
        for (idx, hdr) in parsed.headers.iter().enumerate() {
            if idx == claim_idx {
                parent_of_claim = expected_prev;
            }
            if header_prev_hash(hdr) != expected_prev {
                return Err(AdapterError::ConsensusRule {
                    rule: format!("BitVM2 PoW header {idx} prev_hash breaks chain continuity"),
                });
            }
            if header_bits(hdr) != anchor.bits {
                return Err(AdapterError::ConsensusRule {
                    rule: format!("BitVM2 PoW header {idx} nBits diverges from pinned epoch bits"),
                });
            }
            let ts = header_timestamp(hdr);
            if ts == 0 {
                return Err(AdapterError::ConsensusRule {
                    rule: format!("BitVM2 PoW header {idx} has zero timestamp"),
                });
            }
            if idx > 0 && ts < prev_time {
                return Err(AdapterError::ConsensusRule {
                    rule: format!("BitVM2 PoW header {idx} timestamp regresses"),
                });
            }
            prev_time = ts;
            let raw_pow_hash = sha256d(hdr);
            let mut big_endian_pow = raw_pow_hash;
            big_endian_pow.reverse();
            if big_endian_pow > target {
                return Err(AdapterError::ConsensusRule {
                    rule: format!("BitVM2 PoW header {idx} fails compact target PoW inequality"),
                });
            }
            expected_prev = raw_pow_hash;
        }

        let expected_claim_height = anchor
            .height
            .checked_add((claim_idx as u64) + 1)
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "BitVM2 claim_pow_height overflow".to_string(),
            })?;
        if parsed.claim.claim_pow_height != expected_claim_height {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "BitVM2 claim_pow_height {} != derived height {expected_claim_height}",
                    parsed.claim.claim_pow_height
                ),
            });
        }

        let used_pq = verify_operator_claim_signature(&self.network, anchor, &parsed.claim)?;
        let covenant_tx = parsed.claim.covenant_tx_bytes(&self.network);
        let txid = sha256d(&covenant_tx);
        let claim_hdr =
            parsed
                .headers
                .get(claim_idx)
                .ok_or_else(|| AdapterError::ConsensusRule {
                    rule: "BitVM2 claim_header_index out of bounds".to_string(),
                })?;
        let claim_hdr_merkle = header_merkle_root(claim_hdr);
        verify_spv_merkle_inclusion(txid, &parsed.spv_merkle_proof, claim_hdr_merkle)?;

        Ok((
            anchor,
            parsed,
            parent_of_claim,
            u64::from(prev_time),
            used_pq,
        ))
    }

    fn verify_envelope_and_policy(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<(FinalityAttestation, [u8; 32], bool), AdapterError> {
        if evidence.adapter != self.descriptor.id {
            return Err(AdapterError::WrongAdapter {
                expected: self.descriptor.name.clone(),
                found: hex::encode(evidence.adapter.as_bytes()),
            });
        }
        if !self
            .descriptor
            .accepted_evidence_versions
            .contains(&evidence.evidence_version)
        {
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence.evidence_version,
                accepted: BITVM_EVIDENCE_VERSION.to_string(),
            });
        }
        if self.network.trim().is_empty() {
            return Err(AdapterError::ConsensusRule {
                rule: "BitVM2 network identifier must not be empty".to_string(),
            });
        }
        if evidence.network != self.network {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "BitVM2 evidence network {:?} != adapter network {:?}",
                    evidence.network, self.network
                ),
            });
        }
        if policy.require_slashable {
            return Err(AdapterError::ConsensusRule {
                rule: "BitVM2 external PoW headers are not slashable; pair with bonded IntakeState prover".to_string(),
            });
        }

        let (anchor, parsed, parent_of_claim, tip_time, used_pq) =
            self.verify_chain_and_claim(evidence)?;
        let claim_idx = usize::try_from(parsed.claim_header_index).unwrap_or(usize::MAX);
        let depth =
            u64::try_from(parsed.headers.len().checked_sub(claim_idx).ok_or_else(|| {
                AdapterError::ConsensusRule {
                    rule: "BitVM2 claim_header_index out of bounds".to_string(),
                }
            })?)
            .unwrap_or(u64::MAX);
        if policy.min_depth > depth {
            return Err(AdapterError::InsufficientDepth {
                observed: depth,
                required: policy.min_depth,
            });
        }
        if policy.require_declared_match
            && (evidence.declared_height != parsed.claim.claim_pow_height
                || evidence.declared_root != parsed.claim.state_root)
        {
            return Err(AdapterError::DeclarationMismatch {
                field: "bitvm_covenant_claim",
            });
        }
        if policy.max_age > 0 && tip_time > policy.now.saturating_add(MAX_FUTURE_SECONDS) {
            return Err(AdapterError::ConsensusRule {
                rule: format!("BitVM2 PoW tip timestamp {tip_time} exceeds future drift ceiling"),
            });
        }
        if policy.max_age > 0 && policy.now > tip_time {
            let age = policy.now - tip_time;
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        let claim_hdr = parsed
            .headers
            .get(parsed.claim_header_index as usize)
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "BitVM2 claim_header_index out of bounds".to_string(),
            })?;
        let claim_block_hash = sha256d(claim_hdr);
        let difficulty_bits = cumulative_difficulty_bits(anchor.bits, depth);
        let att = FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &evidence.network),
            height: parsed.claim.claim_pow_height,
            state_root: parsed.claim.state_root,
            finalized_at: tip_time,
            time_unit: TimeUnit::UnixSeconds,
            security: SecurityBacking::Work { difficulty_bits },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
            attested_block_hash: Some(claim_block_hash),
            attested_event_root: Some(parsed.claim.event_root),
            attested_tx_root: Some(parsed.claim.tx_root),
        };
        Ok((att, parent_of_claim, used_pq))
    }
}

impl ExternalFinalityAdapter for BitVmCovenantAdapter {
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
        self.verify_envelope_and_policy(evidence, policy)
            .map(|(att, _, _)| att)
    }

    fn verify_observed(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
        observer: &mut dyn CryptoObserver,
    ) -> Result<FinalityAttestation, AdapterError> {
        let (att, _, used_pq) = self.verify_envelope_and_policy(evidence, policy)?;
        observer.observe(ObservedScheme::Scheme(SchemeId::ED25519));
        if used_pq {
            observer.observe(ObservedScheme::Scheme(SchemeId::ML_DSA_65));
        }
        Ok(att)
    }

    fn attested_parent(&self, evidence: &RawConsensusEvidence) -> Option<[u8; 32]> {
        let (_, _, parent_of_claim, _, _) = self.verify_chain_and_claim(evidence).ok()?;
        Some(parent_of_claim)
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        vec![
            FaultProbe {
                name: "refuses unknown BitVM2 evidence version".into(),
                patch: BytePatch::EvidenceVersion { value: 5 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "refuses foreign BitVM2 network".into(),
                patch: BytePatch::Network {
                    value: format!("{}-foreign", self.network),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses mismatched declared BitVM2 claim height".into(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses mismatched declared BitVM2 state root".into(),
                patch: BytePatch::DeclaredRoot { value: [0xdd; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses corrupted BitVM2 payload magic".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: b"BADMAGIC".to_vec(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses truncated BitVM2 payload".into(),
                patch: BytePatch::TruncatePayload { keep: 16 },
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
    use crate::core::address::Address;
    use crate::cross_domain::external::selftest::{admit, ProbeOutcome};
    use crate::crypto::facts::CryptoFacts;
    use crate::crypto::primitives::{KeyPair, PqKeyPair};

    const NET: &str = "bitcoin-bitvm2-regtest";
    const REGTEST_BITS: u32 = 0x207f_ffff;
    const ANCHOR_HEIGHT: u64 = 100;

    fn mine_header(
        prev_hash: [u8; 32],
        merkle_root: [u8; 32],
        timestamp: u32,
        bits: u32,
    ) -> [u8; POW_HEADER_LEN] {
        let target = expand_compact_bits(bits).expect("target");
        for nonce in 0u32..100_000 {
            let mut hdr = [0u8; POW_HEADER_LEN];
            let (ver_s, rest) = hdr.split_at_mut(4);
            ver_s.copy_from_slice(&0x2000_0000u32.to_le_bytes());
            let (prev_s, rest) = rest.split_at_mut(32);
            prev_s.copy_from_slice(&prev_hash);
            let (mrk_s, rest) = rest.split_at_mut(32);
            mrk_s.copy_from_slice(&merkle_root);
            let (ts_s, rest) = rest.split_at_mut(4);
            ts_s.copy_from_slice(&timestamp.to_le_bytes());
            let (bits_s, nonce_s) = rest.split_at_mut(4);
            bits_s.copy_from_slice(&bits.to_le_bytes());
            nonce_s.copy_from_slice(&nonce.to_le_bytes());
            let mut be = sha256d(&hdr);
            be.reverse();
            if be <= target {
                return hdr;
            }
        }
        panic!("failed to mine regtest header");
    }

    fn fixture() -> (
        KeyPair,
        PqKeyPair,
        PinnedBitVmAnchor,
        TraceChunkStep,
        BitVmCovenantEvidence,
        RawConsensusEvidence,
    ) {
        let op_ed = KeyPair::from_seed(&[0x42; 32]).expect("ed");
        let op_pq = PqKeyPair::generate();
        let program_hash = [0x55; 32];
        let anchor = PinnedBitVmAnchor {
            height: ANCHOR_HEIGHT,
            block_hash: [0x11; 32],
            bits: REGTEST_BITS,
            program_hash,
            min_pow_confirmations: 6,
            challenge_blocks: 4,
            operator_ed25519_pubkey: op_ed.public_key_bytes(),
            operator_pq_pubkey: op_pq.public_key_bytes().to_vec(),
        }
        .validate()
        .expect("anchor");

        let pre0 = [0xAA; 32];
        let witness0 = [0xBB; 32];
        let post0 = evaluate_chunk_transition(&program_hash, 0, &pre0, 1, &witness0);
        let chunk0 = TraceChunkStep {
            chunk_index: 0,
            pre_state: pre0,
            claimed_post_state: post0,
            step_opcode: 1,
            step_witness: witness0,
        };
        let sibling_chunk_leaf = [0x77; 32];
        let trace_root = hash_trace_merkle_node(&chunk0.leaf_digest(), &sibling_chunk_leaf);

        let mut claim = BitVmPegClaim {
            state_root: post0,
            tx_root: [0xC1; 32],
            event_root: [0xC2; 32],
            program_hash,
            trace_merkle_root: trace_root,
            trace_chunk_count: 2,
            claim_pow_height: ANCHOR_HEIGHT + 1,
            operator_ed25519_sig: Vec::new(),
            operator_pq_sig: Vec::new(),
        };
        let claim_digest = claim.signing_digest(NET);
        claim.operator_ed25519_sig = op_ed.sign(&claim_digest).to_vec();
        claim.operator_pq_sig = op_pq
            .sign(ctx::CROSS_DOMAIN_V1, &claim_digest)
            .expect("pq sign");

        let txid = sha256d(&claim.covenant_tx_bytes(NET));
        let spv_sibling = [0x88; 32];
        let mut pair = [0u8; 64];
        let (first_half, second_half) = pair.split_at_mut(32);
        first_half.copy_from_slice(&txid);
        second_half.copy_from_slice(&spv_sibling);
        let claim_merkle_root = sha256d(&pair);

        let mut headers = Vec::new();
        let mut prev_block = anchor.block_hash;
        for idx in 0u32..6 {
            let offset = u8::try_from(idx).unwrap_or(0);
            let mr = if idx == 0 {
                claim_merkle_root
            } else {
                [0x90u8.saturating_add(offset); 32]
            };
            let hdr = mine_header(prev_block, mr, 1_700_000_000 + idx * 600, REGTEST_BITS);
            prev_block = sha256d(&hdr);
            headers.push(hdr);
        }

        let declared_root = claim.state_root;
        let bundle = BitVmCovenantEvidence {
            headers,
            claim_header_index: 0,
            spv_merkle_proof: vec![MerkleStep {
                sibling: spv_sibling,
                sibling_is_left: false,
            }],
            claim,
        };
        let raw = RawConsensusEvidence {
            adapter: AdapterId::from_name(BITVM_COVENANT_ADAPTER_NAME),
            evidence_version: BITVM_EVIDENCE_VERSION,
            network: NET.to_string(),
            payload: encode_bitvm_evidence(&bundle),
            declared_height: ANCHOR_HEIGHT + 1,
            declared_root,
            submitter: Address::from([0x04; 32]),
        };
        (op_ed, op_pq, anchor, chunk0, bundle, raw)
    }

    fn pow_policy() -> VerificationPolicy {
        let mut p = VerificationPolicy::strict(0);
        p.require_slashable = false;
        p
    }

    #[test]
    fn bitvm_covenant_peg_admits_verifies_spv_and_maturity_window() {
        let (_ed, _pq, anchor, _chunk0, bundle, raw) = fixture();
        let adapter = BitVmCovenantAdapter::new(NET, Some(anchor.clone())).with_golden(raw.clone());
        let policy = pow_policy();

        let report = admit(&adapter, &policy);
        assert!(report.admitted, "selftest failed: {report:?}");
        assert!(report
            .probes
            .iter()
            .all(|(_, o)| matches!(o, ProbeOutcome::Refused { .. })));

        let mut obs = CryptoFacts::default();
        let att = adapter
            .verify_observed(&raw, &policy, &mut obs)
            .expect("verify bitvm");
        assert_eq!(att.height, ANCHOR_HEIGHT + 1);
        crate::domain::finality_proof_model::FinalityProofShape::from_external_attestation(
            &adapter.descriptor(),
            &att,
        )
        .expect("BitVM2 shape");
        assert_eq!(att.state_root, bundle.claim.state_root);
        assert_eq!(att.attested_tx_root, Some(bundle.claim.tx_root));
        assert_eq!(att.attested_event_root, Some(bundle.claim.event_root));
        assert!(obs
            .observed()
            .iter()
            .any(|c| c.scheme == ObservedScheme::Scheme(SchemeId::ML_DSA_65)));
        assert_eq!(adapter.attested_parent(&raw), Some(anchor.block_hash));
    }

    #[test]
    fn bitvm_covenant_refuses_premature_window_bad_spv_and_proves_disprove_script_fraud() {
        let (op_ed, op_pq, anchor, honest_chunk, bundle, raw) = fixture();
        let adapter = BitVmCovenantAdapter::new(NET, Some(anchor.clone()));
        let policy = pow_policy();

        let mut slash_policy = VerificationPolicy::strict(0);
        slash_policy.require_slashable = true;
        assert!(adapter.verify(&raw, &slash_policy).is_err());

        let mut shallow = bundle.clone();
        shallow.headers.truncate(5);
        let mut bad_raw = raw;
        bad_raw.payload = encode_bitvm_evidence(&shallow);
        assert!(matches!(
            adapter.verify(&bad_raw, &policy),
            Err(AdapterError::InsufficientDepth { .. })
        ));

        let mut unburied = bundle.clone();
        unburied.claim_header_index = 3;
        unburied.claim.claim_pow_height = ANCHOR_HEIGHT + 4;
        bad_raw.payload = encode_bitvm_evidence(&unburied);
        bad_raw.declared_height = ANCHOR_HEIGHT + 4;
        assert!(adapter.verify(&bad_raw, &policy).is_err());

        let mut bad_spv = bundle.clone();
        if let Some(first_step) = bad_spv.spv_merkle_proof.first_mut() {
            first_step.sibling = [0xFE; 32];
        }
        bad_raw.payload = encode_bitvm_evidence(&bad_spv);
        bad_raw.declared_height = ANCHOR_HEIGHT + 1;
        assert!(adapter.verify(&bad_raw, &policy).is_err());

        assert!(verify_disprove_script(
            NET,
            &anchor,
            &DisproveScriptProof {
                claim: bundle.claim.clone(),
                disputed_chunk: honest_chunk.clone(),
                trace_merkle_proof: vec![MerkleStep {
                    sibling: [0x77; 32],
                    sibling_is_left: false,
                }],
            },
        )
        .is_err());

        let bad_post = [0xEE; 32];
        let fraud_chunk = TraceChunkStep {
            claimed_post_state: bad_post,
            ..honest_chunk
        };
        let fraud_root = hash_trace_merkle_node(&fraud_chunk.leaf_digest(), &[0x77; 32]);
        let mut fraud_claim = BitVmPegClaim {
            state_root: bad_post,
            trace_merkle_root: fraud_root,
            ..bundle.claim
        };
        let d = fraud_claim.signing_digest(NET);
        fraud_claim.operator_ed25519_sig = op_ed.sign(&d).to_vec();
        fraud_claim.operator_pq_sig = op_pq.sign(ctx::CROSS_DOMAIN_V1, &d).expect("pq sign");

        let (idx, expected_post, claimed_post) = verify_disprove_script(
            NET,
            &anchor,
            &DisproveScriptProof {
                claim: fraud_claim,
                disputed_chunk: fraud_chunk,
                trace_merkle_proof: vec![MerkleStep {
                    sibling: [0x77; 32],
                    sibling_is_left: false,
                }],
            },
        )
        .expect("fraud proven");
        assert_eq!(idx, 0);
        assert_eq!(claimed_post, bad_post);
        assert_ne!(expected_post, claimed_post);
    }

    #[test]
    fn regression_live_clock_post_claim_depth_and_empty_network() {
        let (op_ed, op_pq, mut anchor, _, mut bundle, raw) = fixture();
        let adapter = BitVmCovenantAdapter::new(NET, Some(anchor.clone()));

        // 1. IntakeState::submit sets policy.now = old_tip_time (> 0) while
        // policy.max_age == 0. After a >2h relayer pause (10_800s > MAX_FUTURE_SECONDS=7_200s),
        // verification must NOT brick the domain when max_age == 0.
        let tip_ts = u64::from(header_timestamp(bundle.headers.last().expect("tip")));
        let mut paused_intake_policy = VerificationPolicy::strict(tip_ts - 10_800);
        paused_intake_policy.max_age = 0;
        paused_intake_policy.require_slashable = false;
        adapter
            .verify(&raw, &paused_intake_policy)
            .expect("BitVM2 domain must not brick after >2h relayer pause when max_age == 0");

        // When policy.max_age > 0, future drift > MAX_FUTURE_SECONDS MUST still be refused.
        let mut clocked = paused_intake_policy;
        clocked.max_age = 86_400;
        assert!(adapter.verify(&raw, &clocked).is_err());

        // 2. Pre-claim historical PoW headers (0..claim_header_index) must NOT
        // inflate confirmation depth or SecurityBacking::Work cumulative work.
        // Put the claim in headers[4] of a 6-header chain (only 2 post-claim confirmations:
        // headers[4] and headers[5], with challenge_blocks = 1).
        anchor.challenge_blocks = 1;
        bundle.claim_header_index = 4;
        bundle.claim.claim_pow_height = ANCHOR_HEIGHT + 5;
        let d = bundle.claim.signing_digest(NET);
        bundle.claim.operator_ed25519_sig = op_ed.sign(&d).to_vec();
        bundle.claim.operator_pq_sig = op_pq.sign(ctx::CROSS_DOMAIN_V1, &d).expect("pq sign");
        let txid = sha256d(&bundle.claim.covenant_tx_bytes(NET));
        let mut pair = [0u8; 64];
        let (left_half, right_half) = pair.split_at_mut(32);
        left_half.copy_from_slice(&txid);
        right_half.copy_from_slice(&bundle.spv_merkle_proof.first().expect("step 0").sibling);
        let claim_merkle_root = sha256d(&pair);
        let mut headers = Vec::with_capacity(6);
        let mut prev_block = anchor.block_hash;
        for idx in 0u32..6 {
            let mrk = if idx == 4 {
                claim_merkle_root
            } else {
                [u8::try_from(idx + 0x20).unwrap_or(0x20); 32]
            };
            let hdr = mine_header(prev_block, mrk, 1_700_000_000 + idx * 600, REGTEST_BITS);
            prev_block = sha256d(&hdr);
            headers.push(hdr);
        }
        bundle.headers = headers;
        let mut late_raw = raw.clone();
        late_raw.declared_height = bundle.claim.claim_pow_height;
        late_raw.payload = encode_bitvm_evidence(&bundle);
        let shallow_adapter = BitVmCovenantAdapter::new(NET, Some(anchor.clone()));
        let mut six_conf_policy = pow_policy();
        six_conf_policy.min_depth = 6;
        assert!(
            matches!(
                shallow_adapter.verify(&late_raw, &six_conf_policy),
                Err(AdapterError::InsufficientDepth {
                    observed: 2,
                    required: 6
                })
            ),
            "4 pre-claim historical blocks must not count toward 6 post-claim confirmations"
        );

        // 3. Empty/whitespace network must be refused.
        let blank_adapter = BitVmCovenantAdapter::new("  ", Some(anchor));
        let mut blank_raw = raw;
        blank_raw.adapter = blank_adapter.descriptor().id;
        blank_raw.network = "  ".to_string();
        assert!(matches!(
            blank_adapter.verify(&blank_raw, &pow_policy()),
            Err(AdapterError::ConsensusRule { .. })
        ));
    }

    #[test]
    fn bitvm_spv_refuses_right_side_cve_2012_2459_and_zero_first_timestamp() {
        let (_op_ed, _op_pq, anchor, _chunk0, mut bundle, raw) = fixture();
        let adapter = BitVmCovenantAdapter::new(NET, Some(anchor.clone()));
        let policy = pow_policy();

        // Right-side equal-sibling duplication (`sha256d(txid || txid)`, `sibling_is_left == false`)
        // is the exact Bitcoin odd-leaf CVE-2012-2459 malleability vector and must fail closed.
        let txid = sha256d(&bundle.claim.covenant_tx_bytes(NET));
        let mut dup_pair = [0u8; 64];
        dup_pair[..32].copy_from_slice(&txid);
        dup_pair[32..].copy_from_slice(&txid);
        let dup_merkle_root = sha256d(&dup_pair);

        let mut dup_headers = Vec::with_capacity(6);
        let mut prev_block = anchor.block_hash;
        for idx in 0u32..6 {
            let mr = if idx == 0 {
                dup_merkle_root
            } else {
                [u8::try_from(idx + 0x30).unwrap_or(0x30); 32]
            };
            let hdr = mine_header(prev_block, mr, 1_700_000_000 + idx * 600, REGTEST_BITS);
            prev_block = sha256d(&hdr);
            dup_headers.push(hdr);
        }
        bundle.headers = dup_headers;
        bundle.spv_merkle_proof = vec![MerkleStep {
            sibling: txid,
            sibling_is_left: false,
        }];
        let mut dup_raw = raw.clone();
        dup_raw.payload = encode_bitvm_evidence(&bundle);
        assert!(
            matches!(
                adapter.verify(&dup_raw, &policy),
                Err(AdapterError::ConsensusRule { .. })
            ),
            "right-side CVE-2012-2459 equal-sibling SPV branch must be refused"
        );

        // First header carrying timestamp == 0 must also be refused fail-closed.
        let (_op_ed2, _op_pq2, anchor2, _c, mut zero_ts_bundle, zero_ts_raw_base) = fixture();
        let valid_mr = header_merkle_root(zero_ts_bundle.headers.first().expect("hdr0"));
        let mut zero_ts_headers = Vec::with_capacity(6);
        let mut prev2 = anchor2.block_hash;
        for idx in 0u32..6 {
            let mr = if idx == 0 {
                valid_mr
            } else {
                [u8::try_from(idx + 0x40).unwrap_or(0x40); 32]
            };
            let ts = if idx == 0 { 0 } else { idx * 600 };
            let hdr = mine_header(prev2, mr, ts, REGTEST_BITS);
            prev2 = sha256d(&hdr);
            zero_ts_headers.push(hdr);
        }
        zero_ts_bundle.headers = zero_ts_headers;
        let mut zero_ts_raw = zero_ts_raw_base;
        zero_ts_raw.payload = encode_bitvm_evidence(&zero_ts_bundle);
        assert!(
            matches!(
                adapter.verify(&zero_ts_raw, &policy),
                Err(AdapterError::ConsensusRule { .. })
            ),
            "PoW header chain starting at timestamp 0 must be refused"
        );
    }

    #[test]
    fn disprove_script_enforces_canonical_depth_direction_bits_and_post_anchor_height() {
        let (op_ed, op_pq, anchor, honest_chunk, bundle, _raw) = fixture();
        let bad_post = [0xEE; 32];
        let fraud_chunk = TraceChunkStep {
            claimed_post_state: bad_post,
            ..honest_chunk
        };
        let leaf = fraud_chunk.leaf_digest();

        // 1. Empty Merkle proof when trace_chunk_count == 2 (depth must be 1, not 0).
        let mut zero_depth_claim = BitVmPegClaim {
            state_root: bad_post,
            trace_merkle_root: leaf,
            trace_chunk_count: 2,
            ..bundle.claim.clone()
        };
        let d0 = zero_depth_claim.signing_digest(NET);
        zero_depth_claim.operator_ed25519_sig = op_ed.sign(&d0).to_vec();
        zero_depth_claim.operator_pq_sig = op_pq.sign(ctx::CROSS_DOMAIN_V1, &d0).expect("pq sign");
        assert!(
            verify_disprove_script(
                NET,
                &anchor,
                &DisproveScriptProof {
                    claim: zero_depth_claim,
                    disputed_chunk: fraud_chunk.clone(),
                    trace_merkle_proof: Vec::new(),
                },
            )
            .is_err(),
            "trace_chunk_count=2 with empty Merkle branch must be refused"
        );

        // 2. Wrong direction bit: chunk_index=0 is a left child (bit 0 == 0 => sibling_is_left=false),
        // so opening with sibling_is_left=true must be refused.
        let swapped_root = hash_trace_merkle_node(&[0x77; 32], &leaf);
        let mut swapped_claim = BitVmPegClaim {
            state_root: bad_post,
            trace_merkle_root: swapped_root,
            trace_chunk_count: 2,
            ..bundle.claim.clone()
        };
        let d1 = swapped_claim.signing_digest(NET);
        swapped_claim.operator_ed25519_sig = op_ed.sign(&d1).to_vec();
        swapped_claim.operator_pq_sig = op_pq.sign(ctx::CROSS_DOMAIN_V1, &d1).expect("pq sign");
        assert!(
            verify_disprove_script(
                NET,
                &anchor,
                &DisproveScriptProof {
                    claim: swapped_claim,
                    disputed_chunk: fraud_chunk.clone(),
                    trace_merkle_proof: vec![MerkleStep {
                        sibling: [0x77; 32],
                        sibling_is_left: true,
                    }],
                },
            )
            .is_err(),
            "chunk_index=0 opened as right child (sibling_is_left=true) must be refused"
        );

        // 3. Equal-sibling collision in trace Merkle proof (`sibling == current`) must be refused.
        let dup_trace_root = hash_trace_merkle_node(&leaf, &leaf);
        let mut dup_trace_claim = BitVmPegClaim {
            state_root: bad_post,
            trace_merkle_root: dup_trace_root,
            trace_chunk_count: 2,
            ..bundle.claim.clone()
        };
        let d2 = dup_trace_claim.signing_digest(NET);
        dup_trace_claim.operator_ed25519_sig = op_ed.sign(&d2).to_vec();
        dup_trace_claim.operator_pq_sig = op_pq.sign(ctx::CROSS_DOMAIN_V1, &d2).expect("pq sign");
        assert!(
            verify_disprove_script(
                NET,
                &anchor,
                &DisproveScriptProof {
                    claim: dup_trace_claim,
                    disputed_chunk: fraud_chunk.clone(),
                    trace_merkle_proof: vec![MerkleStep {
                        sibling: leaf,
                        sibling_is_left: false,
                    }],
                },
            )
            .is_err(),
            "equal-sibling trace Merkle proof must be refused"
        );

        // 4. Stale pre-anchor claim (`claim_pow_height <= anchor.height`) must not freeze domain.
        let valid_fraud_root = hash_trace_merkle_node(&leaf, &[0x77; 32]);
        let mut stale_claim = BitVmPegClaim {
            state_root: bad_post,
            trace_merkle_root: valid_fraud_root,
            claim_pow_height: anchor.height,
            ..bundle.claim.clone()
        };
        let d3 = stale_claim.signing_digest(NET);
        stale_claim.operator_ed25519_sig = op_ed.sign(&d3).to_vec();
        stale_claim.operator_pq_sig = op_pq.sign(ctx::CROSS_DOMAIN_V1, &d3).expect("pq sign");
        assert!(
            verify_disprove_script(
                NET,
                &anchor,
                &DisproveScriptProof {
                    claim: stale_claim,
                    disputed_chunk: fraud_chunk.clone(),
                    trace_merkle_proof: vec![MerkleStep {
                        sibling: [0x77; 32],
                        sibling_is_left: false,
                    }],
                },
            )
            .is_err(),
            "pre-anchor or at-anchor claim_pow_height must be refused in DisproveScript"
        );

        // 5. Positive control for non-power-of-two trace_chunk_count=3 (depth=2) at chunk_index=2
        // (`bit 0 = 0 => sibling_is_left: false`, `bit 1 = 1 => sibling_is_left: true`).
        let chunk2 = TraceChunkStep {
            chunk_index: 2,
            claimed_post_state: bad_post,
            ..fraud_chunk
        };
        let lvl0 = hash_trace_merkle_node(&chunk2.leaf_digest(), &[0x61; 32]);
        let lvl1 = hash_trace_merkle_node(&[0x62; 32], &lvl0);
        let mut claim3 = BitVmPegClaim {
            state_root: bad_post,
            trace_merkle_root: lvl1,
            trace_chunk_count: 3,
            ..bundle.claim
        };
        let d4 = claim3.signing_digest(NET);
        claim3.operator_ed25519_sig = op_ed.sign(&d4).to_vec();
        claim3.operator_pq_sig = op_pq.sign(ctx::CROSS_DOMAIN_V1, &d4).expect("pq sign");
        let (proved_idx, _, _) = verify_disprove_script(
            NET,
            &anchor,
            &DisproveScriptProof {
                claim: claim3,
                disputed_chunk: chunk2,
                trace_merkle_proof: vec![
                    MerkleStep {
                        sibling: [0x61; 32],
                        sibling_is_left: false,
                    },
                    MerkleStep {
                        sibling: [0x62; 32],
                        sibling_is_left: true,
                    },
                ],
            },
        )
        .expect("canonical 3-chunk depth=2 proof at index 2 must succeed");
        assert_eq!(proved_idx, 2);
    }
}
