//! TON Masterchain key-block rotation, Catchain BFT supermajority, and dynamic
//! split/merge Workchain/Shardchain external finality adapter.
//!
//! Under Durov's Open Network consensus design (2018-2021), a single
//! `Masterchain` (`workchain_id = -1`, full shard prefix `0x8000_0000_0000_0000`)
//! finalizes blocks via bounded-session `Catchain` BFT commits signed by
//! strictly more than `2/3` of the active validator stake established by the
//! latest Masterchain key-block, and embeds a canonical `ShardHashes` Merkle
//! dictionary binding every dynamically split or merged `Workchain` shard.
//!
//! Verification enforces six invariants:
//!
//! 1. **Key-block validator rotation**: starts from the governance-pinned key
//!    block (`key_block_seqno`, `[utime_since, utime_until)`, bonded validator
//!    set) and optionally advances through a strictly ascending chain of up to
//!    `8` key-block handoffs, each signed by strictly more than `2/3` of its
//!    predecessor set's total stake over the successor validator-set digest.
//! 2. **Masterchain header & validity window**: `mc_seqno > active.key_seqno`,
//!    `gen_utime` lies inside `[active.utime_since, active.utime_until)`, and
//!    both `root_hash` and `file_hash` equal their self-derived hashes.
//! 3. **Catchain BFT commit**: distinct active validators with combined weight
//!    strictly exceeding `2/3 * total_weight` sign `(network, catchain_seqno,
//!    validator_list_hash, mc_seqno, root_hash, file_hash)`.
//! 4. **TON binary shard prefix discipline**: every shard identifier encodes a
//!    prefix of length `0..=60` bits via its lowest set tag bit
//!    (`tag = prefix & prefix.wrapping_neg()`, `tag != 0`); overlapping shard
//!    prefixes (for instance an unsplit parent alongside its split child) are
//!    refused fail-closed.
//! 5. **Shardchain inclusion & split/merge continuity**: when attesting a
//!    workchain shard, its `ShardDescr` carries a verified Merkle inclusion
//!    path into `mc.shard_hashes_root`, plus optional split (1 parent -> 2
//!    sibling children) or merge (2 sibling children -> 1 parent) bit-exact
//!    prefix algebra verification.
//! 6. **Hybrid post-quantum non-downgrade**: any validator carrying an
//!    ML-DSA-65 public key MUST attach a valid ML-DSA-65 co-signature under
//!    [`crate::crypto::ctx::CROSS_DOMAIN_V1`].
//!
//! WIRING: implements `ExternalFinalityAdapter` for `ExternalDomainRegistry`
//! (pairing with `execution/tvm`); `AdapterSpec` tag append joins `intake.rs`
//! after concurrent intake hardening merges.

use crate::crypto::facts::{CryptoObserver, ObservedScheme};
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

const ADAPTER_NAME: &str = "ton-catchain-v1";
const ADAPTER_VERSION: u32 = 1;
const EVIDENCE_VERSION: u32 = 1;
const CATCHAIN_COMMIT_DEPTH: u64 = 1;

/// Full unsplit TON shard identifier (`prefix_len = 0`, tag bit at MSB `1 << 63`).
const SHARD_PREFIX_FULL: u64 = 1u64 << 63;
/// Maximum dynamic shard split depth in TON (`60` prefix bits; lowest tag bit `>= 1 << 3`).
const MAX_SHARD_SPLIT_DEPTH: u32 = 60;

const PAYLOAD_MAGIC: &[u8; 8] = b"BDLMTN01";
const MAX_TON_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_TON_VALIDATORS: usize = 256;
const MAX_KEY_BLOCK_ROTATIONS: usize = 8;
const MAX_SHARD_MERKLE_DEPTH: usize = 32;
const MAX_SIBLING_SHARDS: usize = 64;

/// One validator in a TON Masterchain `ValidatorSet` (`ConfigParam 34`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TonValidator {
    /// Classical Ed25519 verifying key (`SigPubKey`, 32 bytes).
    pub ed25519_pubkey: [u8; 32],
    /// Non-zero validator consensus weight.
    pub weight: u64,
    /// Optional ML-DSA-65 post-quantum public key enforced on every Catchain
    /// and key-block rotation vote.
    #[serde(default)]
    pub pq_pubkey: Vec<u8>,
}

/// Governance-pinned TON Masterchain key-block validator anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedTonMasterchainAnchor {
    /// Masterchain sequence number of the pinned key block.
    pub key_block_seqno: u64,
    /// Inclusive start timestamp (`utime_since`) of the validator cycle.
    pub utime_since: u64,
    /// Exclusive end timestamp (`utime_until`, must exceed `utime_since`).
    pub utime_until: u64,
    /// Active validators committed in this key block (`ConfigParam 34`).
    pub validators: Vec<TonValidator>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CatchainSig {
    signer_pubkey: [u8; 32],
    ed25519_sig: Vec<u8>,
    #[serde(default)]
    pq_sig: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct KeyBlockRotation {
    new_key_block_seqno: u64,
    utime_since: u64,
    utime_until: u64,
    next_validators: Vec<TonValidator>,
    next_validator_list_hash: Hash32,
    prev_committee_sigs: Vec<CatchainSig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum SplitMergeTransition {
    /// No topology change at this shard block.
    None,
    /// Parent shard split into left (`0`) and right (`1`) children; target is one of them.
    SplitFrom { parent_prefix: u64 },
    /// Two adjacent sibling shards merged into their common parent target shard.
    MergedFrom {
        left_child_prefix: u64,
        right_child_prefix: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TonShardProof {
    workchain_id: i32,
    shard_prefix: u64,
    shard_seqno: u64,
    state_root: Hash32,
    tx_root: Hash32,
    event_root: Hash32,
    file_hash: Hash32,
    leaf_index: u64,
    merkle_siblings: Vec<Hash32>,
    /// Active co-registered shard prefixes in the same workchain checked for
    /// strict pairwise prefix disjointness.
    co_active_prefixes: Vec<u64>,
    topology_step: SplitMergeTransition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TonMasterchainBlock {
    key_block_seqno: u64,
    catchain_seqno: u64,
    mc_seqno: u64,
    gen_utime: u64,
    prev_root_hash: Hash32,
    mc_state_root: Hash32,
    mc_tx_root: Hash32,
    mc_event_root: Hash32,
    shard_hashes_root: Hash32,
    root_hash: Hash32,
    file_hash: Hash32,
}

impl TonMasterchainBlock {
    #[must_use]
    fn compute_root_hash(&self, network: &str, validator_list_hash: &Hash32) -> Hash32 {
        crate::core::hash::hash_fields_bytes(&[
            b"BDLM_TON_MC_ROOT_V1",
            network.as_bytes(),
            &(-1i32).to_le_bytes(),
            &SHARD_PREFIX_FULL.to_le_bytes(),
            &self.key_block_seqno.to_le_bytes(),
            &self.catchain_seqno.to_le_bytes(),
            &self.mc_seqno.to_le_bytes(),
            &self.gen_utime.to_le_bytes(),
            validator_list_hash,
            &self.prev_root_hash,
            &self.mc_state_root,
            &self.mc_tx_root,
            &self.mc_event_root,
            &self.shard_hashes_root,
        ])
    }

    #[must_use]
    fn compute_file_hash(&self, root_hash: &Hash32) -> Hash32 {
        crate::core::hash::hash_fields_bytes(&[
            b"BDLM_TON_FILE_V1",
            root_hash,
            &self.mc_seqno.to_le_bytes(),
            &self.shard_hashes_root,
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TonCatchainEvidence {
    rotations: Vec<KeyBlockRotation>,
    masterchain: TonMasterchainBlock,
    catchain_sigs: Vec<CatchainSig>,
    /// Optional workchain shard proof; when `None`, the attestation commits the
    /// Masterchain state root directly.
    target_shard: Option<TonShardProof>,
}

/// Validate a TON trailing-tag shard prefix and return `(prefix_bits_len, low_tag_bit)`.
fn parse_shard_prefix(prefix: u64) -> Result<(u32, u64), AdapterError> {
    if prefix == 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "TON shard_prefix cannot be zero (missing trailing tag bit)".into(),
        });
    }
    let tz = prefix.trailing_zeros();
    let prefix_len = 63u32.saturating_sub(tz);
    if prefix_len > MAX_SHARD_SPLIT_DEPTH {
        return Err(AdapterError::ConsensusRule {
            rule: format!("TON shard split depth {prefix_len} exceeds {MAX_SHARD_SPLIT_DEPTH}"),
        });
    }
    let tag = 1u64 << tz;
    Ok((prefix_len, tag))
}

/// Split a valid TON shard prefix into its exact `(left_child, right_child)` pair.
fn split_shard_prefix(parent: u64) -> Result<(u64, u64), AdapterError> {
    let (len, tag) = parse_shard_prefix(parent)?;
    if len >= MAX_SHARD_SPLIT_DEPTH {
        return Err(AdapterError::ConsensusRule {
            rule: "TON shard at maximum depth 60 cannot split further".into(),
        });
    }
    let half = tag >> 1;
    let left = (parent & !tag) | half;
    let right = parent | half;
    Ok((left, right))
}

/// True when two valid TON shard prefixes cover overlapping account-id ranges.
fn shard_prefixes_overlap(a: u64, b: u64) -> Result<bool, AdapterError> {
    let (len_a, _) = parse_shard_prefix(a)?;
    let (len_b, _) = parse_shard_prefix(b)?;
    let common = len_a.min(len_b);
    if common == 0 {
        return Ok(true);
    }
    let mask = !0u64 << (64 - common);
    Ok((a & mask) == (b & mask))
}

#[must_use]
fn compute_validator_list_hash(
    utime_since: u64,
    utime_until: u64,
    validators: &[TonValidator],
) -> Hash32 {
    let mut acc = crate::core::hash::hash_fields_bytes(&[
        b"BDLM_TON_VALSET_V1",
        &utime_since.to_le_bytes(),
        &utime_until.to_le_bytes(),
        &(validators.len() as u64).to_le_bytes(),
    ]);
    for v in validators {
        acc = crate::core::hash::hash_fields_bytes(&[
            b"BDLM_TON_VALSET_V1",
            &acc,
            &v.ed25519_pubkey,
            &v.weight.to_le_bytes(),
            &v.pq_pubkey,
        ]);
    }
    acc
}

#[must_use]
fn key_block_rotation_sign_bytes(
    network: &str,
    prev_key_seqno: u64,
    new_key_seqno: u64,
    utime_since: u64,
    utime_until: u64,
    next_validator_list_hash: &Hash32,
) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_TON_KEYBLOCK_V1",
        network.as_bytes(),
        &prev_key_seqno.to_le_bytes(),
        &new_key_seqno.to_le_bytes(),
        &utime_since.to_le_bytes(),
        &utime_until.to_le_bytes(),
        next_validator_list_hash,
    ])
}

#[must_use]
fn catchain_commit_sign_bytes(
    network: &str,
    catchain_seqno: u64,
    validator_list_hash: &Hash32,
    mc_seqno: u64,
    root_hash: &Hash32,
    file_hash: &Hash32,
) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_TON_CATCHAIN_V1",
        network.as_bytes(),
        &catchain_seqno.to_le_bytes(),
        validator_list_hash,
        &mc_seqno.to_le_bytes(),
        root_hash,
        file_hash,
    ])
}

#[must_use]
fn shard_descr_leaf(shard: &TonShardProof) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_TON_SHARD_LEAF_V1",
        &shard.workchain_id.to_le_bytes(),
        &shard.shard_prefix.to_le_bytes(),
        &shard.shard_seqno.to_le_bytes(),
        &shard.state_root,
        &shard.tx_root,
        &shard.event_root,
        &shard.file_hash,
    ])
}

#[must_use]
fn shard_merkle_node(left: &Hash32, right: &Hash32) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[b"BDLM_TON_SHARD_NODE_V1", left, right])
}

#[must_use]
const fn has_supermajority(signed: u128, total: u128) -> bool {
    total > 0 && signed.saturating_mul(3) > total.saturating_mul(2)
}

#[must_use]
fn min_supermajority_weight(total: u128) -> u64 {
    let need = (total.saturating_mul(2) / 3).saturating_add(1);
    u64::try_from(need).unwrap_or(u64::MAX)
}

type TonValidatorIndex<'a> = (BTreeMap<[u8; 32], &'a TonValidator>, u128, Hash32);

fn validate_validator_set(
    utime_since: u64,
    utime_until: u64,
    validators: &[TonValidator],
) -> Result<TonValidatorIndex<'_>, AdapterError> {
    if utime_until <= utime_since {
        return Err(AdapterError::ConsensusRule {
            rule: "TON validator cycle utime_until must exceed utime_since".into(),
        });
    }
    if validators.is_empty() || validators.len() > MAX_TON_VALIDATORS {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "TON validator set size {} outside 1..={MAX_TON_VALIDATORS}",
                validators.len()
            ),
        });
    }
    let mut by_key = BTreeMap::new();
    let mut total = 0u128;
    for v in validators {
        if v.ed25519_pubkey == [0u8; 32] || v.weight == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "TON validator must have non-zero pubkey and positive weight".into(),
            });
        }
        if !v.pq_pubkey.is_empty() {
            crate::crypto::pq::validate_public_key(SchemeId::ML_DSA_65, &v.pq_pubkey).map_err(
                |_| AdapterError::ConsensusRule {
                    rule: "invalid ML-DSA-65 public key in TON validator set".into(),
                },
            )?;
        }
        if by_key.insert(v.ed25519_pubkey, v).is_some() {
            return Err(AdapterError::ConsensusRule {
                rule: "duplicate Ed25519 public key in TON validator set".into(),
            });
        }
        total =
            total
                .checked_add(u128::from(v.weight))
                .ok_or_else(|| AdapterError::ConsensusRule {
                    rule: "TON validator set total weight overflow".into(),
                })?;
    }
    let vhash = compute_validator_list_hash(utime_since, utime_until, validators);
    Ok((by_key, total, vhash))
}

fn verify_catchain_quorum(
    committee: &BTreeMap<[u8; 32], &TonValidator>,
    total_weight: u128,
    sigs: &[CatchainSig],
    msg: &Hash32,
    what: &str,
) -> Result<(u64, bool), AdapterError> {
    if sigs.is_empty() || sigs.len() > committee.len() {
        return Err(AdapterError::ConsensusRule {
            rule: format!("invalid {what} signature count {}", sigs.len()),
        });
    }
    let mut seen = BTreeSet::new();
    let mut signed = 0u128;
    let mut all_pq = true;
    for sig in sigs {
        if !seen.insert(sig.signer_pubkey) {
            return Err(AdapterError::ConsensusRule {
                rule: format!("duplicate validator signature in {what}"),
            });
        }
        let Some(v) = committee.get(&sig.signer_pubkey) else {
            return Err(AdapterError::ConsensusRule {
                rule: format!("signer not in active TON validator set for {what}"),
            });
        };
        crate::crypto::primitives::verify_signature(msg, &sig.ed25519_sig, &v.ed25519_pubkey)
            .map_err(|_| AdapterError::Crypto {
                what: format!("invalid Ed25519 signature in {what}"),
            })?;
        if v.pq_pubkey.is_empty() {
            all_pq = false;
        } else {
            if sig.pq_sig.is_empty() {
                return Err(AdapterError::Crypto {
                    what: format!("missing mandatory ML-DSA-65 co-signature in {what}"),
                });
            }
            crate::crypto::primitives::PqKeyPair::verify(
                &v.pq_pubkey,
                crate::crypto::ctx::CROSS_DOMAIN_V1,
                msg,
                &sig.pq_sig,
            )
            .map_err(|_| AdapterError::Crypto {
                what: format!("invalid ML-DSA-65 co-signature in {what}"),
            })?;
        }
        signed = signed.checked_add(u128::from(v.weight)).ok_or_else(|| {
            AdapterError::ConsensusRule {
                rule: format!("{what} signed weight overflow"),
            }
        })?;
    }
    if !has_supermajority(signed, total_weight) {
        return Err(AdapterError::ConsensusRule {
            rule: format!("{what} signed weight {signed} does not exceed 2/3 of {total_weight}"),
        });
    }
    Ok((seen.len() as u64, all_pq))
}

fn verify_shard_proof(shard: &TonShardProof, mc_shard_root: &Hash32) -> Result<(), AdapterError> {
    if shard.workchain_id == -1 {
        return Err(AdapterError::ConsensusRule {
            rule: "ShardHashes entry cannot claim Masterchain workchain_id -1".into(),
        });
    }
    if shard.shard_seqno == 0
        || shard.state_root == [0u8; 32]
        || shard.file_hash == [0u8; 32]
        || shard.merkle_siblings.len() > MAX_SHARD_MERKLE_DEPTH
        || shard.co_active_prefixes.len() > MAX_SIBLING_SHARDS
    {
        return Err(AdapterError::ConsensusRule {
            rule: "malformed TON ShardDescr metadata or bounds".into(),
        });
    }
    let _ = parse_shard_prefix(shard.shard_prefix)?;

    // Check pairwise non-overlap across target shard and all declared co-active shards.
    let mut all_prefixes = Vec::with_capacity(shard.co_active_prefixes.len().saturating_add(1));
    all_prefixes.push(shard.shard_prefix);
    for &other in &shard.co_active_prefixes {
        let _ = parse_shard_prefix(other)?;
        for &existing in &all_prefixes {
            if shard_prefixes_overlap(existing, other)? {
                return Err(AdapterError::ConsensusRule {
                    rule: format!(
                        "overlapping TON shard prefixes 0x{existing:016x} and 0x{other:016x}"
                    ),
                });
            }
        }
        all_prefixes.push(other);
    }

    // Verify dynamic split/merge binary-prefix algebra when declared.
    match shard.topology_step {
        SplitMergeTransition::None => {}
        SplitMergeTransition::SplitFrom { parent_prefix } => {
            let (left, right) = split_shard_prefix(parent_prefix)?;
            if shard.shard_prefix != left && shard.shard_prefix != right {
                return Err(AdapterError::ConsensusRule {
                    rule: "TON shard SplitFrom prefix is not an immediate child of parent_prefix"
                        .into(),
                });
            }
        }
        SplitMergeTransition::MergedFrom {
            left_child_prefix,
            right_child_prefix,
        } => {
            let (expected_left, expected_right) = split_shard_prefix(shard.shard_prefix)?;
            if left_child_prefix != expected_left || right_child_prefix != expected_right {
                return Err(AdapterError::ConsensusRule {
                    rule: "TON shard MergedFrom children do not recombine to target shard_prefix"
                        .into(),
                });
            }
        }
    }

    if shard.merkle_siblings.len() < 64 && (shard.leaf_index >> shard.merkle_siblings.len()) != 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "TON ShardHashes leaf_index out of bounds for proof depth".into(),
        });
    }
    let mut acc = shard_descr_leaf(shard);
    let mut idx = shard.leaf_index;
    for sib in &shard.merkle_siblings {
        acc = if idx & 1 == 0 {
            shard_merkle_node(&acc, sib)
        } else {
            shard_merkle_node(sib, &acc)
        };
        idx >>= 1;
    }
    if !bool::from(acc.ct_eq(mc_shard_root)) {
        return Err(AdapterError::ConsensusRule {
            rule: "TON ShardDescr Merkle proof does not resolve to Masterchain shard_hashes_root"
                .into(),
        });
    }
    Ok(())
}

#[cfg(test)]
fn encode_ton_evidence(bundle: &TonCatchainEvidence) -> Result<Vec<u8>, String> {
    let body =
        bincode::serialize(bundle).map_err(|e| format!("ton-catchain encode failed: {e}"))?;
    let total = PAYLOAD_MAGIC.len().saturating_add(body.len());
    if total > MAX_TON_PAYLOAD_BYTES {
        return Err(format!(
            "ton-catchain payload {total} exceeds ceiling {MAX_TON_PAYLOAD_BYTES}"
        ));
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_ton_evidence(payload: &[u8]) -> Result<TonCatchainEvidence, AdapterError> {
    if payload.len() < PAYLOAD_MAGIC.len() {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "TON Catchain payload shorter than 8-byte magic prefix".into(),
        });
    }
    if payload.len() > MAX_TON_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_TON_PAYLOAD_BYTES,
            reason: format!("TON Catchain payload exceeds {MAX_TON_PAYLOAD_BYTES} bytes"),
        });
    }
    if payload.get(0..8) != Some(PAYLOAD_MAGIC.as_slice()) {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "TON Catchain payload magic mismatch".into(),
        });
    }
    let body = payload.get(8..).ok_or_else(|| AdapterError::Malformed {
        offset: 8,
        reason: "missing TON Catchain payload body".into(),
    })?;
    let decoded =
        crate::network::bounded_bincode::decode_bounded_bincode(body, MAX_TON_PAYLOAD_BYTES)
            .map_err(|e| AdapterError::Malformed {
                offset: 8,
                reason: format!("invalid TON Catchain evidence: {e}"),
            })?;
    if bincode::serialized_size(&decoded).ok() != u64::try_from(body.len()).ok() {
        return Err(AdapterError::Malformed {
            offset: 8,
            reason: "trailing bytes after canonical TON Catchain evidence".into(),
        });
    }
    Ok(decoded)
}

/// External finality adapter for TON Masterchain Catchain BFT and dynamically
/// split/merged Workchain Shardchains.
pub struct TonCatchainAdapter {
    network: String,
    pinned: Option<PinnedTonMasterchainAnchor>,
    golden: Option<RawConsensusEvidence>,
    descriptor: AdapterDescriptor,
}

impl TonCatchainAdapter {
    /// Construct a `TonCatchainAdapter` bound to `network` and its pinned
    /// Masterchain key-block validator set.
    #[must_use]
    pub fn new(network: impl Into<String>, pinned: Option<PinnedTonMasterchainAnchor>) -> Self {
        let network = network.into();
        let id = AdapterId::from_name(ADAPTER_NAME);
        let set_size = pinned.as_ref().map_or(0, |p| p.validators.len() as u64);
        let descriptor = AdapterDescriptor {
            id,
            name: ADAPTER_NAME.into(),
            adapter_version: ADAPTER_VERSION,
            accepted_evidence_versions: vec![EVIDENCE_VERSION],
            consensus_kind: "ton-masterchain-catchain-bft".into(),
            finality_kind: FinalityKind::ProtocolFinality,
            required_depth: CATCHAIN_COMMIT_DEPTH,
            time_unit: TimeUnit::Height,
            trust_model: TrustModel::HonestMajority { set_size },
        };
        Self {
            network,
            pinned,
            golden: None,
            descriptor,
        }
    }

    /// Attach a canonical golden sample for [`super::selftest::admit`].
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }

    fn verify_inner(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<(FinalityAttestation, bool), AdapterError> {
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
                    "TON network mismatch: expected {}, got {}",
                    self.network, evidence.network
                ),
            });
        }
        let Some(pinned) = &self.pinned else {
            return Err(AdapterError::ConsensusRule {
                rule: "no governance-pinned TON Masterchain key-block configured".into(),
            });
        };

        let decoded = decode_ton_evidence(&evidence.payload)?;
        if decoded.rotations.len() > MAX_KEY_BLOCK_ROTATIONS {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "TON key-block rotation chain length {} exceeds {MAX_KEY_BLOCK_ROTATIONS}",
                    decoded.rotations.len()
                ),
            });
        }

        // 1. Walk authenticated key-block validator rotations from pinned anchor.
        let mut cur_key_seqno = pinned.key_block_seqno;
        let mut cur_since = pinned.utime_since;
        let mut cur_until = pinned.utime_until;
        let mut cur_validators: &[TonValidator] = &pinned.validators;
        let mut all_pq = true;

        for rot in &decoded.rotations {
            if rot.new_key_block_seqno <= cur_key_seqno {
                return Err(AdapterError::ConsensusRule {
                    rule: "TON key-block rotation seqno must strictly increase".into(),
                });
            }
            if rot.utime_since < cur_since || rot.utime_since > cur_until {
                return Err(AdapterError::ConsensusRule {
                    rule: "TON key-block rotation window has an unauthenticated gap".into(),
                });
            }
            let (prev_map, prev_total, _) =
                validate_validator_set(cur_since, cur_until, cur_validators)?;
            let (_, _, expected_next_hash) =
                validate_validator_set(rot.utime_since, rot.utime_until, &rot.next_validators)?;
            if !bool::from(rot.next_validator_list_hash.ct_eq(&expected_next_hash)) {
                return Err(AdapterError::ConsensusRule {
                    rule: "TON key-block next_validator_list_hash mismatch".into(),
                });
            }
            let rot_msg = key_block_rotation_sign_bytes(
                &self.network,
                cur_key_seqno,
                rot.new_key_block_seqno,
                rot.utime_since,
                rot.utime_until,
                &rot.next_validator_list_hash,
            );
            let (_, rot_pq) = verify_catchain_quorum(
                &prev_map,
                prev_total,
                &rot.prev_committee_sigs,
                &rot_msg,
                "TON key-block rotation",
            )?;
            all_pq &= rot_pq;
            cur_key_seqno = rot.new_key_block_seqno;
            cur_since = rot.utime_since;
            cur_until = rot.utime_until;
            cur_validators = &rot.next_validators;
        }

        let (active_map, active_total, active_vhash) =
            validate_validator_set(cur_since, cur_until, cur_validators)?;

        // 2. Validate Masterchain header against active key block.
        let mc = &decoded.masterchain;
        if mc.key_block_seqno != cur_key_seqno {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "TON Masterchain block references key_block_seqno {}, active is {cur_key_seqno}",
                    mc.key_block_seqno
                ),
            });
        }
        if mc.mc_seqno <= cur_key_seqno {
            return Err(AdapterError::ConsensusRule {
                rule: "TON Masterchain mc_seqno must exceed active key_block_seqno".into(),
            });
        }
        if mc.gen_utime < cur_since || mc.gen_utime >= cur_until {
            return Err(AdapterError::ConsensusRule {
                rule: "TON Masterchain gen_utime falls outside active key-block cycle".into(),
            });
        }
        if mc.mc_state_root == [0u8; 32] || mc.shard_hashes_root == [0u8; 32] {
            return Err(AdapterError::ConsensusRule {
                rule: "TON Masterchain state_root and shard_hashes_root must be non-zero".into(),
            });
        }
        let expected_root = mc.compute_root_hash(&self.network, &active_vhash);
        if !bool::from(mc.root_hash.ct_eq(&expected_root)) {
            return Err(AdapterError::ConsensusRule {
                rule: "TON Masterchain root_hash mismatch".into(),
            });
        }
        let expected_file = mc.compute_file_hash(&mc.root_hash);
        if !bool::from(mc.file_hash.ct_eq(&expected_file)) {
            return Err(AdapterError::ConsensusRule {
                rule: "TON Masterchain file_hash mismatch".into(),
            });
        }

        // 3. Determine attested root (Masterchain or verified dynamic Shardchain).
        let (state_root, tx_root, event_root, block_hash) =
            if let Some(shard) = &decoded.target_shard {
                verify_shard_proof(shard, &mc.shard_hashes_root)?;
                (
                    shard.state_root,
                    shard.tx_root,
                    shard.event_root,
                    shard.file_hash,
                )
            } else {
                (
                    mc.mc_state_root,
                    mc.mc_tx_root,
                    mc.mc_event_root,
                    mc.root_hash,
                )
            };

        if policy.require_declared_match {
            if evidence.declared_height != mc.mc_seqno {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if !bool::from(evidence.declared_root.ct_eq(&state_root)) {
                return Err(AdapterError::DeclarationMismatch {
                    field: "state_root",
                });
            }
        }
        let need_depth = policy.min_depth.max(self.descriptor.required_depth);
        if CATCHAIN_COMMIT_DEPTH < need_depth {
            return Err(AdapterError::InsufficientDepth {
                observed: CATCHAIN_COMMIT_DEPTH,
                required: need_depth,
            });
        }
        if policy.max_age > 0 && policy.now > mc.mc_seqno {
            let age = policy.now.saturating_sub(mc.mc_seqno);
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        // 4. Verify Catchain BFT session >2/3 stake commit signatures.
        let cc_msg = catchain_commit_sign_bytes(
            &self.network,
            mc.catchain_seqno,
            &active_vhash,
            mc.mc_seqno,
            &mc.root_hash,
            &mc.file_hash,
        );
        let (cc_signers, cc_pq) = verify_catchain_quorum(
            &active_map,
            active_total,
            &decoded.catchain_sigs,
            &cc_msg,
            "TON Catchain commit",
        )?;
        all_pq &= cc_pq;

        let scheme = if all_pq {
            ObservedScheme::Scheme(SchemeId::ML_DSA_65)
        } else {
            ObservedScheme::Scheme(SchemeId::ED25519)
        };
        let attestation = FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &evidence.network),
            height: mc.mc_seqno,
            state_root,
            attested_block_hash: Some(block_hash),
            attested_event_root: (event_root != [0u8; 32]).then_some(event_root),
            attested_tx_root: (tx_root != [0u8; 32]).then_some(tx_root),
            finalized_at: mc.mc_seqno,
            time_unit: TimeUnit::Height,
            security: SecurityBacking::SignatureSet {
                scheme,
                signers: cc_signers,
                required: min_supermajority_weight(active_total),
                total_weight: active_total,
                slashable: true,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
        };
        Ok((attestation, all_pq))
    }
}

impl ExternalFinalityAdapter for TonCatchainAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
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
        let (att, all_pq) = self.verify_inner(evidence, policy)?;
        observer.observe(ObservedScheme::Scheme(SchemeId::ED25519));
        if all_pq {
            observer.observe(ObservedScheme::Scheme(SchemeId::ML_DSA_65));
        }
        Ok(att)
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        vec![
            FaultProbe {
                name: "refuses unsupported TON Catchain evidence version".into(),
                patch: BytePatch::EvidenceVersion { value: 4 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "refuses foreign TON network".into(),
                patch: BytePatch::Network {
                    value: format!("{}-other", self.network),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses mismatched declared Masterchain seqno".into(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses mismatched declared shard state root".into(),
                patch: BytePatch::DeclaredRoot { value: [0xEE; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses corrupted TON payload magic".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: vec![0xAA, 0x55],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses excessive TON rotation count length prefix".into(),
                patch: BytePatch::InPayload {
                    offset: 8,
                    bytes: vec![0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses truncated TON Catchain payload".into(),
                patch: BytePatch::TruncatePayload { keep: 5 },
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
    use crate::cross_domain::external::selftest::admit;
    use crate::crypto::facts::CryptoFacts;
    use crate::crypto::primitives::{KeyPair, PqKeyPair};

    struct TonTestKey {
        ed: KeyPair,
        pq: PqKeyPair,
        weight: u64,
    }

    impl TonTestKey {
        fn new(seed: u8, weight: u64) -> Self {
            Self {
                ed: KeyPair::from_seed(&[seed; 32]).unwrap(),
                pq: PqKeyPair::generate(),
                weight,
            }
        }

        fn validator(&self) -> TonValidator {
            TonValidator {
                ed25519_pubkey: self.ed.public_key_bytes(),
                weight: self.weight,
                pq_pubkey: self.pq.public_key_bytes().to_vec(),
            }
        }

        fn sign(&self, msg: &Hash32) -> CatchainSig {
            CatchainSig {
                signer_pubkey: self.ed.public_key_bytes(),
                ed25519_sig: self.ed.sign(msg).to_vec(),
                pq_sig: self
                    .pq
                    .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, msg)
                    .unwrap(),
            }
        }
    }

    fn build_rotated_shard_fixture() -> (
        PinnedTonMasterchainAnchor,
        Vec<TonTestKey>,
        TonCatchainEvidence,
        RawConsensusEvidence,
    ) {
        let net = "ton-mainnet";
        let gen0 = [
            TonTestKey::new(11, 40),
            TonTestKey::new(12, 35),
            TonTestKey::new(13, 25),
        ];
        let gen1 = vec![
            TonTestKey::new(21, 30),
            TonTestKey::new(22, 30),
            TonTestKey::new(23, 25),
            TonTestKey::new(24, 15),
        ];
        let pinned = PinnedTonMasterchainAnchor {
            key_block_seqno: 1_000,
            utime_since: 10_000,
            utime_until: 20_000,
            validators: gen0.iter().map(TonTestKey::validator).collect(),
        };
        let next_vals: Vec<TonValidator> = gen1.iter().map(TonTestKey::validator).collect();
        let next_vhash = compute_validator_list_hash(19_500, 30_000, &next_vals);
        let rot_msg = key_block_rotation_sign_bytes(net, 1_000, 2_000, 19_500, 30_000, &next_vhash);
        // gen0[0] + gen0[1] = 75/100 > 2/3.
        let rotation = KeyBlockRotation {
            new_key_block_seqno: 2_000,
            utime_since: 19_500,
            utime_until: 30_000,
            next_validators: next_vals,
            next_validator_list_hash: next_vhash,
            prev_committee_sigs: vec![gen0[0].sign(&rot_msg), gen0[1].sign(&rot_msg)],
        };

        // Split basechain (workchain 0) SHARD_PREFIX_FULL -> (0x4000.., 0xC000..).
        let (left_prefix, right_prefix) = split_shard_prefix(SHARD_PREFIX_FULL).unwrap();
        let mut left_shard = TonShardProof {
            workchain_id: 0,
            shard_prefix: left_prefix,
            shard_seqno: 88_001,
            state_root: [0x51; 32],
            tx_root: [0x52; 32],
            event_root: [0x53; 32],
            file_hash: [0x54; 32],
            leaf_index: 0,
            merkle_siblings: Vec::new(),
            co_active_prefixes: vec![right_prefix],
            topology_step: SplitMergeTransition::SplitFrom {
                parent_prefix: SHARD_PREFIX_FULL,
            },
        };
        let right_leaf = [0x9A; 32];
        left_shard.merkle_siblings = vec![right_leaf];
        let shard_hashes_root = shard_merkle_node(&shard_descr_leaf(&left_shard), &right_leaf);

        let mut mc = TonMasterchainBlock {
            key_block_seqno: 2_000,
            catchain_seqno: 77,
            mc_seqno: 2_050,
            gen_utime: 22_000,
            prev_root_hash: [0x11; 32],
            mc_state_root: [0x22; 32],
            mc_tx_root: [0x33; 32],
            mc_event_root: [0x44; 32],
            shard_hashes_root,
            root_hash: [0; 32],
            file_hash: [0; 32],
        };
        mc.root_hash = mc.compute_root_hash(net, &next_vhash);
        mc.file_hash = mc.compute_file_hash(&mc.root_hash);

        let cc_msg =
            catchain_commit_sign_bytes(net, 77, &next_vhash, 2_050, &mc.root_hash, &mc.file_hash);
        let catchain_sigs = vec![
            gen1[0].sign(&cc_msg),
            gen1[1].sign(&cc_msg),
            gen1[2].sign(&cc_msg),
        ];

        let bundle = TonCatchainEvidence {
            rotations: vec![rotation],
            masterchain: mc,
            catchain_sigs,
            target_shard: Some(left_shard),
        };
        let payload = encode_ton_evidence(&bundle).unwrap();
        let ev = RawConsensusEvidence {
            adapter: AdapterId::from_name(ADAPTER_NAME),
            evidence_version: EVIDENCE_VERSION,
            network: net.into(),
            payload,
            declared_height: 2_050,
            declared_root: [0x51; 32],
            submitter: Address::from([0x07; 32]),
        };
        (pinned, gen1, bundle, ev)
    }

    #[test]
    fn ton_keyblock_rotation_and_split_shard_passes_selftest_with_hybrid_pq() {
        let (pinned, _, _, golden) = build_rotated_shard_fixture();
        let adapter =
            TonCatchainAdapter::new("ton-mainnet", Some(pinned)).with_golden(golden.clone());
        let policy = VerificationPolicy {
            min_depth: 1,
            require_declared_match: true,
            max_age: 100,
            now: 2_060,
            require_slashable: true,
        };

        let mut facts = CryptoFacts::default();
        let att = adapter
            .verify_observed(&golden, &policy, &mut facts)
            .unwrap();
        assert_eq!(att.height, 2_050);
        assert_eq!(att.state_root, [0x51; 32]);
        assert_eq!(att.attested_tx_root, Some([0x52; 32]));
        assert_eq!(att.attested_event_root, Some([0x53; 32]));
        assert_eq!(facts.count(ObservedScheme::Scheme(SchemeId::ED25519)), 1);
        assert_eq!(facts.count(ObservedScheme::Scheme(SchemeId::ML_DSA_65)), 1);

        let report = admit(&adapter, &policy);
        assert!(
            report.admitted,
            "TON Catchain selftest failed: {:?}",
            report.probes
        );
    }

    #[test]
    fn overlapping_shards_bad_merge_expired_keyblock_and_unrotated_sigs_fail_closed() {
        let (pinned, _, mut bundle, mut ev) = build_rotated_shard_fixture();
        let adapter = TonCatchainAdapter::new("ton-mainnet", Some(pinned));
        let policy = VerificationPolicy {
            min_depth: 1,
            require_declared_match: true,
            max_age: 100,
            now: 2_060,
            require_slashable: true,
        };

        // 1. Overlapping parent shard SHARD_PREFIX_FULL alongside child 0x4000.. is refused.
        let shard = bundle.target_shard.as_mut().unwrap();
        let orig_co = shard.co_active_prefixes.clone();
        shard.co_active_prefixes.push(SHARD_PREFIX_FULL);
        ev.payload = encode_ton_evidence(&bundle).unwrap();
        assert!(matches!(
            adapter.verify(&ev, &policy),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("overlapping TON shard")
        ));
        bundle.target_shard.as_mut().unwrap().co_active_prefixes = orig_co;

        // 2. Invalid MergedFrom children (wrong sibling pair) are refused.
        let orig_tr = bundle.target_shard.as_ref().unwrap().topology_step.clone();
        bundle.target_shard.as_mut().unwrap().topology_step = SplitMergeTransition::MergedFrom {
            left_child_prefix: 1u64 << 61,
            right_child_prefix: 7u64 << 61,
        };
        ev.payload = encode_ton_evidence(&bundle).unwrap();
        assert!(matches!(
            adapter.verify(&ev, &policy),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("MergedFrom")
        ));
        bundle.target_shard.as_mut().unwrap().topology_step = orig_tr;

        // 3. Stripping ML-DSA-65 co-signature from key-block rotation vote fails closed.
        let saved_pq = std::mem::take(&mut bundle.rotations[0].prev_committee_sigs[0].pq_sig);
        ev.payload = encode_ton_evidence(&bundle).unwrap();
        assert!(matches!(
            adapter.verify(&ev, &policy),
            Err(AdapterError::Crypto { .. })
        ));
        bundle.rotations[0].prev_committee_sigs[0].pq_sig = saved_pq;

        // 4. Key-block rotation with <= 2/3 stake (only 40/100) fails closed.
        bundle.rotations[0].prev_committee_sigs.truncate(1);
        ev.payload = encode_ton_evidence(&bundle).unwrap();
        assert!(matches!(
            adapter.verify(&ev, &policy),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("2/3")
        ));
    }

    #[test]
    fn registry_lifecycle_contradiction_slash_and_pq_cosig_tracking() {
        use crate::cross_domain::external::{
            ChallengeReward, DomainEconomics, DomainState, ExternalDomainRegistry, VersionPolicy,
        };

        let (pinned, gen1, mut bundle_b, ev_a) = build_rotated_shard_fixture();
        let prover = ev_a.submitter;
        let challenger = Address::from([0x96; 32]);

        // Equivocating Catchain Masterchain commit by rotated gen1 supermajority at mc_seqno 2050.
        let next_vhash = bundle_b.rotations[0].next_validator_list_hash;
        bundle_b.target_shard = None;
        bundle_b.masterchain.mc_state_root = [0xDE; 32];
        bundle_b.masterchain.root_hash = bundle_b
            .masterchain
            .compute_root_hash("ton-mainnet", &next_vhash);
        bundle_b.masterchain.file_hash = bundle_b
            .masterchain
            .compute_file_hash(&bundle_b.masterchain.root_hash);
        let cc_msg = catchain_commit_sign_bytes(
            "ton-mainnet",
            77,
            &next_vhash,
            2_050,
            &bundle_b.masterchain.root_hash,
            &bundle_b.masterchain.file_hash,
        );
        bundle_b.catchain_sigs = gen1[0..3].iter().map(|v| v.sign(&cc_msg)).collect();
        let mut ev_b = ev_a.clone();
        ev_b.declared_root = [0xDE; 32];
        ev_b.submitter = challenger;
        ev_b.payload = encode_ton_evidence(&bundle_b).unwrap();

        let adapter =
            TonCatchainAdapter::new("ton-mainnet", Some(pinned)).with_golden(ev_a.clone());
        let policy = VerificationPolicy {
            min_depth: 1,
            require_declared_match: true,
            max_age: 1_000,
            now: 2_060,
            require_slashable: true,
        };
        let admission = admit(&adapter, &policy);
        assert!(admission.admitted);

        let econ = DomainEconomics {
            routing_ceiling_atoms: 1_000_000,
            challenge: ChallengeReward {
                bps_of_slash: 1_000,
                floor_atoms: 0,
            },
            ..DomainEconomics::default()
        };
        let req_bond = econ.required_bond_atoms();
        let mut registry = ExternalDomainRegistry::new();
        let domain = registry
            .register(
                "ton-mainnet",
                adapter.descriptor(),
                econ,
                VersionPolicy::single(adapter.descriptor().id, EVIDENCE_VERSION, 0),
                &admission,
                req_bond,
                prover,
            )
            .unwrap();
        registry.bond_prover(&domain, challenger, req_bond).unwrap();

        let att = registry.submit(&adapter, &ev_a, &policy).unwrap();
        assert_eq!(
            registry
                .domain(&domain)
                .unwrap()
                .record
                .crypto_facts
                .count(ObservedScheme::Scheme(SchemeId::ML_DSA_65)),
            1
        );

        let conflict = adapter.verify(&ev_b, &policy).unwrap();
        assert_eq!(conflict.height, att.height);
        assert_ne!(conflict.state_root, att.state_root);
        assert!(registry.submit(&adapter, &ev_b, &policy).is_err());
        registry
            .mark_faulted(&domain, "TON Catchain equivocation proof")
            .unwrap();
        assert_eq!(
            registry.domain(&domain).unwrap().record.state,
            DomainState::Faulted
        );
        let (slashed, reward) = registry
            .slash(
                &domain,
                prover,
                att.evidence_digest,
                econ.routing_ceiling_atoms,
                challenger,
            )
            .unwrap();
        assert!(slashed > 0 && reward > 0 && reward <= slashed);
        assert!(!registry
            .domain(&domain)
            .unwrap()
            .attestations
            .contains_key(&(att.height, EVIDENCE_VERSION)));
    }
}
