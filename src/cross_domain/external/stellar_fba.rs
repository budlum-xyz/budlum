//! Federated Byzantine Agreement / Stellar Consensus Protocol (`Mazieres 2015`)
//! external finality adapter with quorum-intersection and `EXTERNALIZE` closure.
//!
//! Unlike closed-committee BFT protocols that share one global validator table,
//! an FBA system (`SCP`, SOSP 2019) lets each validator `v` declare its own
//! hierarchical [`ScpQuorumSet`] specifying threshold slices over peer nodes
//! and nested inner sets. Safety holds if and only if every pair of quorums
//! intersects (`Mazieres Theorem 1`), and slot `i` reaches irreversible
//! finality when a valid quorum `U` emits signed `SCPStatementExternalize`
//! envelopes for the same ledger header.
//!
//! This adapter enforces all six FBA/SCP soundness rules:
//!
//! 1. **Bounded recursive `QuorumSet` discipline**: depth `<= 4`, total
//!    validator references `<= 64`, strictly sorted unique validators at every
//!    level, and `1 <= threshold <= validators.len() + inner_sets.len()`.
//! 2. **Exact FBAS Quorum Intersection check**: over the governance-pinned top
//!    tier (`<= 16` core validators), enumerates every inclusion-minimal quorum
//!    within a deterministic work ceiling and verifies both non-vacuity (at
//!    least one quorum exists) and pairwise intersection (`Q1 & Q2 != empty`
//!    for all pairs). Split-brain configurations with disjoint quorums are
//!    refused fail-closed before any signature is accepted.
//! 3. **Transitive `EXTERNALIZE` quorum closure**: let `U` be the distinct
//!    pinned nodes signing valid `EXTERNALIZE` envelopes for `(ledger_seq,
//!    ledger_header_hash)`. Every node `v in U` must have its own pinned
//!    [`ScpQuorumSet`] recursively satisfied by `U`, guaranteeing `U` is a
//!    complete closed FBA quorum that intersects every other quorum.
//! 4. **Self-derived ledger & ballot integrity**: `ledger_header_hash` commits
//!    `(network_id_hash, ledger_seq, close_time_secs, prev_ledger_hash,
//!    state_root, tx_set_hash, event_root, base_fee_stroops)`, and every
//!    envelope carries `1 <= commit_counter <= highest_counter` plus a
//!    constant-time matching `quorum_set_hash`.
//! 5. **Hybrid post-quantum non-downgrade**: every node with a registered
//!    ML-DSA-65 public key MUST attach a valid ML-DSA-65 co-signature under
//!    [`crate::crypto::ctx::CROSS_DOMAIN_V1`].
//! 6. **Honest economic disclosure**: native FBA/SCP relies on federated trust
//!    without in-protocol stake slashing, so `SecurityBacking::SignatureSet`
//!    reports `slashable: pinned.has_bonded_slash_escrow` (callers requiring
//!    protocol slashing refuse bare federated tiers automatically, while
//!    Budlum's bonded prover remains slashable on contradiction).
//!
//! WIRING: implements `ExternalFinalityAdapter` for `ExternalDomainRegistry`
//! admission/submission/slashing; `AdapterSpec` tag append joins `intake.rs`
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

const ADAPTER_NAME: &str = "stellar-scp-v1";
const ADAPTER_VERSION: u32 = 1;
const EVIDENCE_VERSION: u32 = 1;
const SCP_EXTERNALIZE_DEPTH: u64 = 1;

const PAYLOAD_MAGIC: &[u8; 8] = b"BDLMSC01";
const MAX_SCP_PAYLOAD_BYTES: usize = 512 * 1024;
/// Maximum pinned top-tier size so exact subset quorum-intersection checking
/// completes in at most `2^16 = 65_536` bitmask steps deterministically.
const MAX_SCP_TIER_NODES: usize = 16;
const MAX_SCP_QSET_DEPTH: usize = 4;
const MAX_SCP_QSET_REFS: usize = 64;

/// Recursive Stellar XDR-equivalent `SCPQuorumSet`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScpQuorumSet {
    /// Minimum number of entries (`validators` + satisfied `inner_sets`) needed
    /// to satisfy this slice (`1..=validators.len() + inner_sets.len()`).
    pub threshold: u32,
    /// Strictly ascending distinct Ed25519 `NodeID`s directly in this set.
    pub validators: Vec<[u8; 32]>,
    /// Nested inner quorum sets (bounded to depth `<= 4`).
    pub inner_sets: Vec<Self>,
}

impl ScpQuorumSet {
    /// Canonical domain-separated digest of this `SCPQuorumSet`.
    #[must_use]
    pub fn hash(&self) -> Hash32 {
        let mut acc = crate::core::hash::hash_fields_bytes(&[
            b"BDLM_SCP_QSET_V1",
            &self.threshold.to_le_bytes(),
            &(self.validators.len() as u64).to_le_bytes(),
            &(self.inner_sets.len() as u64).to_le_bytes(),
        ]);
        for v in &self.validators {
            acc = crate::core::hash::hash_fields_bytes(&[b"BDLM_SCP_QSET_V1", b"V", &acc, v]);
        }
        for inner in &self.inner_sets {
            let child = inner.hash();
            acc = crate::core::hash::hash_fields_bytes(&[b"BDLM_SCP_QSET_V1", b"I", &acc, &child]);
        }
        acc
    }

    fn validate(
        &self,
        depth: usize,
        known_nodes: &BTreeMap<[u8; 32], usize>,
        total_refs: &mut usize,
    ) -> Result<(), AdapterError> {
        if depth > MAX_SCP_QSET_DEPTH {
            return Err(AdapterError::ConsensusRule {
                rule: format!("SCP QuorumSet nesting depth exceeds {MAX_SCP_QSET_DEPTH}"),
            });
        }
        let entries = self.validators.len().saturating_add(self.inner_sets.len());
        if self.threshold == 0 || usize::try_from(self.threshold).is_ok_and(|t| t > entries) {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "SCP QuorumSet threshold {} outside 1..={entries}",
                    self.threshold
                ),
            });
        }
        let mut prev: Option<[u8; 32]> = None;
        for &v in &self.validators {
            *total_refs = total_refs.saturating_add(1);
            if *total_refs > MAX_SCP_QSET_REFS {
                return Err(AdapterError::ConsensusRule {
                    rule: format!("SCP QuorumSet references exceed {MAX_SCP_QSET_REFS}"),
                });
            }
            if prev.is_some_and(|p| v <= p) {
                return Err(AdapterError::ConsensusRule {
                    rule: "SCP QuorumSet validators must be strictly ascending and unique".into(),
                });
            }
            if !known_nodes.contains_key(&v) {
                return Err(AdapterError::ConsensusRule {
                    rule: "SCP QuorumSet references an unpinned validator NodeID".into(),
                });
            }
            prev = Some(v);
        }
        for inner in &self.inner_sets {
            inner.validate(depth.saturating_add(1), known_nodes, total_refs)?;
        }
        Ok(())
    }

    #[must_use]
    fn satisfied_by_mask(&self, mask: u32, node_index: &BTreeMap<[u8; 32], usize>) -> bool {
        let mut met = 0u32;
        for v in &self.validators {
            if let Some(&idx) = node_index.get(v) {
                if (mask & (1u32 << idx)) != 0 {
                    met = met.saturating_add(1);
                }
            }
        }
        for inner in &self.inner_sets {
            if inner.satisfied_by_mask(mask, node_index) {
                met = met.saturating_add(1);
            }
        }
        met >= self.threshold
    }
}

/// One validator node in a governance-pinned FBA/SCP top tier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScpValidatorNode {
    /// Classical Ed25519 `NodeID` (32 bytes).
    pub ed25519_pubkey: [u8; 32],
    /// This validator's declared [`ScpQuorumSet`].
    pub quorum_set: ScpQuorumSet,
    /// Optional ML-DSA-65 post-quantum public key enforced on every
    /// `SCPStatementExternalize` envelope from this node.
    #[serde(default)]
    pub pq_pubkey: Vec<u8>,
}

/// Governance-pinned FBA/SCP top tier and network passphrase binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedScpTier {
    /// Canonical Stellar network passphrase hashed into every signing root.
    pub network_passphrase: String,
    /// True only when every tier validator is backed by an active external
    /// slashable bond escrow; `false` for bare reputation-backed Stellar SCP.
    pub has_bonded_slash_escrow: bool,
    /// Pinned top-tier validators (`1..=16`) whose `QuorumSet`s must enjoy
    /// strict pairwise quorum intersection.
    pub nodes: Vec<ScpValidatorNode>,
}

impl PinnedScpTier {
    /// Canonical length-prefixed SHA3-256 commitment over the network
    /// passphrase, slash-escrow flag, and every pinned node's `NodeID`,
    /// `QuorumSet` commitment, and ML-DSA-65 co-signing key.
    ///
    /// WIRING: checked in constant time by `crate::cross_domain::economic_guard`
    /// on both backing refreshes and contradiction submissions.
    #[must_use]
    pub fn canonical_pin_digest(&self) -> Hash32 {
        let mut acc = crate::core::hash::hash_fields_bytes(&[
            b"BDLM_SCP_PIN_V1",
            self.network_passphrase.as_bytes(),
            &[u8::from(self.has_bonded_slash_escrow)],
            &(self.nodes.len() as u64).to_le_bytes(),
        ]);
        for node in &self.nodes {
            let qhash = node.quorum_set.hash();
            acc = crate::core::hash::hash_fields_bytes(&[
                b"BDLM_SCP_PIN_V1",
                &[1u8],
                &acc,
                &node.ed25519_pubkey,
                &qhash,
                &node.pq_pubkey,
            ]);
        }
        acc
    }

    /// Return `(bonded_unit_weight, has_pq_key)` for `node_id` in this tier.
    ///
    /// WIRING: used by `crate::cross_domain::economic_guard` for incremental
    /// per-offender Stellar SCP slashing accounting.
    #[must_use]
    pub fn node_member_info(&self, node_id: &[u8; 32]) -> Option<(u128, bool)> {
        self.nodes
            .iter()
            .find(|n| bool::from(n.ed25519_pubkey.ct_eq(node_id)))
            .map(|n| {
                let unit = u128::from(self.has_bonded_slash_escrow);
                (unit, !n.pq_pubkey.is_empty())
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ScpLedgerHeader {
    ledger_seq: u64,
    close_time_secs: u64,
    prev_ledger_hash: Hash32,
    state_root: Hash32,
    tx_set_hash: Hash32,
    event_root: Hash32,
    base_fee_stroops: u32,
    header_hash: Hash32,
}

impl ScpLedgerHeader {
    #[must_use]
    fn compute_hash(&self, network_id_hash: &Hash32) -> Hash32 {
        crate::core::hash::hash_fields_bytes(&[
            b"BDLM_SCP_LEDGER_V1",
            network_id_hash,
            &self.ledger_seq.to_le_bytes(),
            &self.close_time_secs.to_le_bytes(),
            &self.prev_ledger_hash,
            &self.state_root,
            &self.tx_set_hash,
            &self.event_root,
            &self.base_fee_stroops.to_le_bytes(),
        ])
    }
}

/// Signed `SCPStatementExternalize` envelope emitted by a pinned SCP validator.
///
/// WIRING: verified by [`StellarScpAdapter`] and
/// [`verify_stellar_ballot_equivocation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScpExternalizeEnvelope {
    /// Validator Ed25519 `NodeID` (32 bytes).
    pub node_id: [u8; 32],
    /// Ballot counter at which the node committed the value (`>= 1`).
    pub commit_counter: u32,
    /// Highest ballot counter observed when externalizing (`>= commit_counter`).
    pub highest_counter: u32,
    /// Declared `QuorumSet` commitment (`ScpQuorumSet::hash()`).
    pub quorum_set_hash: Hash32,
    /// Detached Ed25519 signature over [`externalize_sign_bytes`].
    pub ed25519_sig: Vec<u8>,
    /// Mandatory ML-DSA-65 co-signature when `pq_pubkey` is configured.
    #[serde(default)]
    pub pq_sig: Vec<u8>,
}

/// Permissionless SCP ballot equivocation proof demonstrating that one or more
/// pinned top-tier nodes externalized two distinct ledger header hashes at the
/// same `slot_index` (an unconditional safety fault in Mazieres SCP).
///
/// WIRING: verified in production by [`verify_stellar_ballot_equivocation`] via
/// `crate::cross_domain::economic_guard::BridgeEconomicGuard::submit_contradiction`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StellarBallotEquivocationProof {
    /// Ledger slot index at which both conflicting values were externalized (`> 0`).
    pub slot_index: u64,
    /// First externalized ledger header hash (non-zero).
    pub ledger_header_hash_a: Hash32,
    /// Signed externalize envelopes attesting `ledger_header_hash_a`.
    pub envelopes_a: Vec<ScpExternalizeEnvelope>,
    /// Second conflicting externalized ledger header hash (non-zero, `!= a`).
    pub ledger_header_hash_b: Hash32,
    /// Signed externalize envelopes attesting `ledger_header_hash_b`.
    pub envelopes_b: Vec<ScpExternalizeEnvelope>,
}

/// Verified outcome of [`verify_stellar_ballot_equivocation`].
///
/// WIRING: consumed by `crate::cross_domain::economic_guard` when freezing a
/// faulted FBA/SCP domain and recording proven equivocating top-tier nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedStellarSlash {
    /// Canonical order-independent digest of the proven SCP equivocation.
    pub evidence_digest: Hash32,
    /// Slot index at which the conflicting `EXTERNALIZE` envelopes were signed.
    pub slot_index: u64,
    /// Sorted unique Ed25519 `NodeID`s of proven equivocating tier nodes.
    pub offenders: Vec<[u8; 32]>,
    /// Bonded slashable node count (`offenders.len()` when
    /// `pinned.has_bonded_slash_escrow`, otherwise `0`).
    pub slashed_bonded_nodes: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ScpFinalityEvidence {
    ledger: ScpLedgerHeader,
    envelopes: Vec<ScpExternalizeEnvelope>,
}

/// Compute the canonical SCP network identifier hash for `(network, passphrase)`.
///
/// WIRING: shared between [`StellarScpAdapter`] and
/// [`verify_stellar_ballot_equivocation`].
#[must_use]
pub fn compute_network_id_hash(network: &str, passphrase: &str) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_SCP_NET_V1",
        network.as_bytes(),
        passphrase.as_bytes(),
    ])
}

/// Compute the canonical signing digest for an `SCPStatementExternalize`
/// envelope.
///
/// WIRING: shared between [`StellarScpAdapter`] and
/// [`verify_stellar_ballot_equivocation`].
#[must_use]
pub fn externalize_sign_bytes(
    network_id_hash: &Hash32,
    slot_index: u64,
    commit_counter: u32,
    highest_counter: u32,
    ledger_header_hash: &Hash32,
    quorum_set_hash: &Hash32,
) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_SCP_EXTERNALIZE_V1",
        network_id_hash,
        &slot_index.to_le_bytes(),
        &commit_counter.to_le_bytes(),
        &highest_counter.to_le_bytes(),
        ledger_header_hash,
        quorum_set_hash,
    ])
}

/// True iff non-empty subset `mask` is a closed FBA quorum: every member `v` in
/// `mask` has its own `QuorumSet` satisfied by `mask`.
#[must_use]
fn is_closed_quorum(
    mask: u32,
    nodes: &[ScpValidatorNode],
    node_index: &BTreeMap<[u8; 32], usize>,
) -> bool {
    if mask == 0 {
        return false;
    }
    for (idx, node) in nodes.iter().enumerate() {
        if (mask & (1u32 << idx)) != 0 && !node.quorum_set.satisfied_by_mask(mask, node_index) {
            return false;
        }
    }
    true
}

/// Verify Mazieres Quorum Intersection across all inclusion-minimal quorums of
/// `nodes` and return the smallest valid quorum cardinality.
fn verify_fbas_quorum_intersection(
    nodes: &[ScpValidatorNode],
    node_index: &BTreeMap<[u8; 32], usize>,
) -> Result<u64, AdapterError> {
    let n = nodes.len();
    let total_masks = 1u32 << n;
    let mut minimal_quorums: Vec<u32> = Vec::new();
    let mut min_size = u32::MAX;

    for mask in 1u32..total_masks {
        if minimal_quorums.iter().any(|&q| (mask | q) == mask) {
            continue;
        }
        if is_closed_quorum(mask, nodes, node_index) {
            // Check intersection against every previously discovered minimal quorum.
            if minimal_quorums.iter().any(|&other| (mask & other) == 0) {
                return Err(AdapterError::ConsensusRule {
                    rule: "SCP tier violates FBA quorum intersection: disjoint quorums exist"
                        .into(),
                });
            }
            min_size = min_size.min(mask.count_ones());
            minimal_quorums.push(mask);
        }
    }

    if minimal_quorums.is_empty() {
        return Err(AdapterError::ConsensusRule {
            rule: "SCP tier contains zero satisfiable closed quorums".into(),
        });
    }
    Ok(u64::from(min_size))
}

#[cfg(test)]
fn encode_scp_evidence(bundle: &ScpFinalityEvidence) -> Result<Vec<u8>, String> {
    let body = bincode::serialize(bundle).map_err(|e| format!("stellar-scp encode failed: {e}"))?;
    let total = PAYLOAD_MAGIC.len().saturating_add(body.len());
    if total > MAX_SCP_PAYLOAD_BYTES {
        return Err(format!(
            "stellar-scp payload {total} exceeds ceiling {MAX_SCP_PAYLOAD_BYTES}"
        ));
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_scp_evidence(payload: &[u8]) -> Result<ScpFinalityEvidence, AdapterError> {
    if payload.len() < PAYLOAD_MAGIC.len() {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "SCP payload shorter than 8-byte magic prefix".into(),
        });
    }
    if payload.len() > MAX_SCP_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_SCP_PAYLOAD_BYTES,
            reason: format!("SCP payload exceeds {MAX_SCP_PAYLOAD_BYTES} bytes"),
        });
    }
    if payload.get(0..8) != Some(PAYLOAD_MAGIC.as_slice()) {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "SCP payload magic mismatch".into(),
        });
    }
    let body = payload.get(8..).ok_or_else(|| AdapterError::Malformed {
        offset: 8,
        reason: "missing SCP payload body".into(),
    })?;
    let decoded =
        crate::network::bounded_bincode::decode_bounded_bincode(body, MAX_SCP_PAYLOAD_BYTES)
            .map_err(|e| AdapterError::Malformed {
                offset: 8,
                reason: format!("invalid SCP EXTERNALIZE evidence: {e}"),
            })?;
    if bincode::serialized_size(&decoded).ok() != u64::try_from(body.len()).ok() {
        return Err(AdapterError::Malformed {
            offset: 8,
            reason: "trailing bytes after canonical SCP EXTERNALIZE evidence".into(),
        });
    }
    Ok(decoded)
}

fn verify_scp_slash_side(
    pinned: &PinnedScpTier,
    node_index: &BTreeMap<[u8; 32], usize>,
    net_hash: &Hash32,
    slot_index: u64,
    ledger_hash: &Hash32,
    envelopes: &[ScpExternalizeEnvelope],
    what: &str,
) -> Result<BTreeSet<[u8; 32]>, AdapterError> {
    if envelopes.is_empty() || envelopes.len() > pinned.nodes.len() {
        return Err(AdapterError::ConsensusRule {
            rule: format!("invalid {what} envelope count {}", envelopes.len()),
        });
    }
    let mut seen = BTreeSet::new();
    for env in envelopes {
        if !seen.insert(env.node_id) {
            return Err(AdapterError::ConsensusRule {
                rule: format!("duplicate node envelope in {what}"),
            });
        }
        if env.commit_counter == 0 || env.highest_counter < env.commit_counter {
            return Err(AdapterError::ConsensusRule {
                rule: format!("invalid SCP ballot counters in {what}"),
            });
        }
        let Some(&idx) = node_index.get(&env.node_id) else {
            return Err(AdapterError::ConsensusRule {
                rule: format!("unknown SCP tier node in {what}"),
            });
        };
        let Some(node) = pinned.nodes.get(idx) else {
            return Err(AdapterError::ConsensusRule {
                rule: format!("unknown SCP tier node in {what}"),
            });
        };
        let expected_qhash = node.quorum_set.hash();
        if !bool::from(env.quorum_set_hash.ct_eq(&expected_qhash)) {
            return Err(AdapterError::ConsensusRule {
                rule: format!("SCP quorum_set_hash mismatch in {what}"),
            });
        }
        let msg = externalize_sign_bytes(
            net_hash,
            slot_index,
            env.commit_counter,
            env.highest_counter,
            ledger_hash,
            &expected_qhash,
        );
        crate::crypto::primitives::verify_signature(&msg, &env.ed25519_sig, &node.ed25519_pubkey)
            .map_err(|_| AdapterError::Crypto {
            what: format!("invalid Ed25519 signature in {what}"),
        })?;
        if !node.pq_pubkey.is_empty() {
            if env.pq_sig.is_empty() {
                return Err(AdapterError::Crypto {
                    what: format!("missing mandatory ML-DSA-65 co-signature in {what}"),
                });
            }
            crate::crypto::primitives::PqKeyPair::verify(
                &node.pq_pubkey,
                crate::crypto::ctx::CROSS_DOMAIN_V1,
                &msg,
                &env.pq_sig,
            )
            .map_err(|_| AdapterError::Crypto {
                what: format!("invalid ML-DSA-65 co-signature in {what}"),
            })?;
        }
    }
    Ok(seen)
}

/// Verify permissionless Stellar/FBA `SCPStatementExternalize` equivocation
/// evidence against a governance-pinned [`PinnedScpTier`].
///
/// WIRING: invoked in production by
/// `crate::cross_domain::economic_guard::BridgeEconomicGuard::submit_contradiction`.
///
/// # Errors
///
/// Returns [`AdapterError`] when the pinned tier violates Mazieres quorum
/// intersection, `slot_index == 0`, the externalized ledger hashes are zero or
/// equal, any ballot counter, `quorum_set_hash`, Ed25519 signature, or
/// mandatory ML-DSA-65 signature fails verification, or no node signed both.
pub fn verify_stellar_ballot_equivocation(
    network: &str,
    pinned: &PinnedScpTier,
    proof: &StellarBallotEquivocationProof,
) -> Result<VerifiedStellarSlash, AdapterError> {
    if network.trim().is_empty() {
        return Err(AdapterError::ConsensusRule {
            rule: "SCP equivocation network cannot be empty".into(),
        });
    }
    let (node_index, _min_quorum) = StellarScpAdapter::validate_tier(pinned)?;
    if proof.slot_index == 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "SCP equivocation slot_index must be positive".into(),
        });
    }
    if bool::from(proof.ledger_header_hash_a.ct_eq(&[0u8; 32]))
        || bool::from(proof.ledger_header_hash_b.ct_eq(&[0u8; 32]))
        || bool::from(
            proof
                .ledger_header_hash_a
                .ct_eq(&proof.ledger_header_hash_b),
        )
    {
        return Err(AdapterError::ConsensusRule {
            rule: "SCP equivocation requires two distinct non-zero ledger hashes".into(),
        });
    }
    let net_hash = compute_network_id_hash(network, &pinned.network_passphrase);
    let set_a = verify_scp_slash_side(
        pinned,
        &node_index,
        &net_hash,
        proof.slot_index,
        &proof.ledger_header_hash_a,
        &proof.envelopes_a,
        "scp-slash-a",
    )?;
    let set_b = verify_scp_slash_side(
        pinned,
        &node_index,
        &net_hash,
        proof.slot_index,
        &proof.ledger_header_hash_b,
        &proof.envelopes_b,
        "scp-slash-b",
    )?;
    let offenders: Vec<[u8; 32]> = set_a.intersection(&set_b).copied().collect();
    if offenders.is_empty() {
        return Err(AdapterError::ConsensusRule {
            rule: "SCP equivocation has no overlapping offending tier node".into(),
        });
    }
    let (lo_hash, hi_hash) = if proof.ledger_header_hash_a <= proof.ledger_header_hash_b {
        (&proof.ledger_header_hash_a, &proof.ledger_header_hash_b)
    } else {
        (&proof.ledger_header_hash_b, &proof.ledger_header_hash_a)
    };
    let slot_le = proof.slot_index.to_le_bytes();
    let count_le = (offenders.len() as u64).to_le_bytes();
    let mut fields: Vec<&[u8]> = Vec::with_capacity(offenders.len().saturating_add(6));
    fields.push(b"BDLM_SCP_SLASH_V1");
    fields.push(&net_hash);
    fields.push(&slot_le);
    fields.push(lo_hash);
    fields.push(hi_hash);
    fields.push(&count_le);
    for pk in &offenders {
        fields.push(pk);
    }
    let slashed = if pinned.has_bonded_slash_escrow {
        offenders.len() as u128
    } else {
        0
    };
    Ok(VerifiedStellarSlash {
        evidence_digest: crate::core::hash::hash_fields_bytes(&fields),
        slot_index: proof.slot_index,
        offenders,
        slashed_bonded_nodes: slashed,
    })
}

/// External finality adapter for Federated Byzantine Agreement / Stellar
/// Consensus Protocol (`SCP`) domains.
pub struct StellarScpAdapter {
    network: String,
    pinned: Option<PinnedScpTier>,
    golden: Option<RawConsensusEvidence>,
    descriptor: AdapterDescriptor,
}

impl StellarScpAdapter {
    /// Construct a `StellarScpAdapter` bound to `network` and its pinned
    /// FBA/SCP top tier.
    #[must_use]
    pub fn new(network: impl Into<String>, pinned: Option<PinnedScpTier>) -> Self {
        let network = network.into();
        let id = AdapterId::from_name(ADAPTER_NAME);
        let set_size = pinned.as_ref().map_or(0, |p| p.nodes.len() as u64);
        let finality_kind = if pinned.as_ref().is_some_and(|p| p.has_bonded_slash_escrow) {
            FinalityKind::EconomicFinality
        } else {
            FinalityKind::ProtocolFinality
        };
        let descriptor = AdapterDescriptor {
            id,
            name: ADAPTER_NAME.into(),
            adapter_version: ADAPTER_VERSION,
            accepted_evidence_versions: vec![EVIDENCE_VERSION],
            consensus_kind: "federated-bft-scp".into(),
            finality_kind,
            required_depth: SCP_EXTERNALIZE_DEPTH,
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

    fn validate_tier(
        pinned: &PinnedScpTier,
    ) -> Result<(BTreeMap<[u8; 32], usize>, u64), AdapterError> {
        if pinned.network_passphrase.trim().is_empty() {
            return Err(AdapterError::ConsensusRule {
                rule: "SCP network_passphrase cannot be empty".into(),
            });
        }
        if pinned.nodes.is_empty() || pinned.nodes.len() > MAX_SCP_TIER_NODES {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "SCP pinned tier size {} outside 1..={MAX_SCP_TIER_NODES}",
                    pinned.nodes.len()
                ),
            });
        }
        let mut node_index = BTreeMap::new();
        for (idx, node) in pinned.nodes.iter().enumerate() {
            if node.ed25519_pubkey == [0u8; 32] {
                return Err(AdapterError::ConsensusRule {
                    rule: "SCP validator NodeID cannot be all-zero".into(),
                });
            }
            if !node.pq_pubkey.is_empty() {
                crate::crypto::pq::validate_public_key(SchemeId::ML_DSA_65, &node.pq_pubkey)
                    .map_err(|_| AdapterError::ConsensusRule {
                        rule: "invalid ML-DSA-65 public key in pinned SCP tier".into(),
                    })?;
            }
            if node_index.insert(node.ed25519_pubkey, idx).is_some() {
                return Err(AdapterError::ConsensusRule {
                    rule: "duplicate validator NodeID in pinned SCP tier".into(),
                });
            }
        }
        for node in &pinned.nodes {
            let mut refs = 0usize;
            node.quorum_set.validate(0, &node_index, &mut refs)?;
        }
        let min_quorum = verify_fbas_quorum_intersection(&pinned.nodes, &node_index)?;
        Ok((node_index, min_quorum))
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
                    "SCP network mismatch: expected {}, got {}",
                    self.network, evidence.network
                ),
            });
        }
        let Some(pinned) = &self.pinned else {
            return Err(AdapterError::ConsensusRule {
                rule: "no governance-pinned SCP tier configured".into(),
            });
        };
        if policy.require_slashable && !pinned.has_bonded_slash_escrow {
            return Err(AdapterError::ConsensusRule {
                rule: "caller policy requires slashable backing; bare FBA/SCP is non-slashable without bonded slash escrow".into(),
            });
        }
        let (node_index, min_quorum) = Self::validate_tier(pinned)?;

        let decoded = decode_scp_evidence(&evidence.payload)?;
        let ledger = &decoded.ledger;

        if ledger.ledger_seq == 0
            || ledger.state_root == [0u8; 32]
            || ledger.tx_set_hash == [0u8; 32]
        {
            return Err(AdapterError::ConsensusRule {
                rule: "SCP ledger_seq, state_root, and tx_set_hash must be non-zero".into(),
            });
        }

        if policy.require_declared_match {
            if evidence.declared_height != ledger.ledger_seq {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if !bool::from(evidence.declared_root.ct_eq(&ledger.state_root)) {
                return Err(AdapterError::DeclarationMismatch {
                    field: "state_root",
                });
            }
        }
        let need_depth = policy.min_depth.max(self.descriptor.required_depth);
        if SCP_EXTERNALIZE_DEPTH < need_depth {
            return Err(AdapterError::InsufficientDepth {
                observed: SCP_EXTERNALIZE_DEPTH,
                required: need_depth,
            });
        }
        if policy.max_age > 0 {
            if ledger.ledger_seq > policy.now {
                return Err(AdapterError::Stale {
                    age: ledger.ledger_seq - policy.now,
                    max_age: policy.max_age,
                });
            }
            let age = policy.now - ledger.ledger_seq;
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        let net_hash = compute_network_id_hash(&self.network, &pinned.network_passphrase);
        let expected_header_hash = ledger.compute_hash(&net_hash);
        if !bool::from(ledger.header_hash.ct_eq(&expected_header_hash)) {
            return Err(AdapterError::ConsensusRule {
                rule: "SCP ledger header_hash does not match self-derived fields".into(),
            });
        }

        if decoded.envelopes.is_empty() || decoded.envelopes.len() > pinned.nodes.len() {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "SCP EXTERNALIZE envelope count {} outside 1..={}",
                    decoded.envelopes.len(),
                    pinned.nodes.len()
                ),
            });
        }

        let mut seen = BTreeSet::new();
        let mut signer_mask = 0u32;
        let mut all_pq = true;

        for env in &decoded.envelopes {
            if !seen.insert(env.node_id) {
                return Err(AdapterError::ConsensusRule {
                    rule: "duplicate NodeID in SCP EXTERNALIZE bundle".into(),
                });
            }
            if env.commit_counter == 0 || env.highest_counter < env.commit_counter {
                return Err(AdapterError::ConsensusRule {
                    rule: "invalid SCP EXTERNALIZE ballot counter bounds".into(),
                });
            }
            let Some(&idx) = node_index.get(&env.node_id) else {
                return Err(AdapterError::ConsensusRule {
                    rule: "SCP EXTERNALIZE signer is not in pinned tier".into(),
                });
            };
            let Some(node) = pinned.nodes.get(idx) else {
                return Err(AdapterError::ConsensusRule {
                    rule: "SCP pinned tier index out of bounds".into(),
                });
            };
            let expected_qhash = node.quorum_set.hash();
            if !bool::from(env.quorum_set_hash.ct_eq(&expected_qhash)) {
                return Err(AdapterError::ConsensusRule {
                    rule: "SCP EXTERNALIZE quorum_set_hash disagrees with pinned node QuorumSet"
                        .into(),
                });
            }
            let msg = externalize_sign_bytes(
                &net_hash,
                ledger.ledger_seq,
                env.commit_counter,
                env.highest_counter,
                &ledger.header_hash,
                &env.quorum_set_hash,
            );
            crate::crypto::primitives::verify_signature(
                &msg,
                &env.ed25519_sig,
                &node.ed25519_pubkey,
            )
            .map_err(|_| AdapterError::Crypto {
                what: "invalid Ed25519 signature on SCP EXTERNALIZE envelope".into(),
            })?;
            if node.pq_pubkey.is_empty() {
                all_pq = false;
            } else {
                if env.pq_sig.is_empty() {
                    return Err(AdapterError::Crypto {
                        what: "missing mandatory ML-DSA-65 co-signature on SCP EXTERNALIZE".into(),
                    });
                }
                crate::crypto::primitives::PqKeyPair::verify(
                    &node.pq_pubkey,
                    crate::crypto::ctx::CROSS_DOMAIN_V1,
                    &msg,
                    &env.pq_sig,
                )
                .map_err(|_| AdapterError::Crypto {
                    what: "invalid ML-DSA-65 co-signature on SCP EXTERNALIZE".into(),
                })?;
            }
            signer_mask |= 1u32 << idx;
        }

        // Enforce transitive FBA quorum closure: every signer in U must have its
        // own QuorumSet recursively satisfied by U.
        if !is_closed_quorum(signer_mask, &pinned.nodes, &node_index) {
            return Err(AdapterError::ConsensusRule {
                rule: "SCP EXTERNALIZE signers do not form a transitively closed FBA quorum".into(),
            });
        }

        let scheme = if all_pq {
            ObservedScheme::Scheme(SchemeId::ML_DSA_65)
        } else {
            ObservedScheme::Scheme(SchemeId::ED25519)
        };
        let attestation = FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &evidence.network),
            height: ledger.ledger_seq,
            state_root: ledger.state_root,
            attested_block_hash: Some(ledger.header_hash),
            attested_event_root: (ledger.event_root != [0u8; 32]).then_some(ledger.event_root),
            attested_tx_root: Some(ledger.tx_set_hash),
            finalized_at: ledger.ledger_seq,
            time_unit: TimeUnit::Height,
            security: SecurityBacking::SignatureSet {
                scheme,
                signers: u64::try_from(seen.len()).unwrap_or(u64::MAX),
                required: min_quorum,
                total_weight: u128::try_from(pinned.nodes.len()).unwrap_or(u128::MAX),
                slashable: pinned.has_bonded_slash_escrow,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
        };
        Ok((attestation, all_pq))
    }
}

impl ExternalFinalityAdapter for StellarScpAdapter {
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
        let sig_tail = self
            .golden
            .as_ref()
            .map_or(32, |g| g.payload.len().saturating_sub(16));
        vec![
            FaultProbe {
                name: "refuses unsupported SCP evidence version".into(),
                patch: BytePatch::EvidenceVersion { value: 6 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "refuses foreign SCP network".into(),
                patch: BytePatch::Network {
                    value: format!("{}-other", self.network),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses mismatched declared SCP ledger_seq".into(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses mismatched declared SCP state root".into(),
                patch: BytePatch::DeclaredRoot { value: [0xEE; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses corrupted SCP payload magic".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: vec![0x11, 0x22],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses tampered SCP close_time_secs breaking ledger hash".into(),
                patch: BytePatch::InPayload {
                    offset: 16,
                    bytes: vec![0xFF, 0x7F],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses corrupted SCP EXTERNALIZE signature".into(),
                patch: BytePatch::InPayload {
                    offset: sig_tail,
                    bytes: vec![0xFE, 0xED, 0xFA, 0xCE],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Crypto),
            },
            FaultProbe {
                name: "refuses truncated SCP payload".into(),
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
    use crate::core::address::Address;
    use crate::cross_domain::external::selftest::admit;
    use crate::crypto::facts::CryptoFacts;
    use crate::crypto::primitives::{KeyPair, PqKeyPair};

    struct OrgNode {
        ed: KeyPair,
        pq: PqKeyPair,
    }

    impl OrgNode {
        fn new(seed: u8) -> Self {
            Self {
                ed: KeyPair::from_seed(&[seed; 32]).unwrap(),
                pq: PqKeyPair::generate(),
            }
        }

        fn id(&self) -> [u8; 32] {
            self.ed.public_key_bytes()
        }

        fn sign_externalize(
            &self,
            net_hash: &Hash32,
            ledger_seq: u64,
            header_hash: &Hash32,
            qset: &ScpQuorumSet,
        ) -> ScpExternalizeEnvelope {
            let qhash = qset.hash();
            let msg = externalize_sign_bytes(net_hash, ledger_seq, 2, 3, header_hash, &qhash);
            ScpExternalizeEnvelope {
                node_id: self.id(),
                commit_counter: 2,
                highest_counter: 3,
                quorum_set_hash: qhash,
                ed25519_sig: self.ed.sign(&msg).to_vec(),
                pq_sig: self
                    .pq
                    .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &msg)
                    .unwrap(),
            }
        }
    }

    fn sorted(mut ids: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
        ids.sort_unstable();
        ids
    }

    /// Build a 3-organization hierarchical FBA tier (2 nodes per org; each node
    /// requires 2-of-3 organizations, and each organization inner-set requires
    /// 2-of-2 of its own nodes -> every minimal quorum is 2 orgs = 4 nodes, and
    /// any two minimal quorums intersect in at least 1 full organization = 2 nodes).
    fn build_hierarchical_scp_fixture(
        slash_escrow: bool,
    ) -> (
        PinnedScpTier,
        Vec<OrgNode>,
        ScpFinalityEvidence,
        RawConsensusEvidence,
    ) {
        let net = "stellar-pubnet";
        let passphrase = "Public Global Stellar Network ; September 2015";
        let nodes_raw: Vec<OrgNode> = (1u8..=6).map(OrgNode::new).collect();

        let org_a = ScpQuorumSet {
            threshold: 2,
            validators: sorted(vec![nodes_raw[0].id(), nodes_raw[1].id()]),
            inner_sets: Vec::new(),
        };
        let org_b = ScpQuorumSet {
            threshold: 2,
            validators: sorted(vec![nodes_raw[2].id(), nodes_raw[3].id()]),
            inner_sets: Vec::new(),
        };
        let org_c = ScpQuorumSet {
            threshold: 2,
            validators: sorted(vec![nodes_raw[4].id(), nodes_raw[5].id()]),
            inner_sets: Vec::new(),
        };
        let top_qset = ScpQuorumSet {
            threshold: 2,
            validators: Vec::new(),
            inner_sets: vec![org_a, org_b, org_c],
        };

        let tier_nodes: Vec<ScpValidatorNode> = nodes_raw
            .iter()
            .map(|n| ScpValidatorNode {
                ed25519_pubkey: n.id(),
                quorum_set: top_qset.clone(),
                pq_pubkey: n.pq.public_key_bytes().to_vec(),
            })
            .collect();
        let pinned = PinnedScpTier {
            network_passphrase: passphrase.into(),
            has_bonded_slash_escrow: slash_escrow,
            nodes: tier_nodes,
        };

        let net_hash = compute_network_id_hash(net, passphrase);
        let mut ledger = ScpLedgerHeader {
            ledger_seq: 52_000_000,
            close_time_secs: 1_760_000_000,
            prev_ledger_hash: [0x12; 32],
            state_root: [0x88; 32],
            tx_set_hash: [0x89; 32],
            event_root: [0x8A; 32],
            base_fee_stroops: 100,
            header_hash: [0; 32],
        };
        ledger.header_hash = ledger.compute_hash(&net_hash);

        // Org A (0, 1) + Org B (2, 3) = 4 nodes form a minimal closed quorum!
        let envelopes: Vec<ScpExternalizeEnvelope> = nodes_raw[0..4]
            .iter()
            .map(|n| {
                n.sign_externalize(&net_hash, ledger.ledger_seq, &ledger.header_hash, &top_qset)
            })
            .collect();
        let bundle = ScpFinalityEvidence { ledger, envelopes };
        let payload = encode_scp_evidence(&bundle).unwrap();
        let ev = RawConsensusEvidence {
            adapter: AdapterId::from_name(ADAPTER_NAME),
            evidence_version: EVIDENCE_VERSION,
            network: net.into(),
            payload,
            declared_height: 52_000_000,
            declared_root: [0x88; 32],
            submitter: Address::from([0x04; 32]),
        };
        (pinned, nodes_raw, bundle, ev)
    }

    #[test]
    fn hierarchical_scp_quorum_passes_intersection_closure_and_selftest() {
        let (pinned, _, _, golden) = build_hierarchical_scp_fixture(false);
        let adapter =
            StellarScpAdapter::new("stellar-pubnet", Some(pinned)).with_golden(golden.clone());
        let policy = VerificationPolicy {
            min_depth: 1,
            require_declared_match: true,
            max_age: 1_000,
            now: 52_000_010,
            require_slashable: false,
        };

        let mut facts = CryptoFacts::default();
        let att = adapter
            .verify_observed(&golden, &policy, &mut facts)
            .unwrap();
        assert_eq!(att.height, 52_000_000);
        assert_eq!(att.state_root, [0x88; 32]);
        assert!(matches!(
            att.security,
            SecurityBacking::SignatureSet {
                signers: 4,
                required: 4,
                slashable: false,
                ..
            }
        ));
        assert_eq!(facts.count(ObservedScheme::Scheme(SchemeId::ED25519)), 1);
        assert_eq!(facts.count(ObservedScheme::Scheme(SchemeId::ML_DSA_65)), 1);

        // Honest disclosure: require_slashable refuses bare unbonded SCP.
        let mut slash_req = policy.clone();
        slash_req.require_slashable = true;
        assert!(matches!(
            adapter.verify(&golden, &slash_req),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("non-slashable")
        ));

        let report = admit(&adapter, &policy);
        assert!(
            report.admitted,
            "Stellar SCP selftest failed: {:?}",
            report.probes
        );
    }

    #[test]
    fn split_brain_disjoint_quorums_and_incomplete_slice_closure_fail_closed() {
        let (pinned, _, mut bundle, mut ev) = build_hierarchical_scp_fixture(true);
        let adapter = StellarScpAdapter::new("stellar-pubnet", Some(pinned));
        let policy = VerificationPolicy {
            min_depth: 1,
            require_declared_match: true,
            max_age: 1_000,
            now: 52_000_010,
            require_slashable: true,
        };
        assert!(adapter.verify(&ev, &policy).is_ok());

        // 1. Dropping one node of Org B breaks transitive FBA quorum closure.
        let saved = bundle.envelopes.pop().unwrap();
        ev.payload = encode_scp_evidence(&bundle).unwrap();
        assert!(matches!(
            adapter.verify(&ev, &policy),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("closed FBA quorum")
        ));
        bundle.envelopes.push(saved);
        ev.payload = encode_scp_evidence(&bundle).unwrap();

        // 2. Construct a split-brain tier where {0,1} trusts only {0,1} and {2,3} trusts only {2,3}.
        let split_keys: Vec<OrgNode> = (31u8..=34).map(OrgNode::new).collect();
        let q_left = ScpQuorumSet {
            threshold: 2,
            validators: sorted(vec![split_keys[0].id(), split_keys[1].id()]),
            inner_sets: Vec::new(),
        };
        let q_right = ScpQuorumSet {
            threshold: 2,
            validators: sorted(vec![split_keys[2].id(), split_keys[3].id()]),
            inner_sets: Vec::new(),
        };
        let split_tier = PinnedScpTier {
            network_passphrase: "Split Network".into(),
            has_bonded_slash_escrow: true,
            nodes: vec![
                ScpValidatorNode {
                    ed25519_pubkey: split_keys[0].id(),
                    quorum_set: q_left.clone(),
                    pq_pubkey: split_keys[0].pq.public_key_bytes().to_vec(),
                },
                ScpValidatorNode {
                    ed25519_pubkey: split_keys[1].id(),
                    quorum_set: q_left,
                    pq_pubkey: split_keys[1].pq.public_key_bytes().to_vec(),
                },
                ScpValidatorNode {
                    ed25519_pubkey: split_keys[2].id(),
                    quorum_set: q_right.clone(),
                    pq_pubkey: split_keys[2].pq.public_key_bytes().to_vec(),
                },
                ScpValidatorNode {
                    ed25519_pubkey: split_keys[3].id(),
                    quorum_set: q_right,
                    pq_pubkey: split_keys[3].pq.public_key_bytes().to_vec(),
                },
            ],
        };
        let split_adapter = StellarScpAdapter::new("stellar-pubnet", Some(split_tier));
        assert!(matches!(
            split_adapter.verify(&ev, &policy),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("quorum intersection")
        ));
    }

    #[test]
    fn registry_lifecycle_contradiction_slash_and_pq_cosig_tracking() {
        use crate::cross_domain::external::{
            ChallengeReward, DomainEconomics, DomainState, ExternalDomainRegistry, VersionPolicy,
        };

        let (pinned, nodes_raw, mut bundle_b, ev_a) = build_hierarchical_scp_fixture(true);
        let prover = ev_a.submitter;
        let challenger = Address::from([0x94; 32]);

        // Sign a contradictory EXTERNALIZE bundle at same ledger_seq with distinct state_root.
        let net_hash = compute_network_id_hash("stellar-pubnet", &pinned.network_passphrase);
        bundle_b.ledger.state_root = [0x99; 32];
        bundle_b.ledger.header_hash = bundle_b.ledger.compute_hash(&net_hash);
        let qset = pinned.nodes[0].quorum_set.clone();
        bundle_b.envelopes = nodes_raw[0..4]
            .iter()
            .map(|n| {
                n.sign_externalize(
                    &net_hash,
                    bundle_b.ledger.ledger_seq,
                    &bundle_b.ledger.header_hash,
                    &qset,
                )
            })
            .collect();
        let mut ev_b = ev_a.clone();
        ev_b.declared_root = [0x99; 32];
        ev_b.submitter = challenger;
        ev_b.payload = encode_scp_evidence(&bundle_b).unwrap();

        let adapter =
            StellarScpAdapter::new("stellar-pubnet", Some(pinned)).with_golden(ev_a.clone());
        let policy = VerificationPolicy {
            min_depth: 1,
            require_declared_match: true,
            max_age: 1_000,
            now: 52_000_010,
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
                "stellar-pubnet",
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
        assert_stellar_shape_and_future_freshness(&adapter, &ev_a, &policy, &att);
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
            .mark_faulted(&domain, "SCP EXTERNALIZE contradiction proof")
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

    fn assert_stellar_shape_and_future_freshness(
        adapter: &StellarScpAdapter,
        ev: &RawConsensusEvidence,
        policy: &VerificationPolicy,
        att: &FinalityAttestation,
    ) {
        crate::domain::finality_proof_model::FinalityProofShape::from_external_attestation(
            &adapter.descriptor(),
            att,
        )
        .expect("SCP closed-quorum attestation must satisfy FinalityProofShape");
        let mut future_policy = policy.clone();
        future_policy.max_age = 1_000;
        future_policy.now = att.height.saturating_sub(1);
        assert!(
            matches!(
                adapter.verify(ev, &future_policy),
                Err(AdapterError::Stale { .. })
            ),
            "future-dated SCP ledger_seq above policy.now must fail closed when max_age > 0"
        );
    }
}
