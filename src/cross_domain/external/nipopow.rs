//! Non-Interactive Proofs of Proof-of-Work (`NIPoPoW`, Kiayias-Miller-Zindros
//! EUROCRYPT 2020) sublinear genesis-anchored external finality adapter.
//!
//! re-exported by `crate::cross_domain::external` but no production path
//! constructs the adapter yet: sublinear sync is admitted only once an intake
//! registration pins a genesis anchor for it, and admitting it before that
//! would let an unpinned verifier answer for a chain nobody anchored. Until
//! then this module's test suite is its only caller.
//!
//! Whereas linear SPV downloads every block header `O(|C|)`, `NIPoPoW` exploits
//! rare high-work superblocks satisfying `id <= target >> mu` and per-header
//! Merkle-committed interlink pointers so a verifier checks genesis-to-tip work
//! in `O(m * log |C| + k)` headers using pure post-quantum SHA-256 arithmetic.
//!
//! Security boundary:
//! - Exact 256-bit integer `superblock_level(id, target)` with zero floats.
//! - Every hop `pi[i] -> pi[i+1]` in the superchain prefix is authenticated by
//!   a domain-separated Merkle inclusion proof against `pi[i+1].interlink_root`
//!   at `link_level`, and `pi[i]` must genuinely achieve level `>= link_level`
//!   (except the pinned genesis anchor, which sits at every interlink level).
//! - Enforces the KMZ `(m, k)` predicate: at least `min_superblocks_m` verified
//!   superblocks at a single level `mu >= min_level`, followed by a strictly
//!   contiguous `k`-block `PoW` suffix `chi` burying the attested header `chi[0]`.
//! - Pure hash security (`SchemeId::SHA2_256`): immune to Shor's algorithm.
//!
//! Convenience: exposed for external `PoW` light-client intake (Ergo/Kadena/velvet
//! Bitcoin superblock domains) and self-test admission.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::crypto::facts::{AssumptionClass, CryptoObserver, ObservedScheme};

use super::selftest::{BytePatch, ExpectedRefusal, FaultProbe, RefusalKind};
use super::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, RawConsensusEvidence, SecurityBacking, TimeUnit, TrustModel,
    VerificationPolicy,
};

/// Canonical adapter identifier for `NIPoPoW` superblock proofs.
pub const ADAPTER_NAME: &str = "nipopow-superblock-v1";

/// Implementation version for `NipopowAdapter`.
pub const ADAPTER_VERSION: u32 = 1;

/// Accepted wire evidence version.
pub const EVIDENCE_VERSION: u32 = 1;

/// Eight-byte wire magic prefixing canonical `NipopowEvidence` payloads.
pub const NIPOPOW_MAGIC: &[u8; 8] = b"BDLMNP01";

/// Domain-separation tag for canonical `NipopowHeader` double-SHA-256 hashing.
pub const DOMAIN_NIPOPOW_HEADER: &[u8] = b"BDLM_NIPOPOW_HEADER_V1";

/// Domain-separation tag for authenticated interlink Merkle leaves.
pub const DOMAIN_NIPOPOW_INTERLINK_LEAF: &[u8] = b"BDLM_NIPOPOW_INTERLINK_LEAF_V1";

/// Domain-separation tag for authenticated interlink Merkle inner nodes.
pub const DOMAIN_NIPOPOW_INTERLINK_NODE: &[u8] = b"BDLM_NIPOPOW_INTERLINK_NODE_V1";

/// Hard upper bound on serialized `NIPoPoW` evidence size (512 KiB).
pub const MAX_NIPOPOW_PAYLOAD_BYTES: usize = 512 * 1024;

/// Maximum superchain prefix headers accepted per proof (`DoS` bound).
pub const MAX_PREFIX_HEADERS: usize = 512;

/// Maximum contiguous suffix headers accepted per proof (`DoS` bound).
pub const MAX_SUFFIX_HEADERS: usize = 128;

/// Maximum Merkle sibling depth accepted for an interlink pointer proof.
pub const MAX_INTERLINK_PROOF_DEPTH: usize = 16;

/// Maximum superblock level representable over a 256-bit digest.
pub const MAX_SUPERBLOCK_LEVEL: u8 = 255;

fn update_lp(h: &mut Sha256, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    h.update(len.to_le_bytes());
    h.update(bytes);
}

fn shift_right_256_be(value: &[u8; 32], bits: u8) -> [u8; 32] {
    let byte_shift = usize::from(bits / 8);
    let bit_shift = bits % 8;
    let mut out = [0u8; 32];
    if byte_shift >= 32 {
        return out;
    }
    for dst_idx in byte_shift..32 {
        let src_idx = dst_idx - byte_shift;
        let cur = value.get(src_idx).copied().unwrap_or(0);
        let hi = if bit_shift > 0 && src_idx > 0 {
            let prev = value.get(src_idx - 1).copied().unwrap_or(0);
            prev << (8 - bit_shift)
        } else {
            0
        };
        if let Some(slot) = out.get_mut(dst_idx) {
            *slot = (cur >> bit_shift) | hi;
        }
    }
    out
}

/// Verify basic `PoW` target satisfaction (`block_id <= target` with `target != 0`)
/// and return `Some(mu)` where `mu` is the highest level satisfying
/// `block_id <= (target >> mu)`, or `None` if the block fails level-0 `PoW`.
///
/// Convenience: exposed for `NIPoPoW` prover tooling and superblock scoring.
#[must_use]
pub fn superblock_level(block_id: &[u8; 32], target: &[u8; 32]) -> Option<u8> {
    if *target == [0u8; 32] || block_id > target {
        return None;
    }
    let mut best = 0u8;
    for mu in 1..=MAX_SUPERBLOCK_LEVEL {
        let shifted = shift_right_256_be(target, mu);
        if shifted == [0u8; 32] && *block_id != [0u8; 32] {
            break;
        }
        if block_id <= &shifted {
            best = mu;
        } else {
            break;
        }
    }
    Some(best)
}

/// Compute the domain-separated interlink Merkle leaf for `(level, target_hash)`.
///
/// Convenience: exposed for `NIPoPoW` interlink tree construction.
#[must_use]
pub fn interlink_leaf_hash(level: u8, target_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    update_lp(&mut h, DOMAIN_NIPOPOW_INTERLINK_LEAF);
    h.update([level]);
    h.update(target_hash);
    h.finalize().into()
}

/// Combine two interlink Merkle sibling hashes under canonical domain separation.
///
/// Convenience: exposed for `NIPoPoW` interlink tree construction.
#[must_use]
pub fn interlink_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    update_lp(&mut h, DOMAIN_NIPOPOW_INTERLINK_NODE);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// One step in a Merkle inclusion proof for a header's `interlink_root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterlinkMerkleStep {
    /// Sibling node digest.
    pub sibling: [u8; 32],
    /// `true` when `sibling` sits on the left (`H(sibling, acc)`).
    pub sibling_is_left: bool,
}

/// Verify that `(level, ancestor_hash)` is committed inside `interlink_root`.
///
/// Convenience: exposed for standalone interlink proof verification.
#[must_use]
pub fn verify_interlink_inclusion(
    level: u8,
    ancestor_hash: &[u8; 32],
    proof: &[InterlinkMerkleStep],
    interlink_root: &[u8; 32],
) -> bool {
    if proof.len() > MAX_INTERLINK_PROOF_DEPTH {
        return false;
    }
    let mut acc = interlink_leaf_hash(level, ancestor_hash);
    for step in proof {
        acc = if step.sibling_is_left {
            interlink_node_hash(&step.sibling, &acc)
        } else {
            interlink_node_hash(&acc, &step.sibling)
        };
    }
    bool::from(acc.ct_eq(interlink_root))
}

/// Canonical `PoW` block header carrying an authenticated `interlink_root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NipopowHeader {
    /// Block height (`0` for the pinned genesis header).
    pub height: u64,
    /// Immediate level-0 predecessor hash.
    pub parent_hash: [u8; 32],
    /// State / UTXO commitment root attested by this block.
    pub state_root: [u8; 32],
    /// Transaction Merkle root attested by this block.
    pub tx_root: [u8; 32],
    /// Merkle root committing all `(level, ancestor_hash)` interlink pointers.
    pub interlink_root: [u8; 32],
    /// Header timestamp in Unix seconds.
    pub timestamp_secs: u64,
    /// 64-bit `PoW` grinding nonce driving `compute_id` below `target >> mu`.
    pub nonce: u64,
    /// Claimed canonical double-SHA-256 block identifier (recomputed on verify).
    pub block_id: [u8; 32],
}

impl NipopowHeader {
    /// Deterministically compute the canonical double-SHA-256 `PoW` identifier
    /// bound to `network`.
    ///
    /// Convenience: exposed for header mining and verification helpers.
    #[must_use]
    pub fn compute_id(&self, network: &str) -> [u8; 32] {
        let first = crate::core::hash::hash_fields_bytes(&[
            DOMAIN_NIPOPOW_HEADER,
            network.as_bytes(),
            &self.height.to_le_bytes(),
            &self.parent_hash,
            &self.state_root,
            &self.tx_root,
            &self.interlink_root,
            &self.timestamp_secs.to_le_bytes(),
            &self.nonce.to_le_bytes(),
        ]);
        Sha256::digest(first).into()
    }
}

/// Authenticated hop connecting `prefix[i]` to `prefix[i + 1]` at `level`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterlinkHop {
    /// Interlink pointer level `mu` dereferenced inside `prefix[i + 1]`.
    pub level: u8,
    /// Merkle path proving `(level, prefix[i].block_id)` in `prefix[i + 1].interlink_root`.
    pub merkle_path: Vec<InterlinkMerkleStep>,
}

/// Wire bundle proving sublinear `NIPoPoW` finality from pinned genesis to suffix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NipopowEvidence {
    /// Strictly ascending superchain prefix `pi`, starting at pinned genesis.
    pub prefix: Vec<NipopowHeader>,
    /// `prefix.len() - 1` authenticated interlink hops across `prefix`.
    pub prefix_hops: Vec<InterlinkHop>,
    /// Contiguous `k`-block `PoW` suffix `chi`; `suffix[0]` is the finalized block.
    pub suffix: Vec<NipopowHeader>,
}

/// Trusted genesis and KMZ `(m, k)` security parameters pinned per domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedNipopowGenesis {
    /// Canonical genesis block identifier (`prefix[0].block_id` must match).
    pub genesis_id: [u8; 32],
    /// Canonical genesis height (typically `0`, or checkpoint height).
    pub genesis_height: u64,
    /// Big-endian 256-bit level-0 `PoW` difficulty target (`id <= target`).
    pub pow_target: [u8; 32],
    /// KMZ security parameter `m`: minimum count of verified superblocks at one level.
    pub min_superblocks_m: u32,
    /// Minimum superblock level `mu >= 1` at which `min_superblocks_m` must hold.
    pub min_superblock_level: u8,
    /// KMZ stability parameter `k`: minimum contiguous suffix length.
    pub min_suffix_k: u32,
}

impl PinnedNipopowGenesis {
    /// Refuse a pin that is the shape of a trust root but not one.
    ///
    /// A genesis id or difficulty target of all zeroes is not a chain
    /// anybody can anchor to, and a zero `m`, `mu` or `k` turns the KMZ
    /// predicate into a statement that is vacuously true. The adapter
    /// refuses each of these at verification time too; this check exists so
    /// the governance door can refuse the same pin before it reaches
    /// consensus state.
    ///
    /// # Errors
    ///
    /// A message naming the first zero field.
    pub fn validate(&self) -> Result<(), String> {
        if self.genesis_id == [0u8; 32] {
            return Err("the pinned NIPoPoW genesis id is all zeroes".into());
        }
        if self.pow_target == [0u8; 32] {
            return Err("the pinned NIPoPoW difficulty target is all zeroes".into());
        }
        if self.min_superblocks_m == 0 {
            return Err("the pinned NIPoPoW min_superblocks_m is zero".into());
        }
        if self.min_superblock_level == 0 {
            return Err("the pinned NIPoPoW min_superblock_level is zero".into());
        }
        if self.min_suffix_k == 0 {
            return Err("the pinned NIPoPoW min_suffix_k is zero".into());
        }
        Ok(())
    }
}

/// Encode a `NipopowEvidence` bundle with canonical magic prefix.
///
/// Convenience: exposed for relayers and admission self-test builders.
pub fn encode_nipopow_evidence(bundle: &NipopowEvidence) -> Result<Vec<u8>, AdapterError> {
    let body = bincode::serialize(bundle).map_err(|e| AdapterError::Malformed {
        offset: 0,
        reason: format!("failed to serialize NIPoPoW evidence: {e}"),
    })?;
    if body.len().saturating_add(NIPOPOW_MAGIC.len()) > MAX_NIPOPOW_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "NIPoPoW payload exceeds MAX_NIPOPOW_PAYLOAD_BYTES".into(),
        });
    }
    let mut out = Vec::with_capacity(NIPOPOW_MAGIC.len() + body.len());
    out.extend_from_slice(NIPOPOW_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_nipopow_evidence(payload: &[u8]) -> Result<NipopowEvidence, AdapterError> {
    if payload.len() > MAX_NIPOPOW_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "NIPoPoW payload exceeds MAX_NIPOPOW_PAYLOAD_BYTES".into(),
        });
    }
    let magic = payload.get(..8).ok_or_else(|| AdapterError::Malformed {
        offset: 0,
        reason: "NIPoPoW payload shorter than 8-byte magic".into(),
    })?;
    if magic != NIPOPOW_MAGIC {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "NIPoPoW payload magic mismatch".into(),
        });
    }
    let body = payload.get(8..).ok_or_else(|| AdapterError::Malformed {
        offset: 8,
        reason: "missing NIPoPoW payload body".into(),
    })?;
    let decoded: NipopowEvidence =
        crate::network::bounded_bincode::decode_bounded_bincode(body, MAX_NIPOPOW_PAYLOAD_BYTES)
            .map_err(|e| AdapterError::Malformed {
                offset: 8,
                reason: format!("invalid NIPoPoW evidence encoding: {e}"),
            })?;
    if bincode::serialized_size(&decoded).ok() != u64::try_from(body.len()).ok() {
        return Err(AdapterError::Malformed {
            offset: 8,
            reason: "trailing bytes after canonical NIPoPoW evidence".into(),
        });
    }
    Ok(decoded)
}

/// Compute the KMZ best-level superblock work score `max_{mu >= min_level} (|pi_mu| * 2^mu)`
/// over non-genesis superblock levels achieving `|pi_mu| >= m`. Returns `None` if no
/// level meets the `m`-superblock threshold.
///
/// Convenience: exposed for competing `NIPoPoW` fork comparison.
#[must_use]
pub fn best_superchain_score(
    non_genesis_levels: &[u8],
    min_superblocks_m: u32,
    min_level: u8,
) -> Option<(u8, u128)> {
    if min_superblocks_m == 0 || min_level == 0 {
        return None;
    }
    let max_seen = non_genesis_levels.iter().copied().max()?;
    if max_seen < min_level {
        return None;
    }
    let mut best: Option<(u8, u128)> = None;
    for mu in min_level..=max_seen.min(120) {
        let count = non_genesis_levels.iter().filter(|&&lv| lv >= mu).count();
        if count >= usize::from(u16::try_from(min_superblocks_m).unwrap_or(u16::MAX))
            || u64::try_from(count).unwrap_or(0) >= u64::from(min_superblocks_m)
        {
            let weight = 1u128.checked_shl(u32::from(mu)).unwrap_or(u128::MAX);
            let score = (count as u128).saturating_mul(weight);
            if best.is_none_or(|(_, prev)| score >= prev) {
                best = Some((mu, score));
            }
        }
    }
    best
}

/// External finality adapter verifying KMZ `NIPoPoW` superblock + suffix proofs.
pub struct NipopowAdapter {
    network: String,
    pinned: Option<PinnedNipopowGenesis>,
    golden: Option<RawConsensusEvidence>,
    descriptor: AdapterDescriptor,
}

impl NipopowAdapter {
    /// Construct a `NipopowAdapter` bound to `network` and its pinned genesis.
    ///
    /// Convenience: exposed for external domain registration and tests.
    #[must_use]
    pub fn new(network: impl Into<String>, pinned: Option<PinnedNipopowGenesis>) -> Self {
        let required_depth = pinned
            .as_ref()
            .map_or(6, |p| u64::from(p.min_suffix_k.max(1)));
        Self {
            network: network.into(),
            pinned,
            golden: None,
            descriptor: AdapterDescriptor {
                id: AdapterId::from_name(ADAPTER_NAME),
                name: ADAPTER_NAME.to_string(),
                adapter_version: ADAPTER_VERSION,
                accepted_evidence_versions: vec![EVIDENCE_VERSION],
                consensus_kind: "nipopow-superblock".to_string(),
                finality_kind: FinalityKind::Probabilistic,
                required_depth,
                time_unit: TimeUnit::Height,
                trust_model: TrustModel::Trustless,
            },
        }
    }

    /// Attach a golden `NIPoPoW` proof for admission self-test fault probing.
    ///
    /// Convenience: exposed for `selftest::admit` callers.
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }

    fn verify_inner(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError> {
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
                    "NIPoPoW evidence network '{}' mismatches pinned '{}'",
                    evidence.network, self.network
                ),
            });
        }

        let pinned = self
            .pinned
            .as_ref()
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "NIPoPoW genesis anchor is not pinned; fail-closed".into(),
            })?;
        if pinned.genesis_id == [0u8; 32]
            || pinned.pow_target == [0u8; 32]
            || pinned.min_superblocks_m == 0
            || pinned.min_superblock_level == 0
            || pinned.min_suffix_k == 0
        {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned NIPoPoW genesis parameters contain zero field".into(),
            });
        }

        let bundle = decode_nipopow_evidence(&evidence.payload)?;
        if bundle.prefix.len() < 2 || bundle.prefix.len() > MAX_PREFIX_HEADERS {
            return Err(AdapterError::ConsensusRule {
                rule: "NIPoPoW prefix length outside valid bounds [2, 512]".into(),
            });
        }
        if bundle.prefix_hops.len() + 1 != bundle.prefix.len() {
            return Err(AdapterError::ConsensusRule {
                rule: "NIPoPoW prefix_hops count must equal prefix.len() - 1".into(),
            });
        }
        if bundle.suffix.is_empty()
            || bundle.suffix.len() > MAX_SUFFIX_HEADERS
            || u64::try_from(bundle.suffix.len()).unwrap_or(0) < u64::from(pinned.min_suffix_k)
        {
            return Err(AdapterError::ConsensusRule {
                rule: "NIPoPoW suffix shorter than pinned min_suffix_k or above ceiling".into(),
            });
        }

        // 1. Anchor prefix[0] to pinned genesis.
        let genesis = bundle
            .prefix
            .first()
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "empty NIPoPoW prefix".into(),
            })?;
        let computed_gen = genesis.compute_id(&self.network);
        if !bool::from(genesis.block_id.ct_eq(&computed_gen))
            || !bool::from(genesis.block_id.ct_eq(&pinned.genesis_id))
            || genesis.height != pinned.genesis_height
        {
            return Err(AdapterError::ConsensusRule {
                rule: "NIPoPoW prefix[0] does not match pinned genesis anchor".into(),
            });
        }

        // 2. Verify every non-genesis prefix superblock, deduplicate IDs, and
        //    validate every authenticated interlink hop.
        let mut seen_ids = BTreeSet::new();
        seen_ids.insert(genesis.block_id);
        let mut superblock_levels = Vec::with_capacity(bundle.prefix.len());
        let mut prev = genesis;
        let mut prev_level = MAX_SUPERBLOCK_LEVEL; // genesis sits at every interlink level

        for (next, hop) in bundle.prefix.iter().skip(1).zip(bundle.prefix_hops.iter()) {
            let expected_id = next.compute_id(&self.network);
            if !bool::from(next.block_id.ct_eq(&expected_id)) {
                return Err(AdapterError::Crypto {
                    what: "NIPoPoW prefix block_id does not match canonical SHA-256d digest".into(),
                });
            }
            if !seen_ids.insert(next.block_id) {
                return Err(AdapterError::ConsensusRule {
                    rule: "duplicate block_id in NIPoPoW prefix".into(),
                });
            }
            if next.height <= prev.height || next.timestamp_secs < prev.timestamp_secs {
                return Err(AdapterError::ConsensusRule {
                    rule: "NIPoPoW prefix heights must strictly increase with non-regressing time"
                        .into(),
                });
            }
            if next.state_root == [0u8; 32] {
                return Err(AdapterError::ConsensusRule {
                    rule: "NIPoPoW prefix header carries zero state_root".into(),
                });
            }
            let level = superblock_level(&next.block_id, &pinned.pow_target).ok_or_else(|| {
                AdapterError::ConsensusRule {
                    rule: "NIPoPoW prefix header fails level-0 PoW target".into(),
                }
            })?;
            if prev_level < hop.level {
                return Err(AdapterError::ConsensusRule {
                    rule: "NIPoPoW interlink hop cites higher level than predecessor achieved"
                        .into(),
                });
            }
            if !verify_interlink_inclusion(
                hop.level,
                &prev.block_id,
                &hop.merkle_path,
                &next.interlink_root,
            ) {
                return Err(AdapterError::Crypto {
                    what: "NIPoPoW interlink Merkle inclusion proof failed".into(),
                });
            }
            superblock_levels.push(level);
            prev = next;
            prev_level = level;
        }

        // 3. Enforce KMZ m-superblock density predicate and compute cumulative work score.
        let (_best_level, superchain_work) = best_superchain_score(
            &superblock_levels,
            pinned.min_superblocks_m,
            pinned.min_superblock_level,
        )
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "NIPoPoW prefix does not satisfy KMZ (m, min_level) superblock predicate".into(),
        })?;

        // 4. Verify contiguous PoW suffix `chi` linked directly to `prefix.last()`.
        let mut suffix_prev = prev;
        for blk in &bundle.suffix {
            let expected_id = blk.compute_id(&self.network);
            if !bool::from(blk.block_id.ct_eq(&expected_id)) {
                return Err(AdapterError::Crypto {
                    what: "NIPoPoW suffix block_id does not match canonical SHA-256d digest".into(),
                });
            }
            if !seen_ids.insert(blk.block_id) {
                return Err(AdapterError::ConsensusRule {
                    rule: "duplicate block_id in NIPoPoW suffix".into(),
                });
            }
            if Some(blk.height) != suffix_prev.height.checked_add(1) {
                return Err(AdapterError::ConsensusRule {
                    rule: "NIPoPoW suffix heights are not strictly consecutive (+1)".into(),
                });
            }
            if !bool::from(blk.parent_hash.ct_eq(&suffix_prev.block_id)) {
                return Err(AdapterError::ConsensusRule {
                    rule: "NIPoPoW suffix parent_hash chain broken".into(),
                });
            }
            if blk.timestamp_secs < suffix_prev.timestamp_secs {
                return Err(AdapterError::ConsensusRule {
                    rule: "NIPoPoW suffix timestamp regresses below parent".into(),
                });
            }
            if blk.state_root == [0u8; 32] {
                return Err(AdapterError::ConsensusRule {
                    rule: "NIPoPoW suffix block carries zero state_root".into(),
                });
            }
            if superblock_level(&blk.block_id, &pinned.pow_target).is_none() {
                return Err(AdapterError::ConsensusRule {
                    rule: "NIPoPoW suffix block fails PoW difficulty target".into(),
                });
            }
            suffix_prev = blk;
        }

        // The attested block is `suffix[0]`, buried beneath all `suffix.len()` blocks.
        let finalized = bundle
            .suffix
            .first()
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "empty NIPoPoW suffix".into(),
            })?;
        let confirmations = u64::try_from(bundle.suffix.len()).unwrap_or(u64::MAX);

        if policy.require_declared_match {
            if evidence.declared_height != finalized.height {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if !bool::from(evidence.declared_root.ct_eq(&finalized.state_root)) {
                return Err(AdapterError::DeclarationMismatch { field: "root" });
            }
        }
        if confirmations < policy.min_depth {
            return Err(AdapterError::InsufficientDepth {
                observed: confirmations,
                required: policy.min_depth,
            });
        }
        if policy.max_age > 0 && policy.now > finalized.height {
            let age = policy.now - finalized.height;
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        if policy.require_slashable {
            return Err(AdapterError::UnslashableBacking);
        }

        let cumulative_work = superchain_work.saturating_add(u128::from(confirmations));
        let difficulty_bits = 128u32.saturating_sub(cumulative_work.leading_zeros());
        Ok(FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &evidence.network),
            height: finalized.height,
            state_root: finalized.state_root,
            finalized_at: finalized.height,
            time_unit: TimeUnit::Height,
            security: SecurityBacking::Work { difficulty_bits },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
            attested_block_hash: Some(finalized.block_id),
            attested_event_root: None,
            attested_tx_root: Some(finalized.tx_root),
        })
    }
}

impl ExternalFinalityAdapter for NipopowAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn verify(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError> {
        self.verify_inner(evidence, policy)
    }

    fn verify_observed(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
        observer: &mut dyn CryptoObserver,
    ) -> Result<FinalityAttestation, AdapterError> {
        let att = self.verify_inner(evidence, policy)?;
        observer.observe(ObservedScheme::Proof(AssumptionClass::Hash));
        Ok(att)
    }

    fn golden_evidence(&self) -> Option<RawConsensusEvidence> {
        self.golden.clone()
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        let tail_offset = self
            .golden
            .as_ref()
            .map_or(24, |g| g.payload.len().saturating_sub(24));
        vec![
            FaultProbe {
                name: "nipopow_wrong_magic".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: vec![0xFF],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "nipopow_truncated_payload".into(),
                patch: BytePatch::TruncatePayload { keep: 12 },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "nipopow_oversized_length_prefix".into(),
                patch: BytePatch::InPayload {
                    offset: 8,
                    bytes: vec![0xFF; 8],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "nipopow_corrupted_tail_block_id".into(),
                patch: BytePatch::InPayload {
                    offset: tail_offset,
                    bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
                },
                expect: ExpectedRefusal::Any,
            },
            FaultProbe {
                name: "nipopow_declared_height_mismatch".into(),
                patch: BytePatch::DeclaredHeight { value: 999_999_999 },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "nipopow_declared_root_mismatch".into(),
                patch: BytePatch::DeclaredRoot { value: [0xFE; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "nipopow_wrong_evidence_version".into(),
                patch: BytePatch::EvidenceVersion { value: 77 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "nipopow_foreign_network".into(),
                patch: BytePatch::Network {
                    value: "ergo-forged-net".into(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::external::selftest::admit;
    use crate::crypto::facts::CryptoFacts;

    const NET: &str = "ergo-nipopow-testnet";

    /// Generous target (`0x7F..FF`) so level-4 superblocks (`<= 0x07..FF`) mine in < 50 hashes.
    fn test_target() -> [u8; 32] {
        let mut t = [0xFFu8; 32];
        t[0] = 0x7F;
        t
    }

    fn mine_header(
        height: u64,
        parent_hash: [u8; 32],
        state_root: [u8; 32],
        interlink_root: [u8; 32],
        timestamp_secs: u64,
        target: &[u8; 32],
        required_level: u8,
    ) -> NipopowHeader {
        let mut hdr = NipopowHeader {
            height,
            parent_hash,
            state_root,
            tx_root: [height as u8 ^ 0x5C; 32],
            interlink_root,
            timestamp_secs,
            nonce: 0,
            block_id: [0u8; 32],
        };
        for nonce in 0..500_000u64 {
            hdr.nonce = nonce;
            let id = hdr.compute_id(NET);
            if let Some(mu) = superblock_level(&id, target) {
                if mu >= required_level {
                    hdr.block_id = id;
                    return hdr;
                }
            }
        }
        panic!("deterministic superblock mining exhausted budget");
    }

    /// Build a 2-leaf interlink tree committing `(hop_level, prev_id)` on the left
    /// and `(0, genesis_id)` on the right.
    fn build_two_leaf_interlink(
        hop_level: u8,
        prev_id: [u8; 32],
        genesis_id: [u8; 32],
    ) -> ([u8; 32], Vec<InterlinkMerkleStep>) {
        let left = interlink_leaf_hash(hop_level, &prev_id);
        let right = interlink_leaf_hash(0, &genesis_id);
        let root = interlink_node_hash(&left, &right);
        let proof = vec![InterlinkMerkleStep {
            sibling: right,
            sibling_is_left: false,
        }];
        (root, proof)
    }

    fn make_golden_fixture() -> (PinnedNipopowGenesis, NipopowEvidence, RawConsensusEvidence) {
        let target = test_target();
        let genesis = mine_header(
            0,
            [0x01; 32],
            [0x10; 32],
            [0x20; 32],
            1_700_000_000,
            &target,
            0,
        );

        let mut prefix = vec![genesis.clone()];
        let mut hops = Vec::new();
        let super_heights = [1_024u64, 4_096, 16_384];
        for (idx, &h) in super_heights.iter().enumerate() {
            let prev_id = prefix.last().unwrap().block_id;
            let (il_root, path) = build_two_leaf_interlink(3, prev_id, genesis.block_id);
            let sb = mine_header(
                h,
                [0x90 + idx as u8; 32],
                [0x30 + idx as u8; 32],
                il_root,
                1_700_000_000 + h,
                &target,
                3,
            );
            prefix.push(sb);
            hops.push(InterlinkHop {
                level: 3,
                merkle_path: path,
            });
        }

        let mut suffix = Vec::new();
        let mut prev = prefix.last().unwrap().clone();
        for offset in 1..=4u64 {
            let h = prev.height + 1;
            let blk = mine_header(
                h,
                prev.block_id,
                [0xA0 + offset as u8; 32],
                interlink_leaf_hash(0, &genesis.block_id),
                prev.timestamp_secs + 60,
                &target,
                0,
            );
            prev = blk.clone();
            suffix.push(blk);
        }

        let pinned = PinnedNipopowGenesis {
            genesis_id: genesis.block_id,
            genesis_height: 0,
            pow_target: target,
            min_superblocks_m: 3,
            min_superblock_level: 3,
            min_suffix_k: 4,
        };
        let bundle = NipopowEvidence {
            prefix,
            prefix_hops: hops,
            suffix,
        };
        let payload = encode_nipopow_evidence(&bundle).unwrap();
        let finalized = &bundle.suffix[0];
        let raw = RawConsensusEvidence {
            adapter: AdapterId::from_name(ADAPTER_NAME),
            network: NET.to_string(),
            evidence_version: EVIDENCE_VERSION,
            declared_height: finalized.height,
            declared_root: finalized.state_root,
            payload,
            submitter: crate::core::address::Address([0x07; 32]),
        };
        (pinned, bundle, raw)
    }

    #[test]
    fn nipopow_verifies_sublinear_proof_passes_all_admission_probes_and_observes_sha256() {
        let (pinned, bundle, golden) = make_golden_fixture();
        let adapter = NipopowAdapter::new(NET, Some(pinned)).with_golden(golden.clone());
        let policy = VerificationPolicy {
            min_depth: 4,
            max_age: 100,
            now: bundle.suffix[0].height + 4,
            require_declared_match: true,
            require_slashable: false,
        };

        let report = admit(&adapter, &policy);
        assert!(report.admitted, "NIPoPoW admission failed: {report:?}");
        assert_eq!(report.probes.len(), 8);

        let mut facts = CryptoFacts::default();
        let att = adapter
            .verify_observed(&golden, &policy, &mut facts)
            .unwrap();
        assert_eq!(att.height, 16_385);
        assert_eq!(att.state_root, bundle.suffix[0].state_root);
        assert_eq!(facts.count(ObservedScheme::Proof(AssumptionClass::Hash)), 1);
        match att.security {
            SecurityBacking::Work { difficulty_bits } => {
                assert!(difficulty_bits >= 5);
            }
            other => panic!("unexpected security backing: {other:?}"),
        }
    }

    #[test]
    fn nipopow_refuses_forged_interlink_weak_superchain_broken_suffix_and_unpinned_genesis() {
        let (pinned, bundle, golden) = make_golden_fixture();
        let policy = VerificationPolicy {
            min_depth: 4,
            max_age: 0,
            now: 0,
            require_declared_match: true,
            require_slashable: false,
        };

        // 1. Unpinned genesis fails closed.
        let unpinned = NipopowAdapter::new(NET, None);
        assert!(matches!(
            unpinned.verify(&golden, &policy),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("not pinned")
        ));

        let adapter = NipopowAdapter::new(NET, Some(pinned.clone()));

        // 2. Forged interlink Merkle sibling is rejected cryptographically.
        let mut bad_hop = bundle.clone();
        bad_hop.prefix_hops[1].merkle_path[0].sibling[0] ^= 0xFF;
        let mut ev = golden.clone();
        ev.payload = encode_nipopow_evidence(&bad_hop).unwrap();
        assert!(matches!(
            adapter.verify(&ev, &policy),
            Err(AdapterError::Crypto { ref what }) if what.contains("interlink")
        ));

        // 3. Higher KMZ `m` requirement refuses under-dense superchain.
        let mut stricter = pinned.clone();
        stricter.min_superblocks_m = 20;
        let strict_adapter = NipopowAdapter::new(NET, Some(stricter));
        assert!(matches!(
            strict_adapter.verify(&golden, &policy),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("superblock predicate")
        ));

        // 4. Truncated suffix below `min_suffix_k` is refused.
        let mut short_suffix = bundle;
        short_suffix.suffix.pop();
        ev.payload = encode_nipopow_evidence(&short_suffix).unwrap();
        assert!(matches!(
            adapter.verify(&ev, &policy),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("min_suffix_k")
        ));
    }

    #[test]
    fn superblock_level_uses_exact_256bit_shifts_without_floats() {
        let mut target = [0u8; 32];
        target[0] = 0x80;
        let mut lvl0 = [0u8; 32];
        lvl0[0] = 0x80;
        let mut lvl3 = [0u8; 32];
        lvl3[0] = 0x10;
        let mut fail = [0u8; 32];
        fail[0] = 0x81;

        assert_eq!(superblock_level(&lvl0, &target), Some(0));
        assert_eq!(superblock_level(&lvl3, &target), Some(3));
        assert_eq!(superblock_level(&fail, &target), None);
        assert_eq!(superblock_level(&[0u8; 32], &[0u8; 32]), None);
    }

    #[test]
    fn pinned_genesis_refuses_every_zero_security_field() {
        let (pinned, _, _) = make_golden_fixture();
        pinned.validate().expect("the fixture pin is valid");

        let mut zero_genesis = pinned.clone();
        zero_genesis.genesis_id = [0u8; 32];
        assert!(zero_genesis.validate().is_err());

        let mut zero_target = pinned.clone();
        zero_target.pow_target = [0u8; 32];
        assert!(zero_target.validate().is_err());

        let mut zero_m = pinned.clone();
        zero_m.min_superblocks_m = 0;
        assert!(zero_m.validate().is_err());

        let mut zero_level = pinned.clone();
        zero_level.min_superblock_level = 0;
        assert!(zero_level.validate().is_err());

        let mut zero_k = pinned;
        zero_k.min_suffix_k = 0;
        assert!(zero_k.validate().is_err());
    }

    #[test]
    fn governance_anchor_door_installs_and_reads_back_a_nipopow_pin() {
        use crate::cross_domain::external::intake::{AnchorFamily, PinnedExternalAnchor};
        use crate::cross_domain::external::IntakeState;

        let (pinned, _, _) = make_golden_fixture();
        let anchor = PinnedExternalAnchor::Nipopow(pinned.clone());
        assert_eq!(anchor.family(), AnchorFamily::Nipopow);
        anchor.validate().expect("the fixture pin validates");

        let mut state = IntakeState::default();
        state.install_pinned_anchor(NET, anchor.clone());
        assert_eq!(
            state.pinned_anchor(AnchorFamily::Nipopow, NET),
            Some(anchor)
        );
        assert_eq!(
            state.pinned_nipopow_anchors.get(NET),
            Some(&pinned),
            "the install must land in the family map the registration door reads"
        );
    }

    #[test]
    fn nipopow_spec_registers_only_against_the_governance_pin() {
        use crate::core::address::Address;
        use crate::cross_domain::external::intake::IntakeError;
        use crate::cross_domain::external::{
            AdapterId, AdapterSpec, DomainKey, IntakeState, RegistrationRequest,
            VerificationPolicy, VersionPolicy,
        };

        let (pinned, bundle, golden) = make_golden_fixture();
        let policy = VerificationPolicy {
            min_depth: 4,
            max_age: 100,
            now: bundle.suffix[0].height + 4,
            require_declared_match: true,
            require_slashable: false,
        };
        let request = |anchor: Option<PinnedNipopowGenesis>| RegistrationRequest {
            spec: AdapterSpec::Nipopow {
                network: NET.to_string(),
                anchor,
            },
            policy: policy.clone(),
            economics: IntakeState::conservative_economics(1_000_000),
            versions: VersionPolicy::single(
                AdapterId::from_name(ADAPTER_NAME),
                EVIDENCE_VERSION,
                0,
            ),
            bond_atoms: 100_000,
            poster: Address([0x07; 32]),
            golden: golden.clone(),
        };

        // 1. No pin installed: the door refuses before any proof is read.
        let mut state = IntakeState::default();
        let err = state
            .register_domain(request(Some(pinned.clone())), None)
            .expect_err("an unpinned network must refuse registration");
        assert!(matches!(err, IntakeError::CommitteeNotPinned), "{err:?}");

        // 2. A pin the registrant invented is not the governance pin.
        let mut state = IntakeState::default();
        let mut other = pinned.clone();
        other.genesis_id[0] ^= 0xFF;
        state.pin_nipopow_anchor(NET, pinned.clone());
        let err = state
            .register_domain(request(Some(other)), None)
            .expect_err("a foreign pin must refuse registration");
        assert!(matches!(err, IntakeError::CommitteeNotPinned), "{err:?}");

        // 3. The closed admission shape (`anchor: None`) is refused too.
        let mut state = IntakeState::default();
        state.pin_nipopow_anchor(NET, pinned.clone());
        let err = state
            .register_domain(request(None), None)
            .expect_err("a spec without a pin must refuse registration");
        assert!(matches!(err, IntakeError::CommitteeNotPinned), "{err:?}");

        // 4. The governance pin and the spec pin agree: registration admits.
        let key = state
            .register_domain(request(Some(pinned)), None)
            .expect("the pinned NIPoPoW domain must register");
        assert_eq!(
            key,
            DomainKey::from_parts(&AdapterId::from_name(ADAPTER_NAME), NET)
        );
        assert!(state.entries.contains_key(&key));
    }

    /// The point of registering a family is that its evidence actually moves
    /// the settlement state. A registration that admits a domain the intake
    /// can never accept evidence for is a door that opens onto a wall: the
    /// height, the root and the work backing the rest of the tree reads would
    /// never have a source. This test walks the production path - governance
    /// pin, registration, evidence submission - and then reads what the
    /// registry now holds.
    #[test]
    fn a_pinned_nipopow_domain_takes_evidence_and_reports_the_buried_block() {
        use crate::core::address::Address;
        use crate::cross_domain::external::intake::{AnchorFamily, PinnedExternalAnchor};
        use crate::cross_domain::external::{
            AdapterId, AdapterSpec, IntakeState, RegistrationRequest, VersionPolicy,
        };

        let (pinned, bundle, golden) = make_golden_fixture();
        let buried = &bundle.suffix[0];
        let mut state = IntakeState::default();
        // The governance door is the only writer of the anchor map; the
        // registration below must read the value this line installed.
        state.install_pinned_anchor(NET, PinnedExternalAnchor::Nipopow(pinned.clone()));
        assert!(state.pinned_anchor(AnchorFamily::Nipopow, NET).is_some());

        let key = state
            .register_domain(
                RegistrationRequest {
                    spec: AdapterSpec::Nipopow {
                        network: NET.to_string(),
                        anchor: Some(pinned.clone()),
                    },
                    policy: VerificationPolicy {
                        min_depth: 4,
                        max_age: 0,
                        now: 0,
                        require_declared_match: true,
                        require_slashable: false,
                    },
                    economics: IntakeState::conservative_economics(1_000_000),
                    versions: VersionPolicy::single(
                        AdapterId::from_name(ADAPTER_NAME),
                        EVIDENCE_VERSION,
                        0,
                    ),
                    bond_atoms: 100_000,
                    poster: Address([0x07; 32]),
                    golden: golden.clone(),
                },
                None,
            )
            .expect("the pinned NIPoPoW domain must register");

        let attestation = state
            .submit_evidence(&golden, None)
            .expect("governance-pinned evidence on the production path must be accepted");

        // The attestation must describe the block the proof buries, not the
        // proof's tip: `suffix[0]` is what the `k`-deep suffix finalizes.
        assert_eq!(attestation.height, buried.height);
        assert_eq!(attestation.state_root, buried.state_root);
        assert_eq!(
            attestation.attested_block_hash,
            Some(buried.block_id),
            "the attestation must name the block it finalized"
        );
        assert_eq!(attestation.adapter, AdapterId::from_name(ADAPTER_NAME));
        assert_eq!(
            attestation.domain,
            DomainKey::from_parts(&AdapterId::from_name(ADAPTER_NAME), NET)
        );

        // Work is the security backing of a proof-of-work family; a
        // signature-set backing here would claim slashing power that does not
        // exist on the external chain.
        match attestation.security {
            SecurityBacking::Work { difficulty_bits } => assert!(
                difficulty_bits > 0,
                "a verified superchain must report non-zero work"
            ),
            other => panic!("NIPoPoW must back finality with work, got {other:?}"),
        }

        let profile = state
            .registry
            .domain(&key)
            .expect("the registry must hold the domain it admitted");
        assert_eq!(
            profile.attestations.get(&(buried.height, EVIDENCE_VERSION)),
            Some(&attestation),
            "the accepted attestation must be stored under its (height, version) slot"
        );
    }

    /// A domain that admits evidence must be a domain the settlement state
    /// can see. Before the anchor map was part of the presence check, a chain
    /// that had pinned a trust root but not yet registered a domain hashed
    /// like a chain that never heard of external domains, and a
    /// `GlobalBlockHeader` could carry an empty intake root while a live pin
    /// sat in consensus state.
    #[test]
    fn a_nipopow_pin_alone_moves_the_external_intake_presence_flag() {
        use crate::cross_domain::external::intake::PinnedExternalAnchor;
        use crate::cross_domain::external::IntakeState;

        let (pinned, _, _) = make_golden_fixture();
        let mut state = IntakeState::default();
        let registries =
            |intake: IntakeState| crate::settlement::registries::SettlementRegistries {
                external_intake: intake,
                ..Default::default()
            };
        assert!(
            !registries(state.clone()).has_external_intake(),
            "a fresh intake is empty, which is what the header presence tag reads"
        );

        state.install_pinned_anchor(NET, PinnedExternalAnchor::Nipopow(pinned.clone()));
        assert!(
            registries(state.clone()).has_external_intake(),
            "a governance-pinned NIPoPoW anchor is external intake state"
        );
        assert_ne!(
            state.state_digest().expect("the digest must serialize"),
            IntakeState::default()
                .state_digest()
                .expect("the digest must serialize"),
            "the pin must move the intake digest the header commits to"
        );

        // The goodness bound is part of the trust root: two pins that differ
        // in `m` accept different proof sets, so a node that installed one
        // must not compute the other's digest.
        let mut looser = pinned;
        looser.min_superblocks_m = looser.min_superblocks_m.saturating_add(1);
        let mut other = IntakeState::default();
        other.install_pinned_anchor(NET, PinnedExternalAnchor::Nipopow(looser));
        assert_ne!(
            state.state_digest().expect("the digest must serialize"),
            other.state_digest().expect("the digest must serialize"),
            "the KMZ goodness bound must be inside the intake state digest"
        );
    }
}
