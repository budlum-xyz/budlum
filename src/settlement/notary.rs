//! Quantum-safe hash-only notary timestamps chained to SLH-DSA Root Seals.
//!
//! Any 32-byte digest (document, software release, or external state root) is
//! committed into a SHA3-256 Merkle batch, included as a [`QuantumClass::Hash`]
//! leaf inside a [`PqAnchor`], and anchored into the 3,600-block
//! SLH-DSA-SHAKE-256s [`RootSeal`] chain.
//!
//! Offline verification depends solely on SHA3-256 and SHAKE-256
//! (`SLH-DSA-SHAKE-256s`): it makes no network calls and verifies no lattice
//! signatures, so a verified timestamp remains valid even if lattice
//! cryptography is broken.
//!
//! Honest boundary: software seal signing operates only in non-production modes
//! (`AnchorMode::Devnet` / `AnchorMode::GatedOff`); production mode fails
//! closed until the production anchor grant is enabled.
//!
//! WIRING: called directly by `src/bin/bud.rs` (`bud notary anchor` and
//! `bud notary verify`) and verified by `tests/k7d_quantum_safe_notary_tests.rs`.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use subtle::ConstantTimeEq;

use super::pq_anchor::{
    aggregate_finality_roots, anchor_leaf_digest, build_anchor_inclusion_proof,
    enforce_anchor_mode, AnchorError, AnchorInclusionProof, AnchorLeaf, AnchorMode, PqAnchor,
    MAX_ANCHOR_MERKLE_DEPTH,
};
use super::root_seal::{
    anchor_leaf, build_root_seal, period_anchors_root, seal_due, verify_root_seal, RootSeal,
    SealError, SealKeys, SealSigner, MAX_SEAL_ANCHORS, ROOT_SEAL_INTERVAL,
};
use crate::consensus::merkle_tree::{
    combine_sha3, merkle_proof, merkle_root, odd_promotion_sentinel, promote_sha3,
};
use crate::crypto::facts::QuantumClass;

/// Maximum byte length of an optional human-readable notary label.
const MAX_NOTARY_LABEL_BYTES: usize = 256;

/// Maximum Merkle depth for a single notary batch (`2^32` entries).
const MAX_NOTARY_MERKLE_DEPTH: usize = 32;

/// Maximum number of subsequent chained Root Seals carried in one offline bundle.
const MAX_NOTARY_CHAIN_EXTENSIONS: usize = 64;

/// Maximum Merkle depth for anchors inside one Root Seal period (`ceil(log2(64)) = 6`).
const MAX_SEAL_MERKLE_DEPTH: usize = 16;

/// Expected byte length of an SLH-DSA-SHAKE-256s public key (FIPS 205).
const SLH_DSA_SHAKE_256S_PK_LEN: usize = 64;

/// A single notarized digest entry committed at `height`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotaryEntry {
    /// Non-zero 32-byte digest being timestamped.
    pub document_digest: [u8; 32],
    /// Block height at which the digest was committed (must be `>= 1`).
    pub height: u64,
    /// Optional ASCII/UTF-8 label without control characters (`<= 256` bytes).
    pub label: String,
}

impl NotaryEntry {
    /// Validates non-zero digest, positive height, and label bounds.
    ///
    /// # Errors
    ///
    /// Returns [`NotaryError`] when any field violates its invariant.
    pub fn validate(&self) -> Result<(), NotaryError> {
        if bool::from(self.document_digest.ct_eq(&[0u8; 32])) {
            return Err(NotaryError::ZeroDigest {
                field: "document_digest",
            });
        }
        if self.height == 0 {
            return Err(NotaryError::ZeroHeight);
        }
        if self.label.len() > MAX_NOTARY_LABEL_BYTES
            || self.label.bytes().any(|b| b < 0x20 || b == 0x7f)
        {
            return Err(NotaryError::InvalidLabel);
        }
        Ok(())
    }

    /// Canonical domain-separated SHA3-256 leaf digest:
    /// `SHA3-256(BDLM_NOTARY_LEAF_V1 || document_digest || height_le || label_len_le || label)`.
    #[must_use]
    pub fn leaf_digest(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"BDLM_NOTARY_LEAF_V1");
        hasher.update(self.document_digest);
        hasher.update(self.height.to_le_bytes());
        hasher.update((self.label.len() as u64).to_le_bytes());
        hasher.update(self.label.as_bytes());
        hasher.finalize().into()
    }
}

/// Merkle inclusion proof binding one [`NotaryEntry`] to a notary batch root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotaryInclusionProof {
    /// The notarized entry whose membership is proven.
    pub entry: NotaryEntry,
    /// Zero-based position in the notary batch.
    pub leaf_index: u64,
    /// Total number of leaves in the notary batch (`>= 1`).
    pub leaf_count: u64,
    /// Sibling digests from leaf layer up to root, using
    /// [`odd_promotion_sentinel`] for promoted odd tails.
    pub siblings: Vec<[u8; 32]>,
}

/// Merkle inclusion proof binding one [`PqAnchor`] to a [`RootSeal`]'s `anchors_root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealAnchorInclusionProof {
    /// Zero-based position of the anchor inside the seal's ordered anchor list.
    pub anchor_index: u64,
    /// Total number of anchors covered by the seal (`== seal.anchor_count`).
    pub anchor_count: u64,
    /// Sibling digests from anchor leaf layer up to `seal.anchors_root`.
    pub siblings: Vec<[u8; 32]>,
}

/// Complete self-contained offline proof binding a digest to the SLH-DSA Root Seal chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotaryTimestampProof {
    /// Operational mode under which the anchor/seal bundle was constructed.
    pub anchor_mode: AnchorMode,
    /// Inclusion of the document entry in the block's notary root.
    pub notary_proof: NotaryInclusionProof,
    /// The PQ anchor whose `aggregate_root` commits to the notary root.
    pub anchor: PqAnchor,
    /// Inclusion of the notary root leaf in `anchor.aggregate_root`.
    pub anchor_proof: AnchorInclusionProof,
    /// The SLH-DSA-SHAKE-256s Root Seal committing to `anchor`.
    pub seal: RootSeal,
    /// Inclusion of `anchor` in `seal.anchors_root`.
    pub seal_proof: SealAnchorInclusionProof,
    /// Optional subsequent Root Seals extending `seal` by `previous_seal == prev.digest()`.
    #[serde(default)]
    pub seal_chain: Vec<RootSeal>,
}

/// Verified offline timestamp metadata produced by [`verify_notary_proof_offline`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedNotaryTimestamp {
    /// Verified 32-byte notarized digest.
    pub document_digest: [u8; 32],
    /// Block height at which the entry was recorded.
    pub entry_height: u64,
    /// Anchor height binding the notary batch.
    pub anchor_height: u64,
    /// Height of the Root Seal committing the anchor.
    pub seal_height: u64,
    /// Height of the newest verified seal in the bundle (`>= seal_height`).
    pub latest_seal_height: u64,
    /// Digest of the newest verified Root Seal.
    pub latest_seal_digest: [u8; 32],
    /// Verified entry label.
    pub label: String,
    /// Cryptographic assumption class relied on (always [`QuantumClass::Hash`]).
    pub quantum_class: QuantumClass,
    /// Mode tag recorded on the bundle.
    pub anchor_mode: AnchorMode,
}

/// Failure reasons for notary anchoring and offline verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotaryError {
    #[error("notary field `{field}` must not be all-zero")]
    ZeroDigest { field: &'static str },
    #[error("notary entry height must be positive")]
    ZeroHeight,
    #[error("notary label exceeds {MAX_NOTARY_LABEL_BYTES} bytes or contains control bytes")]
    InvalidLabel,
    #[error("notary batch must contain at least one entry")]
    EmptyBatch,
    #[error("notary index {index} out of range for count {count}")]
    IndexOutOfRange { index: usize, count: usize },
    #[error("notary digest mismatch against expected document digest")]
    DigestMismatch,
    #[error("invalid Merkle inclusion proof: {0}")]
    InvalidMerkleProof(&'static str),
    #[error("notary anchor leaf must use hash-only quantum class")]
    NonHashAnchorClass,
    #[error("notary entry height {entry_height} exceeds anchor height {anchor_height}")]
    EntryAfterAnchor {
        entry_height: u64,
        anchor_height: u64,
    },
    #[error("anchor chain_id {got} does not match expected {expected}")]
    AnchorWrongChain { expected: u64, got: u64 },
    #[error("anchor height {anchor_height} lies outside seal period ending at {seal_height}")]
    AnchorOutsideSealPeriod {
        anchor_height: u64,
        seal_height: u64,
    },
    #[error("seal anchor count {seal_count} disagrees with proof count {proof_count}")]
    SealCountMismatch { seal_count: u32, proof_count: u64 },
    #[error("root seal verification failed: {0}")]
    Seal(#[from] SealError),
    #[error("anchor proof construction failed: {0}")]
    Anchor(#[from] AnchorError),
    #[error("root seal chain link broken at seal height {seal_height}")]
    BrokenSealChain { seal_height: u64 },
    #[error("too many chained root seals ({presented} > {MAX_NOTARY_CHAIN_EXTENSIONS})")]
    TooManyChainExtensions { presented: usize },
    #[error("production notary mode is gated off until production anchor approval")]
    ProductionModeBlocked,
    #[error("SLH-DSA-SHAKE-256s public key must be {SLH_DSA_SHAKE_256S_PK_LEN} bytes, got {got}")]
    InvalidPublicKeyLength { got: usize },
}

/// Offline [`SealKeys`] backed by a single pinned SLH-DSA-SHAKE-256s public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticSealKeySet {
    key_index: u8,
    public_key: Vec<u8>,
}

impl StaticSealKeySet {
    /// Construct a pinned single-slot key set for offline SLH-DSA-SHAKE-256s verification.
    ///
    /// # Errors
    ///
    /// Returns [`NotaryError::InvalidPublicKeyLength`] if `public_key` is not 64 bytes.
    pub fn new(key_index: u8, public_key: Vec<u8>) -> Result<Self, NotaryError> {
        if public_key.len() != SLH_DSA_SHAKE_256S_PK_LEN {
            return Err(NotaryError::InvalidPublicKeyLength {
                got: public_key.len(),
            });
        }
        Ok(Self {
            key_index,
            public_key,
        })
    }
}

impl SealKeys for StaticSealKeySet {
    fn seal_key(&self, index: u8) -> Option<&[u8]> {
        (index == self.key_index).then_some(self.public_key.as_slice())
    }

    fn seal_key_suspended(&self, _index: u8, _key_epoch: u32) -> bool {
        false
    }
}

/// Bijective SHA3-256 Merkle inclusion verifier matching `pq_anchor_verify.rs`.
fn verify_sha3_merkle_inclusion(
    leaf_digest: [u8; 32],
    leaf_index: u64,
    leaf_count: u64,
    siblings: &[[u8; 32]],
    expected_root: &[u8; 32],
    max_depth: usize,
) -> Result<(), NotaryError> {
    if leaf_count == 0 {
        return Err(NotaryError::InvalidMerkleProof("leaf count is zero"));
    }
    if max_depth < 64 && leaf_count > (1u64 << max_depth) {
        return Err(NotaryError::InvalidMerkleProof(
            "leaf count exceeds maximum Merkle tree capacity",
        ));
    }
    if leaf_index >= leaf_count {
        return Err(NotaryError::InvalidMerkleProof(
            "leaf index out of range for declared leaf count",
        ));
    }
    if siblings.len() > max_depth {
        return Err(NotaryError::InvalidMerkleProof(
            "inclusion path exceeds maximum Merkle depth",
        ));
    }

    let sentinel = odd_promotion_sentinel();
    let mut current = leaf_digest;
    let mut idx = leaf_index;
    let mut layer_len = leaf_count;

    for sibling in siblings {
        if layer_len <= 1 {
            return Err(NotaryError::InvalidMerkleProof(
                "inclusion path carries extra siblings past the Merkle root",
            ));
        }
        let is_odd = (idx & 1) == 1;
        let must_promote = !is_odd && idx.saturating_add(1) == layer_len;
        let is_sentinel = bool::from(sibling.ct_eq(&sentinel));
        if is_sentinel != must_promote {
            return Err(NotaryError::InvalidMerkleProof(
                "promotion sentinel disagrees with exact layer-tail geometry",
            ));
        }
        if must_promote {
            current = promote_sha3(&current);
        } else {
            if bool::from(sibling.ct_eq(&[0u8; 32])) {
                return Err(NotaryError::ZeroDigest {
                    field: "inclusion sibling",
                });
            }
            current = if is_odd {
                combine_sha3(sibling, &current)
            } else {
                combine_sha3(&current, sibling)
            };
        }
        idx >>= 1;
        layer_len = layer_len.div_ceil(2);
    }

    if layer_len != 1 {
        return Err(NotaryError::InvalidMerkleProof(
            "inclusion path stopped before reaching the Merkle root",
        ));
    }
    if !bool::from(current.ct_eq(expected_root)) {
        return Err(NotaryError::InvalidMerkleProof(
            "reconstructed Merkle root does not match commitment",
        ));
    }
    Ok(())
}

/// Compute the SHA3-256 Merkle root and inclusion proof for `entries[entry_index]`.
fn build_notary_inclusion_proof(
    entries: &[NotaryEntry],
    entry_index: usize,
) -> Result<([u8; 32], NotaryInclusionProof), NotaryError> {
    if entries.is_empty() {
        return Err(NotaryError::EmptyBatch);
    }
    if entry_index >= entries.len() {
        return Err(NotaryError::IndexOutOfRange {
            index: entry_index,
            count: entries.len(),
        });
    }
    let mut leaves = Vec::with_capacity(entries.len());
    for entry in entries {
        entry.validate()?;
        leaves.push(entry.leaf_digest());
    }
    let root = merkle_root(&leaves, combine_sha3, promote_sha3);
    let siblings = merkle_proof(&leaves, entry_index, combine_sha3, promote_sha3).ok_or(
        NotaryError::IndexOutOfRange {
            index: entry_index,
            count: entries.len(),
        },
    )?;
    if siblings.len() > MAX_NOTARY_MERKLE_DEPTH {
        return Err(NotaryError::InvalidMerkleProof(
            "notary batch exceeds maximum Merkle depth",
        ));
    }
    let leaf_index = u64::try_from(entry_index)
        .map_err(|_| NotaryError::InvalidMerkleProof("notary leaf index overflows u64"))?;
    let leaf_count = u64::try_from(entries.len())
        .map_err(|_| NotaryError::InvalidMerkleProof("notary leaf count overflows u64"))?;
    let entry = entries
        .get(entry_index)
        .cloned()
        .ok_or(NotaryError::InvalidMerkleProof(
            "notary entry index out of bounds",
        ))?;
    Ok((
        root,
        NotaryInclusionProof {
            entry,
            leaf_index,
            leaf_count,
            siblings,
        },
    ))
}

/// Build the Merkle inclusion proof for `period_anchors[anchor_index]` inside
/// the Root Seal period ending at `seal_height`.
fn build_seal_anchor_inclusion_proof(
    seal_height: u64,
    period_anchors: &[PqAnchor],
    anchor_index: usize,
) -> Result<SealAnchorInclusionProof, NotaryError> {
    let (_root, count) = period_anchors_root(seal_height, period_anchors)?;
    if anchor_index >= period_anchors.len() {
        return Err(NotaryError::IndexOutOfRange {
            index: anchor_index,
            count: period_anchors.len(),
        });
    }
    let leaves: Vec<[u8; 32]> = period_anchors.iter().map(anchor_leaf).collect();
    let siblings = merkle_proof(&leaves, anchor_index, combine_sha3, promote_sha3).ok_or(
        NotaryError::IndexOutOfRange {
            index: anchor_index,
            count: period_anchors.len(),
        },
    )?;
    Ok(SealAnchorInclusionProof {
        anchor_index: u64::try_from(anchor_index)
            .map_err(|_| NotaryError::InvalidMerkleProof("anchor index overflows u64"))?,
        anchor_count: u64::from(count),
        siblings,
    })
}

/// Parameters for anchoring a notary batch into a fresh SLH-DSA Root Seal bundle.
pub struct NotaryAnchorRequest<'a> {
    pub mode: AnchorMode,
    pub chain_id: u64,
    pub anchor_height: u64,
    pub seal_height: u64,
    pub key_epoch: u32,
    pub key_index: u8,
    pub previous_seal: Option<&'a RootSeal>,
    pub extra_anchor_leaves: &'a [AnchorLeaf],
    pub extra_period_anchors: &'a [PqAnchor],
}

/// Anchor a batch of [`NotaryEntry`] items into a `PqAnchor` and SLH-DSA-SHAKE-256s
/// [`RootSeal`], returning the offline-verifiable proof for `entries[entry_index]`.
///
/// # Errors
///
/// Refuses production mode when unapproved, invalid entries, heights outside
/// the seal period, or seal signing errors.
pub fn anchor_notary_entries(
    req: &NotaryAnchorRequest<'_>,
    entries: &[NotaryEntry],
    entry_index: usize,
    signer: &dyn SealSigner,
) -> Result<NotaryTimestampProof, NotaryError> {
    if enforce_anchor_mode(req.mode).is_err() {
        return Err(NotaryError::ProductionModeBlocked);
    }
    if !seal_due(req.seal_height) {
        return Err(NotaryError::Seal(SealError::HeightNotOnBoundary {
            height: req.seal_height,
        }));
    }
    let period_start = req.seal_height - ROOT_SEAL_INTERVAL;
    if req.anchor_height <= period_start || req.anchor_height > req.seal_height {
        return Err(NotaryError::AnchorOutsideSealPeriod {
            anchor_height: req.anchor_height,
            seal_height: req.seal_height,
        });
    }

    let (notary_root, notary_proof) = build_notary_inclusion_proof(entries, entry_index)?;
    if notary_proof.entry.height > req.anchor_height {
        return Err(NotaryError::EntryAfterAnchor {
            entry_height: notary_proof.entry.height,
            anchor_height: req.anchor_height,
        });
    }

    let mut anchor_leaves = Vec::with_capacity(1 + req.extra_anchor_leaves.len());
    anchor_leaves.push(AnchorLeaf {
        finality_digest: notary_root,
        quantum_class: QuantumClass::Hash,
    });
    anchor_leaves.extend_from_slice(req.extra_anchor_leaves);

    let leaf_digests: Vec<[u8; 32]> = anchor_leaves.iter().map(anchor_leaf_digest).collect();
    let aggregate_root = aggregate_finality_roots(&leaf_digests)?;
    let anchor_proof = build_anchor_inclusion_proof(&anchor_leaves, 0)?;

    let anchor = PqAnchor {
        chain_id: req.chain_id,
        height: req.anchor_height,
        aggregate_root,
        stark_root: None,
        crossdomain_root: None,
        key_epoch: req.key_epoch,
        signatures: Vec::new(),
    };

    let mut period_anchors: Vec<PqAnchor> = req.extra_period_anchors.to_vec();
    period_anchors.push(anchor.clone());
    period_anchors.sort_by_key(|a| a.height);
    if period_anchors.len() > MAX_SEAL_ANCHORS {
        return Err(NotaryError::Seal(SealError::TooManyAnchors {
            max: MAX_SEAL_ANCHORS,
            presented: period_anchors.len(),
        }));
    }
    let anchor_idx = period_anchors
        .iter()
        .position(|a| a.height == anchor.height && a.aggregate_root == anchor.aggregate_root)
        .ok_or(NotaryError::InvalidMerkleProof(
            "constructed anchor missing from period list",
        ))?;

    let seal = build_root_seal(
        req.chain_id,
        req.seal_height,
        &period_anchors,
        req.previous_seal,
        req.key_epoch,
        req.key_index,
        signer,
    )?;
    let seal_proof =
        build_seal_anchor_inclusion_proof(req.seal_height, &period_anchors, anchor_idx)?;

    Ok(NotaryTimestampProof {
        anchor_mode: req.mode,
        notary_proof,
        anchor,
        anchor_proof,
        seal,
        seal_proof,
        seal_chain: Vec::new(),
    })
}

/// Verify a [`NotaryTimestampProof`] completely offline using only SHA3-256 and
/// SLH-DSA-SHAKE-256s (zero lattice assumptions, zero network calls).
///
/// # Errors
///
/// Fails closed on any tampered digest, invalid Merkle proof geometry, wrong
/// chain/epoch/period, non-hash anchor class, invalid SLH-DSA signature, or
/// broken Root Seal hash chain.
pub fn verify_notary_proof_offline(
    proof: &NotaryTimestampProof,
    expected_digest: Option<[u8; 32]>,
    chain_id: u64,
    keys: &dyn SealKeys,
    current_key_epoch: u32,
) -> Result<VerifiedNotaryTimestamp, NotaryError> {
    if proof.seal_chain.len() > MAX_NOTARY_CHAIN_EXTENSIONS {
        return Err(NotaryError::TooManyChainExtensions {
            presented: proof.seal_chain.len(),
        });
    }

    // 1. Validate entry invariants and optional caller-supplied digest match.
    proof.notary_proof.entry.validate()?;
    if let Some(expected) = expected_digest {
        if bool::from(expected.ct_eq(&[0u8; 32])) {
            return Err(NotaryError::ZeroDigest {
                field: "expected_digest",
            });
        }
        if !bool::from(proof.notary_proof.entry.document_digest.ct_eq(&expected)) {
            return Err(NotaryError::DigestMismatch);
        }
    }

    // 2. Anchor leaf must declare hash-only security and commit to notary_root.
    if proof.anchor_proof.leaf.quantum_class != QuantumClass::Hash {
        return Err(NotaryError::NonHashAnchorClass);
    }
    let notary_root = proof.anchor_proof.leaf.finality_digest;
    if bool::from(notary_root.ct_eq(&[0u8; 32])) {
        return Err(NotaryError::ZeroDigest {
            field: "notary_root",
        });
    }
    verify_sha3_merkle_inclusion(
        proof.notary_proof.entry.leaf_digest(),
        proof.notary_proof.leaf_index,
        proof.notary_proof.leaf_count,
        &proof.notary_proof.siblings,
        &notary_root,
        MAX_NOTARY_MERKLE_DEPTH,
    )?;

    // 3. Verify notary_root leaf inclusion in PqAnchor.aggregate_root (pure SHA3-256).
    if proof.anchor.chain_id != chain_id {
        return Err(NotaryError::AnchorWrongChain {
            expected: chain_id,
            got: proof.anchor.chain_id,
        });
    }
    if proof.notary_proof.entry.height > proof.anchor.height {
        return Err(NotaryError::EntryAfterAnchor {
            entry_height: proof.notary_proof.entry.height,
            anchor_height: proof.anchor.height,
        });
    }
    verify_sha3_merkle_inclusion(
        anchor_leaf_digest(&proof.anchor_proof.leaf),
        proof.anchor_proof.leaf_index,
        proof.anchor_proof.leaf_count,
        &proof.anchor_proof.siblings,
        &proof.anchor.aggregate_root,
        MAX_ANCHOR_MERKLE_DEPTH,
    )?;

    // 4. Verify PqAnchor lies inside the Root Seal's 3,600-block period and
    //    its leaf digest is included in RootSeal.anchors_root (pure SHA3-256).
    if !seal_due(proof.seal.seal_height) {
        return Err(NotaryError::Seal(SealError::HeightNotOnBoundary {
            height: proof.seal.seal_height,
        }));
    }
    let period_start = proof.seal.seal_height - ROOT_SEAL_INTERVAL;
    if proof.anchor.height <= period_start || proof.anchor.height > proof.seal.seal_height {
        return Err(NotaryError::AnchorOutsideSealPeriod {
            anchor_height: proof.anchor.height,
            seal_height: proof.seal.seal_height,
        });
    }
    if proof.seal_proof.anchor_count != u64::from(proof.seal.anchor_count) {
        return Err(NotaryError::SealCountMismatch {
            seal_count: proof.seal.anchor_count,
            proof_count: proof.seal_proof.anchor_count,
        });
    }
    verify_sha3_merkle_inclusion(
        anchor_leaf(&proof.anchor),
        proof.seal_proof.anchor_index,
        proof.seal_proof.anchor_count,
        &proof.seal_proof.siblings,
        &proof.seal.anchors_root,
        MAX_SEAL_MERKLE_DEPTH,
    )?;

    // 5. Verify SLH-DSA-SHAKE-256s Root Seal signature (hash-only).
    verify_root_seal(&proof.seal, chain_id, keys, current_key_epoch, None)?;

    // 6. Verify any chained successor seals in strict ascending order.
    let mut latest = &proof.seal;
    for next in &proof.seal_chain {
        if next.seal_height <= latest.seal_height {
            return Err(NotaryError::BrokenSealChain {
                seal_height: next.seal_height,
            });
        }
        let expected_link = latest.digest();
        if !bool::from(next.previous_seal.ct_eq(&expected_link)) {
            return Err(NotaryError::BrokenSealChain {
                seal_height: next.seal_height,
            });
        }
        verify_root_seal(next, chain_id, keys, current_key_epoch, None)?;
        latest = next;
    }

    Ok(VerifiedNotaryTimestamp {
        document_digest: proof.notary_proof.entry.document_digest,
        entry_height: proof.notary_proof.entry.height,
        anchor_height: proof.anchor.height,
        seal_height: proof.seal.seal_height,
        latest_seal_height: latest.seal_height,
        latest_seal_digest: latest.digest(),
        label: proof.notary_proof.entry.label.clone(),
        quantum_class: QuantumClass::Hash,
        anchor_mode: proof.anchor_mode,
    })
}
