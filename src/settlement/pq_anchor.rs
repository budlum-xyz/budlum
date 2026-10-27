//! The post-quantum anchor for GlobalBlockHeader-level trust (Anchor V2).
//!
//! WIRING: wired - anchor emission runs from the committed global headers in
//! `src/chain/blockchain.rs` through
//! `super::anchor_production::AnchorEmission::on_checkpoint`, node-local and
//! mode-gated (devnet writes the anchor line; production needs the three
//! conditions of [`AnchorMode::ProductionApproved`], checked by
//! `super::anchor_production::enforce_production`). The stand-alone
//! [`emit_anchor_node_local`] keeps refusing production mode: it has no
//! grant. Cold-wallet key rotation enters through
//! `Blockchain::rotate_anchor_key_with_committee`, which drives
//! [`rotate_anchor_key_with_committee`] here. Rules are pinned by this
//! file's tests.
//!
//! Budlum has four consensus domains (PoW, PoS, BFT, PoA), and each produces
//! its own finality proof. Instead of making every domain separately
//! post-quantum, this module binds them under a single PQ boundary: the
//! domain finality records are aggregated into one Merkle tree, and
//! post-quantum signatures are placed over the aggregation root. A node or a
//! mobile/browser wallet (via budlum-wallet-core) then verifies two
//! signatures plus one Merkle root instead of per-domain verification logic.
//!
//! Decisions this file implements:
//!
//! - **Anchor V2: two of three ML-DSA-87 keys.** The keys sit in
//!   three separate HSMs from at least two vendors and are listed in the key
//!   ledger of genesis ([`super::anchor_ledger`]). A signature names its key by
//!   the index in the ledger and carries no public key. A single signature is
//!   refused by full and by light verification alike. Two different anchors
//!   at one height are evidence that suspends the key epoch of the keys that
//!   signed both.
//! - **Leaves carry the finality digest and the quantum class.** Each leaf of
//!   the aggregation tree is the domain finality digest and the weakest
//!   quantum class behind it ([`AnchorLeaf`]).
//! - **Hash-based family: SLH-DSA-SHAKE-256s**. It replaced the
//!   reserved SPHINCS+ slot. It signs the hourly Root Seal
//!   ([`super::root_seal`]) and the cold committee devices. Reserved
//!   algorithms still fail closed, never open.
//! - **BPQS: research track.** Our own blockchained-PQ variant stays a
//!   reserved identifier, not a production signer.
//! - **Anchor-break response: the cold committee signs the reserve anchor
//!   directly** (3-of-6 SLH-DSA-SHAKE-256s devices, no on-chain vote required
//!   in the emergency), via [`rotate_anchor_key_with_committee`].
//! - **VerifyMerkle only on the `stark_root` path.** The anchor
//!   signature covers a local SHA3 Merkle root, and VerifyMerkle does not run
//!   on that path. Only an anchor that carries a `stark_root` depends on the
//!   VerifyMerkle audit.
//!
//! # What this is not
//!
//! This module does not modify `GlobalBlockHeader`. The anchor is a sibling
//! record bound to a height and to roots the header already commits.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use super::cold_quorum::{verify_quorum, DeviceSignature, QuorumError};
use super::cold_wallet::{ColdWalletState, RotationError};
use crate::consensus::merkle_tree::{combine_sha3, merkle_root, promote_sha3};
use crate::crypto::facts::QuantumClass;
use crate::domain::types::ConsensusKind;

#[cfg(test)]
pub(crate) use super::pq_anchor_verify::check_signature_list;
pub use super::pq_anchor_verify::{verify_anchor_full, verify_anchor_light, MAX_ANCHOR_SIGNATURES};

/// Blocks between two anchors: one per 360 blocks, six minutes at the
/// one second block time.
pub const ANCHOR_INTERVAL: u64 = 360;

/// Whether an anchor is due at the checkpoint `height`: a positive multiple of
/// [`ANCHOR_INTERVAL`]. Every network's checkpoint interval divides 360.
#[must_use]
pub fn anchor_due(height: u64) -> bool {
    height > 0 && height.is_multiple_of(ANCHOR_INTERVAL)
}

/// The signature schemes the anchor surface understands.
///
/// The reserved variant exists so that the wire format can name the future
/// algorithm without pretending today's code verifies it. Anything that
/// [`AnchorSignatureAlgorithm::is_supported`] does not accept fails closed in
/// verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnchorSignatureAlgorithm {
    /// FIPS 204 ML-DSA at parameter set 87 (Category 5). The anchor payload
    /// signature (`ctx = BDLM/ANCHOR/V2`).
    MlDsa87,
    /// FIPS 205 SLH-DSA-SHAKE-256s (Category 5, hash based). The Root Seal
    /// signature (`ctx = BDLM/SEAL/V1`, [`super::root_seal`]) and the cold
    /// committee device signature (`ctx = BDLM/COLD/V1`). It never signs an
    /// anchor payload: the anchor signature list refuses it.
    SlhDsaShake256s,
    /// The project's own blockchained-PQ signature variant - reserved for
    /// the research track. No verifier exists; fails closed.
    BudlumBpqsReserved,
}

impl AnchorSignatureAlgorithm {
    /// Whether a verifier for this algorithm exists in this build.
    #[must_use]
    pub fn is_supported(self) -> bool {
        matches!(self, Self::MlDsa87 | Self::SlhDsaShake256s)
    }

    /// The registry identifier of the scheme, `None` for the reserved slot.
    #[must_use]
    pub fn scheme_id(self) -> Option<crate::crypto::scheme::SchemeId> {
        match self {
            Self::MlDsa87 => Some(crate::crypto::scheme::SchemeId::ML_DSA_87),
            Self::SlhDsaShake256s => Some(crate::crypto::scheme::SchemeId::SLH_DSA_SHAKE_256S),
            Self::BudlumBpqsReserved => None,
        }
    }
}

/// One signature over the canonical anchor payload (Anchor V2).
///
/// The signature names its key by the slot in the genesis key ledger and
/// carries no public key: trust comes from the ledger, never from bytes the
/// signature brings along. The scheme is fixed by the ledger (ML-DSA-87) and
/// is inside the signed payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorSignature {
    /// The slot of the signing key in the ledger's anchor keys.
    pub key_index: u8,
    /// The ML-DSA-87 signature (4,627 bytes).
    pub signature: Vec<u8>,
}

/// The byte of a quantum class folded into a leaf.
///
/// The class is the weakest assumption behind a finality record, a fact and
/// not a score (`crate::crypto::facts`).
#[must_use]
pub fn quantum_class_code(class: QuantumClass) -> u8 {
    match class {
        QuantumClass::Classical => 1,
        QuantumClass::Lattice => 2,
        QuantumClass::Hash => 3,
    }
}

/// The quantum class of one domain by its consensus kind: the composite
/// ML-DSA-65 plus Ed25519 blocks of PoS, BFT and PoA are lattice based, proof
/// of work and zk proofs are hash based, and a kind the node cannot assess
/// counts as classical (the weakest reading, never the strongest).
#[must_use]
pub fn domain_quantum_class(kind: &ConsensusKind) -> QuantumClass {
    match kind {
        ConsensusKind::PoS | ConsensusKind::Bft | ConsensusKind::PoA => QuantumClass::Lattice,
        ConsensusKind::PoW | ConsensusKind::Zk => QuantumClass::Hash,
        _ => QuantumClass::Classical,
    }
}

/// The weakest class among the given consensus kinds. With no domain at all
/// the chain's own composite signatures are the only evidence: lattice.
pub fn weakest_domain_class<'a>(kinds: impl Iterator<Item = &'a ConsensusKind>) -> QuantumClass {
    kinds
        .map(domain_quantum_class)
        .min()
        .unwrap_or(QuantumClass::Lattice)
}

/// One leaf of the aggregation tree: the domain finality digest and the
/// quantum class behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorLeaf {
    /// The digest of the domain finality record the leaf stands for.
    pub finality_digest: [u8; 32],
    /// The weakest quantum class behind that record.
    pub quantum_class: QuantumClass,
}

/// The PQ anchor record, a sibling of the header at one height.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAnchor {
    /// The chain the anchor belongs to. Inside the signed payload, so an
    /// anchor cannot replay on another network that shares the keys.
    pub chain_id: u64,
    /// The chain height this anchor binds.
    pub height: u64,
    /// The Merkle root over the leaf digests, leaf order as presented by the
    /// caller (domain-id ascending, by contract).
    pub aggregate_root: [u8; 32],
    /// The STARK state-transition proof root, when the BudZero path bound
    /// one this height. Signed alongside, so one signature also answers
    /// "was the computation correct". Only this path depends on VerifyMerkle.
    pub stark_root: Option<[u8; 32]>,
    /// The CrossDomainMessage commitment root, when messages were committed
    /// this height. Same one-umbrella rule as `stark_root`.
    pub crossdomain_root: Option<[u8; 32]>,
    /// The committee key epoch in force when this anchor was assembled.
    pub key_epoch: u32,
    /// The signatures, at most one per ledger key.
    pub signatures: Vec<AnchorSignature>,
}

impl PqAnchor {
    /// The canonical payload the anchor signatures cover.
    #[must_use]
    pub fn payload(&self) -> Vec<u8> {
        anchor_payload_for(
            self.chain_id,
            self.height,
            &self.aggregate_root,
            self.stark_root.as_ref(),
            self.crossdomain_root.as_ref(),
            self.key_epoch,
        )
    }
}

/// Which mode the anchor pipeline runs in. Chosen by configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnchorMode {
    /// The anchor pipeline is inert. Default, and correct until wiring.
    GatedOff,
    /// Devnet/testnet assembly and verification only. Production state
    /// transitions must never consult it.
    Devnet,
    /// Claim to run in production. Needs an HSM backend, a recorded key
    /// ceremony and passing self-tests; see `super::anchor_production`.
    ProductionApproved,
}

/// Why an anchor operation refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorError {
    /// Aggregation needs at least one domain leaf; an empty tree's root is
    /// whatever the caller says it is, which is exactly the forgery surface
    /// this module exists to close.
    EmptyAggregation,
    /// The signature's algorithm has no verifier in this build (reserved
    /// family or future variant). Fail closed, always.
    UnsupportedAlgorithm { algorithm: AnchorSignatureAlgorithm },
    /// Signature bytes failed verification under the ledger key.
    InvalidSignature,
    /// The signature names a slot the ledger does not have.
    UnknownKeyIndex { index: u8 },
    /// BLG-0070: the anchor carries a rotated-out key epoch.
    StaleAnchorEpoch {
        anchor_epoch: u32,
        current_epoch: u32,
    },
    /// The anchor belongs to another chain.
    WrongChain { expected: u64, got: u64 },
    /// BLG-0075: the signature list is over its bound.
    TooManySignatures { max: usize, presented: usize },
    /// BLG-0075: the same ledger key signed twice in one list.
    DuplicateSignature,
    /// Fewer than two distinct, live, valid keys signed: a single
    /// signature is never an anchor.
    ThresholdNotReached { required: usize, valid: usize },
    /// A key slot is suspended for the epoch by equivocation evidence.
    KeySuspended { index: u8, key_epoch: u32 },
    /// The key ledger refused (malformed, or evidence that is no evidence).
    Ledger(&'static str),
    /// Production mode was requested without its conditions. The blocker is
    /// named, because a closed door that cannot say why it is closed gets
    /// opened "just to test".
    ProductionBlocked { blocker: &'static str },
    /// The committee quorum behind a rotation failed.
    CommitteeQuorum(QuorumError),
    /// The cold wallet refused the rotation itself.
    Rotation(RotationError),
    /// The signing backend is not compiled in this build (feature off).
    SigningBackendUnavailable(&'static str),
    /// The node-local anchor log could not be written. Node-local by
    /// contract, never consensus state - the reason is reported, nothing is
    /// retried silently.
    EmissionIo(&'static str),
}

impl AnchorError {
    /// A stable label.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::EmptyAggregation => "anchor-empty-aggregation",
            Self::UnsupportedAlgorithm { .. } => "anchor-unsupported-algorithm",
            Self::InvalidSignature => "anchor-invalid-signature",
            Self::UnknownKeyIndex { .. } => "anchor-unknown-key-index",
            Self::StaleAnchorEpoch { .. } => "anchor-stale-epoch",
            Self::WrongChain { .. } => "anchor-wrong-chain",
            Self::TooManySignatures { .. } => "anchor-too-many-signatures",
            Self::DuplicateSignature => "anchor-duplicate-signature",
            Self::ThresholdNotReached { .. } => "anchor-threshold-not-reached",
            Self::KeySuspended { .. } => "anchor-key-suspended",
            Self::Ledger(_) => "anchor-ledger",
            Self::ProductionBlocked { .. } => "anchor-production-blocked",
            Self::CommitteeQuorum(..) => "anchor-committee-quorum",
            Self::Rotation(..) => "anchor-committee-rotation",
            Self::SigningBackendUnavailable(_) => "anchor-signing-backend-unavailable",
            Self::EmissionIo(_) => "anchor-emission-io",
        }
    }
}

impl std::fmt::Display for AnchorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyAggregation => {
                write!(f, "anchor aggregation needs at least one domain leaf")
            }
            Self::UnsupportedAlgorithm { algorithm } => {
                write!(
                    f,
                    "anchor algorithm {algorithm:?} has no verifier in this build"
                )
            }
            Self::InvalidSignature => write!(f, "anchor signature failed verification"),
            Self::UnknownKeyIndex { index } => {
                write!(
                    f,
                    "anchor signature names key slot {index}, not in the ledger"
                )
            }
            Self::StaleAnchorEpoch {
                anchor_epoch,
                current_epoch,
            } => write!(
                f,
                "anchor key epoch {anchor_epoch} is stale (current {current_epoch})"
            ),
            Self::WrongChain { expected, got } => {
                write!(f, "anchor is for chain {got}, this is chain {expected}")
            }
            Self::TooManySignatures { max, presented } => write!(
                f,
                "anchor carries {presented} signatures, at most {max} are allowed"
            ),
            Self::DuplicateSignature => write!(f, "anchor repeats one key in its list"),
            Self::ThresholdNotReached { required, valid } => {
                write!(f, "anchor needs {required} valid keys, {valid} signed")
            }
            Self::KeySuspended { index, key_epoch } => write!(
                f,
                "anchor key slot {index} is suspended for epoch {key_epoch}"
            ),
            Self::Ledger(rule) => write!(f, "anchor key ledger: {rule}"),
            Self::ProductionBlocked { blocker } => {
                write!(f, "anchor production mode deliberately blocked: {blocker}")
            }
            Self::CommitteeQuorum(err) => write!(f, "anchor committee quorum: {err}"),
            Self::Rotation(err) => write!(f, "anchor committee rotation: {err}"),
            Self::SigningBackendUnavailable(feature) => {
                write!(f, "anchor signing backend unavailable: enable {feature}")
            }
            Self::EmissionIo(stage) => write!(f, "anchor emission log io: {stage}"),
        }
    }
}

impl std::error::Error for AnchorError {}

/// The canonical payload bytes that anchor signatures sign.
///
/// Domain-separated (`BDLM_PQ_ANCHOR_V2`), and every field is length-fixed
/// so alternative parse behaviour cannot split the signed surface. The scheme
/// identifier (ML-DSA-87), the chain id and the key epoch are inside the
/// payload: a rotated-out committee key, another network's anchor or a
/// signature under another scheme must not produce bytes that still verify
/// as current (INV-02).
#[must_use]
pub fn anchor_payload_for(
    chain_id: u64,
    height: u64,
    aggregate_root: &[u8; 32],
    stark_root: Option<&[u8; 32]>,
    crossdomain_root: Option<&[u8; 32]>,
    key_epoch: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(17 + 2 + 8 + 8 + 32 + 1 + 32 + 1 + 32 + 4);
    out.extend_from_slice(b"BDLM_PQ_ANCHOR_V2");
    out.extend_from_slice(&crate::crypto::scheme::SchemeId::ML_DSA_87.to_be_bytes());
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(aggregate_root);
    match stark_root {
        Some(root) => {
            out.push(1);
            out.extend_from_slice(root);
        }
        None => out.push(0),
    }
    match crossdomain_root {
        Some(root) => {
            out.push(1);
            out.extend_from_slice(root);
        }
        None => out.push(0),
    }
    out.extend_from_slice(&key_epoch.to_le_bytes());
    out
}

/// The domain-separated leaf commitment for one finality record in the
/// anchor aggregation:
/// `SHA3-256(BDLM_PQ_ANCHOR_AGG_V2 || finality_digest || quantum_class)`.
/// Callers building an anchor leaf MUST use this rather than the bare
/// finality digest, so a finality proof's digest cannot alias a leaf of any
/// other tree the chain aggregates with `merkle_root`, and so the quantum
/// class is part of what the signatures cover.
#[must_use]
pub fn anchor_leaf_digest(leaf: &AnchorLeaf) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(21 + 32 + 1);
    preimage.extend_from_slice(b"BDLM_PQ_ANCHOR_AGG_V2");
    preimage.extend_from_slice(&leaf.finality_digest);
    preimage.push(quantum_class_code(leaf.quantum_class));
    let mut hasher = Sha3_256::new();
    hasher.update(preimage);
    hasher.finalize().into()
}

/// Aggregates ordered leaf digests into the single root the anchor signs.
/// Uses the same SHA-3 helpers the QC blob trees use; the ordering contract
/// (domain-id ascending, as the caller presents it) is part of the signed
/// meaning.
///
/// # Errors
///
/// [`AnchorError::EmptyAggregation`] for no leaves.
pub fn aggregate_finality_roots(leaves: &[[u8; 32]]) -> Result<[u8; 32], AnchorError> {
    if leaves.is_empty() {
        return Err(AnchorError::EmptyAggregation);
    }
    Ok(merkle_root(leaves, combine_sha3, promote_sha3))
}

/// Where a signer's key lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerBackend {
    /// A key in process memory. Devnet and tests.
    Software,
    /// A non-exportable key in an HSM behind PKCS#11.
    Hsm,
}

/// Who signs anchors. A trait rather than a keypair type: software keys on
/// devnet, HSM/PKCS#11 in production, behind the same surface.
pub trait AnchorSigner {
    /// The slot of this signer's key in the ledger's anchor keys.
    fn key_index(&self) -> u8;
    /// Where the key lives. Production mode refuses anything but
    /// [`SignerBackend::Hsm`].
    fn backend(&self) -> SignerBackend;
    /// The raw public key bytes (ML-DSA-87).
    fn public_key(&self) -> Vec<u8>;
    /// Signs the canonical payload.
    ///
    /// # Errors
    ///
    /// Any backend refusal: rng failure, backend not compiled, vendor call
    /// failure. Never silently substituted output.
    fn sign(&self, payload: &[u8]) -> Result<AnchorSignature, AnchorError>;
}

/// Software ML-DSA-87 signer over the hedged wallet-pillar keying path.
#[cfg(feature = "wallet-ml-dsa")]
pub struct SoftwareMlDsa87Signer {
    key_index: u8,
    keypair: crate::crypto::primitives::WalletKeyPair,
}

#[cfg(feature = "wallet-ml-dsa")]
impl SoftwareMlDsa87Signer {
    /// Generates a fresh keypair behind a software signer for ledger slot
    /// `key_index`.
    #[must_use]
    pub fn generate(key_index: u8) -> Self {
        Self {
            key_index,
            keypair: crate::crypto::primitives::WalletKeyPair::generate(),
        }
    }

    /// Rebuilds the signer from a 32-byte FIPS 204 seed, the form a devnet
    /// key file holds.
    #[must_use]
    pub fn from_seed(key_index: u8, seed: &[u8; 32]) -> Self {
        Self {
            key_index,
            keypair: crate::crypto::primitives::WalletKeyPair::from_seed(seed),
        }
    }
}

#[cfg(feature = "wallet-ml-dsa")]
impl AnchorSigner for SoftwareMlDsa87Signer {
    fn key_index(&self) -> u8 {
        self.key_index
    }

    fn backend(&self) -> SignerBackend {
        SignerBackend::Software
    }

    fn public_key(&self) -> Vec<u8> {
        self.keypair.public_key_bytes().to_vec()
    }

    fn sign(&self, payload: &[u8]) -> Result<AnchorSignature, AnchorError> {
        let signature = self.keypair.sign(crate::crypto::ctx::ANCHOR_V2, payload);
        Ok(AnchorSignature {
            key_index: self.key_index,
            signature: signature.to_vec(),
        })
    }
}

/// The documented-but-unconfigured front for HSM/PKCS#11 custody. Using it
/// fails loudly with the blocker named rather than falling back to anything.
/// A node with real HSM signers replaces it with
/// [`super::anchor_production::HsmAnchorSigner`].
pub struct HsmSignerStub {
    /// Which vendor/device this stub stands for, for audit text.
    pub vendor_label: String,
    /// The ledger slot the stub stands for.
    pub key_index: u8,
}

impl AnchorSigner for HsmSignerStub {
    fn key_index(&self) -> u8 {
        self.key_index
    }

    fn backend(&self) -> SignerBackend {
        SignerBackend::Software
    }

    fn public_key(&self) -> Vec<u8> {
        Vec::new()
    }

    fn sign(&self, _payload: &[u8]) -> Result<AnchorSignature, AnchorError> {
        Err(AnchorError::ProductionBlocked {
            blocker: "hsm-signer-not-configured",
        })
    }
}

/// What one emission needs besides the signers.
#[derive(Debug, Clone, Copy)]
pub struct EmissionRequest<'a> {
    /// The chain the anchor is for.
    pub chain_id: u64,
    /// The checkpoint height the anchor binds.
    pub height: u64,
    /// The finality leaves of the window.
    pub window_leaves: &'a [AnchorLeaf],
    /// The STARK root, when the BudZero path bound one.
    pub stark_root: Option<[u8; 32]>,
    /// The cross-domain commitment root, when messages were committed.
    pub crossdomain_root: Option<[u8; 32]>,
    /// The key epoch the anchor is signed at.
    pub key_epoch: u32,
}

/// Production mode fails by construction here; the full set of conditions is
/// checked by `super::anchor_production::enforce_production`. Devnet and
/// harness modes proceed.
///
/// # Errors
///
/// [`AnchorError::ProductionBlocked`] when `mode` is
/// [`AnchorMode::ProductionApproved`].
pub fn enforce_anchor_mode(mode: AnchorMode) -> Result<(), AnchorError> {
    match mode {
        AnchorMode::GatedOff | AnchorMode::Devnet => Ok(()),
        AnchorMode::ProductionApproved => Err(AnchorError::ProductionBlocked {
            blocker: "production-conditions-unchecked",
        }),
    }
}

/// Assembles an anchor from ordered leaf digests plus optional STARK and
/// cross-domain roots, signed by the given signers.
///
/// A signer that fails is skipped as long as two distinct keys still sign:
/// one unavailable HSM must not stop the anchor, and a single signature is
/// never an anchor.
///
/// # Errors
///
/// [`AnchorError::EmptyAggregation`] for no leaves,
/// [`AnchorError::DuplicateSignature`] when two signers share a slot, or
/// [`AnchorError::ThresholdNotReached`] (with the signer's refusal when only
/// one fault explains it).
pub fn assemble_anchor(
    chain_id: u64,
    height: u64,
    leaf_digests: &[[u8; 32]],
    roots: (Option<[u8; 32]>, Option<[u8; 32]>),
    key_epoch: u32,
    signers: &[&dyn AnchorSigner],
) -> Result<PqAnchor, AnchorError> {
    let (stark_root, crossdomain_root) = roots;
    let aggregate_root = aggregate_finality_roots(leaf_digests)?;
    let mut anchor = PqAnchor {
        chain_id,
        height,
        aggregate_root,
        stark_root,
        crossdomain_root,
        key_epoch,
        signatures: Vec::new(),
    };
    let payload = anchor.payload();
    let mut last_refusal: Option<AnchorError> = None;
    for signer in signers {
        if anchor
            .signatures
            .iter()
            .any(|s| s.key_index == signer.key_index())
        {
            return Err(AnchorError::DuplicateSignature);
        }
        match signer.sign(&payload) {
            Ok(signature) => anchor.signatures.push(signature),
            Err(err) => last_refusal = Some(err),
        }
    }
    if anchor.signatures.len() < super::anchor_ledger::ANCHOR_THRESHOLD {
        return Err(match last_refusal {
            Some(err) if signers.len() >= super::anchor_ledger::ANCHOR_THRESHOLD => err,
            _ => AnchorError::ThresholdNotReached {
                required: super::anchor_ledger::ANCHOR_THRESHOLD,
                valid: anchor.signatures.len(),
            },
        });
    }
    anchor.signatures.sort_by_key(|s| s.key_index);
    Ok(anchor)
}

/// The outcome of one emission attempt: whether an anchor record reached
/// the node-local log, or the mode said no. Distinct from an error so a
/// caller cannot mistake a deliberate gate for a failure (or vice versa).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmissionOutcome {
    /// The anchor was built and appended to the node-local log.
    Written,
    /// `GatedOff`: emission skipped by decision, not by failure.
    Skipped,
}

/// The emission driver: turn one finality window into a signed anchor record.
///
/// Binding rule: every window leaf (the finality digest and quantum class of
/// the global header) enters the anchor aggregation through
/// [`anchor_leaf_digest`], so the anchor tree's leaves can never alias a leaf
/// of the header's own tree even if the digests coincide. Consensus stays
/// untouched: this is a pure derivation whose only side effect is the
/// returned record.
///
/// # Errors
///
/// The refusals of [`assemble_anchor`].
pub fn build_anchor_for_height(
    request: &EmissionRequest<'_>,
    signers: &[&dyn AnchorSigner],
) -> Result<PqAnchor, AnchorError> {
    let leaf_digests: Vec<[u8; 32]> = request
        .window_leaves
        .iter()
        .map(anchor_leaf_digest)
        .collect();
    assemble_anchor(
        request.chain_id,
        request.height,
        &leaf_digests,
        (request.stark_root, request.crossdomain_root),
        request.key_epoch,
        signers,
    )
}

/// Append one anchor to the node-local JSONL log.
///
/// # Errors
///
/// [`AnchorError::EmissionIo`] naming the stage that failed.
pub fn append_anchor_log(log_path: &std::path::Path, anchor: &PqAnchor) -> Result<(), AnchorError> {
    let line =
        serde_json::to_string(anchor).map_err(|_| AnchorError::EmissionIo("json serialize"))?;
    use std::io::Write as _;
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| AnchorError::EmissionIo("mkdir"))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|_| AnchorError::EmissionIo("open"))?;
    writeln!(file, "{line}").map_err(|_| AnchorError::EmissionIo("append"))
}

/// Build the anchor and append it to the node-local JSONL log, under mode
/// control.
///
/// Mode semantics: `GatedOff` -> Ok(Skipped) (the gate is a decision,
/// recorded as such); `Devnet` -> build + append; `ProductionApproved` ->
/// Err(anchor-production-blocked) unless the conditions hold, see
/// `super::anchor_production`. The log is node-local by contract: it is not
/// consensus state and a node that loses it simply re-derives from the chain,
/// so an io failure is reported, never retried silently.
///
/// # Errors
///
/// The mode gate, the refusals of [`build_anchor_for_height`], or the log io.
pub fn emit_anchor_node_local(
    log_path: &std::path::Path,
    mode: AnchorMode,
    request: &EmissionRequest<'_>,
    signers: &[&dyn AnchorSigner],
) -> Result<EmissionOutcome, AnchorError> {
    if mode == AnchorMode::GatedOff {
        return Ok(EmissionOutcome::Skipped);
    }
    enforce_anchor_mode(mode)?;
    let anchor = build_anchor_for_height(request, signers)?;
    append_anchor_log(log_path, &anchor)?;
    Ok(EmissionOutcome::Written)
}

/// The cold-committee reserve-anchor channel (decision record 2026-09-17,
/// item 4): when the anchor key is compromised, the 3-of-6 cold committee
///   (SLH-DSA-SHAKE-256s devices) rotates the cold wallet's key epoch directly
///   - no on-chain vote stalls the response. The rotation certificate signed
///   by the committee is domain-separated (`BDLM_PQ_ANCHOR_ROTATION_V2`) and
///   binds the height and the reason, so a rotation nobody can explain
///   afterwards is as impossible here as it is in the cold wallet itself.
///
/// WIRING: this call is where `cold_wallet::ColdWalletState::rotate_key`
/// stops being merely pinned by its own tests and gains its named caller.
///
/// # Errors
///
/// [`AnchorError::CommitteeQuorum`] when the device quorum fails (distinct
/// devices, strict signatures, epoch pinned), or
/// [`AnchorError::Rotation`] when the wallet refuses the rotation.
pub fn rotate_anchor_key_with_committee(
    state: &mut ColdWalletState,
    at_height: u64,
    reason: &str,
    certificates: &[DeviceSignature],
) -> Result<u32, AnchorError> {
    // S2: the committee comes from the wallet's pinned state, never from
    // the caller.
    if state.trusted_devices.len() != state.policy.device_count as usize {
        return Err(AnchorError::CommitteeQuorum(
            QuorumError::IdentitySetSizeMismatch {
                device_count: state.policy.device_count,
                presented: state.trusted_devices.len(),
            },
        ));
    }
    let identities = state.trusted_devices.clone();
    let payload = rotation_payload(state, at_height, reason);
    let proven = verify_quorum(
        &state.policy,
        &identities,
        &payload,
        state.key_epoch,
        certificates,
    )
    .map_err(AnchorError::CommitteeQuorum)?;
    // The proven device count is part of the evidence; the wallet-side
    // quorum policy enforced it already inside `verify_quorum`.
    debug_assert!(proven.len() >= state.policy.required_quorum as usize);
    state
        .rotate_key(at_height, reason)
        .map_err(AnchorError::Rotation)
}

/// The payload the cold committee devices sign to rotate the anchor key.
///
/// BLG-0069 (P03-F12): the chain id is part of the signed payload. With the
/// same committee devices on two networks, a certificate without it could
/// replay across them and force an epoch bump on the other chain.
#[must_use]
pub fn rotation_payload(state: &ColdWalletState, at_height: u64, reason: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(26 + 8 + 8 + 8 + 32);
    payload.extend_from_slice(b"BDLM_PQ_ANCHOR_ROTATION_V2");
    payload.extend_from_slice(&state.policy.chain_id.to_le_bytes());
    payload.extend_from_slice(&at_height.to_le_bytes());
    payload.extend_from_slice(&u64::from(state.key_epoch).to_le_bytes());
    payload.extend_from_slice(&crate::core::hash::hash_fields_bytes(&[
        b"BDLM_PQ_ANCHOR_ROTATION_REASON_V1",
        reason.as_bytes(),
    ]));
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settlement::cold_quorum::dev_fixture_device_signers;
    use crate::settlement::cold_wallet::ColdWalletPolicy;

    const CHAIN: u64 = 45262;

    fn leaf(n: u8) -> AnchorLeaf {
        AnchorLeaf {
            finality_digest: [n; 32],
            quantum_class: QuantumClass::Lattice,
        }
    }

    fn leaves(n: usize) -> Vec<AnchorLeaf> {
        (0..n).map(|i| leaf(i as u8)).collect()
    }

    fn leaf_digests(n: usize) -> Vec<[u8; 32]> {
        leaves(n).iter().map(anchor_leaf_digest).collect()
    }

    /// Deterministic echo signer: produces structurally valid signatures
    /// without any real cryptography, for plumbing tests that verify the
    /// emission path itself, not the scheme (the scheme has its own tests
    /// behind `wallet-ml-dsa`).
    struct StubSigner(u8);

    impl AnchorSigner for StubSigner {
        fn key_index(&self) -> u8 {
            self.0
        }
        fn backend(&self) -> SignerBackend {
            SignerBackend::Software
        }
        fn public_key(&self) -> Vec<u8> {
            vec![7u8; 8]
        }
        fn sign(&self, payload: &[u8]) -> Result<AnchorSignature, AnchorError> {
            Ok(AnchorSignature {
                key_index: self.0,
                signature: payload[..8].to_vec(),
            })
        }
    }

    fn stubs() -> (StubSigner, StubSigner) {
        (StubSigner(0), StubSigner(1))
    }

    fn temp_log_path(name: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("pq-anchor-test-{name}-{}", std::process::id()));
        let _unused = std::fs::remove_dir_all(&dir);
        dir.push("anchors.jsonl");
        dir
    }

    fn request(window: &[AnchorLeaf]) -> EmissionRequest<'_> {
        EmissionRequest {
            chain_id: CHAIN,
            height: 360,
            window_leaves: window,
            stark_root: None,
            crossdomain_root: None,
            key_epoch: 1,
        }
    }

    #[test]
    fn anchors_are_due_every_360_blocks() {
        assert!(!anchor_due(0));
        assert!(!anchor_due(359));
        assert!(anchor_due(360));
        assert!(!anchor_due(361));
        assert!(anchor_due(3_600));
        for network_interval in [10u64, 5, 2] {
            assert_eq!(
                ANCHOR_INTERVAL % network_interval,
                0,
                "every checkpoint interval divides the anchor interval"
            );
        }
    }

    #[test]
    fn emission_driver_domain_separates_the_window_leaves() {
        let window = leaves(3);
        let (a, b) = stubs();
        let anchor = build_anchor_for_height(&request(&window), &[&a, &b])
            .expect("driver builds over three leaves");
        let separated = leaf_digests(3);
        assert_eq!(
            anchor.aggregate_root,
            aggregate_finality_roots(&separated).expect("three separated leaves aggregate")
        );
        let bare: Vec<[u8; 32]> = window.iter().map(|l| l.finality_digest).collect();
        assert_ne!(
            anchor.aggregate_root,
            aggregate_finality_roots(&bare).expect("bare leaves also aggregate"),
            "the anchor's tree must never share the header's bare leaf space"
        );
    }

    #[test]
    fn a_leaf_binds_its_digest_and_its_quantum_class() {
        let lattice = leaf(5);
        let hash_class = AnchorLeaf {
            quantum_class: QuantumClass::Hash,
            ..lattice
        };
        let classical = AnchorLeaf {
            quantum_class: QuantumClass::Classical,
            ..lattice
        };
        assert_ne!(
            anchor_leaf_digest(&lattice),
            anchor_leaf_digest(&hash_class)
        );
        assert_ne!(anchor_leaf_digest(&lattice), anchor_leaf_digest(&classical));
        assert_ne!(anchor_leaf_digest(&lattice), anchor_leaf_digest(&leaf(6)));
        assert_ne!(anchor_leaf_digest(&lattice), lattice.finality_digest);
        assert!(QuantumClass::Classical < QuantumClass::Lattice);
        assert!(QuantumClass::Lattice < QuantumClass::Hash);
    }

    #[test]
    fn emission_gated_off_skips_and_touches_no_file() {
        let path = temp_log_path("gated-off");
        let window = leaves(2);
        let (a, b) = stubs();
        let outcome =
            emit_anchor_node_local(&path, AnchorMode::GatedOff, &request(&window), &[&a, &b])
                .expect("gated off is a decision, not an error");
        assert_eq!(outcome, EmissionOutcome::Skipped);
        assert!(!path.exists(), "a skipped emission must not create the log");
    }

    #[test]
    fn emission_production_without_conditions_is_blocked() {
        let path = temp_log_path("production");
        let window = leaves(2);
        let (a, b) = stubs();
        let err = emit_anchor_node_local(
            &path,
            AnchorMode::ProductionApproved,
            &request(&window),
            &[&a, &b],
        )
        .expect_err("production stays blocked until its conditions hold");
        assert_eq!(err.kind(), "anchor-production-blocked");
        assert!(!path.exists(), "a blocked emission must not create the log");
    }

    #[test]
    fn emission_devnet_writes_one_jsonl_record() {
        let path = temp_log_path("devnet");
        let window = leaves(2);
        let (a, b) = stubs();
        let written =
            emit_anchor_node_local(&path, AnchorMode::Devnet, &request(&window), &[&a, &b])
                .expect("devnet emission writes the record");
        assert_eq!(written, EmissionOutcome::Written);
        let body = std::fs::read_to_string(&path).expect("the log exists");
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 1, "exactly one record per emission");
        let recorded: PqAnchor = serde_json::from_str(lines[0]).expect("the line is a PqAnchor");
        let expected = build_anchor_for_height(&request(&window), &[&a, &b])
            .expect("same inputs, same anchor");
        assert_eq!(recorded, expected);
        let _cleanup = std::fs::remove_dir_all(path.parent().expect("temp dir"));
    }

    #[test]
    fn one_signer_is_never_an_anchor() {
        let window = leaves(2);
        let (a, _) = stubs();
        let err = build_anchor_for_height(&request(&window), &[&a]).unwrap_err();
        assert_eq!(err.kind(), "anchor-threshold-not-reached");
    }

    #[test]
    fn two_signers_on_one_slot_are_refused() {
        let window = leaves(2);
        let err = build_anchor_for_height(&request(&window), &[&StubSigner(1), &StubSigner(1)])
            .unwrap_err();
        assert_eq!(err.kind(), "anchor-duplicate-signature");
    }

    #[test]
    fn empty_aggregation_is_refused_not_assumed() {
        let err = aggregate_finality_roots(&[]).unwrap_err();
        assert_eq!(err.kind(), "anchor-empty-aggregation");
    }

    #[test]
    fn aggregation_is_deterministic_for_ordered_leaves() {
        let a = aggregate_finality_roots(&leaf_digests(4)).unwrap();
        let b = aggregate_finality_roots(&leaf_digests(4)).unwrap();
        assert_eq!(a, b);
        // And order matters: a shuffled tree is a different tree.
        let mut shuffled = leaf_digests(4);
        shuffled.swap(0, 1);
        let c = aggregate_finality_roots(&shuffled).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn payload_binds_every_field_and_every_optional_flag() {
        let root = [7u8; 32];
        let bare = anchor_payload_for(CHAIN, 9, &root, None, None, 1);
        let with_stark = anchor_payload_for(CHAIN, 9, &root, Some(&[1u8; 32]), None, 1);
        let with_cross = anchor_payload_for(CHAIN, 9, &root, None, Some(&[2u8; 32]), 1);
        let other_height = anchor_payload_for(CHAIN, 10, &root, None, None, 1);
        let other_epoch = anchor_payload_for(CHAIN, 9, &root, None, None, 2);
        let other_chain = anchor_payload_for(CHAIN + 1, 9, &root, None, None, 1);
        assert!(bare.starts_with(b"BDLM_PQ_ANCHOR_V2"));
        assert_ne!(bare, with_stark);
        assert_ne!(bare, with_cross);
        assert_ne!(bare, other_height);
        assert_ne!(bare, other_epoch);
        assert_ne!(bare, other_chain);
        assert_ne!(with_stark, with_cross);
        // The scheme id (ML-DSA-87, 0x0103) sits right after the tag.
        assert_eq!(&bare[17..19], &[0x01, 0x03]);
        // Lengths are pinned: bare 17+2+8+8+32+1+1+4 = 73; with-roots grow by 32.
        assert_eq!(bare.len(), 73);
        assert_eq!(with_stark.len(), 105);
    }

    #[test]
    fn a_repeated_key_in_one_anchor_is_refused() {
        let sig = AnchorSignature {
            key_index: 1,
            signature: vec![2u8; 64],
        };
        let err = check_signature_list(&[sig.clone(), sig]).unwrap_err();
        assert_eq!(err.kind(), "anchor-duplicate-signature");
    }

    #[test]
    fn an_oversized_signature_list_is_refused_before_any_verify() {
        let list: Vec<AnchorSignature> = (0..=MAX_ANCHOR_SIGNATURES as u8)
            .map(|i| AnchorSignature {
                key_index: i,
                signature: vec![2u8; 64],
            })
            .collect();
        let err = check_signature_list(&list).unwrap_err();
        assert_eq!(err.kind(), "anchor-too-many-signatures");
    }

    #[test]
    fn an_empty_signature_list_has_no_threshold() {
        let err = check_signature_list(&[]).unwrap_err();
        assert_eq!(err.kind(), "anchor-threshold-not-reached");
    }

    #[test]
    fn production_mode_is_blocked_by_construction() {
        assert!(enforce_anchor_mode(AnchorMode::GatedOff).is_ok());
        assert!(enforce_anchor_mode(AnchorMode::Devnet).is_ok());
        let err = enforce_anchor_mode(AnchorMode::ProductionApproved).unwrap_err();
        assert_eq!(err.kind(), "anchor-production-blocked");
    }

    #[test]
    fn hsm_stub_names_its_blocker() {
        let stub = HsmSignerStub {
            vendor_label: "vendor-x".to_string(),
            key_index: 0,
        };
        let err = stub.sign(b"payload").unwrap_err();
        assert_eq!(err.kind(), "anchor-production-blocked");
    }

    #[cfg(feature = "wallet-ml-dsa")]
    mod signing {
        use super::*;
        use crate::settlement::anchor_ledger::{test_support, AnchorKeyLedger, ANCHOR_THRESHOLD};

        fn ledger() -> AnchorKeyLedger {
            test_support::software_ledger(CHAIN, 1)
        }

        fn anchor_with(which: &[u8], height: u64, root_tag: u8) -> PqAnchor {
            let signers: Vec<SoftwareMlDsa87Signer> =
                which.iter().map(|i| test_support::signer(*i)).collect();
            let mut dyns: Vec<&dyn AnchorSigner> = Vec::new();
            for signer in &signers {
                dyns.push(signer);
            }
            assemble_anchor(CHAIN, height, &[[root_tag; 32]], (None, None), 1, &dyns)
                .expect("anchor assembles")
        }

        #[test]
        fn two_of_three_verifies_through_full_and_light() {
            let ledger = ledger();
            let anchor = anchor_with(&[0, 2], 360, 1);
            assert_eq!(anchor.signatures.len(), ANCHOR_THRESHOLD);
            verify_anchor_full(&anchor, &ledger).expect("full verifies");
            verify_anchor_light(&anchor, &ledger).expect("light verifies");
            let all = anchor_with(&[0, 1, 2], 720, 2);
            verify_anchor_full(&all, &ledger).expect("three of three verifies");
        }

        #[test]
        fn a_single_signature_is_refused_by_full_and_by_light() {
            let ledger = ledger();
            let mut anchor = anchor_with(&[0, 1], 360, 1);
            anchor.signatures.truncate(1);
            let err = verify_anchor_full(&anchor, &ledger).unwrap_err();
            assert_eq!(err.kind(), "anchor-threshold-not-reached");
            let err = verify_anchor_light(&anchor, &ledger).unwrap_err();
            assert_eq!(err.kind(), "anchor-threshold-not-reached");
        }

        #[test]
        fn a_signer_that_is_down_does_not_stop_the_anchor() {
            let ledger = ledger();
            let down = HsmSignerStub {
                vendor_label: "offline".to_string(),
                key_index: 1,
            };
            let a = test_support::signer(0);
            let c = test_support::signer(2);
            let anchor =
                assemble_anchor(CHAIN, 360, &[[1u8; 32]], (None, None), 1, &[&a, &down, &c])
                    .expect("two live signers still anchor");
            verify_anchor_full(&anchor, &ledger).expect("verifies");
            let err = assemble_anchor(CHAIN, 360, &[[1u8; 32]], (None, None), 1, &[&a, &down])
                .unwrap_err();
            assert_eq!(err.kind(), "anchor-production-blocked");
        }

        #[test]
        fn a_tampered_anchor_fails_everywhere() {
            let ledger = ledger();
            let mut anchor = anchor_with(&[0, 1], 360, 1);
            anchor.height = 361;
            let err = verify_anchor_full(&anchor, &ledger).unwrap_err();
            assert_eq!(err.kind(), "anchor-invalid-signature");
            let err = verify_anchor_light(&anchor, &ledger).unwrap_err();
            assert_eq!(err.kind(), "anchor-threshold-not-reached");
        }

        #[test]
        fn a_signature_under_the_wrong_slot_does_not_count() {
            let ledger = ledger();
            let mut anchor = anchor_with(&[0, 1], 360, 1);
            // Relabel key 1's signature as key 2's: the ledger key of slot 2
            // did not sign it.
            anchor.signatures[1].key_index = 2;
            let err = verify_anchor_full(&anchor, &ledger).unwrap_err();
            assert_eq!(err.kind(), "anchor-invalid-signature");
            let err = verify_anchor_light(&anchor, &ledger).unwrap_err();
            assert_eq!(err.kind(), "anchor-threshold-not-reached");
            let mut unknown = anchor_with(&[0, 1], 360, 1);
            unknown.signatures[1].key_index = 9;
            let err = verify_anchor_full(&unknown, &ledger).unwrap_err();
            assert_eq!(err.kind(), "anchor-unknown-key-index");
        }

        #[test]
        fn chain_epoch_and_duplicates_are_bound() {
            let ledger = ledger();
            let anchor = anchor_with(&[0, 1], 360, 1);
            let mut other_chain = anchor.clone();
            other_chain.chain_id += 1;
            assert_eq!(
                verify_anchor_full(&other_chain, &ledger)
                    .unwrap_err()
                    .kind(),
                "anchor-wrong-chain"
            );
            let mut stale = anchor.clone();
            stale.key_epoch = 7;
            assert_eq!(
                verify_anchor_full(&stale, &ledger).unwrap_err().kind(),
                "anchor-stale-epoch"
            );
            assert_eq!(
                verify_anchor_light(&stale, &ledger).unwrap_err().kind(),
                "anchor-stale-epoch"
            );
            let mut twice = anchor.clone();
            twice.signatures[1] = twice.signatures[0].clone();
            assert_eq!(
                verify_anchor_full(&twice, &ledger).unwrap_err().kind(),
                "anchor-duplicate-signature"
            );
        }

        #[test]
        fn equivocation_suspends_the_key_epoch_of_the_double_signer() {
            let mut ledger = ledger();
            // Key 0 signs two different anchors at height 360; key 1 and key 2
            // each sign one of them.
            let first = anchor_with(&[0, 1], 360, 1);
            let second = anchor_with(&[0, 2], 360, 2);
            let suspended = ledger
                .apply_equivocation(&first, &second)
                .expect("a double signature is evidence");
            assert_eq!(suspended, vec![0]);
            // Key 0 no longer counts: the old two-key anchor drops to one live
            // key and the threshold fails; keys 1 and 2 still anchor.
            let err = verify_anchor_full(&first, &ledger).unwrap_err();
            assert_eq!(err.kind(), "anchor-threshold-not-reached");
            let healthy = anchor_with(&[1, 2], 720, 3);
            verify_anchor_full(&healthy, &ledger).expect("the live keys still anchor");
            assert_eq!(ledger.live_anchor_slots(1), vec![1, 2]);
            assert_eq!(ledger.live_anchor_slots(2).len(), 3, "a new epoch is clean");
        }

        #[test]
        fn pairs_that_are_not_equivocation_do_not_suspend() {
            let mut ledger = ledger();
            let a = anchor_with(&[0, 1], 360, 1);
            let same = a.clone();
            assert_eq!(
                ledger.apply_equivocation(&a, &same).unwrap_err().kind(),
                "ledger-not-equivocation"
            );
            let later = anchor_with(&[0, 1], 720, 2);
            assert_eq!(
                ledger.apply_equivocation(&a, &later).unwrap_err().kind(),
                "ledger-not-equivocation"
            );
            // Different keys signed the two anchors: nobody double signed.
            let mut left = anchor_with(&[0, 1], 360, 5);
            left.signatures.retain(|s| s.key_index == 0);
            let mut right = anchor_with(&[1, 2], 360, 6);
            right.signatures.retain(|s| s.key_index == 2);
            assert_eq!(
                ledger.apply_equivocation(&left, &right).unwrap_err().kind(),
                "ledger-no-common-signer"
            );
            assert!(ledger.suspended.is_empty());
            // A forged second anchor (garbage signatures) is no evidence either.
            let mut forged = anchor_with(&[0, 1], 360, 7);
            forged.signatures[0].signature[10] ^= 1;
            forged.signatures[1].signature[10] ^= 1;
            assert_eq!(
                ledger.apply_equivocation(&a, &forged).unwrap_err().kind(),
                "ledger-no-common-signer"
            );
            assert!(ledger.suspended.is_empty());
        }
    }

    mod committee_channel {
        use super::*;

        fn cold() -> ColdWalletState {
            ColdWalletState::new(ColdWalletPolicy {
                chain_id: 7,
                max_value_per_settlement_atoms: 1000,
                max_value_per_epoch_atoms: 3000,
                min_height_advance: 1,
                required_quorum: 3,
                device_count: 6,
                refusal_history_capacity: 8,
            })
            // S2: the committee is pinned in state at installation.
            .with_trusted_devices(identities())
        }

        fn identities() -> Vec<crate::settlement::cold_quorum::SignerIdentity> {
            dev_fixture_device_signers()
                .iter()
                .map(|d| d.identity.clone())
                .collect()
        }

        fn certs(state: &ColdWalletState, at_height: u64, reason: &str) -> Vec<DeviceSignature> {
            let payload = rotation_payload(state, at_height, reason);
            dev_fixture_device_signers()[..3]
                .iter()
                .map(|d| d.sign_payload(&payload, state.key_epoch))
                .collect()
        }

        #[test]
        fn three_of_six_committee_rotates_the_anchor_key_directly() {
            let mut cold = cold();
            let certification = certs(&cold, 1200, "anchor key believed compromised");
            let next = rotate_anchor_key_with_committee(
                &mut cold,
                1200,
                "anchor key believed compromised",
                &certification,
            )
            .expect("committee rotation succeeds");
            assert_eq!(next, 2);
            assert_eq!(cold.key_epoch, 2);
            assert_eq!(cold.rotations.len(), 1);
            assert_eq!(cold.rotations[0].reason, "anchor key believed compromised");
            assert_eq!(cold.rotations[0].at_height, 1200);
        }

        #[test]
        fn an_uncertified_rotation_is_refused() {
            let mut cold = cold();
            let err = rotate_anchor_key_with_committee(
                &mut cold,
                1200,
                "attacker wants the key changed",
                &[],
            )
            .unwrap_err();
            assert_eq!(err.kind(), "anchor-committee-quorum");
            assert_eq!(cold.key_epoch, 1);
            assert!(cold.rotations.is_empty());
        }

        #[test]
        fn certificates_from_the_old_epoch_do_not_rotate_again() {
            let mut cold = cold();
            let certs_old = certs(&cold, 1200, "epoch one compromised");
            rotate_anchor_key_with_committee(&mut cold, 1200, "epoch one compromised", &certs_old)
                .expect("first rotation succeeds");
            assert_eq!(cold.key_epoch, 2);
            let err = rotate_anchor_key_with_committee(
                &mut cold,
                1300,
                "replay of the same certificate",
                &certs_old,
            )
            .unwrap_err();
            assert_eq!(err.kind(), "anchor-committee-quorum");
            assert_eq!(cold.key_epoch, 2);
            assert_eq!(cold.rotations.len(), 1);
        }
    }
}
