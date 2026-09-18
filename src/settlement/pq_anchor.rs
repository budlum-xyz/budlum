//! The post-quantum anchor for GlobalBlockHeader-level trust.
//!
//! WIRING: unwired - the anchor-emission caller is the consensus slice that
//! lands with domain finality proof wiring (devnet first; production gated
//! until the VerifyMerkle third-party opcode audit - see [`AnchorMode`]).
//! [`rotate_anchor_key_with_committee`] is already the named caller for
//! cold-wallet key rotation. Rules are pinned by this file's tests.
//!
//! Budlum has four consensus domains (PoW, PoS, BFT, PoA), and each produces
//! its own finality proof. Instead of making every domain separately
//! post-quantum, this module binds them under a single PQ boundary: the
//! domain finality proof hashes are aggregated into one Merkle tree, and a
//! single PQ signature is placed over the aggregation root. A node or a
//! mobile/browser wallet (via budlum-wallet-core) then verifies one signature
//! plus one Merkle root instead of per-domain verification logic.
//!
//! Decisions this file implements (record: 2026-09-17, `KARARLAR-2026-09-17-AYAZ.md`):
//!
//! - **Primary algorithm: ML-DSA-87**, stateless, FIPS 204, already the
//!   wallet pillar's choice. Committee-friendly precisely because it is
//!   stateless: there is no signature counter for a 3-of-6 quorum to
//!   coordinate.
//! - **Dormant secondary: SPHINCS+ slots.** Reserved algorithm identifiers
//!   and keybook entries exist now; cryptographic verification of that
//!   family arrives only after a reviewed implementation lands. Reserved
//!   algorithms fail closed, never open.
//! - **BPQS: research track.** Our own blockchained-PQ variant gets
//!   implemented and tested against this keybook/payload surface; until it
//!   passes that, it is a reserved identifier, not a production signer.
//! - **Production is hard-gated.** [`AnchorMode::ProductionApproved`] fails
//!   by construction today: the aggregation path reuses the VerifyMerkle
//!   proving surface, whose third-party opcode audit is pending. Turning
//!   this gate off is a deliberate code change in a future PR, with the
//!   audit recorded alongside - never a config flag flipped in a hurry.
//! - **Anchor-break response: the cold committee signs the reserve anchor
//!   directly** (3-of-6, no on-chain vote required in the emergency), via
//!   [`rotate_anchor_key_with_committee`] - which is also where
//!   `cold_wallet` key rotation becomes wired rather than merely pinned.
//!
//! # What this is not
//!
//! This module does not modify `GlobalBlockHeader`. The anchor is a sibling
//! record bound to a height and to roots the header already commits; wiring
//! it *into* consensus serialization is a separate, deliberate change. A
//! silent consensus-field addition on a branch named for hardening would be
//! the exact kind of change this repository's gates exist to block.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use super::cold_quorum::{verify_quorum, DeviceSignature, QuorumError, SignerIdentity};
use super::cold_wallet::{ColdWalletState, RotationError};
use crate::consensus::merkle_tree::{combine_sha3, merkle_root, promote_sha3};

/// The signature schemes the anchor surface understands.
///
/// The reserved variants exist so that the wire format can name the future
/// algorithms without pretending today's code verifies them. Anything not
/// [`AnchorSignatureAlgorithm::MlDsa87`] fails closed in verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnchorSignatureAlgorithm {
    /// FIPS 204 ML-DSA at parameter set 87 (Category 5). Implemented via the
    /// same hedged keying path as the wallet pillar.
    MlDsa87,
    /// SPHINCS+ (FIPS 205) - reserved for the dormant secondary anchor. No
    /// verifier exists in this build; any signature claiming it fails closed.
    SphincsPlusReserved,
    /// The project's own blockchained-PQ signature variant - reserved for
    /// the research track. No verifier exists; fails closed.
    BudlumBpqsReserved,
}

impl AnchorSignatureAlgorithm {
    /// Whether a verifier for this algorithm exists in this build.
    #[must_use]
    pub fn is_supported(self) -> bool {
        matches!(self, Self::MlDsa87)
    }
}

/// One signature over the canonical anchor payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorSignature {
    /// Which algorithm produced it.
    pub algorithm: AnchorSignatureAlgorithm,
    /// The signer's public key, raw bytes. Travels with the anchor; trust is
    /// established by the anchor keybook (`&[AnchorKeyEntry]` passed to the
    /// verify functions), not by this field.
    pub public_key: Vec<u8>,
    /// Signature bytes.
    pub signature: Vec<u8>,
}

/// The PQ anchor record, a sibling of the header at one height.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAnchor {
    /// The chain height this anchor binds.
    pub height: u64,
    /// The Merkle root over the domain finality proof hashes, leaf order as
    /// presented by the caller (domain-id ascending, by contract).
    pub aggregate_root: [u8; 32],
    /// The STARK state-transition proof root, when the BudZero path bound
    /// one this height. Signed alongside, so one signature also answers
    /// "was the computation correct".
    pub stark_root: Option<[u8; 32]>,
    /// The CrossDomainMessage commitment root, when messages were committed
    /// this height. Same one-umbrella rule as `stark_root`.
    pub crossdomain_root: Option<[u8; 32]>,
    /// The committee key epoch in force when this anchor was assembled.
    pub key_epoch: u32,
    /// The signatures. Full verification demands every *supported* algorithm
    /// present fails to be absent; light verification accepts any one.
    pub signatures: Vec<AnchorSignature>,
}

/// A trusted keybook entry: this algorithm+key pair is authorized to anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorKeyEntry {
    /// The algorithm this key is authorized for.
    pub algorithm: AnchorSignatureAlgorithm,
    /// The raw public key bytes.
    pub public_key: Vec<u8>,
}

impl AnchorKeyEntry {
    /// One entry, convenienced.
    #[must_use]
    pub fn new(algorithm: AnchorSignatureAlgorithm, public_key: Vec<u8>) -> Self {
        Self {
            algorithm,
            public_key,
        }
    }
}

/// Which mode the anchor pipeline runs in. Chosen by configuration; the
/// production arm fails by construction today (see module header).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnchorMode {
    /// The anchor pipeline is inert. Default, and correct until wiring.
    GatedOff,
    /// Devnet/testnet assembly and verification only. Production state
    /// transitions must never consult it.
    Devnet,
    /// Claim to run in production. Deliberately impossible today.
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
    /// Signature bytes failed verification under the presented key.
    InvalidSignature,
    /// The signer's (algorithm, key) pair is not in the keybook.
    SignerNotInKeybook,
    /// Full verification requires at least every supported algorithm to be
    /// represented; a required family is missing.
    MissingAlgorithm { algorithm: AnchorSignatureAlgorithm },
    /// Production mode was requested. The blocker is named, because a closed
    /// door that cannot say why it is closed gets opened "just to test".
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
            Self::SignerNotInKeybook => "anchor-signer-not-in-keybook",
            Self::MissingAlgorithm { .. } => "anchor-missing-algorithm",
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
            Self::SignerNotInKeybook => write!(f, "anchor signer not in the keybook"),
            Self::MissingAlgorithm { algorithm } => {
                write!(
                    f,
                    "anchor full verification lacks a {algorithm:?} signature"
                )
            }
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
/// Domain-separated ("BDLM_PQ_ANCHOR_V1"), and every field is length-fixed
/// so alternative parse behaviour cannot split the signed surface. The key
/// epoch is inside the payload for the same reason `cold_wallet` puts it
/// inside settlement payloads: a rotated-out committee key must not produce
/// bytes that still verify as current.
#[must_use]
pub fn anchor_payload_for(
    height: u64,
    aggregate_root: &[u8; 32],
    stark_root: Option<&[u8; 32]>,
    crossdomain_root: Option<&[u8; 32]>,
    key_epoch: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(17 + 8 + 32 + 1 + 32 + 1 + 32 + 4);
    out.extend_from_slice(b"BDLM_PQ_ANCHOR_V1");
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

/// Aggregates ordered domain finality proof hashes into the single root the
/// anchor signs. Uses the same SHA-3 helpers the VerifyMerkle side of the
/// tree uses; the ordering contract (domain-id ascending, as the caller
/// presents it) is part of the signed meaning.
/// The domain-separated leaf commitment for one finality record in the
/// anchor aggregation: `SHA3-256(BDLM_PQ_ANCHOR_AGG_V1 || payload_digest)`.
/// Callers building an anchor leaf MUST use this rather than the bare
/// payload digest, so a finality proof's digest cannot alias a leaf of any
/// other tree the chain aggregates with `merkle_root`.
pub fn anchor_leaf_digest(payload_digest: &[u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(21 + 32);
    preimage.extend_from_slice(b"BDLM_PQ_ANCHOR_AGG_V1");
    preimage.extend_from_slice(payload_digest);
    let mut hasher = Sha3_256::new();
    hasher.update(preimage);
    hasher.finalize().into()
}

pub fn aggregate_finality_roots(leaves: &[[u8; 32]]) -> Result<[u8; 32], AnchorError> {
    if leaves.is_empty() {
        return Err(AnchorError::EmptyAggregation);
    }
    Ok(merkle_root(leaves, combine_sha3, promote_sha3))
}

/// Who signs anchors. A trait rather than a keypair type, per the 2026-09-17
/// key-custody decision: software keys now, HSM/PKCS#11 behind the same
/// surface later. The HSM blocker is a named stare, not an invisible one.
pub trait AnchorSigner {
    /// The algorithm this signer produces.
    fn algorithm(&self) -> AnchorSignatureAlgorithm;
    /// The raw public key bytes.
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
    keypair: crate::crypto::primitives::WalletKeyPair,
}

#[cfg(feature = "wallet-ml-dsa")]
impl SoftwareMlDsa87Signer {
    /// Generates a fresh keypair behind a software signer.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            keypair: crate::crypto::primitives::WalletKeyPair::generate(),
        }
    }
}

#[cfg(feature = "wallet-ml-dsa")]
impl AnchorSigner for SoftwareMlDsa87Signer {
    fn algorithm(&self) -> AnchorSignatureAlgorithm {
        AnchorSignatureAlgorithm::MlDsa87
    }

    fn public_key(&self) -> Vec<u8> {
        self.keypair.public_key_bytes().to_vec()
    }

    fn sign(&self, payload: &[u8]) -> Result<AnchorSignature, AnchorError> {
        let signature = self.keypair.sign(payload);
        Ok(AnchorSignature {
            algorithm: self.algorithm(),
            public_key: self.public_key(),
            signature: signature.to_vec(),
        })
    }
}

/// The documented-but-unimplemented front for HSM/PKCS#11 custody. It exists
/// so that the call site for vendor custody is reviewable code, and so that
/// using it without the integration present fails loudly with the blocker
/// named rather than falling back to anything.
pub struct HsmSignerStub {
    /// Which vendor/device this stub stands for, for audit text.
    pub vendor_label: String,
}

impl AnchorSigner for HsmSignerStub {
    fn algorithm(&self) -> AnchorSignatureAlgorithm {
        AnchorSignatureAlgorithm::MlDsa87
    }

    fn public_key(&self) -> Vec<u8> {
        Vec::new()
    }

    fn sign(&self, _payload: &[u8]) -> Result<AnchorSignature, AnchorError> {
        Err(AnchorError::ProductionBlocked {
            blocker:
                "hsm-pkcs11-vendor-integration-unresolved (decision record 2026-09-17, blocker 3)",
        })
    }
}

/// Production mode fails by construction until the VerifyMerkle third-party
/// opcode audit lands; devnet/harness modes proceed.
///
/// # Errors
///
/// [`AnchorError::ProductionBlocked`] when `mode` is
/// [`AnchorMode::ProductionApproved`].
pub fn enforce_anchor_mode(mode: AnchorMode) -> Result<(), AnchorError> {
    match mode {
        AnchorMode::GatedOff | AnchorMode::Devnet => Ok(()),
        AnchorMode::ProductionApproved => Err(AnchorError::ProductionBlocked {
            blocker:
                "verifymerkle-opcode-external-audit-pending (decision record 2026-09-17, item 6)",
        }),
    }
}

fn verify_one(
    algorithm: AnchorSignatureAlgorithm,
    public_key: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<(), AnchorError> {
    if !algorithm.is_supported() {
        return Err(AnchorError::UnsupportedAlgorithm { algorithm });
    }
    crate::crypto::primitives::verify_ml_dsa_87_signature(payload, signature, public_key)
        .map_err(|_| AnchorError::InvalidSignature)
}

/// Ensures a signer's (algorithm, key) pair is authorized by the keybook.
fn in_keybook(
    keybook: &[AnchorKeyEntry],
    algorithm: AnchorSignatureAlgorithm,
    public_key: &[u8],
) -> bool {
    keybook
        .iter()
        .any(|e| e.algorithm == algorithm && e.public_key == public_key)
}

/// Full verification: every signature verifies, every signer is keybooked,
/// and every supported algorithm the production profile expects is present.
/// A reserved-algorithm signature does not breed an automatic pass: reserved
/// families fail closed at signature verification anyway.
///
/// # Errors
///
/// The first [`AnchorError`] that applies.
pub fn verify_anchor_full(
    anchor: &PqAnchor,
    keybook: &[AnchorKeyEntry],
) -> Result<(), AnchorError> {
    let payload = anchor_payload_for(
        anchor.height,
        &anchor.aggregate_root,
        anchor.stark_root.as_ref(),
        anchor.crossdomain_root.as_ref(),
        anchor.key_epoch,
    );
    if anchor.signatures.is_empty() {
        return Err(AnchorError::MissingAlgorithm {
            algorithm: AnchorSignatureAlgorithm::MlDsa87,
        });
    }
    for sig in &anchor.signatures {
        if !in_keybook(keybook, sig.algorithm, &sig.public_key) {
            return Err(AnchorError::SignerNotInKeybook);
        }
        verify_one(sig.algorithm, &sig.public_key, &payload, &sig.signature)?;
    }
    if !anchor
        .signatures
        .iter()
        .any(|s| s.algorithm == AnchorSignatureAlgorithm::MlDsa87)
    {
        return Err(AnchorError::MissingAlgorithm {
            algorithm: AnchorSignatureAlgorithm::MlDsa87,
        });
    }
    Ok(())
}

/// Light verification for wallets and mesh nodes (threshold-of-algorithms):
/// any ONE supported, keybooked, verifying signature is enough. The
/// heavy-node rule ([`verify_anchor_full`]) still applies to everything
/// carrying production weight; accepting one-algorithm verification is how
/// the small-payload goal survives the future dual-signature upgrade rather
/// than being undone by it.
///
/// # Errors
///
/// [`AnchorError::MissingAlgorithm`] when no single supported signature
/// verifies against the keybook.
pub fn verify_anchor_light(
    anchor: &PqAnchor,
    keybook: &[AnchorKeyEntry],
) -> Result<(), AnchorError> {
    let payload = anchor_payload_for(
        anchor.height,
        &anchor.aggregate_root,
        anchor.stark_root.as_ref(),
        anchor.crossdomain_root.as_ref(),
        anchor.key_epoch,
    );
    for sig in &anchor.signatures {
        if !in_keybook(keybook, sig.algorithm, &sig.public_key) {
            continue;
        }
        if verify_one(sig.algorithm, &sig.public_key, &payload, &sig.signature).is_ok() {
            return Ok(());
        }
    }
    Err(AnchorError::MissingAlgorithm {
        algorithm: AnchorSignatureAlgorithm::MlDsa87,
    })
}

/// Assembles an anchor from ordered domain leaves plus optional STARK and
/// cross-domain roots, signed by one signer.
///
/// # Errors
///
/// [`AnchorError::EmptyAggregation`] for no leaves, plus the signer's own
/// refusal.
pub fn assemble_anchor(
    height: u64,
    domain_finality_leaves: &[[u8; 32]],
    stark_root: Option<[u8; 32]>,
    crossdomain_root: Option<[u8; 32]>,
    key_epoch: u32,
    signer: &dyn AnchorSigner,
) -> Result<PqAnchor, AnchorError> {
    let aggregate_root = aggregate_finality_roots(domain_finality_leaves)?;
    let payload = anchor_payload_for(
        height,
        &aggregate_root,
        stark_root.as_ref(),
        crossdomain_root.as_ref(),
        key_epoch,
    );
    let signature = signer.sign(&payload)?;
    Ok(PqAnchor {
        height,
        aggregate_root,
        stark_root,
        crossdomain_root,
        key_epoch,
        signatures: vec![signature],
    })
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

/// The devnet emission driver: turn one finality window into a signed
/// anchor record.
///
/// Binding rule: every window leaf (the bare digest the global header's
/// `settlement_finality_root` folds today) enters the anchor aggregation
/// through [`anchor_leaf_digest`], so the anchor tree's leaves can never
/// alias a leaf of the header's own tree even if the payload digests
/// coincide. Consensus stays untouched: this is a pure derivation whose
/// only side effect is the returned record.
///
/// WIRING: the caller is the consensus seam that seals global headers
/// (devnet first), documented in docs/PQ_ANCHOR_RESEARCH.md section 2.
pub fn build_anchor_for_height(
    height: u64,
    window_leaves: &[[u8; 32]],
    stark_root: Option<[u8; 32]>,
    crossdomain_root: Option<[u8; 32]>,
    key_epoch: u32,
    signer: &dyn AnchorSigner,
) -> Result<PqAnchor, AnchorError> {
    let domain_leaves: Vec<[u8; 32]> = window_leaves.iter().map(anchor_leaf_digest).collect();
    assemble_anchor(
        height,
        &domain_leaves,
        stark_root,
        crossdomain_root,
        key_epoch,
        signer,
    )
}

/// Build the anchor and append it to the node-local JSONL log, under mode
/// control.
///
/// Mode semantics: `GatedOff` -> Ok(Skipped) (the gate is a decision,
/// recorded as such); `Devnet` -> build + append; `ProductionApproved` ->
/// Err(anchor-production-blocked) with the same named blocker as the verify
/// gate. The log is node-local by contract: it is not consensus state and a
/// node that loses it simply re-derives from the chain, so an io failure is
/// reported, never retried silently.
pub fn emit_anchor_node_local(
    log_path: &std::path::Path,
    mode: AnchorMode,
    height: u64,
    window_leaves: &[[u8; 32]],
    stark_root: Option<[u8; 32]>,
    crossdomain_root: Option<[u8; 32]>,
    key_epoch: u32,
    signer: &dyn AnchorSigner,
) -> Result<EmissionOutcome, AnchorError> {
    match mode {
        AnchorMode::GatedOff => return Ok(EmissionOutcome::Skipped),
        AnchorMode::Devnet => {}
        AnchorMode::ProductionApproved => {
            return Err(AnchorError::ProductionBlocked {
                blocker: "verifymerkle-opcode-external-audit-pending (decision record 2026-09-17, item 6)",
            });
        }
    }
    let anchor = build_anchor_for_height(
        height,
        window_leaves,
        stark_root,
        crossdomain_root,
        key_epoch,
        signer,
    )?;
    let line =
        serde_json::to_string(&anchor).map_err(|_| AnchorError::EmissionIo("json serialize"))?;
    use std::io::Write as _;
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| AnchorError::EmissionIo("mkdir"))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|_| AnchorError::EmissionIo("open"))?;
    writeln!(file, "{line}").map_err(|_| AnchorError::EmissionIo("append"))?;
    Ok(EmissionOutcome::Written)
}

/// The cold-committee reserve-anchor channel (decision record 2026-09-17,
/// item 4): when the anchor key is compromised, the 3-of-6 cold committee
/// rotates the cold wallet's key epoch directly - no on-chain vote stalls
/// the response. The rotation certificate signed by the committee is
/// domain-separated (`BDLM_PQ_ANCHOR_ROTATION_V1`) and binds the height and
/// the reason, so a rotation nobody can explain afterwards is as impossible
/// here as it is in the cold wallet itself.
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
    identities: &[SignerIdentity],
    certificates: &[DeviceSignature],
) -> Result<u32, AnchorError> {
    let mut payload = Vec::with_capacity(26 + 8 + 8 + 32);
    payload.extend_from_slice(b"BDLM_PQ_ANCHOR_ROTATION_V1");
    payload.extend_from_slice(&at_height.to_le_bytes());
    payload.extend_from_slice(&(state.key_epoch as u64).to_le_bytes());
    payload.extend_from_slice(&crate::core::hash::hash_fields_bytes(&[
        b"BDLM_PQ_ANCHOR_ROTATION_REASON_V1",
        reason.as_bytes(),
    ]));
    let proven = verify_quorum(
        &state.policy,
        identities,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settlement::cold_quorum::dev_fixture_device_signers;
    use crate::settlement::cold_wallet::ColdWalletPolicy;

    fn leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| [i as u8; 32]).collect()
    }

    /// Deterministic echo signer: produces structurally valid signatures
    /// without any real cryptography, for plumbing tests that verify the
    /// emission path itself, not the scheme (the scheme has its own gated
    /// tests behind `wallet-ml-dsa`).
    struct StubSigner;

    impl AnchorSigner for StubSigner {
        fn algorithm(&self) -> AnchorSignatureAlgorithm {
            AnchorSignatureAlgorithm::MlDsa87
        }
        fn public_key(&self) -> Vec<u8> {
            vec![7u8; 8]
        }
        fn sign(&self, payload: &[u8]) -> Result<AnchorSignature, AnchorError> {
            Ok(AnchorSignature {
                algorithm: AnchorSignatureAlgorithm::MlDsa87,
                public_key: vec![7u8; 8],
                signature: payload[..8].to_vec(),
            })
        }
    }

    fn temp_log_path(name: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("pq-anchor-test-{name}-{}", std::process::id()));
        let _unused = std::fs::remove_dir_all(&dir);
        dir.push("anchors.jsonl");
        dir
    }

    #[test]
    fn emission_driver_domain_separates_the_window_leaves() {
        let window = leaves(3);
        let anchor = build_anchor_for_height(9, &window, None, None, 4, &StubSigner)
            .expect("driver builds over three leaves");
        let separated: Vec<[u8; 32]> = window.iter().map(anchor_leaf_digest).collect();
        assert_eq!(
            anchor.aggregate_root,
            aggregate_finality_roots(&separated).expect("three separated leaves aggregate")
        );
        assert_ne!(
            anchor.aggregate_root,
            aggregate_finality_roots(&window).expect("bare leaves also aggregate"),
            "the anchor's tree must never share the header's bare leaf space"
        );
    }

    #[test]
    fn emission_gated_off_skips_and_touches_no_file() {
        let path = temp_log_path("gated-off");
        let outcome = emit_anchor_node_local(
            &path,
            AnchorMode::GatedOff,
            9,
            &leaves(2),
            None,
            None,
            4,
            &StubSigner,
        )
        .expect("gated off is a decision, not an error");
        assert_eq!(outcome, EmissionOutcome::Skipped);
        assert!(!path.exists(), "a skipped emission must not create the log");
    }

    #[test]
    fn emission_production_approved_is_blocked() {
        let path = temp_log_path("production");
        let err = emit_anchor_node_local(
            &path,
            AnchorMode::ProductionApproved,
            9,
            &leaves(2),
            None,
            None,
            4,
            &StubSigner,
        )
        .expect_err("production stays blocked until the opcode audit");
        assert_eq!(err.kind(), "anchor-production-blocked");
        assert!(!path.exists(), "a blocked emission must not create the log");
    }

    #[test]
    fn emission_devnet_writes_one_jsonl_record() {
        let path = temp_log_path("devnet");
        let written = emit_anchor_node_local(
            &path,
            AnchorMode::Devnet,
            9,
            &leaves(2),
            None,
            None,
            4,
            &StubSigner,
        )
        .expect("devnet emission writes the record");
        assert_eq!(written, EmissionOutcome::Written);
        let body = std::fs::read_to_string(&path).expect("the log exists");
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 1, "exactly one record per emission");
        let recorded: PqAnchor = serde_json::from_str(lines[0]).expect("the line is a PqAnchor");
        let expected = build_anchor_for_height(9, &leaves(2), None, None, 4, &StubSigner)
            .expect("same inputs, same anchor");
        assert_eq!(recorded, expected);
        let _cleanup = std::fs::remove_dir_all(path.parent().expect("temp dir"));
    }

    #[test]
    fn empty_aggregation_is_refused_not_assumed() {
        let err = aggregate_finality_roots(&[]).unwrap_err();
        assert_eq!(err.kind(), "anchor-empty-aggregation");
    }

    #[test]
    fn aggregation_is_deterministic_for_ordered_leaves() {
        let a = aggregate_finality_roots(&leaves(4)).unwrap();
        let b = aggregate_finality_roots(&leaves(4)).unwrap();
        assert_eq!(a, b);
        // And order matters: a shuffled tree is a different tree.
        let mut shuffled = leaves(4);
        shuffled.swap(0, 1);
        let c = aggregate_finality_roots(&shuffled).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn payload_binds_every_field_and_every_optional_flag() {
        let root = [7u8; 32];
        let bare = anchor_payload_for(9, &root, None, None, 1);
        let with_stark = anchor_payload_for(9, &root, Some(&[1u8; 32]), None, 1);
        let with_cross = anchor_payload_for(9, &root, None, Some(&[2u8; 32]), 1);
        let other_height = anchor_payload_for(10, &root, None, None, 1);
        let other_epoch = anchor_payload_for(9, &root, None, None, 2);
        assert!(bare.starts_with(b"BDLM_PQ_ANCHOR_V1"));
        assert_ne!(bare, with_stark);
        assert_ne!(bare, with_cross);
        assert_ne!(bare, other_height);
        assert_ne!(bare, other_epoch);
        assert_ne!(with_stark, with_cross);
        // Lengths are pinned: bare 17+8+32+1+1+4 = 63; with-roots grow by 32.
        assert_eq!(bare.len(), 63);
        assert_eq!(with_stark.len(), 95);
    }

    #[cfg(feature = "wallet-ml-dsa")]
    mod signing {
        use super::*;

        fn signer() -> SoftwareMlDsa87Signer {
            SoftwareMlDsa87Signer::generate()
        }

        #[test]
        fn software_signer_roundtrips_through_full_and_light() {
            let signer = signer();
            let keybook = vec![AnchorKeyEntry::new(
                AnchorSignatureAlgorithm::MlDsa87,
                signer.public_key(),
            )];
            let anchor =
                assemble_anchor(500, &leaves(4), Some([5u8; 32]), None, 1, &signer).unwrap();
            verify_anchor_full(&anchor, &keybook).expect("full verifies");
            verify_anchor_light(&anchor, &keybook).expect("light verifies");
        }

        #[test]
        fn a_tampered_anchor_fails_everywhere() {
            let signer = signer();
            let keybook = vec![AnchorKeyEntry::new(
                AnchorSignatureAlgorithm::MlDsa87,
                signer.public_key(),
            )];
            let mut anchor = assemble_anchor(500, &leaves(4), None, None, 1, &signer).unwrap();
            anchor.height = 501;
            verify_anchor_full(&anchor, &keybook).expect_err("tampered height must fail full");
            verify_anchor_light(&anchor, &keybook).expect_err("tampered height must fail light");
        }

        #[test]
        fn an_unkeybooked_signer_is_not_trusted() {
            let signer = signer();
            let stranger = SoftwareMlDsa87Signer::generate();
            let anchor = assemble_anchor(500, &leaves(4), None, None, 1, &signer).unwrap();
            let keybook = vec![AnchorKeyEntry::new(
                AnchorSignatureAlgorithm::MlDsa87,
                stranger.public_key(),
            )];
            let err = verify_anchor_full(&anchor, &keybook).unwrap_err();
            assert_eq!(err.kind(), "anchor-signer-not-in-keybook");
            let err = verify_anchor_light(&anchor, &keybook).unwrap_err();
            assert_eq!(err.kind(), "anchor-missing-algorithm");
        }

        #[test]
        fn an_empty_anchor_has_nothing_to_verify() {
            let anchor = PqAnchor {
                height: 500,
                aggregate_root: [1u8; 32],
                stark_root: None,
                crossdomain_root: None,
                key_epoch: 1,
                signatures: Vec::new(),
            };
            verify_anchor_full(&anchor, &[]).expect_err("empty anchor must fail");
        }

        #[test]
        fn reserved_algorithms_fail_closed() {
            let signature = AnchorSignature {
                algorithm: AnchorSignatureAlgorithm::SphincsPlusReserved,
                public_key: vec![9u8; 32],
                signature: vec![0u8; 64],
            };
            let payload = b"anything";
            let err = verify_one(
                signature.algorithm,
                &signature.public_key,
                payload,
                &signature.signature,
            )
            .unwrap_err();
            assert_eq!(err.kind(), "anchor-unsupported-algorithm");
            let err = verify_one(
                AnchorSignatureAlgorithm::BudlumBpqsReserved,
                &signature.public_key,
                payload,
                &signature.signature,
            )
            .unwrap_err();
            assert_eq!(err.kind(), "anchor-unsupported-algorithm");
        }
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
        };
        let err = stub.sign(b"payload").unwrap_err();
        assert_eq!(err.kind(), "anchor-production-blocked");
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
        }

        fn identities() -> Vec<SignerIdentity> {
            dev_fixture_device_signers()
                .iter()
                .map(|d| d.identity.clone())
                .collect()
        }

        fn certs(state: &ColdWalletState, at_height: u64, reason: &str) -> Vec<DeviceSignature> {
            let mut payload = Vec::new();
            payload.extend_from_slice(b"BDLM_PQ_ANCHOR_ROTATION_V1");
            payload.extend_from_slice(&at_height.to_le_bytes());
            payload.extend_from_slice(&(state.key_epoch as u64).to_le_bytes());
            payload.extend_from_slice(&crate::core::hash::hash_fields_bytes(&[
                b"BDLM_PQ_ANCHOR_ROTATION_REASON_V1",
                reason.as_bytes(),
            ]));
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
                &identities(),
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
                &identities(),
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
            rotate_anchor_key_with_committee(
                &mut cold,
                1200,
                "epoch one compromised",
                &identities(),
                &certs_old,
            )
            .expect("first rotation succeeds");
            assert_eq!(cold.key_epoch, 2);
            let err = rotate_anchor_key_with_committee(
                &mut cold,
                1300,
                "replay of the same certificate",
                &identities(),
                &certs_old,
            )
            .unwrap_err();
            assert_eq!(err.kind(), "anchor-committee-quorum");
            assert_eq!(cold.key_epoch, 2);
            assert_eq!(cold.rotations.len(), 1);
        }
    }

    #[test]
    fn anchor_leaf_digest_is_domain_separated_and_composes_with_aggregation() {
        let a = super::anchor_leaf_digest(&[11u8; 32]);
        let b = super::anchor_leaf_digest(&[22u8; 32]);
        // Domain-separated: bare payload digests never alias anchor leaves.
        assert_ne!(a, [11u8; 32]);
        // Deterministic.
        assert_eq!(a, super::anchor_leaf_digest(&[11u8; 32]));
        // Composes with the aggregation root exactly.
        let root = super::aggregate_finality_roots(&[a, b]).expect("two leaves");
        assert_eq!(
            root,
            crate::consensus::merkle_tree::merkle_root(
                &[a, b],
                crate::consensus::merkle_tree::combine_sha3,
                crate::consensus::merkle_tree::promote_sha3,
            )
        );
    }
}
