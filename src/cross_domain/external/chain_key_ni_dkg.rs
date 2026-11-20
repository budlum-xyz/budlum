//! Chain-Key Non-Interactive DKG (`NiDKG`) + Constant-Size Threshold `BLS12-381`
//! Catch-Up Package (`CUP`) + Post-Quantum `ML-DSA-65` Hybrid Finality Adapter.
//!
//! Models the Internet Computer / Chain-Key consensus family where:
//! 1. A governance-pinned Root Subnet (`NNS`) delegates finality authority to an
//!    application subnet for `dkg_epoch` via a [`ChainKeySubnetDelegation`]
//!    carrying the non-interactive DKG transcript digest, dealer threshold,
//!    96-byte compressed `G2` subnet threshold `BLS12-381` public key, and
//!    mandatory `ML-DSA-65` subnet post-quantum public key, dual-signed by the
//!    pinned root `BLS12-381` + `ML-DSA-65` keys.
//! 2. At every certified catch-up boundary (`height > 0`, aligned to
//!    `dkg_interval_length`), the subnet committee produces a constant-size
//!    `O(1)` [`ChainKeyCatchUpPackage`] (`48-byte G1` threshold `BLS12-381`
//!    signature paired with a subnet `ML-DSA-65` signature under
//!    [`crate::crypto::ctx::CROSS_DOMAIN_V1`]), enabling stateless light-client
//!    verification without downloading per-validator bitmaps or historical epochs.
//!
//! WIRING: re-exported by `crate::cross_domain::external` for permissionless
//! external domain registration and `selftest::admit` verification.

use crate::core::hash::hash_fields_bytes;
use crate::crypto::facts::{CryptoObserver, ObservedScheme};
use crate::crypto::scheme::SchemeId;
use crate::domain::types::Hash32;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::selftest::{BytePatch, ExpectedRefusal, FaultProbe, RefusalKind};
use super::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, RawConsensusEvidence, SecurityBacking, TimeUnit, TrustModel,
    VerificationPolicy,
};

/// Canonical adapter identifier for Chain-Key `NiDKG` finality.
///
/// WIRING: registered with [`AdapterId::from_name`] in [`ChainKeyNiDkgAdapter::new`].
pub const CHAIN_KEY_ADAPTER_NAME: &str = "chain-key-nidkg-v1";

const ADAPTER_VERSION: u32 = 1;
const EVIDENCE_VERSION: u32 = 1;
const CUP_REQUIRED_DEPTH: u64 = 1;
const PAYLOAD_MAGIC: &[u8; 8] = b"BDLMCK01";
const MAX_CHAIN_KEY_PAYLOAD_BYTES: usize = 256 * 1024;
const MAX_SUBNET_COMMITTEE_SIZE: u64 = 1_024;

/// Governance-pinned Root Subnet (`NNS`) anchor keys and subnet interval policy.
///
/// WIRING: supplied to [`ChainKeyNiDkgAdapter::new`] when pinning a Chain-Key domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedChainKeyRoot {
    /// Expected 32-byte target subnet identifier.
    pub subnet_id: [u8; 32],
    /// Root NNS 96-byte compressed `G2` threshold `BLS12-381` public key.
    pub root_bls_pubkey: Vec<u8>,
    /// Root NNS `ML-DSA-65` post-quantum public key.
    pub root_pq_pubkey: Vec<u8>,
    /// Required catch-up interval stride (`>= 1`; `height % dkg_interval_length == 0`).
    pub dkg_interval_length: u64,
    /// Minimum acceptable NNS registry version (`replay / rollback floor`).
    pub min_registry_version: u64,
}

/// Root-signed `NiDKG` transcript delegation for one subnet epoch.
///
/// WIRING: carried inside [`ChainKeyEvidenceBundle`] and verified against [`PinnedChainKeyRoot`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainKeySubnetDelegation {
    /// Target 32-byte subnet identifier.
    pub subnet_id: [u8; 32],
    /// Monotonic `NiDKG` epoch index.
    pub dkg_epoch: u64,
    /// NNS registry version at transcript creation.
    pub registry_version: u64,
    /// Total nodes in the subnet `NiDKG` dealing committee.
    pub committee_size: u64,
    /// Honest reconstruction / signing threshold (`> 2/3 * committee_size`).
    pub signing_threshold: u64,
    /// Digest of the verified non-interactive DKG transcript (`BDLM_CHAIN_KEY_NIDKG_V1`).
    pub nidkg_transcript_digest: Hash32,
    /// Derived 96-byte `G2` subnet threshold `BLS12-381` public key.
    pub subnet_bls_pubkey: Vec<u8>,
    /// Derived subnet `ML-DSA-65` post-quantum public key.
    pub subnet_pq_pubkey: Vec<u8>,
    /// Root NNS 48-byte `G1` threshold `BLS12-381` signature over the delegation digest.
    pub root_bls_sig: Vec<u8>,
    /// Root NNS `ML-DSA-65` co-signature under `CROSS_DOMAIN_V1`.
    pub root_pq_sig: Vec<u8>,
}

/// Constant-size `O(1)` Catch-Up Package (`CUP`) finalizing subnet state at `height`.
///
/// WIRING: carried inside [`ChainKeyEvidenceBundle`] and verified by [`ChainKeyNiDkgAdapter`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainKeyCatchUpPackage {
    /// `NiDKG` epoch whose threshold key signed this CUP.
    pub dkg_epoch: u64,
    /// Finalized checkpoint height (`height > 0` and multiple of `dkg_interval_length`).
    pub height: u64,
    /// Monotonic consensus timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Certified replicated state tree root.
    pub state_root: Hash32,
    /// Certified ingress/message queue root.
    pub ingress_root: Hash32,
    /// Certified cross-subnet `XNet` stream root.
    pub xnet_event_root: Hash32,
    /// Certified block hash at `height`.
    pub block_hash: Hash32,
    /// Constant-size 48-byte `G1` threshold `BLS12-381` signature over the CUP digest.
    pub threshold_bls_sig: Vec<u8>,
    /// Subnet `ML-DSA-65` post-quantum co-signature under `CROSS_DOMAIN_V1`.
    pub subnet_pq_sig: Vec<u8>,
}

/// Wire bundle combining root subnet `NiDKG` delegation with a certified `CUP`.
///
/// WIRING: serialized after `BDLMCK01` magic inside [`RawConsensusEvidence::payload`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainKeyEvidenceBundle {
    /// Root-certified `NiDKG` transcript delegation for `cup.dkg_epoch`.
    pub delegation: ChainKeySubnetDelegation,
    /// Constant-size threshold Catch-Up Package at finalized `height`.
    pub cup: ChainKeyCatchUpPackage,
}

/// Computes the canonical `NiDKG` transcript digest bound to `(network, subnet_id, dkg_epoch)`.
///
/// WIRING: used by Chain-Key `NiDKG` ceremony builders and [`ChainKeyNiDkgAdapter`].
#[must_use]
pub fn compute_nidkg_transcript_digest(
    network: &str,
    subnet_id: &[u8; 32],
    dkg_epoch: u64,
    registry_version: u64,
    dealings_merkle_root: &Hash32,
) -> Hash32 {
    let epoch_le = dkg_epoch.to_le_bytes();
    let reg_le = registry_version.to_le_bytes();
    hash_fields_bytes(&[
        b"BDLM_CHAIN_KEY_NIDKG_V1",
        network.as_bytes(),
        subnet_id,
        &epoch_le,
        &reg_le,
        dealings_merkle_root,
    ])
}

/// Computes the domain-separated root-delegation signing digest.
///
/// WIRING: verified against `root_bls_pubkey` and `root_pq_pubkey` in [`ChainKeyNiDkgAdapter`].
#[must_use]
pub fn delegation_signing_digest(network: &str, del: &ChainKeySubnetDelegation) -> Hash32 {
    let epoch_le = del.dkg_epoch.to_le_bytes();
    let reg_le = del.registry_version.to_le_bytes();
    let size_le = del.committee_size.to_le_bytes();
    let thresh_le = del.signing_threshold.to_le_bytes();
    hash_fields_bytes(&[
        b"BDLM_CHAIN_KEY_DELEGATION_V1",
        network.as_bytes(),
        &del.subnet_id,
        &epoch_le,
        &reg_le,
        &size_le,
        &thresh_le,
        &del.nidkg_transcript_digest,
        &del.subnet_bls_pubkey,
        &del.subnet_pq_pubkey,
    ])
}

/// Computes the domain-separated Catch-Up Package signing digest.
///
/// WIRING: verified against `subnet_bls_pubkey` and `subnet_pq_pubkey` in [`ChainKeyNiDkgAdapter`].
#[must_use]
pub fn cup_signing_digest(
    network: &str,
    subnet_id: &[u8; 32],
    cup: &ChainKeyCatchUpPackage,
) -> Hash32 {
    let epoch_le = cup.dkg_epoch.to_le_bytes();
    let height_le = cup.height.to_le_bytes();
    let ts_le = cup.timestamp_ns.to_le_bytes();
    hash_fields_bytes(&[
        b"BDLM_CHAIN_KEY_CUP_V1",
        network.as_bytes(),
        subnet_id,
        &epoch_le,
        &height_le,
        &ts_le,
        &cup.state_root,
        &cup.ingress_root,
        &cup.xnet_event_root,
        &cup.block_hash,
    ])
}

/// Encodes a [`ChainKeyEvidenceBundle`] with its 8-byte `BDLMCK01` magic header.
///
/// WIRING: exposed for external domain producers and `selftest` golden sample builders.
///
/// # Errors
///
/// Returns an error if serialization fails or exceeds `MAX_CHAIN_KEY_PAYLOAD_BYTES`.
pub fn encode_chain_key_evidence(bundle: &ChainKeyEvidenceBundle) -> Result<Vec<u8>, String> {
    let body = bincode::serialize(bundle).map_err(|e| format!("Chain-Key encode failed: {e}"))?;
    let total = PAYLOAD_MAGIC.len().saturating_add(body.len());
    if total > MAX_CHAIN_KEY_PAYLOAD_BYTES {
        return Err(format!(
            "Chain-Key payload {total} exceeds ceiling {MAX_CHAIN_KEY_PAYLOAD_BYTES}"
        ));
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_chain_key_evidence(payload: &[u8]) -> Result<ChainKeyEvidenceBundle, AdapterError> {
    if payload.len() > MAX_CHAIN_KEY_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_CHAIN_KEY_PAYLOAD_BYTES,
            reason: format!("Chain-Key payload exceeds {MAX_CHAIN_KEY_PAYLOAD_BYTES} bytes"),
        });
    }
    let Some((magic, body)) = payload.split_at_checked(PAYLOAD_MAGIC.len()) else {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "Chain-Key payload shorter than 8-byte magic prefix".into(),
        });
    };
    if magic != PAYLOAD_MAGIC {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "Chain-Key payload magic mismatch".into(),
        });
    }
    let decoded: ChainKeyEvidenceBundle =
        crate::network::bounded_bincode::decode_bounded_bincode(body, MAX_CHAIN_KEY_PAYLOAD_BYTES)
            .map_err(|e| AdapterError::Malformed {
                offset: PAYLOAD_MAGIC.len(),
                reason: format!("invalid Chain-Key evidence: {e}"),
            })?;
    if bincode::serialized_size(&decoded).ok() != u64::try_from(body.len()).ok() {
        return Err(AdapterError::Malformed {
            offset: PAYLOAD_MAGIC.len(),
            reason: "trailing bytes after canonical Chain-Key evidence".into(),
        });
    }
    Ok(decoded)
}

fn verify_delegation_and_cup(
    network: &str,
    pinned: &PinnedChainKeyRoot,
    bundle: &ChainKeyEvidenceBundle,
) -> Result<(), AdapterError> {
    let del = &bundle.delegation;
    let cup = &bundle.cup;

    if !bool::from(del.subnet_id.ct_eq(&pinned.subnet_id)) || del.subnet_id == [0u8; 32] {
        return Err(AdapterError::ConsensusRule {
            rule: "Chain-Key delegation subnet_id mismatches pinned subnet".into(),
        });
    }
    if del.registry_version < pinned.min_registry_version {
        return Err(AdapterError::ConsensusRule {
            rule: "Chain-Key delegation registry_version below pinned rollback floor".into(),
        });
    }
    if del.committee_size == 0
        || del.committee_size > MAX_SUBNET_COMMITTEE_SIZE
        || del.signing_threshold > del.committee_size
        || u128::from(del.signing_threshold).saturating_mul(3)
            <= u128::from(del.committee_size).saturating_mul(2)
    {
        return Err(AdapterError::ConsensusRule {
            rule: "Chain-Key NiDKG threshold must strictly exceed 2/3 of bounded committee".into(),
        });
    }
    if del.nidkg_transcript_digest == [0u8; 32] {
        return Err(AdapterError::ConsensusRule {
            rule: "Chain-Key NiDKG transcript digest must be non-zero".into(),
        });
    }
    if cup.dkg_epoch != del.dkg_epoch {
        return Err(AdapterError::ConsensusRule {
            rule: "Chain-Key CUP dkg_epoch does not match delegated NiDKG transcript epoch".into(),
        });
    }
    if cup.height == 0
        || pinned.dkg_interval_length == 0
        || !cup.height.is_multiple_of(pinned.dkg_interval_length)
    {
        return Err(AdapterError::ConsensusRule {
            rule: "Chain-Key CUP height is zero or misaligned with dkg_interval_length".into(),
        });
    }
    if cup.state_root == [0u8; 32] || cup.block_hash == [0u8; 32] {
        return Err(AdapterError::ConsensusRule {
            rule: "Chain-Key CUP carries zero state_root or block_hash".into(),
        });
    }

    // 1. Verify Root NNS hybrid BLS12-381 + ML-DSA-65 delegation signatures.
    let del_digest = delegation_signing_digest(network, del);
    crate::chain::finality::verify_bls_sig(&pinned.root_bls_pubkey, &del_digest, &del.root_bls_sig)
        .map_err(|_| AdapterError::Crypto {
            what: "invalid Root NNS threshold BLS12-381 signature on NiDKG delegation".into(),
        })?;
    if pinned.root_pq_pubkey.is_empty() || del.root_pq_sig.is_empty() {
        return Err(AdapterError::Crypto {
            what: "missing mandatory Root NNS ML-DSA-65 delegation signature".into(),
        });
    }
    crate::crypto::primitives::PqKeyPair::verify(
        &pinned.root_pq_pubkey,
        crate::crypto::ctx::CROSS_DOMAIN_V1,
        &del_digest,
        &del.root_pq_sig,
    )
    .map_err(|_| AdapterError::Crypto {
        what: "invalid Root NNS ML-DSA-65 signature on NiDKG delegation".into(),
    })?;

    // 2. Verify Subnet constant-size threshold BLS12-381 + ML-DSA-65 CUP signatures.
    let cup_digest = cup_signing_digest(network, &del.subnet_id, cup);
    crate::chain::finality::verify_bls_sig(
        &del.subnet_bls_pubkey,
        &cup_digest,
        &cup.threshold_bls_sig,
    )
    .map_err(|_| AdapterError::Crypto {
        what: "invalid Subnet threshold BLS12-381 signature on Catch-Up Package".into(),
    })?;
    if del.subnet_pq_pubkey.is_empty() || cup.subnet_pq_sig.is_empty() {
        return Err(AdapterError::Crypto {
            what: "missing mandatory Subnet ML-DSA-65 signature on Catch-Up Package".into(),
        });
    }
    crate::crypto::primitives::PqKeyPair::verify(
        &del.subnet_pq_pubkey,
        crate::crypto::ctx::CROSS_DOMAIN_V1,
        &cup_digest,
        &cup.subnet_pq_sig,
    )
    .map_err(|_| AdapterError::Crypto {
        what: "invalid Subnet ML-DSA-65 signature on Catch-Up Package".into(),
    })?;

    Ok(())
}

/// External finality adapter for Chain-Key `NiDKG` + constant-size threshold `BLS12-381` CUPs.
///
/// WIRING: registered via `crate::cross_domain::external` and admitted through `selftest::admit`.
pub struct ChainKeyNiDkgAdapter {
    network: String,
    pinned: Option<PinnedChainKeyRoot>,
    golden: Option<RawConsensusEvidence>,
    descriptor: AdapterDescriptor,
}

impl ChainKeyNiDkgAdapter {
    /// Constructs a [`ChainKeyNiDkgAdapter`] bound to `network` and its pinned root NNS keys.
    ///
    /// WIRING: called by external domain registrars and self-test harnesses.
    #[must_use]
    pub fn new(network: impl Into<String>, pinned: Option<PinnedChainKeyRoot>) -> Self {
        Self {
            network: network.into(),
            pinned,
            golden: None,
            descriptor: AdapterDescriptor {
                id: AdapterId::from_name(CHAIN_KEY_ADAPTER_NAME),
                name: CHAIN_KEY_ADAPTER_NAME.to_string(),
                adapter_version: ADAPTER_VERSION,
                accepted_evidence_versions: vec![EVIDENCE_VERSION],
                consensus_kind: "chain-key-nidkg-threshold-bls".to_string(),
                finality_kind: FinalityKind::ProtocolFinality,
                required_depth: CUP_REQUIRED_DEPTH,
                time_unit: TimeUnit::Height,
                trust_model: TrustModel::HonestMajority { set_size: 28 },
            },
        }
    }

    /// Attaches a golden evidence sample for deterministic `selftest::admit` replay.
    ///
    /// Convenience: chained onto [`Self::new`] before registration.
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
            return Err(AdapterError::ConsensusRule {
                rule: "evidence adapter ID does not match ChainKeyNiDkgAdapter".into(),
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
                rule: "Chain-Key evidence network does not match pinned network".into(),
            });
        }
        let Some(pinned) = &self.pinned else {
            return Err(AdapterError::ConsensusRule {
                rule: "no pinned Chain-Key Root NNS anchor; admission is closed".into(),
            });
        };

        let bundle = decode_chain_key_evidence(&evidence.payload)?;
        let cup = &bundle.cup;
        let del = &bundle.delegation;

        if policy.require_declared_match {
            if evidence.declared_height != cup.height {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if !bool::from(evidence.declared_root.ct_eq(&cup.state_root)) {
                return Err(AdapterError::DeclarationMismatch { field: "root" });
            }
        }
        if policy.min_depth > CUP_REQUIRED_DEPTH {
            return Err(AdapterError::InsufficientDepth {
                observed: CUP_REQUIRED_DEPTH,
                required: policy.min_depth,
            });
        }
        if policy.max_age > 0 && policy.now > cup.height {
            let age = policy.now - cup.height;
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

        verify_delegation_and_cup(&self.network, pinned, &bundle)?;

        Ok(FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &evidence.network),
            height: cup.height,
            state_root: cup.state_root,
            finalized_at: cup.height,
            time_unit: TimeUnit::Height,
            security: SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Scheme(SchemeId::ML_DSA_65),
                signers: del.signing_threshold,
                required: del.signing_threshold,
                total_weight: u128::from(del.committee_size),
                slashable: false,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
            attested_block_hash: Some(cup.block_hash),
            attested_event_root: Some(cup.xnet_event_root),
            attested_tx_root: Some(cup.ingress_root),
        })
    }
}

impl ExternalFinalityAdapter for ChainKeyNiDkgAdapter {
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
        observer.observe(ObservedScheme::Scheme(SchemeId::BLS12381_MINSIG));
        observer.observe(ObservedScheme::Scheme(SchemeId::ML_DSA_65));
        Ok(att)
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        let sig_tail_offset = self
            .golden
            .as_ref()
            .map_or(32, |g| g.payload.len().saturating_sub(24));
        vec![
            FaultProbe {
                name: "refuses unknown Chain-Key evidence version".into(),
                patch: BytePatch::EvidenceVersion { value: 7 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "refuses foreign Chain-Key network".into(),
                patch: BytePatch::Network {
                    value: format!("{}-foreign", self.network),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses mismatched declared Chain-Key height".into(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses mismatched declared Chain-Key state root".into(),
                patch: BytePatch::DeclaredRoot { value: [0xFE; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses corrupted Chain-Key payload magic".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: vec![0x00, 0x00],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses mutated Chain-Key delegation subnet_id".into(),
                patch: BytePatch::InPayload {
                    offset: 8,
                    bytes: vec![0xFF, 0xEE],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses corrupted Chain-Key CUP hybrid signature".into(),
                patch: BytePatch::InPayload {
                    offset: sig_tail_offset,
                    bytes: vec![0x5A, 0xA5, 0x5A, 0xA5],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Crypto),
            },
            FaultProbe {
                name: "refuses truncated Chain-Key payload".into(),
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
    use crate::chain::finality::sign_bls;
    use crate::core::address::Address;
    use crate::cross_domain::external::selftest::admit;
    use crate::crypto::primitives::{BlsKeypair, PqKeyPair};

    fn sample_adapter_with_golden() -> (ChainKeyNiDkgAdapter, RawConsensusEvidence) {
        let network = "icp-mainnet";
        let subnet_id = [0x42; 32];
        let root_bls = BlsKeypair::from_seed(&[0x11; 64]).unwrap();
        let root_pq = PqKeyPair::generate();
        let sub_bls = BlsKeypair::from_seed(&[0x33; 64]).unwrap();
        let sub_pq = PqKeyPair::generate();

        let nidkg_digest =
            compute_nidkg_transcript_digest(network, &subnet_id, 9, 105, &[0x77; 32]);
        let mut del = ChainKeySubnetDelegation {
            subnet_id,
            dkg_epoch: 9,
            registry_version: 105,
            committee_size: 28,
            signing_threshold: 19,
            nidkg_transcript_digest: nidkg_digest,
            subnet_bls_pubkey: sub_bls.public_key.clone(),
            subnet_pq_pubkey: sub_pq.public_key_bytes().to_vec(),
            root_bls_sig: Vec::new(),
            root_pq_sig: Vec::new(),
        };
        let del_digest = delegation_signing_digest(network, &del);
        del.root_bls_sig = sign_bls(&root_bls.secret_key, &del_digest);
        del.root_pq_sig = root_pq
            .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &del_digest)
            .unwrap();

        let mut cup = ChainKeyCatchUpPackage {
            dkg_epoch: 9,
            height: 5_000,
            timestamp_ns: 1_770_000_000_000_000_000,
            state_root: [0xAB; 32],
            ingress_root: [0xBC; 32],
            xnet_event_root: [0xCD; 32],
            block_hash: [0xDE; 32],
            threshold_bls_sig: Vec::new(),
            subnet_pq_sig: Vec::new(),
        };
        let cup_digest = cup_signing_digest(network, &subnet_id, &cup);
        cup.threshold_bls_sig = sign_bls(&sub_bls.secret_key, &cup_digest);
        cup.subnet_pq_sig = sub_pq
            .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &cup_digest)
            .unwrap();

        let payload = encode_chain_key_evidence(&ChainKeyEvidenceBundle {
            delegation: del,
            cup,
        })
        .unwrap();
        let evidence = RawConsensusEvidence {
            adapter: AdapterId::from_name(CHAIN_KEY_ADAPTER_NAME),
            network: network.to_string(),
            evidence_version: EVIDENCE_VERSION,
            declared_height: 5_000,
            declared_root: [0xAB; 32],
            payload,
            submitter: Address::from([0x01; 32]),
        };
        let pinned = PinnedChainKeyRoot {
            subnet_id,
            root_bls_pubkey: root_bls.public_key.clone(),
            root_pq_pubkey: root_pq.public_key_bytes().to_vec(),
            dkg_interval_length: 500,
            min_registry_version: 100,
        };
        let adapter =
            ChainKeyNiDkgAdapter::new(network, Some(pinned)).with_golden(evidence.clone());
        (adapter, evidence)
    }

    #[test]
    fn chain_key_nidkg_adapter_passes_full_selftest_admission() {
        let (adapter, ev) = sample_adapter_with_golden();
        let report = admit(&adapter, &VerificationPolicy::strict(0));
        assert!(report.admitted, "selftest failed: {report:?}");
        assert_eq!(report.probes.len(), 8);

        let mut slash_policy = VerificationPolicy::strict(0);
        slash_policy.require_slashable = true;
        assert!(
            matches!(
                adapter.verify(&ev, &slash_policy),
                Err(AdapterError::UnslashableBacking)
            ),
            "Chain-Key NiDKG without a local Budlum confiscation bond must refuse require_slashable=true"
        );
    }

    #[test]
    fn chain_key_refuses_misaligned_cup_height() {
        let (adapter, mut ev) = sample_adapter_with_golden();
        let mut bundle = decode_chain_key_evidence(&ev.payload).unwrap();
        bundle.cup.height = 5_001;
        ev.declared_height = 5_001;
        ev.payload = encode_chain_key_evidence(&bundle).unwrap();
        assert!(matches!(
            adapter.verify(&ev, &VerificationPolicy::strict(0)),
            Err(AdapterError::ConsensusRule { .. })
        ));
    }
}
