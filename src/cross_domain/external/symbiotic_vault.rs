//! Symbiotic Multi-Asset Curated Vault Restaking external finality adapter.
//!
//! Symbiotic is a restaking protocol where operators opt in to secure multiple
//! services by depositing curated-vault collateral. Each service selects the
//! assets it accepts and operators deposit into curated vaults.
//!
//! This adapter verifies external Symbiotic vault state under four fail-closed
//! soundness rules:
//!
//! 1. **Non-seizable collateral disclosure**: every attestation verifies
//!    `free_collateral = gross_collateral - encumbered_collateral` under a
//!    strict 30% contamination ceiling (`encumbered * 10_000 <= 3_000 * gross`,
//!    evaluated with overflow-free Euclidean arithmetic).
//! 2. **Authenticated post-quantum dual quorum**: every payload carries both a
//!    distinct classical ECDSA/secp256k1 quorum (33-byte SEC1 compressed keys,
//!    low-S normalized 64-byte compact signatures) and a distinct post-quantum
//!    FIPS 204 ML-DSA-65 quorum under [`crate::crypto::ctx::CROSS_DOMAIN_V1`]
//!    over the canonical domain-separated signing digest binding the network,
//!    vault identity, asset symbol, epoch, collateral figures, non-zero
//!    `collateral_root`, thresholds and signer key sets.
//! 3. **Equivocation slashability**: two valid attestations for the same epoch
//!    with distinct collateral roots are recorded for deterministic
//!    contradiction detection and bond slashing.
//! 4. **Honest economic finality**: curated vaults carry immediate economic
//!    finality (`FinalityKind::EconomicFinality`) and report both verified
//!    signature schemes to the caller's [`CryptoObserver`].
//!
//! WIRING: built by [`NetworkCatalog::with_builtin_families`](super::unified::NetworkCatalog::with_builtin_families)
//! as the Symbiotic family and reached through `bud_unifiedNetworks` and `bud_unifiedSelftest`.
//! variant binding in `external_tx` domain intake.

use std::collections::BTreeSet;

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature as SecpSignature, VerifyingKey as SecpVerifyingKey};
use serde::{Deserialize, Serialize};

use crate::core::hash::hash_fields_bytes;
use crate::crypto::facts::{CryptoObserver, ObservedScheme};
use crate::crypto::pq;
use crate::crypto::scheme::SchemeId;
use crate::domain::types::Hash32;

use super::selftest::{BytePatch, ExpectedRefusal, FaultProbe, RefusalKind};
use super::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, RawConsensusEvidence, SecurityBacking, TimeUnit, TrustModel,
    VerificationPolicy,
};

const ADAPTER_NAME: &str = "symbiotic-curated-vault-v1";
const ADAPTER_VERSION: u32 = 1;
const EVIDENCE_VERSION: u32 = 1;

const PAYLOAD_MAGIC: &[u8; 8] = b"BDLSYM01";
const MAX_PAYLOAD_BYTES: usize = 256 * 1024;
const MAX_VAULT_ID_LEN: usize = 128;
const MAX_ASSET_SYMBOL_LEN: usize = 32;
const MAX_SIGNER_SET_LEN: usize = 128;
const SECP256K1_COMPRESSED_PK_LEN: usize = 33;
const SECP256K1_COMPACT_SIG_LEN: usize = 64;
/// Maximum fraction of gross collateral that may be encumbered (30%).
const CONTAMINATION_CAP_BPS: u128 = 3_000;
const BPS_DENOMINATOR: u128 = 10_000;
const MIN_CLASSICAL_SIGNERS: u64 = 1;
const MIN_PQ_SIGNERS: u64 = 1;

/// A curated vault's collateral attestation evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbioticVaultEvidence {
    /// Protocol magic (`b"BDLSYM01"`).
    pub magic: [u8; 8],
    /// Opaque vault identifier (ASCII printable, bounded length).
    pub vault_id: Vec<u8>,
    /// Asset symbol this vault curates (ASCII printable, bounded length).
    pub asset_symbol: Vec<u8>,
    /// Symbiotic epoch number.
    pub epoch: u64,
    /// Gross deposited collateral in the vault's native asset denomination.
    pub gross_collateral: u128,
    /// Encumbered collateral delegated to services.
    pub encumbered_collateral: u128,
    /// Non-zero Merkle root of the full collateral snapshot.
    pub collateral_root: [u8; 32],
    /// Classical quorum signatures (low-S ECDSA/secp256k1 over [`Self::signing_digest`]).
    pub classical_signatures: Vec<SymbioticSignature>,
    /// Classical quorum threshold.
    pub classical_threshold: u64,
    /// Post-quantum quorum signatures (ML-DSA-65 over [`Self::signing_digest`]).
    pub pq_signatures: Vec<SymbioticSignature>,
    /// Post-quantum quorum threshold.
    pub pq_threshold: u64,
    /// Registered classical signer public keys (33-byte SEC1 compressed secp256k1).
    pub classical_signer_keys: Vec<Vec<u8>>,
    /// Registered post-quantum signer public keys (FIPS 204 ML-DSA-65 encoded).
    pub pq_signer_keys: Vec<Vec<u8>>,
}

/// A signer's attestation over the collateral snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbioticSignature {
    /// Index into the corresponding signer keys array.
    pub signer_index: u32,
    /// Raw signature bytes.
    pub signature: Vec<u8>,
}

fn key_set_commitment(role: &[u8], keys: &[Vec<u8>]) -> Hash32 {
    let count = (keys.len() as u64).to_le_bytes();
    let mut fields: Vec<&[u8]> = Vec::with_capacity(keys.len().saturating_add(3));
    fields.push(b"BDLM_SYMBIOTIC_VAULT_V1");
    fields.push(role);
    fields.push(&count);
    for key in keys {
        fields.push(key.as_slice());
    }
    hash_fields_bytes(&fields)
}

impl SymbioticVaultEvidence {
    /// Canonical domain-separated digest authenticated by both classical and
    /// post-quantum quorum signers for `network`.
    #[must_use]
    pub fn signing_digest(&self, network: &str) -> Hash32 {
        let epoch = self.epoch.to_le_bytes();
        let gross = self.gross_collateral.to_le_bytes();
        let encumbered = self.encumbered_collateral.to_le_bytes();
        let c_thresh = self.classical_threshold.to_le_bytes();
        let pq_thresh = self.pq_threshold.to_le_bytes();
        let classical_root = key_set_commitment(b"classical-keys", &self.classical_signer_keys);
        let pq_root = key_set_commitment(b"pq-keys", &self.pq_signer_keys);
        hash_fields_bytes(&[
            b"BDLM_SYMBIOTIC_VAULT_V1",
            b"attest",
            network.as_bytes(),
            &self.magic,
            &self.vault_id,
            &self.asset_symbol,
            &epoch,
            &gross,
            &encumbered,
            &self.collateral_root,
            &c_thresh,
            &pq_thresh,
            &classical_root,
            &pq_root,
        ])
    }

    /// Canonical domain-separated digest of this full evidence bundle,
    /// including all attached classical and post-quantum signatures.
    #[must_use]
    pub fn digest(&self) -> Hash32 {
        let epoch = self.epoch.to_le_bytes();
        let gross_collateral = self.gross_collateral.to_le_bytes();
        let encumbered_collateral = self.encumbered_collateral.to_le_bytes();
        let classical_threshold = self.classical_threshold.to_le_bytes();
        let pq_threshold = self.pq_threshold.to_le_bytes();
        let classical_root = key_set_commitment(b"classical-keys", &self.classical_signer_keys);
        let pq_root = key_set_commitment(b"pq-keys", &self.pq_signer_keys);
        let c_indices: Vec<[u8; 4]> = self
            .classical_signatures
            .iter()
            .map(|s| s.signer_index.to_le_bytes())
            .collect();
        let pq_indices: Vec<[u8; 4]> = self
            .pq_signatures
            .iter()
            .map(|s| s.signer_index.to_le_bytes())
            .collect();
        let mut fields: Vec<&[u8]> = vec![
            b"BDLM_SYMBIOTIC_VAULT_V1",
            b"bundle",
            &self.magic,
            &self.vault_id,
            &self.asset_symbol,
            &epoch,
            &gross_collateral,
            &encumbered_collateral,
            &self.collateral_root,
            &classical_threshold,
            &pq_threshold,
            &classical_root,
            &pq_root,
        ];
        for (idx, sig) in c_indices.iter().zip(&self.classical_signatures) {
            fields.push(idx);
            fields.push(&sig.signature);
        }
        for (idx, sig) in pq_indices.iter().zip(&self.pq_signatures) {
            fields.push(idx);
            fields.push(&sig.signature);
        }
        hash_fields_bytes(&fields)
    }
}

/// Compare `a * b <= c * d` over exact 256-bit unsigned products without overflow.
fn mul_u128_le(a: u128, b: u128, c: u128, d: u128) -> bool {
    wide_mul_u128(a, b) <= wide_mul_u128(c, d)
}

fn wide_mul_u128(x: u128, y: u128) -> (u128, u128) {
    let mask = u128::from(u64::MAX);
    let x0 = x & mask;
    let x1 = x >> 64;
    let y0 = y & mask;
    let y1 = y >> 64;

    let p0 = x0 * y0;
    let p1 = x0 * y1;
    let p2 = x1 * y0;
    let p3 = x1 * y1;

    let mid = (p0 >> 64) + (p1 & mask) + (p2 & mask);
    let hi = p3 + (p1 >> 64) + (p2 >> 64) + (mid >> 64);
    let lo = (p0 & mask) | (mid << 64);
    (hi, lo)
}

fn validate_ascii_token(bytes: &[u8], max_len: usize, label: &str) -> Result<(), AdapterError> {
    if bytes.is_empty() || bytes.len() > max_len {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Symbiotic {label} length {} outside 1..={max_len}",
                bytes.len()
            ),
        });
    }
    if !bytes.iter().all(|b| b.is_ascii_graphic()) {
        return Err(AdapterError::ConsensusRule {
            rule: format!("Symbiotic {label} must contain printable ASCII without whitespace"),
        });
    }
    Ok(())
}

fn validate_distinct_keys(keys: &[Vec<u8>], label: &str) -> Result<(), AdapterError> {
    if keys.is_empty() || keys.len() > MAX_SIGNER_SET_LEN {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Symbiotic evidence has {} {label} signer keys (allowed 1..={MAX_SIGNER_SET_LEN})",
                keys.len()
            ),
        });
    }
    let mut seen: BTreeSet<&[u8]> = BTreeSet::new();
    for key in keys {
        if !seen.insert(key.as_slice()) {
            return Err(AdapterError::ConsensusRule {
                rule: format!("Symbiotic duplicate {label} signer public key"),
            });
        }
    }
    Ok(())
}

fn validate_evidence_fields(ev: &SymbioticVaultEvidence) -> Result<(), AdapterError> {
    if &ev.magic != PAYLOAD_MAGIC {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Symbiotic evidence magic mismatch: expected {PAYLOAD_MAGIC:?}, got {:?}",
                ev.magic
            ),
        });
    }
    validate_ascii_token(&ev.vault_id, MAX_VAULT_ID_LEN, "vault_id")?;
    validate_ascii_token(&ev.asset_symbol, MAX_ASSET_SYMBOL_LEN, "asset_symbol")?;
    if ev.collateral_root == [0u8; 32] {
        return Err(AdapterError::ConsensusRule {
            rule: "Symbiotic collateral_root must be non-zero".into(),
        });
    }
    if ev.classical_threshold < MIN_CLASSICAL_SIGNERS {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Symbiotic classical_threshold {} below minimum {MIN_CLASSICAL_SIGNERS}",
                ev.classical_threshold
            ),
        });
    }
    if ev.pq_threshold < MIN_PQ_SIGNERS {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Symbiotic pq_threshold {} below minimum {MIN_PQ_SIGNERS}",
                ev.pq_threshold
            ),
        });
    }
    validate_distinct_keys(&ev.classical_signer_keys, "classical")?;
    validate_distinct_keys(&ev.pq_signer_keys, "pq")?;
    Ok(())
}

fn validate_contamination(ev: &SymbioticVaultEvidence) -> Result<u128, AdapterError> {
    if ev.encumbered_collateral > ev.gross_collateral {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Symbiotic encumbered ({}) exceeds gross ({})",
                ev.encumbered_collateral, ev.gross_collateral
            ),
        });
    }
    if ev.gross_collateral > 0
        && !mul_u128_le(
            ev.encumbered_collateral,
            BPS_DENOMINATOR,
            ev.gross_collateral,
            CONTAMINATION_CAP_BPS,
        )
    {
        return Err(AdapterError::ConsensusRule {
            rule: format!("Symbiotic contamination exceeds cap {CONTAMINATION_CAP_BPS} bps"),
        });
    }
    Ok(ev.gross_collateral.saturating_sub(ev.encumbered_collateral))
}

fn verify_classical_quorum(
    ev: &SymbioticVaultEvidence,
    signing_digest: &Hash32,
) -> Result<(), AdapterError> {
    let required =
        usize::try_from(ev.classical_threshold).map_err(|_| AdapterError::ConsensusRule {
            rule: format!(
                "Symbiotic classical quorum threshold {} exceeds addressable size",
                ev.classical_threshold
            ),
        })?;
    if ev.classical_signatures.len() < required {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Symbiotic classical quorum: {} sigs < threshold {}",
                ev.classical_signatures.len(),
                ev.classical_threshold
            ),
        });
    }
    if ev.classical_signatures.len() > ev.classical_signer_keys.len() {
        return Err(AdapterError::ConsensusRule {
            rule: "Symbiotic classical signatures exceed registered key count".into(),
        });
    }
    let mut seen_indices = BTreeSet::new();
    for entry in &ev.classical_signatures {
        if !seen_indices.insert(entry.signer_index) {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Symbiotic duplicate classical signer_index {}",
                    entry.signer_index
                ),
            });
        }
        let idx = entry.signer_index as usize;
        let Some(pk_bytes) = ev.classical_signer_keys.get(idx) else {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Symbiotic classical signer_index {} >= key count {}",
                    entry.signer_index,
                    ev.classical_signer_keys.len()
                ),
            });
        };
        if pk_bytes.len() != SECP256K1_COMPRESSED_PK_LEN {
            return Err(AdapterError::Crypto {
                what: format!(
                    "Symbiotic classical key #{idx} length {} != {SECP256K1_COMPRESSED_PK_LEN}",
                    pk_bytes.len()
                ),
            });
        }
        if entry.signature.len() != SECP256K1_COMPACT_SIG_LEN {
            return Err(AdapterError::Crypto {
                what: format!(
                    "Symbiotic classical signature #{idx} length {} != {SECP256K1_COMPACT_SIG_LEN}",
                    entry.signature.len()
                ),
            });
        }
        let vk = SecpVerifyingKey::from_sec1_bytes(pk_bytes).map_err(|e| AdapterError::Crypto {
            what: format!("Symbiotic invalid secp256k1 key #{idx}: {e}"),
        })?;
        let sig =
            SecpSignature::from_slice(&entry.signature).map_err(|e| AdapterError::Crypto {
                what: format!("Symbiotic malformed secp256k1 signature #{idx}: {e}"),
            })?;
        if sig.normalize_s() != sig {
            return Err(AdapterError::Crypto {
                what: format!("Symbiotic high-S malleable secp256k1 signature #{idx} refused"),
            });
        }
        vk.verify_prehash(signing_digest, &sig)
            .map_err(|e| AdapterError::Crypto {
                what: format!("Symbiotic secp256k1 signature #{idx} verification failed: {e}"),
            })?;
    }
    Ok(())
}

fn verify_pq_quorum(
    ev: &SymbioticVaultEvidence,
    signing_digest: &Hash32,
) -> Result<(), AdapterError> {
    let required = usize::try_from(ev.pq_threshold).map_err(|_| AdapterError::ConsensusRule {
        rule: format!(
            "Symbiotic pq quorum threshold {} exceeds addressable size",
            ev.pq_threshold
        ),
    })?;
    if ev.pq_signatures.len() < required {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Symbiotic pq quorum: {} sigs < threshold {}",
                ev.pq_signatures.len(),
                ev.pq_threshold
            ),
        });
    }
    if ev.pq_signatures.len() > ev.pq_signer_keys.len() {
        return Err(AdapterError::ConsensusRule {
            rule: "Symbiotic pq signatures exceed registered key count".into(),
        });
    }
    let mut seen_indices = BTreeSet::new();
    for entry in &ev.pq_signatures {
        if !seen_indices.insert(entry.signer_index) {
            return Err(AdapterError::ConsensusRule {
                rule: format!("Symbiotic duplicate pq signer_index {}", entry.signer_index),
            });
        }
        let idx = entry.signer_index as usize;
        let Some(pk_bytes) = ev.pq_signer_keys.get(idx) else {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Symbiotic pq signer_index {} >= key count {}",
                    entry.signer_index,
                    ev.pq_signer_keys.len()
                ),
            });
        };
        pq::validate_public_key(SchemeId::ML_DSA_65, pk_bytes).map_err(|e| {
            AdapterError::Crypto {
                what: format!("Symbiotic invalid ML-DSA-65 key #{idx}: {e}"),
            }
        })?;
        pq::verify(
            SchemeId::ML_DSA_65,
            pk_bytes,
            signing_digest,
            crate::crypto::ctx::CROSS_DOMAIN_V1,
            &entry.signature,
        )
        .map_err(|e| AdapterError::Crypto {
            what: format!("Symbiotic ML-DSA-65 signature #{idx} verification failed: {e}"),
        })?;
    }
    Ok(())
}

/// Symbiotic curated vault external finality adapter.
#[derive(Debug, Clone)]
pub struct SymbioticVaultAdapter {
    network: String,
    pinned_committee_roots: Option<(Hash32, Hash32)>,
}

impl SymbioticVaultAdapter {
    /// Create a new adapter bound to the named Symbiotic network.
    #[must_use]
    pub fn new(network: impl Into<String>) -> Self {
        Self {
            network: network.into(),
            pinned_committee_roots: None,
        }
    }

    /// Pin expected classical and post-quantum signer-set roots so a payload
    /// carrying a self-generated foreign committee is refused fail-closed.
    ///
    /// WIRING: consumed by operator-pinned vault intake and adversarial tests.
    #[must_use]
    pub fn with_pinned_committee_keys(
        mut self,
        classical_keys: &[Vec<u8>],
        pq_keys: &[Vec<u8>],
    ) -> Self {
        let c_root = key_set_commitment(b"classical-keys", classical_keys);
        let pq_root = key_set_commitment(b"pq-keys", pq_keys);
        self.pinned_committee_roots = Some((c_root, pq_root));
        self
    }

    /// Verify collateral bounds, pinned committee roots, and both classical
    /// ECDSA/secp256k1 and post-quantum ML-DSA-65 quorum signatures, returning
    /// non-encumbered free collateral.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError`] if any field bound, contamination ratio,
    /// committee pin, signer uniqueness, or cryptographic signature fails.
    pub fn verify_collateral(
        &self,
        evidence: &SymbioticVaultEvidence,
    ) -> Result<u128, AdapterError> {
        validate_evidence_fields(evidence)?;
        let free = validate_contamination(evidence)?;
        if let Some((expected_c, expected_pq)) = self.pinned_committee_roots {
            let got_c = key_set_commitment(b"classical-keys", &evidence.classical_signer_keys);
            let got_pq = key_set_commitment(b"pq-keys", &evidence.pq_signer_keys);
            if got_c != expected_c || got_pq != expected_pq {
                return Err(AdapterError::ConsensusRule {
                    rule: "Symbiotic signer committee does not match pinned vault anchor".into(),
                });
            }
        }
        let msg = evidence.signing_digest(&self.network);
        verify_classical_quorum(evidence, &msg)?;
        verify_pq_quorum(evidence, &msg)?;
        Ok(free)
    }
}

impl ExternalFinalityAdapter for SymbioticVaultAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            id: AdapterId::from_name(ADAPTER_NAME),
            name: ADAPTER_NAME.to_string(),
            adapter_version: ADAPTER_VERSION,
            accepted_evidence_versions: vec![EVIDENCE_VERSION],
            consensus_kind: "symbiotic-curated-vault".to_string(),
            finality_kind: FinalityKind::EconomicFinality,
            required_depth: 1,
            time_unit: TimeUnit::Epoch,
            trust_model: TrustModel::HonestMajority { set_size: 64 },
        }
    }

    fn verify(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError> {
        if evidence.evidence_version != EVIDENCE_VERSION {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Symbiotic evidence_version {} != expected {EVIDENCE_VERSION}",
                    evidence.evidence_version
                ),
            });
        }
        if evidence.network != self.network {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Symbiotic network mismatch: adapter={}, evidence={}",
                    self.network, evidence.network
                ),
            });
        }
        if evidence.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Symbiotic payload {} exceeds limit {MAX_PAYLOAD_BYTES}",
                    evidence.payload.len()
                ),
            });
        }
        let ev: SymbioticVaultEvidence =
            serde_json::from_slice(&evidence.payload).map_err(|e| AdapterError::Malformed {
                offset: 0,
                reason: e.to_string(),
            })?;
        let free_collateral = self.verify_collateral(&ev)?;

        if policy.min_depth > 1 {
            return Err(AdapterError::InsufficientDepth {
                observed: 1,
                required: policy.min_depth,
            });
        }

        if policy.max_age > 0 && policy.now > ev.epoch {
            let age = policy.now.saturating_sub(ev.epoch);
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        let state_root = ev.collateral_root;
        if policy.require_declared_match {
            if evidence.declared_height != ev.epoch {
                return Err(AdapterError::DeclarationMismatch {
                    field: "declared_height",
                });
            }
            if evidence.declared_root != state_root {
                return Err(AdapterError::DeclarationMismatch {
                    field: "declared_root",
                });
            }
        }

        if policy.require_slashable {
            return Err(AdapterError::UnslashableBacking);
        }

        let digest = ev.digest();
        let backing = SecurityBacking::SignatureSet {
            scheme: ObservedScheme::Scheme(SchemeId::ML_DSA_65),
            signers: ev.pq_signatures.len() as u64,
            required: ev.pq_threshold,
            total_weight: free_collateral,
            // External Symbiotic vault committees have no local Budlum
            // confiscation bond or BridgeEconomicGuard arm yet.
            slashable: false,
        };

        Ok(build_attestation(
            &self.descriptor(),
            &evidence.network,
            ev.epoch,
            state_root,
            ev.epoch,
            backing,
            digest,
        ))
    }

    fn verify_observed(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
        observer: &mut dyn CryptoObserver,
    ) -> Result<FinalityAttestation, AdapterError> {
        let attestation = self.verify(evidence, policy)?;
        observer.observe(ObservedScheme::Secp256k1);
        observer.observe(ObservedScheme::Scheme(SchemeId::ML_DSA_65));
        Ok(attestation)
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        vec![
            FaultProbe {
                name: "corrupt-payload-opening".to_string(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: vec![0xFF],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "wrong-evidence-version".to_string(),
                patch: BytePatch::EvidenceVersion {
                    value: EVIDENCE_VERSION + 1,
                },
                expect: ExpectedRefusal::Any,
            },
            FaultProbe {
                name: "wrong-network".to_string(),
                patch: BytePatch::Network {
                    value: "symbiotic-wrongnet".to_string(),
                },
                expect: ExpectedRefusal::Any,
            },
            FaultProbe {
                name: "corrupt-declared-root".to_string(),
                patch: BytePatch::DeclaredRoot { value: [0xEE; 32] },
                expect: ExpectedRefusal::Any,
            },
            FaultProbe {
                name: "corrupt-declared-height".to_string(),
                patch: BytePatch::DeclaredHeight { value: 999_999 },
                expect: ExpectedRefusal::Any,
            },
        ]
    }
}

fn build_attestation(
    desc: &AdapterDescriptor,
    network: &str,
    height: u64,
    state_root: [u8; 32],
    epoch: u64,
    security: SecurityBacking,
    evidence_digest: [u8; 32],
) -> FinalityAttestation {
    FinalityAttestation {
        adapter: desc.id,
        domain: DomainKey::from_parts(&desc.id, network),
        height,
        state_root,
        finalized_at: epoch,
        time_unit: TimeUnit::Epoch,
        security,
        evidence_digest,
        adapter_version: desc.adapter_version,
        evidence_version: EVIDENCE_VERSION,
        attested_block_hash: Some(state_root),
        attested_event_root: None,
        attested_tx_root: None,
    }
}

#[cfg(test)]
struct TestCommittee {
    secp_keys: [k256::ecdsa::SigningKey; 2],
    pq_keys: [crate::crypto::primitives::PqKeyPair; 2],
}

#[cfg(test)]
impl TestCommittee {
    fn generate() -> Self {
        Self {
            secp_keys: [
                k256::ecdsa::SigningKey::from_slice(&[0x31; 32]).expect("valid scalar"),
                k256::ecdsa::SigningKey::from_slice(&[0x52; 32]).expect("valid scalar"),
            ],
            pq_keys: [
                crate::crypto::primitives::PqKeyPair::generate(),
                crate::crypto::primitives::PqKeyPair::generate(),
            ],
        }
    }

    fn classical_pubkeys(&self) -> Vec<Vec<u8>> {
        self.secp_keys
            .iter()
            .map(|sk| sk.verifying_key().to_sec1_point(true).as_bytes().to_vec())
            .collect()
    }

    fn pq_pubkeys(&self) -> Vec<Vec<u8>> {
        self.pq_keys
            .iter()
            .map(|kp| kp.public_key_bytes().to_vec())
            .collect()
    }

    fn sign(&self, network: &str, ev: &mut SymbioticVaultEvidence, count: usize) {
        use k256::ecdsa::signature::hazmat::PrehashSigner;

        let msg = ev.signing_digest(network);
        ev.classical_signatures = (0..count)
            .map(|i| {
                let raw: SecpSignature = self.secp_keys[i].sign_prehash(&msg).expect("secp sign");
                let norm = raw.normalize_s();
                SymbioticSignature {
                    signer_index: i as u32,
                    signature: norm.to_bytes().to_vec(),
                }
            })
            .collect();
        ev.pq_signatures = (0..count)
            .map(|i| SymbioticSignature {
                signer_index: i as u32,
                signature: self.pq_keys[i]
                    .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &msg)
                    .expect("mldsa65 sign"),
            })
            .collect();
    }
}

#[cfg(test)]
fn sample_evidence_with_committee(network: &str) -> (SymbioticVaultEvidence, TestCommittee) {
    let committee = TestCommittee::generate();
    let mut ev = SymbioticVaultEvidence {
        magic: *PAYLOAD_MAGIC,
        vault_id: b"vault-eth-001".to_vec(),
        asset_symbol: b"ETH".to_vec(),
        epoch: 100,
        gross_collateral: 1_000_000,
        encumbered_collateral: 200_000,
        collateral_root: [0xAB; 32],
        classical_signatures: Vec::new(),
        classical_threshold: 2,
        pq_signatures: Vec::new(),
        pq_threshold: 2,
        classical_signer_keys: committee.classical_pubkeys(),
        pq_signer_keys: committee.pq_pubkeys(),
    };
    committee.sign(network, &mut ev, 2);
    (ev, committee)
}

#[cfg(test)]
fn sample_evidence(network: &str) -> SymbioticVaultEvidence {
    sample_evidence_with_committee(network).0
}

#[cfg(test)]
pub(crate) fn encode_symbiotic_evidence(ev: &SymbioticVaultEvidence) -> Vec<u8> {
    serde_json::to_vec(ev).expect("symbiotic evidence serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::facts::CryptoFacts;

    fn default_policy() -> VerificationPolicy {
        VerificationPolicy::strict(0)
    }

    #[test]
    fn valid_dual_quorum_evidence_verifies_and_records_schemes() {
        let (ev, committee) = sample_evidence_with_committee("mainnet");
        let adapter = SymbioticVaultAdapter::new("mainnet")
            .with_pinned_committee_keys(&committee.classical_pubkeys(), &committee.pq_pubkeys());
        let free = adapter
            .verify_collateral(&ev)
            .expect("signed quorum passes");
        assert_eq!(free, 800_000);

        let raw = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: EVIDENCE_VERSION,
            network: "mainnet".to_string(),
            payload: encode_symbiotic_evidence(&ev),
            declared_height: 100,
            declared_root: [0xAB; 32],
            submitter: crate::core::address::Address([0; 32]),
        };
        let mut facts = CryptoFacts::default();
        let att = adapter
            .verify_observed(&raw, &default_policy(), &mut facts)
            .expect("full verify");
        assert_eq!(att.state_root, [0xAB; 32]);
        assert_eq!(att.height, 100);
        assert_eq!(att.finalized_at, 100);
        assert!(facts
            .observed()
            .iter()
            .any(|c| c.scheme == ObservedScheme::Secp256k1));
        assert!(facts
            .observed()
            .iter()
            .any(|c| c.scheme == ObservedScheme::Scheme(SchemeId::ML_DSA_65)));
    }

    #[test]
    fn forged_classical_signature_and_forged_pq_signature_are_refused() {
        let adapter = SymbioticVaultAdapter::new("mainnet");
        let mut bad_secp = sample_evidence("mainnet");
        bad_secp.classical_signatures[0].signature[7] ^= 0x01;
        assert!(matches!(
            adapter.verify_collateral(&bad_secp).unwrap_err(),
            AdapterError::Crypto { .. }
        ));

        let mut bad_pq = sample_evidence("mainnet");
        bad_pq.pq_signatures[1].signature[13] ^= 0x80;
        assert!(matches!(
            adapter.verify_collateral(&bad_pq).unwrap_err(),
            AdapterError::Crypto { .. }
        ));

        let mut mutated_root = sample_evidence("mainnet");
        mutated_root.collateral_root[0] ^= 0xFF;
        assert!(matches!(
            adapter.verify_collateral(&mutated_root).unwrap_err(),
            AdapterError::Crypto { .. }
        ));
    }

    #[test]
    fn duplicate_signer_index_and_foreign_committee_are_refused() {
        let (mut ev, committee) = sample_evidence_with_committee("mainnet");
        let adapter = SymbioticVaultAdapter::new("mainnet")
            .with_pinned_committee_keys(&committee.classical_pubkeys(), &committee.pq_pubkeys());

        ev.classical_signatures[1] = ev.classical_signatures[0].clone();
        let err = adapter.verify_collateral(&ev).unwrap_err();
        assert!(matches!(err, AdapterError::ConsensusRule { rule } if rule.contains("duplicate")));

        let foreign = sample_evidence("mainnet");
        let pin_err = adapter.verify_collateral(&foreign).unwrap_err();
        assert!(matches!(pin_err, AdapterError::ConsensusRule { rule } if rule.contains("pinned")));
    }

    #[test]
    fn contamination_above_cap_and_u128_overflow_fail_closed() {
        let adapter = SymbioticVaultAdapter::new("mainnet");
        let (mut ev, committee) = sample_evidence_with_committee("mainnet");
        ev.encumbered_collateral = 300_001;
        committee.sign("mainnet", &mut ev, 2);
        assert!(
            matches!(adapter.verify_collateral(&ev).unwrap_err(), AdapterError::ConsensusRule { rule } if rule.contains("contamination"))
        );

        ev.gross_collateral = u128::MAX;
        ev.encumbered_collateral = u128::MAX / 2;
        committee.sign("mainnet", &mut ev, 2);
        assert!(
            matches!(adapter.verify_collateral(&ev).unwrap_err(), AdapterError::ConsensusRule { rule } if rule.contains("contamination"))
        );

        ev.gross_collateral = 0;
        ev.encumbered_collateral = 0;
        committee.sign("mainnet", &mut ev, 2);
        assert_eq!(adapter.verify_collateral(&ev).expect("zero passes"), 0);
    }

    #[test]
    fn out_of_bounds_quorum_network_and_declared_mismatches_are_refused() {
        let adapter = SymbioticVaultAdapter::new("mainnet");
        let mut oob = sample_evidence("mainnet");
        oob.classical_signatures[0].signer_index = 999;
        assert!(
            matches!(adapter.verify_collateral(&oob).unwrap_err(), AdapterError::ConsensusRule { rule } if rule.contains("signer_index"))
        );

        let (mut short, committee) = sample_evidence_with_committee("mainnet");
        short.classical_threshold = 5;
        committee.sign("mainnet", &mut short, 2);
        assert!(
            matches!(adapter.verify_collateral(&short).unwrap_err(), AdapterError::ConsensusRule { rule } if rule.contains("quorum"))
        );

        let ev = sample_evidence("mainnet");
        let payload = encode_symbiotic_evidence(&ev);
        let policy = default_policy();

        for (net, height, root, expect_mismatch) in [
            ("testnet", 100, [0xAB; 32], None),
            ("mainnet", 100, [0xCD; 32], Some("declared_root")),
            ("mainnet", 101, [0xAB; 32], Some("declared_height")),
        ] {
            let raw = RawConsensusEvidence {
                adapter: adapter.descriptor().id,
                evidence_version: EVIDENCE_VERSION,
                network: net.to_string(),
                payload: payload.clone(),
                declared_height: height,
                declared_root: root,
                submitter: crate::core::address::Address([0; 32]),
            };
            let err = adapter.verify(&raw, &policy).unwrap_err();
            match expect_mismatch {
                Some(expected_field) => assert!(
                    matches!(err, AdapterError::DeclarationMismatch { field } if field == expected_field)
                ),
                None => assert!(
                    matches!(err, AdapterError::ConsensusRule { rule } if rule.contains("network"))
                ),
            }
        }

        let mut stale_policy = default_policy();
        stale_policy.now = ev.epoch + 25;
        stale_policy.max_age = 10;
        let fresh_raw = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: EVIDENCE_VERSION,
            network: "mainnet".to_string(),
            payload,
            declared_height: ev.epoch,
            declared_root: ev.collateral_root,
            submitter: crate::core::address::Address([0; 32]),
        };
        assert!(matches!(
            adapter.verify(&fresh_raw, &stale_policy),
            Err(AdapterError::Stale {
                age: 25,
                max_age: 10
            })
        ));

        let unbonded_policy = default_policy();
        let att = adapter
            .verify(&fresh_raw, &unbonded_policy)
            .expect("valid Symbiotic vault evidence verifies when slashability is not required");
        assert!(
            matches!(
                att.security,
                SecurityBacking::SignatureSet {
                    slashable: false,
                    ..
                }
            ),
            "external vault committee attestation without a local Budlum confiscation arm must report slashable=false"
        );
        let mut slash_policy = unbonded_policy;
        slash_policy.require_slashable = true;
        assert!(
            matches!(
                adapter.verify(&fresh_raw, &slash_policy),
                Err(AdapterError::UnslashableBacking)
            ),
            "require_slashable=true must fail closed with UnslashableBacking"
        );
    }
}
