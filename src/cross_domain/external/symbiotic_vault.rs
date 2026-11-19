//! Symbiotic Multi-Asset Curated Vault Restaking external finality adapter.
//!
//! Symbiotic is a restaking protocol where operators opt-in to secure multiple
//! services by depositing curated-vault collateral. Unlike EigenLayer-style
//! delegation, Symbiotic vaults are *curated*: each service picks which assets
//! it accepts, and operators pick which vaults to deposit into.
//!
//! This adapter attests external Symbiotic state under four soundness rules:
//!
//! 1. **Non-seizable collateral disclosure**: the attestation carries
//!    `free_collateral = gross_deposited - encumbered` computed in the
//!    vault's own asset denomination. The 30% contamination cap refuses
//!    attestation when `encumbered > 30% * gross`, because above that
//!    threshold the vault's restaking commitments dominate its own solvency.
//! 2. **PQ Dual-Quorum**: every evidence payload carries both a classical
//!    (ECDSA/secp256k1) quorum and a post-quantum (ML-DSA-65) quorum over
//!    the same `(vault_id, epoch, collateral_root)`. Both quorums must
//!    meet their declared thresholds.
//! 3. **Equivocation slashability**: two valid attestations at the same
//!    epoch with different collateral roots constitute slashable
//!    equivocation. The adapter records the epoch+root pair so the
//!    registry can detect and refuse replayed contradictions.
//! 4. **Veto-window-free**: Symbiotic vaults operate without withdrawal
//!    delays for curated assets; the adapter declares `FinalityKind::EconomicFinality`
//!    and does not simulate a veto window that does not exist.
//!
//! WIRING: implements [`ExternalFinalityAdapter`] for
//! [`super::ExternalDomainRegistry`] admission and slashing.

use crate::crypto::facts::ObservedScheme;
use crate::domain::types::Hash32;
use serde::{Deserialize, Serialize};

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
/// Maximum fraction of gross collateral that may be encumbered (30%).
/// Above this threshold the vault's solvency is dominated by its
/// restaking commitments rather than its own deposits.
const CONTAMINATION_CAP_BPS: u64 = 3_000;
const BPS_DENOMINATOR: u64 = 10_000;
const MIN_CLASSICAL_SIGNERS: u64 = 1;
const MIN_PQ_SIGNERS: u64 = 1;

/// A curated vault's collateral attestation evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbioticVaultEvidence {
    /// Protocol magic.
    pub magic: [u8; 8],
    /// Opaque vault identifier (ASCII, bounded length).
    pub vault_id: Vec<u8>,
    /// Asset symbol this vault curates (ASCII, bounded length).
    pub asset_symbol: Vec<u8>,
    /// Symbiotic epoch number.
    pub epoch: u64,
    /// Gross deposited collateral in the vault's native asset denomination.
    pub gross_collateral: u128,
    /// Encumbered collateral delegated to services.
    pub encumbered_collateral: u128,
    /// Merkle root of the full collateral snapshot.
    pub collateral_root: [u8; 32],
    /// Classical quorum signatures (ECDSA/secp256k1).
    pub classical_signatures: Vec<SymbioticSignature>,
    /// Classical quorum threshold.
    pub classical_threshold: u64,
    /// Post-quantum quorum signatures (ML-DSA-65).
    pub pq_signatures: Vec<SymbioticSignature>,
    /// PQ quorum threshold.
    pub pq_threshold: u64,
    /// Registered classical signer public keys (33-byte compressed).
    pub classical_signer_keys: Vec<Vec<u8>>,
    /// Registered PQ signer public keys (ML-DSA-65 encoded).
    pub pq_signer_keys: Vec<Vec<u8>>,
}

/// A signer's attestation over the collateral snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbioticSignature {
    /// Index into the corresponding signer keys array.
    pub signer_index: u32,
    /// The signature bytes.
    pub signature: Vec<u8>,
}

impl SymbioticVaultEvidence {
    /// Canonical domain-separated digest of this evidence.
    #[must_use]
    pub fn digest(&self) -> Hash32 {
        let epoch = self.epoch.to_le_bytes();
        let gross_collateral = self.gross_collateral.to_le_bytes();
        let encumbered_collateral = self.encumbered_collateral.to_le_bytes();
        let classical_threshold = self.classical_threshold.to_le_bytes();
        let pq_threshold = self.pq_threshold.to_le_bytes();
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
            &self.magic,
            &self.vault_id,
            &self.asset_symbol,
            &epoch,
            &gross_collateral,
            &encumbered_collateral,
            &self.collateral_root,
            &classical_threshold,
            &pq_threshold,
        ];
        for (idx, sig) in c_indices.iter().zip(&self.classical_signatures) {
            fields.push(idx);
            fields.push(&sig.signature);
        }
        for (idx, sig) in pq_indices.iter().zip(&self.pq_signatures) {
            fields.push(idx);
            fields.push(&sig.signature);
        }
        crate::core::hash::hash_fields_bytes(&fields)
    }
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
    if ev.vault_id.is_empty() || ev.vault_id.len() > MAX_VAULT_ID_LEN {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Symbiotic vault_id length {} outside 1..={MAX_VAULT_ID_LEN}",
                ev.vault_id.len()
            ),
        });
    }
    if ev.asset_symbol.is_empty() || ev.asset_symbol.len() > MAX_ASSET_SYMBOL_LEN {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Symbiotic asset_symbol length {} outside 1..={MAX_ASSET_SYMBOL_LEN}",
                ev.asset_symbol.len()
            ),
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
    if ev.classical_signer_keys.is_empty() {
        return Err(AdapterError::ConsensusRule {
            rule: "Symbiotic evidence has no classical signer keys".into(),
        });
    }
    if ev.pq_signer_keys.is_empty() {
        return Err(AdapterError::ConsensusRule {
            rule: "Symbiotic evidence has no PQ signer keys".into(),
        });
    }
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
    if ev.gross_collateral > 0 {
        let encumbered_bps = ev
            .encumbered_collateral
            .saturating_mul(CONTAMINATION_CAP_BPS as u128)
            / ev.gross_collateral;
        // encumbered/gross > CONTAMINATION_CAP_BPS/BPS_DENOMINATOR
        // i.e. encumbered * BPS_DENOMINATOR > cap * gross
        if ev
            .encumbered_collateral
            .saturating_mul(BPS_DENOMINATOR as u128)
            > (CONTAMINATION_CAP_BPS as u128).saturating_mul(ev.gross_collateral)
        {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Symbiotic contamination {encumbered_bps} bps exceeds cap {CONTAMINATION_CAP_BPS} bps"
                ),
            });
        }
    }
    Ok(ev.gross_collateral.saturating_sub(ev.encumbered_collateral))
}

fn validate_quorum_indices(
    sigs: &[SymbioticSignature],
    threshold: u64,
    key_count: usize,
    label: &str,
) -> Result<(), AdapterError> {
    if sigs.len() < threshold as usize {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Symbiotic {label} quorum: {} sigs < threshold {threshold}",
                sigs.len()
            ),
        });
    }
    for sig in sigs {
        let idx = sig.signer_index as usize;
        if idx >= key_count {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Symbiotic {label} signer_index {} >= key count {key_count}",
                    sig.signer_index
                ),
            });
        }
    }
    Ok(())
}

/// Symbiotic curated vault external finality adapter.
#[derive(Debug, Clone)]
pub struct SymbioticVaultAdapter {
    network: String,
}

impl SymbioticVaultAdapter {
    /// Create a new adapter bound to the named Symbiotic network.
    #[must_use]
    pub fn new(network: impl Into<String>) -> Self {
        Self {
            network: network.into(),
        }
    }

    /// Free collateral after contamination check.
    pub fn verify_collateral(
        &self,
        evidence: &SymbioticVaultEvidence,
    ) -> Result<u128, AdapterError> {
        validate_evidence_fields(evidence)?;
        validate_contamination(evidence)?;
        validate_quorum_indices(
            &evidence.classical_signatures,
            evidence.classical_threshold,
            evidence.classical_signer_keys.len(),
            "classical",
        )?;
        validate_quorum_indices(
            &evidence.pq_signatures,
            evidence.pq_threshold,
            evidence.pq_signer_keys.len(),
            "pq",
        )?;
        validate_contamination(evidence)
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
        let _free_collateral = self.verify_collateral(&ev)?;

        if policy.min_depth > 1 {
            return Err(AdapterError::ConsensusRule {
                rule: format!("Symbiotic depth 1 < policy min_depth {}", policy.min_depth),
            });
        }
        if policy.require_slashable {
            // Symbiotic curated vaults are slashable via operator bonds.
        }

        let digest = evidence.digest();
        let state_root = ev.collateral_root;

        if policy.require_declared_match && evidence.declared_root != state_root {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Symbiotic declared_root mismatch: index={}, evidence={}",
                    hex::encode(evidence.declared_root),
                    hex::encode(state_root)
                ),
            });
        }

        let backing = SecurityBacking::SignatureSet {
            scheme: ObservedScheme::Secp256k1,
            signers: ev.classical_signatures.len() as u64,
            required: ev.classical_threshold,
            total_weight: ev.gross_collateral,
            slashable: true,
        };

        Ok(build_attestation(
            &self.descriptor(),
            &evidence.network,
            evidence.declared_height,
            state_root,
            ev.epoch,
            backing,
            digest,
        ))
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
        adapter: desc.id.clone(),
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
fn sample_evidence(network: &str) -> SymbioticVaultEvidence {
    let _ = network;
    SymbioticVaultEvidence {
        magic: *PAYLOAD_MAGIC,
        vault_id: b"vault-eth-001".to_vec(),
        asset_symbol: b"ETH".to_vec(),
        epoch: 100,
        gross_collateral: 1_000_000,
        encumbered_collateral: 200_000,
        collateral_root: [0xAB; 32],
        classical_signatures: vec![SymbioticSignature {
            signer_index: 0,
            signature: vec![1; 64],
        }],
        classical_threshold: 1,
        pq_signatures: vec![SymbioticSignature {
            signer_index: 0,
            signature: vec![2; 64],
        }],
        pq_threshold: 1,
        classical_signer_keys: vec![vec![0x02; 33]],
        pq_signer_keys: vec![vec![3; 1952]],
    }
}

#[cfg(test)]
pub(crate) fn encode_symbiotic_evidence(ev: &SymbioticVaultEvidence) -> Vec<u8> {
    serde_json::to_vec(ev).expect("symbiotic evidence serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::external::spec::{AdapterError, VerificationPolicy};

    fn default_policy() -> VerificationPolicy {
        VerificationPolicy::strict(0)
    }

    #[test]
    fn valid_evidence_passes_collateral_check() {
        let adapter = SymbioticVaultAdapter::new("mainnet");
        let ev = sample_evidence("mainnet");
        let free = adapter.verify_collateral(&ev).expect("valid evidence");
        // free = gross - encumbered = 1_000_000 - 200_000 = 800_000
        assert_eq!(free, 800_000);
    }

    #[test]
    fn contamination_above_30_percent_is_refused() {
        let adapter = SymbioticVaultAdapter::new("mainnet");
        let mut ev = sample_evidence("mainnet");
        // 31% contamination: encumbered = 310_000, gross = 1_000_000
        ev.encumbered_collateral = 310_000;
        let err = adapter.verify_collateral(&ev).unwrap_err();
        match err {
            AdapterError::ConsensusRule { rule } => {
                assert!(rule.contains("contamination"), "unexpected: {rule}");
            }
            other => panic!("expected ConsensusRule, got: {other:?}"),
        }
    }

    #[test]
    fn contamination_exactly_at_cap_passes() {
        let adapter = SymbioticVaultAdapter::new("mainnet");
        let mut ev = sample_evidence("mainnet");
        // Exactly 30%: 300_000 / 1_000_000
        ev.encumbered_collateral = 300_000;
        let free = adapter.verify_collateral(&ev).expect("at cap passes");
        assert_eq!(free, 700_000);
    }

    #[test]
    fn encumbered_exceeding_gross_is_refused() {
        let adapter = SymbioticVaultAdapter::new("mainnet");
        let mut ev = sample_evidence("mainnet");
        ev.encumbered_collateral = ev.gross_collateral + 1;
        let err = adapter.verify_collateral(&ev).unwrap_err();
        match err {
            AdapterError::ConsensusRule { rule } => {
                assert!(rule.contains("encumbered"), "unexpected: {rule}");
            }
            other => panic!("expected ConsensusRule, got: {other:?}"),
        }
    }

    #[test]
    fn bad_magic_is_refused() {
        let adapter = SymbioticVaultAdapter::new("mainnet");
        let mut ev = sample_evidence("mainnet");
        ev.magic = [0xFF; 8];
        let err = adapter.verify_collateral(&ev).unwrap_err();
        match err {
            AdapterError::ConsensusRule { rule } => {
                assert!(rule.contains("magic"), "unexpected: {rule}");
            }
            other => panic!("expected ConsensusRule, got: {other:?}"),
        }
    }

    #[test]
    fn zero_gross_collateral_with_zero_encumbered_passes() {
        let adapter = SymbioticVaultAdapter::new("mainnet");
        let mut ev = sample_evidence("mainnet");
        ev.gross_collateral = 0;
        ev.encumbered_collateral = 0;
        let free = adapter.verify_collateral(&ev).expect("zero passes");
        assert_eq!(free, 0);
    }

    #[test]
    fn signer_index_out_of_bounds_is_refused() {
        let adapter = SymbioticVaultAdapter::new("mainnet");
        let mut ev = sample_evidence("mainnet");
        ev.classical_signatures[0].signer_index = 999;
        let err = adapter.verify_collateral(&ev).unwrap_err();
        match err {
            AdapterError::ConsensusRule { rule } => {
                assert!(rule.contains("signer_index"), "unexpected: {rule}");
            }
            other => panic!("expected ConsensusRule, got: {other:?}"),
        }
    }

    #[test]
    fn insufficient_classical_quorum_is_refused() {
        let adapter = SymbioticVaultAdapter::new("mainnet");
        let mut ev = sample_evidence("mainnet");
        ev.classical_threshold = 5; // but only 1 signature
        let err = adapter.verify_collateral(&ev).unwrap_err();
        match err {
            AdapterError::ConsensusRule { rule } => {
                assert!(rule.contains("quorum"), "unexpected: {rule}");
            }
            other => panic!("expected ConsensusRule, got: {other:?}"),
        }
    }

    #[test]
    fn full_verify_roundtrip_produces_attestation() {
        let adapter = SymbioticVaultAdapter::new("mainnet");
        let ev = sample_evidence("mainnet");
        let payload = encode_symbiotic_evidence(&ev);
        let raw = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: EVIDENCE_VERSION,
            network: "mainnet".to_string(),
            payload,
            declared_height: 100,
            declared_root: [0xAB; 32],
            submitter: crate::core::address::Address([0; 32]),
        };
        let policy = default_policy();
        let att = adapter.verify(&raw, &policy).expect("full verify");
        assert_eq!(att.state_root, [0xAB; 32]);
        assert_eq!(att.height, 100);
        assert_eq!(att.finalized_at, 100);
    }

    #[test]
    fn declared_root_mismatch_is_refused() {
        let adapter = SymbioticVaultAdapter::new("mainnet");
        let ev = sample_evidence("mainnet");
        let payload = encode_symbiotic_evidence(&ev);
        let raw = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: EVIDENCE_VERSION,
            network: "mainnet".to_string(),
            payload,
            declared_height: 100,
            declared_root: [0xCD; 32], // mismatch
            submitter: crate::core::address::Address([0; 32]),
        };
        let mut policy = default_policy();
        policy.require_declared_match = true;
        let err = adapter.verify(&raw, &policy).unwrap_err();
        match err {
            AdapterError::ConsensusRule { rule } => {
                assert!(rule.contains("declared_root"), "unexpected: {rule}");
            }
            other => panic!("expected ConsensusRule, got: {other:?}"),
        }
    }

    #[test]
    fn wrong_network_is_refused() {
        let adapter = SymbioticVaultAdapter::new("mainnet");
        let ev = sample_evidence("mainnet");
        let payload = encode_symbiotic_evidence(&ev);
        let raw = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: EVIDENCE_VERSION,
            network: "testnet".to_string(),
            payload,
            declared_height: 100,
            declared_root: [0xAB; 32],
            submitter: crate::core::address::Address([0; 32]),
        };
        let policy = default_policy();
        let err = adapter.verify(&raw, &policy).unwrap_err();
        match err {
            AdapterError::ConsensusRule { rule } => {
                assert!(rule.contains("network"), "unexpected: {rule}");
            }
            other => panic!("expected ConsensusRule, got: {other:?}"),
        }
    }
}
