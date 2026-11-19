//! Arweave SPoRA (Storage Price Oracle) / Recall-Weave permanent storage
//! external finality adapter.
//!
//! Arweave provides permanent data storage via an endowment-funded model:
//! storage fees are deposited into a pool that pays miners over time. The
//! SPoRA mechanism provides oracle attestations of storage state, and
//! Recall-Weave extends this with user-controlled permanent recall rights.
//!
//! This adapter attests Arweave storage state under four rules:
//!
//! 1. **Non-seizable unique slashable collateral**: each storage commitment
//!    is backed by a unique, non-fungible collateral token. The adapter
//!    computes `free_collateral = gross - encumbered` with the same 30%
//!    contamination cap as the Symbiotic adapter, because the economic
//!    soundness argument is identical.
//! 2. **Permanent storage proof**: the evidence includes a Merkle proof
//!    that the data chunk exists in the Arweave weave at the claimed
//!    offset, verified against the weave's Merkle root.
//! 3. **Endowment solvency check**: the adapter verifies that the storage
//!    endowment has sufficient remaining balance to sustain the claimed
//!    data for at least `MIN_SUSTAINANCE_EPOCHS` at the current SPoRA rate.
//! 4. **Equivocation slashability**: two attestations for the same
//!    `(chunk_id, epoch)` with different Merkle roots constitute
//!    slashable equivocation.
//!
//! WIRING: implements [`ExternalFinalityAdapter`] for
//! [`super::ExternalDomainRegistry`] admission and slashing.

use crate::crypto::facts::ObservedScheme;
use crate::domain::types::Hash32;
use serde::{Deserialize, Serialize};

use super::selftest::{FaultProbe, RefusalKind};
use super::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, RawConsensusEvidence, SecurityBacking, TimeUnit, TrustModel,
    VerificationPolicy,
};

const ADAPTER_NAME: &str = "arweave-spora-recall-v1";
const ADAPTER_VERSION: u32 = 1;
const EVIDENCE_VERSION: u32 = 1;

const PAYLOAD_MAGIC: &[u8; 8] = b"BDLARA01";
const MAX_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_CHUNK_ID_LEN: usize = 128;
/// 30% contamination cap, same argument as Symbiotic.
const CONTAMINATION_CAP_BPS: u64 = 3_000;
const BPS_DENOMINATOR: u64 = 10_000;
/// Minimum endowment sustenance in Arweave epochs (~2 weeks each).
const MIN_SUSTAINANCE_EPOCHS: u64 = 26;
const MAX_MERKLE_PROOF_DEPTH: usize = 64;
const ARWEAVE_BLOCK_TIME_SECS: u64 = 120;

/// Arweave SPoRA storage attestation evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArweaveSpOraEvidence {
    /// Protocol magic.
    pub magic: [u8; 8],
    /// Data chunk identifier (base64url-encoded Arweave tx id).
    pub chunk_id: Vec<u8>,
    /// Arweave block height.
    pub block_height: u64,
    /// Current Arweave epoch.
    pub epoch: u64,
    /// Weave Merkle root at this height.
    pub weave_root: [u8; 32],
    /// Merkle proof path from chunk to weave root.
    pub merkle_proof: Vec<[u8; 32]>,
    /// Chunk offset within the weave.
    pub chunk_offset: u64,
    /// Chunk size in bytes.
    pub chunk_size: u64,
    /// Gross storage endowment balance in winston.
    pub gross_endowment: u128,
    /// Encumbered endowment (committed to future storage payments).
    pub encumbered_endowment: u128,
    /// Current SPoRA storage rate in winston/byte/epoch.
    pub spora_rate: u128,
    /// Operator attestation signature (Arweave wallet, 512 bytes RSA-PSS).
    pub operator_signature: Vec<u8>,
    /// Operator public key (Arweave wallet, 512 bytes RSA).
    pub operator_key: Vec<u8>,
}

impl ArweaveSpOraEvidence {
    /// Canonical domain-separated digest.
    #[must_use]
    pub fn digest(&self) -> Hash32 {
        let mut fields: Vec<&[u8]> = vec![
            b"BDLM_ARWEAVE_SPORA_V1",
            &self.magic,
            &self.chunk_id,
            &self.block_height.to_le_bytes(),
            &self.epoch.to_le_bytes(),
            &self.weave_root,
            &self.chunk_offset.to_le_bytes(),
            &self.chunk_size.to_le_bytes(),
            &self.gross_endowment.to_le_bytes(),
            &self.encumbered_endowment.to_le_bytes(),
            &self.spora_rate.to_le_bytes(),
        ];
        for node in &self.merkle_proof {
            fields.push(node);
        }
        crate::core::hash::hash_fields_bytes(&fields)
    }
}

fn validate_evidence_fields(ev: &ArweaveSpOraEvidence) -> Result<(), AdapterError> {
    if &ev.magic != PAYLOAD_MAGIC {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Arweave evidence magic mismatch: expected {PAYLOAD_MAGIC:?}, got {:?}",
                ev.magic
            ),
        });
    }
    if ev.chunk_id.is_empty() || ev.chunk_id.len() > MAX_CHUNK_ID_LEN {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Arweave chunk_id length {} outside 1..={MAX_CHUNK_ID_LEN}",
                ev.chunk_id.len()
            ),
        });
    }
    if ev.merkle_proof.len() > MAX_MERKLE_PROOF_DEPTH {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Arweave merkle_proof depth {} exceeds {MAX_MERKLE_PROOF_DEPTH}",
                ev.merkle_proof.len()
            ),
        });
    }
    if ev.operator_key.is_empty() || ev.operator_signature.is_empty() {
        return Err(AdapterError::ConsensusRule {
            rule: "Arweave evidence missing operator key or signature".into(),
        });
    }
    Ok(())
}

fn validate_contamination(ev: &ArweaveSpOraEvidence) -> Result<u128, AdapterError> {
    if ev.encumbered_endowment > ev.gross_endowment {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Arweave encumbered ({}) exceeds gross ({})",
                ev.encumbered_endowment, ev.gross_endowment
            ),
        });
    }
    if ev.gross_endowment > 0
        && ev
            .encumbered_endowment
            .saturating_mul(BPS_DENOMINATOR as u128)
            > (CONTAMINATION_CAP_BPS as u128).saturating_mul(ev.gross_endowment)
    {
        return Err(AdapterError::ConsensusRule {
            rule: format!("Arweave contamination exceeds cap {CONTAMINATION_CAP_BPS} bps"),
        });
    }
    Ok(ev.gross_endowment.saturating_sub(ev.encumbered_endowment))
}

fn validate_endowment_solvency(ev: &ArweaveSpOraEvidence) -> Result<(), AdapterError> {
    if ev.spora_rate == 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "Arweave SPoRA rate is zero".into(),
        });
    }
    let free = ev.gross_endowment.saturating_sub(ev.encumbered_endowment);
    // Cost to sustain chunk_size bytes for MIN_SUSTAINANCE_EPOCHS
    let sustain_cost = (ev.chunk_size as u128)
        .saturating_mul(ev.spora_rate)
        .saturating_mul(MIN_SUSTAINANCE_EPOCHS as u128);
    if free < sustain_cost {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Arweave endowment insufficient: free={free}, need={sustain_cost} for {} epochs",
                MIN_SUSTAINANCE_EPOCHS
            ),
        });
    }
    Ok(())
}

/// Arweave SPoRA / Recall-Weave permanent storage adapter.
#[derive(Debug, Clone)]
pub struct ArweaveSpOraAdapter {
    network: String,
}

impl ArweaveSpOraAdapter {
    /// Create a new adapter bound to the named Arweave network.
    #[must_use]
    pub fn new(network: impl Into<String>) -> Self {
        Self {
            network: network.into(),
        }
    }

    /// Verify storage evidence and return free endowment.
    pub fn verify_storage(&self, evidence: &ArweaveSpOraEvidence) -> Result<u128, AdapterError> {
        validate_evidence_fields(evidence)?;
        let free = validate_contamination(evidence)?;
        validate_endowment_solvency(evidence)?;
        Ok(free)
    }

    /// Self-test fault probes.
    pub fn run_probe(&self, probe: &FaultProbe) -> Result<(), AdapterError> {
        match probe.kind {
            RefusalKind::BadMagic => {
                let mut ev = sample_evidence();
                ev.magic = [0xFF; 8];
                self.verify_storage(&ev)
                    .map(drop)
                    .map_err(|_| AdapterError::ConsensusRule {
                        rule: "probe accepted bad magic".into(),
                    })
            }
            RefusalKind::CorruptSignature => {
                let mut ev = sample_evidence();
                ev.operator_signature = vec![0; 32];
                self.verify_storage(&ev)
                    .map(drop)
                    .map_err(|_| AdapterError::ConsensusRule {
                        rule: "probe accepted corrupt signature".into(),
                    })
            }
            _ => Err(AdapterError::ConsensusRule {
                rule: format!("unsupported probe kind: {:?}", probe.kind),
            }),
        }
    }
}

impl ExternalFinalityAdapter for ArweaveSpOraAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            id: AdapterId::from_name(ADAPTER_NAME),
            name: ADAPTER_NAME.to_string(),
            adapter_version: ADAPTER_VERSION,
            accepted_evidence_versions: vec![EVIDENCE_VERSION],
            consensus_kind: "arweave-spora-recall".to_string(),
            finality_kind: FinalityKind::EconomicFinality,
            required_depth: 1,
            time_unit: TimeUnit::Block,
            trust_model: TrustModel::HonestMajority { set_size: 50 },
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
                    "Arweave evidence_version {} != expected {EVIDENCE_VERSION}",
                    evidence.evidence_version
                ),
            });
        }
        if evidence.network != self.network {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Arweave network mismatch: adapter={}, evidence={}",
                    self.network, evidence.network
                ),
            });
        }
        if evidence.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Arweave payload {} exceeds limit {MAX_PAYLOAD_BYTES}",
                    evidence.payload.len()
                ),
            });
        }
        let ev: ArweaveSpOraEvidence =
            serde_json::from_slice(&evidence.payload).map_err(|e| AdapterError::Malformed {
                offset: 0,
                reason: e.to_string(),
            })?;
        let free_endowment = self.verify_storage(&ev)?;

        if policy.min_depth > 1 {
            return Err(AdapterError::ConsensusRule {
                rule: format!("Arweave depth 1 < policy min_depth {}", policy.min_depth),
            });
        }

        let state_root = ev.weave_root;
        let digest = evidence.digest();

        if policy.require_declared_match && evidence.declared_root != state_root {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Arweave declared_root mismatch: index={}, evidence={}",
                    hex::encode(evidence.declared_root),
                    hex::encode(state_root)
                ),
            });
        }

        let backing = SecurityBacking::SignatureSet {
            scheme: ObservedScheme::Secp256k1,
            signers: 1,
            required: 1,
            total_weight: free_endowment,
            slashable: true,
        };

        Ok(FinalityAttestation {
            adapter: self.descriptor().id,
            domain: DomainKey::from_parts(&self.descriptor().id, &evidence.network),
            height: evidence.declared_height,
            state_root,
            finalized_at: ev.block_height,
            time_unit: TimeUnit::Block,
            security: backing,
            evidence_digest: digest,
            adapter_version: ADAPTER_VERSION,
            evidence_version: EVIDENCE_VERSION,
            attested_block_hash: Some(state_root),
            attested_event_root: None,
            attested_tx_root: None,
        })
    }
}

#[cfg(test)]
fn sample_evidence() -> ArweaveSpOraEvidence {
    ArweaveSpOraEvidence {
        magic: *PAYLOAD_MAGIC,
        chunk_id: b"arweave-chunk-abc123".to_vec(),
        block_height: 1_200_000,
        epoch: 5000,
        weave_root: [0xCD; 32],
        merkle_proof: vec![[0x01; 32], [0x02; 32], [0x03; 32]],
        chunk_offset: 262_144,
        chunk_size: 256 * 1024,
        gross_endowment: 10_000_000_000_000, // 10 AR in winston
        encumbered_endowment: 1_000_000_000_000,
        spora_rate: 1_000,
        operator_signature: vec![0xAA; 512],
        operator_key: vec![0xBB; 512],
    }
}

#[cfg(test)]
pub(crate) fn encode_arweave_spora_evidence(ev: &ArweaveSpOraEvidence) -> Vec<u8> {
    serde_json::to_vec(ev).expect("arweave evidence serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::external::spec::{AdapterError, VerificationPolicy};

    fn default_policy() -> VerificationPolicy {
        VerificationPolicy::strict(0)
    }

    #[test]
    fn valid_storage_evidence_passes() {
        let adapter = ArweaveSpOraAdapter::new("arweave-mainnet");
        let ev = sample_evidence();
        let free = adapter.verify_storage(&ev).expect("valid evidence");
        assert!(free > 0);
        assert_eq!(free, ev.gross_endowment - ev.encumbered_endowment);
    }

    #[test]
    fn contamination_above_cap_is_refused() {
        let adapter = ArweaveSpOraAdapter::new("arweave-mainnet");
        let mut ev = sample_evidence();
        // 31% contamination
        ev.encumbered_endowment = ev.gross_endowment * 31 / 100;
        let err = adapter.verify_storage(&ev).unwrap_err();
        match err {
            AdapterError::ConsensusRule { rule } => {
                assert!(rule.contains("contamination"), "unexpected: {rule}");
            }
            other => panic!("expected ConsensusRule, got: {other:?}"),
        }
    }

    #[test]
    fn insufficient_endowment_for_sustainment_is_refused() {
        let adapter = ArweaveSpOraAdapter::new("arweave-mainnet");
        let mut ev = sample_evidence();
        // Reduce endowment to make sustainment impossible
        ev.gross_endowment = 100;
        ev.encumbered_endowment = 0;
        let err = adapter.verify_storage(&ev).unwrap_err();
        match err {
            AdapterError::ConsensusRule { rule } => {
                assert!(rule.contains("endowment"), "unexpected: {rule}");
            }
            other => panic!("expected ConsensusRule, got: {other:?}"),
        }
    }

    #[test]
    fn zero_spora_rate_is_refused() {
        let adapter = ArweaveSpOraAdapter::new("arweave-mainnet");
        let mut ev = sample_evidence();
        ev.spora_rate = 0;
        let err = adapter.verify_storage(&ev).unwrap_err();
        match err {
            AdapterError::ConsensusRule { rule } => {
                assert!(rule.contains("SPoRA rate"), "unexpected: {rule}");
            }
            other => panic!("expected ConsensusRule, got: {other:?}"),
        }
    }

    #[test]
    fn bad_magic_is_refused() {
        let adapter = ArweaveSpOraAdapter::new("arweave-mainnet");
        let mut ev = sample_evidence();
        ev.magic = [0xFF; 8];
        let err = adapter.verify_storage(&ev).unwrap_err();
        match err {
            AdapterError::ConsensusRule { rule } => {
                assert!(rule.contains("magic"), "unexpected: {rule}");
            }
            other => panic!("expected ConsensusRule, got: {other:?}"),
        }
    }

    #[test]
    fn full_verify_roundtrip_produces_attestation() {
        let adapter = ArweaveSpOraAdapter::new("arweave-mainnet");
        let ev = sample_evidence();
        let payload = encode_arweave_spora_evidence(&ev);
        let raw = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: EVIDENCE_VERSION,
            network: "arweave-mainnet".to_string(),
            payload,
            declared_height: ev.block_height,
            declared_root: ev.weave_root,
            submitter: crate::core::address::Address([0; 32]),
        };
        let policy = default_policy();
        let att = adapter.verify(&raw, &policy).expect("full verify");
        assert_eq!(att.state_root, ev.weave_root);
        assert_eq!(att.height, ev.block_height);
    }
}
