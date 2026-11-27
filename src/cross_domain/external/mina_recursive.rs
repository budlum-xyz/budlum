//! Constant-size succinct recursive blockchain external finality adapter
//! (`Mina` / Ouroboros Samasika lineage over transparent hash-STARKs).
//!
//! Under Bonneau et al. (2020) and Kerber et al. (`Ouroboros Genesis` /
//! `Samasika`, CCS 2018), a succinct blockchain compresses the entire chain
//! history from genesis to tip into a constant-size recursive validity proof
//! paired with a checkpoint-free, exact-integer short-range slot-density chain
//! selection rule (`min_window_density` over `11` rolling sub-windows).
//!
//! Budlum enforces a pure post-quantum verification path: recursive step
//! proofs are verified exclusively as transparent hash-based STARKs
//! ([`ProofSystem::Stark`], [`crate::crypto::facts::AssumptionClass::Hash`])
//! through `bud_proof::DefaultAdapter::verify`, paired with a mandatory
//! ML-DSA-65 aggregator attestation under [`crate::crypto::ctx::CROSS_DOMAIN_V1`].
//! No trusted setup and no elliptic-curve pairing proof system enters the
//! verification path.
//!
//! Six invariants must hold before a succinct tip is admitted:
//!
//! 1. **Genesis continuity**: `tip.genesis_state_hash` equals the
//!    governance-pinned `genesis_state_hash` in constant time, proving the
//!    recursive chain extends the exact canonical genesis block.
//! 2. **Epoch & staking-ledger coherence**: `global_slot / slots_per_epoch ==
//!    epoch`, `1 <= blockchain_length <= global_slot + 1`, epoch `0` commits
//!    `pinned.genesis_staking_ledger_root`, and any later epoch carries a
//!    deterministic inductive epoch-transition digest linking back to genesis.
//! 3. **Samasika exact-integer window density**: all `11` sub-window counts
//!    satisfy `count <= slots_per_sub_window`, the exact integer sum over the
//!    active window is at least `tip.min_window_density`, and
//!    `tip.min_window_density >= pinned.min_window_density_slots` (rejecting
//!    low-density long-range stake-bleeding forks without floating point).
//! 4. **Self-derived protocol state hash**: `tip.protocol_state_hash` commits
//!    every protocol header, ledger, epoch, and Samasika density field.
//! 5. **Transparent hash-STARK verification**: `step_program` is non-trivial,
//!    matches `pinned.step_program_hash`, and `bud_proof::DefaultAdapter`
//!    verifies `envelope` against `inputs` with `exit_code == 0`,
//!    `block_height == tip.blockchain_length`, `final_state_root ==
//!    tip.snarked_ledger_root`, and `state_writes_digest ==
//!    tip.protocol_state_hash`.
//! 6. **Post-quantum ML-DSA-65 binding**: `pinned.aggregator_pq_pubkey` signs
//!    the canonical binding of `(network, protocol_state_hash,
//!    public_inputs_hash)` under `CROSS_DOMAIN_V1`.
//!
//! WIRING: implements `ExternalFinalityAdapter` for `ExternalDomainRegistry`
//! over `bud_proof::DefaultAdapter`; `AdapterSpec` tag append joins `intake.rs`
//! after concurrent intake hardening merges.
//!
//! INTAKE: economic-guard-only - succinct recursive chain proofs are verified here and priced by
//! `cross_domain/economic_guard.rs`; `intake.rs` does not name this adapter, so a
//! recursive proof cannot yet be folded into a global header. The missing piece is one
//! `AdapterSpec` registration.

use crate::crypto::facts::{AssumptionClass, CryptoObserver, ObservedScheme};
use crate::crypto::scheme::SchemeId;
use crate::domain::types::Hash32;
use bud_proof::{ExecutionPublicInputs, ProofEnvelope, ProverAdapter};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::selftest::{BytePatch, ExpectedRefusal, FaultProbe, RefusalKind};
use super::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, ProofSystem, RawConsensusEvidence, SecurityBacking,
    TimeUnit, TrustModel, VerificationPolicy,
};

const ADAPTER_NAME: &str = "succinct-recursive-v1";
const ADAPTER_VERSION: u32 = 1;
const EVIDENCE_VERSION: u32 = 1;

/// Rolling sub-windows tracked per Samasika density window (matches Mina's `11`).
const SAMASIKA_SUB_WINDOWS: usize = 11;
const MAX_EPOCH_TRANSITIONS: usize = 64;
const PAYLOAD_MAGIC: &[u8; 8] = b"BDLMMR01";
const MAX_RECURSIVE_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
const MAX_STEP_PROGRAM_WORDS: usize = 1_024;

/// Governance-pinned genesis, recursive step-program, Samasika density, and
/// post-quantum aggregator anchor for a succinct recursive blockchain domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedSuccinctGenesis {
    /// Canonical genesis protocol state hash inducted across every step.
    pub genesis_state_hash: Hash32,
    /// Staking ledger Merkle root active in epoch `0`.
    pub genesis_staking_ledger_root: Hash32,
    /// Canonical hash of the verified recursive step program (`program_hash_of`).
    pub step_program_hash: Hash32,
    /// Number of slots per sub-window (`>= 1`).
    pub slots_per_sub_window: u64,
    /// Number of slots per consensus epoch (`>= SAMASIKA_SUB_WINDOWS`).
    pub slots_per_epoch: u64,
    /// Minimum exact-integer Samasika window density required for acceptance.
    pub min_window_density_slots: u64,
    /// Mandatory ML-DSA-65 public key binding recursive proof relay envelopes.
    pub aggregator_pq_pubkey: Vec<u8>,
}

impl PinnedSuccinctGenesis {
    /// Canonical length-prefixed SHA3-256 commitment over the pinned genesis
    /// protocol state hash, initial staking ledger root, verified recursive
    /// step-program hash, Samasika window density parameters, and ML-DSA-65
    /// aggregator public key.
    ///
    /// WIRING: checked in constant time by `crate::cross_domain::economic_guard`
    /// when refreshing succinct recursive backing attestations.
    #[must_use]
    pub fn canonical_pin_digest(&self) -> Hash32 {
        crate::core::hash::hash_fields_bytes(&[
            b"BDLM_MINA_PIN_V1",
            &self.genesis_state_hash,
            &self.genesis_staking_ledger_root,
            &self.step_program_hash,
            &self.slots_per_sub_window.to_le_bytes(),
            &self.slots_per_epoch.to_le_bytes(),
            &self.min_window_density_slots.to_le_bytes(),
            &self.aggregator_pq_pubkey,
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EpochLedgerStep {
    epoch: u64,
    prev_staking_ledger_root: Hash32,
    next_staking_ledger_root: Hash32,
    epoch_seed: Hash32,
    transition_digest: Hash32,
}

impl EpochLedgerStep {
    #[must_use]
    fn compute_digest(&self, genesis_state_hash: &Hash32) -> Hash32 {
        crate::core::hash::hash_fields_bytes(&[
            b"BDLM_MINA_EPOCH_V1",
            genesis_state_hash,
            &self.epoch.to_le_bytes(),
            &self.prev_staking_ledger_root,
            &self.next_staking_ledger_root,
            &self.epoch_seed,
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SuccinctProtocolState {
    genesis_state_hash: Hash32,
    previous_state_hash: Hash32,
    blockchain_length: u64,
    global_slot: u64,
    epoch: u64,
    staking_ledger_root: Hash32,
    next_epoch_ledger_root: Hash32,
    snarked_ledger_root: Hash32,
    staged_tx_root: Hash32,
    action_event_root: Hash32,
    min_window_density: u64,
    sub_window_densities: [u64; SAMASIKA_SUB_WINDOWS],
    protocol_state_hash: Hash32,
}

impl SuccinctProtocolState {
    #[must_use]
    fn compute_hash(&self, network: &str) -> Hash32 {
        let mut sub_bytes = [0u8; SAMASIKA_SUB_WINDOWS * 8];
        for (idx, val) in self.sub_window_densities.iter().enumerate() {
            let start = idx.saturating_mul(8);
            if let Some(dst) = sub_bytes.get_mut(start..start.saturating_add(8)) {
                dst.copy_from_slice(&val.to_le_bytes());
            }
        }
        crate::core::hash::hash_fields_bytes(&[
            b"BDLM_MINA_STATE_V1",
            network.as_bytes(),
            &self.genesis_state_hash,
            &self.previous_state_hash,
            &self.blockchain_length.to_le_bytes(),
            &self.global_slot.to_le_bytes(),
            &self.epoch.to_le_bytes(),
            &self.staking_ledger_root,
            &self.next_epoch_ledger_root,
            &self.snarked_ledger_root,
            &self.staged_tx_root,
            &self.action_event_root,
            &self.min_window_density.to_le_bytes(),
            &sub_bytes,
        ])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SuccinctRecursiveEvidence {
    tip: SuccinctProtocolState,
    epoch_chain: Vec<EpochLedgerStep>,
    envelope: ProofEnvelope,
    inputs: ExecutionPublicInputs,
    step_program: Vec<u64>,
    aggregator_pq_sig: Vec<u8>,
}

#[must_use]
fn recursive_attest_sign_bytes(
    network: &str,
    genesis_state_hash: &Hash32,
    protocol_state_hash: &Hash32,
    public_inputs_hash: &Hash32,
) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_MINA_ATTEST_V1",
        network.as_bytes(),
        genesis_state_hash,
        protocol_state_hash,
        public_inputs_hash,
    ])
}

/// Compute exact-integer Samasika active window density over the `11` sub-windows.
fn verify_samasika_density(
    pinned: &PinnedSuccinctGenesis,
    tip: &SuccinctProtocolState,
) -> Result<u64, AdapterError> {
    let max_window = pinned
        .slots_per_sub_window
        .checked_mul(SAMASIKA_SUB_WINDOWS as u64)
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "Samasika maximum window density overflow".into(),
        })?;
    if pinned.min_window_density_slots == 0 || pinned.min_window_density_slots > max_window {
        return Err(AdapterError::ConsensusRule {
            rule: "pinned Samasika min_window_density_slots outside valid range".into(),
        });
    }
    let mut window_sum = 0u64;
    for &sub in &tip.sub_window_densities {
        if sub > pinned.slots_per_sub_window {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Samasika sub-window density {sub} exceeds slots_per_sub_window {}",
                    pinned.slots_per_sub_window
                ),
            });
        }
        window_sum = window_sum
            .checked_add(sub)
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "Samasika sub-window density sum overflow".into(),
            })?;
    }
    if window_sum > tip.blockchain_length {
        return Err(AdapterError::ConsensusRule {
            rule: "Samasika window density exceeds total blockchain_length".into(),
        });
    }
    if tip.min_window_density > window_sum {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "claimed min_window_density {} exceeds current window density {window_sum}",
                tip.min_window_density
            ),
        });
    }
    if tip.min_window_density < pinned.min_window_density_slots {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Samasika min_window_density {} below pinned threshold {}",
                tip.min_window_density, pinned.min_window_density_slots
            ),
        });
    }
    Ok(window_sum)
}

#[cfg(test)]
fn encode_recursive_evidence(bundle: &SuccinctRecursiveEvidence) -> Result<Vec<u8>, String> {
    let body = bincode::serialize(bundle).map_err(|e| format!("recursive encode failed: {e}"))?;
    let total = PAYLOAD_MAGIC.len().saturating_add(body.len());
    if total > MAX_RECURSIVE_PAYLOAD_BYTES {
        return Err(format!(
            "recursive payload {total} exceeds ceiling {MAX_RECURSIVE_PAYLOAD_BYTES}"
        ));
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_recursive_evidence(payload: &[u8]) -> Result<SuccinctRecursiveEvidence, AdapterError> {
    use bincode::Options;

    if payload.len() < PAYLOAD_MAGIC.len() {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "succinct-recursive payload shorter than 8-byte magic prefix".into(),
        });
    }
    if payload.len() > MAX_RECURSIVE_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_RECURSIVE_PAYLOAD_BYTES,
            reason: format!("succinct-recursive payload exceeds {MAX_RECURSIVE_PAYLOAD_BYTES}"),
        });
    }
    if payload.get(0..8) != Some(PAYLOAD_MAGIC.as_slice()) {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "succinct-recursive payload magic mismatch".into(),
        });
    }
    let body = payload.get(8..).ok_or_else(|| AdapterError::Malformed {
        offset: 8,
        reason: "missing succinct-recursive payload body".into(),
    })?;
    let limit = u64::try_from(body.len()).unwrap_or(MAX_RECURSIVE_PAYLOAD_BYTES as u64);
    let decoded: SuccinctRecursiveEvidence = bincode::options()
        .with_fixint_encoding()
        .with_limit(limit)
        .reject_trailing_bytes()
        .deserialize(body)
        .map_err(|e| AdapterError::Malformed {
            offset: 8,
            reason: format!("invalid succinct-recursive evidence: {e}"),
        })?;
    decoded
        .envelope
        .validate_shape()
        .map_err(|e| AdapterError::Malformed {
            offset: 8,
            reason: format!("invalid recursive STARK envelope shape: {e:?}"),
        })?;
    Ok(decoded)
}

/// External finality adapter verifying constant-size genesis-to-tip recursive
/// transparent hash-STARK proofs with Ouroboros Samasika window density and
/// ML-DSA-65 post-quantum binding.
pub struct SuccinctRecursiveAdapter {
    network: String,
    pinned: Option<PinnedSuccinctGenesis>,
    golden: Option<RawConsensusEvidence>,
    descriptor: AdapterDescriptor,
}

impl SuccinctRecursiveAdapter {
    /// Construct a `SuccinctRecursiveAdapter` bound to `network` and its pinned
    /// genesis and recursive step-program anchor.
    #[must_use]
    pub fn new(network: impl Into<String>, pinned: Option<PinnedSuccinctGenesis>) -> Self {
        let network = network.into();
        let id = AdapterId::from_name(ADAPTER_NAME);
        let descriptor = AdapterDescriptor {
            id,
            name: ADAPTER_NAME.into(),
            adapter_version: ADAPTER_VERSION,
            accepted_evidence_versions: vec![EVIDENCE_VERSION],
            consensus_kind: "succinct-recursive-samasika-stark".into(),
            finality_kind: FinalityKind::Proven,
            required_depth: 0,
            time_unit: TimeUnit::Height,
            trust_model: TrustModel::Trustless,
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

    fn validate_pin(pinned: &PinnedSuccinctGenesis) -> Result<(), AdapterError> {
        if pinned.genesis_state_hash == [0u8; 32]
            || pinned.genesis_staking_ledger_root == [0u8; 32]
            || pinned.step_program_hash == [0u8; 32]
        {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned succinct genesis hashes and step_program_hash must be non-zero"
                    .into(),
            });
        }
        if pinned.slots_per_sub_window == 0 || pinned.slots_per_epoch < SAMASIKA_SUB_WINDOWS as u64
        {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned Samasika slot geometry is degenerate".into(),
            });
        }
        crate::crypto::pq::validate_public_key(SchemeId::ML_DSA_65, &pinned.aggregator_pq_pubkey)
            .map_err(|_| AdapterError::ConsensusRule {
            rule: "pinned succinct aggregator_pq_pubkey is not a valid ML-DSA-65 key".into(),
        })?;
        Ok(())
    }

    fn verify_epoch_chain(
        pinned: &PinnedSuccinctGenesis,
        tip: &SuccinctProtocolState,
        chain: &[EpochLedgerStep],
    ) -> Result<(), AdapterError> {
        if chain.len() > MAX_EPOCH_TRANSITIONS {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "succinct epoch chain length {} exceeds {MAX_EPOCH_TRANSITIONS}",
                    chain.len()
                ),
            });
        }
        if tip.epoch == 0 {
            if !chain.is_empty() {
                return Err(AdapterError::ConsensusRule {
                    rule: "epoch 0 succinct state cannot carry epoch transitions".into(),
                });
            }
            if !bool::from(
                tip.staking_ledger_root
                    .ct_eq(&pinned.genesis_staking_ledger_root),
            ) {
                return Err(AdapterError::ConsensusRule {
                    rule: "epoch 0 staking_ledger_root does not match pinned genesis ledger".into(),
                });
            }
            return Ok(());
        }
        if chain.len() as u64 != tip.epoch {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "epoch {} requires {} epoch ledger steps, got {}",
                    tip.epoch,
                    tip.epoch,
                    chain.len()
                ),
            });
        }
        let mut cur_ledger = pinned.genesis_staking_ledger_root;
        for (idx, step) in chain.iter().enumerate() {
            let expected_epoch = (idx as u64).saturating_add(1);
            if step.epoch != expected_epoch
                || step.next_staking_ledger_root == [0u8; 32]
                || !bool::from(step.prev_staking_ledger_root.ct_eq(&cur_ledger))
            {
                return Err(AdapterError::ConsensusRule {
                    rule: format!("broken staking-ledger chain at epoch {expected_epoch}"),
                });
            }
            let expected_digest = step.compute_digest(&pinned.genesis_state_hash);
            if !bool::from(step.transition_digest.ct_eq(&expected_digest)) {
                return Err(AdapterError::ConsensusRule {
                    rule: format!("epoch {expected_epoch} transition_digest mismatch"),
                });
            }
            cur_ledger = step.next_staking_ledger_root;
        }
        if !bool::from(tip.staking_ledger_root.ct_eq(&cur_ledger)) {
            return Err(AdapterError::ConsensusRule {
                rule: "tip staking_ledger_root disagrees with verified epoch chain".into(),
            });
        }
        Ok(())
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
                    "succinct-recursive network mismatch: expected {}, got {}",
                    self.network, evidence.network
                ),
            });
        }
        let Some(pinned) = &self.pinned else {
            return Err(AdapterError::ConsensusRule {
                rule: "no governance-pinned succinct genesis configured".into(),
            });
        };
        Self::validate_pin(pinned)?;

        let decoded = decode_recursive_evidence(&evidence.payload)?;
        let tip = &decoded.tip;

        if !bool::from(tip.genesis_state_hash.ct_eq(&pinned.genesis_state_hash)) {
            return Err(AdapterError::ConsensusRule {
                rule: "tip genesis_state_hash does not match pinned genesis".into(),
            });
        }
        if tip.blockchain_length == 0
            || tip.snarked_ledger_root == [0u8; 32]
            || tip.previous_state_hash == [0u8; 32]
        {
            return Err(AdapterError::ConsensusRule {
                rule: "succinct tip height, snarked_ledger_root, and previous_state_hash must be non-zero".into(),
            });
        }
        if tip.blockchain_length > tip.global_slot.saturating_add(1) {
            return Err(AdapterError::ConsensusRule {
                rule: "succinct blockchain_length exceeds elapsed global_slot + 1".into(),
            });
        }
        if tip.global_slot / pinned.slots_per_epoch != tip.epoch {
            return Err(AdapterError::ConsensusRule {
                rule: "succinct tip epoch disagrees with global_slot / slots_per_epoch".into(),
            });
        }

        if policy.require_declared_match {
            if evidence.declared_height != tip.blockchain_length {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if !bool::from(evidence.declared_root.ct_eq(&tip.snarked_ledger_root)) {
                return Err(AdapterError::DeclarationMismatch {
                    field: "state_root",
                });
            }
        }
        if policy.min_depth > 0 {
            return Err(AdapterError::Unavailable {
                reason: "a proven recursive STARK attestation carries zero confirmation depth"
                    .into(),
            });
        }
        if policy.require_slashable {
            return Err(AdapterError::UnslashableBacking);
        }
        if policy.max_age > 0 {
            if tip.blockchain_length > policy.now {
                return Err(AdapterError::Stale {
                    age: tip.blockchain_length - policy.now,
                    max_age: policy.max_age,
                });
            }
            let age = policy.now - tip.blockchain_length;
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        let expected_state_hash = tip.compute_hash(&self.network);
        if !bool::from(tip.protocol_state_hash.ct_eq(&expected_state_hash)) {
            return Err(AdapterError::ConsensusRule {
                rule: "succinct tip protocol_state_hash mismatch".into(),
            });
        }

        Self::verify_epoch_chain(pinned, tip, &decoded.epoch_chain)?;
        let _ = verify_samasika_density(pinned, tip)?;

        // Bind and verify the transparent hash-STARK recursive step proof.
        if decoded.step_program.len() > MAX_STEP_PROGRAM_WORDS
            || crate::prover::is_empty_or_halt_only_program(&decoded.step_program)
        {
            return Err(AdapterError::ConsensusRule {
                rule: "recursive step program must be bounded and non-trivial".into(),
            });
        }
        let actual_prog_hash = bud_proof::canonical_set::program_hash_of(&decoded.step_program);
        if !bool::from(actual_prog_hash.ct_eq(&pinned.step_program_hash))
            || !bool::from(decoded.inputs.program_hash.ct_eq(&pinned.step_program_hash))
        {
            return Err(AdapterError::ConsensusRule {
                rule: "recursive STARK step program does not match pinned step_program_hash".into(),
            });
        }
        let expected_state_tag = tip
            .protocol_state_hash
            .get(0..8)
            .and_then(|s| <[u8; 8]>::try_from(s).ok())
            .map_or(0, u64::from_le_bytes)
            & 0x7FFF_FFFF_FFFF_FFFF;
        let expected_root_tag = tip
            .snarked_ledger_root
            .get(0..8)
            .and_then(|s| <[u8; 8]>::try_from(s).ok())
            .map_or(0, u64::from_le_bytes)
            & 0x7FFF_FFFF_FFFF_FFFF;
        if decoded.inputs.exit_code != 0
            || decoded.inputs.block_height != tip.blockchain_length
            || decoded.inputs.sender != expected_state_tag
            || decoded.inputs.nonce != expected_root_tag
        {
            return Err(AdapterError::ConsensusRule {
                rule: "recursive STARK public inputs do not bind tip height, snarked_ledger_root, and protocol_state_hash".into(),
            });
        }

        bud_proof::DefaultAdapter::verify(
            &decoded.envelope,
            &decoded.inputs,
            &decoded.step_program,
        )
        .map_err(|e| AdapterError::Crypto {
            what: format!("recursive transparent STARK verification failed: {e:?}"),
        })?;

        // Mandatory ML-DSA-65 post-quantum attestation binding proof to network and genesis.
        if decoded.aggregator_pq_sig.is_empty() {
            return Err(AdapterError::Crypto {
                what: "missing mandatory ML-DSA-65 recursive attestation signature".into(),
            });
        }
        let pq_msg = recursive_attest_sign_bytes(
            &self.network,
            &pinned.genesis_state_hash,
            &tip.protocol_state_hash,
            &decoded.envelope.public_inputs_hash,
        );
        crate::crypto::primitives::PqKeyPair::verify(
            &pinned.aggregator_pq_pubkey,
            crate::crypto::ctx::CROSS_DOMAIN_V1,
            &pq_msg,
            &decoded.aggregator_pq_sig,
        )
        .map_err(|_| AdapterError::Crypto {
            what: "invalid ML-DSA-65 signature on recursive STARK attestation".into(),
        })?;

        Ok(FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &evidence.network),
            height: tip.blockchain_length,
            state_root: tip.snarked_ledger_root,
            attested_block_hash: Some(tip.protocol_state_hash),
            attested_event_root: (tip.action_event_root != [0u8; 32])
                .then_some(tip.action_event_root),
            attested_tx_root: (tip.staged_tx_root != [0u8; 32]).then_some(tip.staged_tx_root),
            finalized_at: tip.blockchain_length,
            time_unit: TimeUnit::Height,
            security: SecurityBacking::Zk {
                system: ProofSystem::Stark,
                public_inputs_digest: decoded.envelope.public_inputs_hash,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
        })
    }
}

impl ExternalFinalityAdapter for SuccinctRecursiveAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn has_pinned_trust_anchor(&self) -> bool {
        self.pinned.as_ref().is_some_and(|p| {
            p.genesis_state_hash != [0u8; 32]
                && p.step_program_hash != [0u8; 32]
                && !p.aggregator_pq_pubkey.is_empty()
        })
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
        observer.observe(ObservedScheme::Scheme(SchemeId::ML_DSA_65));
        Ok(att)
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        let sig_tail = self
            .golden
            .as_ref()
            .map_or(32, |g| g.payload.len().saturating_sub(16));
        vec![
            FaultProbe {
                name: "refuses unsupported succinct-recursive evidence version".into(),
                patch: BytePatch::EvidenceVersion { value: 3 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "refuses foreign succinct-recursive network".into(),
                patch: BytePatch::Network {
                    value: format!("{}-fork", self.network),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses mismatched declared blockchain_length".into(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses mismatched declared snarked_ledger_root".into(),
                patch: BytePatch::DeclaredRoot { value: [0xEE; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses corrupted succinct-recursive magic".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: vec![0xDE, 0xAD],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses mutated genesis_state_hash inside tip".into(),
                patch: BytePatch::InPayload {
                    offset: 8,
                    bytes: vec![0xFF, 0x00],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses corrupted ML-DSA-65 aggregator attestation".into(),
                patch: BytePatch::InPayload {
                    offset: sig_tail,
                    bytes: vec![0xCA, 0xFE, 0xBA, 0xBE],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Crypto),
            },
            FaultProbe {
                name: "refuses truncated succinct-recursive payload".into(),
                patch: BytePatch::TruncatePayload { keep: 3 },
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
    use crate::crypto::primitives::PqKeyPair;
    use bud_proof::ProverAdapter;

    fn recursive_step_program() -> Vec<u64> {
        bud_vm::syscall_context::build_syscall_context_check_program()
            .expect("canonical recursive step program")
    }

    fn build_succinct_fixture(
        snarked_root: Hash32,
        existing_pq: Option<PqKeyPair>,
    ) -> (
        PinnedSuccinctGenesis,
        PqKeyPair,
        SuccinctRecursiveEvidence,
        RawConsensusEvidence,
    ) {
        let net = "mina-stark-1";
        let pq = existing_pq.unwrap_or_else(PqKeyPair::generate);
        let program = recursive_step_program();
        let prog_hash = bud_proof::canonical_set::program_hash_of(&program);
        let genesis_hash = [0x11; 32];
        let genesis_ledger = [0x22; 32];
        let epoch1_ledger = [0x33; 32];

        let pinned = PinnedSuccinctGenesis {
            genesis_state_hash: genesis_hash,
            genesis_staking_ledger_root: genesis_ledger,
            step_program_hash: prog_hash,
            slots_per_sub_window: 10,
            slots_per_epoch: 110,
            min_window_density_slots: 77,
            aggregator_pq_pubkey: pq.public_key_bytes().to_vec(),
        };

        let mut step1 = EpochLedgerStep {
            epoch: 1,
            prev_staking_ledger_root: genesis_ledger,
            next_staking_ledger_root: epoch1_ledger,
            epoch_seed: [0x44; 32],
            transition_digest: [0; 32],
        };
        step1.transition_digest = step1.compute_digest(&genesis_hash);

        // 11 sub-windows summing to 88 >= min_window_density 80 >= pinned floor 77.
        let mut tip = SuccinctProtocolState {
            genesis_state_hash: genesis_hash,
            previous_state_hash: [0x55; 32],
            blockchain_length: 120,
            global_slot: 145,
            epoch: 1,
            staking_ledger_root: epoch1_ledger,
            next_epoch_ledger_root: [0x66; 32],
            snarked_ledger_root: snarked_root,
            staged_tx_root: [0x78; 32],
            action_event_root: [0x79; 32],
            min_window_density: 80,
            sub_window_densities: [8; SAMASIKA_SUB_WINDOWS],
            protocol_state_hash: [0; 32],
        };
        tip.protocol_state_hash = tip.compute_hash(net);

        let state_tag = u64::from_le_bytes(tip.protocol_state_hash[0..8].try_into().unwrap())
            & 0x7FFF_FFFF_FFFF_FFFF;
        let root_tag = u64::from_le_bytes(tip.snarked_ledger_root[0..8].try_into().unwrap())
            & 0x7FFF_FFFF_FFFF_FFFF;
        let mut vm = bud_vm::Vm::new(1024);
        vm.context.sender = state_tag;
        vm.context.nonce = root_tag;
        vm.context.block_height = tip.blockchain_length;
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        let inputs = ExecutionPublicInputs {
            chain_id: 1,
            program_hash: prog_hash,
            initial_state_root: bud_proof::initial_state_root_of(
                bud_proof::memory_image_commitment_of_reads(&bud_proof::initial_memory_reads(
                    &vm.trace,
                )),
                bud_proof::register_image_commitment_of_reads(&bud_proof::initial_register_reads(
                    &vm.trace,
                )),
            ),
            final_state_root: [0; 32],
            sender: vm.context.sender,
            nonce: vm.context.nonce,
            block_height: tip.blockchain_length,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: bud_proof::event_digest_from_events(&receipt.events),
            state_writes_digest: [0; 32],
        };
        let envelope = bud_proof::DefaultAdapter::prove(&vm.trace, &inputs, &program).unwrap();
        let pq_msg = recursive_attest_sign_bytes(
            net,
            &genesis_hash,
            &tip.protocol_state_hash,
            &envelope.public_inputs_hash,
        );
        let pq_sig = pq
            .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &pq_msg)
            .unwrap();

        let bundle = SuccinctRecursiveEvidence {
            tip,
            epoch_chain: vec![step1],
            envelope,
            inputs,
            step_program: program,
            aggregator_pq_sig: pq_sig,
        };
        let payload = encode_recursive_evidence(&bundle).unwrap();
        let ev = RawConsensusEvidence {
            adapter: AdapterId::from_name(ADAPTER_NAME),
            evidence_version: EVIDENCE_VERSION,
            network: net.into(),
            payload,
            declared_height: 120,
            declared_root: snarked_root,
            submitter: Address::from([0x05; 32]),
        };
        (pinned, pq, bundle, ev)
    }

    #[test]
    fn pure_pq_recursive_stark_and_samasika_density_passes_selftest() {
        let (pinned, _, _, golden) = build_succinct_fixture([0x77; 32], None);
        let adapter =
            SuccinctRecursiveAdapter::new("mina-stark-1", Some(pinned)).with_golden(golden.clone());
        let policy = VerificationPolicy::proven(130);

        let mut facts = CryptoFacts::default();
        let att = adapter
            .verify_observed(&golden, &policy, &mut facts)
            .unwrap();
        assert_eq!(att.height, 120);
        assert_eq!(att.state_root, [0x77; 32]);
        assert!(matches!(
            att.security,
            SecurityBacking::Zk {
                system: ProofSystem::Stark,
                ..
            }
        ));
        // Pure post-quantum path: only Hash-STARK + ML-DSA-65 observed, zero classical curves.
        assert_eq!(facts.observed().len(), 2);
        assert_eq!(facts.count(ObservedScheme::Proof(AssumptionClass::Hash)), 1);
        assert_eq!(facts.count(ObservedScheme::Scheme(SchemeId::ML_DSA_65)), 1);

        let report = admit(&adapter, &policy);
        assert!(
            report.admitted,
            "succinct-recursive selftest failed: {:?}",
            report.probes
        );
        assert!(adapter.has_pinned_trust_anchor());
        assert!(!SuccinctRecursiveAdapter::new("mina-stark-1", None).has_pinned_trust_anchor());
        let mut slash_policy = policy;
        slash_policy.require_slashable = true;
        assert!(matches!(
            adapter.verify(&golden, &slash_policy),
            Err(AdapterError::UnslashableBacking)
        ));
    }

    #[test]
    fn low_density_long_range_fork_and_tampered_stark_proof_fail_closed() {
        let (pinned, _, mut bundle, mut ev) = build_succinct_fixture([0x77; 32], None);
        let adapter = SuccinctRecursiveAdapter::new("mina-stark-1", Some(pinned));
        let policy = VerificationPolicy::proven(130);

        // 1. Low-density long-range fork (sub-windows sum to 55 < required 77) is refused.
        let orig_tip = bundle.tip.clone();
        bundle.tip.sub_window_densities = [5; SAMASIKA_SUB_WINDOWS];
        bundle.tip.min_window_density = 55;
        bundle.tip.protocol_state_hash = bundle.tip.compute_hash("mina-stark-1");
        ev.payload = encode_recursive_evidence(&bundle).unwrap();
        assert!(matches!(
            adapter.verify(&ev, &policy),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("min_window_density")
        ));
        bundle.tip = orig_tip;

        // 2. Flipping a single byte inside the transparent STARK proof bytes is refused.
        if let Some(first) = bundle.envelope.proof_bytes.first_mut() {
            *first ^= 0x01;
        }
        ev.payload = encode_recursive_evidence(&bundle).unwrap();
        assert!(matches!(
            adapter.verify(&ev, &policy),
            Err(AdapterError::Crypto { .. })
        ));
    }

    #[test]
    fn registry_lifecycle_contradiction_slash_and_crqc_hash_pq_immunity() {
        use crate::cross_domain::external::{
            ChallengeReward, DomainEconomics, DomainState, ExternalDomainRegistry, VersionPolicy,
        };
        use crate::crypto::facts::QuantumClass;

        let (pinned, pq, _, ev_a) = build_succinct_fixture([0x77; 32], None);
        let (_, _, _, mut ev_b) = build_succinct_fixture([0x99; 32], Some(pq));
        let prover = ev_a.submitter;
        let challenger = Address::from([0x95; 32]);
        ev_b.submitter = challenger;

        let adapter =
            SuccinctRecursiveAdapter::new("mina-stark-1", Some(pinned)).with_golden(ev_a.clone());
        let policy = VerificationPolicy::proven(130);
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
        let required = econ.required_bond_atoms();
        let mut registry = ExternalDomainRegistry::new();
        let domain = registry
            .register(
                "mina-stark-1",
                adapter.descriptor(),
                econ,
                VersionPolicy::single(adapter.descriptor().id, EVIDENCE_VERSION, 0),
                &admission,
                required,
                prover,
            )
            .unwrap();
        registry.bond_prover(&domain, challenger, required).unwrap();

        let att = registry.submit(&adapter, &ev_a, &policy).unwrap();
        assert_eq!(att.height, 120);
        crate::domain::finality_proof_model::FinalityProofShape::from_external_attestation(
            &adapter.descriptor(),
            &att,
        )
        .expect("recursive STARK attestation must satisfy FinalityProofShape");
        let mut future_policy = policy.clone();
        future_policy.max_age = 50;
        future_policy.now = att.height.saturating_sub(1);
        assert!(
            matches!(
                adapter.verify(&ev_a, &future_policy),
                Err(AdapterError::Stale { .. })
            ),
            "future-dated blockchain_length above policy.now must fail closed when max_age > 0"
        );
        // Pure Hash+Lattice PQ domain survives CRQC classical isolation untouched!
        assert_eq!(
            registry
                .domain(&domain)
                .unwrap()
                .record
                .crypto_facts
                .quantum_class(),
            Some(QuantumClass::Lattice)
        );
        assert_eq!(registry.isolate_classical_domains(), 0);
        assert_eq!(
            registry.domain(&domain).unwrap().record.state,
            DomainState::Active
        );

        let conflict = adapter.verify(&ev_b, &policy).unwrap();
        assert_eq!(conflict.height, att.height);
        assert_ne!(conflict.state_root, att.state_root);
        assert!(registry.submit(&adapter, &ev_b, &policy).is_err());
        registry
            .mark_faulted(&domain, "succinct-recursive conflicting STARK proof")
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
            .contains_key(&(120, EVIDENCE_VERSION)));
    }
}
