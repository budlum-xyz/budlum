//! Adaptive escrow ceiling and permissionless prover-contradiction slashing
//! guard for cross-domain bridge value flows.
//!
//! Historical bridge drains occur when a bridge permits net outflow or minting
//! `V` within one settlement window that exceeds the verifiable economic cost
//! `S_effective` of corrupting the external source domain (`V > S_effective`).
//! [`BridgeEconomicGuard`] enforces three consensus-deterministic invariants
//! using pure integer arithmetic (`u128`):
//!
//! 1. **Backing-derived window ceiling ([`effective_ceiling_atoms`])**:
//!    - [`SecurityBacking::None`] and unbonded [`SecurityBacking::Authority`]
//!      yield **zero** (`0` atoms) unconditionally.
//!    - Slashable [`SecurityBacking::SignatureSet`] is divided by
//!      `max(1, shared_consumer_count)` (over-leverage haircut) and scaled by
//!      `stake_haircut_bps / 10_000` (default `3_333` bps, matching the `1/3`
//!      Byzantine corruption lower bound).
//!    - Unslashable [`SecurityBacking::SignatureSet`] (such as Ethereum Altair
//!      sync committees), [`SecurityBacking::Work`], and [`SecurityBacking::Zk`]
//!      never earn validator-stake credit; they are strictly bounded by
//!      declared protocol caps and/or slashable [`ProverBond`] collateral
//!      scaled by `bond_haircut_bps / 10_000`.
//! 2. **Rolling height-window flow bound ([`BridgeEconomicGuard::check_and_record_flow`])**:
//!    for each configured domain and window `height / window_blocks`,
//!    `window_used_atoms + amount_atoms <= effective_ceiling_atoms` is verified
//!    before any state mutation. Domains without an explicit policy stay open
//!    so internal native domains continue unimpeded, while any configured
//!    external domain fails closed on overflow, zero ceiling, or freeze.
//! 3. **Admin-keyless contradiction breaker & prover slashing
//!    ([`BridgeEconomicGuard::submit_contradiction`])**: accepts either a
//!    hybrid-signed dual-root statement or verified protocol-level slashing
//!    evidence from [`RestakingAvsAdapter`], [`AuxPowPopAdapter`], or
//!    [`SimplexBftAdapter`], atomically freezes the domain in
//!    [`DomainGuardStatus::FrozenByContradiction`], rejects evidence replay,
//!    and invokes [`ProverBond::slash`] to cut the bonded prover and compute
//!    the challenger reward.

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::external::auxpow_pop::{
    verify_pop_equivocation, AuxPowPopAdapter, PinnedAuxPowAnchor, PopEquivocationProof,
};
use crate::cross_domain::external::prover::{ProverBond, Slashing, BPS_DEN};
use crate::cross_domain::external::restaking_avs::{
    verify_restaking_slashing, PinnedRestakingAvsSet, RestakingAvsAdapter, RestakingSlashingProof,
};
use crate::cross_domain::external::simplex_bft::{
    verify_simplex_slashing, PinnedSimplexCommittee, SimplexBftAdapter, SimplexSlashingProof,
};
use crate::cross_domain::external::spec::{
    ExternalFinalityAdapter, FinalityAttestation, RawConsensusEvidence, SecurityBacking,
    VerificationPolicy,
};
use crate::crypto::facts::AssumptionClass;
use crate::crypto::pq;
use crate::crypto::primitives::verify_signature;
use crate::crypto::scheme::SchemeId;
use crate::domain::types::{DomainId, Hash32};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use subtle::ConstantTimeEq;

/// Default Byzantine corruption haircut on slashable validator stake (`33.33%`).
///
/// WIRING: default protocol constant for [`DomainCeilingPolicy`].
pub const DEFAULT_STAKE_HAIRCUT_BPS: u64 = 3_333;
/// Default haircut on directly slashable prover bond collateral (`90.00%`).
///
/// WIRING: default protocol constant for [`DomainCeilingPolicy`].
pub const DEFAULT_BOND_HAIRCUT_BPS: u64 = 9_000;
/// Default challenger reward fraction taken out of a slashed prover bond (`10.00%`).
///
/// WIRING: default protocol constant for [`DomainCeilingPolicy`].
pub const DEFAULT_FINDER_REWARD_BPS: u64 = 1_000;
/// Default rolling flow-accounting window length in blocks.
///
/// WIRING: default protocol constant for [`DomainCeilingPolicy`].
pub const DEFAULT_GUARD_WINDOW_BLOCKS: u64 = 7_200;

/// Admin-keyless circuit-breaker state for a guarded domain.
///
/// WIRING: stored inside [`BridgeEconomicGuard`] on [`crate::cross_domain::bridge::BridgeState`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DomainGuardStatus {
    /// Normal operation subject to the rolling window ceiling.
    #[default]
    Active,
    /// Permanently halted by a cryptographically verified contradiction proof.
    /// No administrator key can trigger or silently clear this state.
    FrozenByContradiction {
        /// Budlum block height at which the contradiction was verified.
        frozen_at_height: u64,
        /// Canonical digest of the contradiction evidence that tripped the guard.
        evidence_digest: Hash32,
    },
}

/// Per-domain adaptive escrow ceiling policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainCeilingPolicy {
    /// Latest verified consensus security backing reported for this domain.
    pub backing: SecurityBacking,
    /// Concurrent consumer count sharing `backing`'s slashable stake (`>= 1`).
    pub shared_consumer_count: u32,
    /// Haircut in basis points (`0..=10_000`) applied to slashable validator stake.
    pub stake_haircut_bps: u64,
    /// Haircut in basis points (`0..=10_000`) applied to slashable prover bond.
    pub bond_haircut_bps: u64,
    /// Challenger reward in basis points (`0..=10_000`) of slashed prover bond.
    pub finder_reward_bps: u64,
    /// Optional explicit window cap for verified Proof-of-Work domains.
    pub work_window_cap_atoms: u128,
    /// Minimum `PoW` `difficulty_bits` required before `work_window_cap_atoms` applies.
    pub min_work_difficulty_bits: u32,
    /// Optional explicit window cap for verified hash-STARK/zkVM domains.
    pub zk_window_cap_atoms: u128,
    /// Length of each flow-accounting window in blocks (`>= 1`).
    pub window_blocks: u64,
    /// Optional prover key authorized to sign state statements for this domain.
    pub prover_ed25519_pubkey: Option<[u8; 32]>,
    /// Optional ML-DSA-65 public key paired with `prover_ed25519_pubkey`.
    #[serde(default)]
    pub prover_pq_pubkey: Vec<u8>,
}

impl Default for DomainCeilingPolicy {
    fn default() -> Self {
        Self {
            backing: SecurityBacking::None,
            shared_consumer_count: 1,
            stake_haircut_bps: DEFAULT_STAKE_HAIRCUT_BPS,
            bond_haircut_bps: DEFAULT_BOND_HAIRCUT_BPS,
            finder_reward_bps: DEFAULT_FINDER_REWARD_BPS,
            work_window_cap_atoms: 0,
            min_work_difficulty_bits: 1,
            zk_window_cap_atoms: 0,
            window_blocks: DEFAULT_GUARD_WINDOW_BLOCKS,
            prover_ed25519_pubkey: None,
            prover_pq_pubkey: Vec::new(),
        }
    }
}

/// Mutable consensus state tracked per guarded external domain.
///
/// WIRING: stored per domain inside [`BridgeEconomicGuard`] and exposed via
/// [`BridgeEconomicGuard::record`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainEconomicRecord {
    /// Configured ceiling policy and latest verified security backing.
    pub policy: DomainCeilingPolicy,
    /// Current admin-keyless circuit-breaker status.
    pub status: DomainGuardStatus,
    /// Active window index (`height / policy.window_blocks`).
    pub active_window: u64,
    /// Cumulative atoms minted or unlocked during `active_window`.
    pub window_used_atoms: u128,
    /// Optional slashable prover bond backing this domain's attestations.
    pub prover_bond: Option<ProverBond>,
}

/// Pinned external adapter configuration dispatched by
/// [`BridgeEconomicGuard::refresh_backing_from_adapter`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardedExternalAdapter {
    /// Dual-quorum restaking AVS + Babylon-class EOTS adapter.
    RestakingAvs {
        /// External network identifier.
        network: String,
        /// Governance-pinned dual-quorum + EOTS committee.
        pinned: PinnedRestakingAvsSet,
    },
    /// Merged-mining `AuxPoW` + bonded `PoP` anchor adapter.
    AuxPowPop {
        /// External network identifier.
        network: String,
        /// Governance-pinned parent `PoW` and `PoP` anchor parameters.
        pinned: PinnedAuxPowAnchor,
    },
    /// 2-round Simplex / tail-forking-resistant `MonadBFT` adapter.
    SimplexBft {
        /// External network identifier.
        network: String,
        /// Governance-pinned Simplex epoch committee.
        pinned: PinnedSimplexCommittee,
    },
}

/// Permissionless contradiction evidence capable of freezing a domain and
/// slashing its attached [`ProverBond`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContradictionEvidence {
    /// Bonded prover signed two distinct state roots for the same
    /// `(domain_id, domain_height)`.
    SignedProverDoubleRoot {
        /// Conflicting domain height.
        domain_height: u64,
        /// First attested state root.
        state_root_a: Hash32,
        /// Ed25519 signature over the first statement.
        ed25519_sig_a: Vec<u8>,
        /// Mandatory ML-DSA-65 co-signature when `prover_pq_pubkey` is set.
        #[serde(default)]
        pq_sig_a: Vec<u8>,
        /// Second conflicting state root (`!= state_root_a`).
        state_root_b: Hash32,
        /// Ed25519 signature over the second statement.
        ed25519_sig_b: Vec<u8>,
        /// Mandatory ML-DSA-65 co-signature when `prover_pq_pubkey` is set.
        #[serde(default)]
        pq_sig_b: Vec<u8>,
    },
    /// Verified restaking AVS or EOTS finality equivocation.
    RestakingFault {
        /// External network name.
        network: String,
        /// Governance-pinned restaking AVS quorum configuration.
        pinned: PinnedRestakingAvsSet,
        /// Cryptographic slashing proof.
        proof: RestakingSlashingProof,
    },
    /// Verified `AuxPoW`/`PoP` bonded double-anchor equivocation.
    AuxPowPopFault {
        /// External network name.
        network: String,
        /// Governance-pinned `AuxPoW`/`PoP` anchor configuration.
        pinned: PinnedAuxPowAnchor,
        /// Cryptographic `PoP` double-anchor proof.
        proof: PopEquivocationProof,
    },
    /// Verified Simplex/`MonadBFT` `DoubleNotarize` or `FinalizeAndSkip` fault.
    SimplexFault {
        /// External network name.
        network: String,
        /// Governance-pinned Simplex committee.
        pinned: PinnedSimplexCommittee,
        /// Cryptographic Simplex safety-violation proof.
        proof: SimplexSlashingProof,
    },
}

/// Deterministic slashing receipt returned by
/// [`BridgeEconomicGuard::submit_contradiction`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContradictionOutcome {
    /// Guarded domain frozen by the verified contradiction.
    pub domain_id: DomainId,
    /// Canonical digest of the verified contradiction evidence.
    pub evidence_digest: Hash32,
    /// Address of the bonded prover whose escrow was slashed, when present.
    pub slashed_prover: Option<Address>,
    /// Total prover bond atoms slashed (`0` when no prover bond was attached).
    pub slashed_bond_atoms: u128,
    /// Challenger reward atoms carved out of `slashed_bond_atoms`.
    pub challenger_reward_atoms: u128,
    /// Net burned prover bond atoms (`slashed_bond_atoms - challenger_reward_atoms`).
    pub burned_bond_atoms: u128,
    /// External protocol weight proven culpable (`0` for direct prover double-root).
    pub external_slashed_weight: u128,
}

/// Refusal returned by [`BridgeEconomicGuard`].
///
/// WIRING: returned by [`BridgeEconomicGuard`] checks in [`crate::cross_domain::bridge::BridgeState`]
/// and [`crate::cross_domain::bridge_tx`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EconomicGuardError {
    /// Domain is not registered in the economic guard.
    UnknownDomain(DomainId),
    /// Policy parameter lies outside valid protocol bounds.
    InvalidPolicy(String),
    /// Domain is frozen due to a previously verified contradiction proof.
    DomainFrozen {
        /// Frozen domain identifier.
        domain_id: DomainId,
        /// Contradiction evidence digest that froze the domain.
        evidence_digest: Hash32,
    },
    /// Requested bridge flow exceeds the domain's effective window ceiling.
    CeilingExceeded {
        /// Guarded domain identifier.
        domain_id: DomainId,
        /// Requested flow amount in atoms.
        requested_atoms: u128,
        /// Already consumed flow in the active window.
        window_used_atoms: u128,
        /// Maximum effective ceiling for the active window.
        ceiling_atoms: u128,
    },
    /// Contradiction evidence digest was already processed.
    DuplicateEvidence(Hash32),
    /// Contradiction or external adapter proof failed verification.
    InvalidEvidence(String),
}

impl std::fmt::Display for EconomicGuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownDomain(id) => write!(f, "domain {id} has no economic guard record"),
            Self::InvalidPolicy(msg) => write!(f, "invalid economic guard policy: {msg}"),
            Self::DomainFrozen {
                domain_id,
                evidence_digest,
            } => write!(
                f,
                "domain {domain_id} bridge flow frozen by verified contradiction {}",
                hex::encode(evidence_digest)
            ),
            Self::CeilingExceeded {
                domain_id,
                requested_atoms,
                window_used_atoms,
                ceiling_atoms,
            } => write!(
                f,
                "domain {domain_id} bridge flow exceeds adaptive escrow ceiling \
                 (requested={requested_atoms}, used={window_used_atoms}, ceiling={ceiling_atoms})"
            ),
            Self::DuplicateEvidence(d) => write!(
                f,
                "contradiction evidence {} already applied",
                hex::encode(d)
            ),
            Self::InvalidEvidence(msg) => write!(f, "invalid contradiction evidence: {msg}"),
        }
    }
}

impl std::error::Error for EconomicGuardError {}

/// Canonical signing preimage for a prover state-root statement.
///
/// WIRING: signed by bonded bridge provers and verified inside
/// [`BridgeEconomicGuard::submit_contradiction`].
#[must_use]
pub fn contradiction_statement_bytes(
    domain_id: DomainId,
    domain_height: u64,
    state_root: &Hash32,
) -> Hash32 {
    hash_fields_bytes(&[
        b"BDLM_ECON_GUARD_CONTRA_V1",
        &domain_id.to_le_bytes(),
        &domain_height.to_le_bytes(),
        state_root,
    ])
}

const fn mul_bps_floor(amount: u128, bps: u64) -> u128 {
    let b = bps as u128;
    let q = amount / BPS_DEN;
    let r = amount % BPS_DEN;
    q.saturating_mul(b)
        .saturating_add(r.saturating_mul(b) / BPS_DEN)
}

fn validate_policy(policy: &DomainCeilingPolicy) -> Result<(), EconomicGuardError> {
    if policy.shared_consumer_count == 0 {
        return Err(EconomicGuardError::InvalidPolicy(
            "shared_consumer_count must be at least 1".into(),
        ));
    }
    if policy.window_blocks == 0 {
        return Err(EconomicGuardError::InvalidPolicy(
            "window_blocks must be at least 1".into(),
        ));
    }
    if u128::from(policy.stake_haircut_bps) > BPS_DEN
        || u128::from(policy.bond_haircut_bps) > BPS_DEN
        || u128::from(policy.finder_reward_bps) > BPS_DEN
    {
        return Err(EconomicGuardError::InvalidPolicy(
            "basis-point parameters cannot exceed 10_000".into(),
        ));
    }
    if let Some(ed_pk) = policy.prover_ed25519_pubkey {
        if bool::from(ed_pk.ct_eq(&[0u8; 32])) {
            return Err(EconomicGuardError::InvalidPolicy(
                "prover_ed25519_pubkey cannot be all-zero".into(),
            ));
        }
    }
    if !policy.prover_pq_pubkey.is_empty() {
        if policy.prover_ed25519_pubkey.is_none() {
            return Err(EconomicGuardError::InvalidPolicy(
                "prover_pq_pubkey requires prover_ed25519_pubkey".into(),
            ));
        }
        pq::validate_public_key(SchemeId::ML_DSA_65, &policy.prover_pq_pubkey).map_err(|e| {
            EconomicGuardError::InvalidPolicy(format!("invalid prover ML-DSA-65 public key: {e}"))
        })?;
    }
    Ok(())
}

fn hash_security_backing(backing: &SecurityBacking) -> Hash32 {
    match backing {
        SecurityBacking::None => hash_fields_bytes(&[b"BDLM_ECON_GUARD_DOMAIN_V1", &[0u8]]),
        SecurityBacking::Authority { count } => {
            hash_fields_bytes(&[b"BDLM_ECON_GUARD_DOMAIN_V1", &[1u8], &count.to_le_bytes()])
        }
        SecurityBacking::Work { difficulty_bits } => hash_fields_bytes(&[
            b"BDLM_ECON_GUARD_DOMAIN_V1",
            &[2u8],
            &difficulty_bits.to_le_bytes(),
        ]),
        SecurityBacking::SignatureSet {
            scheme,
            signers,
            required,
            total_weight,
            slashable,
        } => hash_fields_bytes(&[
            b"BDLM_ECON_GUARD_DOMAIN_V1",
            &[3u8],
            scheme.name().as_bytes(),
            &signers.to_le_bytes(),
            &required.to_le_bytes(),
            &total_weight.to_le_bytes(),
            &[u8::from(*slashable)],
        ]),
        SecurityBacking::Zk {
            system,
            public_inputs_digest,
        } => {
            let sys_tag: u8 = match system.assumption_class() {
                AssumptionClass::Hash => 1,
                AssumptionClass::ClassicalPairing => 2,
            };
            hash_fields_bytes(&[
                b"BDLM_ECON_GUARD_DOMAIN_V1",
                &[4u8],
                &[sys_tag],
                public_inputs_digest,
            ])
        }
    }
}

fn hash_prover_bond(bond: &ProverBond) -> Hash32 {
    let slash_count_le = u64::try_from(bond.slashings.len())
        .unwrap_or(u64::MAX)
        .to_le_bytes();
    let mut slash_leaves = Vec::with_capacity(bond.slashings.len());
    for s in &bond.slashings {
        slash_leaves.push(hash_fields_bytes(&[
            b"BDLM_ECON_GUARD_BOND_V1",
            &s.at_height.to_le_bytes(),
            &s.evidence_digest,
            &s.amount_atoms.to_le_bytes(),
            s.challenger.as_bytes(),
            &s.challenge_reward_atoms.to_le_bytes(),
        ]));
    }
    let bond_le = bond.bond_atoms.to_le_bytes();
    let ceil_le = bond.ceiling_atoms.to_le_bytes();
    let slashed_le = bond.slashed_atoms.to_le_bytes();
    let acc_le = bond.accepted.to_le_bytes();
    let ref_le = bond.refused.to_le_bytes();
    let mut fields: Vec<&[u8]> = Vec::with_capacity(slash_leaves.len().saturating_add(8));
    fields.push(b"BDLM_ECON_GUARD_BOND_V1");
    fields.push(bond.prover.as_bytes());
    fields.push(&bond_le);
    fields.push(&ceil_le);
    fields.push(&slashed_le);
    fields.push(&acc_le);
    fields.push(&ref_le);
    fields.push(&slash_count_le);
    for leaf in &slash_leaves {
        fields.push(leaf);
    }
    hash_fields_bytes(&fields)
}

/// Pure-integer computation of a domain's per-window bridge ceiling in atoms.
///
/// WIRING: enforced on every inbound bridge mint and unlock through
/// [`BridgeEconomicGuard::check_and_record_flow`].
///
/// Applies weakest-link economic soundness:
/// - `FrozenByContradiction` or `SecurityBacking::None` -> strictly `0`.
/// - Unslashable `SignatureSet` or `Authority` -> `0` without a live
///   [`ProverBond`], or `floor(live_bond * bond_haircut_bps / 10_000)` when
///   backed by slashable prover collateral.
/// - Slashable `SignatureSet` ->
///   `floor(floor(total_weight / shared_consumer_count) * stake_haircut_bps / 10_000)`,
///   bounded above by `bond_cap` whenever a prover bond is also attached.
/// - Verified `PoW` / hash-STARK domains -> their configured window caps (zero
///   for classical-pairing SNARKs unless covered by a bond), bounded above by
///   `bond_cap` when a prover bond is attached.
///
/// WIRING: evaluated on every guarded bridge flow inside [`BridgeEconomicGuard`].
#[must_use]
pub fn effective_ceiling_atoms(record: &DomainEconomicRecord) -> u128 {
    if matches!(
        record.status,
        DomainGuardStatus::FrozenByContradiction { .. }
    ) {
        return 0;
    }
    let policy = &record.policy;
    let bond_cap = record
        .prover_bond
        .as_ref()
        .map(|b| mul_bps_floor(b.live_atoms(), policy.bond_haircut_bps));

    match &policy.backing {
        SecurityBacking::None => 0,
        SecurityBacking::Authority { .. }
        | SecurityBacking::SignatureSet {
            slashable: false, ..
        } => bond_cap.unwrap_or(0),
        SecurityBacking::SignatureSet {
            total_weight,
            slashable: true,
            ..
        } => {
            let consumers = u128::from(policy.shared_consumer_count.max(1));
            let dedicated_stake = total_weight / consumers;
            let stake_cap = mul_bps_floor(dedicated_stake, policy.stake_haircut_bps);
            bond_cap.map_or(stake_cap, |bc| stake_cap.min(bc))
        }
        SecurityBacking::Work { difficulty_bits } => {
            let work_cap = if *difficulty_bits >= policy.min_work_difficulty_bits {
                policy.work_window_cap_atoms
            } else {
                0
            };
            bond_cap.map_or(work_cap, |bc| work_cap.min(bc))
        }
        SecurityBacking::Zk { system, .. } => {
            let zk_cap = match system.assumption_class() {
                AssumptionClass::Hash => policy.zk_window_cap_atoms,
                AssumptionClass::ClassicalPairing => 0,
            };
            bond_cap.map_or(zk_cap, |bc| zk_cap.min(bc))
        }
    }
}

/// Consensus-deterministic adaptive escrow ceiling and contradiction slashing
/// ledger embedded inside [`crate::cross_domain::bridge::BridgeState`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BridgeEconomicGuard {
    domains: BTreeMap<DomainId, DomainEconomicRecord>,
    consumed_evidence: BTreeSet<Hash32>,
}

impl BridgeEconomicGuard {
    /// Construct an empty economic guard.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return `true` when no domains or evidence records are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.consumed_evidence.is_empty()
    }

    /// Inspect the guard record for `domain_id`, if configured.
    #[must_use]
    pub fn record(&self, domain_id: DomainId) -> Option<&DomainEconomicRecord> {
        self.domains.get(&domain_id)
    }

    /// Configure or update a domain's ceiling policy and optional prover bond.
    ///
    /// Preserves any existing `FrozenByContradiction` status and rolling-window
    /// consumption so updating a policy cannot bypass a contradiction freeze or
    /// reset active-window usage.
    ///
    /// # Errors
    ///
    /// Returns [`EconomicGuardError::InvalidPolicy`] when haircuts exceed
    /// `10_000` bps, `window_blocks == 0`, `shared_consumer_count == 0`, or an
    /// attached PQ public key fails structural validation.
    pub fn configure_domain(
        &mut self,
        domain_id: DomainId,
        policy: DomainCeilingPolicy,
        prover_bond: Option<ProverBond>,
    ) -> Result<(), EconomicGuardError> {
        validate_policy(&policy)?;
        if let Some(existing) = self.domains.get_mut(&domain_id) {
            existing.policy = policy;
            existing.prover_bond = prover_bond;
            return Ok(());
        }
        self.domains.insert(
            domain_id,
            DomainEconomicRecord {
                policy,
                status: DomainGuardStatus::Active,
                active_window: 0,
                window_used_atoms: 0,
                prover_bond,
            },
        );
        Ok(())
    }

    /// Verify a raw external consensus evidence bundle through one of the
    /// supported consensus adapters and update `domain_id`'s [`SecurityBacking`].
    ///
    /// # Errors
    ///
    /// Returns an error when `domain_id` is unconfigured, frozen, or the
    /// adapter rejects `evidence` under `verification_policy`.
    pub fn refresh_backing_from_adapter(
        &mut self,
        domain_id: DomainId,
        adapter_cfg: &GuardedExternalAdapter,
        evidence: &RawConsensusEvidence,
        verification_policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, EconomicGuardError> {
        let Some(existing) = self.domains.get(&domain_id) else {
            return Err(EconomicGuardError::UnknownDomain(domain_id));
        };
        if let DomainGuardStatus::FrozenByContradiction {
            evidence_digest, ..
        } = existing.status
        {
            return Err(EconomicGuardError::DomainFrozen {
                domain_id,
                evidence_digest,
            });
        }
        let attestation = match adapter_cfg {
            GuardedExternalAdapter::RestakingAvs { network, pinned } => {
                RestakingAvsAdapter::new(network.clone(), Some(pinned.clone()))
                    .verify(evidence, verification_policy)
            }
            GuardedExternalAdapter::AuxPowPop { network, pinned } => {
                AuxPowPopAdapter::new(network.clone(), Some(pinned.clone()))
                    .verify(evidence, verification_policy)
            }
            GuardedExternalAdapter::SimplexBft { network, pinned } => {
                SimplexBftAdapter::new(network.clone(), Some(pinned.clone()))
                    .verify(evidence, verification_policy)
            }
        }
        .map_err(|e| EconomicGuardError::InvalidEvidence(e.to_string()))?;

        if let Some(rec) = self.domains.get_mut(&domain_id) {
            rec.policy.backing = attestation.security;
        }
        Ok(attestation)
    }

    /// Ensure `domain_id` is not frozen by a verified contradiction proof.
    ///
    /// # Errors
    ///
    /// Returns [`EconomicGuardError::DomainFrozen`] when `domain_id` is halted.
    pub fn ensure_domain_not_frozen(&self, domain_id: DomainId) -> Result<(), EconomicGuardError> {
        if let Some(rec) = self.domains.get(&domain_id) {
            if let DomainGuardStatus::FrozenByContradiction {
                evidence_digest, ..
            } = rec.status
            {
                return Err(EconomicGuardError::DomainFrozen {
                    domain_id,
                    evidence_digest,
                });
            }
        }
        Ok(())
    }

    /// Verify that `domain_id` is not frozen and that recording `amount_atoms`
    /// at `current_height` fits inside its adaptive escrow ceiling.
    ///
    /// Unconfigured domains return `Ok(())`; configured domains mutate nothing
    /// on refusal.
    ///
    /// # Errors
    ///
    /// Returns [`EconomicGuardError::DomainFrozen`] or
    /// [`EconomicGuardError::CeilingExceeded`] before any state change.
    pub fn check_and_record_flow(
        &mut self,
        domain_id: DomainId,
        amount_atoms: u128,
        current_height: u64,
    ) -> Result<(), EconomicGuardError> {
        let Some(rec) = self.domains.get(&domain_id) else {
            return Ok(());
        };
        if let DomainGuardStatus::FrozenByContradiction {
            evidence_digest, ..
        } = rec.status
        {
            return Err(EconomicGuardError::DomainFrozen {
                domain_id,
                evidence_digest,
            });
        }
        let win_len = rec.policy.window_blocks.max(1);
        let window_idx = current_height / win_len;
        let used = if window_idx == rec.active_window {
            rec.window_used_atoms
        } else {
            0
        };
        let ceiling = effective_ceiling_atoms(rec);
        let Some(next_used) = used.checked_add(amount_atoms) else {
            return Err(EconomicGuardError::CeilingExceeded {
                domain_id,
                requested_atoms: amount_atoms,
                window_used_atoms: used,
                ceiling_atoms: ceiling,
            });
        };
        if next_used > ceiling || (amount_atoms == 0 && ceiling == 0) {
            return Err(EconomicGuardError::CeilingExceeded {
                domain_id,
                requested_atoms: amount_atoms,
                window_used_atoms: used,
                ceiling_atoms: ceiling,
            });
        }
        if let Some(rec_mut) = self.domains.get_mut(&domain_id) {
            rec_mut.active_window = window_idx;
            rec_mut.window_used_atoms = next_used;
        }
        Ok(())
    }

    /// Verify permissionless contradiction evidence, freeze `domain_id` without
    /// any admin key, and slash its attached [`ProverBond`].
    ///
    /// # Errors
    ///
    /// Returns [`EconomicGuardError`] when the domain is unknown, the evidence
    /// was already replayed, or cryptographic verification fails.
    pub fn submit_contradiction(
        &mut self,
        domain_id: DomainId,
        evidence: &ContradictionEvidence,
        challenger: Address,
        at_height: u64,
    ) -> Result<ContradictionOutcome, EconomicGuardError> {
        let Some(rec) = self.domains.get(&domain_id) else {
            return Err(EconomicGuardError::UnknownDomain(domain_id));
        };
        let (evidence_digest, external_slashed_weight) = match evidence {
            ContradictionEvidence::SignedProverDoubleRoot {
                domain_height,
                state_root_a,
                ed25519_sig_a,
                pq_sig_a,
                state_root_b,
                ed25519_sig_b,
                pq_sig_b,
            } => {
                let Some(ed_pk) = rec.policy.prover_ed25519_pubkey else {
                    return Err(EconomicGuardError::InvalidEvidence(
                        "domain has no configured prover_ed25519_pubkey".into(),
                    ));
                };
                if bool::from(state_root_a.ct_eq(&[0u8; 32]))
                    || bool::from(state_root_b.ct_eq(&[0u8; 32]))
                    || bool::from(state_root_a.ct_eq(state_root_b))
                {
                    return Err(EconomicGuardError::InvalidEvidence(
                        "double-root proof requires two distinct non-zero state roots".into(),
                    ));
                }
                let stmt_a = contradiction_statement_bytes(domain_id, *domain_height, state_root_a);
                let stmt_b = contradiction_statement_bytes(domain_id, *domain_height, state_root_b);
                verify_signature(&stmt_a, ed25519_sig_a, &ed_pk).map_err(|e| {
                    EconomicGuardError::InvalidEvidence(format!(
                        "prover statement A Ed25519 signature invalid: {e}"
                    ))
                })?;
                verify_signature(&stmt_b, ed25519_sig_b, &ed_pk).map_err(|e| {
                    EconomicGuardError::InvalidEvidence(format!(
                        "prover statement B Ed25519 signature invalid: {e}"
                    ))
                })?;
                let pq_pk = &rec.policy.prover_pq_pubkey;
                if pq_pk.is_empty() {
                    if !pq_sig_a.is_empty() || !pq_sig_b.is_empty() {
                        return Err(EconomicGuardError::InvalidEvidence(
                            "unexpected prover ML-DSA-65 signature without configured PQ key"
                                .into(),
                        ));
                    }
                } else {
                    if pq_sig_a.is_empty() || pq_sig_b.is_empty() {
                        return Err(EconomicGuardError::InvalidEvidence(
                            "prover contradiction missing mandatory ML-DSA-65 co-signature".into(),
                        ));
                    }
                    pq::verify(
                        SchemeId::ML_DSA_65,
                        pq_pk,
                        &stmt_a,
                        crate::crypto::ctx::CROSS_DOMAIN_V1,
                        pq_sig_a,
                    )
                    .map_err(|e| {
                        EconomicGuardError::InvalidEvidence(format!(
                            "prover statement A ML-DSA-65 signature invalid: {e}"
                        ))
                    })?;
                    pq::verify(
                        SchemeId::ML_DSA_65,
                        pq_pk,
                        &stmt_b,
                        crate::crypto::ctx::CROSS_DOMAIN_V1,
                        pq_sig_b,
                    )
                    .map_err(|e| {
                        EconomicGuardError::InvalidEvidence(format!(
                            "prover statement B ML-DSA-65 signature invalid: {e}"
                        ))
                    })?;
                }
                let (low_root, high_root) = if state_root_a <= state_root_b {
                    (state_root_a, state_root_b)
                } else {
                    (state_root_b, state_root_a)
                };
                let digest = hash_fields_bytes(&[
                    b"BDLM_ECON_GUARD_EVIDENCE_V1",
                    &domain_id.to_le_bytes(),
                    &domain_height.to_le_bytes(),
                    &ed_pk,
                    low_root,
                    high_root,
                ]);
                (digest, 0u128)
            }
            ContradictionEvidence::RestakingFault {
                network,
                pinned,
                proof,
            } => {
                let res = verify_restaking_slashing(network, pinned, proof)
                    .map_err(|e| EconomicGuardError::InvalidEvidence(e.to_string()))?;
                (
                    hash_fields_bytes(&[
                        b"BDLM_ECON_GUARD_EVIDENCE_V1",
                        &[1u8],
                        &domain_id.to_le_bytes(),
                        &res.evidence_digest,
                    ]),
                    res.slashed_effective_weight,
                )
            }
            ContradictionEvidence::AuxPowPopFault {
                network,
                pinned,
                proof,
            } => {
                let res = verify_pop_equivocation(network, pinned, proof)
                    .map_err(|e| EconomicGuardError::InvalidEvidence(e.to_string()))?;
                (
                    hash_fields_bytes(&[
                        b"BDLM_ECON_GUARD_EVIDENCE_V1",
                        &[2u8],
                        &domain_id.to_le_bytes(),
                        &res.evidence_digest,
                    ]),
                    res.slashed_bond_weight,
                )
            }
            ContradictionEvidence::SimplexFault {
                network,
                pinned,
                proof,
            } => {
                let res = verify_simplex_slashing(network, pinned, proof)
                    .map_err(|e| EconomicGuardError::InvalidEvidence(e.to_string()))?;
                (
                    hash_fields_bytes(&[
                        b"BDLM_ECON_GUARD_EVIDENCE_V1",
                        &[3u8],
                        &domain_id.to_le_bytes(),
                        &res.evidence_digest,
                    ]),
                    res.slashed_stake_weight,
                )
            }
        };

        if self.consumed_evidence.contains(&evidence_digest) {
            return Err(EconomicGuardError::DuplicateEvidence(evidence_digest));
        }
        self.consumed_evidence.insert(evidence_digest);

        let Some(rec_mut) = self.domains.get_mut(&domain_id) else {
            return Err(EconomicGuardError::UnknownDomain(domain_id));
        };
        if matches!(rec_mut.status, DomainGuardStatus::Active) {
            rec_mut.status = DomainGuardStatus::FrozenByContradiction {
                frozen_at_height: at_height,
                evidence_digest,
            };
        }
        let finder_bps = rec_mut.policy.finder_reward_bps;
        let (slashed_prover, slashed_bond_atoms, challenger_reward_atoms, burned_bond_atoms) =
            match rec_mut.prover_bond.as_mut() {
                None => (None, 0u128, 0u128, 0u128),
                Some(bond) => {
                    let live = bond.live_atoms();
                    if live == 0 {
                        (None, 0u128, 0u128, 0u128)
                    } else {
                        let prover = bond.prover;
                        let paid = mul_bps_floor(live, finder_bps).min(live);
                        bond.bond_atoms = bond.bond_atoms.saturating_sub(live);
                        bond.slashed_atoms = bond.slashed_atoms.saturating_add(live);
                        bond.slashings.push(Slashing {
                            at_height,
                            evidence_digest,
                            amount_atoms: live,
                            challenger,
                            challenge_reward_atoms: paid,
                        });
                        (Some(prover), live, paid, live.saturating_sub(paid))
                    }
                }
            };

        Ok(ContradictionOutcome {
            domain_id,
            evidence_digest,
            slashed_prover,
            slashed_bond_atoms,
            challenger_reward_atoms,
            burned_bond_atoms,
            external_slashed_weight,
        })
    }

    /// Canonical length-prefixed commitment over all guarded domain policies,
    /// rolling-window counters, freeze states, prover bonds, and consumed
    /// contradiction evidence digests.
    #[must_use]
    pub fn root(&self) -> Hash32 {
        let mut domain_leaves = Vec::with_capacity(self.domains.len());
        for (domain_id, rec) in &self.domains {
            let backing_hash = hash_security_backing(&rec.policy.backing);
            let (status_tag, frozen_h, frozen_ev) = match rec.status {
                DomainGuardStatus::Active => (0u8, 0u64, [0u8; 32]),
                DomainGuardStatus::FrozenByContradiction {
                    frozen_at_height,
                    evidence_digest,
                } => (1u8, frozen_at_height, evidence_digest),
            };
            let (has_ed, ed_pk) = match rec.policy.prover_ed25519_pubkey {
                Some(pk) => (1u8, pk),
                None => (0u8, [0u8; 32]),
            };
            let (has_bond, bond_hash) = match &rec.prover_bond {
                Some(b) => (1u8, hash_prover_bond(b)),
                None => (0u8, [0u8; 32]),
            };
            domain_leaves.push(hash_fields_bytes(&[
                b"BDLM_ECON_GUARD_DOMAIN_V1",
                &domain_id.to_le_bytes(),
                &backing_hash,
                &rec.policy.shared_consumer_count.to_le_bytes(),
                &rec.policy.stake_haircut_bps.to_le_bytes(),
                &rec.policy.bond_haircut_bps.to_le_bytes(),
                &rec.policy.finder_reward_bps.to_le_bytes(),
                &rec.policy.work_window_cap_atoms.to_le_bytes(),
                &rec.policy.min_work_difficulty_bits.to_le_bytes(),
                &rec.policy.zk_window_cap_atoms.to_le_bytes(),
                &rec.policy.window_blocks.to_le_bytes(),
                &[has_ed],
                &ed_pk,
                &rec.policy.prover_pq_pubkey,
                &[status_tag],
                &frozen_h.to_le_bytes(),
                &frozen_ev,
                &rec.active_window.to_le_bytes(),
                &rec.window_used_atoms.to_le_bytes(),
                &[has_bond],
                &bond_hash,
            ]));
        }
        let dom_count_le = u64::try_from(domain_leaves.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes();
        let ev_count_le = u64::try_from(self.consumed_evidence.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes();
        let mut fields: Vec<&[u8]> = Vec::with_capacity(
            domain_leaves
                .len()
                .saturating_add(self.consumed_evidence.len())
                .saturating_add(3),
        );
        fields.push(b"BDLM_ECON_GUARD_ROOT_V1");
        fields.push(&dom_count_le);
        for leaf in &domain_leaves {
            fields.push(leaf);
        }
        fields.push(&ev_count_le);
        for ev in &self.consumed_evidence {
            fields.push(ev);
        }
        hash_fields_bytes(&fields)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::external::restaking_avs::{
        restake_vote_sign_bytes, AvsQuorumMember, AvsSignature, RestakedOperator,
    };
    use crate::crypto::facts::ObservedScheme;
    use crate::crypto::primitives::{KeyPair, PqKeyPair};
    use crate::crypto::scheme::SchemeId;

    fn make_bond(prover: Address, bond_atoms: u128) -> ProverBond {
        ProverBond {
            prover,
            bond_atoms,
            ceiling_atoms: bond_atoms.saturating_mul(10),
            slashed_atoms: 0,
            slashings: Vec::new(),
            accepted: 0,
            refused: 0,
        }
    }

    #[test]
    fn adaptive_ceiling_enforces_zero_on_none_and_unslashable_and_applies_overleverage_haircut() {
        let mut guard = BridgeEconomicGuard::new();

        // 1. SecurityBacking::None -> strictly 0 atoms even for a 1-atom flow.
        guard
            .configure_domain(10, DomainCeilingPolicy::default(), None)
            .expect("valid default policy");
        let err = guard
            .check_and_record_flow(10, 1, 100)
            .expect_err("SecurityBacking::None must never permit non-zero bridge flow");
        assert!(matches!(
            err,
            EconomicGuardError::CeilingExceeded {
                ceiling_atoms: 0,
                ..
            }
        ));

        // 2. Unslashable SignatureSet (Altair-like) without prover bond -> 0; with 10_000 bond -> 9_000.
        let unslashable = DomainCeilingPolicy {
            backing: SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Scheme(SchemeId::ED25519),
                signers: 500,
                required: 342,
                total_weight: 1_000_000_000,
                slashable: false,
            },
            ..DomainCeilingPolicy::default()
        };
        guard
            .configure_domain(11, unslashable.clone(), None)
            .unwrap();
        assert_eq!(effective_ceiling_atoms(guard.record(11).unwrap()), 0);

        let bond = make_bond(Address::from([0xB1; 32]), 10_000);
        guard.configure_domain(11, unslashable, Some(bond)).unwrap();
        assert_eq!(effective_ceiling_atoms(guard.record(11).unwrap()), 9_000);

        // 3. Slashable SignatureSet: total_weight=90_000, shared across 3 AVSs -> 30_000,
        //    * 3_333 / 10_000 = 9_999 atoms per window; rolls cleanly on next window.
        let slashable = DomainCeilingPolicy {
            backing: SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Scheme(SchemeId::ML_DSA_65),
                signers: 4,
                required: 3,
                total_weight: 90_000,
                slashable: true,
            },
            shared_consumer_count: 3,
            stake_haircut_bps: 3_333,
            window_blocks: 100,
            ..DomainCeilingPolicy::default()
        };
        guard.configure_domain(12, slashable, None).unwrap();
        assert_eq!(effective_ceiling_atoms(guard.record(12).unwrap()), 9_999);

        guard.check_and_record_flow(12, 6_000, 10).unwrap();
        let root_after_first = guard.root();
        let over = guard
            .check_and_record_flow(12, 4_000, 50)
            .expect_err("6000 + 4000 > 9999 must fail closed before mutation");
        assert!(matches!(over, EconomicGuardError::CeilingExceeded { .. }));
        assert_eq!(guard.root(), root_after_first, "refusal must not mutate");
        guard.check_and_record_flow(12, 3_999, 99).unwrap();
        // Next height window [100, 200) resets usage deterministically.
        guard.check_and_record_flow(12, 9_999, 100).unwrap();
    }

    #[test]
    fn signed_prover_contradiction_freezes_domain_slashes_bond_and_refuses_replay_or_forgery() {
        let prover_ed = KeyPair::from_seed(&[0x71; 32]).unwrap();
        let prover_pq = PqKeyPair::generate();
        let prover_addr = Address::from([0x71; 32]);
        let challenger = Address::from([0xC1; 32]);

        let mut guard = BridgeEconomicGuard::new();
        let policy = DomainCeilingPolicy {
            backing: SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Scheme(SchemeId::ML_DSA_65),
                signers: 4,
                required: 3,
                total_weight: 1_000_000,
                slashable: true,
            },
            finder_reward_bps: 1_000, // 10%
            prover_ed25519_pubkey: Some(prover_ed.public_key_bytes()),
            prover_pq_pubkey: prover_pq.public_key_bytes().to_vec(),
            ..DomainCeilingPolicy::default()
        };
        guard
            .configure_domain(21, policy, Some(make_bond(prover_addr, 50_000)))
            .unwrap();

        let root_a = [0xAA; 32];
        let root_b = [0xBB; 32];
        let stmt_a = contradiction_statement_bytes(21, 777, &root_a);
        let stmt_b = contradiction_statement_bytes(21, 777, &root_b);

        // Stripped PQ co-signature forgery must be refused without freezing or slashing.
        let root_before = guard.root();
        let sig_ed_a = prover_ed.sign(&stmt_a).to_vec();
        let sig_pq_a = prover_pq
            .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &stmt_a)
            .unwrap();
        let sig_ed_b = prover_ed.sign(&stmt_b).to_vec();
        let stripped = ContradictionEvidence::SignedProverDoubleRoot {
            domain_height: 777,
            state_root_a: root_a,
            ed25519_sig_a: sig_ed_a.clone(),
            pq_sig_a: sig_pq_a.clone(),
            state_root_b: root_b,
            ed25519_sig_b: sig_ed_b.clone(),
            pq_sig_b: Vec::new(),
        };
        assert!(guard
            .submit_contradiction(21, &stripped, challenger, 800)
            .is_err());
        assert_eq!(guard.root(), root_before);

        // Genuine hybrid double-root freezes domain and slashes full 50_000 bond (5_000 finder, 45_000 burned).
        let valid = ContradictionEvidence::SignedProverDoubleRoot {
            domain_height: 777,
            state_root_a: root_a,
            ed25519_sig_a: sig_ed_a,
            pq_sig_a: sig_pq_a,
            state_root_b: root_b,
            ed25519_sig_b: sig_ed_b,
            pq_sig_b: prover_pq
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &stmt_b)
                .unwrap(),
        };
        let outcome = guard
            .submit_contradiction(21, &valid, challenger, 800)
            .expect("valid double-root contradiction slashes and freezes");
        assert_eq!(outcome.slashed_bond_atoms, 50_000);
        assert_eq!(outcome.challenger_reward_atoms, 5_000);
        assert_eq!(outcome.burned_bond_atoms, 45_000);
        assert_ne!(guard.root(), root_before);

        // Replay of the same contradiction evidence is refused.
        let rep = guard
            .submit_contradiction(21, &valid, challenger, 801)
            .expect_err("replayed contradiction evidence must be refused");
        assert!(matches!(rep, EconomicGuardError::DuplicateEvidence(_)));

        // Frozen domain refuses every bridge flow AND survives policy reconfiguration.
        let frozen = guard
            .check_and_record_flow(21, 1, 802)
            .expect_err("frozen domain must refuse all flows");
        assert!(matches!(frozen, EconomicGuardError::DomainFrozen { .. }));
    }

    #[test]
    fn adapter_fault_dispatch_slashes_prover_bond_and_commits_to_root() {
        let op_ed = KeyPair::from_seed(&[0x81; 32]).unwrap();
        let op_pq = PqKeyPair::generate();
        let nat_ed = KeyPair::from_seed(&[0x82; 32]).unwrap();
        let nat_pq = PqKeyPair::generate();
        let pinned = PinnedRestakingAvsSet {
            epoch: 2,
            min_withdrawal_delay: 50,
            max_shared_avs_per_operator: 4,
            min_effective_restaked_stake: 500,
            native_validators: vec![AvsQuorumMember {
                ed25519_pubkey: nat_ed.public_key_bytes(),
                stake_weight: 1_000,
                pq_pubkey: nat_pq.public_key_bytes().to_vec(),
            }],
            restaked_operators: vec![RestakedOperator {
                ed25519_pubkey: op_ed.public_key_bytes(),
                raw_stake: 2_000,
                shared_avs_count: 2,
                pq_pubkey: op_pq.public_key_bytes().to_vec(),
            }],
            eots_providers: vec![],
        };

        let mut guard = BridgeEconomicGuard::new();
        guard
            .configure_domain(
                31,
                DomainCeilingPolicy::default(),
                Some(make_bond(Address::from([0x91; 32]), 20_000)),
            )
            .unwrap();

        let net = "avs-guard-net";
        let ma = restake_vote_sign_bytes(net, 2, 300, 400, &[0x01; 32]);
        let mb = restake_vote_sign_bytes(net, 2, 300, 400, &[0x02; 32]);
        let fault = ContradictionEvidence::RestakingFault {
            network: net.into(),
            pinned,
            proof: RestakingSlashingProof::RestakedEquivocation {
                epoch: 2,
                height: 300,
                horizon_a: 400,
                batch_digest_a: [0x01; 32],
                sigs_a: vec![AvsSignature {
                    signer_pubkey: op_ed.public_key_bytes(),
                    ed25519_sig: op_ed.sign(&ma).to_vec(),
                    pq_sig: op_pq
                        .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &ma)
                        .unwrap(),
                }],
                horizon_b: 400,
                batch_digest_b: [0x02; 32],
                sigs_b: vec![AvsSignature {
                    signer_pubkey: op_ed.public_key_bytes(),
                    ed25519_sig: op_ed.sign(&mb).to_vec(),
                    pq_sig: op_pq
                        .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &mb)
                        .unwrap(),
                }],
            },
        };
        let out = guard
            .submit_contradiction(31, &fault, Address::from([0xC9; 32]), 310)
            .expect("verified restaking fault freezes domain and slashes prover bond");
        assert_eq!(out.external_slashed_weight, 1_000);
        assert_eq!(out.slashed_bond_atoms, 20_000);
        assert_eq!(out.challenger_reward_atoms, 2_000);
        assert_eq!(
            guard.record(31).unwrap().status,
            DomainGuardStatus::FrozenByContradiction {
                frozen_at_height: 310,
                evidence_digest: out.evidence_digest,
            }
        );
    }

    #[test]
    fn bridge_state_enforces_economic_guard_ceiling_freeze_and_root_commitment() {
        use crate::core::account::AccountState;
        use crate::cross_domain::bridge::{AssetId, BridgeState};
        use crate::cross_domain::bridge_tx::{
            configure_domain_economic_guard, report_bridge_contradiction,
        };

        let mut bridge = BridgeState::new();
        let root_empty = bridge.root();
        let asset_a = AssetId(hash_fields_bytes(&[b"guard-bridge-a"]));
        let asset_b = AssetId(hash_fields_bytes(&[b"guard-bridge-b"]));
        let owner = Address::from([0x11; 32]);
        let recipient = Address::from([0x22; 32]);
        bridge.register_asset(asset_a, 7).unwrap();
        bridge.register_asset(asset_b, 7).unwrap();

        let prover_ed = KeyPair::from_seed(&[0x55; 32]).unwrap();
        let prover_pq = PqKeyPair::generate();
        let policy = DomainCeilingPolicy {
            backing: SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Scheme(SchemeId::ML_DSA_65),
                signers: 4,
                required: 3,
                total_weight: 3_000, // 3_000 * 3_333 / 10_000 = 999 atoms/window
                slashable: true,
            },
            prover_ed25519_pubkey: Some(prover_ed.public_key_bytes()),
            prover_pq_pubkey: prover_pq.public_key_bytes().to_vec(),
            ..DomainCeilingPolicy::default()
        };
        let root_pre_guard = bridge.root();
        bridge
            .economic_guard
            .configure_domain(7, policy.clone(), Some(make_bond(owner, 5_000)))
            .unwrap();
        assert_ne!(bridge.root(), root_empty);
        assert_ne!(
            bridge.root(),
            root_pre_guard,
            "BridgeState::root must commit economic_guard state"
        );

        let (_, ev_a) = bridge
            .lock(7, 2, 10, 0, asset_a, owner, recipient, 800, 200)
            .unwrap();
        let (_, ev_b) = bridge
            .lock(7, 2, 11, 1, asset_b, owner, recipient, 300, 200)
            .unwrap();
        bridge
            .mint(&ev_a.message.unwrap(), 15)
            .expect("800 <= 999 ceiling mints cleanly");
        let over = bridge
            .mint(&ev_b.message.unwrap(), 16)
            .expect_err("800 + 300 > 999 ceiling must refuse mint");
        assert!(over.0.contains("ceiling"), "got: {over:?}");

        // Exercise bridge_tx production wiring for escrowed bond locking,
        // contradiction slash, challenger reward, and strict supply conservation.
        let mut state = AccountState::new();
        state.add_balance(&owner, 20_000);
        configure_domain_economic_guard(&mut state, 7, policy, Some(make_bond(owner, 12_000)))
            .unwrap();
        assert_eq!(state.get_balance(&owner), 8_000);
        let sa = contradiction_statement_bytes(7, 42, &[0xA1; 32]);
        let sb = contradiction_statement_bytes(7, 42, &[0xB2; 32]);
        let ev = ContradictionEvidence::SignedProverDoubleRoot {
            domain_height: 42,
            state_root_a: [0xA1; 32],
            ed25519_sig_a: prover_ed.sign(&sa).to_vec(),
            pq_sig_a: prover_pq
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &sa)
                .unwrap(),
            state_root_b: [0xB2; 32],
            ed25519_sig_b: prover_ed.sign(&sb).to_vec(),
            pq_sig_b: prover_pq
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &sb)
                .unwrap(),
        };
        let challenger = Address::from([0xCC; 32]);
        let out = report_bridge_contradiction(&mut state, 7, &ev, challenger, 50).unwrap();
        assert_eq!(out.slashed_bond_atoms, 12_000);
        assert_eq!(out.challenger_reward_atoms, 1_200);
        assert_eq!(state.get_balance(&challenger), 1_200);
    }
}
