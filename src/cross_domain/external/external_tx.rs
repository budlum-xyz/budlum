//! External-domain writes as signed, in-block transactions.
//!
//! The intake (`IntakeState`) records which external domains are registered,
//! who is bonded to carry their evidence, which evidence formats are valid at
//! which heights, how multi-prover rounds decide, and which attestations were
//! accepted. Every one of those writes used to reach the intake through an
//! operator RPC on one node, outside a block:
//! the node that served the call held a registry no peer could reproduce.
//!
//! This family moves them into the block. Each variant is applied by the
//! executor's `ExternalDomain` arm, inside block execution, from a
//! transaction the sender signed, against `AccountState::settlement`. The
//! operator RPCs that used to perform them refuse and name these doors.
//!
//! Who may sign what:
//!
//! - registration: the poster, whose balance funds the bond;
//! - evidence: the submitter named in the evidence, so a bond and a
//!   refusal count attach to the account that carried it;
//! - a prover bond: the prover itself;
//! - readmission, a version fork and a quorum policy: the registrant, the
//!   account that posted the registration bond. Those are rules of one
//!   registration, decided by the bond that backs it; no other key holds
//!   them, and there is no network-wide key at all.
//!
//! - contradiction challenge: any non-self challenger supplying a second
//!   cryptographically verified finality proof at the same external
//!   `(height, evidence_version)` and distinct `state_root`; atomically
//!   withdraws the false attestation, freezes the domain, slashes the
//!   carrier's escrowed bond at the routing ceiling, and pays the challenger
//!   reward (`bud_slashExternalProver` RPC stays refused in favor of this
//!   signed in-block transaction).

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::cross_domain::external::ethereum::BlsVerifier;
use crate::cross_domain::external::intake::{
    AdapterSpec, BondedAnchorChallengeProof, BondedRegistrationRequest,
    CertifiedExternalDomainEnvelope, IntakeError, RegistrationRequest,
    MAX_BONDED_ANCHOR_CHALLENGE_HEIGHTS, MIN_BONDED_ANCHOR_CHALLENGE_HEIGHTS,
};
use crate::cross_domain::external::quorum::QuorumPolicy;
use crate::cross_domain::external::rollup_l1::{
    RollupRegistrationRequest, RollupStateProofSubmission,
};
use crate::cross_domain::external::spec::{DomainKey, RawConsensusEvidence};
use crate::cross_domain::external::versioning::ForkError;
use serde::{Deserialize, Serialize};

/// The longest readmission reason a transaction may carry. The reason is
/// stored in the domain's history, which is consensus state.
const MAX_READMIT_REASON_BYTES: usize = 256;

/// One external-domain write. The actor of every variant is `tx.from`,
/// already signed; a variant that names an account (the poster, the
/// submitter) must name the sender.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExternalDomainTx {
    /// Register an external domain: build the adapter from its spec, run
    /// admission against the golden sample, lock the bond from the poster.
    /// Boxed: the request carries the golden evidence payload.
    Register(Box<RegistrationRequest>),
    /// Submit finality evidence for a registered domain. Boxed for the
    /// payload.
    SubmitEvidence(Box<RawConsensusEvidence>),
    /// Bond the sender as an additional prover of a registered domain.
    BondProver { domain: DomainKey, bond_atoms: u128 },
    /// Re-run admission for a faulted domain from its stored spec and
    /// golden sample, and readmit it when the self-test still passes.
    Readmit { domain: DomainKey, reason: String },
    /// Schedule an evidence-format fork of a registered domain.
    ScheduleFork {
        domain: DomainKey,
        old_version: u32,
        new_version: u32,
        fork_height: u64,
        grace_heights: u64,
    },
    /// Install a multi-prover quorum policy for a registered domain.
    SetQuorumPolicy {
        domain: DomainKey,
        policy: QuorumPolicy,
    },
    /// Prove an accepted external finality attestation false by supplying a
    /// cryptographically verified conflicting proof for the same external
    /// `(height, evidence_version)` and distinct `state_root`. Atomically
    /// withdraws the false attestation, freezes the domain (`Faulted`),
    /// slashes the carrier's escrowed bond, and pays the challenger reward.
    /// APPENDED (tag `6`).
    ChallengeContradiction(Box<RawConsensusEvidence>),
    /// Refute an accepted attestation whose slot the external chain has moved
    /// past, by supplying the successor proof that descends from a different
    /// parent. The successor's own adapter verifies it; the predecessor it
    /// contradicts is found from the accepted book at `height - 1`.
    /// APPENDED (tag `7`).
    ChallengeAncestry(Box<RawConsensusEvidence>),
    /// Submit an objective cryptographic protocol equivocation or `BitVM2`
    /// single-step `DisproveScript` fraud proof against a serving external
    /// domain (`HotStuffQc`, `CasperFfg`, `MysticetiDag`, or `BitVmCovenant`),
    /// atomically recording an adverse round and freezing the domain
    /// (`DomainState::Faulted`). APPENDED LAST (tag `8`).
    SubmitFaultProof {
        domain: DomainKey,
        proof: ObjectiveFaultProof,
    },
    /// Permissionlessly rotate a registered external domain's pinned sync
    /// committee or BFT validator set using a cryptographic rotation proof
    /// (Ethereum SSZ branch or ICS-07 Tendermint skipping / bisection update),
    /// eliminating governance votes for routine committee turnover.
    /// APPENDED LAST (tag `9`).
    RotateCommittee {
        domain: DomainKey,
        proof: CommitteeRotationProof,
    },
    /// Governance-free registration of a collateral-bonded external anchor
    /// (`K-B.4`, `K-B.5`). Folds `anchor_digest` into `DomainKey`, enters
    /// `DomainState::PendingAnchorChallenge` with zero value routing until
    /// `challenge_window_heights` blocks elapse cleanly, and bounds value
    /// routing by live escrowed collateral. APPENDED LAST (tag `10`).
    RegisterBonded(Box<BondedRegistrationRequest>),
    /// Refute a pending bonded anchor inside its optimistic challenge window
    /// (`K-B.5`), dropping the registration to `DomainState::Faulted` and
    /// slashing the registrant's escrowed collateral to reward the challenger.
    /// APPENDED LAST (tag `11`).
    ChallengeBondedAnchor {
        domain: DomainKey,
        proof: Box<BondedAnchorChallengeProof>,
    },
    /// Register an L1-settled rollup domain anchored to a serving
    /// `parent_domain` (and optional external `da-sampling-v1` DA domain).
    /// APPENDED LAST (tag `12`).
    RegisterRollup(Box<RollupRegistrationRequest>),
    /// Submit an Ethereum MPT account + storage proof anchoring a rollup batch
    /// to an already-finalized `l1_height` on `parent_domain`.
    /// APPENDED LAST (tag `13`).
    SubmitRollupStateProof(Box<RollupStateProofSubmission>),
}

/// Cryptographic proof authorizing a permissionless committee or validator-set
/// rotation on a serving external domain without a governance vote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitteeRotationProof {
    /// Ethereum Altair/Deneb/Electra sequential sync-committee rotation proved
    /// via an SSZ Merkle branch (`EthereumSyncAdapter::rotate_committee_with_ssz_branch`).
    EthereumSyncSsz(Box<crate::cross_domain::external::ethereum::EthereumSyncRotationPayload>),
    /// Single-hop ICS-07 Tendermint skipping commit rotation
    /// (`IntakeState::rotate_tendermint_anchor`).
    TendermintSkip {
        anchor_commit: Box<crate::cross_domain::external::tendermint::TendermintCommitEvidence>,
        update: Box<crate::cross_domain::external::tendermint::TendermintCommitEvidence>,
        next_validators_proof: Option<(
            [u8; 32],
            crate::cross_domain::external::tendermint::Rfc6962Proof,
        )>,
        trusting_period_secs: u64,
    },
    /// Multi-hop ICS-07 Tendermint bisection rotation
    /// (`IntakeState::rotate_tendermint_anchor_bisection`).
    TendermintBisection {
        trusted: Box<crate::cross_domain::external::tendermint::TrustedTendermintState>,
        light_params: crate::cross_domain::external::tendermint::TendermintLightParams,
        steps: Vec<crate::cross_domain::external::tendermint::TendermintCommitEvidence>,
    },
}

/// Objective protocol-level cryptographic equivocation or single-step fraud
/// proof carried by [`ExternalDomainTx::SubmitFaultProof`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectiveFaultProof {
    /// Double-vote equivocation in the same `(epoch, view)` for an
    /// `AdapterSpec::HotStuffQc` domain.
    HotStuffEquivocation(Box<crate::cross_domain::external::hotstuff::HotStuffEquivocationProof>),
    /// Rule-1 (double-vote) or Rule-2 (surround-vote) equivocation for an
    /// `AdapterSpec::CasperFfg` domain.
    CasperFfgEquivocation(Box<crate::cross_domain::external::casper_ffg::FfgEquivocationProof>),
    /// Same-round conflicting vertex equivocation for an
    /// `AdapterSpec::MysticetiDag` domain.
    MysticetiEquivocation(
        Box<crate::cross_domain::external::mysticeti_dag::MysticetiEquivocationProof>,
    ),
    /// Single-step `DisproveScript` execution fraud proof for an
    /// `AdapterSpec::BitVmCovenant` domain.
    BitVmDisprove(Box<crate::cross_domain::external::bitvm_covenant::DisproveScriptProof>),
    /// Objective Bullshark `DAG-BFT` equivocation proof (double availability
    /// certificate or same-round vertex fork) for an
    /// `AdapterSpec::DagCertificate` domain. APPENDED (tag `4`).
    DagEquivocation(Box<crate::cross_domain::external::dag_bft::DagEquivocationProof>),
    /// Objective ICS-07 `Tendermint`/`CometBFT` misbehaviour proof (double-sign,
    /// BFT time violation, or lunatic header) bound to the domain's pinned
    /// validator-set commitment for an `AdapterSpec::TendermintCommit` domain.
    /// APPENDED (tag `5`).
    TendermintMisbehaviour {
        trusted: Box<crate::cross_domain::external::tendermint::TrustedTendermintState>,
        params: crate::cross_domain::external::tendermint::TendermintLightParams,
        evidence: Box<crate::cross_domain::external::tendermint::TendermintMisbehaviour>,
    },
}

/// What the executor hands the door: the signer, the chain, the fee the
/// sender must still hold after the door has run, and the pairing
/// implementation (the executor passes the production one; tests pass a
/// fixture verifier, because fixture evidence carries no curve points).
pub struct ExternalDomainTxContext {
    pub sender: Address,
    pub chain_id: u64,
    pub fee: u64,
    pub bls: fn() -> Box<dyn BlsVerifier>,
}

/// Why an external-domain transaction was refused. A refused transaction
/// changes nothing; a submission the registry refused but recorded is not an
/// error (see [`execute_external_domain_tx`]).
/// exposed for `execute_external_domain_tx`: reported via `Display` in executor.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExternalDomainTxError {
    #[error("external domains are not enabled on mainnet")]
    MainnetDisabled,
    #[error("ethereum sync committee finality is closed on testnet")]
    TestnetSyncCommitteeDisabled,
    #[error("the registration poster must be the transaction sender")]
    PosterIsNotSender,
    #[error("the evidence submitter must be the transaction sender")]
    SubmitterIsNotSender,
    #[error("only the registrant of this domain may change its rules")]
    NotTheRegistrant,
    #[error("no external domain is registered under this key")]
    UnknownDomain,
    #[error("bond {0} does not fit the balance type")]
    BondTooLarge(u128),
    #[error("the sender holds {balance}, and the bond plus the fee need {needed}")]
    BondUnfunded { needed: u64, balance: u64 },
    #[error("the readmission reason is {len} bytes; the limit is {max}")]
    ReasonTooLong { len: usize, max: usize },
    #[error("refused by the intake: {0}")]
    Intake(String),
    #[error("refused by the version policy: {0}")]
    Fork(String),
}

impl From<IntakeError> for ExternalDomainTxError {
    fn from(e: IntakeError) -> Self {
        Self::Intake(e.to_string())
    }
}

fn is_mainnet(chain_id: u64) -> bool {
    chain_id
        == crate::core::chain_config::Network::Mainnet
            .chain_id()
            .value()
}

fn is_testnet(chain_id: u64) -> bool {
    chain_id
        == crate::core::chain_config::Network::Testnet
            .chain_id()
            .value()
}

/// Whether this transaction operates on an Ethereum sync-committee adapter.
///
/// The public testnet gate covers the complete lifecycle, not only
/// registration. This keeps restored pre-activation state fail-closed too.
fn uses_ethereum_sync(state: &AccountState, tx: &ExternalDomainTx) -> bool {
    let entry_is_sync = |domain: &DomainKey| {
        state
            .settlement
            .external_intake
            .entries
            .get(domain)
            .is_some_and(|entry| matches!(&entry.spec, AdapterSpec::EthereumSync { .. }))
    };
    match tx {
        ExternalDomainTx::Register(request) => {
            matches!(&request.spec, AdapterSpec::EthereumSync { .. })
        }
        ExternalDomainTx::RegisterBonded(bonded) => {
            matches!(&bonded.request.spec, AdapterSpec::EthereumSync { .. })
        }
        ExternalDomainTx::SubmitEvidence(evidence)
        | ExternalDomainTx::ChallengeContradiction(evidence)
        | ExternalDomainTx::ChallengeAncestry(evidence) => state
            .settlement
            .external_intake
            .resolve_evidence_domain_key(&evidence.adapter, &evidence.network)
            .ok()
            .is_some_and(|k| entry_is_sync(&k)),
        ExternalDomainTx::BondProver { domain, .. }
        | ExternalDomainTx::Readmit { domain, .. }
        | ExternalDomainTx::ScheduleFork { domain, .. }
        | ExternalDomainTx::SetQuorumPolicy { domain, .. }
        | ExternalDomainTx::SubmitFaultProof { domain, .. }
        | ExternalDomainTx::RotateCommittee { domain, .. }
        | ExternalDomainTx::ChallengeBondedAnchor { domain, .. } => entry_is_sync(domain),
        ExternalDomainTx::RegisterRollup(req) => entry_is_sync(&req.spec.parent_domain),
        ExternalDomainTx::SubmitRollupStateProof(proof) => state
            .settlement
            .external_intake
            .rollup_domains
            .get(&proof.rollup_domain)
            .is_some_and(|r| entry_is_sync(&r.spec.parent_domain)),
    }
}

/// Apply one external-domain write to `state`.
///
/// Every variant decides its refusals before it writes, and a refusal leaves
/// the state as it was, with one deliberate exception: evidence the registry
/// refuses for a registered domain is an accepted transaction. The registry
/// records the refusal (the domain's and the prover's refusal counters are
/// part of its public profile), the sender pays the fee, and the attestation
/// book does not move. Evidence for an unknown domain, or a submission that
/// left the intake untouched, is refused like any other door.
///
/// # Errors
///
/// The [`ExternalDomainTxError`] that names the failed check.
pub fn execute_external_domain_tx(
    state: &mut AccountState,
    ctx: &ExternalDomainTxContext,
    tx: &ExternalDomainTx,
) -> Result<(), ExternalDomainTxError> {
    if is_mainnet(ctx.chain_id) {
        return Err(ExternalDomainTxError::MainnetDisabled);
    }
    if is_testnet(ctx.chain_id) && uses_ethereum_sync(state, tx) {
        return Err(ExternalDomainTxError::TestnetSyncCommitteeDisabled);
    }
    match tx {
        ExternalDomainTx::Register(request) => register(state, ctx, request),
        ExternalDomainTx::SubmitEvidence(evidence) => submit_evidence(state, ctx, evidence),
        ExternalDomainTx::BondProver { domain, bond_atoms } => {
            bond_prover(state, ctx, domain, *bond_atoms)
        }
        ExternalDomainTx::Readmit { domain, reason } => readmit(state, ctx, domain, reason),
        ExternalDomainTx::ScheduleFork {
            domain,
            old_version,
            new_version,
            fork_height,
            grace_heights,
        } => {
            require_registrant(state, ctx, domain)?;
            schedule_fork(
                state,
                domain,
                (*old_version, *new_version),
                *fork_height,
                *grace_heights,
            )
        }
        ExternalDomainTx::SetQuorumPolicy { domain, policy } => {
            require_registrant(state, ctx, domain)?;
            require_domain_mutable(state, domain)?;
            state
                .settlement
                .external_intake
                .set_quorum_policy(domain, *policy)
                .map_err(ExternalDomainTxError::from)
        }
        ExternalDomainTx::ChallengeContradiction(evidence) => {
            challenge_contradiction(state, ctx, evidence)
        }
        ExternalDomainTx::ChallengeAncestry(evidence) => challenge_ancestry(state, ctx, evidence),
        ExternalDomainTx::SubmitFaultProof { domain, proof } => {
            submit_fault_proof(state, domain, proof)
        }
        ExternalDomainTx::RotateCommittee { domain, proof } => {
            rotate_committee(state, domain, proof)
        }
        ExternalDomainTx::RegisterBonded(bonded) => register_bonded(state, ctx, bonded),
        ExternalDomainTx::ChallengeBondedAnchor { domain, proof } => {
            challenge_bonded_anchor(state, ctx, domain, proof)
        }
        ExternalDomainTx::RegisterRollup(request) => register_rollup(state, ctx, request),
        ExternalDomainTx::SubmitRollupStateProof(proof) => {
            submit_rollup_state_proof(state, ctx, proof)
        }
    }
}

/// The pairing implementation a spec needs, or none for a spec that needs
/// no curve arithmetic.
fn bls_for(spec: &AdapterSpec, ctx: &ExternalDomainTxContext) -> Option<Box<dyn BlsVerifier>> {
    matches!(spec, AdapterSpec::EthereumSync { .. }).then(ctx.bls)
}

/// The bond as a balance amount, and the refusal when the sender cannot pay
/// it and still pay the fee the executor charges afterwards.
fn fundable_bond(
    state: &AccountState,
    ctx: &ExternalDomainTxContext,
    bond_atoms: u128,
) -> Result<u64, ExternalDomainTxError> {
    let bond =
        u64::try_from(bond_atoms).map_err(|_| ExternalDomainTxError::BondTooLarge(bond_atoms))?;
    // The spendable balance, not the raw one: a bond is a spend, and the
    // locked part of a vesting account does not fund collateral.
    let balance = state.spendable_balance(&ctx.sender);
    let needed = bond
        .checked_add(ctx.fee)
        .ok_or(ExternalDomainTxError::BondTooLarge(bond_atoms))?;
    if balance < needed {
        return Err(ExternalDomainTxError::BondUnfunded { needed, balance });
    }
    Ok(bond)
}

fn require_registrant(
    state: &AccountState,
    ctx: &ExternalDomainTxContext,
    domain: &DomainKey,
) -> Result<(), ExternalDomainTxError> {
    let entry = state
        .settlement
        .external_intake
        .entries
        .get(domain)
        .ok_or(ExternalDomainTxError::UnknownDomain)?;
    if entry.registrant != ctx.sender {
        return Err(ExternalDomainTxError::NotTheRegistrant);
    }
    Ok(())
}

fn require_domain_mutable(
    state: &AccountState,
    domain: &DomainKey,
) -> Result<(), ExternalDomainTxError> {
    use crate::cross_domain::external::profile::DomainState;
    let reg = state
        .settlement
        .external_intake
        .registry
        .domain(domain)
        .ok_or(ExternalDomainTxError::UnknownDomain)?;
    if matches!(
        reg.record.state,
        DomainState::QuantumIsolated | DomainState::Retired
    ) {
        return Err(ExternalDomainTxError::Intake(
            "domain is quantum-isolated or retired and cannot mutate rules or readmit".into(),
        ));
    }
    Ok(())
}

fn register(
    state: &mut AccountState,
    ctx: &ExternalDomainTxContext,
    request: &RegistrationRequest,
) -> Result<(), ExternalDomainTxError> {
    if is_testnet(ctx.chain_id) && matches!(request.spec, AdapterSpec::EthereumSync { .. }) {
        return Err(ExternalDomainTxError::TestnetSyncCommitteeDisabled);
    }
    if request.poster != ctx.sender {
        return Err(ExternalDomainTxError::PosterIsNotSender);
    }
    let bond = fundable_bond(state, ctx, request.bond_atoms)?;
    let bls = bls_for(&request.spec, ctx);
    let observer_adapter = request
        .spec
        .build(bls_for(&request.spec, ctx), Some(request.golden.clone()));
    let (_, observed_crypto) =
        crate::cross_domain::external::admit_observed(observer_adapter.as_ref(), &request.policy);
    // The bond is locked first, from a balance already checked to hold it
    // and the fee, and handed back if the intake refuses: a registration
    // never stands without the bond behind it.
    state
        .lock_external_bond(&ctx.sender, bond)
        .map_err(ExternalDomainTxError::Intake)?;
    let key = match state
        .settlement
        .external_intake
        .register_domain(request.clone(), bls)
    {
        Ok(k) => k,
        Err(e) => {
            state
                .release_external_bond(&ctx.sender, bond)
                .map_err(ExternalDomainTxError::Intake)?;
            return Err(e.into());
        }
    };
    if !observed_crypto.is_empty() {
        if let Some(reg) = state.settlement.external_intake.registry.domain_mut(&key) {
            reg.record.crypto_facts.merge(&observed_crypto);
        }
    }
    Ok(())
}

fn submit_evidence(
    state: &mut AccountState,
    ctx: &ExternalDomainTxContext,
    evidence: &RawConsensusEvidence,
) -> Result<(), ExternalDomainTxError> {
    if evidence.submitter != ctx.sender {
        return Err(ExternalDomainTxError::SubmitterIsNotSender);
    }
    let intake = &mut state.settlement.external_intake;
    let key = match intake.resolve_evidence_domain_key(&evidence.adapter, &evidence.network) {
        Ok(k) => k,
        Err(IntakeError::UnknownDomain) => return Err(ExternalDomainTxError::UnknownDomain),
        Err(e) => return Err(e.into()),
    };
    let Some(entry) = intake.entries.get(&key) else {
        return Err(ExternalDomainTxError::UnknownDomain);
    };
    if is_testnet(ctx.chain_id) && matches!(entry.spec, AdapterSpec::EthereumSync { .. }) {
        return Err(ExternalDomainTxError::TestnetSyncCommitteeDisabled);
    }
    let bls = bls_for(&entry.spec, ctx);
    let before = intake.clone();
    match intake.submit_evidence_for_domain(&key, evidence, bls) {
        // Accepted, or entered a quorum round that has not decided yet: both
        // are recorded states.
        Ok(_) | Err(IntakeError::RoundPending) => Ok(()),
        // The registry recorded the refusal: an accepted transaction.
        Err(_) if *intake != before => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn register_bonded(
    state: &mut AccountState,
    ctx: &ExternalDomainTxContext,
    bonded: &BondedRegistrationRequest,
) -> Result<(), ExternalDomainTxError> {
    let request = &bonded.request;
    if is_testnet(ctx.chain_id) && matches!(request.spec, AdapterSpec::EthereumSync { .. }) {
        return Err(ExternalDomainTxError::TestnetSyncCommitteeDisabled);
    }
    if request.poster != ctx.sender {
        return Err(ExternalDomainTxError::PosterIsNotSender);
    }
    if !(MIN_BONDED_ANCHOR_CHALLENGE_HEIGHTS..=MAX_BONDED_ANCHOR_CHALLENGE_HEIGHTS)
        .contains(&bonded.challenge_window_heights)
    {
        return Err(IntakeError::InvalidBondedAnchor {
            reason: format!(
                "challenge_window_heights {} outside [{MIN_BONDED_ANCHOR_CHALLENGE_HEIGHTS}, {MAX_BONDED_ANCHOR_CHALLENGE_HEIGHTS}]",
                bonded.challenge_window_heights
            ),
        }
        .into());
    }
    let _anchor_digest = request.spec.bonded_anchor_digest()?;
    let bond = fundable_bond(state, ctx, request.bond_atoms)?;
    let bls = bls_for(&request.spec, ctx);
    let observer_adapter = request
        .spec
        .build(bls_for(&request.spec, ctx), Some(request.golden.clone()));
    let (_, observed_crypto) =
        crate::cross_domain::external::admit_observed(observer_adapter.as_ref(), &request.policy);
    state
        .lock_external_bond(&ctx.sender, bond)
        .map_err(ExternalDomainTxError::Intake)?;
    let key = match state
        .settlement
        .external_intake
        .register_bonded_domain(bonded.clone(), bls)
    {
        Ok(k) => k,
        Err(e) => {
            state
                .release_external_bond(&ctx.sender, bond)
                .map_err(ExternalDomainTxError::Intake)?;
            return Err(e.into());
        }
    };
    if !observed_crypto.is_empty() {
        if let Some(reg) = state.settlement.external_intake.registry.domain_mut(&key) {
            reg.record.crypto_facts.merge(&observed_crypto);
        }
    }
    let envelope: CertifiedExternalDomainEnvelope = state
        .settlement
        .external_intake
        .certified_domain_envelope(&key)
        .ok_or_else(|| {
            ExternalDomainTxError::Intake(
                "bonded registration missing certified domain envelope".to_string(),
            )
        })?;
    if envelope.economic_bound.safe_value_outflow_ceiling_atoms != 0 {
        return Err(ExternalDomainTxError::Intake(
            "bonded registration must carry zero safe value outflow during PendingAnchorChallenge"
                .to_string(),
        ));
    }
    Ok(())
}

fn register_rollup(
    state: &mut AccountState,
    ctx: &ExternalDomainTxContext,
    request: &RollupRegistrationRequest,
) -> Result<(), ExternalDomainTxError> {
    if request.poster != ctx.sender {
        return Err(ExternalDomainTxError::PosterIsNotSender);
    }
    let bond = fundable_bond(state, ctx, request.bond_atoms)?;
    state
        .lock_external_bond(&ctx.sender, bond)
        .map_err(ExternalDomainTxError::Intake)?;
    if let Err(err) = state
        .settlement
        .external_intake
        .register_rollup_domain(request.clone())
    {
        state
            .release_external_bond(&ctx.sender, bond)
            .map_err(ExternalDomainTxError::Intake)?;
        return Err(err.into());
    }
    Ok(())
}

fn submit_rollup_state_proof(
    state: &mut AccountState,
    ctx: &ExternalDomainTxContext,
    proof: &RollupStateProofSubmission,
) -> Result<(), ExternalDomainTxError> {
    if proof.submitter != ctx.sender {
        return Err(ExternalDomainTxError::SubmitterIsNotSender);
    }
    if !state
        .settlement
        .external_intake
        .rollup_domains
        .contains_key(&proof.rollup_domain)
    {
        return Err(ExternalDomainTxError::UnknownDomain);
    }
    state
        .settlement
        .external_intake
        .submit_rollup_state_proof(proof)?;
    Ok(())
}

fn challenge_bonded_anchor(
    state: &mut AccountState,
    ctx: &ExternalDomainTxContext,
    domain: &DomainKey,
    proof: &BondedAnchorChallengeProof,
) -> Result<(), ExternalDomainTxError> {
    if let BondedAnchorChallengeProof::ConflictingFinality(ev) = proof {
        if ev.submitter != ctx.sender {
            return Err(ExternalDomainTxError::SubmitterIsNotSender);
        }
    }
    let Some(spec) = state
        .settlement
        .external_intake
        .entries
        .get(domain)
        .map(|entry| entry.spec.clone())
    else {
        return Err(ExternalDomainTxError::UnknownDomain);
    };
    if is_testnet(ctx.chain_id) && matches!(spec, AdapterSpec::EthereumSync { .. }) {
        return Err(ExternalDomainTxError::TestnetSyncCommitteeDisabled);
    }
    let bls = bls_for(&spec, ctx);
    let now_unix_secs = state.current_block_unix_secs;
    let intake_before = state.settlement.external_intake.clone();
    let outcome = state.settlement.external_intake.challenge_bonded_anchor(
        domain,
        proof,
        ctx.sender,
        now_unix_secs,
        bls,
    )?;
    let slashed = match u64::try_from(outcome.slashed_atoms) {
        Ok(v) => v,
        Err(_) => {
            state.settlement.external_intake = intake_before;
            return Err(ExternalDomainTxError::BondTooLarge(outcome.slashed_atoms));
        }
    };
    let reward = match u64::try_from(outcome.challenger_reward_atoms) {
        Ok(v) => v,
        Err(_) => {
            state.settlement.external_intake = intake_before;
            return Err(ExternalDomainTxError::BondTooLarge(
                outcome.challenger_reward_atoms,
            ));
        }
    };
    if slashed > 0 {
        if let Err(err) =
            state.slash_external_bond(&outcome.slashed_prover, slashed, reward, &ctx.sender)
        {
            state.settlement.external_intake = intake_before;
            return Err(ExternalDomainTxError::Intake(err));
        }
    }
    Ok(())
}

fn challenge_contradiction(
    state: &mut AccountState,
    ctx: &ExternalDomainTxContext,
    evidence: &RawConsensusEvidence,
) -> Result<(), ExternalDomainTxError> {
    if evidence.submitter != ctx.sender {
        return Err(ExternalDomainTxError::SubmitterIsNotSender);
    }
    let key = match state
        .settlement
        .external_intake
        .resolve_evidence_domain_key(&evidence.adapter, &evidence.network)
    {
        Ok(k) => k,
        Err(IntakeError::UnknownDomain) => return Err(ExternalDomainTxError::UnknownDomain),
        Err(e) => return Err(e.into()),
    };
    let Some(spec) = state
        .settlement
        .external_intake
        .entries
        .get(&key)
        .map(|entry| entry.spec.clone())
    else {
        return Err(ExternalDomainTxError::UnknownDomain);
    };
    if is_testnet(ctx.chain_id) && matches!(spec, AdapterSpec::EthereumSync { .. }) {
        return Err(ExternalDomainTxError::TestnetSyncCommitteeDisabled);
    }
    let bls = bls_for(&spec, ctx);
    let intake_before = state.settlement.external_intake.clone();
    let outcome: crate::cross_domain::external::intake::ContradictionSlashOutcome = state
        .settlement
        .external_intake
        .slash_on_contradiction(evidence, ctx.sender, bls)?;
    let slashed = match u64::try_from(outcome.slashed_atoms) {
        Ok(v) => v,
        Err(_) => {
            state.settlement.external_intake = intake_before;
            return Err(ExternalDomainTxError::BondTooLarge(outcome.slashed_atoms));
        }
    };
    let reward = match u64::try_from(outcome.challenger_reward_atoms) {
        Ok(v) => v,
        Err(_) => {
            state.settlement.external_intake = intake_before;
            return Err(ExternalDomainTxError::BondTooLarge(
                outcome.challenger_reward_atoms,
            ));
        }
    };
    if slashed > 0 {
        if let Err(err) =
            state.slash_external_bond(&outcome.slashed_prover, slashed, reward, &ctx.sender)
        {
            state.settlement.external_intake = intake_before;
            return Err(ExternalDomainTxError::Intake(err));
        }
    }
    Ok(())
}

/// The cross-slot door: a successor proof refutes the slot it descends past.
///
/// The money half is identical to [`challenge_contradiction`]: the intake
/// decides, then `slash_external_bond` moves the atoms, and any refusal on the
/// way restores the intake snapshot so a failed challenge changes nothing.
fn challenge_ancestry(
    state: &mut AccountState,
    ctx: &ExternalDomainTxContext,
    evidence: &RawConsensusEvidence,
) -> Result<(), ExternalDomainTxError> {
    if evidence.submitter != ctx.sender {
        return Err(ExternalDomainTxError::SubmitterIsNotSender);
    }
    let key = match state
        .settlement
        .external_intake
        .resolve_evidence_domain_key(&evidence.adapter, &evidence.network)
    {
        Ok(k) => k,
        Err(IntakeError::UnknownDomain) => return Err(ExternalDomainTxError::UnknownDomain),
        Err(e) => return Err(e.into()),
    };
    let Some(spec) = state
        .settlement
        .external_intake
        .entries
        .get(&key)
        .map(|entry| entry.spec.clone())
    else {
        return Err(ExternalDomainTxError::UnknownDomain);
    };
    if is_testnet(ctx.chain_id) && matches!(spec, AdapterSpec::EthereumSync { .. }) {
        return Err(ExternalDomainTxError::TestnetSyncCommitteeDisabled);
    }
    let bls = bls_for(&spec, ctx);
    let intake_before = state.settlement.external_intake.clone();
    let outcome = state
        .settlement
        .external_intake
        .adjudicate_ancestry(evidence, ctx.sender, bls)?;
    let refuted = outcome;
    let slashed = match u64::try_from(refuted.slashed_atoms) {
        Ok(v) => v,
        Err(_) => {
            state.settlement.external_intake = intake_before;
            return Err(ExternalDomainTxError::BondTooLarge(refuted.slashed_atoms));
        }
    };
    let reward = match u64::try_from(refuted.challenger_reward_atoms) {
        Ok(v) => v,
        Err(_) => {
            state.settlement.external_intake = intake_before;
            return Err(ExternalDomainTxError::BondTooLarge(
                refuted.challenger_reward_atoms,
            ));
        }
    };
    if slashed > 0 {
        if let Err(err) =
            state.slash_external_bond(&refuted.slashed_prover, slashed, reward, &ctx.sender)
        {
            state.settlement.external_intake = intake_before;
            return Err(ExternalDomainTxError::Intake(err));
        }
    }
    Ok(())
}

fn bond_prover(
    state: &mut AccountState,
    ctx: &ExternalDomainTxContext,
    domain: &DomainKey,
    bond_atoms: u128,
) -> Result<(), ExternalDomainTxError> {
    let bond = fundable_bond(state, ctx, bond_atoms)?;
    state
        .lock_external_bond(&ctx.sender, bond)
        .map_err(ExternalDomainTxError::Intake)?;
    if let Err(e) = state
        .settlement
        .external_intake
        .bond_prover(domain, ctx.sender, bond_atoms)
    {
        state
            .release_external_bond(&ctx.sender, bond)
            .map_err(ExternalDomainTxError::Intake)?;
        return Err(e.into());
    }
    Ok(())
}

fn readmit(
    state: &mut AccountState,
    ctx: &ExternalDomainTxContext,
    domain: &DomainKey,
    reason: &str,
) -> Result<(), ExternalDomainTxError> {
    if reason.trim().is_empty() {
        return Err(ExternalDomainTxError::Intake(
            "readmission reason cannot be empty or whitespace".into(),
        ));
    }
    if reason.len() > MAX_READMIT_REASON_BYTES {
        return Err(ExternalDomainTxError::ReasonTooLong {
            len: reason.len(),
            max: MAX_READMIT_REASON_BYTES,
        });
    }
    require_registrant(state, ctx, domain)?;
    require_domain_mutable(state, domain)?;
    {
        let reg = state
            .settlement
            .external_intake
            .registry
            .domain(domain)
            .ok_or(ExternalDomainTxError::UnknownDomain)?;
        let required = reg.economics.required_bond_atoms();
        let live_total = reg
            .provers
            .values()
            .fold(0u128, |acc, bond| acc.saturating_add(bond.live_atoms()));
        if live_total < required {
            return Err(ExternalDomainTxError::Intake(format!(
                "cannot readmit with live prover collateral {live_total} below required floor {required}"
            )));
        }
    }
    let intake = &mut state.settlement.external_intake;
    let Some(entry) = intake.entries.get(domain) else {
        return Err(ExternalDomainTxError::UnknownDomain);
    };
    // The golden sample and the spec come from the stored entry: readmission
    // proves the adapter still refuses what it must, not that somebody
    // re-uploaded new rules.
    let adapter = entry
        .spec
        .build(bls_for(&entry.spec, ctx), Some(entry.golden.clone()));
    let (admission, observed_crypto) =
        crate::cross_domain::external::admit_observed(adapter.as_ref(), &entry.policy);
    intake
        .registry
        .readmit(domain, &admission, reason)
        .map_err(|e| ExternalDomainTxError::Intake(e.to_string()))?;
    if !observed_crypto.is_empty() {
        if let Some(reg) = intake.registry.domain_mut(domain) {
            reg.record.crypto_facts.merge(&observed_crypto);
        }
    }
    if let Some(entry) = intake.entries.get_mut(domain) {
        entry.admission = admission;
    }
    Ok(())
}

fn schedule_fork(
    state: &mut AccountState,
    domain: &DomainKey,
    (old_version, new_version): (u32, u32),
    fork_height: u64,
    grace_heights: u64,
) -> Result<(), ExternalDomainTxError> {
    require_domain_mutable(state, domain)?;
    let intake = &mut state.settlement.external_intake;
    let Some(reg) = intake.registry.domain(domain) else {
        return Err(ExternalDomainTxError::UnknownDomain);
    };
    let mut versions = reg.versions.clone();
    // The fork lands only on a version the adapter itself accepts
    // The registration's accepted list is policy output and
    // cannot vouch for what the adapter takes.
    versions
        .schedule_fork(
            old_version,
            new_version,
            fork_height,
            grace_heights,
            &reg.record.descriptor.accepted_evidence_versions,
        )
        .map_err(|e: ForkError| ExternalDomainTxError::Fork(e.to_string()))?;
    intake
        .set_version_policy(domain, versions)
        .map_err(ExternalDomainTxError::Fork)
}

fn rotate_committee(
    state: &mut AccountState,
    domain: &DomainKey,
    proof: &CommitteeRotationProof,
) -> Result<(), ExternalDomainTxError> {
    let spec = state
        .settlement
        .external_intake
        .entries
        .get(domain)
        .ok_or(ExternalDomainTxError::UnknownDomain)?
        .spec
        .clone();
    let now_unix_secs = state.current_block_unix_secs;
    let intake = &mut state.settlement.external_intake;
    match (&spec, proof) {
        (
            AdapterSpec::EthereumSync { network, .. },
            CommitteeRotationProof::EthereumSyncSsz(payload),
        ) => {
            intake.rotate_ethereum_committee(network, payload)?;
            Ok(())
        }
        (
            AdapterSpec::TendermintCommit { network, .. },
            CommitteeRotationProof::TendermintSkip {
                anchor_commit,
                update,
                next_validators_proof,
                trusting_period_secs,
            },
        ) => {
            intake.rotate_tendermint_anchor(
                network,
                anchor_commit,
                update,
                next_validators_proof
                    .as_ref()
                    .map(|(root, merkle)| (*root, merkle)),
                *trusting_period_secs,
                now_unix_secs,
            )?;
            Ok(())
        }
        (
            AdapterSpec::TendermintCommit { network, .. },
            CommitteeRotationProof::TendermintBisection {
                trusted,
                light_params,
                steps,
            },
        ) => {
            intake.rotate_tendermint_anchor_bisection(
                network,
                trusted,
                *light_params,
                steps,
                now_unix_secs,
            )?;
            Ok(())
        }
        _ => Err(ExternalDomainTxError::Intake(
            IntakeError::CommitteeNotPinned.to_string(),
        )),
    }
}

fn submit_fault_proof(
    state: &mut AccountState,
    domain: &DomainKey,
    proof: &ObjectiveFaultProof,
) -> Result<(), ExternalDomainTxError> {
    let now_secs = state.current_block_unix_secs;
    let intake = &mut state.settlement.external_intake;
    match proof {
        ObjectiveFaultProof::HotStuffEquivocation(hs) => intake
            .adjudicate_hotstuff_equivocation(domain, hs)
            .map(|_| ()),
        ObjectiveFaultProof::CasperFfgEquivocation(ffg) => intake
            .adjudicate_casper_ffg_equivocation(domain, ffg)
            .map(|_| ()),
        ObjectiveFaultProof::MysticetiEquivocation(my) => intake
            .adjudicate_mysticeti_equivocation(domain, my)
            .map(|_| ()),
        ObjectiveFaultProof::BitVmDisprove(bv) => {
            intake.adjudicate_bitvm_disprove(domain, bv).map(|_| ())
        }
        ObjectiveFaultProof::DagEquivocation(dag) => {
            intake.adjudicate_dag_equivocation(domain, dag).map(|_| ())
        }
        ObjectiveFaultProof::TendermintMisbehaviour {
            trusted,
            params,
            evidence,
        } => intake
            .adjudicate_tendermint_misbehaviour(domain, trusted, params, evidence, now_secs)
            .map(|_| ()),
    }
    .map_err(ExternalDomainTxError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::external::ethereum::{layout, PinnedCommittee};
    use crate::cross_domain::external::intake::IntakeState;
    use crate::cross_domain::external::spec::VerificationPolicy;
    use crate::cross_domain::external::versioning::VersionPolicy;
    use crate::cross_domain::external::DomainState;

    const DEVNET: u64 = 45262;

    /// The intake tests' strict fixture verifier: it refuses the corruptions
    /// the admission probes inject, without pairing arithmetic.
    struct StrictTestBls;

    impl BlsVerifier for StrictTestBls {
        fn verify_aggregate(
            &self,
            _signing_root: &[u8; 32],
            aggregate_pubkey: &[u8],
            signature: &[u8],
            participants: u64,
        ) -> Result<(), String> {
            if participants == 0 {
                return Err("nobody signed".to_string());
            }
            if signature.iter().all(|b| *b == 0) {
                return Err("signature is not a valid curve point".to_string());
            }
            if aggregate_pubkey.iter().all(|b| *b == 0) {
                return Err("public key is not a valid curve point".to_string());
            }
            Ok(())
        }

        fn sync_committee_closed(&self) -> bool {
            false
        }
    }

    fn test_bls() -> Box<dyn BlsVerifier> {
        Box::new(StrictTestBls)
    }

    fn addr(b: u8) -> Address {
        Address::from([b; 32])
    }

    fn ctx(sender: Address) -> ExternalDomainTxContext {
        ExternalDomainTxContext {
            sender,
            chain_id: DEVNET,
            fee: 10,
            bls: test_bls,
        }
    }

    fn spec() -> AdapterSpec {
        AdapterSpec::EthereumSync {
            network: "testnet".to_string(),
            committee: Some(PinnedCommittee {
                period: 0,
                aggregate_pubkey: vec![0x11; 96],
                next_committee_root: [0xbb; 32],
            }),
        }
    }

    fn evidence(submitter: Address, height: u64, root: [u8; 32]) -> RawConsensusEvidence {
        let committee = PinnedCommittee {
            period: 0,
            aggregate_pubkey: vec![0x11; 96],
            next_committee_root: [0xbb; 32],
        };
        let payload = crate::cross_domain::external::ethereum::build_deneb_update_payload(
            height,
            height * 2,
            0,
            &committee,
            &[0x22; 96],
            &[0xff; 64],
            root,
        );
        let adapter = spec().build(Some(test_bls()), None);
        RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: 2,
            network: "testnet".to_string(),
            payload,
            declared_height: height,
            declared_root: root,
            submitter,
        }
    }

    fn request(poster: Address) -> RegistrationRequest {
        let adapter = spec().build(Some(test_bls()), None);
        let economics = IntakeState::conservative_economics(1_000_000);
        RegistrationRequest {
            spec: spec(),
            policy: VerificationPolicy::strict(1_000),
            bond_atoms: economics.required_bond_atoms(),
            economics,
            versions: VersionPolicy::single(adapter.descriptor().id, 2, 0),
            poster,
            golden: evidence(poster, 64, [0xcc; 32]),
        }
    }

    fn bond() -> u64 {
        u64::try_from(IntakeState::conservative_economics(1_000_000).required_bond_atoms())
            .expect("the fixture bond fits")
    }

    /// A state with one registered domain and its funded registrant.
    fn registered() -> (AccountState, DomainKey, Address) {
        let mut state = AccountState::new();
        let poster = addr(9);
        state.add_balance(&poster, bond() * 4);
        if let AdapterSpec::EthereumSync {
            network,
            committee: Some(committee),
        } = spec()
        {
            state
                .settlement
                .external_intake
                .pin_ethereum_committee(network, committee);
        }
        let tx = ExternalDomainTx::Register(Box::new(request(poster)));
        execute_external_domain_tx(&mut state, &ctx(poster), &tx).expect("registers");
        let key = *state
            .settlement
            .external_intake
            .entries
            .keys()
            .next()
            .expect("one entry");
        (state, key, poster)
    }

    #[test]
    fn the_poster_registers_in_block_and_the_bond_leaves_its_balance() {
        let (state, key, poster) = registered();
        assert_eq!(state.get_balance(&poster), bond() * 3);
        assert_eq!(
            state.external_bond_escrow.get(&poster).copied(),
            Some(bond())
        );
        let entry = state
            .settlement
            .external_intake
            .entries
            .get(&key)
            .expect("entry");
        assert_eq!(entry.registrant, poster);
        assert!(!state.settlement.is_empty());
    }

    /// The bond is collateral moved out of the
    /// sender's balance, so it is a spend. The vesting lock of the team
    /// account holds against it: locked funds cannot be escrowed as a bond.
    #[test]
    fn vesting_gate_covers_external_collateral() {
        let mut state = AccountState::new();
        let poster = addr(9);
        state.add_balance(&poster, bond() * 4);
        state.team_vesting = Some((
            poster,
            crate::tokenomics::VestingSchedule {
                total: bond() * 4,
                start_epoch: 0,
                cliff_epochs: 10,
                duration_epochs: 100,
            },
        ));
        assert_eq!(
            state.spendable_balance(&poster),
            0,
            "pre-cliff: nothing is spendable"
        );
        let tx = ExternalDomainTx::Register(Box::new(request(poster)));
        let err = execute_external_domain_tx(&mut state, &ctx(poster), &tx).unwrap_err();
        assert!(
            matches!(err, ExternalDomainTxError::BondUnfunded { .. }),
            "unexpected refusal: {err:?}"
        );
        assert_eq!(state.get_balance(&poster), bond() * 4);
        assert!(!state.external_bond_escrow.contains_key(&poster));
        assert!(state.settlement.is_empty());
    }

    #[test]
    fn a_registration_in_someone_elses_name_is_refused_and_writes_nothing() {
        let mut state = AccountState::new();
        let poster = addr(9);
        let stranger = addr(10);
        state.add_balance(&stranger, bond() * 4);
        let tx = ExternalDomainTx::Register(Box::new(request(poster)));
        let err = execute_external_domain_tx(&mut state, &ctx(stranger), &tx).unwrap_err();
        assert_eq!(err, ExternalDomainTxError::PosterIsNotSender);
        assert!(state.settlement.is_empty());
        assert_eq!(state.get_balance(&stranger), bond() * 4);
    }

    #[test]
    fn an_unfunded_registration_is_refused_before_admission() {
        let mut state = AccountState::new();
        let poster = addr(9);
        state.add_balance(&poster, bond());
        let tx = ExternalDomainTx::Register(Box::new(request(poster)));
        let err = execute_external_domain_tx(&mut state, &ctx(poster), &tx).unwrap_err();
        assert!(
            matches!(err, ExternalDomainTxError::BondUnfunded { .. }),
            "{err}"
        );
        assert!(state.settlement.is_empty());
        assert!(state.external_bond_escrow.is_empty());
    }

    #[test]
    fn a_registration_that_fails_admission_locks_nothing() {
        let mut state = AccountState::new();
        let poster = addr(9);
        state.add_balance(&poster, bond() * 4);
        if let AdapterSpec::EthereumSync {
            network,
            committee: Some(committee),
        } = spec()
        {
            state
                .settlement
                .external_intake
                .pin_ethereum_committee(network, committee);
        }
        let root_before = state.settlement.root();
        let mut bad = request(poster);
        // A golden sample with no signers cannot verify: admission refuses.
        bad.golden.payload[layout::PARTICIPATION_BITS].copy_from_slice(&[0x00; 64]);
        let tx = ExternalDomainTx::Register(Box::new(bad));
        let err = execute_external_domain_tx(&mut state, &ctx(poster), &tx).unwrap_err();
        assert!(matches!(err, ExternalDomainTxError::Intake(_)), "{err}");
        assert!(state.settlement.external_intake.registry.is_empty());
        assert!(state.external_bond_escrow.is_empty());
        assert_eq!(state.settlement.root(), root_before);
        assert_eq!(state.get_balance(&poster), bond() * 4);
    }

    #[test]
    fn external_domains_are_refused_on_mainnet() {
        let mut state = AccountState::new();
        let poster = addr(9);
        state.add_balance(&poster, bond() * 4);
        let mainnet = ExternalDomainTxContext {
            chain_id: crate::core::chain_config::Network::Mainnet
                .chain_id()
                .value(),
            ..ctx(poster)
        };
        let tx = ExternalDomainTx::Register(Box::new(request(poster)));
        let err = execute_external_domain_tx(&mut state, &mainnet, &tx).unwrap_err();
        assert_eq!(err, ExternalDomainTxError::MainnetDisabled);
    }

    #[test]
    fn the_bonded_registrant_submits_evidence_and_the_attestation_lands() {
        let (mut state, key, poster) = registered();
        let tx = ExternalDomainTx::SubmitEvidence(Box::new(evidence(poster, 64, [0xcc; 32])));
        execute_external_domain_tx(&mut state, &ctx(poster), &tx).expect("accepted");
        let reg = state
            .settlement
            .external_intake
            .registry
            .domain(&key)
            .expect("domain");
        assert_eq!(reg.record.attestations_accepted, 1);
        assert_eq!(reg.record.state, DomainState::Active);
    }

    #[test]
    fn evidence_carried_in_someone_elses_name_is_refused() {
        let (mut state, _key, poster) = registered();
        let tx = ExternalDomainTx::SubmitEvidence(Box::new(evidence(poster, 64, [0xcc; 32])));
        let err = execute_external_domain_tx(&mut state, &ctx(addr(10)), &tx).unwrap_err();
        assert_eq!(err, ExternalDomainTxError::SubmitterIsNotSender);
    }

    #[test]
    fn evidence_from_an_unbonded_submitter_is_recorded_as_a_refusal() {
        let (mut state, key, _poster) = registered();
        let outsider = addr(11);
        let tx = ExternalDomainTx::SubmitEvidence(Box::new(evidence(outsider, 64, [0xcc; 32])));
        execute_external_domain_tx(&mut state, &ctx(outsider), &tx)
            .expect("a recorded refusal is an accepted transaction");
        let reg = state
            .settlement
            .external_intake
            .registry
            .domain(&key)
            .expect("domain");
        assert_eq!(reg.record.attestations_refused, 1);
        assert_eq!(reg.record.attestations_accepted, 0);
        assert!(reg.attestations.is_empty(), "nothing enters the book");
    }

    #[test]
    fn evidence_for_an_unknown_domain_is_refused_and_writes_nothing() {
        let mut state = AccountState::new();
        let who = addr(12);
        let tx = ExternalDomainTx::SubmitEvidence(Box::new(evidence(who, 64, [0xcc; 32])));
        let err = execute_external_domain_tx(&mut state, &ctx(who), &tx).unwrap_err();
        assert_eq!(err, ExternalDomainTxError::UnknownDomain);
        assert!(state.settlement.is_empty());
    }

    #[test]
    fn a_second_prover_bonds_itself_and_pays_from_its_own_balance() {
        let (mut state, key, _poster) = registered();
        let prover = addr(13);
        state.add_balance(&prover, bond() * 2);
        let tx = ExternalDomainTx::BondProver {
            domain: key,
            bond_atoms: u128::from(bond()),
        };
        execute_external_domain_tx(&mut state, &ctx(prover), &tx).expect("bonds");
        assert_eq!(state.get_balance(&prover), bond());
        let reg = state
            .settlement
            .external_intake
            .registry
            .domain(&key)
            .expect("domain");
        assert!(reg.provers.contains_key(&prover));
    }

    #[test]
    fn a_prover_bond_on_an_unknown_domain_locks_nothing() {
        let mut state = AccountState::new();
        let prover = addr(13);
        state.add_balance(&prover, bond() * 2);
        let tx = ExternalDomainTx::BondProver {
            domain: DomainKey([0x77; 32]),
            bond_atoms: u128::from(bond()),
        };
        assert!(execute_external_domain_tx(&mut state, &ctx(prover), &tx).is_err());
        assert_eq!(state.get_balance(&prover), bond() * 2);
        assert!(state.external_bond_escrow.is_empty());
    }

    #[test]
    fn only_the_registrant_changes_a_registrations_rules() {
        let (mut state, key, poster) = registered();
        let stranger = addr(14);
        let fork = ExternalDomainTx::ScheduleFork {
            domain: key,
            old_version: 2,
            new_version: 3,
            fork_height: 500,
            grace_heights: 10,
        };
        let policy = ExternalDomainTx::SetQuorumPolicy {
            domain: key,
            policy: QuorumPolicy::strict(1, 1),
        };
        let readmit = ExternalDomainTx::Readmit {
            domain: key,
            reason: "recovered".to_string(),
        };
        for tx in [&fork, &policy, &readmit] {
            let err = execute_external_domain_tx(&mut state, &ctx(stranger), tx).unwrap_err();
            assert_eq!(err, ExternalDomainTxError::NotTheRegistrant);
        }
        // The registrant's quorum policy stands: one bonded prover, a strict
        // majority of one seat.
        execute_external_domain_tx(&mut state, &ctx(poster), &policy).expect("policy");
        assert!(state
            .settlement
            .external_intake
            .quorum
            .policy_of(&key)
            .is_some());
    }

    #[test]
    fn readmitting_a_healthy_domain_is_refused_by_the_registry() {
        let (mut state, key, poster) = registered();
        let tx = ExternalDomainTx::Readmit {
            domain: key,
            reason: "no change".to_string(),
        };
        let err = execute_external_domain_tx(&mut state, &ctx(poster), &tx).unwrap_err();
        assert!(matches!(err, ExternalDomainTxError::Intake(_)), "{err}");
    }

    #[test]
    fn an_oversized_readmission_reason_is_refused() {
        let (mut state, key, poster) = registered();
        let tx = ExternalDomainTx::Readmit {
            domain: key,
            reason: "x".repeat(MAX_READMIT_REASON_BYTES + 1),
        };
        let err = execute_external_domain_tx(&mut state, &ctx(poster), &tx).unwrap_err();
        assert!(
            matches!(err, ExternalDomainTxError::ReasonTooLong { .. }),
            "{err}"
        );
    }

    #[test]
    fn a_fork_to_a_version_the_adapter_does_not_accept_is_refused() {
        let (mut state, key, poster) = registered();
        let before = state.settlement.root();
        let tx = ExternalDomainTx::ScheduleFork {
            domain: key,
            old_version: 2,
            new_version: 99,
            fork_height: 500,
            grace_heights: 10,
        };
        let err = execute_external_domain_tx(&mut state, &ctx(poster), &tx).unwrap_err();
        assert!(matches!(err, ExternalDomainTxError::Fork(_)), "{err}");
        assert_eq!(state.settlement.root(), before);
    }

    #[test]
    fn challenge_contradiction_slashes_carrier_freezes_domain_and_refuses_self_or_forged() {
        use crate::cross_domain::external::profile::DomainState;

        let (mut state, key, poster) = registered();
        let challenger = addr(42);
        state.add_balance(&challenger, 10_000);

        // 1. Accept initial attestation at height 200 for state_root [0xAA; 32].
        let accepted = evidence(poster, 200, [0xAA; 32]);
        execute_external_domain_tx(
            &mut state,
            &ctx(poster),
            &ExternalDomainTx::SubmitEvidence(Box::new(accepted)),
        )
        .expect("initial evidence accepted");

        let pre_root = state.settlement.root();
        let pre_escrow = state
            .external_bond_escrow
            .get(&poster)
            .copied()
            .expect("poster escrowed bond");
        let pre_challenger_bal = state.get_balance(&challenger);

        // 2. Self-challenge MUST be refused with zero state change.
        let self_ev = evidence(poster, 200, [0xBB; 32]);
        assert!(execute_external_domain_tx(
            &mut state,
            &ctx(poster),
            &ExternalDomainTx::ChallengeContradiction(Box::new(self_ev)),
        )
        .is_err());
        assert_eq!(state.settlement.root(), pre_root);

        // 3. Same state_root "contradiction" MUST be refused with zero state change.
        let same_root_ev = evidence(challenger, 200, [0xAA; 32]);
        assert!(execute_external_domain_tx(
            &mut state,
            &ctx(challenger),
            &ExternalDomainTx::ChallengeContradiction(Box::new(same_root_ev)),
        )
        .is_err());
        assert_eq!(state.settlement.root(), pre_root);

        // 4. Forged/corrupted proof (zeroed BLS signature) MUST be refused with zero state change.
        let mut forged = evidence(challenger, 200, [0xBB; 32]);
        forged.payload[crate::cross_domain::external::ethereum::layout::SIGNATURE].fill(0);
        assert!(execute_external_domain_tx(
            &mut state,
            &ctx(challenger),
            &ExternalDomainTx::ChallengeContradiction(Box::new(forged)),
        )
        .is_err());
        assert_eq!(state.settlement.root(), pre_root);
        assert_eq!(state.external_bond_escrow.get(&poster), Some(&pre_escrow));

        // 5. Valid conflicting proof for the same (height=200, version=2) and root [0xBB; 32]
        // withdraws the false attestation, freezes the domain, slashes poster's escrow,
        // and rewards challenger without minting net supply.
        let valid_contradiction = evidence(challenger, 200, [0xBB; 32]);
        execute_external_domain_tx(
            &mut state,
            &ctx(challenger),
            &ExternalDomainTx::ChallengeContradiction(Box::new(valid_contradiction.clone())),
        )
        .expect("verified contradiction slashes carrier and freezes domain");

        let post_escrow = state
            .external_bond_escrow
            .get(&poster)
            .copied()
            .unwrap_or(0);
        let post_challenger_bal = state.get_balance(&challenger);
        assert!(post_escrow < pre_escrow, "carrier bond must be slashed");
        assert!(
            post_challenger_bal > pre_challenger_bal,
            "challenger must receive slash reward"
        );
        let slashed_delta = pre_escrow - post_escrow;
        let reward_delta = post_challenger_bal - pre_challenger_bal;
        assert!(
            reward_delta <= slashed_delta,
            "challenger reward must never exceed slashed bond (conservation)"
        );

        let reg = state
            .settlement
            .external_intake
            .registry
            .domain(&key)
            .expect("domain registered");
        assert_eq!(reg.record.state, DomainState::Faulted);
        assert!(!reg.attestations.contains_key(&(200, 2)));

        // 6. Replaying the same contradiction after slashing MUST fail cleanly.
        assert!(execute_external_domain_tx(
            &mut state,
            &ctx(challenger),
            &ExternalDomainTx::ChallengeContradiction(Box::new(valid_contradiction)),
        )
        .is_err());
    }

    /// The ancestry door must fail closed on an adapter that binds no parent
    /// digest: the default is "cannot answer", never "assume the parent".
    #[test]
    fn challenge_ancestry_is_refused_when_the_adapter_binds_no_parent() {
        let (mut state, _key, poster) = registered();
        let challenger = addr(42);
        state.add_balance(&challenger, 10_000);
        let accepted = evidence(poster, 200, [0xAA; 32]);
        execute_external_domain_tx(
            &mut state,
            &ctx(poster),
            &ExternalDomainTx::SubmitEvidence(Box::new(accepted)),
        )
        .expect("initial evidence accepted");
        let pre_root = state.settlement.root();
        let pre_escrow = state.external_bond_escrow.get(&poster).copied();

        let successor = evidence(challenger, 201, [0xBB; 32]);
        assert!(
            execute_external_domain_tx(
                &mut state,
                &ctx(challenger),
                &ExternalDomainTx::ChallengeAncestry(Box::new(successor)),
            )
            .is_err(),
            "an unbound parent cannot refute anything"
        );
        assert_eq!(
            state.settlement.root(),
            pre_root,
            "a refusal writes nothing"
        );
        assert_eq!(state.external_bond_escrow.get(&poster).copied(), pre_escrow);
    }

    #[test]
    fn register_seeds_crqc_isolation_and_readmit_blocks_isolated_or_underbonded() {
        let (mut state, key, poster) = registered();
        let challenger = addr(42);

        // Freshly registered classical EthereumSync domain is already visible to
        // CRQC isolation before any attestation lands, and Readmit cannot undo it.
        let mut crqc_state = state.clone();
        assert_eq!(
            crqc_state
                .settlement
                .external_intake
                .registry
                .isolate_classical_domains(),
            1
        );
        assert!(execute_external_domain_tx(
            &mut crqc_state,
            &ctx(poster),
            &ExternalDomainTx::Readmit {
                domain: key,
                reason: "attempting to bypass CRQC quarantine".into(),
            },
        )
        .is_err());
        assert!(execute_external_domain_tx(
            &mut crqc_state,
            &ctx(poster),
            &ExternalDomainTx::SetQuorumPolicy {
                domain: key,
                policy: QuorumPolicy::strict(2, 3),
            },
        )
        .is_err());

        // After slashing drains live collateral below the required floor, neither
        // blank reasons nor unreplenished collateral may readmit.
        let ev_a = evidence(poster, 210, [0xA1; 32]);
        let ev_digest = ev_a.digest();
        execute_external_domain_tx(
            &mut state,
            &ctx(poster),
            &ExternalDomainTx::SubmitEvidence(Box::new(ev_a)),
        )
        .unwrap();
        state
            .settlement
            .external_intake
            .registry
            .mark_faulted(&key, "contradicted height 210")
            .unwrap();
        state
            .settlement
            .external_intake
            .registry
            .slash(&key, poster, ev_digest, 1_000, challenger)
            .unwrap();
        assert!(execute_external_domain_tx(
            &mut state,
            &ctx(poster),
            &ExternalDomainTx::Readmit {
                domain: key,
                reason: "   ".into(),
            },
        )
        .is_err());
        assert!(execute_external_domain_tx(
            &mut state,
            &ctx(poster),
            &ExternalDomainTx::Readmit {
                domain: key,
                reason: "operator audited after slash".into(),
            },
        )
        .is_err());

        // Replenishing bond up to required floor restores honest readmission.
        // Bonding a fresh prover at the required floor restores honest readmission.
        let backup_prover = Address([11; 32]);
        state.get_or_create(&backup_prover).balance = 5_000_000;
        let required_bond = state
            .settlement
            .external_intake
            .registry
            .domain(&key)
            .expect("domain stays registered while quarantined")
            .economics
            .required_bond_atoms();
        execute_external_domain_tx(
            &mut state,
            &ctx(backup_prover),
            &ExternalDomainTx::BondProver {
                domain: key,
                bond_atoms: required_bond,
            },
        )
        .unwrap();
        execute_external_domain_tx(
            &mut state,
            &ctx(poster),
            &ExternalDomainTx::Readmit {
                domain: key,
                reason: "bond replenished and adapter verified".into(),
            },
        )
        .unwrap();
    }

    #[test]
    fn submit_fault_proof_freezes_hotstuff_casper_mysticeti_bitvm_and_rejects_replay() {
        use crate::crypto::primitives::{KeyPair, PqKeyPair};

        let mut state = AccountState::new();
        state.settlement.external_intake.on_block_committed(50);
        let poster = addr(21);
        state.add_balance(&poster, 50_000_000);
        let challenger = addr(22);

        let mut non_slash = VerificationPolicy::strict(0);
        non_slash.require_slashable = false;
        let econ = IntakeState::conservative_economics(1_000);
        let ed = KeyPair::from_seed(&[0x51; 32]).expect("ed");
        let pq = PqKeyPair::generate();

        let (hs_key, hs_proof) =
            check_hotstuff_fault_tx(&mut state, poster, challenger, &non_slash, econ);
        assert!(execute_external_domain_tx(
            &mut state,
            &ctx(challenger),
            &ExternalDomainTx::SubmitFaultProof {
                domain: hs_key,
                proof: ObjectiveFaultProof::HotStuffEquivocation(Box::new(hs_proof.clone())),
            },
        )
        .is_err());
        check_casper_fault_tx(
            &mut state,
            (poster, challenger),
            &non_slash,
            econ,
            &ed,
            &pq,
            hs_proof,
        );
        check_mysticeti_fault_tx(&mut state, (poster, challenger), &non_slash, econ, &ed, &pq);
        check_bitvm_fault_tx(&mut state, (poster, challenger), &non_slash, econ, &ed, &pq);
    }

    fn check_hotstuff_fault_tx(
        state: &mut AccountState,
        poster: Address,
        challenger: Address,
        non_slash: &VerificationPolicy,
        econ: crate::cross_domain::external::DomainEconomics,
    ) -> (
        DomainKey,
        crate::cross_domain::external::hotstuff::HotStuffEquivocationProof,
    ) {
        use crate::cross_domain::external::hotstuff::{
            hotstuff_fault_test_fixture, sign_hotstuff_equivocation_proof,
        };

        let hs_net = "aptos-hotstuff-tx";
        let (hs_committee, hs_keys, hs_golden) = hotstuff_fault_test_fixture(hs_net, 7, poster);
        state
            .settlement
            .external_intake
            .pin_hotstuff_committee(hs_net, hs_committee.clone());
        let hs_spec = AdapterSpec::HotStuffQc {
            network: hs_net.to_string(),
            committee: Some(hs_committee),
        };
        let hs_adapter = hs_spec.build(None, None);
        let ver = hs_adapter
            .descriptor()
            .accepted_evidence_versions
            .first()
            .copied()
            .unwrap_or(1);
        execute_external_domain_tx(
            state,
            &ctx(poster),
            &ExternalDomainTx::Register(Box::new(RegistrationRequest {
                spec: hs_spec,
                policy: non_slash.clone(),
                economics: econ,
                versions: VersionPolicy::single(hs_adapter.descriptor().id, ver, 0),
                golden: hs_golden,
                bond_atoms: econ.required_bond_atoms(),
                poster,
            })),
        )
        .expect("register hotstuff");
        let hs_key = DomainKey::from_parts(&hs_adapter.descriptor().id, hs_net);

        let Some((hs_ed, hs_pq)) = hs_keys.first() else {
            panic!("missing hotstuff fixture key");
        };
        let hs_proof =
            sign_hotstuff_equivocation_proof(hs_net, 7, 45, [0xA1; 32], [0xB2; 32], hs_ed, hs_pq);
        let mut mainnet_ctx = ctx(challenger);
        mainnet_ctx.chain_id = crate::core::chain_config::Network::Mainnet
            .chain_id()
            .value();
        let bad_tx = |proof| ExternalDomainTx::SubmitFaultProof {
            domain: hs_key,
            proof: ObjectiveFaultProof::HotStuffEquivocation(Box::new(proof)),
        };
        assert!(matches!(
            execute_external_domain_tx(state, &mainnet_ctx, &bad_tx(hs_proof.clone())),
            Err(ExternalDomainTxError::MainnetDisabled)
        ));
        let mut forged_hs = hs_proof.clone();
        forged_hs.vote_a.pq_sig.clear();
        assert!(execute_external_domain_tx(state, &ctx(challenger), &bad_tx(forged_hs)).is_err());
        assert_eq!(
            state
                .settlement
                .external_intake
                .registry
                .domain(&hs_key)
                .expect("hs")
                .record
                .state,
            DomainState::Admitted
        );
        execute_external_domain_tx(state, &ctx(challenger), &bad_tx(hs_proof.clone()))
            .expect("hotstuff SubmitFaultProof");
        assert_eq!(
            state
                .settlement
                .external_intake
                .registry
                .domain(&hs_key)
                .expect("hs")
                .record
                .state,
            DomainState::Faulted
        );
        assert!(
            execute_external_domain_tx(state, &ctx(challenger), &bad_tx(hs_proof.clone())).is_err()
        );
        (hs_key, hs_proof)
    }

    fn register_fault_test_domain(
        state: &mut AccountState,
        spec: AdapterSpec,
        policy: &VerificationPolicy,
        econ: crate::cross_domain::external::DomainEconomics,
        golden: RawConsensusEvidence,
        poster: Address,
    ) -> DomainKey {
        let adapter_id = golden.adapter;
        let ver = golden.evidence_version;
        let net = golden.network.clone();
        let req = RegistrationRequest {
            spec,
            policy: policy.clone(),
            economics: econ,
            versions: VersionPolicy::single(adapter_id, ver, 0),
            golden,
            bond_atoms: econ.required_bond_atoms(),
            poster,
        };
        execute_external_domain_tx(
            state,
            &ctx(poster),
            &ExternalDomainTx::Register(Box::new(req)),
        )
        .expect("register fault test domain");
        DomainKey::from_parts(&adapter_id, &net)
    }

    fn assert_fault_domain_state(state: &AccountState, key: &DomainKey, expected: DomainState) {
        assert_eq!(
            state
                .settlement
                .external_intake
                .registry
                .domain(key)
                .expect("domain")
                .record
                .state,
            expected
        );
    }

    fn check_casper_fault_tx(
        state: &mut AccountState,
        (poster, challenger): (Address, Address),
        non_slash: &VerificationPolicy,
        econ: crate::cross_domain::external::DomainEconomics,
        ed: &crate::crypto::primitives::KeyPair,
        pq: &crate::crypto::primitives::PqKeyPair,
        hs_proof: crate::cross_domain::external::hotstuff::HotStuffEquivocationProof,
    ) {
        use crate::cross_domain::external::casper_ffg::{
            encode_ffg_payload, FfgEquivocationProof, FfgValidator, FfgVote, PinnedFfgCommittee,
            CASPER_FFG_ADAPTER_NAME, FFG_EVIDENCE_VERSION,
        };
        use crate::cross_domain::external::spec::AdapterId;
        use crate::crypto::ctx;

        let pub_ed = ed.public_key_bytes();
        let ffg_net = "eth-ffg-tx";
        let ffg_committee = PinnedFfgCommittee::new(
            10,
            vec![FfgValidator {
                pubkey: pub_ed,
                stake: 1_000,
                pq_pubkey: pq.public_key_bytes().to_vec(),
            }],
        )
        .expect("ffg committee");
        state
            .settlement
            .external_intake
            .pin_casper_ffg_committee(ffg_net, ffg_committee.clone());
        let sign_ffg = |se: u64, sr: [u8; 32], te: u64, tr: [u8; 32]| -> FfgVote {
            let mut v = FfgVote {
                signer: pub_ed,
                source_epoch: se,
                source_root: sr,
                target_epoch: te,
                target_root: tr,
                signature: Vec::new(),
                pq_signature: Vec::new(),
            };
            let d = v.digest(ffg_net);
            v.signature = ed.sign(&d).to_vec();
            v.pq_signature = pq.sign(ctx::CROSS_DOMAIN_V1, &d).expect("pq");
            v
        };
        let fv1 = sign_ffg(8, [0x11; 32], 9, [0x21; 32]);
        let fv2 = sign_ffg(9, [0x21; 32], 10, [0x31; 32]);
        let ffg_id = AdapterId::from_name(CASPER_FFG_ADAPTER_NAME);
        let payload = encode_ffg_payload(
            9,
            [0x21; 32],
            [0x11; 32],
            10,
            [0x31; 32],
            std::slice::from_ref(&fv1),
            &[fv2],
        );
        let ffg_key = register_fault_test_domain(
            state,
            AdapterSpec::CasperFfg {
                network: ffg_net.to_string(),
                committee: Some(ffg_committee),
            },
            non_slash,
            econ,
            RawConsensusEvidence {
                adapter: ffg_id,
                evidence_version: FFG_EVIDENCE_VERSION,
                network: ffg_net.to_string(),
                payload,
                declared_height: 10,
                declared_root: [0x31; 32],
                submitter: poster,
            },
            poster,
        );
        let wrong = ExternalDomainTx::SubmitFaultProof {
            domain: ffg_key,
            proof: ObjectiveFaultProof::HotStuffEquivocation(Box::new(hs_proof)),
        };
        assert!(execute_external_domain_tx(state, &ctx(challenger), &wrong).is_err());
        assert_fault_domain_state(state, &ffg_key, DomainState::Admitted);
        let ffg_proof = FfgEquivocationProof {
            vote_a: sign_ffg(7, [0x17; 32], 10, [0x98; 32]),
            vote_b: fv1,
        };
        let ok_tx = ExternalDomainTx::SubmitFaultProof {
            domain: ffg_key,
            proof: ObjectiveFaultProof::CasperFfgEquivocation(Box::new(ffg_proof)),
        };
        execute_external_domain_tx(state, &ctx(challenger), &ok_tx)
            .expect("casper SubmitFaultProof");
        assert_fault_domain_state(state, &ffg_key, DomainState::Faulted);
    }

    fn check_mysticeti_fault_tx(
        state: &mut AccountState,
        (poster, challenger): (Address, Address),
        non_slash: &VerificationPolicy,
        econ: crate::cross_domain::external::DomainEconomics,
        ed: &crate::crypto::primitives::KeyPair,
        pq: &crate::crypto::primitives::PqKeyPair,
    ) {
        use crate::cross_domain::external::mysticeti_dag::{
            encode_mysticeti_evidence, MysticetiAnchorCommitment, MysticetiEquivocationProof,
            MysticetiMember, MysticetiVertex, MysticetiWaveEvidence, PinnedMysticetiCommittee,
            MYSTICETI_DAG_ADAPTER_NAME, MYSTICETI_EVIDENCE_VERSION,
        };
        use crate::cross_domain::external::spec::AdapterId;
        use crate::crypto::ctx;

        let pub_ed = ed.public_key_bytes();
        let my_net = "sui-mysticeti-tx";
        let my_committee = PinnedMysticetiCommittee::new(
            4,
            vec![MysticetiMember {
                ed25519_pubkey: pub_ed,
                voting_weight: 100,
                pq_pubkey: pq.public_key_bytes().to_vec(),
            }],
        )
        .expect("mysticeti committee");
        state
            .settlement
            .external_intake
            .pin_mysticeti_committee(my_net, my_committee.clone());
        let sign_my = |round: u64, payload_digest: [u8; 32], parents: Vec<[u8; 32]>| {
            let mut v = MysticetiVertex {
                author: pub_ed,
                epoch: 4,
                round,
                payload_digest,
                parents,
                ed25519_sig: Vec::new(),
                pq_sig: Vec::new(),
            };
            let d = v.digest(my_net);
            v.ed25519_sig = ed.sign(&d).to_vec();
            v.pq_sig = pq.sign(ctx::CROSS_DOMAIN_V1, &d).expect("pq");
            v
        };
        let commit = MysticetiAnchorCommitment {
            state_root: [0x61; 32],
            tx_root: [0x62; 32],
            event_root: [0x63; 32],
            block_hash: [0x44; 32],
            parent_anchor_digest: [0x31; 32],
        };
        let anchor_v = sign_my(10, commit.digest(), vec![commit.parent_anchor_digest]);
        let wave1_v = sign_my(11, [0x42; 32], vec![anchor_v.digest(my_net)]);
        let wave2_v = sign_my(12, [0x43; 32], vec![wave1_v.digest(my_net)]);
        let my_id = AdapterId::from_name(MYSTICETI_DAG_ADAPTER_NAME);
        let payload = encode_mysticeti_evidence(&MysticetiWaveEvidence {
            commitment: commit.clone(),
            anchor: anchor_v.clone(),
            voting_vertices: vec![wave1_v],
            decision_vertices: vec![wave2_v],
        });
        let my_key = register_fault_test_domain(
            state,
            AdapterSpec::MysticetiDag {
                network: my_net.to_string(),
                committee: Some(my_committee),
            },
            non_slash,
            econ,
            RawConsensusEvidence {
                adapter: my_id,
                evidence_version: MYSTICETI_EVIDENCE_VERSION,
                network: my_net.to_string(),
                payload,
                declared_height: 10,
                declared_root: commit.state_root,
                submitter: poster,
            },
            poster,
        );
        let my_fork = sign_my(10, [0xEE; 32], vec![commit.parent_anchor_digest]);
        let proof =
            ObjectiveFaultProof::MysticetiEquivocation(Box::new(MysticetiEquivocationProof {
                vertex_a: anchor_v,
                vertex_b: my_fork,
            }));
        let tx = ExternalDomainTx::SubmitFaultProof {
            domain: my_key,
            proof,
        };
        execute_external_domain_tx(state, &ctx(challenger), &tx)
            .expect("mysticeti SubmitFaultProof");
        assert_fault_domain_state(state, &my_key, DomainState::Faulted);
    }

    fn build_bitvm_disprove_proof(
        bv_net: &str,
        claim: crate::cross_domain::external::bitvm_covenant::BitVmPegClaim,
        chunk: crate::cross_domain::external::bitvm_covenant::TraceChunkStep,
        sib: [u8; 32],
        ed: &crate::crypto::primitives::KeyPair,
        pq: &crate::crypto::primitives::PqKeyPair,
    ) -> ObjectiveFaultProof {
        use crate::cross_domain::external::bitvm_covenant::{
            hash_trace_merkle_node, BitVmPegClaim, DisproveScriptProof, MerkleStep, TraceChunkStep,
        };
        use crate::crypto::ctx;

        let bad_chunk = TraceChunkStep {
            claimed_post_state: [0xFE; 32],
            ..chunk
        };
        let mut bad_claim = BitVmPegClaim {
            state_root: [0xFE; 32],
            trace_merkle_root: hash_trace_merkle_node(&bad_chunk.leaf_digest(), &sib),
            ..claim
        };
        let bad_digest = bad_claim.signing_digest(bv_net);
        bad_claim.operator_ed25519_sig = ed.sign(&bad_digest).to_vec();
        bad_claim.operator_pq_sig = pq.sign(ctx::CROSS_DOMAIN_V1, &bad_digest).expect("pq");
        ObjectiveFaultProof::BitVmDisprove(Box::new(DisproveScriptProof {
            claim: bad_claim,
            disputed_chunk: bad_chunk,
            trace_merkle_proof: vec![MerkleStep {
                sibling: sib,
                sibling_is_left: false,
            }],
        }))
    }

    fn check_bitvm_fault_tx(
        state: &mut AccountState,
        (poster, challenger): (Address, Address),
        non_slash: &VerificationPolicy,
        econ: crate::cross_domain::external::DomainEconomics,
        ed: &crate::crypto::primitives::KeyPair,
        pq: &crate::crypto::primitives::PqKeyPair,
    ) {
        use crate::cross_domain::external::bitvm_covenant::{
            encode_bitvm_evidence, evaluate_chunk_transition, hash_trace_merkle_node,
            BitVmCovenantEvidence, BitVmPegClaim, PinnedBitVmAnchor, TraceChunkStep,
            BITVM_COVENANT_ADAPTER_NAME, BITVM_EVIDENCE_VERSION,
        };
        use crate::cross_domain::external::spec::AdapterId;
        use crate::crypto::ctx;

        let bv_net = "btc-bitvm2-tx";
        let (bits, prog) = (0x207f_ffffu32, [0x77; 32]);
        let bv_anchor = PinnedBitVmAnchor {
            height: 50,
            block_hash: [0x12; 32],
            bits,
            program_hash: prog,
            min_pow_confirmations: 6,
            challenge_blocks: 4,
            operator_ed25519_pubkey: ed.public_key_bytes(),
            operator_pq_pubkey: pq.public_key_bytes().to_vec(),
        };
        state
            .settlement
            .external_intake
            .pin_bitvm_anchor(bv_net, bv_anchor.clone());
        let (pre, wit, sib) = ([0x81; 32], [0x82; 32], [0x83; 32]);
        let post = evaluate_chunk_transition(&prog, 0, &pre, 3, &wit);
        let chunk = TraceChunkStep {
            chunk_index: 0,
            pre_state: pre,
            claimed_post_state: post,
            step_opcode: 3,
            step_witness: wit,
        };
        let mut claim = BitVmPegClaim {
            state_root: post,
            tx_root: [0x84; 32],
            event_root: [0x85; 32],
            program_hash: prog,
            trace_merkle_root: hash_trace_merkle_node(&chunk.leaf_digest(), &sib),
            trace_chunk_count: 2,
            claim_pow_height: 51,
            operator_ed25519_sig: Vec::new(),
            operator_pq_sig: Vec::new(),
        };
        let claim_digest = claim.signing_digest(bv_net);
        claim.operator_ed25519_sig = ed.sign(&claim_digest).to_vec();
        claim.operator_pq_sig = pq.sign(ctx::CROSS_DOMAIN_V1, &claim_digest).expect("pq");
        let headers = mine_bitvm_headers(bv_anchor.block_hash, bits, &claim, bv_net);
        let bv_id = AdapterId::from_name(BITVM_COVENANT_ADAPTER_NAME);
        let payload = encode_bitvm_evidence(&BitVmCovenantEvidence {
            headers,
            claim_header_index: 0,
            spv_merkle_proof: Vec::new(),
            claim: claim.clone(),
        });
        let bv_key = register_fault_test_domain(
            state,
            AdapterSpec::BitVmCovenant {
                network: bv_net.to_string(),
                anchor: Some(bv_anchor),
            },
            non_slash,
            econ,
            RawConsensusEvidence {
                adapter: bv_id,
                evidence_version: BITVM_EVIDENCE_VERSION,
                network: bv_net.to_string(),
                payload,
                declared_height: 51,
                declared_root: post,
                submitter: poster,
            },
            poster,
        );
        let proof = build_bitvm_disprove_proof(bv_net, claim, chunk, sib, ed, pq);
        execute_external_domain_tx(
            state,
            &ctx(challenger),
            &ExternalDomainTx::SubmitFaultProof {
                domain: bv_key,
                proof,
            },
        )
        .expect("bitvm SubmitFaultProof");
        assert_fault_domain_state(state, &bv_key, DomainState::Faulted);
    }

    fn mine_bitvm_headers(
        anchor_hash: [u8; 32],
        bits: u32,
        claim: &crate::cross_domain::external::bitvm_covenant::BitVmPegClaim,
        bv_net: &str,
    ) -> Vec<[u8; crate::cross_domain::external::bitvm_covenant::POW_HEADER_LEN]> {
        use crate::cross_domain::external::bitcoin_spv::sha256d;
        use crate::cross_domain::external::bitvm_covenant::{expand_compact_bits, POW_HEADER_LEN};
        let txid = sha256d(&claim.covenant_tx_bytes(bv_net));
        let target = expand_compact_bits(bits).expect("target");
        let mine = |prev: [u8; 32], mr: [u8; 32], ts: u32| -> [u8; POW_HEADER_LEN] {
            for nonce in 0u32..50_000 {
                let mut hdr = [0u8; POW_HEADER_LEN];
                let (ver_slot, rem1) = hdr.split_at_mut(4);
                ver_slot.copy_from_slice(&0x2000_0000u32.to_le_bytes());
                let (prev_slot, rem2) = rem1.split_at_mut(32);
                prev_slot.copy_from_slice(&prev);
                let (mr_slot, rem3) = rem2.split_at_mut(32);
                mr_slot.copy_from_slice(&mr);
                let (time_slot, rem4) = rem3.split_at_mut(4);
                time_slot.copy_from_slice(&ts.to_le_bytes());
                let (bits_slot, nonce_slot) = rem4.split_at_mut(4);
                bits_slot.copy_from_slice(&bits.to_le_bytes());
                nonce_slot.copy_from_slice(&nonce.to_le_bytes());
                let mut be = sha256d(&hdr);
                be.reverse();
                if be <= target {
                    return hdr;
                }
            }
            panic!("mine failed");
        };
        let mut headers = Vec::new();
        let mut prev = anchor_hash;
        for idx in 0u32..6 {
            let mr = if idx == 0 {
                txid
            } else {
                [0x90u8.saturating_add(u8::try_from(idx).unwrap_or(0)); 32]
            };
            let hdr = mine(prev, mr, 1_700_000_000 + idx * 600);
            prev = sha256d(&hdr);
            headers.push(hdr);
        }
        headers
    }

    #[test]
    fn submit_fault_proof_freezes_dag_and_tendermint_domains_and_refuses_unpinned_set() {
        use crate::cross_domain::external::dag_bft::{
            dag_anchor_cert_sign_bytes, DagAnchorVertex, DagBftSig, DagBftValidator,
            DagCausalParent, DagEquivocationProof, DagVoterVertex, DagWaveCommitEvidence,
            PinnedDagCommittee,
        };
        use crate::cross_domain::external::tendermint::PinnedTendermintAnchor;
        use crate::cross_domain::external::tendermint::{
            validator_address_of, validator_set_commitment, vote_sign_bytes,
            TendermintCommitEvidence, TendermintLightParams, TendermintMisbehaviour,
            TendermintSignature, TendermintValidator, TrustedTendermintState,
        };
        use crate::crypto::primitives::{KeyPair, PqKeyPair};

        let poster = addr(0x31);
        let challenger = addr(0x32);
        let mut state = AccountState::new();
        state.add_balance(&poster, 50_000_000);
        state.add_balance(&challenger, 50_000_000);
        let mut non_slash = VerificationPolicy::strict(0);
        non_slash.require_slashable = false;
        let econ = IntakeState::conservative_economics(1_000);

        // --- 1. Bullshark DAG-BFT double-certification equivocation ---
        let dag_net = "bullshark-fault-testnet";
        let keys: Vec<(KeyPair, PqKeyPair)> = (0..4)
            .map(|_| {
                (
                    KeyPair::generate().expect("ed25519 key"),
                    PqKeyPair::generate(),
                )
            })
            .collect();
        let members: Vec<DagBftValidator> = keys
            .iter()
            .map(|(ek, pk)| DagBftValidator {
                ed25519_pubkey: ek.public_key_bytes(),
                pq_pubkey: pk.public_key_bytes().to_vec(),
                voting_weight: 100,
            })
            .collect();
        let pinned_dag = PinnedDagCommittee { epoch: 1, members };
        state
            .settlement
            .external_intake
            .pin_dag_committee(dag_net, pinned_dag.clone());

        let mut parents: Vec<DagCausalParent> = keys
            .iter()
            .take(3)
            .enumerate()
            .map(|(idx, (ek, pk))| {
                let mut cp = DagCausalParent {
                    round: 99,
                    author: ek.public_key_bytes(),
                    payload_root: [0x10u8.saturating_add(u8::try_from(idx).unwrap_or(0)); 32],
                    digest: [0u8; 32],
                    author_ed25519_sig: Vec::new(),
                    author_pq_sig: Vec::new(),
                };
                cp.digest = cp.compute_digest(dag_net, 1);
                cp.author_ed25519_sig = ek.sign(&cp.digest).to_vec();
                cp.author_pq_sig = pk
                    .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &cp.digest)
                    .expect("pq sign");
                cp
            })
            .collect();
        parents.sort_by_key(|p| p.digest);
        let parent_digests: Vec<[u8; 32]> = parents.iter().map(|p| p.digest).collect();

        let leader = crate::cross_domain::external::dag_bft::elect_dag_wave_leader(
            dag_net,
            &pinned_dag,
            100,
        )
        .expect("leader");
        let mut anchor = DagAnchorVertex {
            epoch: 1,
            round: 100,
            author: leader,
            timestamp_secs: 1_700_000_100,
            state_root: [0xA1; 32],
            tx_root: [0xA2; 32],
            event_root: [0xA3; 32],
            parent_digests: parent_digests.clone(),
            digest: [0u8; 32],
        };
        anchor.digest = anchor.compute_digest(dag_net);

        let sign_cert = |digest: &[u8; 32]| -> Vec<DagBftSig> {
            let msg = dag_anchor_cert_sign_bytes(dag_net, 1, 100, digest);
            keys.iter()
                .take(3)
                .map(|(ek, pk)| DagBftSig {
                    signer_pubkey: ek.public_key_bytes(),
                    ed25519_sig: ek.sign(&msg).to_vec(),
                    pq_sig: pk
                        .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &msg)
                        .expect("pq sign"),
                })
                .collect()
        };
        let cert_sigs = sign_cert(&anchor.digest);
        let voters: Vec<DagVoterVertex> = keys
            .iter()
            .take(3)
            .map(|(ek, pk)| {
                let mut v = DagVoterVertex {
                    round: 101,
                    author: ek.public_key_bytes(),
                    parent_digests: vec![anchor.digest],
                    digest: [0u8; 32],
                    ed25519_sig: Vec::new(),
                    pq_sig: Vec::new(),
                };
                v.digest = v.compute_digest(dag_net, 1);
                v.ed25519_sig = ek.sign(&v.digest).to_vec();
                v.pq_sig = pk
                    .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &v.digest)
                    .expect("pq sign");
                v
            })
            .collect();
        let dag_evidence = DagWaveCommitEvidence {
            anchor: anchor.clone(),
            causal_parents: parents,
            anchor_cert_sigs: cert_sigs.clone(),
            voter_vertices: voters,
        };
        let dag_spec = AdapterSpec::DagCertificate {
            network: dag_net.into(),
            committee: Some(pinned_dag),
        };
        let dag_key = register_fault_test_domain(
            &mut state,
            dag_spec,
            &non_slash,
            econ,
            RawConsensusEvidence {
                adapter: crate::cross_domain::external::spec::AdapterId::from_name(
                    crate::cross_domain::external::dag_bft::ADAPTER_NAME,
                ),
                evidence_version: 1,
                network: dag_net.into(),
                declared_height: 100,
                declared_root: [0xA1; 32],
                payload: crate::cross_domain::external::dag_bft::encode_dag_evidence_for_test(
                    &dag_evidence,
                )
                .expect("encode dag golden"),
                submitter: poster,
            },
            poster,
        );

        let mut alt_anchor = anchor.clone();
        alt_anchor.state_root = [0xB1; 32];
        alt_anchor.digest = alt_anchor.compute_digest(dag_net);
        let alt_cert_sigs = sign_cert(&alt_anchor.digest);
        execute_external_domain_tx(
            &mut state,
            &ctx(challenger),
            &ExternalDomainTx::SubmitFaultProof {
                domain: dag_key,
                proof: ObjectiveFaultProof::DagEquivocation(Box::new(
                    DagEquivocationProof::AnchorCertificate {
                        round: 100,
                        first_anchor_digest: anchor.digest,
                        first_sigs: cert_sigs,
                        second_anchor_digest: alt_anchor.digest,
                        second_sigs: alt_cert_sigs,
                    },
                )),
            },
        )
        .expect("dag SubmitFaultProof freezes serving domain");
        assert_fault_domain_state(&state, &dag_key, DomainState::Faulted);

        // --- 2. Tendermint/CometBFT ICS-07 double-sign equivocation ---
        let tm_net = "cometbft-fault-testnet";
        let tm_chain = "comet-fault-1";
        let tm_keys: Vec<KeyPair> = (0..4)
            .map(|_| KeyPair::generate().expect("ed25519 key"))
            .collect();
        let tm_vals: Vec<TendermintValidator> = tm_keys
            .iter()
            .map(|k| TendermintValidator {
                address: validator_address_of(&k.public_key_bytes()),
                public_key: k.public_key_bytes(),
                voting_power: 100,
            })
            .collect();
        let tm_val_hash = validator_set_commitment(&tm_vals);

        let make_tm_commit = |height: u64,
                              ts: u64,
                              app_hash: [u8; 32],
                              signers: &[usize]|
         -> TendermintCommitEvidence {
            let mut c = TendermintCommitEvidence {
                chain_id: tm_chain.into(),
                height,
                round: 0,
                block_hash: [0u8; 32],
                parts_total: 1,
                parts_hash: [0x55; 32],
                version_block: 11,
                last_block_hash: [0x44; 32],
                last_parts_total: 1,
                last_parts_hash: [0x45; 32],
                last_commit_hash: [0x46; 32],
                data_hash: [0x47; 32],
                validators_hash: tm_val_hash,
                next_validators_hash: tm_val_hash,
                consensus_hash: [0x48; 32],
                app_hash,
                last_results_hash: [0x49; 32],
                evidence_hash: [0x4A; 32],
                proposer_address: tm_vals[0].address,
                commit_time: ts,
                commit_time_nanos: 0,
                validators: tm_vals.clone(),
                signatures: Vec::new(),
            };
            c.block_hash = c.header_hash();
            c.signatures = signers
                .iter()
                .map(|&idx| {
                    let sb = vote_sign_bytes(
                        &c.chain_id,
                        c.height,
                        c.round,
                        &c.block_hash,
                        c.parts_total,
                        &c.parts_hash,
                        (c.commit_time as i64, 0),
                    );
                    TendermintSignature {
                        address: tm_vals[idx].address,
                        timestamp_seconds: c.commit_time as i64,
                        timestamp_nanos: 0,
                        signature: tm_keys[idx].sign(&sb).to_vec(),
                    }
                })
                .collect();
            c
        };

        state.settlement.external_intake.pin_tendermint_anchor(
            tm_net,
            PinnedTendermintAnchor {
                chain_id: tm_chain.into(),
                validator_set_hash: tm_val_hash,
            },
        );
        let tm_golden = make_tm_commit(500, 1_780_000_000, [0x77; 32], &[0, 1, 2, 3]);
        let tm_spec = AdapterSpec::TendermintCommit {
            network: tm_net.into(),
            chain_id: tm_chain.into(),
            validator_set_hash: Some(tm_val_hash),
        };
        let tm_key = register_fault_test_domain(
            &mut state,
            tm_spec,
            &non_slash,
            econ,
            RawConsensusEvidence {
                adapter: crate::cross_domain::external::spec::AdapterId::from_name(&format!(
                    "tendermint-commit-{tm_net}"
                )),
                evidence_version: crate::cross_domain::external::tendermint::EVIDENCE_VERSION,
                network: tm_net.into(),
                declared_height: 500,
                declared_root: [0x77; 32],
                payload: tm_golden.encode().expect("encode tm golden"),
                submitter: poster,
            },
            poster,
        );

        let params = TendermintLightParams::standard_for_unbonding(1_814_400).expect("params");
        let fork_a = make_tm_commit(510, 1_780_000_600, [0xC1; 32], &[0, 1, 2]);
        let fork_b = make_tm_commit(510, 1_780_000_600, [0xD2; 32], &[1, 2, 3]);
        state.current_block_unix_secs = 1_780_001_000;

        // Forged trusted validator set that does not match pinned validator_set_hash MUST be refused.
        let forged_key = KeyPair::generate().expect("ed25519 key");
        let forged_trusted = TrustedTendermintState {
            chain_id: tm_chain.into(),
            height: 500,
            time_secs: 1_780_000_000,
            trusting_period_secs: params.trusting_period_secs,
            validators: vec![TendermintValidator {
                address: validator_address_of(&forged_key.public_key_bytes()),
                public_key: forged_key.public_key_bytes(),
                voting_power: 400,
            }],
            next_validators_hash: tm_val_hash,
        };
        assert!(execute_external_domain_tx(
            &mut state,
            &ctx(challenger),
            &ExternalDomainTx::SubmitFaultProof {
                domain: tm_key,
                proof: ObjectiveFaultProof::TendermintMisbehaviour {
                    trusted: Box::new(forged_trusted),
                    params,
                    evidence: Box::new(TendermintMisbehaviour {
                        header_1: fork_a.clone(),
                        header_2: Some(fork_b.clone()),
                    }),
                },
            },
        )
        .is_err());
        assert_fault_domain_state(&state, &tm_key, DomainState::Admitted);

        // Pinned trusted state + valid ICS-07 double-sign equivocation freezes the domain.
        let honest_trusted = TrustedTendermintState {
            chain_id: tm_chain.into(),
            height: 500,
            time_secs: 1_780_000_000,
            trusting_period_secs: params.trusting_period_secs,
            validators: tm_vals,
            next_validators_hash: tm_val_hash,
        };
        execute_external_domain_tx(
            &mut state,
            &ctx(challenger),
            &ExternalDomainTx::SubmitFaultProof {
                domain: tm_key,
                proof: ObjectiveFaultProof::TendermintMisbehaviour {
                    trusted: Box::new(honest_trusted),
                    params,
                    evidence: Box::new(TendermintMisbehaviour {
                        header_1: fork_a,
                        header_2: Some(fork_b),
                    }),
                },
            },
        )
        .expect("tendermint SubmitFaultProof freezes serving domain");
        assert_fault_domain_state(&state, &tm_key, DomainState::Faulted);
    }

    #[test]
    fn rotate_committee_tx_rotates_tendermint_permissionlessly_and_refuses_invalid_eth_ssz() {
        use crate::cross_domain::external::ethereum::{
            EthereumSyncRotationPayload, PinnedCommittee,
        };
        use crate::cross_domain::external::tendermint::{
            validator_address_of, validator_set_commitment, vote_sign_bytes,
            PinnedTendermintAnchor, TendermintCommitEvidence, TendermintSignature,
            TendermintValidator, EVIDENCE_VERSION,
        };
        use crate::crypto::primitives::KeyPair;

        let mut state = AccountState::new();
        state.current_block_unix_secs = 1_700_000_600;
        let registrant = addr(0x61);
        let relayer = addr(0x62); // NOT the registrant (permissionless!)
        state.add_balance(&registrant, 50_000_000);
        state.add_balance(&relayer, 50_000_000);
        let mut non_slash = VerificationPolicy::strict(0);
        non_slash.require_slashable = false;
        let econ = IntakeState::conservative_economics(1_000);

        let chain_id = "cosmos-rot-tx-1";
        let net = "cosmos-rot-tx";
        let keys_v1: Vec<KeyPair> = (0..4)
            .map(|_| KeyPair::generate().expect("ed25519 key"))
            .collect();
        let vals_v1: Vec<TendermintValidator> = keys_v1
            .iter()
            .map(|kp| TendermintValidator {
                address: validator_address_of(&kp.public_key_bytes()),
                public_key: kp.public_key_bytes(),
                voting_power: 100,
            })
            .collect();
        let set_hash_v1 = validator_set_commitment(&vals_v1);

        // Rotate 1 of 4 validators (3/4 = 75% > 1/3 trusted overlap, 4/4 >= 2/3+1 target quorum).
        let replacement_kp = KeyPair::generate().expect("ed25519 key");
        let mut vals_v2 = vals_v1.clone();
        vals_v2[3] = TendermintValidator {
            address: validator_address_of(&replacement_kp.public_key_bytes()),
            public_key: replacement_kp.public_key_bytes(),
            voting_power: 100,
        };
        let set_hash_v2 = validator_set_commitment(&vals_v2);
        let keys_v2: Vec<&KeyPair> = vec![&keys_v1[0], &keys_v1[1], &keys_v1[2], &replacement_kp];

        let mk_commit = |height: u64,
                         commit_time: u64,
                         vals: &[TendermintValidator],
                         kps: &[&KeyPair],
                         v_hash: [u8; 32],
                         next_v_hash: [u8; 32],
                         app_hash: [u8; 32]|
         -> TendermintCommitEvidence {
            let mut c = TendermintCommitEvidence {
                chain_id: chain_id.to_string(),
                height,
                round: 0,
                block_hash: [0u8; 32],
                parts_total: 1,
                parts_hash: [0x22; 32],
                version_block: 11,
                last_block_hash: [0x33; 32],
                last_parts_total: 1,
                last_parts_hash: [0x44; 32],
                last_commit_hash: [0x55; 32],
                data_hash: [0x66; 32],
                validators_hash: v_hash,
                next_validators_hash: next_v_hash,
                consensus_hash: [0x77; 32],
                app_hash,
                last_results_hash: [0x88; 32],
                evidence_hash: [0x99; 32],
                proposer_address: vals[0].address,
                commit_time,
                commit_time_nanos: 0,
                validators: vals.to_vec(),
                signatures: Vec::new(),
            };
            c.block_hash = c.header_hash();
            for (v, kp) in vals.iter().zip(kps.iter()) {
                let sb = vote_sign_bytes(
                    chain_id,
                    height,
                    0,
                    &c.block_hash,
                    c.parts_total,
                    &c.parts_hash,
                    (commit_time as i64, 0),
                );
                c.signatures.push(TendermintSignature {
                    address: v.address,
                    timestamp_seconds: commit_time as i64,
                    timestamp_nanos: 0,
                    signature: kp.sign(&sb).to_vec(),
                });
            }
            c
        };

        let kps_v1_refs: Vec<&KeyPair> = keys_v1.iter().collect();
        let anchor_commit = mk_commit(
            10,
            1_700_000_000,
            &vals_v1,
            &kps_v1_refs,
            set_hash_v1,
            set_hash_v2,
            [0xA1; 32],
        );
        let update_commit = mk_commit(
            20,
            1_700_000_500,
            &vals_v2,
            &keys_v2,
            set_hash_v2,
            set_hash_v2,
            [0xA2; 32],
        );

        state.settlement.external_intake.pin_tendermint_anchor(
            net,
            PinnedTendermintAnchor {
                chain_id: chain_id.to_string(),
                validator_set_hash: set_hash_v1,
            },
        );
        let tm_spec = AdapterSpec::TendermintCommit {
            network: net.to_string(),
            chain_id: chain_id.to_string(),
            validator_set_hash: Some(set_hash_v1),
        };
        let tm_domain = register_fault_test_domain(
            &mut state,
            tm_spec,
            &non_slash,
            econ,
            RawConsensusEvidence {
                adapter: crate::cross_domain::external::spec::AdapterId::from_name(&format!(
                    "tendermint-commit-{net}"
                )),
                evidence_version: EVIDENCE_VERSION,
                network: net.to_string(),
                payload: anchor_commit.encode().expect("encode tm anchor"),
                declared_height: 10,
                declared_root: [0xA1; 32],
                submitter: registrant,
            },
            registrant,
        );

        // Any relayer (not the registrant) can permissionlessly rotate the
        // validator set via a valid ICS-07 skipping commit proof.
        let rot_tx = ExternalDomainTx::RotateCommittee {
            domain: tm_domain,
            proof: CommitteeRotationProof::TendermintSkip {
                anchor_commit: Box::new(anchor_commit),
                update: Box::new(update_commit),
                next_validators_proof: None,
                trusting_period_secs: 3_600,
            },
        };
        execute_external_domain_tx(&mut state, &ctx(relayer), &rot_tx)
            .expect("permissionless Tendermint ICS-07 rotation must succeed");
        let pinned_after = state
            .settlement
            .external_intake
            .pinned_tendermint_anchors
            .get(net)
            .expect("pinned anchor");
        assert_eq!(pinned_after.validator_set_hash, set_hash_v2);

        // Mismatched proof family (Ethereum SSZ proof against Tendermint domain)
        // must fail closed without mutating the anchor.
        let bad_eth_payload = EthereumSyncRotationPayload {
            next_period: 1,
            next_member_pubkeys: Vec::new(),
            next_aggregate_pubkey: Vec::new(),
            finalized_state_root: [0u8; 32],
            next_sync_committee_gindex: 55,
            next_sync_committee_branch: Vec::new(),
            finalized_root_gindex: 105,
            subsequent_committee_root: [0u8; 32],
        };
        let err = execute_external_domain_tx(
            &mut state,
            &ctx(relayer),
            &ExternalDomainTx::RotateCommittee {
                domain: tm_domain,
                proof: CommitteeRotationProof::EthereumSyncSsz(Box::new(bad_eth_payload.clone())),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ExternalDomainTxError::Intake(_)));

        // Direct Ethereum SSZ rotation with malformed member count must fail closed
        // and leave the pinned committee untouched.
        state.settlement.external_intake.pin_ethereum_committee(
            "sepolia",
            PinnedCommittee {
                period: 100,
                aggregate_pubkey: vec![0xAA; 96],
                next_committee_root: [0xBB; 32],
            },
        );
        let eth_err = state
            .settlement
            .external_intake
            .rotate_ethereum_committee("sepolia", &bad_eth_payload)
            .unwrap_err();
        assert!(matches!(eth_err, IntakeError::Registry(_)));
        assert_eq!(
            state
                .settlement
                .external_intake
                .pinned_ethereum_committees
                .get("sepolia")
                .expect("pinned")
                .period,
            100
        );
    }

    fn sepolia_evidence(
        submitter: Address,
        committee: &PinnedCommittee,
        height: u64,
        root: [u8; 32],
    ) -> RawConsensusEvidence {
        let spec = AdapterSpec::EthereumSync {
            network: "sepolia".to_string(),
            committee: Some(committee.clone()),
        };
        let payload = crate::cross_domain::external::ethereum::build_deneb_update_payload(
            height,
            height * 2,
            committee.period,
            committee,
            &[0x22; 96],
            &[0xff; 64],
            root,
        );
        let adapter = spec.build(Some(test_bls()), None);
        RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: 2,
            network: "sepolia".to_string(),
            payload,
            declared_height: height,
            declared_root: root,
            submitter,
        }
    }

    #[test]
    fn sepolia_bonded_anchor_registers_without_governance_vote_and_caps_ceiling_by_bond() {
        use crate::cross_domain::external::{profile_of, AnchorClass};
        use crate::unification::UniversalDomainCatalog;

        let poster_a = addr(0x51);
        let poster_b = addr(0x52);
        let mut state = AccountState::new();
        state.add_balance(&poster_a, 500_000);
        state.add_balance(&poster_b, 500_000);

        let committee_a = PinnedCommittee {
            period: 0,
            aggregate_pubkey: vec![0x33; 96],
            next_committee_root: [0xaa; 32],
        };
        let committee_b = PinnedCommittee {
            period: 0,
            aggregate_pubkey: vec![0x44; 96],
            next_committee_root: [0xbb; 32],
        };
        let spec_a = AdapterSpec::EthereumSync {
            network: "sepolia".to_string(),
            committee: Some(committee_a.clone()),
        };
        let spec_b = AdapterSpec::EthereumSync {
            network: "sepolia".to_string(),
            committee: Some(committee_b.clone()),
        };
        let adapter_id = spec_a.build(Some(test_bls()), None).descriptor().id;
        // Declared ceiling is 1_000_000 (required bond = 100_000); poster posts
        // 150_000 atoms so live bond < declared ceiling, proving the certificate
        // caps value outflow by the posted collateral (150_000) rather than 1_000_000.
        let economics = IntakeState::conservative_economics(1_000_000);
        let posted_bond = 150_000u128;

        let req_a = RegistrationRequest {
            spec: spec_a.clone(),
            policy: VerificationPolicy::strict(1_000),
            economics,
            versions: VersionPolicy::single(adapter_id, 2, 0),
            bond_atoms: posted_bond,
            poster: poster_a,
            golden: sepolia_evidence(poster_a, &committee_a, 64, [0xc1; 32]),
        };

        // 1. Governance-voted `Register` on Sepolia with no governance vote fails closed.
        let unpinned_err = execute_external_domain_tx(
            &mut state,
            &ctx(poster_a),
            &ExternalDomainTx::Register(Box::new(req_a.clone())),
        )
        .expect_err("governance-voted registration without a vote must fail closed");
        assert!(
            matches!(unpinned_err, ExternalDomainTxError::Intake(ref msg) if msg.contains("no sync committee is pinned")),
            "unexpected error: {unpinned_err:?}"
        );
        assert!(state
            .settlement
            .external_intake
            .pinned_ethereum_committees
            .is_empty());

        // 2. Signed `RegisterBonded` registers Sepolia with zero governance vote,
        //    and a second distinct anchor on Sepolia yields a distinct `DomainKey`.
        execute_external_domain_tx(
            &mut state,
            &ctx(poster_a),
            &ExternalDomainTx::RegisterBonded(Box::new(BondedRegistrationRequest {
                request: req_a,
                challenge_window_heights: 15,
            })),
        )
        .expect("Sepolia bonded registration must succeed without governance vote");

        let req_b = RegistrationRequest {
            spec: spec_b.clone(),
            policy: VerificationPolicy::strict(1_000),
            economics,
            versions: VersionPolicy::single(adapter_id, 2, 0),
            bond_atoms: posted_bond,
            poster: poster_b,
            golden: sepolia_evidence(poster_b, &committee_b, 64, [0xc2; 32]),
        };
        execute_external_domain_tx(
            &mut state,
            &ctx(poster_b),
            &ExternalDomainTx::RegisterBonded(Box::new(BondedRegistrationRequest {
                request: req_b,
                challenge_window_heights: 15,
            })),
        )
        .expect("second distinct Sepolia bonded anchor must coexist cleanly");

        let digest_a = spec_a.bonded_anchor_digest().expect("digest a");
        let digest_b = spec_b.bonded_anchor_digest().expect("digest b");
        let key_a = DomainKey::from_bonded_anchor(&adapter_id, "sepolia", &digest_a);
        let key_b = DomainKey::from_bonded_anchor(&adapter_id, "sepolia", &digest_b);
        let voted_key = DomainKey::from_parts(&adapter_id, "sepolia");
        assert_ne!(
            key_a, key_b,
            "distinct bonded anchors must produce distinct DomainKeys"
        );
        assert_ne!(
            key_a, voted_key,
            "bonded DomainKey must not collide with governance-voted key"
        );
        assert!(state
            .settlement
            .external_intake
            .entries
            .contains_key(&key_a));
        assert!(state
            .settlement
            .external_intake
            .entries
            .contains_key(&key_b));

        // Before the challenge window matures, neither pending bonded domain is
        // exposed for live routing in `UniversalDomainCatalog`, and its routing
        // ceiling is zero.
        let catalog_pending = UniversalDomainCatalog::from_chain_state(&state);
        assert!(
            catalog_pending.list().is_empty(),
            "PendingAnchorChallenge domains must not be exposed in UniversalDomainCatalog before maturity"
        );
        assert_eq!(
            state
                .settlement
                .external_intake
                .certified_domain_envelope(&key_a)
                .expect("pending envelope")
                .economic_bound
                .routing_ceiling_atoms,
            0
        );

        // 3. Mature challenge window -> submit attestation -> verify catalog,
        //    profile, and envelope publish `AnchorClass::Bonded` and cap the
        //    effective routing ceiling to `posted_bond` (150_000 < 1_000_000).
        state.settlement.external_intake.on_block_committed(15);
        let catalog_matured = UniversalDomainCatalog::from_chain_state(&state);
        assert!(
            catalog_matured.list().len() >= 2,
            "matured bonded Sepolia domains must coexist in UniversalDomainCatalog without CAIP-2 collision"
        );
        let att_ev = sepolia_evidence(poster_a, &committee_a, 128, [0xd1; 32]);
        let att = state
            .settlement
            .external_intake
            .submit_evidence_for_domain(&key_a, &att_ev, Some(test_bls()))
            .expect("matured Sepolia bonded domain must accept valid finality evidence");
        assert_eq!(att.domain, key_a);

        let reg_a = state
            .settlement
            .external_intake
            .registry
            .domain(&key_a)
            .expect("registered");
        let profile = profile_of(&reg_a.record);
        assert_eq!(
            profile.anchor_class,
            AnchorClass::Bonded {
                anchor_digest: digest_a,
                challenge_until_height: 15,
            }
        );
        assert!(profile.summary_line().contains("anchor_class=bonded"));

        let envelope = state
            .settlement
            .external_intake
            .certified_domain_envelope(&key_a)
            .expect("certified envelope");
        assert_eq!(envelope.anchor_class, profile.anchor_class);
        assert_eq!(envelope.state, DomainState::Active);
        assert_eq!(
            envelope.economic_bound.routing_ceiling_atoms, posted_bond,
            "bonded anchor effective routing ceiling must be capped by live collateral (150_000 < 1_000_000)"
        );
        assert_eq!(
            envelope.economic_bound.safe_value_outflow_ceiling_atoms, 0,
            "Altair sync-committee attestation carries no event_root or protocol slashing"
        );
    }

    #[test]
    fn bonded_anchor_challenge_window_blocks_routing_slashes_fraud_and_activates_honest_anchor() {
        let dishonest = addr(0x61);
        let honest = addr(0x62);
        let challenger = addr(0x63);
        let mut state = AccountState::new();
        let initial_bond = bond();
        state.add_balance(&dishonest, initial_bond + 1_000);
        state.add_balance(&honest, initial_bond + 1_000);
        state.add_balance(&challenger, 1_000);

        let bad_committee = PinnedCommittee {
            period: 0,
            aggregate_pubkey: vec![0x71; 96],
            next_committee_root: [0xe1; 32],
        };
        let good_committee = PinnedCommittee {
            period: 0,
            aggregate_pubkey: vec![0x72; 96],
            next_committee_root: [0xe2; 32],
        };
        let bad_spec = AdapterSpec::EthereumSync {
            network: "sepolia".to_string(),
            committee: Some(bad_committee.clone()),
        };
        let good_spec = AdapterSpec::EthereumSync {
            network: "sepolia".to_string(),
            committee: Some(good_committee.clone()),
        };
        let adapter_id = bad_spec.build(Some(test_bls()), None).descriptor().id;
        let economics = IntakeState::conservative_economics(1_000_000);

        execute_external_domain_tx(
            &mut state,
            &ctx(dishonest),
            &ExternalDomainTx::RegisterBonded(Box::new(BondedRegistrationRequest {
                request: RegistrationRequest {
                    spec: bad_spec.clone(),
                    policy: VerificationPolicy::strict(1_000),
                    bond_atoms: economics.required_bond_atoms(),
                    economics,
                    versions: VersionPolicy::single(adapter_id, 2, 0),
                    poster: dishonest,
                    golden: sepolia_evidence(dishonest, &bad_committee, 64, [0xa1; 32]),
                },
                challenge_window_heights: 20,
            })),
        )
        .expect("dishonest bonded registration enters challenge window");

        execute_external_domain_tx(
            &mut state,
            &ctx(honest),
            &ExternalDomainTx::RegisterBonded(Box::new(BondedRegistrationRequest {
                request: RegistrationRequest {
                    spec: good_spec.clone(),
                    policy: VerificationPolicy::strict(1_000),
                    bond_atoms: economics.required_bond_atoms(),
                    economics,
                    versions: VersionPolicy::single(adapter_id, 2, 0),
                    poster: honest,
                    golden: sepolia_evidence(honest, &good_committee, 64, [0xb1; 32]),
                },
                challenge_window_heights: 20,
            })),
        )
        .expect("honest bonded registration enters challenge window");

        let bad_key = DomainKey::from_bonded_anchor(
            &adapter_id,
            "sepolia",
            &bad_spec.bonded_anchor_digest().unwrap(),
        );
        let good_key = DomainKey::from_bonded_anchor(
            &adapter_id,
            "sepolia",
            &good_spec.bonded_anchor_digest().unwrap(),
        );

        // 1. Inside the challenge window (`height = 10 < 20`), both sit in
        //    `PendingAnchorChallenge`, carry zero value ceiling, refuse evidence,
        //    and refuse `Readmit` window-skip attempts.
        state.settlement.external_intake.on_block_committed(10);
        for k in [bad_key, good_key] {
            let env = state
                .settlement
                .external_intake
                .certified_domain_envelope(&k)
                .expect("envelope");
            assert_eq!(env.state, DomainState::PendingAnchorChallenge);
            assert!(!env.state.serves());
            assert_eq!(env.economic_bound.safe_value_outflow_ceiling_atoms, 0);
        }
        let early_ev = sepolia_evidence(honest, &good_committee, 96, [0xb2; 32]);
        let not_serving = state
            .settlement
            .external_intake
            .submit_evidence_for_domain(&good_key, &early_ev, Some(test_bls()))
            .expect_err("evidence during PendingAnchorChallenge must be refused");
        assert!(not_serving.to_string().contains("pending-anchor-challenge"));

        let skip_err = execute_external_domain_tx(
            &mut state,
            &ctx(dishonest),
            &ExternalDomainTx::Readmit {
                domain: bad_key,
                reason: "try skipping challenge window".to_string(),
            },
        )
        .expect_err("Readmit must not skip PendingAnchorChallenge");
        assert!(skip_err.to_string().contains("pending-anchor-challenge"));

        // 2. Self-challenge and identical-root challenge are refused without mutating state.
        let self_proof = BondedAnchorChallengeProof::ConflictingFinality(Box::new(
            sepolia_evidence(dishonest, &bad_committee, 64, [0xa9; 32]),
        ));
        let self_err = execute_external_domain_tx(
            &mut state,
            &ctx(dishonest),
            &ExternalDomainTx::ChallengeBondedAnchor {
                domain: bad_key,
                proof: Box::new(self_proof),
            },
        )
        .expect_err("self-challenge must be forbidden");
        assert!(self_err.to_string().contains("cannot challenge its own"));

        let same_root_proof = BondedAnchorChallengeProof::ConflictingFinality(Box::new(
            sepolia_evidence(challenger, &bad_committee, 64, [0xa1; 32]),
        ));
        let same_err = execute_external_domain_tx(
            &mut state,
            &ctx(challenger),
            &ExternalDomainTx::ChallengeBondedAnchor {
                domain: bad_key,
                proof: Box::new(same_root_proof),
            },
        )
        .expect_err("non-conflicting root must be refused");
        assert!(same_err.to_string().contains("same state_root"));

        // 3. Valid conflicting finality proof drops `bad_key` to `Faulted`,
        //    slashes 100% of `dishonest`'s escrowed bond, and rewards `challenger`.
        let challenger_before = state.spendable_balance(&challenger);
        let valid_fraud = BondedAnchorChallengeProof::ConflictingFinality(Box::new(
            sepolia_evidence(challenger, &bad_committee, 64, [0xfe; 32]),
        ));
        execute_external_domain_tx(
            &mut state,
            &ctx(challenger),
            &ExternalDomainTx::ChallengeBondedAnchor {
                domain: bad_key,
                proof: Box::new(valid_fraud),
            },
        )
        .expect("conflicting finality proof must take down dishonest bonded anchor");

        let bad_reg = state
            .settlement
            .external_intake
            .registry
            .domain(&bad_key)
            .expect("bad_reg");
        assert_eq!(bad_reg.record.state, DomainState::Faulted);
        assert_eq!(bad_reg.record.bond_atoms, 0);
        assert_eq!(
            state
                .external_bond_escrow
                .get(&dishonest)
                .copied()
                .unwrap_or(0),
            0,
            "dishonest registrant's entire escrowed bond must be slashed"
        );
        assert!(
            state.spendable_balance(&challenger) > challenger_before,
            "challenger must receive the slash reward"
        );

        // 4. At height 19 `good_key` is still pending; at height 20 it promotes to
        //    `Admitted` while `bad_key` stays `Faulted` and cannot be readmitted.
        state.settlement.external_intake.on_block_committed(19);
        assert_eq!(
            state
                .settlement
                .external_intake
                .registry
                .domain(&good_key)
                .unwrap()
                .record
                .state,
            DomainState::PendingAnchorChallenge
        );

        state.settlement.external_intake.on_block_committed(20);
        assert_eq!(
            state
                .settlement
                .external_intake
                .registry
                .domain(&good_key)
                .unwrap()
                .record
                .state,
            DomainState::Admitted
        );
        assert_eq!(
            state
                .settlement
                .external_intake
                .registry
                .domain(&bad_key)
                .unwrap()
                .record
                .state,
            DomainState::Faulted
        );

        // Refuted bonded anchor can never be readmitted even after top-up.
        state.add_balance(&dishonest, initial_bond + 1_000);
        execute_external_domain_tx(
            &mut state,
            &ctx(dishonest),
            &ExternalDomainTx::BondProver {
                domain: bad_key,
                bond_atoms: economics.required_bond_atoms(),
            },
        )
        .expect_err("already-bonded registrant cannot reset bond");

        // Honest matured domain now serves attestations and carries live value ceiling.
        let post_window_ev = sepolia_evidence(honest, &good_committee, 128, [0xb3; 32]);
        execute_external_domain_tx(
            &mut state,
            &ctx(honest),
            &ExternalDomainTx::SubmitEvidence(Box::new(post_window_ev)),
        )
        .expect("matured honest bonded domain must accept SubmitEvidence");
        let good_env = state
            .settlement
            .external_intake
            .certified_domain_envelope(&good_key)
            .expect("good envelope");
        assert_eq!(good_env.state, DomainState::Active);
        assert_eq!(
            good_env.economic_bound.routing_ceiling_atoms,
            economics.required_bond_atoms()
        );
    }

    #[test]
    fn rollup_l1_mpt_op_and_zk_domains_execute_end_to_end_with_meet_and_da_verdicts() {
        use crate::cross_domain::external::da_sampling::{
            DaCommitteeMember, DataAvailabilityAdapter, PinnedDaCommittee,
        };
        use crate::cross_domain::external::rollup_l1::tests::{build_l1_fixture, u64_word};
        use crate::cross_domain::external::spec::ExternalFinalityAdapter;
        use crate::cross_domain::external::{
            RollupDaBinding, RollupDomainSpec, RollupProofModel, RollupRegistrationRequest,
            RollupStateProofSubmission,
        };
        use crate::crypto::facts::QuantumClass;
        use crate::unification::domain_catalog::{DomainCapability, UniversalDomainCatalog};

        let poster = addr(0x71);
        let prover = addr(0x72);
        let mut state = AccountState::new();
        let initial_bond = bond();
        state.add_balance(&poster, initial_bond * 4 + 10_000);
        state.add_balance(&prover, initial_bond * 2 + 10_000);

        let committee = PinnedCommittee {
            period: 0,
            aggregate_pubkey: vec![0x77; 96],
            next_committee_root: [0xe7; 32],
        };
        state
            .settlement
            .external_intake
            .pin_ethereum_committee("sepolia", committee.clone());
        let l1_spec = AdapterSpec::EthereumSync {
            network: "sepolia".to_string(),
            committee: Some(committee.clone()),
        };
        let l1_adapter_id = l1_spec.build(Some(test_bls()), None).descriptor().id;
        let economics = IntakeState::conservative_economics(1_000_000);
        execute_external_domain_tx(
            &mut state,
            &ctx(poster),
            &ExternalDomainTx::Register(Box::new(RegistrationRequest {
                spec: l1_spec,
                policy: VerificationPolicy::strict(1_000),
                bond_atoms: economics.required_bond_atoms(),
                economics,
                versions: VersionPolicy::single(l1_adapter_id, 2, 0),
                poster,
                golden: sepolia_evidence(poster, &committee, 64, [0xa0; 32]),
            })),
        )
        .expect("register L1 parent domain");
        let parent_key = DomainKey::from_parts(&l1_adapter_id, "sepolia");

        let op_contract = [0x31; 20];
        let op_state_slot = [0x01; 32];
        let op_height_slot = [0x02; 32];
        let op_ts_slot = [0x03; 32];
        let op_l2_root = [0xB1; 32];
        let (l1_root_op, op_code_hash, op_acct_proof, op_stor_proof) = build_l1_fixture(
            op_contract,
            b"OP_OUTPUT_ORACLE_V1",
            &[
                (op_state_slot, op_l2_root),
                (op_height_slot, u64_word(777)),
                (op_ts_slot, u64_word(1_400)),
            ],
        );

        execute_external_domain_tx(
            &mut state,
            &ctx(poster),
            &ExternalDomainTx::SubmitEvidence(Box::new(sepolia_evidence(
                poster, &committee, 128, l1_root_op,
            ))),
        )
        .expect("submit L1 slot 128");

        let op_spec = RollupDomainSpec {
            rollup_network: "op-sepolia".to_string(),
            parent_domain: parent_key,
            l1_rollup_contract: op_contract,
            expected_code_hash: Some(op_code_hash),
            state_root_slot: op_state_slot,
            batch_height_slot: op_height_slot,
            proof_model: RollupProofModel::OptimisticFaultProof {
                proposal_timestamp_slot: op_ts_slot,
                challenge_window_secs: 300,
            },
            da_binding: RollupDaBinding::ParentL1,
        };
        let op_key = op_spec.domain_key();
        execute_external_domain_tx(
            &mut state,
            &ctx(poster),
            &ExternalDomainTx::RegisterRollup(Box::new(RollupRegistrationRequest {
                spec: op_spec,
                economics,
                bond_atoms: economics.required_bond_atoms(),
                poster,
            })),
        )
        .expect("register OP rollup");

        execute_external_domain_tx(
            &mut state,
            &ctx(prover),
            &ExternalDomainTx::SubmitRollupStateProof(Box::new(RollupStateProofSubmission {
                rollup_domain: op_key,
                l1_height: 128,
                account_proof: op_acct_proof.clone(),
                state_root_proof: op_stor_proof.clone(),
                batch_height_proof: op_stor_proof.clone(),
                auxiliary_slot_proof: op_stor_proof.clone(),
                da_height: None,
                submitter: prover,
            })),
        )
        .expect("submit OP rollup proof inside challenge window");

        let op_early = state
            .settlement
            .external_intake
            .certified_rollup_row(&op_key)
            .expect("OP row recorded");
        assert!(!op_early.both_established());
        assert_eq!(op_early.value_routing_ceiling_atoms, 0);
        assert_eq!(
            op_early.verdict_summary(),
            "finality=pending-challenge-window|da=established-parent-l1"
        );
        let catalog_early = UniversalDomainCatalog::from_chain_state(&state);
        assert!(catalog_early
            .list()
            .into_iter()
            .filter(|d| d.name == "Rollup-op-sepolia")
            .all(|d| !d
                .capabilities
                .contains(&DomainCapability::OutputComposition)));

        execute_external_domain_tx(
            &mut state,
            &ctx(poster),
            &ExternalDomainTx::SubmitEvidence(Box::new(sepolia_evidence(
                poster, &committee, 512, l1_root_op,
            ))),
        )
        .expect("submit L1 slot 512");
        execute_external_domain_tx(
            &mut state,
            &ctx(prover),
            &ExternalDomainTx::SubmitRollupStateProof(Box::new(RollupStateProofSubmission {
                rollup_domain: op_key,
                l1_height: 512,
                account_proof: op_acct_proof,
                state_root_proof: op_stor_proof.clone(),
                batch_height_proof: op_stor_proof.clone(),
                auxiliary_slot_proof: op_stor_proof,
                da_height: None,
                submitter: prover,
            })),
        )
        .expect("submit OP rollup proof after challenge window");

        let op_matured = state
            .settlement
            .external_intake
            .certified_rollup_row(&op_key)
            .expect("matured OP row");
        assert!(op_matured.both_established());
        assert!(op_matured.value_routing_ceiling_atoms > 0);
        assert_eq!(
            op_matured.verdict_summary(),
            "finality=established|da=established-parent-l1"
        );
        let catalog_matured = UniversalDomainCatalog::from_chain_state(&state);
        assert!(catalog_matured
            .list()
            .into_iter()
            .any(|d| d.name == "Rollup-op-sepolia"
                && d.capabilities
                    .contains(&DomainCapability::OutputComposition)));

        let sk_da = [0x44u8; 32];
        let vk_da = ed25519_dalek::SigningKey::from_bytes(&sk_da)
            .verifying_key()
            .to_bytes();
        let da_committee = PinnedDaCommittee {
            namespace_id: [0x5A; 32],
            min_samples: 2,
            min_square_size: 2,
            members: vec![DaCommitteeMember {
                ed25519_pubkey: vk_da,
                voting_weight: 100,
                pq_pubkey: Vec::new(),
            }],
        };
        let da_adapter = DataAvailabilityAdapter::new("celestia-mocha", Some(da_committee.clone()));
        let da_adapter_id = da_adapter.descriptor().id;
        let da_key = DomainKey::from_parts(&da_adapter_id, "celestia-mocha");
        state
            .settlement
            .external_intake
            .pinned_da_committees
            .insert("celestia-mocha".to_string(), da_committee.clone());
        let da_spec = AdapterSpec::DataAvailability {
            network: "celestia-mocha".to_string(),
            committee: Some(da_committee),
        };
        let dummy_golden = RawConsensusEvidence {
            adapter: da_adapter_id,
            evidence_version: 1,
            network: "celestia-mocha".to_string(),
            payload: vec![1, 2, 3],
            declared_height: 1,
            declared_root: [0x51; 32],
            submitter: poster,
        };
        let fake_report = crate::cross_domain::external::AdmissionReport {
            adapter_version: da_adapter.descriptor().adapter_version,
            evidence_version: 1,
            golden_verified: true,
            probes: vec![(
                "probe".to_string(),
                crate::cross_domain::external::ProbeOutcome::Refused {
                    kind: crate::cross_domain::external::RefusalKind::Malformed,
                },
            )],
            probe_commitment: [0x11; 32],
            admitted: true,
        };
        state
            .settlement
            .external_intake
            .registry
            .register(
                "celestia-mocha",
                da_adapter.descriptor(),
                economics,
                VersionPolicy::single(da_adapter_id, 1, 0),
                &fake_report,
                economics.required_bond_atoms(),
                poster,
            )
            .expect("register DA domain");
        state.settlement.external_intake.entries.insert(
            da_key,
            crate::cross_domain::external::IntakeEntry {
                spec: da_spec,
                policy: VerificationPolicy::strict(1_000),
                admission: fake_report,
                golden: dummy_golden,
                registrant: poster,
            },
        );

        let zk_contract = [0x32; 20];
        let zk_state_slot = [0x11; 32];
        let zk_height_slot = [0x12; 32];
        let zk_prog_slot = [0x13; 32];
        let zk_vk = [0x91; 32];
        let zk_l2_root = [0xC2; 32];
        let (l1_root_zk, zk_code_hash, zk_acct_proof, zk_stor_proof) = build_l1_fixture(
            zk_contract,
            b"ZK_VALIDITY_VERIFIER_V1",
            &[
                (zk_state_slot, zk_l2_root),
                (zk_height_slot, u64_word(999)),
                (zk_prog_slot, zk_vk),
            ],
        );
        execute_external_domain_tx(
            &mut state,
            &ctx(poster),
            &ExternalDomainTx::SubmitEvidence(Box::new(sepolia_evidence(
                poster, &committee, 640, l1_root_zk,
            ))),
        )
        .expect("submit L1 slot 640 for ZK rollup");

        let zk_spec = RollupDomainSpec {
            rollup_network: "zksync-era".to_string(),
            parent_domain: parent_key,
            l1_rollup_contract: zk_contract,
            expected_code_hash: Some(zk_code_hash),
            state_root_slot: zk_state_slot,
            batch_height_slot: zk_height_slot,
            proof_model: RollupProofModel::ValidityProof {
                verifier_program_commitment: zk_vk,
                program_commitment_slot: Some(zk_prog_slot),
                quantum_posture: QuantumClass::Hash,
            },
            da_binding: RollupDaBinding::ExternalDaDomain {
                da_domain: da_key,
                min_samples: 2,
            },
        };
        let zk_key = zk_spec.domain_key();
        execute_external_domain_tx(
            &mut state,
            &ctx(poster),
            &ExternalDomainTx::RegisterRollup(Box::new(RollupRegistrationRequest {
                spec: zk_spec,
                economics,
                bond_atoms: economics.required_bond_atoms(),
                poster,
            })),
        )
        .expect("register ZK rollup");

        execute_external_domain_tx(
            &mut state,
            &ctx(prover),
            &ExternalDomainTx::SubmitRollupStateProof(Box::new(RollupStateProofSubmission {
                rollup_domain: zk_key,
                l1_height: 640,
                account_proof: zk_acct_proof.clone(),
                state_root_proof: zk_stor_proof.clone(),
                batch_height_proof: zk_stor_proof.clone(),
                auxiliary_slot_proof: zk_stor_proof.clone(),
                da_height: Some(77),
                submitter: prover,
            })),
        )
        .expect("submit ZK rollup proof while DA pending");

        let zk_pending_da = state
            .settlement
            .external_intake
            .certified_rollup_row(&zk_key)
            .expect("ZK row");
        assert!(zk_pending_da.finality_verdict.is_established());
        assert!(!zk_pending_da.da_verdict.is_established());
        assert_eq!(zk_pending_da.value_routing_ceiling_atoms, 0);
        assert_eq!(
            zk_pending_da.verdict_summary(),
            "finality=established|da=pending"
        );
        let digest_before = state
            .settlement
            .external_intake
            .state_digest()
            .expect("state_digest");

        state
            .settlement
            .external_intake
            .registry
            .commit_attestation(
                &crate::cross_domain::external::FinalityAttestation {
                    adapter: da_adapter_id,
                    domain: da_key,
                    height: 77,
                    state_root: [0xD4; 32],
                    finalized_at: 1_700_000_077,
                    time_unit: crate::cross_domain::external::spec::TimeUnit::UnixSeconds,
                    security: crate::cross_domain::external::SecurityBacking::SignatureSet {
                        scheme: crate::crypto::facts::ObservedScheme::Scheme(
                            crate::crypto::scheme::SchemeId::ED25519,
                        ),
                        signers: 1,
                        required: 1,
                        total_weight: 100,
                        slashable: true,
                    },
                    evidence_digest: [0xE1; 32],
                    adapter_version: 1,
                    evidence_version: 1,
                    attested_block_hash: None,
                    attested_event_root: None,
                    attested_tx_root: None,
                },
                poster,
            )
            .expect("commit DA attestation at height 77");

        execute_external_domain_tx(
            &mut state,
            &ctx(prover),
            &ExternalDomainTx::SubmitRollupStateProof(Box::new(RollupStateProofSubmission {
                rollup_domain: zk_key,
                l1_height: 640,
                account_proof: zk_acct_proof,
                state_root_proof: zk_stor_proof.clone(),
                batch_height_proof: zk_stor_proof.clone(),
                auxiliary_slot_proof: zk_stor_proof,
                da_height: Some(77),
                submitter: prover,
            })),
        )
        .expect("re-submit ZK rollup proof with DA height 77 attested");

        let zk_established = state
            .settlement
            .external_intake
            .certified_rollup_row(&zk_key)
            .expect("ZK row established");
        assert!(zk_established.both_established());
        assert!(zk_established.value_routing_ceiling_atoms > 0);
        assert_eq!(
            zk_established.verdict_summary(),
            "finality=established|da=established-sampled"
        );
        let digest_after = state
            .settlement
            .external_intake
            .state_digest()
            .expect("state_digest");
        assert_ne!(digest_before, digest_after);
    }
}
