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
//! Slashing a prover is not a door here. The registry's `slash` takes the
//! challenger's word that an accepted attestation was wrong; there is no
//! contradiction proof format yet, and a door that slashes on a claim would
//! let anyone take any carrier's bond. `bud_slashExternalProver` stays
//! refused until a proof that an attestation was false is defined.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::cross_domain::external::ethereum::BlsVerifier;
use crate::cross_domain::external::intake::{AdapterSpec, IntakeError, RegistrationRequest};
use crate::cross_domain::external::quorum::QuorumPolicy;
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
/// exposed for execute_external_domain_tx: the executor's ExternalDomain arm reports it by its message, not by name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExternalDomainTxError {
    #[error("external domains are not enabled on mainnet")]
    MainnetDisabled,
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
            state
                .settlement
                .external_intake
                .set_quorum_policy(domain, *policy)
                .map_err(ExternalDomainTxError::from)
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
    let balance = state.get_balance(&ctx.sender);
    let needed = bond.saturating_add(ctx.fee);
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

fn register(
    state: &mut AccountState,
    ctx: &ExternalDomainTxContext,
    request: &RegistrationRequest,
) -> Result<(), ExternalDomainTxError> {
    if request.poster != ctx.sender {
        return Err(ExternalDomainTxError::PosterIsNotSender);
    }
    let bond = fundable_bond(state, ctx, request.bond_atoms)?;
    let bls = bls_for(&request.spec, ctx);
    // The bond is locked first, from a balance already checked to hold it
    // and the fee, and handed back if the intake refuses: a registration
    // never stands without the bond behind it.
    state
        .lock_external_bond(&ctx.sender, bond)
        .map_err(ExternalDomainTxError::Intake)?;
    if let Err(e) = state
        .settlement
        .external_intake
        .register_domain(request.clone(), bls)
    {
        state
            .release_external_bond(&ctx.sender, bond)
            .map_err(ExternalDomainTxError::Intake)?;
        return Err(e.into());
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
    let key = DomainKey::from_parts(&evidence.adapter, &evidence.network);
    let intake = &mut state.settlement.external_intake;
    let Some(entry) = intake.entries.get(&key) else {
        return Err(ExternalDomainTxError::UnknownDomain);
    };
    let bls = bls_for(&entry.spec, ctx);
    let before = intake.clone();
    match intake.submit_evidence(evidence, bls) {
        // Accepted, or entered a quorum round that has not decided yet: both
        // are recorded states.
        Ok(_) | Err(IntakeError::RoundPending) => Ok(()),
        // The registry recorded the refusal: an accepted transaction.
        Err(_) if *intake != before => Ok(()),
        Err(e) => Err(e.into()),
    }
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
    if reason.len() > MAX_READMIT_REASON_BYTES {
        return Err(ExternalDomainTxError::ReasonTooLong {
            len: reason.len(),
            max: MAX_READMIT_REASON_BYTES,
        });
    }
    require_registrant(state, ctx, domain)?;
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
    let admission = crate::cross_domain::external::admit(adapter.as_ref(), &entry.policy);
    intake
        .registry
        .readmit(domain, &admission, reason)
        .map_err(|e| ExternalDomainTxError::Intake(e.to_string()))?;
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
    let intake = &mut state.settlement.external_intake;
    let Some(reg) = intake.registry.domain(domain) else {
        return Err(ExternalDomainTxError::UnknownDomain);
    };
    let mut versions = reg.versions.clone();
    // The fork lands only on a version the adapter itself accepts
    // (BLG-0161): the registration's accepted list is policy output and
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::external::ethereum::{layout, PinnedCommittee};
    use crate::cross_domain::external::intake::IntakeState;
    use crate::cross_domain::external::spec::VerificationPolicy;
    use crate::cross_domain::external::versioning::VersionPolicy;
    use crate::cross_domain::external::DomainState;

    const TESTNET: u64 = 45261;

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
            chain_id: TESTNET,
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
        let mut payload = vec![0u8; layout::LEN];
        payload[layout::FINALIZED_ROOT].copy_from_slice(&[0xaa; 32]);
        payload[layout::FINALIZED_SLOT].copy_from_slice(&height.to_le_bytes());
        payload[layout::ATTESTED_SLOT].copy_from_slice(&(height * 2).to_le_bytes());
        payload[layout::PERIOD].copy_from_slice(&0u64.to_le_bytes());
        payload[layout::NEXT_COMMITTEE_ROOT].copy_from_slice(&[0xbb; 32]);
        payload[layout::AGGREGATE_PUBKEY].copy_from_slice(&[0x11; 96]);
        payload[layout::SIGNATURE].copy_from_slice(&[0x22; 96]);
        payload[layout::PARTICIPATION_BITS].copy_from_slice(&[0xff; 64]);
        payload[layout::STATE_ROOT].copy_from_slice(&root);
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
        let mut bad = request(poster);
        // A golden sample with no signers cannot verify: admission refuses.
        bad.golden.payload[layout::PARTICIPATION_BITS].copy_from_slice(&[0x00; 64]);
        let tx = ExternalDomainTx::Register(Box::new(bad));
        let err = execute_external_domain_tx(&mut state, &ctx(poster), &tx).unwrap_err();
        assert!(matches!(err, ExternalDomainTxError::Intake(_)), "{err}");
        assert!(state.settlement.is_empty());
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
}
