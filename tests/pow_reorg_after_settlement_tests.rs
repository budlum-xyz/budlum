//! PoW reorg after settlement (R11, Reddit `zomerbk`): for a `PoW` domain
//! "settled" is probabilistic (`FinalityReversibility::ProbabilisticWork`),
//! so a rival root at the accepted height must freeze the domain, take it
//! out of the `established` bucket of every later checkpoint certificate,
//! keep every previously applied commitment in place (settlement never rolls
//! back), and never treat two rival roots at one height as equivalent.
//!
//! Integration level on purpose: `src/settlement/domains.rs` is owned by
//! another lock. This file drives only the public settlement door
//! (`execute_settlement_tx`), the state-derived certificate
//! (`SettlementRegistries::universal_finality_certificate`) and the public
//! value contract (`FinalityGuarantee::admits_cross_domain_value`, whose
//! `MIN_VALUE_SAFE_POW_CONFIRMATIONS` threshold this test pins to 6).
//!
//! Free helpers here sit outside `clippy.toml`'s `allow-expect-in-tests`
//! scope, so they panic with `if let Err` instead of `expect()`.

use budlum_core::core::account::AccountState;
use budlum_core::core::address::Address;
use budlum_core::domain::producer::{build_pow_commitment, PowBlockContent, PowChainSpec};
use budlum_core::domain::registry::MIN_DOMAIN_OPERATOR_BOND;
use budlum_core::domain::types::DomainStatus;
use budlum_core::domain::{
    default_domain, ConsensusDomain, ConsensusKind, VerifiedDomainCommitment,
    POW_HEADER_CHAIN_ADAPTER, PoWDomainParameters,
};
use budlum_core::registry::role::roles::RELAYER;
use budlum_core::settlement::domains::{
    execute_settlement_tx, SettlementTx, SettlementTxContext, SettlementTxError,
};
use budlum_core::settlement::universal_finality::{
    FinalityGuarantee, FinalityReversibility, FinalityVerdict,
};

const HUB_CHAIN_ID: u64 = 45_262;
const FEE_ATOMS: u64 = 1_000;
const CHECKPOINT_HEIGHT: u64 = 100;
const POW_DOMAIN_ID: u32 = 101;
const POW_CHAIN_ID: u64 = 9_101;
const POW_CHAIN_2_ID: u32 = 102;
const POW_CHAIN_2: u64 = 9_102;
/// `MIN_VALUE_SAFE_POW_CONFIRMATIONS`: the depth at which probabilistic PoW
/// finality may carry cross-domain value without slashable stake.
const VALUE_SAFE_CONFIRMATIONS: u64 = 6;

fn tx_ctx(sender: Address) -> SettlementTxContext {
    SettlementTxContext {
        sender,
        chain_id: HUB_CHAIN_ID,
        fee: FEE_ATOMS,
        bls: budlum_core::cross_domain::external::IntakeState::production_bls,
    }
}

fn pow_domain(id: u32, chain_id: u64, min_confirmations: u64) -> ConsensusDomain {
    let mut domain = default_domain(
        id,
        ConsensusKind::PoW,
        chain_id,
        POW_HEADER_CHAIN_ADAPTER,
        min_confirmations,
    );
    domain.config_hash = [0x11; 32];
    domain.pow_parameters = Some(PoWDomainParameters {
        min_difficulty_bits: 1,
        max_difficulty_bits: 16,
        min_cumulative_work: 4,
        max_headers: 8,
    });
    domain
}

fn funded_state_with_relayer() -> (AccountState, Address, Address) {
    let mut state = AccountState::default();
    state.current_block_height = CHECKPOINT_HEIGHT;
    let operator = Address::from([0xA1; 32]);
    let relayer = Address::from([0xB2; 32]);
    state.get_or_create(&operator).balance = 50_000_000_000;
    state.get_or_create(&relayer).balance = 50_000_000_000;
    let min_relayer_stake = state.registry.params().min_stake.max(10_000);
    if let Err(err) = state.registry.register(relayer, RELAYER, min_relayer_stake, 0) {
        panic!("relayer registration must succeed: {err}");
    }
    // The commitment door requires its sender to be an active RELAYER; the
    // tests submit as the domain operator, so the operator carries the role.
    if let Err(err) = state.registry.register(operator, RELAYER, min_relayer_stake, 0) {
        panic!("operator relayer registration must succeed: {err}");
    }
    (state, operator, relayer)
}

fn register_pow(state: &mut AccountState, operator: Address, domain: ConsensusDomain) {
    let mut domain = domain;
    domain.operator = Some(operator);
    domain.operator_bond = MIN_DOMAIN_OPERATOR_BOND.max(100_000);
    domain.last_committed_height = 0;
    domain.last_committed_hash = [0u8; 32];
    if let Err(err) = execute_settlement_tx(
        state,
        &tx_ctx(operator),
        &SettlementTx::RegisterDomain(Box::new(domain)),
    ) {
        panic!("domain registration must succeed: {err:?}");
    }
}

/// A valid deep header chain whose roots carry `marker`, so two calls with
/// different markers are two rival chains of the same height.
fn pow_commitment(
    state: &AccountState,
    operator: Address,
    domain_id: u32,
    height: u64,
    marker: u8,
) -> Box<VerifiedDomainCommitment> {
    let registered = match state.settlement.domains.get(domain_id) {
        Some(domain) => domain.clone(),
        None => panic!("domain {domain_id} must be registered first"),
    };
    let blocks = (0..8u8)
        .map(|i| {
            let m = marker.wrapping_add(i);
            PowBlockContent {
                timestamp_ms: 1_700_000_000_000u128 + u128::from(i) * 1_000,
                state_root: [m; 32],
                tx_root: [m.wrapping_add(0x10); 32],
                event_root: [m.wrapping_add(0x20); 32],
            }
        })
        .collect();
    match build_pow_commitment(&PowChainSpec {
        domain: registered,
        parent_hash: [0u8; 32],
        height,
        difficulty_bits: 1,
        sequence: 0,
        producer: Some(operator),
        blocks,
    }) {
        Ok(built) => Box::new(built),
        Err(err) => panic!("a well-formed PoW header chain must build: {err}"),
    }
}

fn submit_commitment(
    state: &mut AccountState,
    sender: Address,
    commitment: Box<VerifiedDomainCommitment>,
) -> Result<(), SettlementTxError> {
    execute_settlement_tx(
        state,
        &tx_ctx(sender),
        &SettlementTx::SubmitCommitment(commitment),
    )
}

#[test]
fn six_confirmations_admit_cross_domain_value_and_five_do_not() {
    let deep = pow_domain(POW_DOMAIN_ID, POW_CHAIN_ID, VALUE_SAFE_CONFIRMATIONS);
    let deep_guarantee = FinalityGuarantee::for_domain(&deep, false);
    assert_eq!(
        deep_guarantee.reversibility,
        FinalityReversibility::ProbabilisticWork {
            confirmations: VALUE_SAFE_CONFIRMATIONS
        },
        "a PoW domain's guarantee carries its confirmation depth"
    );
    assert!(
        deep_guarantee.admits_cross_domain_value(),
        "{VALUE_SAFE_CONFIRMATIONS} confirmations clear the PoW value threshold"
    );

    let shallow = pow_domain(POW_DOMAIN_ID, POW_CHAIN_ID, VALUE_SAFE_CONFIRMATIONS - 1);
    assert!(
        !FinalityGuarantee::for_domain(&shallow, false).admits_cross_domain_value(),
        "one confirmation below the threshold must not open the value path"
    );
}

#[test]
fn a_rival_root_at_the_accepted_height_freezes_the_domain_without_rolling_back() {
    let (mut state, operator, _relayer) = funded_state_with_relayer();
    register_pow(
        &mut state,
        operator,
        pow_domain(POW_DOMAIN_ID, POW_CHAIN_ID, VALUE_SAFE_CONFIRMATIONS),
    );

    // 1. A deep-enough PoW commitment is accepted and opens the value path.
    let commitment = pow_commitment(&state, operator, POW_DOMAIN_ID, 1, 0x21);
    submit_commitment(&mut state, operator, commitment)
    .expect("the first well-formed commitment must be accepted");
    let accepted_hash = state
        .settlement
        .domains
        .get(POW_DOMAIN_ID)
        .unwrap()
        .last_committed_hash;
    assert_eq!(
        state.settlement.domains.get(POW_DOMAIN_ID).unwrap().status,
        DomainStatus::Active
    );
    let before = state
        .settlement
        .universal_finality_certificate(CHECKPOINT_HEIGHT)
        .expect("a registered domain produces a checkpoint certificate");
    let row = before
        .established
        .iter()
        .find(|row| row.domain_id == POW_DOMAIN_ID)
        .expect("the accepted PoW commitment must sit in the established bucket");
    assert!(
        row.guarantee.admits_cross_domain_value(),
        "the established row must open the value path at {VALUE_SAFE_CONFIRMATIONS} confirmations"
    );

    // 2. A rival root at the SAME height contradicts the settled commitment.
    let commitment = pow_commitment(&state, operator, POW_DOMAIN_ID, 1, 0xEE);
    submit_commitment(&mut state, operator, commitment)
    .expect("the rival chain verifies as PoW; the freeze happens inside the door");
    let frozen = state.settlement.domains.get(POW_DOMAIN_ID).unwrap();
    assert_eq!(
        frozen.status,
        DomainStatus::Frozen,
        "a rival root at the accepted height must freeze the domain"
    );
    assert_eq!(
        frozen.last_committed_height, 1,
        "settlement never rolls back the applied height"
    );
    assert_eq!(
        frozen.last_committed_hash, accepted_hash,
        "settlement never rolls back the applied commitment hash"
    );

    // 3. The frozen domain leaves the value path: later certificates carry it
    // as Refuted, and the established bucket no longer includes it.
    let after = state
        .settlement
        .universal_finality_certificate(CHECKPOINT_HEIGHT)
        .expect("the frozen domain still appears, in the refuted bucket");
    assert!(
        after
            .established
            .iter()
            .all(|row| row.domain_id != POW_DOMAIN_ID),
        "a frozen domain must not stay in the established bucket"
    );
    let refuted_row = after
        .refuted
        .iter()
        .find(|row| row.domain_id == POW_DOMAIN_ID)
        .expect("the frozen domain must be refuted in every later certificate");
    assert!(
        matches!(refuted_row.verdict, FinalityVerdict::Refuted { .. }),
        "the refuted bucket carries an explicit rejection verdict"
    );

    // 4. The value door stays closed: no further commitment is accepted for
    // the frozen domain.
    let commitment = pow_commitment(&state, operator, POW_DOMAIN_ID, 2, 0x21);
    let err = submit_commitment(&mut state, operator, commitment)
        .expect_err("a frozen domain must refuse every later commitment");
    assert!(
        matches!(&err, SettlementTxError::Refused(msg) if msg.contains("frozen")),
        "the refusal must name the frozen status, got: {err:?}"
    );
}

#[test]
fn two_rival_roots_at_one_height_are_never_both_accepted() {
    let (mut state, operator, _relayer) = funded_state_with_relayer();
    register_pow(
        &mut state,
        operator,
        pow_domain(POW_DOMAIN_ID, POW_CHAIN_ID, VALUE_SAFE_CONFIRMATIONS),
    );

    let commitment = pow_commitment(&state, operator, POW_DOMAIN_ID, 1, 0x21);
    submit_commitment(&mut state, operator, commitment)
    .unwrap();
    let first_hash = state
        .settlement
        .domains
        .get(POW_DOMAIN_ID)
        .unwrap()
        .last_committed_hash;

    // The rival at the same height must NOT be treated as an equivalent
    // (idempotent) resubmission: it freezes instead.
    let commitment = pow_commitment(&state, operator, POW_DOMAIN_ID, 1, 0xEE);
    submit_commitment(&mut state, operator, commitment)
    .unwrap();
    let domain = state.settlement.domains.get(POW_DOMAIN_ID).unwrap();
    assert_eq!(
        domain.status,
        DomainStatus::Frozen,
        "rival roots at one height are equivocation, never equivalence"
    );
    assert_eq!(
        domain.last_committed_hash, first_hash,
        "the rival must not overwrite the accepted root"
    );
}

#[test]
fn dependent_domains_do_not_silently_stay_established_after_a_freeze() {
    let (mut state, operator, _relayer) = funded_state_with_relayer();
    register_pow(
        &mut state,
        operator,
        pow_domain(POW_DOMAIN_ID, POW_CHAIN_ID, VALUE_SAFE_CONFIRMATIONS),
    );
    // A second domain registered but never committed: its own commitment is
    // still pending evidence, independent of the first domain.
    register_pow(
        &mut state,
        operator,
        pow_domain(POW_CHAIN_2_ID, POW_CHAIN_2, VALUE_SAFE_CONFIRMATIONS),
    );

    let commitment = pow_commitment(&state, operator, POW_DOMAIN_ID, 1, 0x21);
    submit_commitment(&mut state, operator, commitment)
    .unwrap();
    let commitment = pow_commitment(&state, operator, POW_DOMAIN_ID, 1, 0xEE);
    submit_commitment(&mut state, operator, commitment)
    .unwrap();
    assert_eq!(
        state.settlement.domains.get(POW_DOMAIN_ID).unwrap().status,
        DomainStatus::Frozen
    );

    let cert = state
        .settlement
        .universal_finality_certificate(CHECKPOINT_HEIGHT)
        .unwrap();
    assert_eq!(
        cert.established.len(),
        0,
        "no domain may stay established once the only committed domain is frozen"
    );
    assert!(
        cert.pending
            .iter()
            .any(|row| row.domain_id == POW_CHAIN_2_ID),
        "a dependent domain without its own evidence stays pending"
    );
    assert!(
        cert.guarantee.is_none(),
        "with no established leg the certificate carries no value-path guarantee"
    );
}
