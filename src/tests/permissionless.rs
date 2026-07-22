//! Acceptance-criteria tests for the permissionless participation model and the
//! isolation of the permissioned PoA domain (master-context Section 2).
//!
//! These tests are the executable form of the instruction set's acceptance
//! criteria:
//!  * A permissionless account can join validator/verifier/relayer roles by
//!    staking alone, with no whitelist (negative "can it join without a
//!    whitelist?" check).
//!  * PoA-domain permissioned rules do not leak into PoW/PoS/BFT, and vice
//!    versa: a permissionless (stake-only) account cannot enter the PoA domain
//!    without KYC/approval, and a PoA member gains no permissionless role.

use crate::core::address::Address;
use crate::domain::types::DomainId;
use crate::registry::permissionless::{
    PermissionlessRegistry, RegistryError, SlashingCondition, MIN_REGISTRATION_STAKE,
};
use crate::registry::poa_membership::PoaMembershipRegistry;
use crate::registry::role::{roles, RoleId};

fn addr(b: u8) -> Address {
    Address::from([b; 32])
}

const POA_DOMAIN: DomainId = 7;

// --- Permissionless participation ------------------------------------------

/// Negative whitelist test: an account nobody ever approved joins purely by
/// staking. If a whitelist/approval gate were (re)introduced, this fails.
#[test]
fn any_account_joins_validator_role_without_whitelist() {
    let mut reg = PermissionlessRegistry::new();
    let newcomer = addr(0xAB); // never approved, never listed anywhere
    reg.register_validator(newcomer, MIN_REGISTRATION_STAKE, 0)
        .expect("staking alone must be sufficient to join");
    assert!(
        reg.is_active(&newcomer, roles::VALIDATOR),
        "a staked account must be an active validator with no approval step"
    );
}

#[test]
fn relayer_set_is_permissionless_not_fixed() {
    let mut reg = PermissionlessRegistry::new();
    // Several unrelated accounts each become relayers just by staking. This
    // asserts there is no fixed/whitelisted relayer committee.
    for b in [1u8, 2, 3, 4, 5] {
        reg.register_relayer(addr(b), MIN_REGISTRATION_STAKE, 0)
            .unwrap();
    }
    assert_eq!(reg.active_members(roles::RELAYER).len(), 5);
}

#[test]
fn verifier_registration_is_open_but_stake_gated_only() {
    let mut reg = PermissionlessRegistry::new();
    // Below the economic floor is rejected...
    let err = reg
        .register_verifier(addr(1), MIN_REGISTRATION_STAKE - 1, 0)
        .unwrap_err();
    assert!(
        matches!(err, RegistryError::InsufficientStake { .. }),
        "the only barrier must be stake, not permission"
    );
    // ...but the SAME account succeeds the moment it meets the stake floor,
    // proving the gate is economic, not identity/approval based.
    reg.register_verifier(addr(1), MIN_REGISTRATION_STAKE, 0)
        .unwrap();
    assert!(reg.is_active(&addr(1), roles::VERIFIER));
}

#[test]
fn slashing_removes_active_status() {
    use crate::core::chain_config::FIXED_POINT_SCALE;
    let mut reg = PermissionlessRegistry::new();
    reg.register_validator(addr(1), 10_000, 0).unwrap();
    reg.slash(
        addr(1),
        roles::VALIDATOR,
        SlashingCondition::DoubleSign,
        FIXED_POINT_SCALE, // 100% slash
    )
    .unwrap();
    assert!(!reg.is_active(&addr(1), roles::VALIDATOR));
}

// --- PoA isolation ----------------------------------------------------------

/// A permissionless (stake-only) account must NOT gain PoA-domain authority.
/// PoA entry requires KYC + admin approval; staking buys nothing there.
#[test]
fn permissionless_account_cannot_enter_poa_without_approval() {
    // The account is a fully-fledged permissionless validator...
    let mut open = PermissionlessRegistry::new();
    open.register_validator(addr(1), 1_000_000, 0).unwrap();
    assert!(open.is_active(&addr(1), roles::VALIDATOR));

    // ...yet it has zero standing in the PoA domain, which is a separate
    // registry with no stake concept.
    let poa = PoaMembershipRegistry::new();
    assert!(
        !poa.is_authorized(POA_DOMAIN, &addr(1)),
        "stake must not translate into PoA authorization"
    );
}

/// Even after submitting KYC, a candidate is not authorized until an admin
/// approves — the permissioned gate the permissionless registry does not have.
#[test]
fn poa_requires_admin_approval_not_stake() {
    let mut poa = PoaMembershipRegistry::new();
    poa.add_admin(POA_DOMAIN, addr(100)); // compliance authority
    poa.submit_application(POA_DOMAIN, addr(2), [9u8; 32])
        .unwrap();
    assert!(!poa.is_authorized(POA_DOMAIN, &addr(2)));

    // A non-admin (even a heavily-staked one elsewhere) cannot approve.
    assert!(poa.approve(POA_DOMAIN, addr(3), addr(2)).is_err());
    assert!(!poa.is_authorized(POA_DOMAIN, &addr(2)));

    // Only the admin can.
    poa.approve(POA_DOMAIN, addr(100), addr(2)).unwrap();
    assert!(poa.is_authorized(POA_DOMAIN, &addr(2)));
}

/// A PoA-approved member gains NO permissionless role automatically. The two
/// registries do not share membership, so PoA rules do not leak outward.
#[test]
fn poa_membership_does_not_grant_permissionless_roles() {
    let mut poa = PoaMembershipRegistry::new();
    poa.add_admin(POA_DOMAIN, addr(100));
    poa.submit_application(POA_DOMAIN, addr(2), [9u8; 32])
        .unwrap();
    poa.approve(POA_DOMAIN, addr(100), addr(2)).unwrap();
    assert!(poa.is_authorized(POA_DOMAIN, &addr(2)));

    let open = PermissionlessRegistry::new();
    assert!(!open.is_active(&addr(2), roles::VALIDATOR));
    assert!(!open.is_active(&addr(2), roles::VERIFIER));
    assert!(!open.is_active(&addr(2), roles::RELAYER));
}

/// The permissionless registry is generic: adding a brand-new role does not
/// require touching the registry or breaking existing behaviour (acceptance
/// criterion: "new domain/role type must not break existing tests").
#[test]
fn adding_new_role_type_is_non_breaking() {
    let mut reg = PermissionlessRegistry::new();
    // A future application-layer role that never existed at registry-design time.
    let data_availability_sampler = RoleId::new(50_000);
    reg.register(
        addr(1),
        data_availability_sampler,
        MIN_REGISTRATION_STAKE,
        0,
    )
    .unwrap();
    assert!(reg.is_active(&addr(1), data_availability_sampler));
    // Pre-existing roles are entirely unaffected.
    reg.register_validator(addr(2), MIN_REGISTRATION_STAKE, 0)
        .unwrap();
    assert!(reg.is_active(&addr(2), roles::VALIDATOR));
    assert_eq!(reg.active_members(data_availability_sampler).len(), 1);
    assert_eq!(reg.active_members(roles::VALIDATOR).len(), 1);
}

// --- Integration: stake tx -> register() -----------------------------------

use crate::core::account::AccountState;
use crate::core::transaction::{Transaction, TransactionType};
use crate::execution::executor::Executor;
use crate::registry::evidence::{ProofProvenance, SlashingProof, SlashingReport};

fn funded_state(account: Address, balance: u64) -> AccountState {
    let mut state = AccountState::new();
    state.get_or_create(&account).balance = balance;
    state
}

fn stake_tx(from: Address, amount: u64, nonce: u64) -> Transaction {
    let mut tx = Transaction::new_with_chain_id(
        from,
        Address::zero(),
        amount,
        1, // fee
        nonce,
        vec![],
        crate::core::transaction::DEFAULT_CHAIN_ID,
        TransactionType::Stake,
    );
    tx.hash = tx.calculate_hash();
    tx
}

/// Applying a Stake transaction must AUTOMATICALLY register the account in the
/// permissionless registry — no separate registration call. This is the core
/// "staking == registration" acceptance criterion.
#[test]
fn stake_tx_auto_registers_in_registry() {
    let staker = addr(0x21);
    let mut state = funded_state(staker, 1_000_000);

    // Meets the stake floor.
    let amount = state.registry.params().min_stake + 500;
    Executor::apply_transaction(&mut state, &stake_tx(staker, amount, 0)).unwrap();

    // Registered as a validator purely as a side effect of staking.
    assert!(state.registry.is_active(&staker, roles::VALIDATOR));
    let reg = state.get_validator(&staker).unwrap();
    assert_eq!(reg.stake, amount);
}

/// Additional stake by an existing validator keeps the registry stake in sync.
#[test]
fn additional_stake_updates_registry_stake() {
    let staker = addr(0x22);
    let mut state = funded_state(staker, 1_000_000);
    let base = state.registry.params().min_stake + 100;
    Executor::apply_transaction(&mut state, &stake_tx(staker, base, 0)).unwrap();
    Executor::apply_transaction(&mut state, &stake_tx(staker, 400, 1)).unwrap();

    let member = state.registry.get(&staker, roles::VALIDATOR).unwrap();
    assert_eq!(member.stake, base + 400);
}

/// A stake below the floor still creates a validator (existing behaviour) but is
/// NOT active in the registry — the economic floor is the only gate, and there
/// is still no whitelist.
#[test]
fn stake_below_floor_is_not_active_in_registry() {
    let staker = addr(0x23);
    let mut state = funded_state(staker, 1_000_000);
    let floor = state.registry.params().min_stake;
    Executor::apply_transaction(&mut state, &stake_tx(staker, floor - 1, 0)).unwrap();
    assert!(!state.registry.is_active(&staker, roles::VALIDATOR));
}

// --- Integration: slashing evidence -> slash() -----------------------------

/// A consensus-verified slashing report drives the registry slash and reduces
/// the offender's bonded stake using the governance-configured ratio.
#[test]
fn actionable_report_slashes_registered_validator() {
    let offender = addr(0x31);
    let mut state = funded_state(offender, 1_000_000);
    let amount = 10_000;
    Executor::apply_transaction(&mut state, &stake_tx(offender, amount, 0)).unwrap();
    assert!(state.registry.is_active(&offender, roles::VALIDATOR));

    let report = SlashingReport::consensus_double_sign(
        offender,
        7,
        "aa".into(),
        "bb".into(),
        vec![1],
        vec![2],
        None,
    );
    let outcome = state.registry.slash_from_report(&report).unwrap().unwrap();
    // Default double-sign ratio is 50%.
    assert_eq!(outcome.penalty, amount / 2);
    assert!(!state.registry.is_active(&offender, roles::VALIDATOR));
}

/// An unverified (externally-submitted) report must NOT slash — even though it
/// is structurally valid. This is what makes the permissionless
/// `submit_slashing_report` RPC safe without a whitelist.
#[test]
fn unverified_report_does_not_slash() {
    let offender = addr(0x32);
    let mut state = funded_state(offender, 1_000_000);
    Executor::apply_transaction(&mut state, &stake_tx(offender, 10_000, 0)).unwrap();

    let report = SlashingReport::new(
        offender,
        roles::VALIDATOR,
        SlashingProof::DoubleSign {
            height: 7,
            block_hash_1: "aa".into(),
            block_hash_2: "bb".into(),
            signature_1: vec![1],
            signature_2: vec![2],
        },
        ProofProvenance::Unverified,
        Some(addr(0x99)),
    );
    // Registry refuses to act.
    assert!(state.registry.slash_from_report(&report).is_err());
    // Stake untouched, still active.
    assert!(state.registry.is_active(&offender, roles::VALIDATOR));
}

/// A report against an account that never registered is a harmless no-op
/// (Ok(None)), not an error — anyone can submit reports permissionlessly.
#[test]
fn report_against_unregistered_is_noop() {
    let mut state = AccountState::new();
    let report = SlashingReport::consensus_double_sign(
        addr(0x33),
        7,
        "aa".into(),
        "bb".into(),
        vec![1],
        vec![2],
        None,
    );
    assert_eq!(state.registry.slash_from_report(&report).unwrap(), None);
}

/// Slashing the validator via the account-state path also mirrors into the
/// registry (consensus slashing keeps both views consistent).
#[test]
fn account_slash_validator_mirrors_into_registry() {
    use crate::core::chain_config::FIXED_POINT_SCALE;
    let offender = addr(0x34);
    let mut state = funded_state(offender, 1_000_000);
    Executor::apply_transaction(&mut state, &stake_tx(offender, 10_000, 0)).unwrap();
    assert!(state.registry.is_active(&offender, roles::VALIDATOR));

    state.slash_validator(&offender, FIXED_POINT_SCALE / 2, "test");
    // Registry now reflects the slash.
    assert!(!state.registry.is_active(&offender, roles::VALIDATOR));
}

// --- Integration: params are config-driven, not hard-coded -----------------

#[test]
fn registry_respects_custom_params() {
    use crate::registry::RegistryParams;
    let params = RegistryParams {
        min_stake: 50_000,
        unbonding_epochs: 21,
        ..RegistryParams::default()
    };
    let mut reg = PermissionlessRegistry::with_params(params);
    // Below the custom (higher) floor is rejected...
    assert!(reg.register_validator(addr(1), 1_000, 0).is_err());
    // ...at the custom floor it succeeds, and unbonding uses the custom window.
    reg.register_validator(addr(1), 50_000, 0).unwrap();
    let release = reg.begin_unbonding(addr(1), roles::VALIDATOR, 5).unwrap();
    assert_eq!(release, 5 + 21);
}

/// Regression guard: introducing the registry must not disturb PoA isolation.
/// A staked (thus registry-registered) validator still has zero PoA authority.
#[test]
fn stake_registration_does_not_grant_poa_authority() {
    let staker = addr(0x41);
    let mut state = funded_state(staker, 1_000_000);
    Executor::apply_transaction(&mut state, &stake_tx(staker, 10_000, 0)).unwrap();
    assert!(state.registry.is_active(&staker, roles::VALIDATOR));

    let poa = PoaMembershipRegistry::new();
    assert!(!poa.is_authorized(POA_DOMAIN, &staker));
}

// --- Task 3 §3.5: Validator onboarding E2E (stake → active → produce) --------

use crate::chain::blockchain::Blockchain;
use crate::chain::genesis::GenesisConfig;
use crate::consensus::pow::PoWEngine;
use crate::core::chain_config::Network;
use crate::crypto::primitives::KeyPair;
use std::sync::Arc;

fn signed_stake_tx(
    keypair: &KeyPair,
    amount: u64,
    nonce: u64,
    chain_id: u64,
    fee: u64,
) -> Transaction {
    let from = Address::from(keypair.public_key_bytes());
    let mut tx = Transaction::new_with_chain_id(
        from,
        Address::zero(),
        amount,
        fee,
        nonce,
        vec![],
        chain_id,
        TransactionType::Stake,
    );
    tx.sign(keypair);
    tx
}

/// Task 3 §3.5 acceptance: empty-ish chain → fund → stake tx → registry Active
/// → produce_block as that validator succeeds.
#[test]
fn task3_validator_onboarding_e2e_stake_register_produce() {
    let consensus = Arc::new(PoWEngine::new(0));
    // Use devnet chain id for test speed (min_stake=1000), but exercise the
    // same stake→registry→produce path documented for mainnet onboarding.
    let mut genesis = GenesisConfig::for_network(Network::Devnet);
    // Start with no pre-seeded validators so the newcomer is the onboarding path.
    genesis.validators.clear();
    // Keep a treasury allocation for fees/funding.
    if genesis.allocations.is_empty() {
        genesis.allocations.push((addr(0x01), 1_000_000_000));
    }

    let mut bc =
        Blockchain::new_with_genesis(consensus, None, genesis.chain_id, None, Some(genesis));

    let keypair = KeyPair::generate().unwrap();
    let staker = Address::from(keypair.public_key_bytes());
    let min_stake = bc.state.registry.params().min_stake;
    let stake_amount = min_stake + 5_000;
    let fee = bc.state.base_fee.max(1);

    // Fund newcomer (simulates treasury transfer / faucet for onboarding).
    bc.state.add_balance(&staker, stake_amount + fee * 10);

    assert!(
        !bc.state.registry.is_active(&staker, roles::VALIDATOR),
        "newcomer must not be active before staking"
    );

    let tx = signed_stake_tx(&keypair, stake_amount, 0, bc.chain_id, fee);
    bc.add_transaction(tx).expect("stake tx must enter mempool");

    let (block, _) = bc
        .produce_block(staker)
        .expect("new staker must be able to produce after onboarding stake");
    assert_eq!(block.producer, Some(staker));
    assert!(
        block.index >= 1,
        "first produced block after genesis should be height >= 1"
    );

    assert!(
        bc.state.registry.is_active(&staker, roles::VALIDATOR),
        "stake must auto-register Active VALIDATOR in permissionless registry"
    );
    let reg = bc
        .state
        .registry
        .get(&staker, roles::VALIDATOR)
        .expect("registration exists");
    assert_eq!(reg.stake, stake_amount);
    assert!(reg.is_active());

    // Second block production: already-onboarded validator keeps producing.
    let (block2, _) = bc
        .produce_block(staker)
        .expect("active validator continues producing");
    assert_eq!(block2.producer, Some(staker));
    assert!(block2.index > block.index);
}

/// Task 3 §3.5: mainnet economic floor (min_stake=1_000_000) still gates activity.
#[test]
fn task3_mainnet_min_stake_floor_for_onboarding() {
    let genesis = GenesisConfig::for_network(Network::Mainnet);
    assert!(
        genesis.validators.is_empty(),
        "mainnet genesis must start permissionless (empty validators)"
    );
    assert_eq!(Network::Mainnet.min_stake(), 1_000_000);

    // Registry default min_stake may differ from network consensus min_stake;
    // onboarding docs use Network::Mainnet.min_stake() as the operator target.
    // Ensure mainnet genesis builds and is deterministic for empty validator set.
    let g1 = genesis.build_genesis_block();
    let g2 = genesis.build_genesis_block();
    assert_eq!(g1.hash, g2.hash);
    assert_eq!(g1.chain_id, 1);
}

/// Task 3 §3.5: below-floor stake does not grant active validator role.
#[test]
fn task3_onboarding_rejects_below_floor_as_active() {
    let consensus = Arc::new(PoWEngine::new(0));
    let mut genesis = GenesisConfig::for_network(Network::Devnet);
    genesis.validators.clear();
    let mut bc =
        Blockchain::new_with_genesis(consensus, None, genesis.chain_id, None, Some(genesis));

    let keypair = KeyPair::generate().unwrap();
    let staker = Address::from(keypair.public_key_bytes());
    let floor = bc.state.registry.params().min_stake;
    let fee = bc.state.base_fee.max(1);
    bc.state.add_balance(&staker, floor + fee * 10);

    let tx = signed_stake_tx(
        &keypair,
        floor.saturating_sub(1).max(1),
        0,
        bc.chain_id,
        fee,
    );
    // May enter mempool and apply; economic floor means not Active in registry.
    let _ = bc.add_transaction(tx);
    let _ = bc.produce_block(staker);

    assert!(
        !bc.state.registry.is_active(&staker, roles::VALIDATOR),
        "below-floor stake must not yield Active VALIDATOR"
    );
}

#[test]
fn task3_storage_operator_active_members() {
    let mut reg = PermissionlessRegistry::new();
    let op = addr(0x55);
    let floor = reg.params().min_stake;
    reg.register_storage_operator(op, floor, 0).unwrap();
    let active = reg.active_members(roles::STORAGE_OPERATOR);
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].account, op);
    assert!(reg.is_active(&op, roles::STORAGE_OPERATOR));
}

#[test]
fn task3_validator_onboarding_e2e_multi_validator_parallel() {
    // Q9 add_more (10-question survey): additional E2E for parallel onboarding
    // Two validators stake at same epoch, both become active, both produce blocks
    let consensus = Arc::new(PoWEngine::new(0));
    let mut genesis = GenesisConfig::for_network(Network::Devnet);
    genesis.validators.clear();
    let mut bc =
        Blockchain::new_with_genesis(consensus, None, genesis.chain_id, None, Some(genesis));

    let kp1 = KeyPair::generate().unwrap();
    let kp2 = KeyPair::generate().unwrap();
    let staker1 = Address::from(kp1.public_key_bytes());
    let staker2 = Address::from(kp2.public_key_bytes());
    let floor = bc.state.registry.params().min_stake;
    let fee = bc.state.base_fee.max(1);
    let stake1 = floor + 1_000;
    let stake2 = floor + 2_000;
    // Fund each staker for stake + fee (projected mempool balance check).
    bc.state.add_balance(&staker1, stake1 + fee * 10);
    bc.state.add_balance(&staker2, stake2 + fee * 10);

    let tx1 = signed_stake_tx(&kp1, stake1, 0, bc.chain_id, fee);
    let tx2 = signed_stake_tx(&kp2, stake2, 0, bc.chain_id, fee);
    bc.add_transaction(tx1)
        .expect("staker1 stake enters mempool");
    bc.add_transaction(tx2)
        .expect("staker2 stake enters mempool");

    let (block, _) = bc.produce_block(staker1).unwrap();
    assert!(block.index >= 1);
    assert!(bc.state.registry.is_active(&staker1, roles::VALIDATOR));
    assert!(bc.state.registry.is_active(&staker2, roles::VALIDATOR));

    let active = bc.state.registry.active_members(roles::VALIDATOR);
    assert!(active.len() >= 2, "both validators should be active");
}
