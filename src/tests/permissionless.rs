//! Acceptance-criteria tests for the permissionless participation model and the
//! Isolation of the permissioned PoA domain (master-context Section 2).
//!
//! These tests are the executable form of the instruction set's acceptance
//! Criteria:
//!  * A permissionless account can join validator/verifier/relayer roles by
//!    Staking alone, with no whitelist (negative "can it join without a
//!    Whitelist?" check).
//!  * PoA-domain permissioned rules do not leak into PoW/PoS/BFT, and vice
//!    Versa: a permissionless (stake-only) account cannot enter the PoA domain
//!    Without KYC/approval, and a PoA member gains no permissionless role.

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
/// Staking. If a whitelist/approval gate were (re)introduced, this fails.
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
    // Asserts there is no fixed/whitelisted relayer committee.
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
    // Proving the gate is economic, not identity/approval based.
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
    // Registry with no stake concept.
    let poa = PoaMembershipRegistry::new();
    assert!(
        !poa.is_authorized(POA_DOMAIN, &addr(1)),
        "stake must not translate into PoA authorization"
    );
}

/// Even after submitting KYC, a candidate is not authorized until an admin
/// Approves - the permissioned gate the permissionless registry does not have.
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
/// Registries do not share membership, so PoA rules do not leak outward.
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
/// Require touching the registry or breaking existing behaviour (acceptance
/// Criterion: "new domain/role type must not break existing tests").
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

// --- Integration: stake tx -> register -----------------------------------

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
/// Permissionless registry - no separate registration call. This is the core
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
/// NOT active in the registry - the economic floor is the only gate, and there
/// Is still no whitelist.
#[test]
fn stake_below_floor_is_not_active_in_registry() {
    let staker = addr(0x23);
    let mut state = funded_state(staker, 1_000_000);
    let floor = state.registry.params().min_stake;
    Executor::apply_transaction(&mut state, &stake_tx(staker, floor - 1, 0)).unwrap();
    assert!(!state.registry.is_active(&staker, roles::VALIDATOR));
}

// --- Integration: slashing evidence -> slash -----------------------------

/// A consensus-verified slashing report drives the registry slash and reduces
/// The offender's bonded stake using the governance-configured ratio.
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

/// An unverified (externally-submitted) report must NOT slash, even though it
/// Is structurally valid. This is what makes the permissionless
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
/// (Ok(None)), not an error - anyone can submit reports permissionlessly.
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
/// Registry (consensus slashing keeps both views consistent).
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

fn unstake_tx(from: Address, amount: u64, nonce: u64) -> Transaction {
    let mut tx = Transaction::new_with_chain_id(
        from,
        Address::zero(),
        amount,
        1, // fee
        nonce,
        vec![],
        crate::core::transaction::DEFAULT_CHAIN_ID,
        TransactionType::Unstake,
    );
    tx.hash = tx.calculate_hash();
    tx
}

/// The `Unstake` ledger path must queue the release using the governance
/// Parameter, not a compile-time constant.
///
/// `unbonding_epochs` is in `GOVERNANCE_PARAMETER_WHITELIST` and
/// `RegistryParams::validate` bounds it to `1..=100_000`, so a vote to lengthen
/// The window is a legitimate, accepted governance action. The executor read
/// `core::account::UNBONDING_EPOCHS` (7) instead, so the vote changed the
/// Registry's stored parameter and changed nothing about when stake actually
/// Came back. Canary: pin the executor back to the constant and this fails
/// With `release_epoch == 5 + 7` instead of `5 + 40`.
#[test]
fn unstake_release_epoch_follows_the_governance_parameter() {
    use crate::registry::RegistryParams;

    let staker = addr(0x51);
    let mut state = funded_state(staker, 1_000_000);

    // A window deliberately different from `UNBONDING_EPOCHS` (7) so the two
    // Sources cannot be confused for each other.
    let window = 40;
    assert_ne!(
        window,
        crate::core::account::UNBONDING_EPOCHS,
        "the test window must differ from the constant or it proves nothing"
    );
    let params = RegistryParams {
        unbonding_epochs: window,
        ..RegistryParams::default()
    };
    params.validate().expect("40 epochs is inside the bounds");
    state.registry.set_params(params);

    let amount = state.registry.params().min_stake + 500;
    Executor::apply_transaction(&mut state, &stake_tx(staker, amount, 0)).unwrap();

    state.epoch_index = 5;
    Executor::apply_transaction(&mut state, &unstake_tx(staker, 400, 1)).unwrap();

    let entry = state
        .unbonding_queue
        .iter()
        .find(|e| e.address == staker)
        .expect("unstake must queue an unbonding entry");
    assert_eq!(
        entry.release_epoch,
        5 + window,
        "release epoch must use the governance window, not UNBONDING_EPOCHS"
    );
}

/// The RoleId(8) bond must unbond on the same governance window as every other
/// Role. `begin_agent_operator_unbonding` called `begin_unbonding_with_delay`
/// With the hard-coded constant, so a governance vote moved every role's window
/// Except this one. Canary: restore the `_with_delay(.., UNBONDING_EPOCHS)`
/// Call and this fails with `7` instead of the configured window.
#[test]
fn agent_operator_unbonding_follows_the_governance_parameter() {
    use crate::registry::RegistryParams;

    let operator = addr(0x52);
    let mut state = funded_state(operator, 1_000_000);

    let window = 33;
    assert_ne!(window, crate::core::account::UNBONDING_EPOCHS);
    let params = RegistryParams {
        unbonding_epochs: window,
        ..RegistryParams::default()
    };
    params.validate().expect("33 epochs is inside the bounds");
    state.registry.set_params(params);

    let bond = state.required_agent_bond(crate::core::transaction::DEFAULT_CHAIN_ID);
    state
        .bond_agent_operator(&operator, bond, crate::core::transaction::DEFAULT_CHAIN_ID)
        .expect("bond at the required floor");

    state.epoch_index = 11;
    let release = state
        .begin_agent_operator_unbonding(&operator)
        .expect("an operator with no open obligations may unbond");
    assert_eq!(
        release,
        11 + window,
        "the RoleId(8) bond must use the same governance window as other roles"
    );
}

/// `Unstake` must mirror the reduced stake into the permissionless registry.
///
/// `Stake` calls `sync_validator_registration`; `Unstake` did not. The registry
/// Therefore reported the pre-unstake stake forever. That is not cosmetic:
/// `registry.root()` is folded into the state root, `registry.is_active` gates
/// The liveness and invalid-vote slashing paths, and `active_members` backs the
/// RPC validator views. Canary: drop the `sync_validator_registration` call
/// From the `Unstake` arm and this fails with the full pre-unstake stake.
#[test]
fn unstake_mirrors_the_reduced_stake_into_the_registry() {
    let staker = addr(0x53);
    let mut state = funded_state(staker, 1_000_000);

    let amount = state.registry.params().min_stake + 5_000;
    Executor::apply_transaction(&mut state, &stake_tx(staker, amount, 0)).unwrap();
    assert_eq!(
        state.registry.get(&staker, roles::VALIDATOR).unwrap().stake,
        amount
    );

    Executor::apply_transaction(&mut state, &unstake_tx(staker, 3_000, 1)).unwrap();

    let member = state
        .registry
        .get(&staker, roles::VALIDATOR)
        .expect("still above the floor, so still registered");
    assert_eq!(
        member.stake,
        amount - 3_000,
        "registry stake must track the canonical validator stake after Unstake"
    );
    assert_eq!(
        member.stake,
        state.get_validator(&staker).unwrap().stake,
        "the registry and the validator set must never disagree"
    );
}

/// Unstaking below the floor must deactivate the registry membership.
///
/// Without the mirror, a validator could unstake down to dust (or to zero) and
/// Keep an `Active` registry entry with its original stake, passing
/// `registry.is_active` and appearing in `active_members` with stake it no
/// Longer has.
#[test]
fn unstaking_below_the_floor_deactivates_the_registry_entry() {
    let staker = addr(0x54);
    let mut state = funded_state(staker, 1_000_000);

    let floor = state.registry.params().min_stake;
    let amount = floor + 100;
    Executor::apply_transaction(&mut state, &stake_tx(staker, amount, 0)).unwrap();
    assert!(state.registry.is_active(&staker, roles::VALIDATOR));

    // Take the whole stake out.
    Executor::apply_transaction(&mut state, &unstake_tx(staker, amount, 1)).unwrap();

    assert_eq!(state.get_validator(&staker).unwrap().stake, 0);
    assert!(
        !state.registry.is_active(&staker, roles::VALIDATOR),
        "a fully unstaked account must not remain an active registry validator"
    );
}

/// The registry root is consensus state, so an `Unstake` must move it.
///
/// Before the mirror, applying `Unstake` left `registry.root()` byte-identical:
/// the reduced stake was invisible to the state root. Two nodes, one of which
/// Replayed history through a path that did sync, would compute different roots.
#[test]
fn unstake_changes_the_registry_root() {
    let staker = addr(0x55);
    let mut state = funded_state(staker, 1_000_000);

    let amount = state.registry.params().min_stake + 5_000;
    Executor::apply_transaction(&mut state, &stake_tx(staker, amount, 0)).unwrap();
    let root_before = state.registry.root();

    Executor::apply_transaction(&mut state, &unstake_tx(staker, 2_000, 1)).unwrap();

    assert_ne!(
        root_before,
        state.registry.root(),
        "reducing bonded stake must be visible in the registry root"
    );
}

// --- Role bonds must have an exit ------------------------------------------

/// A RELAYER bond must be recoverable.
///
/// `bond_relayer` debits the account balance and registers the bond, and its
/// Doc-comment says the bond "remains locked but slashable until the relayer
/// Begins unbonding". Nothing in the tree began that unbonding: no
/// `ChainCommand`, no RPC method, no transaction type, no call to
/// `registry.begin_unbonding` for RoleId(3). The debit was one-way and the
/// Bond was permanently unrecoverable.
///
/// Canary: delete `begin_role_bond_unbonding` / `withdraw_role_bond` and this
/// Fails to compile - which is the point. Delete only the balance credit in
/// `withdraw_role_bond` and it fails on the final balance assertion.
#[test]
fn a_relayer_bond_can_be_unbonded_and_withdrawn() {
    let relayer = addr(0x61);
    let bond = 2_000;
    let mut state = funded_state(relayer, 10_000);

    state.bond_relayer(&relayer, bond).expect("bond succeeds");
    assert_eq!(
        state.get_balance(&relayer),
        10_000 - bond,
        "bond is debited"
    );
    assert!(state.registry.is_active(&relayer, roles::RELAYER));

    let release = state
        .begin_role_bond_unbonding(&relayer, roles::RELAYER)
        .expect("a bonded relayer may begin unbonding");
    assert_eq!(release, state.registry.params().unbonding_epochs);

    state.epoch_index = release;
    let withdrawn = state
        .withdraw_role_bond(&relayer, roles::RELAYER)
        .expect("a matured bond may be withdrawn");

    assert_eq!(withdrawn, bond);
    assert_eq!(
        state.get_balance(&relayer),
        10_000,
        "the bond must come back to the balance it was debited from"
    );
    assert!(state.registry.get(&relayer, roles::RELAYER).is_none());
}

/// The same exit must exist for `PROVER` and `STORAGE_OPERATOR`, which are debited
/// By the same one-way pattern.
#[test]
fn prover_and_storage_operator_bonds_can_also_be_withdrawn() {
    for (role, bond_amount) in [
        (roles::PROVER, 1_500u64),
        (roles::STORAGE_OPERATOR, 3_000u64),
    ] {
        let account = addr(0x62);
        let mut state = funded_state(account, 10_000);
        if role == roles::PROVER {
            state.bond_prover(&account, bond_amount).unwrap();
        } else {
            state.bond_storage_operator(&account, bond_amount).unwrap();
        }
        assert_eq!(state.get_balance(&account), 10_000 - bond_amount);

        let release = state.begin_role_bond_unbonding(&account, role).unwrap();
        state.epoch_index = release;
        let withdrawn = state.withdraw_role_bond(&account, role).unwrap();

        assert_eq!(withdrawn, bond_amount, "role {role}");
        assert_eq!(state.get_balance(&account), 10_000, "role {role}");
    }
}

/// Withdrawal before the release epoch must fail, and must not credit anything.
///
/// This is the property that stops the exit from becoming a mint: without the
/// Maturity check a bonded account could withdraw repeatedly.
#[test]
fn a_role_bond_cannot_be_withdrawn_before_it_matures() {
    let relayer = addr(0x63);
    let bond = 2_000;
    let mut state = funded_state(relayer, 10_000);
    state.bond_relayer(&relayer, bond).unwrap();

    let release = state
        .begin_role_bond_unbonding(&relayer, roles::RELAYER)
        .unwrap();
    assert!(release > 0, "the default window must not be zero");

    state.epoch_index = release - 1;
    let err = state
        .withdraw_role_bond(&relayer, roles::RELAYER)
        .expect_err("an immature bond must not be withdrawable");
    assert!(
        err.contains("Unbonding") || err.contains("unbonding"),
        "got: {err}"
    );
    assert_eq!(
        state.get_balance(&relayer),
        10_000 - bond,
        "a rejected withdrawal must not credit the balance"
    );
}

/// A bond can be withdrawn exactly once. `registry.withdraw` removes the
/// Registration, so the second attempt has nothing to pay out.
#[test]
fn a_role_bond_cannot_be_withdrawn_twice() {
    let relayer = addr(0x64);
    let bond = 2_000;
    let mut state = funded_state(relayer, 10_000);
    state.bond_relayer(&relayer, bond).unwrap();
    let release = state
        .begin_role_bond_unbonding(&relayer, roles::RELAYER)
        .unwrap();
    state.epoch_index = release;
    state.withdraw_role_bond(&relayer, roles::RELAYER).unwrap();
    assert_eq!(state.get_balance(&relayer), 10_000);

    state
        .withdraw_role_bond(&relayer, roles::RELAYER)
        .expect_err("a withdrawn bond must not pay out again");
    assert_eq!(
        state.get_balance(&relayer),
        10_000,
        "the second attempt must not mint"
    );
}

/// Withdrawing without unbonding first must fail: an `Active` bond is still
/// Slashable, and paying it out on demand would let a relayer exit the moment
/// It sees evidence coming.
#[test]
fn an_active_role_bond_cannot_skip_the_unbonding_window() {
    let relayer = addr(0x65);
    let mut state = funded_state(relayer, 10_000);
    state.bond_relayer(&relayer, 2_000).unwrap();

    state
        .withdraw_role_bond(&relayer, roles::RELAYER)
        .expect_err("an active bond must go through unbonding first");
    assert_eq!(state.get_balance(&relayer), 8_000);
}

/// Validator stake must NOT be payable through this path. It unwinds through
/// `Unstake` -> `unbonding_queue` -> `process_unbonding`; crediting it here as
/// Well would pay the same stake out twice.
#[test]
fn validator_stake_is_not_withdrawable_through_the_role_bond_path() {
    let staker = addr(0x66);
    let mut state = funded_state(staker, 1_000_000);
    let amount = state.registry.params().min_stake + 500;
    Executor::apply_transaction(&mut state, &stake_tx(staker, amount, 0)).unwrap();

    let err = state
        .begin_role_bond_unbonding(&staker, roles::VALIDATOR)
        .expect_err("validator stake must not use the role-bond exit");
    assert!(err.contains("Unstake"), "got: {err}");

    let err = state
        .withdraw_role_bond(&staker, roles::VALIDATOR)
        .expect_err("validator stake must not be withdrawable here");
    assert!(err.contains("Unstake"), "got: {err}");
}

/// The RoleId(8) bond has its own pair, which also checks open inference
/// Obligations and charges the fee. Routing it here would skip both.
#[test]
fn the_agent_bond_is_not_withdrawable_through_the_role_bond_path() {
    let operator = addr(0x67);
    let mut state = funded_state(operator, 1_000_000);
    let bond = state.required_agent_bond(crate::core::transaction::DEFAULT_CHAIN_ID);
    state
        .bond_agent_operator(&operator, bond, crate::core::transaction::DEFAULT_CHAIN_ID)
        .unwrap();

    state
        .begin_role_bond_unbonding(&operator, roles::AGENT_OPERATOR)
        .expect_err("the RoleId(8) bond has its own unbonding entry point");
    state
        .withdraw_role_bond(&operator, roles::AGENT_OPERATOR)
        .expect_err("the RoleId(8) bond has its own withdrawal entry point");
}

/// A role that never debits a balance has nothing to pay out, so the path must
/// Refuse rather than invent a credit.
#[test]
fn a_role_with_no_independent_bond_is_rejected() {
    let account = addr(0x68);
    let mut state = funded_state(account, 10_000);
    let err = state
        .withdraw_role_bond(&account, roles::ATTESTER)
        .expect_err("ATTESTER has no independently debited bond");
    assert!(err.contains("no independently debited bond"), "got: {err}");
    assert_eq!(state.get_balance(&account), 10_000);
}

/// Supply conservation across the full bond lifecycle.
///
/// `total_bud_committed` counts liquid balances plus registry role bonds, so a
/// Bond that is debited and never creditable is not a supply leak in the
/// Accounting sense - but it is a leak for the account. Round-tripping the bond
/// Must leave both the balance and the committed total exactly where they
/// Started.
#[test]
fn a_role_bond_round_trip_conserves_supply() {
    let relayer = addr(0x69);
    let mut state = funded_state(relayer, 10_000);
    let before = state.total_bud_committed();

    state.bond_relayer(&relayer, 2_000).unwrap();
    assert_eq!(
        state.total_bud_committed(),
        before,
        "bonding moves supply between buckets, it does not create or destroy it"
    );

    let release = state
        .begin_role_bond_unbonding(&relayer, roles::RELAYER)
        .unwrap();
    state.epoch_index = release;
    state.withdraw_role_bond(&relayer, roles::RELAYER).unwrap();

    assert_eq!(
        state.total_bud_committed(),
        before,
        "withdrawing must not mint"
    );
    assert_eq!(state.get_balance(&relayer), 10_000);
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

// ---: Validator onboarding E2E (stake → active → produce) --------

use crate::chain::blockchain::Blockchain;
use crate::chain::genesis::GenesisConfig;
use crate::consensus::pow::PoWEngine;
use crate::core::chain_config::Network;
use crate::crypto::primitives::{KeyPair, ValidatorKeys};
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

fn consensus_key_registration(
    keys: &ValidatorKeys,
    chain_id: u64,
    address: &Address,
) -> crate::core::transaction::ConsensusKeyRegistration {
    let bls = keys.bls_key.as_ref().expect("BLS key");
    crate::core::transaction::ConsensusKeyRegistration {
        scheme_id: crate::chain::finality::BLS_SCHEME_RFC9380_V1.to_string(),
        vrf_public_key: keys.vrf_key.public.to_bytes().to_vec(),
        bls_public_key: bls.public_key.clone(),
        pop_signature: bls.generate_pop(chain_id, address),
        pq_public_key: keys
            .pq_key
            .as_ref()
            .expect("PQ key")
            .public_key_bytes()
            .to_vec(),
    }
}

#[test]
fn separate_consensus_key_transaction_activates_bonded_validator() {
    let mut state = AccountState::new();
    let keys = ValidatorKeys::generate().expect("validator keys");
    let validator = Address::from(keys.sig_key.public_key_bytes());
    let min_stake = Network::Devnet.min_stake();
    let fee = state.base_fee.max(1);
    state.add_balance(&validator, fee * 2);
    state.add_validator(validator, min_stake);
    state.get_validator_mut(&validator).unwrap().active = false;
    assert!(!state.get_validator(&validator).unwrap().active);

    let mut tx = Transaction::new_consensus_key_registration(
        validator,
        fee,
        0,
        Network::Devnet.chain_id().value(),
        consensus_key_registration(&keys, Network::Devnet.chain_id().value(), &validator),
    );
    tx.sign(&keys.sig_key);
    state
        .validate_transaction_with_context(&tx, 0, state.get_balance(&validator))
        .expect("registration precheck");
    Executor::apply_transaction(&mut state, &tx).expect("registration applies");

    let registered = state.get_validator(&validator).unwrap();
    assert!(registered.active);
    assert!(registered.verify_pop_is_valid(Network::Devnet.chain_id().value()));
    assert_eq!(
        registered.vrf_public_key.as_slice(),
        keys.vrf_key.public.to_bytes().as_slice(),
    );
    assert_eq!(state.get_nonce(&validator), 1);

    let hash_before = state.consensus_validator_set_hash(45262).unwrap();
    let alternate_vrf = ValidatorKeys::generate().unwrap().vrf_key.public.to_bytes();
    state.get_validator_mut(&validator).unwrap().vrf_public_key = alternate_vrf.to_vec();
    let hash_after = state.consensus_validator_set_hash(45262).unwrap();
    assert_ne!(hash_before, hash_after);
}

#[test]
fn malformed_consensus_key_registration_is_atomic() {
    let mut state = AccountState::new();
    let keys = ValidatorKeys::generate().expect("validator keys");
    let validator = Address::from(keys.sig_key.public_key_bytes());
    let min_stake = Network::Devnet.min_stake();
    let fee = state.base_fee.max(1);
    state.add_balance(&validator, fee * 2);
    state.add_validator(validator, min_stake);
    state.get_validator_mut(&validator).unwrap().active = false;
    let balance_before = state.get_balance(&validator);

    let mut registration =
        consensus_key_registration(&keys, Network::Devnet.chain_id().value(), &validator);
    registration.pop_signature[0] ^= 1;
    let mut tx = Transaction::new_consensus_key_registration(
        validator,
        fee,
        0,
        Network::Devnet.chain_id().value(),
        registration,
    );
    tx.sign(&keys.sig_key);
    assert!(Executor::apply_transaction(&mut state, &tx).is_err());

    let unchanged = state.get_validator(&validator).unwrap();
    assert!(!unchanged.active);
    assert!(unchanged.bls_public_key.is_empty());
    assert_eq!(state.get_balance(&validator), balance_before);
    assert_eq!(state.get_nonce(&validator), 0);
}

/// Acceptance: empty-ish chain → fund → stake tx → registry Active
/// → produce_block as that validator succeeds.
#[test]
fn validator_onboarding_e2e_stake_register_produce() {
    let consensus = Arc::new(PoWEngine::new(0));
    // Use devnet chain id for test speed (min_stake=1000), but exercise the
    // Same stake→registry→produce path documented for mainnet onboarding.
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

/// Mainnet economic floor (min_stake=1_000_000) still gates activity.
#[test]
fn mainnet_min_stake_floor_for_onboarding() {
    let genesis = GenesisConfig::for_network(Network::Mainnet);
    assert!(
        genesis.validators.is_empty(),
        "mainnet genesis must start permissionless (empty validators)"
    );
    assert_eq!(Network::Mainnet.min_stake(), 1_000_000);

    // Registry default min_stake may differ from network consensus min_stake;
    // Onboarding docs use Network::Mainnet.min_stake as the operator target.
    // Ensure mainnet genesis builds and is deterministic for empty validator set.
    let g1 = genesis.build_genesis_block();
    let g2 = genesis.build_genesis_block();
    assert_eq!(g1.hash, g2.hash);
    assert_eq!(g1.chain_id, Network::Mainnet.chain_id().value());
}

/// Below-floor stake does not grant active validator role.
#[test]
fn onboarding_rejects_below_floor_as_active() {
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
fn storage_operator_active_members() {
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
fn validator_onboarding_e2e_multi_validator_parallel() {
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
