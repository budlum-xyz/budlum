//! End-to-end security tests for PermissionlessRegistry and ReplayNonceStore:
//! - PermissionlessRegistry::upsert_stake enforces min_stake before activating/retaining Active
//! - PermissionlessRegistry::move_delegation and begin_delegation_unbonding block dust remainders
//!   below min_delegation_amount
//! - PermissionlessRegistry::register and delegate refuse Address::zero()
//! - ReplayNonceStore::mark_processed_at refuses same-domain channels and backwards heights

use budlum_core::core::address::Address;
use budlum_core::cross_domain::nonce::ReplayNonceStore;
use budlum_core::registry::permissionless::{
    MemberStatus, PermissionlessRegistry, MIN_REGISTRATION_STAKE,
};
use budlum_core::registry::role::roles;

fn addr(byte: u8) -> Address {
    Address::from([byte; 32])
}

#[test]
fn upsert_stake_cannot_reactivate_unbonding_member_below_min_stake() {
    let mut reg = PermissionlessRegistry::new();
    let v = addr(1);
    reg.register_validator(v, MIN_REGISTRATION_STAKE, 1)
        .expect("register");
    reg.begin_unbonding(v, roles::VALIDATOR, 2)
        .expect("begin unbonding");

    // Attempting to reactivate an Unbonding validator with 1 atom (< min_stake) MUST NOT
    // flip status back to Active!
    reg.upsert_stake(v, roles::VALIDATOR, 1, 3);
    let rec = reg.get(&v, roles::VALIDATOR).expect("record");
    assert!(
        !matches!(rec.status, MemberStatus::Active),
        "member below min_stake MUST NOT reactivate to Active: {:?}",
        rec.status
    );

    // Restoring at or above min_stake reactivates cleanly.
    reg.upsert_stake(v, roles::VALIDATOR, MIN_REGISTRATION_STAKE, 4);
    let rec2 = reg.get(&v, roles::VALIDATOR).expect("record");
    assert!(matches!(rec2.status, MemberStatus::Active));
}

#[test]
fn move_delegation_and_unbonding_forbid_leaving_dust_below_min_delegation_amount() {
    let mut reg = PermissionlessRegistry::new();
    let v1 = addr(1);
    let v2 = addr(2);
    let delegator = addr(9);
    reg.register_validator(v1, MIN_REGISTRATION_STAKE, 0)
        .expect("v1");
    reg.register_validator(v2, MIN_REGISTRATION_STAKE, 0)
        .expect("v2");

    let floor = reg.params().min_delegation_amount;
    reg.delegate(delegator, v1, floor + 1)
        .expect("initial delegation clears floor");

    // Moving `floor` units out of `floor + 1` would leave a 1-atom dust position on v1:
    // MUST fail closed without mutating v1 or v2!
    let move_err = reg
        .move_delegation(delegator, v1, v2, floor)
        .expect_err("move_delegation must not leave dust remainder below min_delegation_amount");
    assert!(
        move_err.contains("minimum") || move_err.contains("dust") || move_err.contains("at least"),
        "unexpected error: {move_err}"
    );
    assert_eq!(reg.delegated_amount(delegator, v1), floor + 1);
    assert_eq!(reg.delegated_amount(delegator, v2), 0);

    // Partial unbonding leaving a 1-atom dust position MUST also fail closed!
    let unbond_err = reg
        .begin_delegation_unbonding(delegator, v1, floor, 1)
        .expect_err("begin_delegation_unbonding must not leave dust remainder below floor");
    assert!(
        unbond_err.contains("minimum")
            || unbond_err.contains("dust")
            || unbond_err.contains("at least"),
        "unexpected error: {unbond_err}"
    );
    assert_eq!(reg.delegated_amount(delegator, v1), floor + 1);

    // Full unbond leaving exact 0 remainder MUST still succeed.
    reg.begin_delegation_unbonding(delegator, v1, floor + 1, 1)
        .expect("full unbond leaving 0 succeeds");
    assert_eq!(reg.delegated_amount(delegator, v1), 0);
}

#[test]
fn permissionless_registry_refuses_zero_account_on_register_and_delegate() {
    let mut reg = PermissionlessRegistry::new();
    assert!(reg
        .register_validator(Address::zero(), MIN_REGISTRATION_STAKE, 0)
        .is_err());
    let floor = reg.params().min_delegation_amount;
    assert!(reg.delegate(Address::zero(), addr(1), floor).is_err());
    assert!(reg.delegate(addr(1), Address::zero(), floor).is_err());
}

#[test]
fn replay_nonce_store_refuses_same_domain_and_backwards_heights() {
    let mut store = ReplayNonceStore::new();
    let s = addr(7);

    // Same-domain channel (source == target) MUST be refused fail-closed.
    let same_dom_err = store
        .mark_processed_at(2, 2, &s, 0, 100)
        .expect_err("same-domain nonce channel must fail closed");
    assert!(
        same_dom_err.contains("differ"),
        "expected distinct domain error, got: {same_dom_err}"
    );

    // Advance channel (1 -> 2) to nonce 0 at height 100.
    store
        .mark_processed_at(1, 2, &s, 0, 100)
        .expect("valid advance");

    // Backwards height (99 < 100) on the same channel MUST be refused fail-closed.
    let back_err = store
        .mark_processed_at(1, 2, &s, 1, 99)
        .expect_err("backwards block height must fail closed");
    assert!(
        back_err.contains("precedes") || back_err.contains("height"),
        "expected monotonic height error, got: {back_err}"
    );
    assert!(!store.is_processed(1, 2, &s, 1));

    // Monotonic height (100 or 101) advances cleanly.
    store
        .mark_processed_at(1, 2, &s, 1, 100)
        .expect("same-block next nonce succeeds");
    assert!(store.is_processed(1, 2, &s, 1));
}
