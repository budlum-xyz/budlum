//! Expanded BNS Registry tests coverage.

use crate::bns::types::BnsError;
use crate::bns::BnsRegistry;
use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};
use crate::crypto::primitives::KeyPair;
use crate::execution::executor::Executor;

fn addr(b: u8) -> Address {
    Address::from([b; 32])
}

#[test]
fn test_bns_cost_scaling() {
    let reg = BnsRegistry::new();

    // Short names cost more (multiplier 100)
    let cost_short = reg.calculate_cost("abc", 1); // 100 * 100 * 1 = 10,000 (x2 for short) -> 20,000

    // Medium names (multiplier 10)
    let cost_med = reg.calculate_cost("abcde", 1); // 100 * 10 * 1 = 1,000 (x2 for med) -> 2,000

    // Long names (multiplier 1)
    let cost_long = reg.calculate_cost("abcdefgh", 1); // 100 * 1 * 1 = 100

    assert!(cost_short > cost_med);
    assert!(cost_med > cost_long);
}

#[test]
fn test_bns_renewal() {
    let mut reg = BnsRegistry::new();
    let alice = addr(1);
    let bob = addr(2);

    reg.register("test.bud".to_string(), alice, 0, 100).unwrap();
    assert_eq!(reg.resolve("test.bud", 50), Some(alice));

    // Only the current owner may renew.
    assert!(matches!(
        reg.renew("test.bud", &bob, 50, 200),
        Err(BnsError::NotOwner)
    ));

    // Renewal extends from the current expiry (100 + 200 = 300).
    reg.renew("test.bud", &alice, 50, 200).unwrap();
    assert_eq!(reg.resolve("test.bud", 150), Some(alice));
    assert_eq!(reg.resolve("test.bud", 250), Some(alice));
    assert_eq!(reg.resolve("test.bud", 350), None);

    // Expired names cannot be renewed; they become re-registerable.
    assert!(matches!(
        reg.renew("test.bud", &alice, 400, 100),
        Err(BnsError::Expired)
    ));
    // F14: grace-period - expire (350) + GRACE_PERIOD (3000)
    // no third party can squat inside it. epoch 400 < 3350, so bob is REFUSED.
    assert!(matches!(
        reg.register("test.bud".to_string(), bob, 400, 100),
        Err(BnsError::NameTaken)
    ));
    // After the grace period (epoch 3360 > 3350) bob may register.
    reg.register("test.bud".to_string(), bob, 3360, 100)
        .unwrap();
    assert_eq!(reg.resolve("test.bud", 3370), Some(bob));
}

#[test]
fn test_bns_subdomains_owner_only() {
    let mut reg = BnsRegistry::new();
    let alice = addr(1);
    let bob = addr(2);

    reg.register("alice.bud".to_string(), alice, 0, 1000)
        .unwrap();

    // Alice can create subdomain
    reg.register_subdomain("alice.bud", "app".to_string(), bob, &alice, 0)
        .unwrap();

    assert_eq!(reg.resolve_subdomain("alice.bud", "app", 100), Some(bob));

    // Bob (not owner of parent) cannot create subdomain under alice.bud
    let res = reg.register_subdomain("alice.bud", "malicious".to_string(), bob, &bob, 0);
    assert!(res.is_err());
}

#[test]
fn test_bns_invalid_names() {
    let mut reg = BnsRegistry::new();
    let alice = addr(1);

    // Empty name
    assert!(reg.register(String::new(), alice, 0, 100).is_err());

    // Name too long
    let long_name = "a".repeat(256);
    assert!(reg.register(long_name, alice, 0, 100).is_err());
}

#[test]
fn test_bns_transfer() {
    let mut reg = BnsRegistry::new();
    let alice = addr(1);
    let bob = addr(2);

    reg.register("transfer.bud".to_string(), alice, 0, 1000)
        .unwrap();

    // A live name cannot be re-registered by anyone (NameTaken guard is the
    // Anti-hijack invariant).
    assert!(matches!(
        reg.register("transfer.bud".to_string(), bob, 10, 1000),
        Err(BnsError::NameTaken)
    ));

    // Only the current owner may transfer.
    assert!(matches!(
        reg.transfer("transfer.bud", &bob, bob, 10),
        Err(BnsError::NotOwner)
    ));

    // Ownership moves to Bob: resolution follows the new owner and the
    // Previous owner loses control over the record (e.g. subdomains).
    reg.transfer("transfer.bud", &alice, bob, 10).unwrap();
    assert_eq!(reg.resolve("transfer.bud", 100), Some(bob));
    assert!(matches!(
        reg.register_subdomain("transfer.bud", "ghost".to_string(), alice, &alice, 10),
        Err(BnsError::NotOwner)
    ));
    reg.register_subdomain("transfer.bud", "app".to_string(), alice, &bob, 10)
        .unwrap();
    assert_eq!(
        reg.resolve_subdomain("transfer.bud", "app", 100),
        Some(alice)
    );
}

#[test]
fn test_bns_full_resolve_with_storage() {
    let mut reg = BnsRegistry::new();
    let alice = addr(1);
    let cid = [7u8; 32];

    reg.register("storage.bud".to_string(), alice, 0, 1000)
        .unwrap();
    reg.set_storage("storage.bud", alice, cid, 1, 10).unwrap();

    let resolved = reg.resolve_full("storage.bud", 10).unwrap();
    assert_eq!(resolved.owner, alice);
    assert_eq!(resolved.storage_root, Some(cid));
    assert_eq!(resolved.storage_domain_id, Some(1));
}

#[test]
fn bns_lifecycle_doors_reject_zero_duration_and_zero_owner() {
    let alice = Address::from([1u8; 32]);
    let mut reg = BnsRegistry::new();
    reg.register("term.bud".into(), alice, 0, 100).unwrap();

    assert_eq!(
        reg.renew("term.bud", &alice, 10, 0),
        Err(BnsError::InvalidName),
        "a renewal must extend the registration"
    );
    assert_eq!(
        reg.transfer("term.bud", &alice, Address::zero(), 10),
        Err(BnsError::InvalidName),
        "a transfer must not create a name owned by the zero address"
    );
}

#[test]
fn test_bns_transfer_clears_previous_owner_pointers() {
    let mut reg = BnsRegistry::new();
    let alice = addr(1);
    let bob = addr(2);
    reg.register("pointers.bud".to_string(), alice, 0, 1000)
        .unwrap();
    reg.register_subdomain("pointers.bud", "app".to_string(), alice, &alice, 0)
        .unwrap();
    reg.set_content(
        "pointers.bud",
        &alice,
        crate::storage::content_id::ContentId([9u8; 32]),
        0,
    )
    .unwrap();

    reg.transfer("pointers.bud", &alice, bob, 10).unwrap();
    let resolved = reg.resolve_full("pointers.bud", 100).unwrap();
    assert_eq!(resolved.address, Some(bob));
    assert_eq!(resolved.content_id, None);
    assert_eq!(reg.resolve_subdomain("pointers.bud", "app", 100), None);
}

#[test]
fn test_bns_expired_name_refuses_writes() {
    let mut reg = BnsRegistry::new();
    let alice = addr(1);
    reg.register("stale.bud".to_string(), alice, 0, 100)
        .unwrap();
    assert!(matches!(
        reg.register_subdomain("stale.bud", "app".to_string(), alice, &alice, 100),
        Err(BnsError::Expired)
    ));
    assert!(matches!(
        reg.set_content(
            "stale.bud",
            &alice,
            crate::storage::content_id::ContentId([1u8; 32]),
            100
        ),
        Err(BnsError::Expired)
    ));
}

#[test]
fn test_bns_default_registry_matches_new() {
    let reg = BnsRegistry::default();
    assert_eq!(reg.base_cost, BnsRegistry::new().base_cost);
    assert!(reg.is_empty());
}

#[test]
fn test_bns_register_refuses_expiry_overflow() {
    let mut reg = BnsRegistry::new();
    let alice = addr(1);
    assert!(reg
        .register("overflow.bud".to_string(), alice, 1, u64::MAX)
        .is_err());
    assert!(reg.is_empty());
}

fn lifecycle_tx(
    from: Address,
    amount: u64,
    fee: u64,
    nonce: u64,
    tx_type: TransactionType,
    data: Vec<u8>,
) -> Transaction {
    Transaction::new_with_chain_id(
        from,
        Address::zero(),
        amount,
        fee,
        nonce,
        data,
        DEFAULT_CHAIN_ID,
        tx_type,
    )
}

#[test]
fn bns_renew_and_transfer_execute_through_consensus_doors() {
    let key = KeyPair::from_seed(&[1u8; 32]).unwrap();
    let alice = Address::from(key.public_key_bytes());
    let bob = addr(2);
    let name = "term.bud".to_string();
    let duration = 100;
    let mut state = AccountState::new();
    state.add_balance(&alice, 100_000);
    state
        .bns_registry
        .register(name.clone(), alice, 0, duration)
        .unwrap();

    let cost = state.bns_registry.calculate_cost(&name, duration);
    let mut renewal = lifecycle_tx(
        alice,
        cost,
        1,
        0,
        TransactionType::BnsRenew,
        bincode::serialize(&(name.clone(), duration)).unwrap(),
    );
    renewal.sign(&key);
    state.validate_transaction(&renewal).unwrap();
    Executor::apply_transaction_checked(&mut state, &renewal).unwrap();
    assert_eq!(
        state.bns_registry.names.get(&name).unwrap().expires_at,
        200,
        "renewal extends from the old expiry"
    );
    assert_eq!(state.get_balance(&alice), 100_000 - cost - 1);
    assert_eq!(state.get_nonce(&alice), 1);

    let mut transfer = lifecycle_tx(
        alice,
        0,
        1,
        1,
        TransactionType::BnsTransfer,
        bincode::serialize(&(name.clone(), bob)).unwrap(),
    );
    transfer.sign(&key);
    state.validate_transaction(&transfer).unwrap();
    Executor::apply_transaction_checked(&mut state, &transfer).unwrap();
    assert_eq!(state.bns_registry.resolve(&name, 100), Some(bob));
    assert_eq!(state.get_nonce(&alice), 2);

    let mut unauthorized = lifecycle_tx(
        alice,
        0,
        1,
        2,
        TransactionType::BnsTransfer,
        bincode::serialize(&(name, alice)).unwrap(),
    );
    unauthorized.sign(&key);
    state.validate_transaction(&unauthorized).unwrap();
    let error = Executor::apply_transaction_checked(&mut state, &unauthorized).unwrap_err();
    assert_eq!(error.code(), "bns_transfer_failed");
    assert_eq!(
        state.get_nonce(&alice),
        2,
        "refused transfers do not advance nonce"
    );
}
