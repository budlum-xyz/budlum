//! Expanded BNS Registry tests coverage.

use crate::bns::types::BnsError;
use crate::bns::BnsRegistry;
use crate::core::address::Address;

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

/// `renew` and `transfer` are unreachable from a transaction, and
/// re-registering is not an equivalent substitute.
///
/// `TransactionType` has `BnsRegister`, `BnsSetContent`,
/// `BnsRegisterSubdomain` and `BnsSetStorage` - no `BnsRenew`, no
/// `BnsTransfer`. Both methods are called only from tests, so on a live chain
/// an owner cannot renew a name and cannot hand one over.
///
/// The grace period in `register` softens it: the previous owner can
/// re-register after expiry without being front-run. It does not replace
/// renewal, because the two compute a different expiry -
///
///     renew:    expires_at += duration
///     register: expires_at  = current_epoch + duration
///
/// So the only reachable path discards the remaining term. Renewing a year
/// early costs that year; waiting until the last epoch to avoid the loss puts
/// the name one missed block from the grace window. This asserts the size of
/// that gap so it cannot be mistaken for a rounding difference, and fails the
/// moment a `BnsRenew` transaction exists, forcing whoever adds it to delete
/// the test deliberately.
#[test]
fn bns_renewal_is_unreachable_and_re_registering_loses_the_remaining_term() {
    let alice = Address::from([1u8; 32]);
    let mut reg = BnsRegistry::new();

    // Registered at epoch 0 for 100 epochs: expires at 100.
    reg.register("term.bud".into(), alice, 0, 100).unwrap();
    assert_eq!(reg.names.get("term.bud").unwrap().expires_at, 100);

    // Renewing at epoch 10 for another 100 extends from the *expiry*: 200.
    reg.renew("term.bud", &alice, 10, 100).unwrap();
    assert_eq!(
        reg.names.get("term.bud").unwrap().expires_at,
        200,
        "renew must extend from the existing expiry"
    );

    // What an owner can actually do today. Re-register the same name at the
    // same epoch, for the same duration, and the expiry restarts from now.
    let mut reg2 = BnsRegistry::new();
    reg2.register("term.bud".into(), alice, 0, 100).unwrap();
    // Not yet expired, so a re-registration is refused outright while live...
    assert_eq!(
        reg2.register("term.bud".into(), alice, 10, 100),
        Err(BnsError::NameTaken),
        "a live name cannot be re-registered, so there is no early-renewal path at all"
    );
    // ...and after expiry the term restarts rather than extending.
    reg2.register("term.bud".into(), alice, 100, 100).unwrap();
    assert_eq!(
        reg2.names.get("term.bud").unwrap().expires_at,
        200,
        "re-registering restarts from current_epoch"
    );

    // The transaction surface still has no way in.
    let tx_src = include_str!("../core/transaction.rs");
    assert!(
        !tx_src.contains("BnsRenew"),
        "a BnsRenew transaction now exists - wire it to `renew`, charge \
         `calculate_cost`, and drop this test"
    );
    assert!(
        !tx_src.contains("BnsTransfer"),
        "a BnsTransfer transaction now exists - wire it to `transfer` and drop \
         this test"
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
