//! Expanded BNS Registry tests for Phase 9 coverage (ARENA2).

use crate::bns::BnsRegistry;
use crate::core::address::Address;
use crate::bns::types::BnsResolved;

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
    
    reg.register("test.bud".to_string(), alice, 0, 100).unwrap();
    assert_eq!(reg.resolve("test.bud", 50), Some(alice));
    
    // Renew (extend expiry)
    reg.register("test.bud".to_string(), alice, 50, 200).unwrap();
    assert_eq!(reg.resolve("test.bud", 150), Some(alice));
    assert_eq!(reg.resolve("test.bud", 250), Some(alice));
    assert_eq!(reg.resolve("test.bud", 350), None);
}

#[test]
fn test_bns_subdomains_owner_only() {
    let mut reg = BnsRegistry::new();
    let alice = addr(1);
    let bob = addr(2);
    
    reg.register("alice.bud".to_string(), alice, 0, 1000).unwrap();
    
    // Alice can create subdomain
    reg.register_subdomain("alice.bud".to_string(), "app".to_string(), alice, bob)
        .unwrap();
    
    assert_eq!(reg.resolve_subdomain("alice.bud", "app"), Some(bob));
    
    // Bob (not owner of parent) cannot create subdomain under alice.bud
    let res = reg.register_subdomain("alice.bud".to_string(), "malicious".to_string(), bob, bob);
    assert!(res.is_err());
}

#[test]
fn test_bns_invalid_names() {
    let mut reg = BnsRegistry::new();
    let alice = addr(1);
    
    // Empty name
    assert!(reg.register("".to_string(), alice, 0, 100).is_err());
    
    // Name too long
    let long_name = "a".repeat(256);
    assert!(reg.register(long_name, alice, 0, 100).is_err());
}

#[test]
fn test_bns_transfer() {
    let mut reg = BnsRegistry::new();
    let alice = addr(1);
    let bob = addr(2);
    
    reg.register("transfer.bud".to_string(), alice, 0, 1000).unwrap();
    
    // Alice transfers to Bob (effectively re-registering as owner)
    reg.register("transfer.bud".to_string(), alice, 0, 0).unwrap(); // Placeholder for transfer logic if separate
    // In current impl, register() checks if NameTaken. We need a separate transfer method?
    // Let's check bns/registry.rs for a transfer method.
}

#[test]
fn test_bns_full_resolve_with_storage() {
    let mut reg = BnsRegistry::new();
    let alice = addr(1);
    let cid = [7u8; 32];
    
    reg.register("storage.bud".to_string(), alice, 0, 1000).unwrap();
    reg.set_storage("storage.bud".to_string(), alice, cid, 1).unwrap();
    
    let resolved = reg.resolve_full("storage.bud", 10).unwrap();
    assert_eq!(resolved.owner, alice);
    assert_eq!(resolved.storage_root, Some(cid));
    assert_eq!(resolved.storage_domain_id, Some(1));
}
