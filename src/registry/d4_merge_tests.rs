//! D4 — Verifier Registry Birleştirme (merge) scenario tests.
//!
//! These tests prove the *single* stake-based [`PermissionlessRegistry`] serves
//! all four v1 application domains from one primitive, as required by the D4
//! decision (2026-07-22):
//!
//! 1. DeEd master verifier      → `MASTER_VERIFIER` (RoleId 2, alias of `VERIFIER`)
//! 2. SocialFi content validator → `CONTENT_VALIDATOR` (RoleId 9)
//! 3. Permissionless relayer     → `RELAYER` (RoleId 3)
//! 4. Supply-chain attester      → `ATTESTER` (RoleId 7)
//!
//! and that `LUBOT_OPERATOR` (RoleId 8) is preserved (never removed).
//!
//! There is exactly ONE registry type and ONE stake/slashing model — no
//! per-domain allow-lists, no separate registries. The consumer gates
//! (`ensure_active_relayer`, `ensure_active_attester`) are the same methods
//! the production paths [`crate::chain::blockchain::Blockchain::submit_relay_proof`]
//! and `verify_domain_commitment_finality` call, so these tests exercise the
//! exact primitive the four domains share.
#![cfg(test)]

use super::*;
use crate::core::address::Address;
use crate::core::chain_config::FIXED_POINT_SCALE;
use crate::registry::role::roles;

fn addr(b: u8) -> Address {
    Address::from([b; 32])
}

/// One registry instance simultaneously serves all four v1 domains plus the
/// preserved `LUBOT_OPERATOR` role. This is the core D4 "merge" assertion.
#[test]
fn d4_single_registry_serves_all_four_domains() {
    let mut reg = PermissionlessRegistry::new();

    // Four distinct v1 domains registered on the SAME registry primitive.
    reg.register_master_verifier(addr(1), MIN_REGISTRATION_STAKE, 0)
        .expect("master verifier (DeEd) registration");
    reg.register_content_validator(addr(2), MIN_REGISTRATION_STAKE, 0)
        .expect("content validator (SocialFi) registration");
    reg.register_relayer(addr(3), MIN_REGISTRATION_STAKE, 0)
        .expect("relayer registration");
    reg.register_attester(addr(4), MIN_REGISTRATION_STAKE, 0)
        .expect("attester (supply-chain) registration");

    // LUBOT_OPERATOR must remain preserved (D4 acceptance criterion).
    reg.register_lubot_operator(addr(5), MIN_REGISTRATION_STAKE, 0)
        .expect("lubot operator registration");

    assert!(reg.is_active_master_verifier(&addr(1)));
    assert!(reg.is_active_content_validator(&addr(2)));
    assert!(reg.is_active_relayer(&addr(3)));
    assert!(reg.is_active_attester(&addr(4)));
    assert!(reg.is_active_lubot_operator(&addr(5)));

    // Exactly one registry holds every entry (no per-domain split).
    assert_eq!(reg.len(), 5);
}

/// The same account can hold all four domain roles simultaneously under the
/// merged model, with independent stakes but unified slashing.
#[test]
fn d4_same_account_holds_all_four_domains() {
    let mut reg = PermissionlessRegistry::new();
    let a = addr(42);

    reg.register_master_verifier(a, 10_000, 0).unwrap();
    reg.register_content_validator(a, 2_000, 0).unwrap();
    reg.register_relayer(a, MIN_REGISTRATION_STAKE, 0).unwrap();
    reg.register_attester(a, 5_000, 0).unwrap();

    assert!(reg.is_active_master_verifier(&a));
    assert!(reg.is_active_content_validator(&a));
    assert!(reg.is_active_relayer(&a));
    assert!(reg.is_active_attester(&a));
    assert_eq!(reg.len(), 4);
}

/// `MASTER_VERIFIER` (RoleId 2) is a true alias of `VERIFIER` — DeEd master
/// verifiers ARE generic verifiers in the unified registry.
#[test]
fn d4_master_verifier_is_verifier_alias() {
    let mut reg = PermissionlessRegistry::new();
    reg.register_master_verifier(addr(11), MIN_REGISTRATION_STAKE, 0)
        .unwrap();

    assert!(reg.is_active_master_verifier(&addr(11)));
    assert!(reg.is_active(&addr(11), roles::VERIFIER));
    assert_eq!(roles::MASTER_VERIFIER, roles::VERIFIER);
    assert_eq!(roles::MASTER_VERIFIER.value(), 2);
}

/// Relayer domain gate: the primitive the production `submit_relay_proof` path
/// uses rejects unregistered / inactive accounts and admits staked ones.
#[test]
fn d4_relayer_gate_enforces_active_registration() {
    let mut reg = PermissionlessRegistry::new();

    // Unregistered account cannot act as relayer.
    assert!(reg.ensure_active_relayer(&addr(1)).is_err());
    assert!(!reg.is_active_relayer(&addr(1)));

    // Staked account is admitted.
    reg.register_relayer(addr(1), MIN_REGISTRATION_STAKE, 0)
        .unwrap();
    assert!(reg.ensure_active_relayer(&addr(1)).is_ok());
    assert!(reg.is_active_relayer(&addr(1)));

    // Below the stake floor: rejected (stake, not permission, is the gate).
    let below = reg.register_relayer(addr(2), MIN_REGISTRATION_STAKE - 1, 0);
    assert!(matches!(
        below,
        Err(RegistryError::InsufficientStake { .. })
    ));
}

/// Supply-chain attester gate: the primitive `verify_domain_commitment_finality`
/// calls to authorize PoA authorities.
#[test]
fn d4_attester_gate_enforces_active_registration() {
    let mut reg = PermissionlessRegistry::new();

    assert!(reg.ensure_active_attester(&addr(1)).is_err());
    assert!(!reg.is_active_attester(&addr(1)));

    reg.register_attester(addr(1), MIN_REGISTRATION_STAKE, 0)
        .unwrap();
    assert!(reg.ensure_active_attester(&addr(1)).is_ok());
    assert!(reg.is_active_attester(&addr(1)));
}

/// Unified slashing: slashing an account on ANY role jails every other role it
/// holds across all four domains — proving the merged stake model is shared.
#[test]
fn d4_cross_role_slash_jails_all_four_domains() {
    let mut reg = PermissionlessRegistry::new();
    let a = addr(77);

    reg.register_validator(a, 10_000, 0).unwrap();
    reg.register_master_verifier(a, MIN_REGISTRATION_STAKE, 0)
        .unwrap();
    reg.register_content_validator(a, 2_000, 0).unwrap();
    reg.register_relayer(a, MIN_REGISTRATION_STAKE, 0).unwrap();
    reg.register_attester(a, 5_000, 0).unwrap();

    // Slash on the validator role for double-signing.
    reg.slash(
        a,
        roles::VALIDATOR,
        SlashingCondition::DoubleSign,
        FIXED_POINT_SCALE / 2,
    )
    .unwrap();

    // Every domain role the account held is now jailed.
    assert!(!reg.is_active(&a, roles::VALIDATOR));
    assert!(!reg.is_active_master_verifier(&a));
    assert!(!reg.is_active_content_validator(&a));
    assert!(!reg.is_active_relayer(&a));
    assert!(!reg.is_active_attester(&a));

    let validator = reg.get(&a, roles::VALIDATOR).unwrap();
    assert_eq!(validator.stake, 5_000);
    assert!(matches!(validator.status, MemberStatus::Slashed));
}

/// LUBOT_OPERATOR (RoleId 8) is preserved across the D4 merge — its RoleId is
/// pinned and its registration path is intact.
#[test]
fn d4_lubot_operator_preserved() {
    let mut reg = PermissionlessRegistry::new();
    reg.register_lubot_operator(addr(8), MIN_REGISTRATION_STAKE, 0)
        .unwrap();

    assert!(reg.is_active_lubot_operator(&addr(8)));
    assert_eq!(roles::LUBOT_OPERATOR.value(), 8);

    // Slashing the validator role of the same account also jails its lubot
    // operator role — the merged model never leaves a role behind.
    let a = addr(8);
    reg.register_validator(a, 10_000, 0).unwrap();
    reg.slash(
        a,
        roles::VALIDATOR,
        SlashingCondition::DoubleSign,
        FIXED_POINT_SCALE / 2,
    )
    .unwrap();
    assert!(!reg.is_active_lubot_operator(&a));
}

/// Slashing a malicious relayer (the `relayer_invalid_proof` / `MaliciousBehaviour`
/// path used by D1) jails its other domain roles too — griefing/front-running
/// on one domain cannot be laundered through another.
#[test]
fn d4_malicious_relayer_slash_jails_other_domains() {
    let mut reg = PermissionlessRegistry::new();
    let a = addr(99);

    reg.register_relayer(a, MIN_REGISTRATION_STAKE, 0).unwrap();
    reg.register_attester(a, 5_000, 0).unwrap();
    reg.register_content_validator(a, 2_000, 0).unwrap();

    reg.slash(
        a,
        roles::RELAYER,
        SlashingCondition::MaliciousBehaviour,
        FIXED_POINT_SCALE, // 100% — default malicious_slash_ratio_fixed
    )
    .unwrap();

    assert!(!reg.is_active_relayer(&a));
    assert!(!reg.is_active_attester(&a));
    assert!(!reg.is_active_content_validator(&a));
}
