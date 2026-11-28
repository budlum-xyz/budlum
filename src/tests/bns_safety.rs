//! BNS (Budlum Name Service) safety tests.

use crate::bns::BnsRegistry;

#[test]
fn bns_registry_starts_empty() {
    let reg = BnsRegistry::default();
    assert!(reg.names().is_empty());
}

#[test]
fn bns_registry_serde_round_trip() {
    let reg = BnsRegistry::default();
    let json = serde_json::to_string(&reg).expect("serialize");
    let parsed: BnsRegistry = serde_json::from_str(&json).expect("deserialize");
    assert!(parsed.names().is_empty());
}

#[test]
fn bns_grace_period_is_3000() {
    assert_eq!(BnsRegistry::GRACE_PERIOD, 3000);
}

#[test]
fn bns_max_names_starts_at_the_registry_parameter() {
    assert_eq!(crate::registry::params::DEFAULT_MAX_NAMES, 1_000_000);
    assert_eq!(
        BnsRegistry::default().max_names,
        crate::registry::params::DEFAULT_MAX_NAMES
    );
}

#[test]
fn bns_max_subdomains_per_name_is_1000() {
    assert_eq!(BnsRegistry::MAX_SUBDOMAINS_PER_NAME, 1_000);
}

#[test]
fn bns_base_cost_is_positive() {
    let reg = BnsRegistry::default();
    assert!(reg.base_cost > 0);
}

#[test]
fn bns_max_names_is_committed_to_account_state_root() {
    use crate::core::account::AccountState;

    let mut default_state = AccountState::default();
    let mut capped_two = AccountState::default();
    capped_two.bns_registry.max_names = 2;
    let mut capped_three = AccountState::default();
    capped_three.bns_registry.max_names = 3;

    assert!(!capped_two.bns_registry.is_empty());
    assert_ne!(
        default_state.calculate_state_root(),
        capped_two.calculate_state_root(),
        "non-default max_names must alter AccountState::calculate_state_root"
    );
    assert_ne!(
        capped_two.calculate_state_root(),
        capped_three.calculate_state_root(),
        "distinct max_names ceilings must alter AccountState::calculate_state_root"
    );
}
