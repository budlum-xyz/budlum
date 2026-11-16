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
