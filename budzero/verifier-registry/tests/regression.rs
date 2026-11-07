//! Regression tests for `verifier-registry`.

use verifier_registry::address::Address;
use verifier_registry::evidence::{EvidenceError, ProofProvenance, SlashingProof, SlashingReport};
use verifier_registry::params::RegistryParams;
use verifier_registry::role::roles;

fn liveness(missed: u64, expected: u64) -> SlashingReport {
    SlashingReport::new(
        Address::from([1u8; 32]),
        roles::ATTESTER,
        SlashingProof::Liveness {
            window_start_epoch: 0,
            window_end_epoch: 10,
            missed,
            expected,
        },
        ProofProvenance::ConsensusVerified,
        Some(Address::from([2u8; 32])),
    )
}

/// A liveness offence needs a window that expected duties and a miss.
#[test]
fn zero_missed_liveness_report_is_refused() {
    assert!(liveness(0, 0).validate_shape().is_err());
    assert!(liveness(0, 10).validate_shape().is_err());
    assert_eq!(
        liveness(11, 10).validate_shape(),
        Err(EvidenceError::ImpossibleLivenessWindow)
    );
    // Control: a real miss inside the window is a valid offence.
    assert!(liveness(3, 10).validate_shape().is_ok());
}

/// A slashing deterrent cannot be configured to zero.
#[test]
fn zero_slash_ratios_are_refused() {
    assert!(RegistryParams::default().validate().is_ok());
    let no_malicious = RegistryParams {
        malicious_slash_ratio_fixed: 0,
        ..RegistryParams::default()
    };
    assert!(no_malicious.validate().is_err(), "0% malicious slash");
    let no_double_sign = RegistryParams {
        double_sign_slash_ratio_fixed: 0,
        ..RegistryParams::default()
    };
    assert!(no_double_sign.validate().is_err(), "0% double-sign slash");
}

#[test]
fn blg_069_state_root_commits_params_history_and_zero_liveness_refused() {
    use verifier_registry::registry::VerifierRegistry;
    let base = VerifierRegistry::default();
    let Ok(custom) = VerifierRegistry::with_params(RegistryParams {
        min_stake: 2_500,
        ..RegistryParams::default()
    }) else {
        panic!("valid params");
    };
    assert_ne!(base.state_root(), custom.state_root());
    assert!(liveness(0, 0).validate_shape().is_err());
    assert!(liveness(0, 5).validate_shape().is_err());
}

#[test]
fn blg_148_verifier_registry_caps_unbounded_params_and_zero_malice_slash() {
    use verifier_registry::params::{MAX_PARAM_AMOUNT, MAX_UNBONDING_EPOCHS};
    let max_stake = RegistryParams {
        min_stake: u64::MAX,
        ..RegistryParams::default()
    };
    assert!(max_stake.validate().is_err());
    let over_stake = RegistryParams {
        min_stake: MAX_PARAM_AMOUNT + 1,
        ..RegistryParams::default()
    };
    assert!(over_stake.validate().is_err());
    let max_epochs = RegistryParams {
        unbonding_epochs: u64::MAX,
        ..RegistryParams::default()
    };
    assert!(max_epochs.validate().is_err());
    let over_epochs = RegistryParams {
        unbonding_epochs: MAX_UNBONDING_EPOCHS + 1,
        ..RegistryParams::default()
    };
    assert!(over_epochs.validate().is_err());
    let zero_malice = RegistryParams {
        malicious_slash_ratio_fixed: 0,
        ..RegistryParams::default()
    };
    assert!(zero_malice.validate().is_err());
}
