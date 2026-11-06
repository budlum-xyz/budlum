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
