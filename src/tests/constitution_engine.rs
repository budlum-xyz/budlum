use crate::core::account::AccountState;
use crate::core::address::Address;

use crate::core::constitution::{
    ConstitutionParameter, ConstitutionParameterKey, ConstitutionValue,
};

#[test]
fn constitution_parameter_update_changes_state_root() {
    let mut state = AccountState::new();
    let owner = Address::from([0x44; 32]);
    state.add_balance(&owner, 1);

    let before = state.calculate_state_root();
    state
        .governance
        .constitution
        .set_parameter(ConstitutionParameter::new(
            ConstitutionParameterKey::MaxEmergencyHaltEpochs,
            ConstitutionValue::U64(720),
            42,
            [0xAB; 32],
        ))
        .unwrap();
    let after = state.calculate_state_root();

    assert_ne!(before, after);
}

#[test]
fn constitution_hard_guardrails_block_governance_read_override() {
    let mut state = AccountState::new();
    let err = state
        .governance
        .constitution
        .set_parameter(ConstitutionParameter::new(
            ConstitutionParameterKey::NoGovernanceReadOverride,
            ConstitutionValue::Bool(false),
            7,
            [0xCD; 32],
        ))
        .unwrap_err();

    assert!(err.contains("cannot be disabled"));
}

#[test]
fn constitution_hard_guardrails_preserve_permissionless_core() {
    let mut state = AccountState::new();
    let err = state
        .governance
        .constitution
        .set_parameter(ConstitutionParameter::new(
            ConstitutionParameterKey::PermissionlessCoreNoAdminWhitelist,
            ConstitutionValue::Bool(true),
            7,
            [0xEF; 32],
        ))
        .unwrap_err();

    assert!(err.contains("cannot be changed by governance"));
}
