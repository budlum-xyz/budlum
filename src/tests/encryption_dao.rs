use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::governance::{GovernanceAction, ProposalStatus, ProposalType};
use crate::execution::executor::Executor;

fn addr(byte: u8) -> Address {
    Address::from([byte; 32])
}

fn policy(version: u32, max_grant_duration_blocks: u64) -> crate::pollen::EncryptionPolicy {
    crate::pollen::EncryptionPolicy {
        version,
        hpke_suite_id: 0x20,
        min_public_key_bytes: 32,
        max_grant_duration_blocks,
        deprecated_after_block: None,
        active: true,
    }
}

#[test]
fn dao_encryption_policy_update_changes_state_root_without_decrypt_authority() {
    let proposer = addr(1);
    let mut state = AccountState::new();
    state.add_balance(&proposer, 100);
    let before = state.calculate_state_root();

    state
        .governance
        .create_proposal(
            proposer,
            ProposalType::SetEncryptionPolicy(policy(1, 100)),
            0,
            10,
        )
        .unwrap();
    let proposal = state.governance.find_proposal_mut(0).unwrap();
    proposal.status = ProposalStatus::Passed;

    Executor::apply_block_checked(&mut state, &[], None).unwrap();
    assert_eq!(
        state
            .marketplace
            .get_encryption_policy(1)
            .unwrap()
            .max_grant_duration_blocks,
        100
    );
    let after = state.calculate_state_root();
    assert_ne!(
        before, after,
        "encryption policy must be state-root visible"
    );

    let json = serde_json::to_string(state.marketplace.get_encryption_policy(1).unwrap()).unwrap();
    assert!(!json.contains("decrypt"));
    assert!(!json.contains("private_key"));
    assert!(!json.contains("override"));
}

#[test]
fn invalid_encryption_policy_proposal_is_rejected_before_vote() {
    let proposer = addr(1);
    let mut state = AccountState::new();
    let err = state
        .governance
        .create_proposal(
            proposer,
            ProposalType::SetEncryptionPolicy(policy(1, 0)),
            0,
            10,
        )
        .unwrap_err();
    assert!(err.contains("max_grant_duration"));
}

#[test]
fn governance_action_for_encryption_policy_contains_only_parameters() {
    let action = GovernanceAction::SetEncryptionPolicy(policy(2, 500));
    let encoded = serde_json::to_string(&action).unwrap();
    assert!(encoded.contains("hpke_suite_id"));
    assert!(encoded.contains("max_grant_duration_blocks"));
    assert!(!encoded.contains("decrypt"));
    assert!(!encoded.contains("private"));
}
