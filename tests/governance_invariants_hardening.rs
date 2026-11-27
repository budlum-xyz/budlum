//! Regression tests for on-chain governance voting bounds, zero-stake/zero-quorum
//! refusals, and PoA proposal validation.

use budlum_core::core::address::Address;
use budlum_core::core::governance::{GovernanceState, Proposal, ProposalStatus, ProposalType};

#[test]
fn proposal_refuses_zero_stake_pre_start_votes_and_zero_quorum_finalization() {
    // 1. Overflowing start_epoch + duration in Proposal::new must saturate instead of panicking.
    let p_sat = Proposal::new(
        1,
        Address::from([0x11; 32]),
        ProposalType::ChangeBlockReward(0),
        u64::MAX - 2,
        10,
    );
    assert_eq!(p_sat.end_epoch, u64::MAX);

    // 2. Pre-start voting (current_epoch < start_epoch) and zero-stake voting must fail closed.
    let mut prop = Proposal::new(
        2,
        Address::from([0x11; 32]),
        ProposalType::ChangeBlockReward(0),
        10,
        20,
    );
    assert!(
        prop.add_vote(Address::from([0x22; 32]), 1_000, true, 9)
            .is_err(),
        "vote cast before start_epoch must be refused"
    );
    assert!(
        prop.add_vote(Address::from([0x22; 32]), 0, true, 10)
            .is_err(),
        "zero-stake vote must be refused to prevent map-bloat and slot-locking"
    );

    // 3. Finalizing with total_stake == 0 or quorum_pct == 0 must fail closed (Failed, never Passed).
    prop.add_vote(Address::from([0x33; 32]), 100, true, 12)
        .expect("valid stake vote in active window");
    let mut zero_quorum = prop.clone();
    zero_quorum.finalize(1_000_000, 0, 30);
    assert_eq!(
        zero_quorum.status,
        ProposalStatus::Failed,
        "quorum_pct == 0 must never pass a governance proposal"
    );

    let mut zero_total_stake = prop;
    zero_total_stake.finalize(0, 50, 30);
    assert_eq!(
        zero_total_stake.status,
        ProposalStatus::Failed,
        "total_stake == 0 must never pass a governance proposal"
    );
}

#[test]
fn governance_state_refuses_zero_proposer_and_malformed_poa_compliance_proposals() {
    let mut gov = GovernanceState::default();
    assert!(
        gov.create_proposal(Address::zero(), ProposalType::ChangeBlockReward(0), 10, 1,)
            .is_err(),
        "zero-address proposer must be refused"
    );

    let proposer = Address::from([0x55; 32]);
    assert!(
        gov.create_proposal(
            proposer,
            ProposalType::VerifyHubApp {
                app_id: 1,
                developer: Address::zero(),
                manifest_id: None,
                website_url_hash: [0x99; 32],
            },
            10,
            1,
        )
        .is_err(),
        "VerifyHubApp with zero developer must be refused at submission"
    );
    assert!(
        gov.create_proposal(
            proposer,
            ProposalType::FreezePoaAccount {
                domain_id: 0,
                admin: Address::from([0x01; 32]),
                address: Address::from([0x02; 32]),
                reason_hash: [0xAB; 32],
            },
            10,
            1,
        )
        .is_err(),
        "PoA compliance proposal targeting domain_id 0 must be refused at submission"
    );
    assert!(
        gov.create_proposal(
            proposer,
            ProposalType::FreezePoaAccount {
                domain_id: 7,
                admin: Address::from([0x01; 32]),
                address: Address::from([0x02; 32]),
                reason_hash: [0u8; 32],
            },
            10,
            1,
        )
        .is_err(),
        "PoA freeze proposal with all-zero reason_hash must be refused at submission"
    );
}
