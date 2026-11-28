//! Regression tests for genesis tokenomics distinct/non-zero allocation
//! addresses, zero-address validator reward exclusion, and cross-domain message
//! domain/sender/kind bounds.

use budlum_core::core::account::AccountState;
use budlum_core::core::address::Address;
use budlum_core::cross_domain::message::{
    register_cross_domain_on_state, CrossDomainMessage, CrossDomainMessageParams, MessageKind,
};
use budlum_core::tokenomics::reward_pool::{reward_for_epoch, RewardPoolSchedule};
use budlum_core::tokenomics::{genesis_allocations, TokenomicsAddresses, TokenomicsParams};

#[test]
fn genesis_allocations_refuses_duplicate_or_zero_pool_addresses_and_rewards_skip_zero_address() {
    let params = TokenomicsParams::default();
    let mut dup_addrs = TokenomicsAddresses::reserved();
    dup_addrs.team = dup_addrs.community;
    assert!(
        genesis_allocations(&params, &dup_addrs).is_err(),
        "overlapping genesis allocation addresses co-mingle vested and liquid supply and must fail"
    );

    let mut zero_addrs = TokenomicsAddresses::reserved();
    zero_addrs.burn_reserve = Address::zero();
    assert!(
        genesis_allocations(&params, &zero_addrs).is_err(),
        "zero-address genesis allocation must fail closed"
    );

    // Zero address in active_validator_stakes must never capture validator rewards or dust.
    let honest = Address::from([0x77; 32]);
    let payouts = reward_for_epoch(
        RewardPoolSchedule::default(),
        0,
        RewardPoolSchedule::default().validation_reward_pool,
        &[(Address::zero(), 500_000), (honest, 500_000)],
    );
    assert_eq!(
        payouts.len(),
        1,
        "Address::zero() must be excluded from payouts"
    );
    assert_eq!(payouts[0].0, honest);
}

#[test]
fn register_cross_domain_refuses_zero_domains_zero_endpoints_and_oversized_custom_kind() {
    let mut state = AccountState::new();
    state.current_block_height = 10;

    let zero_src = CrossDomainMessage::new(CrossDomainMessageParams {
        source_domain: 0,
        target_domain: 2,
        source_height: 5,
        event_index: 0,
        nonce: 1,
        sender: Address::from([0x11; 32]),
        recipient: Address::from([0x22; 32]),
        payload_hash: [0xAA; 32],
        kind: MessageKind::BridgeLock,
        expiry_height: 100,
    });
    assert!(
        register_cross_domain_on_state(&mut state, &zero_src).is_err(),
        "source_domain == 0 must be refused"
    );

    let zero_recipient = CrossDomainMessage::new(CrossDomainMessageParams {
        source_domain: 1,
        target_domain: 2,
        source_height: 5,
        event_index: 0,
        nonce: 2,
        sender: Address::from([0x11; 32]),
        recipient: Address::zero(),
        payload_hash: [0xBB; 32],
        kind: MessageKind::BridgeLock,
        expiry_height: 100,
    });
    assert!(
        register_cross_domain_on_state(&mut state, &zero_recipient).is_err(),
        "Address::zero() recipient must be refused"
    );

    let huge_custom = CrossDomainMessage::new(CrossDomainMessageParams {
        source_domain: 1,
        target_domain: 2,
        source_height: 5,
        event_index: 0,
        nonce: 3,
        sender: Address::from([0x11; 32]),
        recipient: Address::from([0x22; 32]),
        payload_hash: [0xCC; 32],
        kind: MessageKind::Custom(vec![0x41; 4_096]),
        expiry_height: 100,
    });
    assert!(
        register_cross_domain_on_state(&mut state, &huge_custom).is_err(),
        "oversized Custom(4096B) message kind must be refused"
    );
}
