use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use std::sync::Arc;

fn addr(b: u8) -> Address {
    Address::from([b; 32])
}

fn fresh_chain() -> Blockchain {
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, None, 1337, None);
    // Initialize empty blockchain correctly: it must have a block so the height advances!
    let producer = addr(0x11);
    let _ = bc.produce_block(producer).unwrap(); // Block 1
    bc
}

fn total_bud_committed(bc: &Blockchain) -> u128 {
    bc.state.circulating_supply()
        + bc.state.get_total_stake() as u128
        + bc.state
            .unbonding_queue
            .iter()
            .map(|entry| entry.amount as u128)
            .sum::<u128>()
}

#[test]
fn test_block_reward_from_config() {
    let mut bc = fresh_chain();
    let producer = addr(0x11);

    // Change config
    bc.state.tokenomics.block_reward = 123;
    let balance_before = bc.state.get_balance(&producer);

    // Produce block
    let _ = bc.produce_block(producer).unwrap();

    let balance_after = bc.state.get_balance(&producer);
    assert_eq!(balance_after, balance_before + 123);
}

#[test]
fn test_block_reward_hard_supply_cap() {
    use crate::tokenomics::BUD_TOTAL_SUPPLY;

    let mut bc = fresh_chain();
    let producer = addr(0x11);

    // Reset balances to zero so the supply is deterministic before the cap test.
    // The fresh chain already produced 1 block in setup, so without this reset
    // the supply would already include that block's reward.
    let addrs_to_burn: Vec<(Address, u64)> = bc
        .state
        .accounts
        .iter()
        .map(|(a, acc)| (*a, acc.balance))
        .collect();
    for (a, bal) in addrs_to_burn {
        bc.state.burn_from(&a, bal);
    }
    assert_eq!(bc.state.circulating_supply(), 0);

    let max = BUD_TOTAL_SUPPLY as u128;
    let non_circulating = bc.state.get_total_stake() as u128
        + bc.state
            .unbonding_queue
            .iter()
            .map(|entry| entry.amount as u128)
            .sum::<u128>();
    assert!(
        non_circulating <= max.saturating_sub(50),
        "test setup must leave at least 50 BUD room under cap"
    );

    // V144: hard cap is circulating + staked + unbonding, not circulating only.
    // Put the chain exactly 50 units below cap using the new denominator.
    bc.state
        .add_balance(&addr(0x99), (max - non_circulating - 50) as u64);
    assert_eq!(total_bud_committed(&bc), max - 50);

    // Configure block_reward = 100. Produce a block: producer should be paid
    // only the 50 that fits under the cap (clamped), not 100.
    bc.state.tokenomics.block_reward = 100;
    let _ = bc.produce_block(producer).unwrap();
    assert_eq!(
        total_bud_committed(&bc),
        max,
        "Total BUD should be exactly at the cap after the partial-mint block"
    );

    // Now produce another block with zero cap room: no more minted.
    let balance_producer_before = bc.state.get_balance(&producer);
    let _ = bc.produce_block(producer).unwrap();
    let balance_producer_after = bc.state.get_balance(&producer);
    // Only tx fees (zero here, empty txs) → producer balance unchanged.
    assert_eq!(
        balance_producer_after, balance_producer_before,
        "Producer must NOT receive block_reward when total BUD is at cap"
    );
    assert_eq!(
        total_bud_committed(&bc),
        max,
        "Total BUD must remain exactly at the cap"
    );
}

#[test]
fn test_epoch_based_stake_yield_distribution() {
    // Task 0.60 Görev 2: anlamlı ödül eşiği. Default tokenomics (5% APY, 10s slot,
    // 32 slots/epoch) ile küçük stake'ler (1k) .max(1) tabanına yuvarlanır —
    // bu, gerçek formülün dürüst sonucu. Test, "minimum stake bile en az 1
    // BUD alır" invariant'ını doğrular (anlamlı ödülün alt sınırı).
    let mut bc = fresh_chain();
    let val1 = addr(0x55);
    bc.state.add_balance(&val1, 10_000_000);
    bc.state.add_validator(val1, 1_000);

    let bal1_before = bc.state.get_balance(&val1);
    bc.state.advance_epoch(1_000);
    let bal1_after = bc.state.get_balance(&val1);
    let yield1 = bal1_after - bal1_before;

    // Minimum-stake validator earns the .max(1) floor — explicit invariant.
    assert!(
        yield1 >= 1,
        "Minimum-stake validator must earn at least 1 BUD per epoch (got {yield1})"
    );
}

#[test]
fn test_epoch_based_stake_yield_exact_ratio() {
    // Stake-orantılı yield: iki validatorün yield'i stake oranıyla
    // orantılı olmalı. Default tokenomics ile 10B/20B stake = 1:2 oran.
    let mut bc = fresh_chain();
    let val1 = addr(0x55);
    let val2 = addr(0x66);

    bc.state.add_balance(&val1, 100_000_000_000);
    bc.state.add_validator(val1, 10_000_000_000);

    bc.state.add_balance(&val2, 200_000_000_000);
    bc.state.add_validator(val2, 20_000_000_000);

    let bal1_before = bc.state.get_balance(&val1);
    let bal2_before = bc.state.get_balance(&val2);

    bc.state.advance_epoch(1_000);

    let yield1 = bc.state.get_balance(&val1) - bal1_before;
    let yield2 = bc.state.get_balance(&val2) - bal2_before;

    // 1:2 stake oranı → 1:2 yield oranı. BUD hassasiyetiyle diff <= 2.
    assert!(yield1 > 0, "yield1 must be > 0 (got {yield1})");
    assert!(yield2 > 0, "yield2 must be > 0 (got {yield2})");
    let diff = yield2.abs_diff(yield1 * 2);
    assert!(
        diff <= 2,
        "yield2 must be ~2x yield1 (ratio 1:2 stake); diff={diff}"
    );
}
