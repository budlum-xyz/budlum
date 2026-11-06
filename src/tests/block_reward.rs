use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;

use crate::core::transaction::{Transaction, TransactionType};
use crate::crypto::primitives::KeyPair;
use std::sync::Arc;

fn addr(b: u8) -> Address {
    Address::from([b; 32])
}

fn fresh_chain() -> Blockchain {
    Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None)
}

#[test]
fn nonzero_block_reward_config_cannot_mint() {
    let mut bc = fresh_chain();
    let producer = addr(0x11);
    bc.state.tokenomics.block_reward = 123;

    let balance_before = bc.state.get_balance(&producer);
    let supply_before = bc.state.total_bud_committed();
    bc.produce_block(producer).unwrap();

    assert_eq!(bc.state.get_balance(&producer), balance_before);
    assert_eq!(bc.state.total_bud_committed(), supply_before);
}

#[test]
fn block_reward_is_disabled_even_below_supply_cap() {
    let mut bc = fresh_chain();
    let producer = addr(0x22);
    bc.state.tokenomics.block_reward = 10_000;
    assert!(bc.state.supply_capacity_remaining() > 10_000);

    let supply_before = bc.state.total_bud_committed();
    bc.produce_block(producer).unwrap();

    assert_eq!(bc.state.get_balance(&producer), 0);
    assert_eq!(bc.state.total_bud_committed(), supply_before);
}

#[test]
fn epoch_transition_does_not_mint_validator_yield() {
    let mut bc = fresh_chain();
    let validator = addr(0x55);
    bc.state.add_balance(&validator, 10_000_000);
    bc.state.add_validator(validator, 1_000);

    let balance_before = bc.state.get_balance(&validator);
    let supply_before = bc.state.total_bud_committed();
    bc.state
        .advance_epoch(1_000, crate::core::transaction::DEFAULT_CHAIN_ID);

    assert_eq!(bc.state.get_balance(&validator), balance_before);
    assert_eq!(bc.state.total_bud_committed(), supply_before);
}

#[test]
fn flat_fee_block_credits_producer_once_after_metabolic_burn() {
    let mut bc = fresh_chain();
    let sender_key = KeyPair::generate().unwrap();
    let sender = Address::from(sender_key.public_key_bytes());
    let recipient = addr(0x66);
    let producer = addr(0x77);
    bc.state.add_balance(&sender, 1_000);
    bc.state.tokenomics.block_reward = 999_999;

    let mut tx = Transaction::new_with_chain_id(
        sender,
        recipient,
        1,
        100,
        0,
        Vec::new(),
        45262,
        TransactionType::Transfer,
    );
    tx.sign(&sender_key);
    bc.add_transaction(tx).unwrap();

    let supply_before = bc.state.total_bud_committed();
    bc.produce_block(producer).unwrap();

    // Default metabolic burn is 1%; validator receives the remaining 99 once.
    assert_eq!(bc.state.get_balance(&producer), 99);
    assert_eq!(bc.state.get_balance(&recipient), 1);
    assert_eq!(bc.state.get_balance(&sender), 899);
    assert_eq!(bc.state.total_bud_committed(), supply_before - 1);
}
