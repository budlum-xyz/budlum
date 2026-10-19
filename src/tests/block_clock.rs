use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use std::sync::Arc;

fn fresh_chain() -> Blockchain {
    Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None)
}

#[test]
fn applying_a_block_sets_the_block_clock() {
    let mut bc = fresh_chain();
    let (block, _) = bc.produce_block(Address::from([0x11; 32])).unwrap();
    assert_eq!(
        bc.state.current_block_unix_secs,
        u64::try_from(block.timestamp / 1_000).unwrap()
    );
    let (block2, _) = bc.produce_block(Address::from([0x11; 32])).unwrap();
    assert_eq!(
        bc.state.current_block_unix_secs,
        u64::try_from(block2.timestamp / 1_000).unwrap()
    );
}

#[test]
fn block_clock_is_not_part_of_the_state_root() {
    let mut bc = fresh_chain();
    bc.state.current_block_unix_secs = 0;
    let root_zero = bc.state.calculate_state_root();
    bc.state.current_block_unix_secs = 1_700_000_000;
    assert_eq!(root_zero, bc.state.calculate_state_root());
}

#[test]
fn produced_timestamp_keeps_the_slot_formula() {
    let mut bc = fresh_chain();
    let index = bc.chain.len() as u64;
    let slot_ms = crate::core::chain_config::slot_ms_for_chain_id(bc.chain_id);
    let planned = bc.genesis_time + u128::from(index) * u128::from(slot_ms);
    let (block, _) = bc.produce_block(Address::from([0x22; 32])).unwrap();
    assert_eq!(block.timestamp, planned);
    assert_eq!(
        bc.state.current_block_unix_secs,
        u64::try_from(planned / 1_000).unwrap()
    );
}

#[test]
fn restored_state_carries_the_tip_clock() {
    let bc = fresh_chain();
    assert_eq!(bc.state.current_block_unix_secs, bc.current_unix_secs());
}
