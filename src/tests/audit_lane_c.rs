//! Lane C live-verification regression tests (WP-01 to WP-04).
//!
//! Only "previously fixed" findings live here: each test is green and stays
//! permanent (directive section 14.1 rule 7). Repro tests for findings that are
//! still open live on the `audit/repro-c` branch and do not merge.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use crate::cross_domain::AssetId;
use crate::domain::plugin::default_domain;
use crate::domain::ConsensusKind;
use std::sync::Arc;

fn lane_c_addr(b: u8) -> Address {
    Address::from([b; 32])
}

fn lane_c_asset() -> AssetId {
    AssetId([42u8; 32])
}

/// A chain with two bridge-enabled PoW domains (1, 2) and one registered asset.
fn lane_c_bridge_chain() -> Blockchain {
    let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None);
    for (id, operator) in [(1u32, lane_c_addr(11)), (2u32, lane_c_addr(12))] {
        let mut d = default_domain(id, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 1);
        d.operator = Some(operator);
        d.operator_bond = 100_000;
        d.bridge_enabled = true;
        bc.register_consensus_domain(d)
            .expect("domain must register");
    }
    bc.register_bridge_asset(lane_c_asset(), 1)
        .expect("asset must register");
    bc
}

/// BLG-043: the burn debits the holder exactly what the mint credited and records it on
/// the row; the unlock refund basis is that recorded amount.
#[test]
fn audit_lane_c_blg_043_burn_records_the_debit_the_unlock_refunds() {
    let mut bc = lane_c_bridge_chain();
    let (owner, recipient) = (lane_c_addr(77), lane_c_addr(12));
    bc.state.add_balance(&owner, 1_000);
    let (_, lock_event) = bc
        .lock_bridge_transfer(1, 2, 20, 0, lane_c_asset(), owner, recipient, 400, 1_000)
        .expect("lock");
    assert_eq!(bc.state.get_balance(&owner), 600, "lock debits the owner");
    let message = lock_event.message.expect("lock carries a message");
    let params = *bc.state.registry.params();
    let (held, _fee) = crate::cross_domain::bridge::split_bridge_fee(
        crate::core::money::Bud::new(400),
        params.bridge_relayer_fee_ppm,
        params.bridge_relayer_min_fee,
    )
    .expect("a 400 transfer covers the fee");
    bc.state.bridge_state.mint(&message, 20).expect("mint");
    bc.state.get_or_create(&recipient).balance += held.get();
    let before = bc.state.get_balance(&recipient);
    bc.burn_bridge_transfer_with_event(message.message_id, 2, 40, 0, 0, [7u8; 20])
        .expect("burn");
    assert_eq!(before - bc.state.get_balance(&recipient), held.get());
    let row = bc
        .state
        .bridge_state
        .transfer(&message.message_id)
        .expect("row");
    assert_eq!(row.burned_amount, held.get());
    bc.state
        .bridge_state
        .unlock(message.message_id, 2, 41)
        .expect("unlock");
    let row = bc
        .state
        .bridge_state
        .transfer(&message.message_id)
        .expect("row");
    assert_eq!(row.burned_amount, held.get());
}

/// BLG-043: a mint carrying no committed proof is refused and creates no supply.
#[test]
fn audit_lane_c_blg_043_unproven_mint_creates_no_supply() {
    let mut bc = lane_c_bridge_chain();
    let (owner, recipient) = (lane_c_addr(77), lane_c_addr(12));
    bc.state.add_balance(&owner, 1_000);
    let (_, lock_event) = bc
        .lock_bridge_transfer(1, 2, 20, 0, lane_c_asset(), owner, recipient, 400, 1_000)
        .expect("lock");
    let supply_before = bc.state.total_bud_committed();
    let refused = bc.mint_bridge_transfer_from_verified_event(
        1,
        20,
        0,
        Some([0xAAu8; 32]),
        lock_event,
        &crate::cross_domain::MerkleProof {
            leaf: [0u8; 32],
            index: 0,
            siblings: vec![],
        },
        lane_c_addr(99),
    );
    assert!(refused.is_err());
    assert_eq!(bc.state.get_balance(&recipient), 0);
    assert_eq!(bc.state.get_balance(&lane_c_addr(99)), 0);
    assert_eq!(bc.state.total_bud_committed(), supply_before);
}

/// BLG-057: expired and replayed messages cannot be minted; the fee split cannot overflow.
#[test]
fn audit_lane_c_blg_057_mint_refuses_expired_and_replayed_messages() {
    use crate::cross_domain::BridgeState;
    let mut bs = BridgeState::new();
    let a = AssetId([3u8; 32]);
    bs.register_asset(a, 1).expect("asset");
    let (owner, recipient) = (lane_c_addr(5), lane_c_addr(6));
    let (_, event) = bs
        .lock(1, 2, 20, 0, a, owner, recipient, 100, 1_000)
        .expect("lock");
    let message = event.message.expect("message");
    assert!(bs.mint(&message, 1_001).is_err(), "expired mint refused");
    bs.mint(&message, 1_000)
        .expect("the expiry block itself is live");
    assert!(bs.mint(&message, 1_000).is_err(), "replay refused");
    let (held, fee) = crate::cross_domain::bridge::split_bridge_fee(
        crate::core::money::Bud::new(u64::MAX),
        10_000,
        10,
    )
    .expect("the top of the range splits without overflow");
    assert_eq!(
        u128::from(held.get()) + u128::from(fee.get()),
        u128::from(u64::MAX)
    );
}

/// BLG-194: a refused relay keeps its pending entry, and the supply ceiling refuses a mint.
#[test]
fn audit_lane_c_blg_194_refused_relay_keeps_pending_entry_and_ceiling_holds() {
    let mut bc = lane_c_bridge_chain();
    let (owner, recipient) = (lane_c_addr(77), lane_c_addr(12));
    bc.state.add_balance(&owner, 1_000);
    let (_, lock_event) = bc
        .lock_bridge_transfer(1, 2, 20, 0, lane_c_asset(), owner, recipient, 400, 1_000)
        .expect("lock");
    let message_id = lock_event.message.expect("message").message_id;
    assert_eq!(bc.pending_relay_count(), 1);
    let refused = crate::cross_domain::bridge_tx::submit_relay_proof(
        &mut bc.state,
        message_id,
        lane_c_addr(99),
        &crate::cross_domain::MerkleProof {
            leaf: [0u8; 32],
            index: 0,
            siblings: vec![],
        },
        1,
        30,
    );
    assert!(refused.is_err());
    assert_eq!(bc.pending_relay_count(), 1);
    assert!(!bc.state.settlement.relayer.is_relayed(&message_id));
    let mut full = crate::core::account::AccountState::new();
    full.add_balance(&lane_c_addr(1), crate::tokenomics::BUD_TOTAL_SUPPLY);
    assert!(full.ensure_mint_headroom(1).is_err());
}

/// BLG-052: a compliance freeze has an unfreeze.
#[test]
fn audit_lane_c_blg_052_compliance_freeze_can_be_lifted() {
    use crate::registry::poa_compliance::{ComplianceDomainKind, PoaComplianceRegistry};
    let mut registry = PoaComplianceRegistry::new();
    let (admin, subject) = (lane_c_addr(1), lane_c_addr(2));
    let domain = ComplianceDomainKind::PoA;
    registry
        .freeze_suspicious(domain, admin, subject, [7u8; 32], 10)
        .expect("freeze");
    assert!(registry.is_frozen(domain, &subject));
    registry
        .unfreeze(domain, admin, subject, [8u8; 32], 11)
        .expect("unfreeze");
    assert!(!registry.is_frozen(domain, &subject));
    assert_eq!(registry.frozen_count(), 0);
    assert!(registry
        .freeze_suspicious(domain, Address::zero(), subject, [7u8; 32], 12)
        .is_err());
}
