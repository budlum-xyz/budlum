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

/// BLG-054 and BLG-134: non-canonical RLP and hex-prefix paths are refused.
#[test]
fn audit_lane_c_blg_054_non_canonical_rlp_and_hp_are_refused() {
    use crate::cross_domain::evm::{mpt, rlp};
    assert!(rlp::decode(&[0x81, 0x05]).is_err());
    assert!(rlp::decode(&[0x05]).is_ok());
    assert!(mpt::hp_decode(&[0x0f, 0x12]).is_err());
    assert!(mpt::hp_decode(&[0x00, 0x12]).is_ok());
}

/// BLG-130: the quorum short-circuit counts participants still out; rotation needs its branch.
#[test]
fn audit_lane_c_blg_130_quorum_early_decision_and_rotation_branch() {
    use crate::cross_domain::evm::sync_committee::{
        rotate_period, SyncCommitteeError, SyncCommitteeState, BLS_PUBKEY_LEN, SYNC_COMMITTEE_SIZE,
    };
    use crate::cross_domain::external::{lead_is_unassailable, Answer, QuorumPolicy};
    let claim = Answer::Claim([1u8; 32]);
    let policy = QuorumPolicy::strict(2, 16);
    assert!(!lead_is_unassailable(&[claim, claim], &policy, 3));
    assert!(lead_is_unassailable(&[claim, claim], &policy, 0));
    let mut state = SyncCommitteeState {
        current_period: 0,
        current_sync_committee: [[0u8; BLS_PUBKEY_LEN]; SYNC_COMMITTEE_SIZE],
        next_sync_committee: [[0xAAu8; BLS_PUBKEY_LEN]; SYNC_COMMITTEE_SIZE],
    };
    assert_eq!(
        rotate_period(&mut state),
        Err(SyncCommitteeError::RotationBranchRequired)
    );
    assert_eq!(state.current_period, 0);
}

/// BLG-058: the domain registry leaf commits to the allowlist and the plugin code hash.
#[test]
fn audit_lane_c_blg_058_domain_leaf_commits_allowlist_and_plugin_hash() {
    use crate::domain::registry::domain_leaf_hash;
    let base = default_domain(7, ConsensusKind::Zk, 45262, "zk-adapter", 1);
    let mut with_program = base.clone();
    with_program.zk_program_allowlist.push([5u8; 32]);
    let mut with_other = base.clone();
    with_other.zk_program_allowlist.push([6u8; 32]);
    let mut with_plugin = base.clone();
    with_plugin.plugin_code_hash = Some([9u8; 32]);
    let leaves = [
        domain_leaf_hash(&base),
        domain_leaf_hash(&with_program),
        domain_leaf_hash(&with_other),
        domain_leaf_hash(&with_plugin),
    ];
    for i in 0..leaves.len() {
        for j in (i + 1)..leaves.len() {
            assert_ne!(leaves[i], leaves[j], "leaves {i} and {j} share a digest");
        }
    }
}

// WP-33 testnet closures (directive 14.1 rule 8): the opcodes whose verification is not
// finished stay refused on the testnet chain id.
mod testnet_closures {
    use crate::core::account::AccountState;
    use crate::core::address::Address;
    use crate::core::chain_config::Network;
    use crate::core::transaction::{Transaction, TransactionType};
    use crate::crypto::primitives::KeyPair;
    use crate::execution::executor::Executor;
    use bud_isa::{Instruction, Opcode};

    fn program(opcode: Opcode) -> Vec<u8> {
        [opcode, Opcode::Halt]
            .into_iter()
            .flat_map(|op| {
                Instruction {
                    opcode: op,
                    rd: 1,
                    rs1: 2,
                    rs2: 3,
                    imm: 0,
                }
                .encode()
                .to_le_bytes()
            })
            .collect()
    }

    /// A signed `ContractCall` on the testnet chain id, applied to a funded account. The
    /// transaction must be refused for the activation gate, and leave no trace.
    fn refused_on_testnet(opcode: Opcode) {
        let keypair = KeyPair::generate().expect("keypair");
        let from = Address::from(keypair.public_key_bytes());
        let mut state = AccountState::new();
        state.add_balance(&from, 1_000);
        let mut tx = Transaction::new_with_chain_id(
            from,
            Address::zero(),
            0,
            5,
            0,
            program(opcode),
            Network::Testnet.chain_id().value(),
            TransactionType::ContractCall,
        );
        tx.sign(&keypair);
        let err = Executor::apply_transaction(&mut state, &tx)
            .expect_err("a gated opcode must not run on the testnet");
        assert!(
            err.contains("activation") || err.contains("Activation"),
            "{opcode:?} was refused for the wrong reason: {err}"
        );
        assert_eq!(state.get_balance(&from), 1_000, "no fee, no write");
        assert_eq!(state.get_nonce(&from), 0);
    }

    #[test]
    fn verify_merkle_is_closed_on_testnet() {
        refused_on_testnet(Opcode::VerifyMerkle);
    }

    #[test]
    fn verify_inference_is_closed_on_testnet() {
        refused_on_testnet(Opcode::VerifyInference);
    }
}
