//! Regression and exploit-validation suite for post-quantum reseal prechecks,
//! DAG tip-eviction replay safety, and PoH fork-choice witness verification.

use budlum_core::consensus::dag::{DAGConfig, DagEngine};
use budlum_core::consensus::poh::{PohConfig, PohEngine};
use budlum_core::consensus::ConsensusEngine;
use budlum_core::core::account::AccountState;
use budlum_core::core::block::Block;
use budlum_core::crypto::scheme::SchemeStatusRegistry;
use budlum_core::settlement::anchor_ledger::{AnchorKeyLedger, LedgerKey};
use budlum_core::settlement::pq_anchor::AnchorSignature;
use budlum_core::settlement::reseal::{
    covered_root, unsigned_certificate, verify_reseal, ResealAuthority, ResealError,
};

#[test]
fn reseal_refuses_zero_digest_leaf_and_checks_cardinality_before_crypto() {
    // 1. All-zero aggregate_root in covered anchors must be refused fail-closed.
    let zero_leaf_res = covered_root(&[(10, [0u8; 32])]);
    assert_eq!(
        zero_leaf_res,
        Err(ResealError::BadCoverage),
        "all-zero aggregate_root must not be accepted into a reseal Merkle tree"
    );

    // 2. Single signature (< ANCHOR_THRESHOLD = 2) with invalid signature bytes
    //    must fail with ThresholdNotReached BEFORE running ML-DSA-87 verification!
    let anchors = [(10u64, [0xAB; 32])];
    let mut cert = unsigned_certificate(45_262, 1, &anchors).expect("valid non-zero anchor");
    cert.authority = ResealAuthority::AnchorKeys(vec![AnchorSignature {
        key_index: 0,
        signature: vec![0xDE, 0xAD],
    }]);

    let ledger = AnchorKeyLedger {
        chain_id: 45_262,
        key_epoch: 1,
        anchor_keys: vec![
            LedgerKey {
                index: 0,
                vendor: "vendor-a".into(),
                public_key: vec![0x11; 2592],
            },
            LedgerKey {
                index: 1,
                vendor: "vendor-b".into(),
                public_key: vec![0x22; 2592],
            },
            LedgerKey {
                index: 2,
                vendor: "vendor-c".into(),
                public_key: vec![0x33; 2592],
            },
        ],
        seal_keys: Vec::new(),
        suspended: Default::default(),
        revoked_key_hashes: Default::default(),
    };
    let registry = SchemeStatusRegistry::genesis();
    let res = verify_reseal(&cert, 45_262, &ledger, &registry, &anchors);
    assert_eq!(
        res,
        Err(ResealError::ThresholdNotReached),
        "sub-quorum signature list must return ThresholdNotReached before ML-DSA verification"
    );
}

#[test]
fn dag_replaying_superseded_ancestors_must_not_evict_live_tip() {
    let engine = DagEngine::new(DAGConfig::default());
    let state = AccountState::new();
    let genesis_zero = "0000000000000000000000000000000000000000000000000000000000000000";

    // Build a linear chain of 260 DAG blocks: B_1 -> B_2 -> ... -> B_260.
    let mut blocks = Vec::with_capacity(260);
    let mut prev = genesis_zero.to_string();
    for h in 1..=260u64 {
        let mut b = Block::new_with_chain_id(h, prev.clone(), Vec::new(), 1);
        engine.prepare_block(&mut b, &state).expect("prepare");
        engine.add_block(&b).expect("add");
        prev = b.hash.clone();
        blocks.push(b);
    }
    assert!(
        engine.info().contains("tips: 1,"),
        "single chain must have 1 live tip before replay, got: {}",
        engine.info()
    );

    // Replay superseded ancestors B_1 .. B_256 (all already built upon!).
    for old_block in blocks.iter().take(256) {
        engine.add_block(old_block).expect("idempotent replay");
    }

    // Live tip B_260 MUST still be the sole tip (tips == 1).
    assert!(
        engine.info().contains("tips: 1,"),
        "replaying 256 superseded ancestors resurrected stale tips and evicted live tip: {}",
        engine.info()
    );

    // Genesis block (index == 0) claiming non-empty fake parents must also be refused.
    let mut fake_genesis = Block::new_with_chain_id(0, "deadbeef".to_string(), Vec::new(), 1);
    fake_genesis.hash = fake_genesis.calculate_hash();
    assert!(
        engine.validate_block(&fake_genesis, &[], &state).is_err(),
        "genesis DAG block with non-empty parent list must be refused"
    );
}

#[test]
fn poh_fork_choice_refuses_forged_hash_and_zero_work_witnessless_chain() {
    let cfg = PohConfig {
        hashes_per_slot: 8,
        seed: [0x42; 32],
    };
    let honest_engine = PohEngine::new(cfg.clone());
    let state = AccountState::new();

    // Honest 2-block PoH chain with real sequential SHA-256 witnesses: genesis -> B_1.
    let mut genesis = Block::new_with_chain_id(0, "0".repeat(64), Vec::new(), 1);
    genesis.timestamp = 1_000;
    genesis.hash = genesis.calculate_hash();

    let mut b1_honest = Block::new_with_chain_id(1, genesis.hash.clone(), Vec::new(), 1);
    b1_honest.timestamp = 1_001;
    honest_engine
        .prepare_block(&mut b1_honest, &state)
        .expect("honest PoH prepare");
    honest_engine
        .record_block(&b1_honest, None)
        .expect("honest PoH record");
    let honest_chain = vec![genesis.clone(), b1_honest];

    // Attack 1: 3-block fake PoH chain with ZERO sequential PoH work (empty vrf_proof / vrf_output)!
    let mut f1 = Block::new_with_chain_id(1, genesis.hash.clone(), Vec::new(), 1);
    f1.timestamp = 1_001;
    f1.hash = f1.calculate_hash();
    let mut f2 = Block::new_with_chain_id(2, f1.hash.clone(), Vec::new(), 1);
    f2.timestamp = 1_002;
    f2.hash = f2.calculate_hash();
    let witnessless_chain = vec![genesis, f1, f2];

    let eval_engine = PohEngine::new(cfg);
    assert!(
        honest_engine.fork_choice_score(&honest_chain) > 0,
        "honest PoH chain with valid witnesses must have positive score"
    );
    assert_eq!(
        eval_engine.fork_choice_score(&witnessless_chain),
        0,
        "zero-work witnessless candidate chain must score 0 in PoH fork choice"
    );
    assert!(
        !eval_engine.is_better_chain(&honest_chain, &witnessless_chain),
        "zero-work forged PoH chain must never beat honest PoH chain"
    );
}
