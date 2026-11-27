//! Regression tests for explorer WalletContextGraph duplicate-node/self-loop
//! refusals and AtlasQueryEngine duplicate-evidence eviction resistance.

use budlum_core::core::address::Address;
use budlum_core::domain::ConsensusKind;
use budlum_core::explorer_evidence::{
    AtlasQueryEngine, EvidenceRecord, WalletContextEdge, WalletContextGraph, WalletContextNode,
    WalletEdgeType, WalletNodeType, MAX_ATLAS_EVIDENCE_RECORDS,
};

#[test]
fn wallet_context_graph_refuses_duplicate_nodes_and_self_loop_edges() {
    let center = Address::from([0x01; 32]);
    let peer = Address::from([0x02; 32]);

    let dup_nodes = WalletContextGraph {
        center,
        nodes: vec![
            WalletContextNode {
                address: peer,
                node_type: WalletNodeType::User,
                connection_count: 1,
                last_active_epoch: 5,
            },
            WalletContextNode {
                address: peer,
                node_type: WalletNodeType::Validator,
                connection_count: 2,
                last_active_epoch: 6,
            },
        ],
        edges: Vec::new(),
        total_transfer_volume: 0,
        depth: 1,
    };
    assert!(
        dup_nodes.validate().is_err(),
        "duplicate node addresses in WalletContextGraph must be refused"
    );

    let self_loop = WalletContextGraph {
        center,
        nodes: Vec::new(),
        edges: vec![WalletContextEdge {
            from: center,
            to: center,
            edge_type: WalletEdgeType::Transfer,
            weight: 100,
            last_interaction_epoch: 5,
        }],
        total_transfer_volume: 100,
        depth: 1,
    };
    assert!(
        self_loop.validate().is_err(),
        "self-loop edge (from == to) in WalletContextGraph must be refused"
    );
}

#[test]
fn atlas_query_engine_deduplicates_replayed_evidence_slots_without_evicting_honest_records() {
    let mut engine = AtlasQueryEngine::new();
    let honest = EvidenceRecord {
        domain_id: 1,
        domain_height: 10,
        event_index: 0,
        event_kind: String::from("bridge_lock"),
        event_root: [0x11; 32],
        block_hash: [0x22; 32],
        verified_epoch: 1,
        consensus_kind: ConsensusKind::PoS,
    };
    engine
        .insert_evidence_record(honest)
        .expect("insert honest");

    // Replaying the exact same (domain_id=2, height=99, event_index=0) MAX_ATLAS_EVIDENCE_RECORDS
    // times must deduplicate in-place rather than evicting domain 1's honest evidence!
    let dup = EvidenceRecord {
        domain_id: 2,
        domain_height: 99,
        event_index: 0,
        event_kind: String::from("spam"),
        event_root: [0x33; 32],
        block_hash: [0x44; 32],
        verified_epoch: 2,
        consensus_kind: ConsensusKind::PoS,
    };
    for _ in 0..MAX_ATLAS_EVIDENCE_RECORDS {
        engine
            .insert_evidence_record(dup.clone())
            .expect("idempotent insert");
    }

    assert_eq!(
        engine.query_evidence_by_domain(1).len(),
        1,
        "replaying one duplicate evidence coordinate must not evict other domains' evidence"
    );
    assert_eq!(engine.query_evidence_by_domain(2).len(), 1);
}
