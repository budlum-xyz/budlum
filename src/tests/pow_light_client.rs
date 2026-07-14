use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use crate::cross_domain::DomainEventTree;
use crate::domain::finality_adapter::leading_zero_bits;
use crate::domain::{
    default_domain, hash_finality_proof, hash_pow_header, ConsensusKind, DomainCommitment,
    FinalityProof, PoWDomainParameters, PoWHeader, POW_HEADER_CHAIN_ADAPTER,
};
use std::collections::BTreeMap;
use std::sync::Arc;

fn address(byte: u8) -> Address {
    Address::from([byte; 32])
}

fn mine_header(
    domain: &crate::domain::ConsensusDomain,
    mut header: PoWHeader,
) -> (PoWHeader, [u8; 32]) {
    loop {
        let hash = hash_pow_header(domain, &header).expect("supported hash scheme");
        if leading_zero_bits(&hash) >= header.difficulty_bits {
            return (header, hash);
        }
        header.nonce = header.nonce.checked_add(1).expect("test nonce space");
    }
}

#[test]
fn tur13_5_pow_header_finality_authorizes_bridge_mint_but_legacy_does_not() {
    let mut chain = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 1337, None);

    let mut source = default_domain(41, ConsensusKind::PoW, 41_001, POW_HEADER_CHAIN_ADAPTER, 3);
    source.operator = Some(address(41));
    source.bridge_enabled = true;
    source.pow_parameters = Some(PoWDomainParameters {
        min_difficulty_bits: 4,
        max_difficulty_bits: 8,
        min_cumulative_work: 3 * (1u128 << 4),
        max_headers: 8,
    });
    chain
        .register_consensus_domain(source.clone())
        .expect("light-client domain registration");

    let mut target = default_domain(42, ConsensusKind::PoA, 42_001, "poa-authority-quorum", 0);
    target.operator = Some(address(42));
    target.bridge_enabled = true;
    chain
        .register_consensus_domain(target)
        .expect("target domain registration");

    // The legacy domain remains usable for archival settlement, but its
    // self-declared confirmation proof must never authorize mint.
    let mut legacy = default_domain(43, ConsensusKind::PoW, 43_001, "pow-confirmation-depth", 64);
    legacy.operator = Some(address(43));
    legacy.bridge_enabled = true;
    chain
        .register_consensus_domain(legacy)
        .expect("legacy domain remains decodable/registerable");

    let asset = [0xA5; 32];
    chain
        .register_bridge_asset(asset, source.id)
        .expect("asset registration");
    let (_transfer, event) = chain
        .lock_bridge_transfer(source.id, 42, 1, 0, asset, address(7), address(8), 500, 100)
        .expect("bridge lock");

    let mut events = DomainEventTree::new();
    events.push(event.clone());
    let event_proof = events.proof(0).expect("single-event proof");

    let mut commitment = DomainCommitment {
        domain_id: source.id,
        domain_height: 1,
        domain_block_hash: [0u8; 32],
        parent_domain_block_hash: [0u8; 32],
        state_root: [1u8; 32],
        tx_root: [2u8; 32],
        event_root: events.root(),
        finality_proof_hash: [0u8; 32],
        consensus_kind: ConsensusKind::PoW,
        validator_set_hash: source.validator_set_hash,
        timestamp_ms: 1_000,
        sequence: 0,
        producer: None,
        state_updates: BTreeMap::new(),
    };

    let (first, first_hash) = mine_header(
        &source,
        PoWHeader {
            height: 1,
            parent_hash: commitment.parent_domain_block_hash,
            state_root: commitment.state_root,
            tx_root: commitment.tx_root,
            event_root: commitment.event_root,
            timestamp_ms: 1_000,
            nonce: 0,
            difficulty_bits: 4,
        },
    );
    commitment.domain_block_hash = first_hash;
    let (second, second_hash) = mine_header(
        &source,
        PoWHeader {
            height: 2,
            parent_hash: first_hash,
            state_root: [3u8; 32],
            tx_root: [4u8; 32],
            event_root: [5u8; 32],
            timestamp_ms: 1_001,
            nonce: 0,
            difficulty_bits: 4,
        },
    );
    let (third, _) = mine_header(
        &source,
        PoWHeader {
            height: 3,
            parent_hash: second_hash,
            state_root: [6u8; 32],
            tx_root: [7u8; 32],
            event_root: [8u8; 32],
            timestamp_ms: 1_002,
            nonce: 0,
            difficulty_bits: 4,
        },
    );
    let proof = FinalityProof::PoWHeaderChain {
        headers: vec![first, second, third],
    };
    commitment.finality_proof_hash = hash_finality_proof(&proof);

    chain
        .submit_verified_domain_commitment(commitment.clone(), proof)
        .expect("real header chain finalizes and applies the commitment");
    chain
        .mint_bridge_transfer_from_verified_event(
            source.id,
            commitment.domain_height,
            commitment.sequence,
            Some(commitment.domain_block_hash),
            event,
            &event_proof,
        )
        .expect("header-chain-finalized PoW event may mint");

    let legacy_error = chain
        .mint_bridge_transfer_from_verified_event(
            43,
            1,
            0,
            Some([0u8; 32]),
            events.events()[0].clone(),
            &event_proof,
        )
        .expect_err("legacy self-declared PoW must stay mint-gated");
    assert!(legacy_error.contains(POW_HEADER_CHAIN_ADAPTER));
}
