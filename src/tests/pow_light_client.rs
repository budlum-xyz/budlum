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
fn pow_header_finality_authorizes_bridge_mint_but_legacy_does_not() {
    let mut chain = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None);

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
    // Self-declared confirmation proof must never authorize mint.
    let mut legacy = default_domain(43, ConsensusKind::PoW, 43_001, "pow-header-chain-v1", 64);
    legacy.operator = Some(address(43));
    legacy.bridge_enabled = true;
    chain
        .register_consensus_domain(legacy)
        .expect("legacy domain remains decodable/registerable");

    let asset = crate::cross_domain::AssetId([0xA5; 32]);
    chain
        .register_bridge_asset(asset, source.id)
        .expect("asset registration");
    // Lock debits owner balance.
    chain
        .fund_development_account(&address(7))
        .expect("devnet faucet");
    chain
        .fund_development_account(&address(8))
        .expect("devnet faucet");
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
    commitment.finality_proof_hash = hash_finality_proof(&proof).unwrap();

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
            Address::zero(),
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
            Address::zero(),
        )
        .expect_err("legacy self-declared PoW must stay mint-gated");
    // The legacy PoW domain never finalized a commitment, so its mint is
    // Gated by the applied-domain-chain height check (no tip). The rejection
    // Must mention the missing/finality-gated state.
    assert!(
        legacy_error.contains("not on the applied domain chain")
            || legacy_error.contains("tip 0")
            || legacy_error.contains(POW_HEADER_CHAIN_ADAPTER),
        "legacy self-declared PoW must stay mint-gated, got: {legacy_error}"
    );
}

/// Shared fixture: a registered PoW header-chain domain plus four chained
/// mined headers. The first header's state root is parameterized so tests
/// can exercise the zero-root boundary; the later headers always carry
/// distinct non-zero roots.
fn pow_fixture(first_state_root: [u8; 32]) -> (
    Blockchain,
    crate::domain::ConsensusDomain,
    Vec<(PoWHeader, [u8; 32])>,
) {
    let mut chain = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None);

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

    let mut mined = Vec::new();
    let mut parent = [0u8; 32];
    for (i, height) in (1u64..=4).enumerate() {
        let state_root = if i == 0 {
            first_state_root
        } else {
            [10u8 + i as u8; 32]
        };
        let (header, hash) = mine_header(
            &source,
            PoWHeader {
                height,
                parent_hash: parent,
                state_root,
                tx_root: [2u8; 32],
                event_root: [5u8; 32],
                // `height` is the `u64` from the range, and this field is `u128`:
                // `1_000 + height` infers `u64` and the field then refuses it (E0308).
                timestamp_ms: 1_000 + u128::from(height),
                nonce: 0,
                difficulty_bits: 4,
            },
        );
        parent = hash;
        mined.push((header, hash));
    }
    (chain, source, mined)
}

/// Bind a three-header sliding window to a domain commitment: the window's
/// first header is the target (height, parent, roots, timestamp, hash); the
/// rest provide the confirmation depth.
fn commitment_for_window(
    source: &crate::domain::ConsensusDomain,
    window: &[(PoWHeader, [u8; 32])],
) -> (DomainCommitment, FinalityProof) {
    let target = &window[0].0;
    let proof = FinalityProof::PoWHeaderChain {
        headers: window.iter().map(|(header, _)| header.clone()).collect(),
    };
    let commitment = DomainCommitment {
        domain_id: source.id,
        domain_height: target.height,
        domain_block_hash: window[0].1,
        parent_domain_block_hash: target.parent_hash,
        state_root: target.state_root,
        tx_root: target.tx_root,
        event_root: target.event_root,
        finality_proof_hash: hash_finality_proof(&proof).unwrap(),
        consensus_kind: ConsensusKind::PoW,
        validator_set_hash: source.validator_set_hash,
        timestamp_ms: target.timestamp_ms,
        sequence: target.height - 1,
        producer: None,
        state_updates: BTreeMap::new(),
    };
    (commitment, proof)
}

#[test]
fn finalized_pow_commitment_anchors_external_root() {
    let (mut chain, source, mined) = pow_fixture([1u8; 32]);
    let (commitment, proof) = commitment_for_window(&source, &mined[0..3]);
    chain
        .submit_verified_domain_commitment(commitment, proof)
        .expect("real header chain finalizes");
    assert_eq!(
        chain.state.external_roots.get(&source.id),
        Some(&[1u8; 32]),
        "a finalized commitment must anchor its state root in the consensus registry"
    );
}

#[test]
fn zero_state_root_commitment_is_refused_fail_closed() {
    let (mut chain, source, mined) = pow_fixture([0u8; 32]);
    let (commitment, proof) = commitment_for_window(&source, &mined[0..3]);
    let err = chain
        .submit_verified_domain_commitment(commitment, proof)
        .expect_err("a zero state root must not finalize");
    assert!(err.contains("zero state root"), "got: {err}");
    assert!(
        chain.state.external_roots.is_empty(),
        "no anchor may be written for a zero root"
    );
    let domain = chain
        .domain_registry
        .get(source.id)
        .expect("domain registered");
    assert_eq!(
        domain.last_committed_height, 0,
        "the domain must not advance without an anchor"
    );
}

#[test]
fn newer_finalized_commitment_supersedes_older_anchor() {
    let (mut chain, source, mined) = pow_fixture([1u8; 32]);

    let (first, first_proof) = commitment_for_window(&source, &mined[0..3]);
    chain
        .submit_verified_domain_commitment(first, first_proof)
        .expect("first commitment finalizes");
    assert_eq!(
        chain.state.external_roots.get(&source.id),
        Some(&[1u8; 32]),
        "first anchor written"
    );

    let second_root = mined[1].0.state_root;
    assert_ne!(second_root, [0u8; 32]);
    let (second, second_proof) = commitment_for_window(&source, &mined[1..4]);
    chain
        .submit_verified_domain_commitment(second, second_proof)
        .expect("second commitment finalizes");
    assert_eq!(
        chain.state.external_roots.get(&source.id),
        Some(&second_root),
        "one latest finalized root per domain: the newer anchor supersedes"
    );
}
