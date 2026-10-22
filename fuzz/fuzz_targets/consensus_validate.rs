#![no_main]

// NOTE: when a new field is added to the BlockHeader struct this target fails
// to compile with E0063. The fields must be filled in COMPLETELY here, and the
// "Fuzz Quick" gate in CI catches it. (The target had rotted on 2026-07-16 when
// chain_id/nonce/epoch/slot/vrf_* were added.)

use budlum_core::chain::blockchain::Blockchain;
use budlum_core::consensus::pow::PoWEngine;
use budlum_core::core::address::Address;
use budlum_core::core::block::{Block, BlockHeader};
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

fn take_u64(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    for (idx, byte) in bytes.iter_mut().enumerate() {
        *byte = data.get(offset + idx).copied().unwrap_or_default();
    }
    u64::from_le_bytes(bytes)
}

fn take_u128(data: &[u8], offset: usize) -> u128 {
    let mut bytes = [0u8; 16];
    for (idx, byte) in bytes.iter_mut().enumerate() {
        *byte = data.get(offset + idx).copied().unwrap_or_default();
    }
    u128::from_le_bytes(bytes)
}

fn take_32(data: &[u8], offset: usize) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (idx, byte) in bytes.iter_mut().enumerate() {
        *byte = data.get(offset + idx).copied().unwrap_or_default();
    }
    bytes
}

fn hex32(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let flag = data.first().copied().unwrap_or_default();
    let producer = if flag & 1 == 1 {
        Some(Address::from(take_32(data, 97)))
    } else {
        None
    };
    let storage_root = if flag & 2 == 2 {
        Some(take_32(data, 273))
    } else {
        None
    };

    let header = BlockHeader {
        index: take_u64(data, 1),
        hash: hex32(take_32(data, 9)),
        previous_hash: hex32(take_32(data, 41)),
        timestamp: take_u128(data, 73),
        producer,
        state_root: hex32(take_32(data, 129)),
        tx_root: hex32(take_32(data, 161)),
        chain_id: take_u64(data, 193),
        nonce: take_u64(data, 201),
        epoch: take_u64(data, 209),
        slot: take_u64(data, 217),
        vrf_output: data.get(225..241).unwrap_or_default().to_vec(),
        vrf_proof: data.get(241..273).unwrap_or_default().to_vec(),
        validator_set_hash: hex32(take_32(data, 305)),
        slashing_evidence: None,
        slashing_reports: None,
        storage_root,
        shards_root: None,
    };

    // Header encoding is deterministic and its hash survives a round trip.
    let first = header.calculate_hash();
    assert_eq!(first, header.calculate_hash());
    if let Ok(bytes) = bincode::serialize(&header) {
        if let Ok(decoded) = bincode::deserialize::<BlockHeader>(&bytes) {
            assert_eq!(decoded.calculate_hash(), first, "header hash changed in a round trip");
        }
    }

    // Validation: the same fields as a block, offered to a fresh chain. The
    // fuzzed `hash` field is not the block hash, so the chain must refuse it
    // and stay unchanged. With the hash recomputed and the cheap checks
    // (height, chain id) satisfied the block reaches the consensus engine;
    // any outcome is fine, but a refusal must not change the chain and an
    // acceptance must add exactly one block.
    let mut chain = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 1337, None);
    let before = chain.chain.len();
    let mut block = Block::new(header.index, header.previous_hash.clone(), Vec::new());
    block.timestamp = header.timestamp;
    block.producer = header.producer;
    block.chain_id = if flag & 4 == 4 { 1337 } else { header.chain_id };
    block.index = if flag & 8 == 8 { before as u64 } else { header.index };
    block.state_root = header.state_root.clone();
    block.nonce = header.nonce;
    block.epoch = header.epoch;
    block.slot = header.slot;
    block.vrf_output = header.vrf_output.clone();
    block.vrf_proof = header.vrf_proof.clone();
    block.validator_set_hash = header.validator_set_hash.clone();
    block.storage_root = header.storage_root;
    block.tx_root = block.calculate_tx_root();

    block.hash = header.hash.clone();
    if block.hash != block.calculate_hash() {
        assert!(chain.validate_and_add_block(block.clone()).is_err());
        assert_eq!(chain.chain.len(), before, "a refused block changed the chain");
    }

    block.hash = block.calculate_hash();
    match chain.validate_and_add_block(block) {
        Ok(_) => assert_eq!(chain.chain.len(), before + 1),
        Err(_) => assert_eq!(chain.chain.len(), before, "a refused block changed the chain"),
    }
});
