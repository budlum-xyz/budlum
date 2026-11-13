#![no_main]

//! Light-client header segment verification.
//!
//! `LightClient::verify_header_chain` is the only thing standing between a
//! header a peer hands over and the set of headers a finality certificate may
//! name. The input builds a segment above a trust anchor and bends it: heights
//! repeat or skip, parents point at the wrong block, hashes go stale. The
//! segment is accepted exactly when it is self-consistent, starts one above
//! the anchor on the anchor's hash and is parent-linked without a gap. Any
//! other verdict, or a panic, is a finding. Raw bytes are also decoded as a
//! header list and handed over as they are.

use budlum_core::core::block::{Block, BlockHeader};
use budlum_core::light_client::{LightClient, TrustedCheckpoint};
use libfuzzer_sys::fuzz_target;

const CHAIN_ID: u64 = 45_261;
const RECORD_BYTES: usize = 4;
const MAX_HEADERS: usize = 32;
const HEIGHT_STEPS: u8 = 3;
const PARENT_MODES: u8 = 3;
const HASH_MODES: u8 = 4;

fn anchor_hash() -> String {
    "0".repeat(64)
}

fn client_at(height: u64) -> Option<LightClient> {
    LightClient::new(TrustedCheckpoint {
        height,
        block_hash: anchor_hash(),
        set_hash: anchor_hash(),
    })
    .ok()
}

fn segment(anchor_height: u64, records: &[u8]) -> Vec<BlockHeader> {
    let mut headers = Vec::new();
    let mut parent = anchor_hash();
    let mut height = anchor_height;
    for record in records.chunks_exact(RECORD_BYTES).take(MAX_HEADERS) {
        height = height.saturating_add(u64::from(record[0] % HEIGHT_STEPS));
        let previous = match record[1] % PARENT_MODES {
            0 => parent.clone(),
            1 => anchor_hash(),
            _ => hex_word(record[1]),
        };
        let block = Block::new_with_chain_id(height, previous, Vec::new(), CHAIN_ID);
        let mut header = BlockHeader::from_block(&block);
        // The constructor stamps the wall clock. A fixed timestamp keeps a
        // crashing input reproducible.
        header.timestamp = u128::from(height);
        header.nonce = u64::from(record[3]);
        header.hash = header.calculate_hash();
        if record[2] % HASH_MODES == 0 {
            // A stale hash: the header changed after it was hashed.
            header.nonce = header.nonce.wrapping_add(1);
        }
        parent = header.hash.clone();
        headers.push(header);
    }
    headers
}

fn hex_word(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn is_linked_segment(anchor_height: u64, headers: &[BlockHeader]) -> bool {
    let Some(first) = headers.first() else {
        return false;
    };
    if headers
        .iter()
        .any(|header| header.hash != header.calculate_hash())
    {
        return false;
    }
    if anchor_height.checked_add(1) != Some(first.index) || first.previous_hash != anchor_hash() {
        return false;
    }
    headers.windows(2).all(|pair| {
        pair[0].index.checked_add(1) == Some(pair[1].index) && pair[1].previous_hash == pair[0].hash
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&anchor_byte, records)) = data.split_first() else {
        return;
    };
    let anchor_height = u64::from(anchor_byte);

    if let Some(mut client) = client_at(anchor_height) {
        let headers = segment(anchor_height, records);
        let accepted = client.verify_header_chain(&headers).is_ok();
        assert_eq!(
            accepted,
            is_linked_segment(anchor_height, &headers),
            "anchor {anchor_height}, {} headers",
            headers.len()
        );
    }

    if let Ok(headers) = bincode::deserialize::<Vec<BlockHeader>>(records) {
        if let Some(mut client) = client_at(anchor_height) {
            let accepted = client.verify_header_chain(&headers).is_ok();
            assert!(
                !accepted || is_linked_segment(anchor_height, &headers),
                "a decoded segment that is not linked was accepted"
            );
        }
    }
});
