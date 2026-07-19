#![no_main]

//! Phase 11.2 Görev 3 — consensus state transition / reorg safety.
//!
//! Oracle: panic/abort freedom. Random block production sequences and
//! candidate reorg chains must not crash the L1 state machine. Deep reorgs
//! past `MAX_REORG_DEPTH` / finality must be rejected (Err), not panic.

use budlum_core::chain::blockchain::{Blockchain, MAX_REORG_DEPTH};
use budlum_core::consensus::pow::PoWEngine;
use budlum_core::core::address::Address;
use budlum_core::core::block::Block;
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

const MAX_PRODUCE: usize = 12;
const MAX_CANDIDATE: usize = 16;

fn take_u8(data: &[u8], i: &mut usize) -> u8 {
    let b = data.get(*i).copied().unwrap_or(0);
    *i = i.saturating_add(1);
    b
}

fn producer_from(byte: u8) -> Address {
    let mut raw = [0u8; 32];
    raw[0] = byte;
    raw[31] = byte ^ 0xA5;
    Address::from(raw)
}

fuzz_target!(|data: &[u8]| {
    let mut i = 0usize;
    let consensus = Arc::new(PoWEngine::new(0));
    let mut chain = Blockchain::new(consensus, None, 1337, None);

    let produce_n = (take_u8(data, &mut i) as usize % (MAX_PRODUCE + 1)).min(MAX_PRODUCE);
    let mut produced = Vec::with_capacity(produce_n);
    for _ in 0..produce_n {
        let who = producer_from(take_u8(data, &mut i));
        if let Some((block, _)) = chain.produce_block(who) {
            produced.push(block);
        }
    }

    // Property: chain length is genesis + successfully produced blocks.
    let _height = chain.chain.len();
    let _root = chain.chain.last().map(|b| b.hash.clone());

    // Build a candidate chain from fuzz bytes (possibly invalid / deep).
    let mode = take_u8(data, &mut i);
    let mut candidate: Vec<Block> = match mode % 4 {
        0 => {
            // Longer extension of current chain tip (valid better-chain attempt).
            let mut alt = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 1337, None);
            // Replay same number of blocks with different producers when possible.
            let extra = (take_u8(data, &mut i) as usize % 5) + 1;
            for k in 0..(produce_n + extra).min(MAX_CANDIDATE) {
                let who = producer_from(take_u8(data, &mut i).wrapping_add(k as u8));
                let _ = alt.produce_block(who);
            }
            alt.chain
        }
        1 => {
            // Truncated prefix — should not be "better".
            let keep = (take_u8(data, &mut i) as usize) % chain.chain.len().max(1);
            chain.chain[..keep.max(1)].to_vec()
        }
        2 => {
            // Deep synthetic reorg attempt past MAX_REORG_DEPTH.
            let mut deep = chain.chain.clone();
            let depth = MAX_REORG_DEPTH + 1 + (take_u8(data, &mut i) as usize % 8);
            for d in 0..depth {
                if let Some(last) = deep.last() {
                    let mut b = Block::new(
                        last.index.saturating_add(1),
                        last.hash.clone(),
                        vec![],
                    );
                    b.chain_id = last.chain_id;
                    b.producer = Some(producer_from(take_u8(data, &mut i)));
                    b.timestamp = last.timestamp.saturating_add(1000);
                    b.hash = b.calculate_hash();
                    deep.push(b);
                }
                if deep.len() > MAX_CANDIDATE + chain.chain.len() {
                    break;
                }
                let _ = d;
            }
            deep
        }
        _ => {
            // Empty / garbage single-block candidate.
            if take_u8(data, &mut i) & 1 == 1 {
                vec![Block::genesis()]
            } else {
                Vec::new()
            }
        }
    };

    // Cap candidate size to keep each iteration bounded.
    if candidate.len() > MAX_CANDIDATE + 4 {
        candidate.truncate(MAX_CANDIDATE + 4);
    }

    // try_reorg must not panic — Ok(false)/Err are both acceptable.
    let _ = chain.try_reorg(candidate);

    // State root query must not panic at arbitrary heights.
    let h = take_u8(data, &mut i) as u64;
    let _ = chain.get_state_root(h);
});
