#![no_main]

//! Consensus state transition / reorg safety.
//!
//! Oracle: panic freedom, plus the reorg safety rules. A reorg that is
//! accepted must keep genesis, stay within `MAX_REORG_DEPTH`, fork above the
//! finalized height and install the candidate. A refused reorg must leave the
//! chain unchanged.

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

    // One input in 256 builds a chain longer than MAX_REORG_DEPTH. Without it
    // the local chain stays at 13 blocks and the depth rule is unreachable.
    let deep_chain = data.first() == Some(&0xFF);
    let produce_n = if deep_chain {
        MAX_REORG_DEPTH + 2
    } else {
        (take_u8(data, &mut i) as usize % (MAX_PRODUCE + 1)).min(MAX_PRODUCE)
    };
    if deep_chain {
        i = 1;
    }
    let mut produced = Vec::with_capacity(produce_n);
    for _ in 0..produce_n {
        let who = producer_from(take_u8(data, &mut i));
        if let Some((block, _)) = chain.produce_block(who) {
            produced.push(block);
        }
    }


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
            // Truncated prefix - should not be "better".
            let keep = (take_u8(data, &mut i) as usize) % chain.chain.len().max(1);
            chain.chain[..keep.max(1)].to_vec()
        }
        2 => {
            // Deep DIVERGENT reorg attempt past MAX_REORG_DEPTH: fork from
            // an ancestor of the tip and replace every block after the
            // branch point with differently-produced ones. Appending to a
            // clone of the current chain (what this mode used to do) is an
            // extension, not a reorg - `try_reorg` never saw a candidate
            // that removes old blocks.
            let depth = MAX_REORG_DEPTH + 1 + (take_u8(data, &mut i) as usize % 8);
            let branch_at = chain.chain.len().saturating_sub(depth).max(1);
            let mut deep = chain.chain[..branch_at].to_vec();
            for d in 0..(depth + 4) {
                if let Some(last) = deep.last() {
                    let mut b = Block::new(last.index.saturating_add(1), last.hash.clone(), vec![]);
                    b.chain_id = last.chain_id;
                    // A different producer and timestamp than the block this
                    // replaces, so the fork block really is another block.
                    b.producer = Some(producer_from(take_u8(data, &mut i).wrapping_add(d as u8)));
                    b.timestamp = last.timestamp.saturating_add(1000);
                    b.hash = b.calculate_hash();
                    deep.push(b);
                }
                if deep.len() > MAX_CANDIDATE + chain.chain.len() {
                    break;
                }
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

    // Sometimes pin a finalized checkpoint on the local chain, so the fork
    // point and checkpoint hash rules are reachable too.
    if take_u8(data, &mut i) & 1 == 1 {
        let at = take_u8(data, &mut i) as usize % chain.chain.len();
        chain.finalized_height = at as u64;
        chain.finalized_hash = chain.chain[at].hash.clone();
    }

    // Oracle: a reorg is accepted only inside the safety rules. A refusal
    // leaves the chain untouched; an acceptance installs the candidate.
    let before: Vec<String> = chain.chain.iter().map(|b| b.hash.clone()).collect();
    let fork_point = chain.find_fork_point(&candidate);
    let finalized_height = chain.finalized_height;
    let candidate_hashes: Vec<String> = candidate.iter().map(|b| b.hash.clone()).collect();
    match chain.try_reorg(candidate) {
        Ok(true) => {
            let Some(fork_point) = fork_point else {
                panic!("reorg accepted without a fork point");
            };
            assert!(fork_point > 0, "reorg replaced genesis");
            assert!(
                before.len().saturating_sub(fork_point) <= MAX_REORG_DEPTH,
                "reorg deeper than MAX_REORG_DEPTH was accepted"
            );
            assert!(
                fork_point as u64 > finalized_height,
                "reorg at or below the finalized height was accepted"
            );
            let after: Vec<String> = chain.chain.iter().map(|b| b.hash.clone()).collect();
            assert_eq!(after, candidate_hashes, "accepted reorg did not install the candidate");
        }
        Ok(false) | Err(_) => {
            let after: Vec<String> = chain.chain.iter().map(|b| b.hash.clone()).collect();
            assert_eq!(after, before, "a refused reorg changed the chain");
        }
    }

    // State root query must not panic at arbitrary heights.
    let h = take_u8(data, &mut i) as u64;
    let _ = chain.get_state_root(h);
});
