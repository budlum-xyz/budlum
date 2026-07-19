#![no_main]
use libfuzz_sys::fuzz_target;
use budlum_core::chain::blockchain::Blockchain;
use budlum_core::consensus::pow::PoWEngine;
use budlum_core::core::address::Address;
use std::sync::Arc;

// Phase 11.2 Görev 3: Consensus state transition fuzz target.
// Rastgele block sequence → produce → state root deterministik + reorg güvenli.
// Panic YOK (DoS güvenliği).

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let num_blocks = (data[0] as usize) % 10 + 1;
    let producer = Address::from([data[1]; 32]);

    let consensus = Arc::new(PoWEngine::new(0));
    let mut chain_a = Blockchain::new(consensus.clone(), None, 1337, None);
    let mut chain_b = Blockchain::new(consensus, None, 1337, None);

    for _ in 0..num_blocks {
        let _ = chain_a.produce_block(producer);
    }

    let num_blocks_b = (data[2] as usize) % 10 + 1;
    for _ in 0..num_blocks_b {
        let _ = chain_b.produce_block(producer);
    }

    let _ = chain_a.try_reorg(chain_b.chain.clone());
});
