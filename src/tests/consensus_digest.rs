//! (2026-07-21 - from the task list item "CI hardening")
//! **Cross-platform consensus determinism digest'i.**
//!
//! The task item: "a cross-platform determinism matrix - is the consensus output
//! byte for byte identical across Linux, macOS and Windows".
//!
//! The method: a four-block scenario is run with fixed-seed keys, a fixed
//! genesis_time and a fixed transaction plan. After each block
//! `calculate_state_root` and the transaction order of the block are recorded,
//! and the final account state (balance and nonce) is dumped over a fixed address
//! list. Every observation is reduced with SHA-256 to a single
//! is reduced to a 64-hex digest and written to stdout as
//! line, written out under `--nocapture`. `determinism.yml` collects that line as
//! an artifact on three operating systems and requires byte equality in the
//! `consensus-digest-compare` job - any difference is a cross-platform consensus
//! divergence and FAILs (no false green: `if-no-files-found: error`).
//!
//! The boundaries of the determinism, deliberately:
//!   * `genesis_time` sabitlenir (`Blockchain::new` aksi halde duvar saatini
//!     Okur; `produce_block` timestamp'i `genesis_time + slot*SLOT_MS`'tir).
//!   * The transactions are signed with Ed25519 (RFC 8032 - a deterministic signature).
//!   * The scenario contains an equal-fee tie pair (bob and carol at fee=9):
//!     because the mempool tie-break is canonical under the
//!     `BTreeSet<(fee, hash)>` rule, the inclusion order is platform independent
//!     (see the patch in `src/mempool/pool.rs`).
//!   * Only consensus outputs enter the digest: the state root, the transaction order,
//!     Bakiye/nonce. Duvar saati, float, artalan thread'i yok.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use crate::core::transaction::Transaction;
use crate::crypto::primitives::KeyPair;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const SCENARIO_CHAIN_ID: u64 = 45262;
/// The fixed genesis time in milliseconds, for digest normalisation. The value is
/// arbitrary but identical on EVERY platform and in EVERY run; changing it
/// changes the digest, which is deliberate - it is a fixed, documented anchor.
const SCENARIO_GENESIS_TIME_MS: u128 = 1_700_000_000_000;

/// Runs the whole scenario and produces the platform-independent observation
/// vector. The same vector is produced twice; any difference surfaces in-process
/// nondeterminism as a test failure, with no retry and no masking.
fn run_scenario() -> Vec<String> {
    let consensus = Arc::new(PoWEngine::new(0));
    let mut chain = Blockchain::new(consensus, None, SCENARIO_CHAIN_ID, None);
    chain.genesis_time = SCENARIO_GENESIS_TIME_MS;

    // Fixed seeds: the same key bits independently of platform and run.
    let alice_kp = KeyPair::from_seed(&[0xA1; 32]).expect("seed alice");
    let bob_kp = KeyPair::from_seed(&[0xB2; 32]).expect("seed bob");
    let carol_kp = KeyPair::from_seed(&[0xC3; 32]).expect("seed carol");
    let alice = Address::from(alice_kp.public_key_bytes());
    let bob = Address::from(bob_kp.public_key_bytes());
    let carol = Address::from(carol_kp.public_key_bytes());
    let miner = alice; // the block producer is fixed - not part of the digest, but held constant

    // The initial distribution: a test fixture. It does NOT affect the genesis
    // hash - this state is test scaffolding after the genesis block, not the
    // mainnet genesis config.
    chain.state.add_balance(&alice, 100_000);
    chain.state.add_balance(&bob, 50_000);
    chain.state.add_balance(&carol, 25_000);

    let mut observations: Vec<String> = Vec::new();
    observations.push(format!(
        "genesis_root={}",
        chain.state.calculate_state_root()
    ));

    // The transaction plan: (sender_idx, recipient_idx, amount, fee) - 3 rounds of
    // 3 to 4 transactions. In round 2 bob and carol produce a tie at the same fee
    // (9), which exercises the canonical ordering.
    // Sender indeksleri: 0=alice,1=bob,2=carol
    let rounds: [&[(usize, usize, u64, u64)]; 4] = [
        &[(0, 1, 100, 7), (1, 2, 50, 11), (0, 2, 25, 13)],
        &[(1, 0, 10, 9), (2, 0, 15, 9), (0, 1, 40, 5)],
        &[(2, 1, 5, 3), (0, 2, 60, 21), (1, 0, 30, 17), (2, 0, 1, 2)],
        &[(0, 1, 3, 4), (1, 2, 2, 6), (2, 1, 4, 8)],
    ];

    let kps = [&alice_kp, &bob_kp, &carol_kp];
    let addrs = [alice, bob, carol];
    let mut nonces = [0u64; 3];

    for plan in rounds.iter() {
        for &(from_i, to_i, amount, fee) in plan.iter() {
            let mut tx = Transaction::new_with_fee(
                addrs[from_i],
                addrs[to_i],
                amount,
                fee,
                nonces[from_i],
                Vec::new(),
            );
            nonces[from_i] += 1;
            tx.timestamp = 0; // wall-clock normalisation, following the genesis pattern
            tx.max_fee = fee;
            tx.priority_fee = 0;
            tx.sign(kps[from_i]);
            chain
                .add_transaction(tx)
                .unwrap_or_else(|e| panic!("scenario tx admission failed: {e}"));
        }
        let (block, _events) = chain
            .produce_block(miner)
            .expect("scenario block production must succeed");
        let tx_order: Vec<String> = block.transactions.iter().map(|t| t.hash.clone()).collect();
        observations.push(format!("block{}_tx_count={}", block.index, tx_order.len()));
        observations.push(format!(
            "block{}_tx_order={}",
            block.index,
            tx_order.join(",")
        ));
        observations.push(format!(
            "block{}_state_root={}",
            block.index,
            chain.state.calculate_state_root()
        ));
    }

    // The final state: a deterministic dump over a fixed address list.
    for (name, addr) in [("alice", alice), ("bob", bob), ("carol", carol)] {
        let acc = chain.state.accounts.get(&addr).expect("scenario account");
        observations.push(format!("final_{}={}:{}", name, acc.balance, acc.nonce));
    }
    observations.push(format!("final_supply={}", chain.state.circulating_supply()));
    observations
}

/// Reduces the observation vector to a single SHA-256 digest.
fn digest_of(observations: &[String]) -> String {
    let mut hasher = Sha256::new();
    for line in observations {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cross-platform digest production for CI. It runs under `--nocapture`
    /// and the workflow collects the `CONSENSUS_DIGEST=` line. The two-round
    /// equality assert inside the test catches in-process nondeterminism (HashMap
    /// or HashSet iteration, for instance) on the spot; equality across platforms
    /// is the business of the compare job in determinism.yml.
    #[test]
    fn consensus_scenario_digest_cross_platform() {
        let pass1 = run_scenario();
        let pass2 = run_scenario();
        assert_eq!(
            pass1, pass2,
            "process-internal nondeterminism: two scenario runs produced different observations"
        );
        let digest = digest_of(&pass1);
        println!("CONSENSUS_DIGEST={digest}");
        // The false-green lock: the digest has a fixed length and cannot be empty.
        assert_eq!(digest.len(), 64);
        // Proof of the minimum scenario: the 4 block, genesis, final account and
        // supply observations all have to have been produced - a short run cannot
        // pass silently.
        assert!(
            pass1.len() > 1 + 4 * 3 + 3,
            "scenario observation vector too short: {}",
            pass1.len()
        );
    }
}
