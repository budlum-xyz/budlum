//! (2026-07-21 - from the task list item "CI hardening")
//! **The genesis reproducibility probe (CI expansion, item 1).**
//!
//! Background: the job in `.github/workflows/determinism.yml`
//! `Genesis Reproducibility (Madde 1)` job'u `genesis_hash_deterministic`
//! compares the `GENESIS_HASH=<hex>` line of a test with that name across two
//! clean builds. Until the hardening, the job was comparing an empty hash with
//! an empty hash - a vacuous pass - because no test with that name EXISTED in
//! the repository. This module is the real body of that probe.
//!
//! What is measured (the things that MUST be independent of platform and run):
//!   * The resolution of the three networks (Mainnet=45260, Testnet=45261,
//!     Devnet=45262) plus an undefined
//!     Chain_id fallback'i (`GenesisConfig::new`): genesis blok hash'i,
//!     one: the timestamp, tx_root, validator_set_hash, the state root, the
//!     account count and the total circulation.
//!   * The equality of the `state_root` in the block and the root of
//!     `build_state` - a mirror of the node's fail-closed genesis and DB check
//!     at boot; see the startup check in `Blockchain::new_with_genesis`.
//!   * The full constructor path: the genesis block of a chain produced by
//!     `Blockchain::new(...)` has to be byte for byte the same as the direct
//!     output of `build_genesis_block`.
//!
//! Every observation is reduced to a single SHA-256 digest and written to
//! stdout as `GENESIS_HASH=<64hex>` (under `--nocapture`).
//! Inside the test every observation is produced from two independent builds and
//! their equality is asserted: in-process nondeterminism (HashMap iteration, a
//! wall-clock leak and the like) turns red on the spot. Equality across builds is
//! the CI job's business - the same test runs in two builds after `cargo clean`.

use crate::chain::blockchain::Blockchain;
use crate::chain::genesis::GenesisConfig;
use crate::consensus::pow::PoWEngine;
use crate::core::chain_config::Network;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// The genesis observation vector for one chain_id. It mirrors the resolution
/// path inside `Blockchain::new_with_genesis`: `for_network` when the network is
/// known,
/// Yoksa `GenesisConfig::new` fallback'i.
fn probe_chain(chain_id: u64) -> Vec<String> {
    let config = Network::from_chain_id(chain_id)
        .map(GenesisConfig::for_network)
        .unwrap_or_else(|| GenesisConfig::new(chain_id));

    let block = config.build_genesis_block();
    let mut rebuilt_state = config.build_state();
    let rebuilt_root = rebuilt_state.calculate_state_root();

    // The static twin of the fail-closed boot check: the state_root inside the
    // block and a fresh build_state root have to stay identical (a divergence is
    // CRITICAL at boot
    // Mismatch riski demektir).
    assert_eq!(
        block.state_root, rebuilt_root,
        "genesis state_root({chain_id}) != build_state() root - the boot check breaks"
    );

    // The full constructor round-trip: the genesis block of the chain produced by
    // the library constructor has to be byte for byte equal to the direct build
    // output.
    let chain = Blockchain::new(Arc::new(PoWEngine::new(0)), None, chain_id, None);
    assert_eq!(
        chain.chain.len(),
        1,
        "fresh chain must hold exactly genesis"
    );
    assert_eq!(
        chain.chain[0].hash, block.hash,
        "Blockchain::new genesis hash != build_genesis_block hash (chain_id={chain_id})"
    );

    let mut obs = Vec::new();
    obs.push(format!("chain_id={chain_id}"));
    obs.push(format!("genesis_hash={}", block.hash));
    obs.push(format!("genesis_timestamp={}", block.timestamp));
    obs.push(format!("genesis_tx_root={}", block.tx_root));
    obs.push(format!("genesis_state_root={}", block.state_root));
    obs.push(format!(
        "genesis_validator_set_hash={}",
        block.validator_set_hash
    ));
    obs.push(format!("genesis_tx_count={}", block.transactions.len()));
    if let Some(genesis_tx) = block.transactions.first() {
        obs.push(format!("genesis_tx_hash={}", genesis_tx.hash));
    }
    obs.push(format!("built_accounts={}", rebuilt_state.accounts.len()));
    obs.push(format!(
        "built_supply={}",
        rebuilt_state.circulating_supply()
    ));
    obs.push(format!("boot_chain_hash={}", chain.chain[0].hash));
    obs
}

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

    /// The CI item 1 probe. determinism.yml runs this test in two separate clean
    /// builds and compares the `GENESIS_HASH=` lines. The internal asserts catch
    /// in-process nondeterminism; CI checks equality across builds.
    #[test]
    fn genesis_hash_deterministic() {
        // Mainnet=45260 (asal hedef), Testnet=45261, Devnet=45262, fallback=9999.
        let chain_ids = [45260u64, 45261, 45262, 9999];
        let mut observations = Vec::new();
        for &chain_id in &chain_ids {
            let run_a = probe_chain(chain_id);
            let run_b = probe_chain(chain_id);
            assert_eq!(
                run_a, run_b,
                "process-internal nondeterminism in genesis construction (chain_id={chain_id})"
            );
            observations.extend(run_a);
        }

        let digest = digest_of(&observations);
        println!("GENESIS_HASH={digest}");

        // The false-green locks: the digest has a fixed length, and the
        // observation vector cannot pass silently without 4 chains times at least
        // 10 lines.
        assert_eq!(digest.len(), 64);
        assert!(
            observations.len() >= chain_ids.len() * 10,
            "genesis observation vector too short: {}",
            observations.len()
        );
    }
}
