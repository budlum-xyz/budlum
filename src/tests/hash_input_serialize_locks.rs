//! Nothing that feeds a hash may swallow a serialize failure.
//!
//! `bincode::serialize(..).unwrap_or_default()` yields an empty `Vec` when it
//! fails. On a path whose output is hashed, that turns a failure into a
//! *collision*: every value that fails hashes identically to every other value
//! that fails, and to a value that legitimately serialises to nothing.
//!
//! Three sites did this on hash inputs:
//!
//!   - `RelayerExternalResult::result_leaf` — the chain discriminator. Every
//!     `ExternalChain` would have produced the same leaf, which is precisely
//!     the cross-domain replay the `BDLM_RELAYER_RESULT_V2` tag exists to stop.
//!   - `snapshot::hash_serializable` — every field of the state-root digest.
//!   - the `finality_certificates` branch of the same digest.
//!
//! The state root is what nodes compare to agree they are on the same chain,
//! so a silent collision there is a fork with no error surfaced anywhere.
//!
//! These are `expect` now, not `unwrap_or_default`. Bincode on these types can
//! only fail on allocation failure, which is a bug rather than an input: a
//! panic is the honest response, and it is loud.

use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn code_lines(rel: &str) -> Vec<(usize, String)> {
    let src = fs::read_to_string(repo_root().join(rel))
        .unwrap_or_else(|e| panic!("{rel} is readable: {e}"));
    src.lines()
        .enumerate()
        .map(|(i, line)| (i + 1, line.to_string()))
        .filter(|(_, line)| {
            let t = line.trim_start();
            !t.starts_with("//") && !t.starts_with("///")
        })
        .collect()
}

/// The three hash-input sites must not reintroduce the swallow.
#[test]
fn hash_inputs_do_not_swallow_a_serialize_failure() {
    for rel in ["src/core/transaction.rs", "src/chain/snapshot.rs"] {
        let offenders: Vec<usize> = code_lines(rel)
            .into_iter()
            .filter(|(_, line)| line.contains("bincode::serialize"))
            .filter(|(_, line)| line.contains("unwrap_or_default"))
            .map(|(n, _)| n)
            .collect();
        assert!(
            offenders.is_empty(),
            "{rel} feeds a hash from `bincode::serialize(..).unwrap_or_default()` \
             at lines {offenders:?}; an empty Vec on failure makes two different \
             values commit to the same digest"
        );
    }
}

/// The scan must be able to see a violation.
///
/// A source check that silently matches nothing passes forever after a rename.
#[test]
fn the_serialize_swallow_scan_can_detect_a_violation() {
    let planted = [
        "        let bytes = bincode::serialize(val).unwrap_or_default();",
        "/// let bytes = bincode::serialize(val).unwrap_or_default();",
    ];
    let caught = planted
        .iter()
        .filter(|line| {
            let t = line.trim_start();
            !t.starts_with("//") && !t.starts_with("///")
        })
        .filter(|line| line.contains("bincode::serialize") && line.contains("unwrap_or_default"))
        .count();
    assert_eq!(
        caught, 1,
        "the scan must catch the real line and ignore the doc-comment one"
    );
}

/// Two different chains must not share a result leaf.
///
/// The behavioural half of the source check above.
#[test]
fn every_external_chain_produces_a_distinct_result_leaf() {
    use crate::core::transaction::{ExternalChain, RelayerExternalResult};
    use std::collections::BTreeSet;

    let chains = [
        ExternalChain::Ethereum,
        ExternalChain::Solana,
        ExternalChain::Bitcoin,
        ExternalChain::Avalanche,
        ExternalChain::Polygon,
        ExternalChain::Arbitrum,
        ExternalChain::Optimism,
        ExternalChain::Custom(1),
        ExternalChain::Custom(2),
    ];

    let leaves: BTreeSet<[u8; 32]> = chains
        .iter()
        .map(|chain| {
            RelayerExternalResult {
                chain: *chain,
                tx_hash: "0xsame".to_string(),
                success: true,
                message: None,
                receipt_proof: Vec::new(),
                external_state_root: [1u8; 32],
            }
            .result_leaf()
        })
        .collect();

    assert_eq!(
        leaves.len(),
        chains.len(),
        "two chains share a result leaf, so a proof for one would satisfy the other"
    );
}
