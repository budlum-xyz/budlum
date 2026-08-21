//! Budlum's chain ids must not belong to somebody else.
//!
//! The ids were 1, 42 and 1337. All three are assigned in the public EIP-155
//! registry at `chainid.network` - measured against the live list of 2668
//! chains: 1 is Ethereum Mainnet, 42 is LUKSO Mainnet, 1337 is Geth Testnet.
//!
//! The signing preimage is domain-separated (`BDLM_TX_V4` plus the chain id),
//! so a Budlum signature was never replayable onto Ethereum. The damage was to
//! users: every EVM wallet resolves a chain id through that registry, so an
//! RPC announcing `1` presents itself to MetaMask as Ethereum Mainnet and the
//! user approves what looks like an Ethereum transaction.
//!
//! These tests are offline on purpose. A gate that reaches the network is a
//! gate that fails when the network does, and a hard-coded list of the ids we
//! collided with is enough to stop the specific mistake coming back.

use crate::core::chain_config::Network;
use crate::core::transaction::DEFAULT_CHAIN_ID;

/// Ids that were measured as assigned in the registry on 2026-07-30, plus the
/// low-numbered space that is effectively reserved by convention.
///
/// Not the whole registry - 2668 entries pinned here would rot immediately and
/// tell a reader nothing. These are the ones this project actually used.
const KNOWN_TAKEN: &[(u64, &str)] = &[
    (1, "Ethereum Mainnet"),
    (42, "LUKSO Mainnet"),
    (1337, "Geth Testnet"),
    (5, "Goerli"),
    (10, "OP Mainnet"),
    (56, "BNB Smart Chain"),
    (100, "Gnosis"),
    (137, "Polygon"),
    (8453, "Base"),
    (42161, "Arbitrum One"),
    (43114, "Avalanche C-Chain"),
    (11155111, "Sepolia"),
];

#[test]
fn no_network_uses_a_chain_id_that_belongs_to_another_chain() {
    for network in [Network::Mainnet, Network::Testnet, Network::Devnet] {
        let id = network.chain_id().value();
        if let Some((_, owner)) = KNOWN_TAKEN.iter().find(|(taken, _)| *taken == id) {
            panic!(
                "{} uses chain id {id}, which is {owner} in the public EIP-155 \
                 registry. Every EVM wallet resolves the id through that \
                 registry, so users would be shown the wrong network name.",
                network.name()
            );
        }
    }
}

#[test]
fn the_three_networks_have_distinct_chain_ids() {
    let ids: Vec<u64> = [Network::Mainnet, Network::Testnet, Network::Devnet]
        .iter()
        .map(|n| n.chain_id().value())
        .collect();
    let unique: std::collections::BTreeSet<u64> = ids.iter().copied().collect();
    assert_eq!(
        unique.len(),
        ids.len(),
        "two networks share a chain id, so a transaction signed for one would \
         verify on the other: {ids:?}"
    );
}

#[test]
fn the_implied_chain_id_matches_devnet() {
    // `DEFAULT_CHAIN_ID` is used wherever a chain id is implied rather than
    // configured. If it drifts from devnet, locally built transactions stop
    // verifying against a locally running node for no visible reason.
    assert_eq!(
        DEFAULT_CHAIN_ID,
        Network::Devnet.chain_id().value(),
        "DEFAULT_CHAIN_ID and Network::Devnet disagree"
    );
}

#[test]
fn the_shipped_genesis_files_agree_with_the_code() {
    // A genesis file carrying a different id than the binary produces a chain
    // nobody can transact on: every signature is built for one id and checked
    // against the other.
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for (file, network) in [
        ("config/mainnet-genesis.json", Network::Mainnet),
        ("config/testnet-genesis.json", Network::Testnet),
        ("config/devnet-genesis.json", Network::Devnet),
    ] {
        let raw = std::fs::read_to_string(root.join(file))
            .unwrap_or_else(|e| panic!("{file} is readable: {e}"));
        let parsed: serde_json::Value =
            serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{file} is valid JSON: {e}"));
        let declared = parsed
            .get("chain_id")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| panic!("{file} has no numeric chain_id"));
        assert_eq!(
            declared,
            network.chain_id().value(),
            "{file} declares chain id {declared} but {} is {} in code",
            network.name(),
            network.chain_id().value()
        );
    }
}

/// The check has to be able to fail.
#[test]
fn the_registry_collision_scan_can_detect_a_violation() {
    let planted = 1u64;
    assert!(
        KNOWN_TAKEN.iter().any(|(taken, _)| *taken == planted),
        "the taken-id list no longer contains Ethereum Mainnet, so the scan \
         would accept it"
    );
    let ours = Network::Mainnet.chain_id().value();
    assert!(
        !KNOWN_TAKEN.iter().any(|(taken, _)| *taken == ours),
        "mainnet's own id is in the taken list"
    );
}
