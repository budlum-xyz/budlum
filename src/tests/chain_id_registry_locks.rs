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

/// The node profiles carry `network.chain_id` next to the network name. The
/// loader refuses a profile whose id differs from the network's registered id
/// (`NodeConfig::validate`), so a profile with the wrong number is a profile
/// nobody can start. All six shipped profiles used to carry the pre-registry
/// numbers (1, 42, 1337) and were refused at startup; this lock reads each one
/// and compares it with the code the way the loader does.
#[test]
fn the_shipped_node_profiles_agree_with_the_code() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for (file, network) in [
        ("config/mainnet.toml", Network::Mainnet),
        ("config/testnet.toml", Network::Testnet),
        ("config/devnet.toml", Network::Devnet),
        ("config/personas/enterprise-poa.toml", Network::Mainnet),
        ("config/personas/developer.toml", Network::Devnet),
        ("config/personas/user-devnet.toml", Network::Devnet),
    ] {
        let raw = std::fs::read_to_string(root.join(file))
            .unwrap_or_else(|e| panic!("{file} is readable: {e}"));
        let parsed: toml::Value =
            toml::from_str(&raw).unwrap_or_else(|e| panic!("{file} is valid TOML: {e}"));
        let declared = parsed
            .get("network")
            .and_then(|n| n.get("chain_id"))
            .and_then(toml::Value::as_integer)
            .unwrap_or_else(|| panic!("{file} has no numeric network.chain_id"));
        assert_eq!(
            u64::try_from(declared).ok(),
            Some(network.chain_id().value()),
            "{file} declares chain id {declared} but {} is {} in code",
            network.name(),
            network.chain_id().value()
        );
    }
}

/// A shipped profile that listens on every interface carries a key, and its
/// metrics listener stays on loopback.
///
/// `mainnet.toml` and `testnet.toml` bound the public RPC to `0.0.0.0` with
/// no `auth_required` and no `api_key_env`. The code default is
/// `auth_required = true`, so the node either refused to start (no key
/// source) or, once an operator flipped the flag to get past that, served
/// every method to the internet with no key. The metrics listener has no
/// authentication of its own, and two profiles put it on `0.0.0.0` as well.
/// This lock reads every checked-in profile the way the loader does: a
/// public listener off loopback requires `auth_required = true` and a named
/// key variable, and the metrics listener is loopback everywhere.
#[test]
fn profiles_that_listen_on_every_interface_carry_a_key() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // The seven shipped profiles by path. A count alone let an unrelated
    // TOML stand in for a required profile: a missing `rpc` table reads as
    // a loopback default and a missing `metrics` table is skipped, so the
    // replaced profile passed without being checked.
    const SHIPPED: [&str; 7] = [
        "config/archive.toml",
        "config/devnet.toml",
        "config/mainnet.toml",
        "config/personas/developer.toml",
        "config/personas/enterprise-poa.toml",
        "config/personas/user-devnet.toml",
        "config/testnet.toml",
    ];
    let mut seen: Vec<String> = Vec::new();
    for entry in ["config", "config/personas"]
        .iter()
        .flat_map(|dir| std::fs::read_dir(root.join(dir)).expect("profile directory is readable"))
    {
        let path = entry.expect("profile entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let file = path.strip_prefix(&root).unwrap().display().to_string();
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{file}: {e}"));
        let parsed: toml::Value =
            toml::from_str(&raw).unwrap_or_else(|e| panic!("{file} is valid TOML: {e}"));
        seen.push(file.clone());

        let rpc = parsed.get("rpc");
        let listener = rpc
            .and_then(|r| r.get("public_listener"))
            .and_then(toml::Value::as_str)
            .unwrap_or("127.0.0.1:0");
        let is_loopback = listener.starts_with("127.") || listener.starts_with("[::1]");
        if !is_loopback {
            let auth = rpc
                .and_then(|r| r.get("auth_required"))
                .and_then(toml::Value::as_bool);
            let key_env = rpc
                .and_then(|r| r.get("api_key_env"))
                .and_then(toml::Value::as_str)
                .unwrap_or("");
            assert_eq!(
                auth,
                Some(true),
                "{file} listens on {listener} and must say auth_required = true"
            );
            assert!(
                !key_env.trim().is_empty(),
                "{file} listens on {listener} and must name api_key_env"
            );
        }

        if let Some(metrics) = parsed
            .get("metrics")
            .and_then(|m| m.get("listener"))
            .and_then(toml::Value::as_str)
        {
            assert!(
                metrics.starts_with("127.") || metrics.starts_with("[::1]"),
                "{file} exposes the unauthenticated metrics endpoint on {metrics}"
            );
        }
    }
    seen.sort();
    for shipped in SHIPPED {
        assert!(
            seen.iter().any(|s| s == shipped),
            "the shipped profile {shipped} was not read; found {seen:?}"
        );
    }
}
