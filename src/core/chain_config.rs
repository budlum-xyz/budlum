use serde::{Deserialize, Serialize};
pub const PROTOCOL_VERSION: u32 = 1;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum, Default,
)]
pub enum Network {
    Mainnet,
    Testnet,
    #[default]
    Devnet,
}

impl Network {
    /// EIP-155 chain id.
    ///
    /// These used to be 1, 42 and 1337. All three are taken in the public
    /// registry at `chainid.network` - checked against the live list of 2668
    /// chains: 1 is Ethereum Mainnet, 42 is LUKSO Mainnet, and 1337 is Geth
    /// Testnet.
    ///
    /// Budlum's own signing preimage is domain-separated (`BDLM_TX_V4` plus
    /// the chain id), so a signature could not have been replayed onto
    /// Ethereum. The cost was to users rather than to consensus: every EVM
    /// wallet resolves a chain id through that registry, so a Budlum RPC
    /// announcing `1` presents itself to MetaMask as Ethereum Mainnet, and the
    /// user is asked to approve what looks like an Ethereum transaction.
    ///
    /// 45260..=45262 are unassigned in the same registry. Changing this before
    /// mainnet costs a genesis hash; changing it after would mean asking every
    /// wallet and explorer to migrate.
    pub fn chain_id(&self) -> ChainId {
        match self {
            Network::Mainnet => ChainId(45260),
            Network::Testnet => ChainId(45261),
            Network::Devnet => ChainId(45262),
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            Network::Mainnet => 4001,
            Network::Testnet => 5001,
            Network::Devnet => 6001,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Devnet => "devnet",
        }
    }

    pub fn bootnodes(&self) -> Vec<String> {
        match self {
            Network::Mainnet => guarded_mainnet_peer_entries(MAINNET_BOOTNODES),
            Network::Testnet => TESTNET_BOOTNODES.iter().map(|s| s.to_string()).collect(),
            Network::Devnet => DEVNET_BOOTNODES.iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn fallback_bootnodes(&self) -> Vec<String> {
        match self {
            Network::Mainnet => guarded_mainnet_peer_entries(MAINNET_FALLBACK_BOOTNODES),
            Network::Testnet => TESTNET_FALLBACK_BOOTNODES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            Network::Devnet => Vec::new(),
        }
    }

    pub fn dns_seeds(&self) -> Vec<String> {
        match self {
            Network::Mainnet => guarded_mainnet_peer_entries(MAINNET_DNS_SEEDS),
            Network::Testnet => TESTNET_DNS_SEEDS.iter().map(|s| s.to_string()).collect(),
            Network::Devnet => Vec::new(),
        }
    }

    /// Inverse of [`Self::chain_id`].
    ///
    /// Kept next to `chain_id` on purpose: the two are a pair, and an id
    /// changed in one and not the other silently stops resolving.
    pub fn from_chain_id(chain_id: u64) -> Option<Self> {
        match chain_id {
            45260 => Some(Network::Mainnet),
            45261 => Some(Network::Testnet),
            45262 => Some(Network::Devnet),
            _ => None,
        }
    }

    pub fn epoch_len(&self) -> u64 {
        self.consensus_params().epoch_len
    }

    pub fn min_stake(&self) -> u64 {
        self.consensus_params().min_stake
    }

    pub fn finality_quorum(&self) -> (u64, u64) {
        let params = self.consensus_params();
        (
            params.finality_quorum_numerator,
            params.finality_quorum_denominator,
        )
    }

    pub fn slot_ms(&self) -> u64 {
        self.consensus_params().slot_ms
    }

    pub fn consensus_params(&self) -> ConsensusParams {
        match self {
            Network::Mainnet => ConsensusParams {
                epoch_len: 100,
                min_stake: 1_000_000,
                slot_ms: 6_000,
                finality_checkpoint_interval: 10,
                finality_quorum_numerator: 2,
                finality_quorum_denominator: 3,
                max_votes_per_msg: 128,
                transport_v2_activation_height: 0,
            },
            Network::Testnet => ConsensusParams {
                epoch_len: 50,
                min_stake: 10_000,
                slot_ms: 3_000,
                finality_checkpoint_interval: 5,
                finality_quorum_numerator: 2,
                finality_quorum_denominator: 3,
                max_votes_per_msg: 128,
                transport_v2_activation_height: 0,
            },
            Network::Devnet => ConsensusParams {
                epoch_len: 10,
                min_stake: 1_000,
                slot_ms: 1_000,
                finality_checkpoint_interval: 2,
                finality_quorum_numerator: 1,
                finality_quorum_denominator: 2,
                max_votes_per_msg: 64,
                transport_v2_activation_height: 0,
            },
        }
    }

    pub fn mempool_config(&self) -> crate::mempool::pool::MempoolConfig {
        match self {
            Network::Mainnet => crate::mempool::pool::MempoolConfig {
                max_size: 100_000,
                max_per_sender: 100,
                min_fee: 10,
                tx_ttl_secs: 1_800,
                rbf_bump_percent: 15,
            },
            Network::Testnet => crate::mempool::pool::MempoolConfig {
                max_size: 50_000,
                max_per_sender: 200,
                min_fee: 1,
                tx_ttl_secs: 3_600,
                rbf_bump_percent: 10,
            },
            Network::Devnet => crate::mempool::pool::MempoolConfig::default(),
        }
    }

    pub fn security_config(&self) -> SecurityConfig {
        match self {
            Network::Mainnet => SecurityConfig {
                max_peers: 100,
                peer_rate_limit_per_minute: 120,
                max_peers_per_subnet: 4,
                rpc_rate_limit_per_minute: 300,
                rpc_auth_required: true,
                persist_banned_peers: true,
                mdns_enabled: false,
                max_outbound_per_subnet: 4,
                enable_circuit_relay: false,
            },
            Network::Testnet => SecurityConfig {
                max_peers: 75,
                peer_rate_limit_per_minute: 240,
                max_peers_per_subnet: 4,
                rpc_rate_limit_per_minute: 600,
                rpc_auth_required: true,
                persist_banned_peers: true,
                mdns_enabled: false,
                max_outbound_per_subnet: 4,
                enable_circuit_relay: false,
            },
            Network::Devnet => SecurityConfig {
                max_peers: 25,
                peer_rate_limit_per_minute: 1_000,
                max_peers_per_subnet: 8,
                rpc_rate_limit_per_minute: 10_000,
                rpc_auth_required: false,
                persist_banned_peers: false,
                mdns_enabled: true,
                max_outbound_per_subnet: 0,
                enable_circuit_relay: true,
            },
        }
    }

    pub fn magic_bytes(&self) -> [u8; 4] {
        match self {
            Network::Mainnet => *b"BDLM",
            Network::Testnet => *b"BDLT",
            Network::Devnet => *b"BDLD",
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

pub const EPOCH_LEN: u64 = 100;

pub fn epoch_len_for_chain_id(chain_id: u64) -> u64 {
    Network::from_chain_id(chain_id)
        .map(|network| network.epoch_len())
        .unwrap_or(EPOCH_LEN)
}

pub const SLOT_MS: u64 = 1000;

pub fn slot_ms_for_chain_id(chain_id: u64) -> u64 {
    Network::from_chain_id(chain_id)
        .map(|network| network.slot_ms())
        .unwrap_or(SLOT_MS)
}

pub const FINALITY_CHECKPOINT_INTERVAL: u64 = 10;

pub fn finality_checkpoint_interval_for_chain_id(chain_id: u64) -> u64 {
    Network::from_chain_id(chain_id)
        .map(|network| network.consensus_params().finality_checkpoint_interval)
        .unwrap_or(FINALITY_CHECKPOINT_INTERVAL)
}

pub const FINALITY_QUORUM_NUMERATOR: u64 = 2;
pub const FINALITY_QUORUM_DENOMINATOR: u64 = 3;
pub const FIXED_POINT_SCALE: u64 = 1_000_000;
pub const VRF_BASE_PROB: u64 = FIXED_POINT_SCALE;
pub const QC_BLOB_TTL_EPOCHS: u64 = 10;
pub const MAX_QC_BLOB_BYTES: usize = 1_048_576;
pub const MAX_VOTES_PER_MSG: usize = 128;

// Empty until the mainnet genesis ceremony fills in real multiaddrs.
// Q7 dummy bootnodes - NOT production; ceremony must replace.
// Ceremony (2026-07-16): ceremony-ready bootstrap peers.
// These use well-known placeholder peer IDs. During MAINNET_GENESIS_CEREMONY,
// Operators MUST replace these with their actual libp2p peer IDs.
// The IP addresses are RFC 5737 TEST-NET-3 documentation ranges.
const MAINNET_BOOTNODES: &[&str] = &[
    "/ip4/203.0.113.10/tcp/4001/p2p/12D3KooWCeremonyBootstrap1BudlumMainnetNod0001",
    "/ip4/203.0.113.11/tcp/4001/p2p/12D3KooWCeremonyBootstrap2BudlumMainnetNod0002",
    "/ip4/203.0.113.12/tcp/4001/p2p/12D3KooWCeremonyBootstrap3BudlumMainnetNod0003",
];
const TESTNET_BOOTNODES: &[&str] = &[];
const DEVNET_BOOTNODES: &[&str] = &[];
const MAINNET_FALLBACK_BOOTNODES: &[&str] = &[];
const TESTNET_FALLBACK_BOOTNODES: &[&str] = &[];
// // Ceremony (2026-07-16): ceremony DNS seeds.
// Replace with actual operator-published DNS TXT records during ceremony.
// Fail-closed onarim: hedef ceremony domain'leri
// `_dnsaddr.bootstrap-{1,2}.mainnet.budlum.network` - operatorler ceremony'de
// GERCEK TXT publish edene kadar "placeholder" marker'i bilinclidir; guard
// Mainnet boot'unu bloke etmeye devam eder (4129861 regresyonu kapatildi).
const MAINNET_DNS_SEEDS: &[&str] = &[
    "_dnsaddr.placeholder-seed-1.mainnet.budlum.network",
    "_dnsaddr.placeholder-seed-2.mainnet.budlum.network",
];
const TESTNET_DNS_SEEDS: &[&str] = &[];

// (kullanıcı onayı 2026-07-16) mainnet placeholder peer
// Fail-closed guard'ı. Genesis placeholder reddiyle (cli/commands.rs Rule 4)
// Simetrik: dummy/placeholder marker içeren bootnode veya dns seed
// Mainnet'te DIAL EDİLMEZ - süreç startup'ta CRITICAL exit 1 ile durur.
// Ceremony'si bu sabitleri gerçek multiaddr'lara çevirir.
const PLACEHOLDER_PEER_MARKERS: &[&str] = &["dummy", "placeholder", "203.0.113.", ".example"];

fn guarded_mainnet_peer_entries(entries: &[&str]) -> Vec<String> {
    let rendered: Vec<String> = entries.iter().map(|entry| (*entry).to_string()).collect();
    if first_placeholder_peer(&rendered).is_some() {
        Vec::new()
    } else {
        rendered
    }
}

/// Girdi listesindeki placeholder/dummy marker içeren ilk kaydı döner
/// (küçük-büyük harf duyarsız). Temiz listede `None`.
pub fn first_placeholder_peer(entries: &[String]) -> Option<String> {
    entries
        .iter()
        .find(|entry| {
            let lower = entry.to_lowercase();
            PLACEHOLDER_PEER_MARKERS
                .iter()
                .any(|marker| lower.contains(marker))
        })
        .cloned()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusParams {
    pub epoch_len: u64,
    pub min_stake: u64,
    pub slot_ms: u64,
    pub finality_checkpoint_interval: u64,
    pub finality_quorum_numerator: u64,
    pub finality_quorum_denominator: u64,
    pub max_votes_per_msg: usize,
    /// (§1.3 / P0 Transport v2) activation block height for fail-closed v2 wire transport.
    pub transport_v2_activation_height: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub max_peers: usize,
    pub peer_rate_limit_per_minute: u64,
    pub max_peers_per_subnet: usize,
    pub rpc_rate_limit_per_minute: u64,
    pub rpc_auth_required: bool,
    pub persist_banned_peers: bool,
    pub mdns_enabled: bool,
    /// Max outbound connections per /24 subnet (0 = no limit). Outbound
    /// Peer diversity - prevents eclipse via single-subnet outbound concentration.
    #[serde(default)]
    pub max_outbound_per_subnet: usize,
    /// Enable libp2p circuit relay for NAT traversal. Default false
    /// (mainnet v1 follow-up; enable when relay nodes are deployed).
    #[serde(default)]
    pub enable_circuit_relay: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChainId(pub u64);

impl ChainId {
    pub fn new(value: u64) -> Self {
        ChainId(value)
    }
    pub fn value(&self) -> u64 {
        self.0
    }
}

impl Default for ChainId {
    fn default() -> Self {
        Network::Devnet.chain_id()
    }
}

impl From<u64> for ChainId {
    fn from(value: u64) -> Self {
        ChainId(value)
    }
}

impl std::fmt::Display for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_network_configs() {
        assert_eq!(Network::Mainnet.chain_id().value(), 45260);
        assert_eq!(Network::Testnet.chain_id().value(), 45261);
        assert_eq!(Network::Devnet.chain_id().value(), 45262);
        assert_eq!(Network::Mainnet.default_port(), 4001);
    }

    #[test]
    fn chain_id_schedule_helpers_use_one_canonical_source() {
        for network in [Network::Mainnet, Network::Testnet, Network::Devnet] {
            let chain_id = network.chain_id().value();
            let params = network.consensus_params();
            assert_eq!(epoch_len_for_chain_id(chain_id), params.epoch_len);
            assert_eq!(slot_ms_for_chain_id(chain_id), params.slot_ms);
            assert_eq!(
                finality_checkpoint_interval_for_chain_id(chain_id),
                params.finality_checkpoint_interval
            );
        }
    }

    /// Dummy bootnode/dns-seed sabitleri guard tarafından
    /// Yakalanmalı (fail-closed), gerçek multiaddr'lar serbest kalmalı.
    /// Guard test gücü artırıldı - derlenmiş mainnet sabitlerinin
    /// Placeholder marker ile yakalandığını doğrular (c953049 regresyonu kapatıldı).
    #[test]
    fn test_placeholder_peer_detection_blocks_dummy_mainnet_entries() {
        // Negatif kontroller: placeholder/dummy marker içeren kayıtlar YAKALANMALI.
        let dummy = vec!["/ip4/203.0.113.10/tcp/4001/p2p/dummy".to_string()];
        assert!(first_placeholder_peer(&dummy).is_some());
        let dummy_dns = vec!["_dnsaddr.placeholder-seed.mainnet.budlum.network".to_string()];
        assert!(first_placeholder_peer(&dummy_dns).is_some());

        // F7: Derlenmiş mainnet sabitleri placeholder içermeli ve guard tarafından yakalanmalı.
        // Bu, c953049'daki guard bypass regresyonunun tekrarını engeller.
        let compiled_bootnodes: Vec<String> =
            MAINNET_BOOTNODES.iter().map(|s| s.to_string()).collect();
        assert!(
            first_placeholder_peer(&compiled_bootnodes).is_some(),
            "Compiled MAINNET_BOOTNODES must be detected as placeholder (fail-closed guard active)"
        );
        let compiled_dns: Vec<String> = MAINNET_DNS_SEEDS.iter().map(|s| s.to_string()).collect();
        assert!(
            first_placeholder_peer(&compiled_dns).is_some(),
            "Compiled MAINNET_DNS_SEEDS must be detected as placeholder"
        );

        // Defense in depth: callers of Network::Mainnet must never receive
        // Placeholder entries directly. Startup still rejects explicit
        // Operator-provided placeholders through the same guard.
        assert!(Network::Mainnet.bootnodes().is_empty());
        assert!(Network::Mainnet.fallback_bootnodes().is_empty());
        assert!(Network::Mainnet.dns_seeds().is_empty());

        // Pozitif kontroller: gerçek görünümlü kayıtlar serbest.
        let clean = vec![
            "/ip4/139.59.10.20/tcp/4001/p2p/12D3KooWAbCdEfGhIjKlMnOpQrStUvWxYz1234567890"
                .to_string(),
            "/ip6/2606:4700::1/tcp/4001/p2p/12D3KooWAbCdEfGhIjKlMnOpQrStUvWxYz1234567890"
                .to_string(),
        ];
        assert!(first_placeholder_peer(&clean).is_none());
        let clean_dns = vec!["_dnsaddr.seed-1.mainnet.budlum.xyz".to_string()];
        assert!(first_placeholder_peer(&clean_dns).is_none());
        // Boş liste: guard değil, mevcut "boş bootnode" kuralı devrede.
        assert!(first_placeholder_peer(&[]).is_none());
    }

    /// Mainnet is the strictest security profile.
    #[test]
    fn security_profiles() {
        let m = Network::Mainnet.security_config();
        let t = Network::Testnet.security_config();
        let d = Network::Devnet.security_config();

        assert_eq!(m.max_peers, 100);
        assert_eq!(m.peer_rate_limit_per_minute, 120);
        assert_eq!(m.rpc_rate_limit_per_minute, 300);
        assert!(m.rpc_auth_required);
        assert!(m.persist_banned_peers);
        assert!(!m.mdns_enabled);

        assert!(t.peer_rate_limit_per_minute > m.peer_rate_limit_per_minute);
        assert!(d.rpc_rate_limit_per_minute > t.rpc_rate_limit_per_minute);
        assert!(!d.rpc_auth_required);
        assert!(d.mdns_enabled);
        assert!(!d.persist_banned_peers);
    }
}
