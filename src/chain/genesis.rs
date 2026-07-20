use crate::chain::finality::{ValidatorEntry, ValidatorSetSnapshot};
use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::block::{Block, DEFAULT_CHAIN_ID};
use crate::core::chain_config::Network;
use crate::core::transaction::Transaction;
use serde::{Deserialize, Serialize};

pub const BLOCK_REWARD: u64 = 50;

pub const BASE_FEE: u64 = 1;

pub const GENESIS_ALLOCATION: u64 = 1_000_000_000;

pub const GENESIS_TIMESTAMP: u128 = 0;

/// Phase 11.2: Genesis'te bootstrap edilecek domain konfigürasyonu.
/// Serialization-safe (serde), ceremony'de placeholder adreslerle başlar.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapDomainConfig {
    /// Domain ID (1=PoW, 2=PoS, 3=BFT, 4=PoA).
    pub id: u32,
    /// Consensus türü ("pow", "pos", "bft", "poa").
    pub kind: String,
    /// Finality adapter adı (örn "pow-confirmation-depth", "pos-qc-finality").
    pub finality_adapter: String,
    /// Bridge enabled (köprü lifecycle'a katılım).
    pub bridge_enabled: bool,
    /// Min confirmation (PoW için header-chain depth).
    pub min_confirmations: u64,
    /// PoA authority placeholder adresleri (yalnızca PoA domain için).
    /// Ceremony'de gerçek kurum adresleriyle değiştirilir.
    #[serde(default)]
    pub poa_authorities: Vec<String>,
}

impl BootstrapDomainConfig {
    /// Mainnet için 4 domain bootstrap listesi (PoW/PoS/BFT/PoA placeholder).
    pub fn mainnet_defaults() -> Vec<Self> {
        vec![
            Self {
                id: 1,
                kind: "pow".to_string(),
                finality_adapter: "pow-confirmation-depth".to_string(),
                bridge_enabled: true,
                min_confirmations: 6,
                poa_authorities: vec![],
            },
            Self {
                id: 2,
                kind: "pos".to_string(),
                finality_adapter: "pos-qc-finality".to_string(),
                bridge_enabled: true,
                min_confirmations: 1,
                poa_authorities: vec![],
            },
            Self {
                id: 3,
                kind: "bft".to_string(),
                finality_adapter: "bft-aggregate-sig".to_string(),
                bridge_enabled: true,
                min_confirmations: 1,
                poa_authorities: vec![],
            },
            // PoA domain: placeholder authority adresleri (kullanıcı kararı:
            // placeholder ile başla, ceremony'de gerçek adreslere dönüşür).
            Self {
                id: 4,
                kind: "poa".to_string(),
                finality_adapter: "poa-authority-quorum".to_string(),
                bridge_enabled: false, // PoA domain bridge default kapalı
                min_confirmations: 1,
                poa_authorities: vec![
                    "0x0000000000000000000000000000000000000000000000000000000000000AA1"
                        .to_string(),
                    "0x0000000000000000000000000000000000000000000000000000000000000AA2"
                        .to_string(),
                    "0x0000000000000000000000000000000000000000000000000000000000000AA3"
                        .to_string(),
                ],
            },
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    pub chain_id: u64,

    pub allocations: Vec<(Address, u64)>,

    pub validators: Vec<Address>,

    pub block_reward: u64,

    pub base_fee: u64,

    pub gas_schedule: crate::core::transaction::GasSchedule,

    pub timestamp: u128,

    /// Optional $BUD tokenomics (Phase 0.14/8b). When `Some`, genesis additionally
    /// seeds the $BUD distribution accounts (Community/Liquidity/Ecosystem/Team/
    /// BurnReserve) and configures the on-chain burn-reserve address + team
    /// vesting schedule. Default `None` — plain genesis is unchanged.
    #[serde(default)]
    pub bud_tokenomics: Option<crate::tokenomics::TokenomicsParams>,

    /// Phase 11.2: Bootstrap domain listesi. Her domain genesis'te otomatik
    /// register edilir (storage boşsa = yeni chain). PoW/PoS/BFT/PoA 4 domain
    /// mainnet için varsayılan. Default boş (devnet/testnet backward-compat).
    #[serde(default)]
    pub bootstrap_domains: Vec<BootstrapDomainConfig>,
}

impl Default for GenesisConfig {
    fn default() -> Self {
        GenesisConfig {
            chain_id: DEFAULT_CHAIN_ID,
            allocations: vec![],
            validators: vec![],
            block_reward: BLOCK_REWARD,
            base_fee: BASE_FEE,
            gas_schedule: Network::Devnet.gas_schedule(),
            timestamp: GENESIS_TIMESTAMP,
            bud_tokenomics: None,
            bootstrap_domains: vec![],
        }
    }
}

impl GenesisConfig {
    pub fn new(chain_id: u64) -> Self {
        GenesisConfig {
            chain_id,
            ..Default::default()
        }
    }

    pub fn for_network(network: Network) -> Self {
        match network {
            Network::Mainnet => mainnet_genesis(),
            Network::Testnet => testnet_genesis(),
            Network::Devnet => devnet_genesis(),
        }
    }

    pub fn with_allocation(mut self, address: Address, amount: u64) -> Self {
        self.allocations.push((address, amount));
        self
    }

    /// Enable $BUD tokenomics for this genesis (Phase 0.14b): the $BUD distribution
    /// accounts are seeded and the burn-reserve address + team vesting are
    /// configured on the resulting state. Uses reserved tokenomics addresses.
    /// Default genesis is unchanged unless this is explicitly called.
    pub fn with_bud_tokenomics(mut self) -> Self {
        self.bud_tokenomics = Some(crate::tokenomics::TokenomicsParams::default());
        self
    }

    /// Enable $BUD tokenomics with explicit parameters.
    pub fn with_bud_tokenomics_params(
        mut self,
        params: crate::tokenomics::TokenomicsParams,
    ) -> Self {
        self.bud_tokenomics = Some(params);
        self
    }

    pub fn with_validator(mut self, address: Address) -> Self {
        self.validators.push(address);
        self
    }

    pub fn build_genesis_block(&self) -> Block {
        let genesis_tx = Transaction::genesis();
        let mut genesis_state = self.build_state();

        let mut block = Block {
            index: 0,
            timestamp: self.timestamp,
            previous_hash: "0".repeat(64),
            hash: String::new(),
            transactions: vec![genesis_tx],
            nonce: 0,
            producer: None,
            signature: None,
            chain_id: self.chain_id,
            slashing_evidence: None,
            state_root: genesis_state.calculate_state_root(),
            tx_root: "0".repeat(64),
            epoch: 0,
            slot: 0,
            vrf_output: Vec::new(),
            vrf_proof: Vec::new(),
            validator_set_hash: self.validator_set_hash(),
            storage_root: None,
        };

        block.tx_root = block.calculate_tx_root();
        block.hash = block.calculate_hash();
        block
    }

    pub fn build_state(&self) -> AccountState {
        let mut state = AccountState::new();
        state.base_fee = self.base_fee;
        // `block_reward` now lives under `state.tokenomics` (Phase 0.02 tokenomics
        // refactor). The top-level `state.block_reward` field was removed.
        state.tokenomics.block_reward = self.block_reward;

        for (address, amount) in &self.allocations {
            state.add_balance(address, *amount);
        }

        let validator_stake = self.validator_stake();
        for validator in &self.validators {
            state.add_validator(*validator, validator_stake);
        }

        // $BUD tokenomics (Phase 0.14b): seed the distribution accounts and configure
        // the on-chain burn-reserve address + team vesting so the timed burn and
        // vesting enforcement operate on the real chain state.
        if let Some(params) = &self.bud_tokenomics {
            let addrs = crate::tokenomics::TokenomicsAddresses::reserved();
            for (address, amount) in crate::tokenomics::genesis_allocations(params, &addrs) {
                state.add_balance(&address, amount);
            }
            state.tokenomics = *params;
            state.burn_reserve_address = Some(addrs.burn_reserve);
            state.team_vesting = Some((addrs.team, params.team_vesting(0)));
        }

        state
    }

    fn validator_stake(&self) -> u64 {
        Network::from_chain_id(self.chain_id)
            .map(|network| network.min_stake())
            .unwrap_or(1)
    }

    fn validator_set_hash(&self) -> String {
        let stake = self.validator_stake();
        let entries = self
            .validators
            .iter()
            .map(|address| ValidatorEntry {
                address: *address,
                stake,
                bls_public_key: Vec::new(),
                pop_signature: Vec::new(),
                pq_public_key: Vec::new(),
            })
            .collect::<Vec<_>>();

        ValidatorSetSnapshot::compute_hash(&entries)
    }
}

fn address(byte: u8) -> Address {
    Address::from([byte; 32])
}

// === MAINNET GENESIS — Phase 3 §3.1 ===

/// Mainnet genesis configuration.
///
/// Key characteristics:
/// - **Timestamp: TBD** — set to 0, actual launch timestamp configured separately
/// - **Permissionless validators** — validator set starts empty, registered via §3.5 permissionless.rs
/// - **Full $BUD tokenomics** — 100M fixed supply, 6 decimals, 2 burn mechanisms
///
/// Token distribution (100M total, 6 decimals = 10^14 base units):
/// - 10M Community (dev + users)
/// - 10M Liquidity (DEX provisioning)
/// - 20M Ecosystem (grants, incentives)
/// - 20M Team (1-year cliff, 4-year linear vesting)
/// - 40M Burn Reserve (10% annual burn)
///
/// Economics:
/// - Block reward: 50 BUD
/// - Validator APY: 5%
/// - Metabolic burn: 1% of tx fees
pub fn mainnet_genesis() -> GenesisConfig {
    use crate::core::chain_config::FIXED_POINT_SCALE;
    use crate::tokenomics::bud;

    // Full tokenomics params — 100M fixed supply
    let tokenomics = crate::tokenomics::TokenomicsParams {
        community: bud(10_000_000),    // 10M - community/dev
        liquidity: bud(10_000_000),    // 10M - liquidity provisioning
        ecosystem: bud(20_000_000),    // 20M - ecosystem growth
        team: bud(20_000_000),         // 20M - team (vesting)
        burn_reserve: bud(40_000_000), // 40M - burn reserve

        // 10% annual burn of reserve (~10 years to burn 40M)
        epochs_per_year: 52560, // 1 year in epochs (10s slot, 32 slots/epoch)
        annual_burn_ratio_fixed: FIXED_POINT_SCALE / 10,

        // Team vesting: 1-year cliff + 4-year linear
        team_cliff_epochs: 52560,    // 1 year cliff
        team_vesting_epochs: 210240, // 4 years linear

        // 1% metabolic burn (symbolic, tunable)
        tx_fee_burn_ratio_fixed: FIXED_POINT_SCALE / 100,

        // Block emission: 50 BUD per block
        block_reward: 50,

        // Stake yield: 5% APY
        validator_annual_yield_ratio_fixed: (FIXED_POINT_SCALE * 5) / 100,
        slot_duration_secs: 10,
        epoch_length_slots: 32,
    };

    GenesisConfig {
        chain_id: Network::Mainnet.chain_id().value(),

        // TBD: Actual launch timestamp configured at deployment time
        // Set to 0 until launch date is determined
        timestamp: 0,

        // Permissionless: validator set starts empty
        // Validators register via §3.5 permissionless.rs onboarding flow
        validators: vec![],

        // Token allocations handled by tokenomics (bud_tokenomics field)
        allocations: vec![],

        block_reward: 50,
        base_fee: Network::Mainnet.gas_schedule().base_fee,
        gas_schedule: Network::Mainnet.gas_schedule(),

        // Full tokenomics active
        bud_tokenomics: Some(tokenomics),

        // Phase 11.2: 4 domain bootstrap (PoW/PoS/BFT/PoA).
        // PoA: placeholder authorities (ceremony'de gerçek adreslere dönüşür).
        bootstrap_domains: BootstrapDomainConfig::mainnet_defaults(),
    }
}

pub fn testnet_genesis() -> GenesisConfig {
    GenesisConfig {
        chain_id: Network::Testnet.chain_id().value(),
        allocations: vec![
            (address(0x30), 1_000_000_000),
            (address(0x31), 1_000_000_000),
        ],
        validators: vec![address(0x40), address(0x41), address(0x42)],
        block_reward: 50,
        base_fee: Network::Testnet.gas_schedule().base_fee,
        gas_schedule: Network::Testnet.gas_schedule(),
        timestamp: 1_735_689_600_000,
        bud_tokenomics: None,
        bootstrap_domains: vec![],
    }
}

pub fn devnet_genesis() -> GenesisConfig {
    GenesisConfig {
        chain_id: Network::Devnet.chain_id().value(),
        allocations: vec![(address(0x01), GENESIS_ALLOCATION)],
        validators: vec![address(0x02)],
        block_reward: BLOCK_REWARD,
        base_fee: Network::Devnet.gas_schedule().base_fee,
        gas_schedule: Network::Devnet.gas_schedule(),
        timestamp: GENESIS_TIMESTAMP,
        bud_tokenomics: None,
        bootstrap_domains: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = GenesisConfig::default();
        assert_eq!(config.chain_id, DEFAULT_CHAIN_ID);
        assert_eq!(config.block_reward, BLOCK_REWARD);
        assert_eq!(config.base_fee, BASE_FEE);
        assert_eq!(config.timestamp, GENESIS_TIMESTAMP);
    }

    #[test]
    fn test_genesis_deterministic() {
        let config = GenesisConfig::default();
        let genesis1 = config.build_genesis_block();
        let genesis2 = config.build_genesis_block();

        assert_eq!(genesis1.hash, genesis2.hash);
        assert_eq!(genesis1.timestamp, GENESIS_TIMESTAMP);
    }

    #[test]
    fn test_network_genesis_configs_are_distinct() {
        let mainnet = GenesisConfig::for_network(Network::Mainnet);
        let testnet = GenesisConfig::for_network(Network::Testnet);
        let devnet = GenesisConfig::for_network(Network::Devnet);

        assert_ne!(mainnet.chain_id, testnet.chain_id);
        assert_ne!(mainnet.chain_id, devnet.chain_id);
        // Mainnet uses full tokenomics; testnet/devnet do not.
        assert!(mainnet.bud_tokenomics.is_some());
        assert!(testnet.bud_tokenomics.is_none());
        assert!(devnet.bud_tokenomics.is_none());
        // Mainnet is permissionless (empty validators); testnet/devnet seed validators.
        assert!(mainnet.validators.is_empty());
        assert!(!testnet.validators.is_empty());
        assert!(!devnet.validators.is_empty());
        assert_ne!(mainnet.gas_schedule, testnet.gas_schedule);
        assert_ne!(mainnet.gas_schedule, devnet.gas_schedule);
    }

    #[test]
    fn test_config_builder() {
        let config = GenesisConfig::new(42)
            .with_allocation(Address::from_hex(&"0".repeat(64)).unwrap(), 1000)
            .with_validator(Address::from_hex(&"1".repeat(64)).unwrap());

        assert_eq!(config.chain_id, 42);
        assert_eq!(config.allocations.len(), 1);
        assert_eq!(config.validators.len(), 1);
    }

    #[test]
    fn test_genesis_state_applies_allocations_and_validators() {
        let config = GenesisConfig::for_network(Network::Devnet);
        let allocation = config.allocations[0];
        let validator = config.validators[0];

        let state = config.build_state();

        assert_eq!(state.get_balance(&allocation.0), allocation.1);
        assert_eq!(state.base_fee, config.base_fee);
        assert_eq!(state.tokenomics.block_reward, config.block_reward);
        assert_eq!(
            state.get_validator(&validator).map(|v| v.stake),
            Some(Network::Devnet.min_stake())
        );
    }

    #[test]
    fn test_genesis_block_commits_initial_state() {
        let config = GenesisConfig::for_network(Network::Devnet);
        let mut state = config.build_state();
        let block = config.build_genesis_block();

        assert_eq!(block.state_root, state.calculate_state_root());
        assert_ne!(block.state_root, "0".repeat(64));
        assert_ne!(block.validator_set_hash, "0".repeat(64));
        assert_eq!(block.hash, block.calculate_hash());
    }

    #[test]
    fn test_mainnet_genesis_deterministic() {
        // Phase 3 §3.1: mainnet genesis must be deterministic — same config → same hash
        let cfg = GenesisConfig::for_network(Network::Mainnet);
        let g1 = cfg.build_genesis_block();
        let g2 = cfg.build_genesis_block();
        assert_eq!(g1.hash, g2.hash);
        assert_eq!(g1.chain_id, Network::Mainnet.chain_id().value());
        assert_eq!(g1.hash, g1.calculate_hash());
    }

    #[test]
    fn test_mainnet_genesis_hash_distinct_from_testnet_devnet() {
        // Phase 3 §3.1: distinct networks must produce distinct genesis hashes
        let mainnet = GenesisConfig::for_network(Network::Mainnet).build_genesis_block();
        let testnet = GenesisConfig::for_network(Network::Testnet).build_genesis_block();
        let devnet = GenesisConfig::for_network(Network::Devnet).build_genesis_block();
        assert_ne!(mainnet.hash, testnet.hash);
        assert_ne!(mainnet.hash, devnet.hash);
        assert_ne!(testnet.hash, devnet.hash);
    }

    /// Load a checked-in network genesis JSON (Phase 3 §3.1).
    fn load_genesis_json(relative: &str) -> GenesisConfig {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
        let data = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        serde_json::from_str(&data)
            .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()))
    }

    #[test]
    fn test_mainnet_genesis_params() {
        // ARENA1 e20397c design: permissionless validators + full $BUD tokenomics.
        let config = mainnet_genesis();
        assert_eq!(config.chain_id, 1);
        assert_eq!(config.block_reward, 50);
        assert_eq!(config.base_fee, Network::Mainnet.gas_schedule().base_fee);
        assert_eq!(config.gas_schedule, Network::Mainnet.gas_schedule());
        assert!(config.allocations.is_empty());
        assert!(config.validators.is_empty());
        assert!(config.bud_tokenomics.is_some());
        assert!(config.bud_tokenomics.unwrap().is_balanced());
        assert_eq!(config.timestamp, 0);
    }

    #[test]
    fn test_mainnet_genesis_json_matches_code() {
        // Critical: config/mainnet-genesis.json must equal mainnet_genesis() hash.
        let from_code = mainnet_genesis();
        let from_json = load_genesis_json("config/mainnet-genesis.json");

        assert_eq!(from_json.chain_id, from_code.chain_id);
        assert_eq!(from_json.allocations, from_code.allocations);
        assert_eq!(from_json.validators, from_code.validators);
        assert_eq!(from_json.block_reward, from_code.block_reward);
        assert_eq!(from_json.base_fee, from_code.base_fee);
        assert_eq!(from_json.gas_schedule, from_code.gas_schedule);
        assert_eq!(from_json.timestamp, from_code.timestamp);
        assert_eq!(from_json.bud_tokenomics, from_code.bud_tokenomics);

        let code_block = from_code.build_genesis_block();
        let json_block = from_json.build_genesis_block();
        assert_eq!(
            code_block.hash, json_block.hash,
            "config/mainnet-genesis.json must produce the same genesis hash as mainnet_genesis()"
        );
        assert_eq!(code_block.state_root, json_block.state_root);
        assert_eq!(code_block.validator_set_hash, json_block.validator_set_hash);
    }

    #[test]
    fn test_testnet_and_devnet_genesis_json_match_code() {
        for (network, path) in [
            (Network::Testnet, "config/testnet-genesis.json"),
            (Network::Devnet, "config/devnet-genesis.json"),
        ] {
            let from_code = GenesisConfig::for_network(network);
            let from_json = load_genesis_json(path);
            assert_eq!(from_json.chain_id, from_code.chain_id, "{path}");
            assert_eq!(from_json.allocations, from_code.allocations, "{path}");
            assert_eq!(from_json.validators, from_code.validators, "{path}");
            assert_eq!(from_json.block_reward, from_code.block_reward, "{path}");
            assert_eq!(from_json.gas_schedule, from_code.gas_schedule, "{path}");
            assert_eq!(from_json.timestamp, from_code.timestamp, "{path}");
            assert_eq!(
                from_code.build_genesis_block().hash,
                from_json.build_genesis_block().hash,
                "{path} genesis hash mismatch"
            );
        }
    }

    #[test]
    fn test_mainnet_genesis_json_roundtrip() {
        let original = mainnet_genesis();
        let encoded = serde_json::to_string_pretty(&original).expect("serialize");
        let decoded: GenesisConfig = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(original.chain_id, decoded.chain_id);
        assert_eq!(original.allocations, decoded.allocations);
        assert_eq!(original.validators, decoded.validators);
        assert_eq!(
            original.build_genesis_block().hash,
            decoded.build_genesis_block().hash
        );
    }
}

// === MAINNET GENESIS TESTS — Phase 3 §3.1 ===

#[cfg(test)]
mod mainnet_genesis_tests {
    use super::*;

    #[test]
    fn test_mainnet_genesis_tokenomics_balanced() {
        // Mainnet must have tokenomics and it must sum to 100M
        let config = mainnet_genesis();
        assert!(
            config.bud_tokenomics.is_some(),
            "Mainnet must have tokenomics"
        );
        let params = config.bud_tokenomics.unwrap();
        assert!(params.is_balanced(), "Tokenomics must sum to 100M BUD");
    }

    #[test]
    fn test_mainnet_genesis_permissionless_validators() {
        // Mainnet starts with empty validator set (permissionless)
        let config = mainnet_genesis();
        assert!(
            config.validators.is_empty(),
            "Mainnet starts with permissionless validators"
        );
    }

    #[test]
    fn test_mainnet_genesis_deterministic() {
        // Genesis block hash must be deterministic
        let config = mainnet_genesis();
        let genesis1 = config.build_genesis_block();
        let genesis2 = config.build_genesis_block();

        assert_eq!(
            genesis1.hash, genesis2.hash,
            "Genesis hash must be deterministic"
        );
        assert_eq!(
            genesis1.state_root, genesis2.state_root,
            "State root must be deterministic"
        );
    }

    #[test]
    fn test_mainnet_genesis_token_distribution() {
        use crate::tokenomics::{Allocation, BUD_TOTAL_SUPPLY};

        let config = mainnet_genesis();
        let params = config.bud_tokenomics.unwrap();

        // Verify distribution sums to 100M
        assert_eq!(
            params.total(),
            BUD_TOTAL_SUPPLY,
            "Tokenomics must total 100M (100_000_000 * 10^6)"
        );

        // Verify individual allocations
        assert_eq!(
            params.amount_of(Allocation::Community),
            crate::tokenomics::bud(10_000_000)
        );
        assert_eq!(
            params.amount_of(Allocation::Liquidity),
            crate::tokenomics::bud(10_000_000)
        );
        assert_eq!(
            params.amount_of(Allocation::Ecosystem),
            crate::tokenomics::bud(20_000_000)
        );
        assert_eq!(
            params.amount_of(Allocation::Team),
            crate::tokenomics::bud(20_000_000)
        );
        assert_eq!(
            params.amount_of(Allocation::BurnReserve),
            crate::tokenomics::bud(40_000_000)
        );
    }

    #[test]
    fn test_mainnet_genesis_economics_params() {
        use crate::core::chain_config::FIXED_POINT_SCALE;

        let config = mainnet_genesis();
        let params = config.bud_tokenomics.unwrap();

        // Block reward: 50 BUD
        assert_eq!(params.block_reward, 50);

        // Annual burn: 10%
        assert_eq!(params.annual_burn_ratio_fixed, FIXED_POINT_SCALE / 10);

        // Validator APY: 5%
        assert_eq!(
            params.validator_annual_yield_ratio_fixed,
            (FIXED_POINT_SCALE * 5) / 100
        );

        // Metabolic burn: 1%
        assert_eq!(params.tx_fee_burn_ratio_fixed, FIXED_POINT_SCALE / 100);
    }

    /// F9 fix (ARENAX): Genesis hash constant documented in config/mainnet.toml:5
    /// previously had no absolute-value assert — only JSON==code equality (V5).
    /// This test seals the constant so accidental genesis config change is caught.
    #[test]
    fn test_mainnet_genesis_hash_matches_documented_constant() {
        // CI-computed current value (re-anchored 2026-07-20 after DAO encryption policy state-root change)
        const DOCUMENTED_MAINNET_GENESIS_HASH: &str =
            "fd5f7cb272e01333517d9f85b7e1052b89489a80dd497b2655c3dea99d53add4";

        let genesis = mainnet_genesis().build_genesis_block();
        assert_eq!(
            genesis.hash, DOCUMENTED_MAINNET_GENESIS_HASH,
            "Mainnet genesis hash must match documented constant in mainnet.toml:5 —              if this intentionally changed, update docs/operations/PRODUCTION_RUNBOOK.md §8.2 and config/mainnet.toml comment"
        );
    }
}
