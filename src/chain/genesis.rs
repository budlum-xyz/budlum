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

/// Genesis'te bootstrap edilecek domain konfigürasyonu.
/// Serialization-safe (serde), ceremony'de placeholder adreslerle başlar.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapDomainConfig {
    /// Domain ID (1=PoW, 2=PoS, 3=BFT, 4=PoA).
    pub id: u32,
    /// Consensus türü ("pow", "pos", "bft", "poa").
    pub kind: String,
    /// Finality adapter adı (örn "pow-header-chain-v1", "pos-qc-finality").
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
                finality_adapter: "pow-header-chain-v1".to_string(),
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
                finality_adapter: "bft-quorum-commit".to_string(),
                bridge_enabled: true,
                min_confirmations: 1,
                poa_authorities: vec![],
            },
            // PoA domain: placeholder authority adresleri (kullanıcı kararı:
            // Placeholder ile başla, ceremony'de gerçek adreslere dönüşür).
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
pub struct GenesisConsensusKeys {
    pub validator: Address,
    pub registration: crate::core::transaction::ConsensusKeyRegistration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    pub chain_id: u64,

    pub allocations: Vec<(Address, u64)>,

    pub validators: Vec<Address>,

    /// Ceremony-produced public consensus keys for address-only validators.
    /// Every mainnet validator must have exactly one matching record.
    #[serde(default)]
    pub validator_consensus_keys: Vec<GenesisConsensusKeys>,

    pub block_reward: u64,

    pub base_fee: u64,

    pub gas_schedule: crate::core::transaction::GasSchedule,

    pub timestamp: u128,

    /// Optional $BUD tokenomics. When `Some`, genesis additionally
    /// Seeds the $BUD distribution accounts (Community/Liquidity/Ecosystem/Team/
    /// BurnReserve) and configures the on-chain burn-reserve address + team
    /// Vesting schedule. Default `None` - plain genesis is unchanged.
    #[serde(default)]
    pub bud_tokenomics: Option<crate::tokenomics::TokenomicsParams>,

    /// Ceremony-controlled tokenomics destinations committed into genesis.
    /// Reserved marker addresses are allowed only for non-mainnet development
    /// Chains. Spending policies are enforced separately by consensus state.
    #[serde(default)]
    pub tokenomics_addresses: Option<crate::tokenomics::TokenomicsAddresses>,

    /// Post-quantum signature scheme this chain was launched with.
    ///
    /// The PQ backend is a compile-time feature, but the public key it emits is
    /// consensus data - its length is enforced on the validation path, and
    /// Dilithium5 (2592 bytes) and ML-DSA-65 (1952) disagree. Two nodes built
    /// with different features would reject each other's validator
    /// registrations as malformed keys and split the network with no error
    /// naming the cause.
    ///
    /// Recording the scheme in genesis turns that into a startup failure: a
    /// node whose build does not match the chain refuses to run instead of
    /// joining and diverging. `None` means a chain launched before this field
    /// existed; the check is skipped rather than guessing.
    #[serde(default)]
    pub pq_scheme: Option<String>,

    /// Bootstrap domain listesi. Her domain genesis'te otomatik
    /// Register edilir (storage boşsa = yeni chain). PoW/PoS/BFT/PoA 4 domain
    /// Mainnet için varsayılan. Default boş (devnet/testnet backward-compat).
    #[serde(default)]
    pub bootstrap_domains: Vec<BootstrapDomainConfig>,
}

impl Default for GenesisConfig {
    fn default() -> Self {
        GenesisConfig {
            chain_id: DEFAULT_CHAIN_ID,
            allocations: vec![],
            validators: vec![],
            validator_consensus_keys: vec![],
            block_reward: BLOCK_REWARD,
            base_fee: BASE_FEE,
            gas_schedule: Network::Devnet.gas_schedule(),
            timestamp: GENESIS_TIMESTAMP,
            bud_tokenomics: None,
            tokenomics_addresses: None,
            pq_scheme: Some(crate::crypto::primitives::PQ_SCHEME_ID.to_string()),
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

    /// Enable $BUD tokenomics for this genesis: the $BUD distribution
    /// Accounts are seeded and the burn-reserve address + team vesting are
    /// Configured on the resulting state. Uses reserved tokenomics addresses.
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

    /// Materialize the declarative `bootstrap_domains` list into concrete
    /// `ConsensusDomain` records that the runtime can register on startup.
    ///
    /// This keeps the ceremony-facing genesis JSON as the single source of truth
    /// For the hybrid-domain topology. Invalid bootstrap entries fail closed so
    /// A node cannot silently start with a partial domain set.
    pub fn bootstrap_consensus_domains(
        &self,
    ) -> Result<Vec<crate::domain::ConsensusDomain>, String> {
        self.bootstrap_domains
            .iter()
            .map(|cfg| {
                let kind = match cfg.kind.as_str() {
                    "pow" => crate::domain::ConsensusKind::PoW,
                    "pos" => crate::domain::ConsensusKind::PoS,
                    "poa" => crate::domain::ConsensusKind::PoA,
                    "bft" => crate::domain::ConsensusKind::Bft,
                    other => {
                        return Err(format!(
                            "Unsupported bootstrap domain kind '{}' for domain {}",
                            other, cfg.id
                        ))
                    }
                };

                let mut domain = crate::domain::default_domain(
                    cfg.id,
                    kind,
                    self.chain_id,
                    cfg.finality_adapter.clone(),
                    cfg.min_confirmations,
                );
                domain.bridge_enabled = cfg.bridge_enabled;

                if matches!(domain.kind, crate::domain::ConsensusKind::PoA)
                    && !cfg.poa_authorities.is_empty()
                {
                    let mut entries = Vec::with_capacity(cfg.poa_authorities.len());
                    for authority in &cfg.poa_authorities {
                        let address = Address::from_hex(authority).map_err(|e| {
                            format!(
                                "Invalid PoA authority '{}' in bootstrap domain {}: {}",
                                authority, cfg.id, e
                            )
                        })?;
                        entries.push(ValidatorEntry {
                            address,
                            stake: 1,
                            bls_public_key: Vec::new(),
                            pop_signature: Vec::new(),
                            pq_public_key: Vec::new(),
                        });
                    }
                    domain.validator_set_hash = crate::domain::validator_set_commitment(
                        b"bootstrap_validator_set_hash",
                        cfg.id,
                        &crate::domain::RootScheme::Sha3_256,
                        ValidatorSetSnapshot::compute_hash(&entries).as_bytes(),
                    );
                }

                Ok(domain)
            })
            .collect()
    }

    /// Refuse to run when this binary's PQ backend is not the one the chain
    /// was launched with.
    ///
    /// Deliberately fail-closed. The alternative - starting anyway - produces a
    /// node that accepts blocks but rejects every validator registration from
    /// its peers, which looks like a peering problem rather than a build
    /// problem and costs an operator hours to diagnose.
    pub fn validate_pq_scheme(&self) -> Result<(), String> {
        let Some(chain_scheme) = self.pq_scheme.as_deref() else {
            // Chain predates the field. Nothing to compare against; the
            // operator gets no false assurance either way.
            return Ok(());
        };
        let build_scheme = crate::crypto::primitives::PQ_SCHEME_ID;
        if chain_scheme != build_scheme {
            return Err(format!(
                "post-quantum backend mismatch: this binary was built for `{build_scheme}` \
                 (public keys {} bytes) but the chain genesis declares `{chain_scheme}`. \
                 Rebuild with the matching feature - running anyway would reject every \
                 validator registration on this chain as a malformed key.",
                crate::crypto::primitives::pq_public_key_len()
            ));
        }
        Ok(())
    }

    pub fn validate_consensus_ceremony(&self, network: Network) -> Result<(), String> {
        self.validate_pq_scheme()?;
        if self.chain_id != network.chain_id().value() {
            return Err(format!(
                "Genesis chain ID {} does not match {} profile chain ID {}",
                self.chain_id,
                network,
                network.chain_id()
            ));
        }
        let validator_set = self
            .validators
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        if validator_set.len() != self.validators.len() {
            return Err("Genesis validator list contains duplicate addresses".into());
        }

        let mut registered = std::collections::BTreeSet::new();
        for keys in &self.validator_consensus_keys {
            if !validator_set.contains(&keys.validator) {
                return Err(format!(
                    "Consensus keys supplied for non-validator {}",
                    keys.validator
                ));
            }
            if !registered.insert(keys.validator) {
                return Err(format!(
                    "Duplicate consensus key registration for {}",
                    keys.validator
                ));
            }
            keys.registration
                .validate(keys.validator, self.chain_id)
                .map_err(|error| {
                    format!(
                        "Invalid genesis consensus keys for {}: {error}",
                        keys.validator
                    )
                })?;
        }

        if network == Network::Mainnet {
            let tokenomics_addresses = self.tokenomics_addresses.ok_or_else(|| {
                "Mainnet genesis requires ceremony-controlled tokenomics addresses".to_string()
            })?;
            let categories = [
                tokenomics_addresses.community,
                tokenomics_addresses.liquidity,
                tokenomics_addresses.ecosystem,
                tokenomics_addresses.team,
                tokenomics_addresses.burn_reserve,
            ];
            let unique_categories = categories
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>();
            if unique_categories.len() != categories.len()
                || categories.iter().any(|address| {
                    address == &Address::zero() || address.as_bytes().starts_with(&[0xB0, 0xD0])
                })
            {
                return Err(
                    "Mainnet tokenomics addresses must be unique non-reserved ceremony accounts"
                        .into(),
                );
            }
            self.validate_mainnet_poa_authorities()?;
            if self.validators.len() < 4 {
                return Err(
                    "Mainnet genesis requires at least four ceremony validators (3f+1)".into(),
                );
            }
            if registered.len() != self.validators.len() {
                return Err(format!(
                    "Mainnet genesis has {} validators but only {} complete consensus-key records",
                    self.validators.len(),
                    registered.len()
                ));
            }
        }
        Ok(())
    }

    fn validate_mainnet_poa_authorities(&self) -> Result<(), String> {
        let poa_domains: Vec<&BootstrapDomainConfig> = self
            .bootstrap_domains
            .iter()
            .filter(|domain| domain.kind == "poa")
            .collect();
        if poa_domains.is_empty() {
            return Err("Mainnet genesis requires an Enterprise PoA bootstrap domain".into());
        }

        for domain in poa_domains {
            if domain.poa_authorities.is_empty() {
                return Err(format!(
                    "Mainnet PoA domain {} requires ceremony-provided authority addresses",
                    domain.id
                ));
            }
            let mut unique = std::collections::BTreeSet::new();
            for authority in &domain.poa_authorities {
                let address = Address::from_hex(authority).map_err(|error| {
                    format!(
                        "Invalid PoA authority '{}' in bootstrap domain {}: {}",
                        authority, domain.id, error
                    )
                })?;
                if address == Address::zero()
                    || address.as_bytes().starts_with(&[0u8; 30])
                    || address.as_bytes().starts_with(&[0xB0, 0xD0])
                {
                    return Err(format!(
                        "Mainnet PoA authority {} in domain {} is a placeholder or reserved marker",
                        address, domain.id
                    ));
                }
                if !unique.insert(address) {
                    return Err(format!(
                        "Mainnet PoA domain {} contains duplicate authority {}",
                        domain.id, address
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn build_genesis_block(&self) -> Block {
        let genesis_tx = Transaction::genesis();
        let mut genesis_state = self.build_state();

        let validator_set_hash = genesis_state
            .consensus_validator_set_hash(self.chain_id)
            .unwrap_or_else(|_| "INVALID_CONSENSUS_VALIDATOR_SET".to_string());

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
            validator_set_hash,
            storage_root: None,
        };

        block.tx_root = block.calculate_tx_root();
        block.hash = block.calculate_hash();
        block
    }

    pub fn build_state(&self) -> AccountState {
        let mut state = AccountState::new();
        state.base_fee = self.base_fee;
        // `block_reward` now lives under `state.tokenomics` (tokenomics
        // Refactor). The top-level `state.block_reward` field was removed.
        state.tokenomics.block_reward = self.block_reward;

        for (address, amount) in &self.allocations {
            state.add_balance(address, *amount);
        }

        let validator_stake = self.validator_stake();
        for validator in &self.validators {
            state.add_validator(*validator, validator_stake);
            if let Some(entry) = state.get_validator_mut(validator) {
                // Address-only legacy genesis entries are bonded but cannot
                // Enter PoS/finality until RegisterConsensusKeys is applied.
                entry.active = false;
                if let Some(keys) = self
                    .validator_consensus_keys
                    .iter()
                    .find(|keys| keys.validator == *validator)
                {
                    if keys
                        .registration
                        .validate(*validator, self.chain_id)
                        .is_ok()
                    {
                        entry.vrf_public_key = keys.registration.vrf_public_key.clone();
                        entry.bls_public_key = keys.registration.bls_public_key.clone();
                        entry.pop_signature = keys.registration.pop_signature.clone();
                        entry.pq_public_key = keys.registration.pq_public_key.clone();
                        entry.active = entry.stake >= validator_stake
                            && entry.is_consensus_ready()
                            && entry.verify_pop_is_valid();
                    }
                }
            }
        }

        // $BUD tokenomics: seed the distribution accounts and configure
        // The on-chain burn-reserve address + team vesting so the timed burn and
        // Vesting enforcement operate on the real chain state.
        if let Some(params) = &self.bud_tokenomics {
            let addrs = self
                .tokenomics_addresses
                .unwrap_or_else(crate::tokenomics::TokenomicsAddresses::reserved);
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
}

fn address(byte: u8) -> Address {
    Address::from([byte; 32])
}

// === MAINNET GENESIS ===

/// Mainnet genesis configuration.
///
/// Key characteristics:
/// - **Timestamp: TBD** - set to 0, actual launch timestamp configured separately
/// - **Ceremony bootstrap** - at least four keyed validators at genesis;
///   Permissionless onboarding follows
/// - **Full $BUD tokenomics** - 100M fixed supply, 6 decimals, 2 burn mechanisms
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

    // Full tokenomics params - 100M fixed supply
    let tokenomics = crate::tokenomics::TokenomicsParams {
        community: bud(10_000_000),    // 10M - community/dev
        liquidity: bud(10_000_000),    // 10M - liquidity provisioning
        ecosystem: bud(20_000_000),    // 20M - ecosystem growth
        team: bud(20_000_000),         // 20M - team (vesting)
        burn_reserve: bud(40_000_000), // 40M - burn reserve

        // 10% annual burn of reserve (~10 years to burn 40M)
        epochs_per_year: 52560, // 1 year: 6s slot × 100 slots/epoch
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

        // Ceremony template: operators must populate at least four validators
        // And matching validator_consensus_keys before mainnet startup.
        validators: vec![],
        validator_consensus_keys: vec![],

        // Token allocations handled by tokenomics (bud_tokenomics field)
        allocations: vec![],

        block_reward: 50,
        base_fee: Network::Mainnet.gas_schedule().base_fee,
        gas_schedule: Network::Mainnet.gas_schedule(),

        // Full tokenomics active
        bud_tokenomics: Some(tokenomics),
        tokenomics_addresses: None,

        // 4 domain bootstrap (PoW/PoS/BFT/PoA).
        // PoA: placeholder authorities (ceremony'de gerçek adreslere dönüşür).
        pq_scheme: Some(crate::crypto::primitives::PQ_SCHEME_ID.to_string()),
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
        validator_consensus_keys: vec![],
        block_reward: 50,
        base_fee: Network::Testnet.gas_schedule().base_fee,
        gas_schedule: Network::Testnet.gas_schedule(),
        timestamp: 1_735_689_600_000,
        bud_tokenomics: None,
        tokenomics_addresses: None,
        pq_scheme: Some(crate::crypto::primitives::PQ_SCHEME_ID.to_string()),
        bootstrap_domains: vec![],
    }
}

pub fn devnet_genesis() -> GenesisConfig {
    GenesisConfig {
        chain_id: Network::Devnet.chain_id().value(),
        allocations: vec![(address(0x01), GENESIS_ALLOCATION)],
        validators: vec![address(0x02)],
        validator_consensus_keys: vec![],
        block_reward: BLOCK_REWARD,
        base_fee: Network::Devnet.gas_schedule().base_fee,
        gas_schedule: Network::Devnet.gas_schedule(),
        timestamp: GENESIS_TIMESTAMP,
        bud_tokenomics: None,
        tokenomics_addresses: None,
        pq_scheme: Some(crate::crypto::primitives::PQ_SCHEME_ID.to_string()),
        bootstrap_domains: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_economic_year_matches_canonical_slot_epoch_schedule() {
        let genesis = mainnet_genesis();
        let tokenomics = genesis.bud_tokenomics.unwrap();
        let params = Network::Mainnet.consensus_params();
        let seconds_per_year = tokenomics
            .epochs_per_year
            .checked_mul(params.epoch_len)
            .and_then(|slots| slots.checked_mul(params.slot_ms / 1_000))
            .unwrap();
        assert_eq!(seconds_per_year, 365 * 24 * 60 * 60);
        assert_eq!(tokenomics.team_cliff_epochs, tokenomics.epochs_per_year);
        assert_eq!(
            tokenomics.team_vesting_epochs,
            tokenomics.epochs_per_year * 4
        );
    }

    fn ceremony_tokenomics_addresses() -> crate::tokenomics::TokenomicsAddresses {
        crate::tokenomics::TokenomicsAddresses {
            community: address(10),
            liquidity: address(11),
            ecosystem: address(12),
            team: address(13),
            burn_reserve: address(14),
        }
    }

    fn set_valid_poa_authorities(config: &mut GenesisConfig) {
        for domain in &mut config.bootstrap_domains {
            if domain.kind == "poa" {
                domain.poa_authorities = vec![
                    address(0x91).to_hex(),
                    address(0x92).to_hex(),
                    address(0x93).to_hex(),
                ];
            }
        }
    }

    #[test]
    fn mainnet_ceremony_rejects_missing_reserved_or_duplicate_tokenomics_addresses() {
        let missing = mainnet_genesis();
        assert!(missing
            .validate_consensus_ceremony(Network::Mainnet)
            .unwrap_err()
            .contains("ceremony-controlled tokenomics addresses"));

        let mut reserved = mainnet_genesis();
        reserved.tokenomics_addresses = Some(crate::tokenomics::TokenomicsAddresses::reserved());
        assert!(reserved
            .validate_consensus_ceremony(Network::Mainnet)
            .unwrap_err()
            .contains("unique non-reserved"));

        let mut duplicate = mainnet_genesis();
        let mut duplicate_addresses = ceremony_tokenomics_addresses();
        duplicate_addresses.team = duplicate_addresses.community;
        duplicate.tokenomics_addresses = Some(duplicate_addresses);
        assert!(duplicate
            .validate_consensus_ceremony(Network::Mainnet)
            .unwrap_err()
            .contains("unique non-reserved"));
    }

    #[test]
    fn mainnet_ceremony_rejects_placeholder_duplicate_or_malformed_poa_authorities() {
        let ceremony_addresses = ceremony_tokenomics_addresses();

        let mut placeholder = mainnet_genesis();
        placeholder.tokenomics_addresses = Some(ceremony_addresses);
        assert!(placeholder
            .validate_consensus_ceremony(Network::Mainnet)
            .unwrap_err()
            .contains("placeholder or reserved"));

        let mut duplicate = mainnet_genesis();
        duplicate.tokenomics_addresses = Some(ceremony_addresses);
        for domain in &mut duplicate.bootstrap_domains {
            if domain.kind == "poa" {
                domain.poa_authorities = vec![address(0x91).to_hex(), address(0x91).to_hex()];
            }
        }
        assert!(duplicate
            .validate_consensus_ceremony(Network::Mainnet)
            .unwrap_err()
            .contains("duplicate authority"));

        let mut malformed = mainnet_genesis();
        malformed.tokenomics_addresses = Some(ceremony_addresses);
        for domain in &mut malformed.bootstrap_domains {
            if domain.kind == "poa" {
                domain.poa_authorities = vec!["not-hex".into()];
            }
        }
        assert!(malformed
            .validate_consensus_ceremony(Network::Mainnet)
            .unwrap_err()
            .contains("Invalid PoA authority"));
    }

    #[test]
    fn mainnet_ceremony_rejects_empty_or_incomplete_validator_keys() {
        let ceremony_addresses = ceremony_tokenomics_addresses();
        let mut empty = mainnet_genesis();
        empty.tokenomics_addresses = Some(ceremony_addresses);
        set_valid_poa_authorities(&mut empty);
        assert!(empty
            .validate_consensus_ceremony(Network::Mainnet)
            .unwrap_err()
            .contains("at least four"));

        let mut incomplete = mainnet_genesis();
        incomplete.tokenomics_addresses = Some(ceremony_addresses);
        set_valid_poa_authorities(&mut incomplete);
        incomplete.validators = vec![address(1), address(2), address(3), address(4)];
        assert!(incomplete
            .validate_consensus_ceremony(Network::Mainnet)
            .unwrap_err()
            .contains("complete consensus-key records"));
    }

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
        // Mainnet genesis must be deterministic - same config → same hash
        let cfg = GenesisConfig::for_network(Network::Mainnet);
        let g1 = cfg.build_genesis_block();
        let g2 = cfg.build_genesis_block();
        assert_eq!(g1.hash, g2.hash);
        assert_eq!(g1.chain_id, Network::Mainnet.chain_id().value());
        assert_eq!(g1.hash, g1.calculate_hash());
    }

    #[test]
    fn test_mainnet_genesis_hash_distinct_from_testnet_devnet() {
        // Distinct networks must produce distinct genesis hashes
        let mainnet = GenesisConfig::for_network(Network::Mainnet).build_genesis_block();
        let testnet = GenesisConfig::for_network(Network::Testnet).build_genesis_block();
        let devnet = GenesisConfig::for_network(Network::Devnet).build_genesis_block();
        assert_ne!(mainnet.hash, testnet.hash);
        assert_ne!(mainnet.hash, devnet.hash);
        assert_ne!(testnet.hash, devnet.hash);
    }

    /// Load a checked-in network genesis JSON.
    fn load_genesis_json(relative: &str) -> GenesisConfig {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
        let data = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        serde_json::from_str(&data)
            .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()))
    }

    #[test]
    fn test_mainnet_genesis_params() {
        // Permissionless validators + full $BUD tokenomics.
        let config = mainnet_genesis();
        assert_eq!(config.chain_id, Network::Mainnet.chain_id().value());
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
    fn test_mainnet_bootstrap_domains_materialize_and_validate() {
        let config = mainnet_genesis();
        let domains = config.bootstrap_consensus_domains().unwrap();
        assert_eq!(domains.len(), 4);

        let mut registry = crate::domain::ConsensusDomainRegistry::new();
        for domain in domains {
            registry.register(domain).unwrap();
        }

        assert!(registry.get(1).is_some());
        assert!(registry.get(2).is_some());
        assert!(registry.get(3).is_some());
        let poa = registry.get(4).expect("poa bootstrap domain");
        assert!(!poa.bridge_enabled);
        assert_ne!(poa.validator_set_hash, [0u8; 32]);
    }

    #[test]
    fn test_mainnet_genesis_json_matches_code() {
        // Critical: config/mainnet-genesis.json must equal mainnet_genesis hash.
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

// === MAINNET GENESIS TESTS ===

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

    #[test]
    fn mainnet_genesis_template_is_deterministic_but_not_launchable() {
        let config = mainnet_genesis();
        let first = config.build_genesis_block();
        let second = config.build_genesis_block();
        assert_eq!(first.hash, second.hash);
        assert!(config
            .validate_consensus_ceremony(Network::Mainnet)
            .is_err());
    }
}
