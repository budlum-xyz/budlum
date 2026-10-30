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

/// Post-quantum signature scheme the shipped networks launched with.
///
/// Fixed here rather than read from `crate::crypto::primitives::PQ_SCHEME_ID`:
/// that constant names whatever backend this binary was compiled with, so a
/// genesis built from it follows the build instead of the chain, and the
/// startup comparison in `GenesisConfig::validate_pq_scheme` passes for every
/// build. The shipped `config/*-genesis.json` files declare this same word,
/// and `Blockchain::new_with_genesis` refuses to start a binary built for any
/// other scheme. Custom chains (`GenesisConfig::new`) still record the scheme
/// of the build that created them.
/// Minimum per-header difficulty (leading zero bits) of a mainnet
/// bridge-enabled PoW domain. 2^64 hashes per header is out of reach
/// for a self-mined forgery; the cumulative minimum scales with the
/// confirmation depth.
///
/// Convenience: pub so the bridge finality side can read the same
/// mainnet floor the genesis parameters in this file are built with.
pub const MAINNET_BRIDGE_POW_MIN_DIFFICULTY_BITS: u32 = 64;

const LAUNCHED_PQ_SCHEME: &str = "ml-dsa-65";

/// The domain configuration bootstrapped at genesis.
/// Serialisation-safe (serde); it starts with placeholder addresses and the
/// launch ceremony replaces them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapDomainConfig {
    /// Domain ID (1=PoW, 2=PoS, 3=BFT, 4=PoA).
    pub id: u32,
    /// The consensus kind ("pow", "pos", "bft", "poa").
    pub kind: String,
    /// The finality adapter name (for example "pow-header-chain-v1" or
    /// "pos-qc-finality").
    pub finality_adapter: String,
    /// Bridge enabled (participation in the bridge lifecycle).
    pub bridge_enabled: bool,
    /// The minimum confirmation count (the header-chain depth for PoW).
    pub min_confirmations: u64,
    /// The PoA authority placeholder addresses (only for a PoA domain).
    /// The launch ceremony replaces them with real institutional addresses.
    #[serde(default)]
    pub poa_authorities: Vec<String>,
}

impl BootstrapDomainConfig {
    /// The four-domain bootstrap list for mainnet (PoW, PoS, BFT and PoA
    /// placeholders).
    ///
    /// The PoS and BFT entries are declared bridge-enabled but carry no
    /// validator set (only a PoA entry can name one here), so they register
    /// with a zero `validator_set_hash`. A set-bound finality adapter refuses
    /// every proof for a bridge-enabled domain in that state (see
    /// `reject_unregistered_set_for_bridge`), so until a launch ceremony
    /// registers their sets these two domains finalize nothing. That is the
    /// intended shape of a bridge with no one behind it; the alternative,
    /// letting the proof name its own validator set, would let anyone
    /// finalize a commitment and mint against it.
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
            // PoA domain: placeholder authority adresleri (politika:
            // Start with a placeholder; the launch ceremony turns these into
            // real addresses.
            Self {
                id: 4,
                kind: "poa".to_string(),
                finality_adapter: "poa-authority-quorum".to_string(),
                bridge_enabled: false, // the bridge is off by default for a PoA domain
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

/// The validation reward pool as a genesis parameter, written
/// `"reward_pool": { "enabled": true }` in a ceremony file.
///
/// The flag decides two things at once, and they have to agree: whether
/// genesis moves the pool out of the ecosystem share into the keyless pool
/// account, and whether the epoch transition of the chain pays from it. A
/// chain that funds a pool it never pays from strands 10M BUD; a chain that
/// pays from a pool it never funded would have to mint, which no chain does.
///
/// `None` on `GenesisConfig` means "follow the network profile"
/// ([`crate::core::chain_config::Network::reward_pool`]): testnet on, mainnet
/// and devnet off. Writing the flag explicitly is what makes the choice a
/// recorded genesis parameter rather than a property of the binary that
/// happened to build the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// WIRING: chain surface - the block/snapshot paths that read it land with their wiring.
pub struct GenesisRewardPool {
    /// Whether this chain pays validation rewards from a pre-funded pool.
    pub enabled: bool,
}

impl GenesisRewardPool {
    /// The flag, on.
    #[must_use]
    pub const fn enabled() -> Self {
        Self { enabled: true }
    }

    /// The flag, off.
    #[must_use]
    /// WIRING: chain surface - the block/snapshot paths that read it land with their wiring.
    pub const fn disabled() -> Self {
        Self { enabled: false }
    }
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

    /// Address-only PoA authorities.
    ///
    /// A PoA authority signs with an ordinary Ed25519 key and has no VRF, BLS
    /// or PQ registration, so a plain entry in `validators` lands inactive and
    /// `validate_candidate_chain` replays against an empty authority set and
    /// fails with "No active PoA authorities". Listing the addresses here
    /// seeds them as active stake-1 authorities in `build_state`, so the
    /// genesis state the candidate replay starts from holds the same set the
    /// live node was started with. Ignored on chains that require consensus
    /// keys; ceremony files for PoS chains must keep this empty.
    #[serde(default)]
    pub poa_authorities: Vec<Address>,

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
    /// Registered when storage is empty, which means a new chain. The four
    /// domains PoW, PoS, BFT and PoA are the mainnet default. The default is
    /// empty, for devnet and testnet backward compatibility.
    #[serde(default)]
    pub bootstrap_domains: Vec<BootstrapDomainConfig>,

    /// The PQ anchor key ledger of the ceremony: three
    /// ML-DSA-87 anchor keys across at least two HSM vendors and the Root Seal
    /// keys. A signature names a key by its slot here and carries no public
    /// key. Absent until the anchor key ceremony; a mainnet or testnet node
    /// cannot enter anchor production mode without it, and devnet derives its
    /// own public development ledger (`AnchorEmission::devnet`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_ledger: Option<crate::settlement::AnchorKeyLedger>,

    /// The validation reward pool flag of this chain (testnet item 8).
    ///
    /// `None` follows the network profile, which is what every ceremony file
    /// written before the flag existed means: testnet funds and pays the
    /// default schedule, mainnet and devnet do not. `Some` pins the answer in
    /// genesis, so a chain can refuse a pool its profile would otherwise
    /// provide - and, once mainnet's schedule is decided, take one it
    /// would not. The pool is never minted: it moves out of the ecosystem
    /// share at genesis and the epoch transition pays only its balance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reward_pool: Option<GenesisRewardPool>,
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
            poa_authorities: Vec::new(),
            anchor_ledger: None,
            reward_pool: None,
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

                // The default PoW floor (8 bits, about 1.5k hashes
                // for six headers) lets anyone mine a "finalized" header
                // chain for a bridge-enabled domain. On mainnet the floor is
                // raised to a work level that is not self-mineable.
                if domain.bridge_enabled && self.chain_id == Network::Mainnet.chain_id().value() {
                    if let Some(params) = domain.pow_parameters.as_mut() {
                        params.min_difficulty_bits = MAINNET_BRIDGE_POW_MIN_DIFFICULTY_BITS;
                        params.min_cumulative_work = u128::from(cfg.min_confirmations.max(1))
                            .saturating_mul(1u128 << MAINNET_BRIDGE_POW_MIN_DIFFICULTY_BITS);
                    }
                }

                let poa_authorities: Vec<String> =
                    if matches!(domain.kind, crate::domain::ConsensusKind::PoA)
                        && cfg.poa_authorities.is_empty()
                        && !self.poa_authorities.is_empty()
                    {
                        self.poa_authorities
                            .iter()
                            .map(|address| address.to_hex())
                            .collect()
                    } else {
                        cfg.poa_authorities.clone()
                    };
                if matches!(domain.kind, crate::domain::ConsensusKind::PoA)
                    && !poa_authorities.is_empty()
                {
                    let mut entries = Vec::with_capacity(poa_authorities.len());
                    for authority in &poa_authorities {
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
    /// Deliberately fail-closed. The alternative, starting anyway, produces a
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

    /// Everything `build_state` credits to balances at genesis - the plain
    /// allocations and the tokenomics distribution - stays within the fixed
    /// supply. Validator stake is a bond, not a balance credit.
    ///
    /// Each part was checked alone, so a ceremony could pass every check and
    /// still seed more than `BUD_TOTAL_SUPPLY`.
    ///
    /// # Errors
    ///
    /// Names the total that would be minted and the supply it exceeds.
    ///
    /// Convenience: pub so ceremony tooling can run the whole-issuance
    /// check on its own; in-tree `validate_consensus_ceremony` calls it.
    pub fn validate_total_issuance(&self) -> Result<(), String> {
        let allocations: u128 = self.allocations.iter().map(|(_, a)| u128::from(*a)).sum();
        let distribution = self
            .bud_tokenomics
            .as_ref()
            .map_or(0, |params| u128::from(params.total()));
        // Genesis validator stake is supply too. With a tokenomics
        // distribution it is drawn from the ecosystem share (`build_state`),
        // which therefore has to cover it; without one it adds to the total.
        let stake = u128::from(self.genesis_stake_total());
        let total = match &self.bud_tokenomics {
            Some(params) => {
                let pool = u128::from(self.genesis_reward_pool());
                if stake + pool > u128::from(params.ecosystem) {
                    return Err(format!(
                        "Genesis validator stake {stake} and reward pool {pool} exceed the ecosystem share {} they are drawn from",
                        params.ecosystem
                    ));
                }
                allocations + distribution
            }
            None => allocations + distribution + stake,
        };
        if total > u128::from(crate::tokenomics::BUD_TOTAL_SUPPLY) {
            return Err(format!(
                "Genesis mints {total} base units, above the fixed supply of {}",
                crate::tokenomics::BUD_TOTAL_SUPPLY
            ));
        }
        Ok(())
    }

    /// The `bud_tokenomics` distribution, if present, sums to the fixed
    /// supply, and its team vesting is at least as long as its cliff.
    ///
    /// `build_state` seeds nothing for a genesis that fails the supply check,
    /// so a chain built on one would run with an empty distribution; every
    /// path that builds a chain checks it first, next to the PQ scheme check.
    ///
    /// # Errors
    ///
    /// Names the sum and the supply it should have been, or the vesting and
    /// the cliff it falls short of.
    pub fn validate_tokenomics_supply(&self) -> Result<(), String> {
        if let Some(params) = &self.bud_tokenomics {
            if !params.is_balanced() {
                return Err(format!(
                    "Genesis bud_tokenomics allocations sum to {} base units, not the fixed supply of {}",
                    params.total(),
                    crate::tokenomics::BUD_TOTAL_SUPPLY
                ));
            }
            // The team schedule unlocks linearly from genesis over
            // `team_vesting_epochs` and pays nothing before the cliff. A
            // duration shorter than the cliff would unlock the whole
            // allocation the moment the cliff ends, which is a cliff without
            // a schedule; it is refused rather than read as one.
            if params.team_vesting_epochs != 0
                && params.team_vesting_epochs < params.team_cliff_epochs
            {
                return Err(format!(
                    "Genesis bud_tokenomics team vesting of {} epochs is shorter than its cliff of {} epochs",
                    params.team_vesting_epochs, params.team_cliff_epochs
                ));
            }
            // Zero `epochs_per_year` cannot express a calendar. The reward
            // path clamps with `.max(1)` and would pay the whole annual
            // yield every epoch; `TimedBurnState::due_years` returns 0 for
            // it and silently skips the timed reserve burn. Refuse the
            // configuration at the genesis boundary instead.
            if params.epochs_per_year == 0 {
                return Err("Genesis bud_tokenomics epochs_per_year must be non-zero".into());
            }
            // A burn ratio above 100% burns more than the fee or the reserve.
            // The executor then refuses every block that carries a fee.
            let scale = crate::core::chain_config::FIXED_POINT_SCALE;
            if params.tx_fee_burn_ratio_fixed > scale {
                return Err(format!(
                    "Genesis bud_tokenomics tx_fee_burn_ratio_fixed {} is above the scale {scale}",
                    params.tx_fee_burn_ratio_fixed
                ));
            }
            if params.annual_burn_ratio_fixed > scale {
                return Err(format!(
                    "Genesis bud_tokenomics annual_burn_ratio_fixed {} is above the scale {scale}",
                    params.annual_burn_ratio_fixed
                ));
            }
            // The third ratio too. A yield above 100%
            // per year can never be paid from the schedule and was not
            // checked here at all.
            if params.validator_annual_yield_ratio_fixed > scale {
                return Err(format!(
                    "Genesis bud_tokenomics validator_annual_yield_ratio_fixed {} is above the scale {scale}",
                    params.validator_annual_yield_ratio_fixed
                ));
            }
        }
        Ok(())
    }

    /// Whether this chain pays validation rewards from a pre-funded pool
    /// (testnet item 8).
    ///
    /// The genesis flag when the ceremony file states one, otherwise the
    /// network profile. This is the single answer genesis uses for both the
    /// pool funding and the epoch-transition gate, so the two can never
    /// disagree.
    #[must_use]
    pub fn reward_pool_enabled(&self) -> bool {
        match self.reward_pool {
            Some(flag) => flag.enabled,
            None => crate::core::chain_config::reward_pool_for_chain_id(self.chain_id).is_some(),
        }
    }

    /// The reward pool flag is consistent with the chain it is written into.
    ///
    /// A mainnet genesis may not turn the pool on: there is no mainnet
    /// schedule yet ( is Ayaz's), and a flag with no schedule would fund
    /// nothing while telling operators the pool is live. Refusing names the
    /// owner instead of failing later as an empty epoch payout.
    /// WIRING: chain surface - the block/snapshot paths that read it land with their wiring.
    pub fn validate_reward_pool_flag(&self) -> Result<(), String> {
        let Some(flag) = self.reward_pool else {
            return Ok(());
        };
        if !flag.enabled {
            return Ok(());
        }
        let expected = crate::core::chain_config::reward_pool_for_chain_id(self.chain_id);
        if expected.is_none() {
            let network = crate::core::chain_config::Network::from_chain_id(self.chain_id);
            return Err(format!(
                "Genesis reward_pool.enabled is true on {:?} (chain {}), which has no reward-pool schedule in \
                 the binary; a mainnet schedule is Ayaz's decision (D-04)",
                network, self.chain_id
            ));
        }
        Ok(())
    }

    /// The anchor key ledger, when genesis carries one, is well formed and is
    /// the ledger of this chain. Absence is allowed here: the ledger
    /// arrives with the anchor key ceremony, and production anchoring refuses
    /// to start without it.
    /// WIRING: chain surface - the block/snapshot paths that read it land with their wiring.
    pub fn validate_anchor_ledger(&self) -> Result<(), String> {
        let Some(ledger) = &self.anchor_ledger else {
            return Ok(());
        };
        if ledger.chain_id != self.chain_id {
            return Err(format!(
                "Genesis anchor ledger is for chain {}, this genesis is chain {}",
                ledger.chain_id, self.chain_id
            ));
        }
        ledger
            .validate()
            .map_err(|e| format!("Genesis anchor ledger refused: {e}"))
    }

    pub fn validate_consensus_ceremony(&self, network: Network) -> Result<(), String> {
        self.validate_pq_scheme()?;
        self.validate_anchor_ledger()?;
        self.validate_reward_pool_flag()?;
        if self.chain_id != network.chain_id().value() {
            return Err(format!(
                "Genesis chain ID {} does not match {} profile chain ID {}",
                self.chain_id,
                network,
                network.chain_id()
            ));
        }
        if let Some(params) = &self.bud_tokenomics {
            if params.block_reward != self.block_reward {
                return Err(format!(
                    "Genesis block_reward {} disagrees with bud_tokenomics.block_reward {}",
                    self.block_reward, params.block_reward
                ));
            }
        }
        self.validate_tokenomics_supply()?;
        self.validate_total_issuance()?;
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
            self.validate_mainnet_pow_parameters()?;
        }
        // The testnet is the mainnet rehearsal: the same validator ceremony.
        if matches!(network, Network::Mainnet | Network::Testnet) {
            if self.validators.len() < 4 {
                return Err(format!(
                    "{network} genesis requires at least four ceremony validators (3f+1)"
                ));
            }
            if registered.len() != self.validators.len() {
                return Err(format!(
                    "{network} genesis has {} validators but only {} complete consensus-key records",
                    self.validators.len(),
                    registered.len()
                ));
            }
        }
        Ok(())
    }

    fn validate_mainnet_pow_parameters(&self) -> Result<(), String> {
        let pow_domains: Vec<&BootstrapDomainConfig> = self
            .bootstrap_domains
            .iter()
            .filter(|domain| domain.kind == "pow")
            .collect();
        for domain in pow_domains {
            if domain.bridge_enabled && domain.min_confirmations == 0 {
                return Err(format!(
                    "Mainnet bridge-enabled PoW domain {} requires min_confirmations >= 1",
                    domain.id
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
            if !self.poa_authorities.is_empty() {
                let declared: std::collections::BTreeSet<Address> =
                    self.poa_authorities.iter().copied().collect();
                if declared != unique {
                    return Err(format!(
                        "Mainnet PoA domain {} authorities disagree with top-level poa_authorities",
                        domain.id
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
            producer_public_key: Vec::new(),
            chain_id: self.chain_id,
            slashing_evidence: None,
            slashing_reports: None,
            state_root: genesis_state.calculate_state_root(),
            tx_root: "0".repeat(64),
            epoch: 0,
            slot: 0,
            vrf_output: Vec::new(),
            vrf_proof: Vec::new(),
            validator_set_hash,
            storage_root: None,
            shards_root: None,
            witness_root: None,
        };

        block.tx_root = block.calculate_tx_root();
        block.hash = block.calculate_hash();
        block
    }

    pub fn build_state(&self) -> AccountState {
        let mut state = AccountState::new();
        // TESTNET-DEFAULT: fee rates belong to genesis state, not
        // a node-local config overlay, so every testnet replay commits the same
        // economic profile. Mainnet and development chains keep their explicit
        // zero-rate defaults until their own genesis decisions land.
        if self.chain_id == Network::Testnet.chain_id().value() {
            state
                .registry
                .set_params(crate::registry::RegistryParams::testnet_defaults());
        }
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
                            && entry.verify_pop_is_valid(self.chain_id);
                    }
                }
            }
        }

        // Seed the PoA onboarding trust root from the
        // ceremony-declared bootstrap PoA domain authorities when top-level
        // `poa_authorities` is empty, keeping `poa_authorities` as an explicit
        // override for custom chains that declare no bootstrap PoA domain.
        let declared: Vec<Address> = if self.poa_authorities.is_empty() {
            self.bootstrap_domains
                .iter()
                .find(|domain| domain.kind == "poa")
                .map(|domain| {
                    domain
                        .poa_authorities
                        .iter()
                        .filter_map(|authority| Address::from_hex(authority).ok())
                        .collect()
                })
                .unwrap_or_default()
        } else {
            self.poa_authorities.clone()
        };
        // Address-only PoA authorities: active stake-1 entries with
        // no consensus keys. Bootstrap-domain authorities must enter the same
        // consensus state as top-level authorities; otherwise a restart has
        // an authority hash but no producer set to replay against.
        for authority in &declared {
            state.ensure_validator(*authority, 1);
            if let Some(entry) = state.get_validator_mut(authority) {
                entry.active = true;
                entry.slashed = false;
            }
        }
        if let Some((admin, rest)) = declared.split_first() {
            // A bootstrap domain owns its own admission namespace. Domain 0 is
            // retained only for custom genesis configurations without a PoA
            // bootstrap record.
            let poa_domain = self
                .bootstrap_domains
                .iter()
                .find(|domain| domain.kind == "poa")
                .map_or(0, |domain| domain.id);
            const GENESIS_KYC_COMMITMENT: [u8; 32] = [0x01; 32];
            state.poa_onboarding.add_admin(poa_domain, *admin);
            for authority in std::iter::once(admin).chain(rest.iter()) {
                // Both steps cannot refuse on a fresh registry (a distinct
                // address, a non-zero commitment, a horizon at the ceiling);
                // a refusal here would leave the authority un-admitted and
                // the chain would fail closed at its first block.
                let _ = state.poa_onboarding.submit_application(
                    poa_domain,
                    *authority,
                    GENESIS_KYC_COMMITMENT,
                    0,
                );
                let _ = state.poa_onboarding.approve(
                    poa_domain,
                    *admin,
                    *authority,
                    0,
                    crate::registry::poa_onboarding::MAX_KYC_VALIDITY_HORIZON,
                );
            }
            state.refresh_poa_admissions(0);
        }

        // $BUD tokenomics: seed the distribution accounts and configure
        // The on-chain burn-reserve address + team vesting so the timed burn and
        // Vesting enforcement operate on the real chain state.
        if let Some(params) = &self.bud_tokenomics {
            // The tokenomics struct is the committed economic parameter set,
            // so it also decides `block_reward`; the top-level field only
            // serves chains without `bud_tokenomics`. A disagreement between
            // the two is rejected by `validate_consensus_ceremony`.
            state.tokenomics = *params;
            if let Some(addrs) = self.tokenomics_destinations() {
                // An unbalanced distribution is refused by
                // `validate_consensus_ceremony` before any chain is built on
                // this genesis; a configuration that reaches this point
                // unchecked seeds nothing rather than a wrong supply.
                if let Ok(allocations) = crate::tokenomics::genesis_allocations(params, &addrs) {
                    for (address, amount) in allocations {
                        state.add_balance(&address, amount);
                    }
                    // The genesis validators' stake comes out of the
                    // ecosystem share, so the genesis holds exactly the
                    // fixed supply (`validate_total_issuance` checks the
                    // share covers it).
                    let stake = self.genesis_stake_total();
                    if stake > 0 {
                        let ecosystem = state.get_or_create(&addrs.ecosystem);
                        ecosystem.balance = ecosystem.balance.saturating_sub(stake);
                        state.mark_dirty(&addrs.ecosystem);
                    }
                    // The validation reward pool also comes out of the
                    // ecosystem share, into the keyless pool account the
                    // epoch transition pays from.
                    let pool = self.genesis_reward_pool();
                    if pool > 0 {
                        let ecosystem = state.get_or_create(&addrs.ecosystem);
                        ecosystem.balance = ecosystem.balance.saturating_sub(pool);
                        state.mark_dirty(&addrs.ecosystem);
                        state.add_balance(
                            &crate::tokenomics::reward_pool::reward_pool_account(),
                            pool,
                        );
                    }
                    state.burn_reserve_address = Some(addrs.burn_reserve);
                    state.team_vesting = Some((addrs.team, params.team_vesting(0)));
                }
            }
        }

        // The bootstrap consensus domains are genesis state, written into
        // the settlement registry here and nowhere else (
        //): every node that builds this genesis holds the same domains,
        // and a restart replays them instead of rewriting their status. A PoA
        // domain with a ceremony authority set is ready at genesis; a PoA
        // domain without one starts frozen and opens only through governance,
        // in block. A configuration the bootstrap builder refuses is refused
        // at chain construction, before this state is used.
        if let Ok(domains) = self.bootstrap_consensus_domains() {
            for domain in domains {
                let id = domain.id;
                let poa = matches!(domain.kind, crate::domain::ConsensusKind::PoA);
                let poa_ready = poa && !declared.is_empty();
                if crate::settlement::domains::register_domain(&mut state, domain).is_ok()
                    && poa
                    && !poa_ready
                {
                    let _ = state
                        .settlement
                        .domains
                        .transition_status_checked(id, crate::domain::DomainStatus::Frozen);
                }
            }
        }

        // testnet item 8: the same answer genesis funded the pool with is the
        // one the epoch transition reads, recorded in consensus state so a
        // replay, a snapshot restore and a peer all gate identically.
        state.reward_pool_enabled = self.reward_pool_enabled();
        state
    }

    /// The $BUD distribution destinations this genesis seeds. Development
    /// chains fall back to the reserved marker addresses. Mainnet accepts only
    /// ceremony-controlled addresses, so a mainnet genesis without them seeds
    /// no distribution at all instead of committing marker accounts into the
    /// state root.
    fn tokenomics_destinations(&self) -> Option<crate::tokenomics::TokenomicsAddresses> {
        if self.tokenomics_addresses.is_some() {
            return self.tokenomics_addresses;
        }
        if Network::from_chain_id(self.chain_id) == Some(Network::Mainnet) {
            return None;
        }
        Some(crate::tokenomics::TokenomicsAddresses::reserved())
    }

    /// The stake every genesis validator is bonded with.
    ///
    /// At least one whole BUD, the smallest bond `bud validator join` can
    /// express (`--stake-bud 1`). A seat bonded at the bare floor and a
    /// joiner bonded at one BUD are not peers: on the devnet the four seats
    /// held 1 000 atoms each against a joiner's 1 000 000, so once the joiner
    /// was eligible it owned 99.6% of the slot lottery and the four founders
    /// - threshold 0.1% each - stopped producing. A seat is sized in the same
    /// unit the join path uses.
    fn validator_stake(&self) -> u64 {
        Network::from_chain_id(self.chain_id).map_or(1, |network| {
            network.min_stake().max(crate::tokenomics::bud(1))
        })
    }

    /// The validation reward pool the profile funds at genesis; 0 without one
    /// or with an invalid schedule.
    fn genesis_reward_pool(&self) -> u64 {
        if !self.reward_pool_enabled() {
            return 0;
        }
        crate::core::chain_config::reward_pool_for_chain_id(self.chain_id)
            .filter(|schedule| schedule.validate().is_ok())
            .map_or(0, |schedule| schedule.validation_reward_pool)
    }

    /// The stake every genesis validator is bonded with, summed.
    fn genesis_stake_total(&self) -> u64 {
        u64::try_from(self.validators.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(self.validator_stake())
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
    let tokenomics = mainnet_tokenomics();
    mainnet_genesis_with(tokenomics)
}

/// The mainnet economic parameters: the 100M fixed-supply distribution, the
/// burns, the team schedule and the reward settings on the mainnet calendar.
/// WIRING: chain surface - the block/snapshot paths that read it land with their wiring.
pub fn mainnet_tokenomics() -> crate::tokenomics::TokenomicsParams {
    use crate::core::chain_config::FIXED_POINT_SCALE;
    use crate::tokenomics::bud;

    // Full tokenomics params - 100M fixed supply
    crate::tokenomics::TokenomicsParams {
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
        // The tokenomics epoch is the consensus epoch: 6 s slots, 100 slots,
        // 600 s, so `epochs_per_year` (52 560) is a calendar year.
        slot_duration_secs: 6,
        epoch_length_slots: 100,
    }
}

fn mainnet_genesis_with(tokenomics: crate::tokenomics::TokenomicsParams) -> GenesisConfig {
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
        // PoA: placeholder authorities (the launch ceremony turns these into
        // real addresses).
        pq_scheme: Some(LAUNCHED_PQ_SCHEME.to_string()),
        bootstrap_domains: BootstrapDomainConfig::mainnet_defaults(),
        poa_authorities: Vec::new(),
        anchor_ledger: None,
        // mainnet: no pool until Ayaz fixes the schedule. The flag is
        // written rather than left to default so the ceremony file states the
        // decision, and a mainnet genesis asking for the pool is refused by
        // `validate_reward_pool_flag` instead of quietly minting nothing.
        reward_pool: Some(GenesisRewardPool::disabled()),
    }
}

/// The testnet ceremony template.
///
/// The testnet is the mainnet rehearsal: the same 100M distribution, the
/// same validator ceremony (at least four validators with complete consensus
/// keys, `validate_consensus_ceremony`), on the testnet calendar (3 s slots,
/// 50-slot epochs). The template holds no validator and no destination: the
/// ceremony (`cargo run --manifest-path xtask/tools/Cargo.toml --
/// testnet-genesis`) fills both from the operators' public records and
/// writes the launch file. A node refuses the template itself, which has no
/// validators.
pub fn testnet_genesis() -> GenesisConfig {
    let tokenomics = testnet_tokenomics();
    GenesisConfig {
        chain_id: Network::Testnet.chain_id().value(),
        allocations: vec![],
        validators: vec![],
        validator_consensus_keys: vec![],
        block_reward: tokenomics.block_reward,
        base_fee: Network::Testnet.gas_schedule().base_fee,
        gas_schedule: Network::Testnet.gas_schedule(),
        timestamp: 1_735_689_600_000,
        bud_tokenomics: Some(tokenomics),
        tokenomics_addresses: None,
        pq_scheme: Some(LAUNCHED_PQ_SCHEME.to_string()),
        bootstrap_domains: vec![],
        poa_authorities: Vec::new(),
        anchor_ledger: None,
        // testnet: the reward pool is on, and genesis says so.
        reward_pool: Some(GenesisRewardPool::enabled()),
    }
}

/// The mainnet distribution on the testnet calendar: 3 s slots and 50-slot
/// epochs make a 150 s epoch, so 210 240 epochs are a calendar year. Testnet
/// block emission remains disabled; the compatibility field is zero.
/// TESTNET-DEFAULT: every economic value equals the mainnet template's.
/// WIRING: chain surface - the block/snapshot paths that read it land with their wiring.
pub fn testnet_tokenomics() -> crate::tokenomics::TokenomicsParams {
    const EPOCHS_PER_YEAR: u64 = 210_240;
    let mut params = mainnet_tokenomics();
    params.epochs_per_year = EPOCHS_PER_YEAR;
    params.team_cliff_epochs = EPOCHS_PER_YEAR;
    params.team_vesting_epochs = EPOCHS_PER_YEAR.saturating_mul(4);
    params.slot_duration_secs = 3;
    params.epoch_length_slots = 50;
    // TESTNET-DEFAULT: block execution does not mint emission; the field is
    // retained only for snapshot/wire compatibility and must not advertise a
    // live reward on the testnet template.
    params.block_reward = 0;
    params
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
        pq_scheme: Some(LAUNCHED_PQ_SCHEME.to_string()),
        bootstrap_domains: vec![],
        poa_authorities: Vec::new(),
        anchor_ledger: None,
        // devnet: no distribution to fund a pool from.
        reward_pool: Some(GenesisRewardPool::disabled()),
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
    fn mainnet_state_never_seeds_reserved_marker_addresses() {
        let reserved = crate::tokenomics::TokenomicsAddresses::reserved();

        // The template has no ceremony addresses: nothing is credited and the
        // marker accounts stay out of the state root.
        let template = mainnet_genesis();
        let state = template.build_state();
        assert_eq!(state.get_balance(&reserved.community), 0);
        assert_eq!(state.get_balance(&reserved.burn_reserve), 0);
        assert_eq!(state.burn_reserve_address, None);
        assert!(state.team_vesting.is_none());
        assert_eq!(state.circulating_supply(), 0);
        assert_eq!(
            state.tokenomics,
            template
                .bud_tokenomics
                .expect("mainnet template tokenomics")
        );

        // Ceremony addresses are seeded exactly as configured.
        let mut ceremony = mainnet_genesis();
        let addresses = ceremony_tokenomics_addresses();
        ceremony.tokenomics_addresses = Some(addresses);
        let seeded = ceremony.build_state();
        assert_eq!(
            seeded.circulating_supply(),
            u128::from(crate::tokenomics::BUD_TOTAL_SUPPLY)
        );
        assert_eq!(seeded.burn_reserve_address, Some(addresses.burn_reserve));
        assert_eq!(seeded.get_balance(&reserved.community), 0);

        // Development chains keep the reserved fallback.
        let devnet = GenesisConfig::new(Network::Devnet.chain_id().value()).with_bud_tokenomics();
        let dev_state = devnet.build_state();
        assert_eq!(dev_state.burn_reserve_address, Some(reserved.burn_reserve));
        assert_eq!(
            dev_state.circulating_supply(),
            u128::from(crate::tokenomics::BUD_TOTAL_SUPPLY)
        );
    }

    /// An unbalanced distribution is refused by the ceremony check and seeds
    /// nothing in `build_state`, so it can never become a chain with a
    /// supply other than the fixed one.
    #[test]
    fn an_unbalanced_tokenomics_is_refused_and_seeds_nothing() {
        let mut config = mainnet_genesis();
        config.tokenomics_addresses = Some(ceremony_tokenomics_addresses());
        let mut params = config.bud_tokenomics.expect("tokenomics");
        params.community += 1;
        config.bud_tokenomics = Some(params);
        let error = config
            .validate_tokenomics_supply()
            .expect_err("an unbalanced distribution must be refused");
        assert!(error.contains("not the fixed supply"), "{error}");
        assert!(config
            .validate_consensus_ceremony(Network::Mainnet)
            .is_err());
        assert_eq!(config.build_state().circulating_supply(), 0);
        assert_eq!(config.build_state().burn_reserve_address, None);
    }

    /// A ceremony whose plain allocations come on top of a balanced
    /// distribution mints more than the fixed supply and is refused.
    #[test]
    fn a_genesis_minting_above_the_fixed_supply_is_refused() {
        let mut config = mainnet_genesis();
        config.tokenomics_addresses = Some(ceremony_tokenomics_addresses());
        assert!(config.validate_total_issuance().is_ok());
        config.allocations.push((address(0x77), 1));
        let error = config
            .validate_total_issuance()
            .expect_err("an over-supply genesis must be refused");
        assert!(error.contains("above the fixed supply"), "{error}");
        assert!(config
            .validate_consensus_ceremony(Network::Mainnet)
            .is_err());
    }

    /// A team vesting shorter than its cliff is a cliff without a schedule:
    /// the ceremony refuses it instead of unlocking the allocation at once.
    #[test]
    fn a_team_vesting_shorter_than_its_cliff_is_refused() {
        let mut config = mainnet_genesis();
        config.tokenomics_addresses = Some(ceremony_tokenomics_addresses());
        let mut params = config.bud_tokenomics.expect("tokenomics");
        params.team_vesting_epochs = params.team_cliff_epochs - 1;
        config.bud_tokenomics = Some(params);
        let error = config
            .validate_tokenomics_supply()
            .expect_err("a vesting shorter than its cliff must be refused");
        assert!(error.contains("shorter than its cliff"), "{error}");
        assert!(config
            .validate_consensus_ceremony(Network::Mainnet)
            .is_err());

        // Zero duration is the no-schedule case and still unlocks at the
        // cliff, so it stays accepted.
        params.team_vesting_epochs = 0;
        config.bud_tokenomics = Some(params);
        assert!(config.validate_tokenomics_supply().is_ok());
    }

    /// A burn ratio above the fixed-point scale burns more than the
    /// fee. The executor then refuses every block that has a transaction.
    #[test]
    fn burn_ratio_above_the_scale_is_refused_at_genesis() {
        use crate::core::chain_config::FIXED_POINT_SCALE;
        let mut config = mainnet_genesis();
        config.tokenomics_addresses = Some(ceremony_tokenomics_addresses());
        let params = config.bud_tokenomics.expect("tokenomics");

        let mut fee_ratio = params;
        fee_ratio.tx_fee_burn_ratio_fixed = FIXED_POINT_SCALE + 1;
        config.bud_tokenomics = Some(fee_ratio);
        let error = config
            .validate_tokenomics_supply()
            .expect_err("a fee burn ratio above 100% must be refused");
        assert!(error.contains("tx_fee_burn_ratio_fixed"), "{error}");

        let mut annual_ratio = params;
        annual_ratio.annual_burn_ratio_fixed = FIXED_POINT_SCALE + 1;
        config.bud_tokenomics = Some(annual_ratio);
        let error = config
            .validate_tokenomics_supply()
            .expect_err("an annual burn ratio above 100% must be refused");
        assert!(error.contains("annual_burn_ratio_fixed"), "{error}");
    }

    /// Zero `epochs_per_year` cannot reach the burn or reward math: the
    /// ceremony refuses it at the genesis boundary.
    #[test]
    fn zero_epochs_per_year_is_refused_at_genesis() {
        let mut config = mainnet_genesis();
        config.tokenomics_addresses = Some(ceremony_tokenomics_addresses());
        let mut params = config.bud_tokenomics.expect("tokenomics");
        params.epochs_per_year = 0;
        config.bud_tokenomics = Some(params);
        let error = config
            .validate_tokenomics_supply()
            .expect_err("zero epochs_per_year must be refused");
        assert!(
            error.contains("epochs_per_year must be non-zero"),
            "{error}"
        );
        assert!(config
            .validate_consensus_ceremony(Network::Mainnet)
            .is_err());
    }

    #[test]
    fn ceremony_rejects_block_reward_disagreement() {
        let mut config = mainnet_genesis();
        config.tokenomics_addresses = Some(ceremony_tokenomics_addresses());
        config.block_reward = config.bud_tokenomics.expect("tokenomics").block_reward + 1;
        let error = config
            .validate_consensus_ceremony(Network::Mainnet)
            .unwrap_err();
        assert!(error.contains("disagrees with bud_tokenomics.block_reward"));

        // The committed value is the tokenomics one, never the stray field.
        assert_eq!(
            config.build_state().tokenomics.block_reward,
            config.bud_tokenomics.expect("tokenomics").block_reward
        );
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

    /// The `docker-smoke-mainnet` tool (`xtask/tools`) pins the devnet genesis hash and
    /// refuses to boot when the image disagrees with it. The pin has to move
    /// with `devnet_genesis()`: when this test fails, update
    /// `DEVNET_GENESIS_HASH` in `xtask/tools/src/docker_smoke.rs` in the same change. The pinned
    /// value is the hash the docker-smoke job itself printed at head
    /// `25f0583` (run 34156887325).
    #[test]
    fn devnet_genesis_hash_matches_the_docker_smoke_pin() {
        let block = devnet_genesis().build_genesis_block();
        assert_eq!(
            block.hash, "ba194aa08eb23a094c04cc1f005266e43f961aa2d8fd127f91cfec1c9f262484",
            "the pin in xtask/tools/src/docker_smoke.rs must move with devnet_genesis()"
        );
    }

    /// A genesis that lists PoA authorities declares the
    /// admission gate; an outsider with stake is not in the admitted set.
    #[test]
    fn genesis_poa_authorities_open_the_admission_gate() {
        let a = Address::from_hex(&"a1".repeat(32)).unwrap();
        let b = Address::from_hex(&"b2".repeat(32)).unwrap();
        let outsider = Address::from_hex(&"c3".repeat(32)).unwrap();
        let mut config = GenesisConfig::new(4242);
        config.poa_authorities = vec![a, b];
        let state = config.build_state();
        assert!(state.poa_is_permissioned(0), "the gate must be declared");
        let admitted = state.poa_admitted_addresses(0);
        assert!(admitted.contains(&a) && admitted.contains(&b));
        assert!(!admitted.contains(&outsider));
        // No authorities listed: the chain stays ungated, as before.
        assert!(!GenesisConfig::new(4242)
            .build_state()
            .poa_is_permissioned(0));
    }

    #[test]
    fn test_network_genesis_configs_are_distinct() {
        let mainnet = GenesisConfig::for_network(Network::Mainnet);
        let testnet = GenesisConfig::for_network(Network::Testnet);
        let devnet = GenesisConfig::for_network(Network::Devnet);

        assert_ne!(mainnet.chain_id, testnet.chain_id);
        assert_ne!(mainnet.chain_id, devnet.chain_id);
        // Mainnet and its testnet rehearsal use the full tokenomics; devnet
        // does not.
        assert!(mainnet.bud_tokenomics.is_some());
        assert!(testnet.bud_tokenomics.is_some());
        assert!(devnet.bud_tokenomics.is_none());
        // Mainnet and testnet are ceremony templates (no validators); devnet
        // seeds one.
        assert!(mainnet.validators.is_empty());
        assert!(testnet.validators.is_empty());
        assert!(!devnet.validators.is_empty());
        assert_ne!(mainnet.gas_schedule, testnet.gas_schedule);
        assert_ne!(mainnet.gas_schedule, devnet.gas_schedule);
    }

    #[test]
    fn testnet_genesis_commits_the_published_fee_profile() {
        let testnet = GenesisConfig::for_network(Network::Testnet).build_state();
        let params = testnet.registry.params();
        assert_eq!(params.transfer_fee_ppm, 200);
        assert_eq!(params.swap_fee_ppm, 400);
        assert_eq!(params.bridge_fee_ppm, 800);
        assert_eq!(params.app_fee_share_ppm, 400_000);

        let devnet = GenesisConfig::for_network(Network::Devnet).build_state();
        assert_eq!(
            devnet.registry.params(),
            &crate::registry::RegistryParams::default()
        );
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
        // A seat is one whole BUD even where the floor is lower: see
        // `validator_stake`. The devnet floor is 1 000 atoms.
        assert_eq!(
            state.get_validator(&validator).map(|v| v.stake),
            Some(crate::tokenomics::bud(1))
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

    /// The mainnet bridge-enabled PoW domain must not keep the
    /// 8-bit default floor.
    #[test]
    fn mainnet_bridge_pow_domain_has_a_non_trivial_difficulty_floor() {
        let config = mainnet_genesis();
        let domains = config.bootstrap_consensus_domains().unwrap();
        let pow = domains
            .iter()
            .find(|d| d.bridge_enabled && d.pow_parameters.is_some())
            .expect("mainnet has a bridge-enabled PoW domain");
        let params = pow.pow_parameters.as_ref().unwrap();
        assert_eq!(
            params.min_difficulty_bits,
            MAINNET_BRIDGE_POW_MIN_DIFFICULTY_BITS
        );
        assert!(params.min_cumulative_work >= 6u128 << 64);
        assert!(params.validate(pow.min_confirmations).is_ok());
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

        // The PoS and BFT placeholders ship bridge-enabled with no validator
        // set. Until a ceremony registers one, a proof that names its own
        // set must not finalize on them: the adapter refuses before it
        // looks at the certificate.
        use crate::domain::{DomainFinalityAdapter, FinalityProof, FinalityStatus};
        let snapshot = crate::chain::finality::ValidatorSetSnapshot::new(0, vec![]);
        for (id, kind) in [(2u32, "PoS"), (3u32, "BFT")] {
            let domain = registry.get(id).expect("bootstrap domain");
            assert!(domain.bridge_enabled);
            assert_eq!(domain.validator_set_hash, [0u8; 32]);
            let commitment = crate::domain::DomainCommitment {
                domain_id: domain.id,
                domain_height: 1,
                domain_block_hash: [9u8; 32],
                parent_domain_block_hash: [0u8; 32],
                state_root: [1u8; 32],
                tx_root: [2u8; 32],
                event_root: [3u8; 32],
                finality_proof_hash: [0u8; 32],
                consensus_kind: domain.kind.clone(),
                validator_set_hash: [0u8; 32],
                timestamp_ms: 0,
                sequence: 0,
                producer: None,
                state_updates: std::collections::BTreeMap::new(),
            };
            let cert = crate::chain::finality::FinalityCert {
                epoch: 0,
                checkpoint_height: 1,
                checkpoint_hash: hex::encode(commitment.domain_block_hash),
                chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
                agg_sig_bls: vec![],
                bitmap: vec![],
                set_hash: snapshot.set_hash.clone(),
            };
            let status = if kind == "PoS" {
                crate::domain::PoSFinalityAdapter.verify_finality(
                    domain,
                    &commitment,
                    &FinalityProof::PoS {
                        cert,
                        validator_snapshot: snapshot.clone(),
                    },
                )
            } else {
                crate::domain::BftFinalityAdapter::default().verify_finality(
                    domain,
                    &commitment,
                    &FinalityProof::Bft {
                        round: 0,
                        commit_hash: commitment.domain_block_hash,
                        cert,
                        validator_snapshot: snapshot.clone(),
                    },
                )
            }
            .expect("verification runs");
            match status {
                FinalityStatus::Rejected(reason) => {
                    assert!(
                        reason.contains("no registered validator set"),
                        "{kind}: {reason}"
                    )
                }
                other => panic!("{kind} placeholder must refuse, got {other:?}"),
            }
        }
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
        // The scheme is the launched one, fixed, not whichever backend this
        // test binary was built with; and the file says the same word.
        assert_eq!(from_code.pq_scheme.as_deref(), Some(LAUNCHED_PQ_SCHEME));
        assert_eq!(from_json.pq_scheme, from_code.pq_scheme);

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
                from_code.pq_scheme.as_deref(),
                Some(LAUNCHED_PQ_SCHEME),
                "{path}"
            );
            assert_eq!(from_json.pq_scheme, from_code.pq_scheme, "{path}");
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

    #[test]
    fn mainnet_genesis_seeds_permissioned_poa_onboarding_gate() {
        let from_json = load_genesis_json("config/mainnet-genesis.json");
        let state = from_json.build_state();
        let poa_domain_id = from_json
            .bootstrap_domains
            .iter()
            .find(|domain| domain.kind == "poa")
            .map(|domain| domain.id)
            .expect("mainnet genesis must declare a PoA bootstrap domain");
        assert!(
            state.poa_is_permissioned(poa_domain_id),
            "mainnet genesis must seed the PoA onboarding gate from bootstrap_domains"
        );
        let expected: std::collections::BTreeSet<Address> = from_json
            .bootstrap_domains
            .iter()
            .find(|d| d.kind == "poa")
            .unwrap()
            .poa_authorities
            .iter()
            .map(|a| Address::from_hex(a).unwrap())
            .collect();
        let admitted: std::collections::BTreeSet<Address> = state
            .poa_admitted_addresses(poa_domain_id)
            .into_iter()
            .collect();
        assert_eq!(admitted, expected);
        assert_eq!(
            state.settlement.domains.get(poa_domain_id).unwrap().status,
            crate::domain::DomainStatus::Active
        );

        let mut mismatch = from_json;
        mismatch.poa_authorities = vec![Address::from([0x22; 32])];
        assert!(mismatch.validate_mainnet_poa_authorities().is_err());
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

    /// testnet item 8: `reward_pool.enabled` is the genesis parameter, and it
    /// decides both halves at once - the funding at genesis and the flag the
    /// epoch transition reads. Testnet states it on, devnet off, mainnet off.
    #[test]
    fn the_reward_pool_flag_is_a_genesis_parameter() {
        let testnet = testnet_genesis();
        assert_eq!(testnet.reward_pool, Some(GenesisRewardPool::enabled()));
        assert!(testnet.reward_pool_enabled());
        assert!(testnet.validate_reward_pool_flag().is_ok());

        let devnet = devnet_genesis();
        assert!(!devnet.reward_pool_enabled());
        assert_eq!(devnet.genesis_reward_pool(), 0);

        let mainnet = mainnet_genesis();
        assert!(!mainnet.reward_pool_enabled());
        assert_eq!(mainnet.genesis_reward_pool(), 0);
    }

    /// The flag is written, not merely read: a ceremony file that leaves it
    /// out follows the profile, and one that turns the pool off keeps both
    /// sides off (no funding, no payments).
    #[test]
    fn turning_the_flag_off_leaves_the_pool_unfunded_and_the_gate_closed() {
        let mut genesis = testnet_genesis();
        genesis.reward_pool = None;
        assert!(
            genesis.reward_pool_enabled(),
            "an absent flag follows the testnet profile"
        );

        genesis.reward_pool = Some(GenesisRewardPool::disabled());
        assert!(!genesis.reward_pool_enabled());
        assert_eq!(genesis.genesis_reward_pool(), 0);
        let state = genesis.build_state();
        assert!(!state.reward_pool_enabled);
        assert_eq!(
            state.get_balance(&crate::tokenomics::reward_pool::reward_pool_account()),
            0
        );

        genesis.reward_pool = Some(GenesisRewardPool::enabled());
        let state = genesis.build_state();
        assert!(state.reward_pool_enabled);
        assert_eq!(
            state.get_balance(&crate::tokenomics::reward_pool::reward_pool_account()),
            crate::tokenomics::reward_pool::DEFAULT_VALIDATION_REWARD_POOL
        );
    }

    /// A mainnet genesis may not turn the pool on: there is no mainnet
    /// schedule yet, and the flag would promise an epoch payment nothing can
    /// make. The refusal names the owner of the decision.
    #[test]
    fn mainnet_refuses_to_turn_the_reward_pool_on() {
        let mut genesis = mainnet_genesis();
        genesis.reward_pool = Some(GenesisRewardPool::enabled());
        let error = genesis
            .validate_reward_pool_flag()
            .expect_err("a mainnet pool has no schedule to pay from");
        assert!(error.contains("D-04"), "error names the decision: {error}");
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
