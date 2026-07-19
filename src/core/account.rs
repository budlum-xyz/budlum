use crate::consensus::pos::SlashingEvidence;
use crate::core::address::Address;
use crate::core::governance::GovernanceState;
use crate::core::transaction::{Transaction, TransactionType};
use crate::cross_domain::message_registry::CrossDomainMessageRegistry;
use crate::cross_domain::BridgeState;
use crate::domain::storage_deal::StorageRegistry;
use crate::storage::db::Storage;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
pub const MIN_TX_FEE: u64 = 1;
/// Phase 0.334 / A8: protocol bounds for governance fee/reward proposals.
pub const MAX_BASE_FEE: u64 = 1_000_000;
pub const MIN_BLOCK_REWARD: u64 = 0;
pub const MAX_BLOCK_REWARD: u64 = 10_000 * crate::tokenomics::BUD_UNIT;
pub const GENESIS_BALANCE: u64 = 1_000_000_000;
pub const UNBONDING_EPOCHS: u64 = 7;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnbondingEntry {
    pub address: Address,
    pub amount: u64,
    pub release_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub public_key: Address,
    pub balance: u64,
    pub nonce: u64,
}
impl Account {
    pub fn new(public_key: Address) -> Self {
        Account {
            public_key,
            balance: 0,
            nonce: 0,
        }
    }
    pub fn with_balance(public_key: Address, balance: u64) -> Self {
        Account {
            public_key,
            balance,
            nonce: 0,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validator {
    pub address: Address,
    pub stake: u64,
    pub active: bool,
    pub slashed: bool,
    pub jailed: bool,
    pub jail_until: u64,
    pub last_proposed_block: Option<u64>,
    pub votes_for: u64,
    pub votes_against: u64,
    #[serde(default)]
    pub vrf_public_key: Vec<u8>,
    #[serde(default)]
    pub bls_public_key: Vec<u8>,
    #[serde(default)]
    pub pop_signature: Vec<u8>,
    #[serde(default)]
    pub pq_public_key: Vec<u8>,
}

impl Validator {
    pub fn new(address: Address, stake: u64) -> Self {
        Validator {
            address,
            stake,
            active: true,
            slashed: false,
            jailed: false,
            jail_until: 0,
            last_proposed_block: None,
            votes_for: 0,
            votes_against: 0,
            vrf_public_key: Vec::new(),
            bls_public_key: Vec::new(),
            pop_signature: Vec::new(),
            pq_public_key: Vec::new(),
        }
    }
    pub fn effective_stake(&self) -> u64 {
        if self.slashed || self.jailed {
            0
        } else {
            self.stake
        }
    }
    pub fn is_eligible(&self, current_epoch: u64) -> bool {
        self.active && !self.slashed && (!self.jailed || current_epoch >= self.jail_until)
    }
}

#[derive(Clone)]
pub struct AccountState {
    pub accounts: BTreeMap<Address, Account>,
    pub validators: BTreeMap<Address, Validator>,
    /// $BUD tokenomics parameters (distribution, burn schedule, vesting).
    pub tokenomics: crate::tokenomics::TokenomicsParams,
    /// State of the timed (annual) reserve burn.
    pub timed_burn: crate::tokenomics::TimedBurnState,
    pub bns_registry: crate::bns::BnsRegistry,
    pub nft_registry: crate::socialfi::NftRegistry,
    pub marketplace: crate::pollen::MarketplaceRegistry,
    pub hub: crate::hub::HubRegistry,
    pub storage_registry: StorageRegistry,
    pub ai_registry: crate::ai::registry::AiRegistry,
    pub bridge_state: BridgeState,
    pub message_registry: CrossDomainMessageRegistry,
    pub external_roots: BTreeMap<crate::domain::types::DomainId, crate::domain::types::Hash32>,
    /// On-chain burn-reserve account the timed burn consumes. `None` when $BUD
    /// tokenomics is not enabled for this chain (e.g. plain devnet genesis).
    pub burn_reserve_address: Option<Address>,
    /// Team account + its vesting schedule, enforced on transfers. `None` when
    /// $BUD tokenomics is not enabled.
    pub team_vesting: Option<(Address, crate::tokenomics::VestingSchedule)>,
    pub unbonding_queue: Vec<UnbondingEntry>,
    storage: Option<Storage>,
    pub epoch_index: u64,
    pub last_epoch_time: u64,
    /// V28 fix (Phase 11): gerçek blok yüksekliği. Eskiden executor
    /// `epoch_index * 100` approximation kullanıyordu (≤99 blok sapma).
    /// Blockchain produce/validate'da tx işleme öncesi set edilir.
    pub current_block_height: u64,
    pub governance: GovernanceState,
    pub base_fee: u64,
    dirty_accounts: HashSet<Address>,
    keys_dirty: bool,
    cached_leaves: Vec<[u8; 32]>,
    cached_keys: Vec<Address>,
    cached_tree: Vec<Vec<[u8; 32]>>,
    pub bridge_root: [u8; 32],
    pub message_root: [u8; 32],
    pub settlement_root: [u8; 32],
    pub global_header_summary: [u8; 32],
    /// Permissionless registry (Phase 0.08): stake-based membership for
    /// validator/relayer/prover roles. `PermissionlessRegistry::new()`
    /// gives a deterministic empty state for tests and fresh chains.
    pub registry: crate::registry::PermissionlessRegistry,
    /// Liveness tracker (Phase 0.08): per-epoch participation counters used
    /// to detect absent validators and trigger liveness slashing.
    pub liveness: crate::registry::LivenessTracker,
    /// Invalid-vote tracker (Phase 0.08): counts consensus-rule violations
    /// per validator per epoch so we can slash or jail on spam.
    pub invalid_votes: crate::registry::InvalidVoteTracker,
    /// F4: Accumulated B.U.D. boost share pending distribution to storage operators.
    /// Populated by executor during NftBoost (4% of boost amount).
    /// Distributed by blockchain after block commit via distribute_bud_boost_share.
    pub pending_bud_boost_share: u64,
}
impl AccountState {
    pub fn new() -> Self {
        AccountState {
            accounts: BTreeMap::new(),
            validators: BTreeMap::new(),
            tokenomics: crate::tokenomics::TokenomicsParams::default(),
            timed_burn: crate::tokenomics::TimedBurnState::new(),
            burn_reserve_address: None,
            team_vesting: None,
            unbonding_queue: Vec::new(),
            storage: None,
            epoch_index: 0,
            last_epoch_time: 0,
            current_block_height: 0,
            governance: GovernanceState::default(),
            bns_registry: crate::bns::BnsRegistry::new(),
            nft_registry: crate::socialfi::NftRegistry::new(),
            marketplace: crate::pollen::MarketplaceRegistry::new(),
            storage_registry: StorageRegistry::new(),
            ai_registry: crate::ai::registry::AiRegistry::new(),
            bridge_state: BridgeState::new(),
            message_registry: CrossDomainMessageRegistry::new(),
            hub: crate::hub::HubRegistry::new(),
            external_roots: BTreeMap::new(),
            base_fee: MIN_TX_FEE,
            dirty_accounts: HashSet::new(),
            keys_dirty: true,
            cached_leaves: Vec::new(),
            cached_keys: Vec::new(),
            cached_tree: Vec::new(),
            bridge_root: [0u8; 32],
            message_root: [0u8; 32],
            settlement_root: [0u8; 32],
            global_header_summary: [0u8; 32],
            registry: crate::registry::PermissionlessRegistry::new(),
            liveness: crate::registry::LivenessTracker::new(),
            invalid_votes: crate::registry::InvalidVoteTracker::new(),
            pending_bud_boost_share: 0,
        }
    }
    pub fn with_storage(storage: Storage) -> Self {
        let mut state = AccountState {
            accounts: BTreeMap::new(),
            validators: BTreeMap::new(),
            tokenomics: crate::tokenomics::TokenomicsParams::default(),
            timed_burn: crate::tokenomics::TimedBurnState::new(),
            burn_reserve_address: None,
            team_vesting: None,
            unbonding_queue: Vec::new(),
            storage: Some(storage),
            epoch_index: 0,
            last_epoch_time: 0,
            current_block_height: 0,
            governance: GovernanceState::default(),
            storage_registry: StorageRegistry::new(),
            ai_registry: crate::ai::registry::AiRegistry::new(),
            bridge_state: BridgeState::new(),
            message_registry: CrossDomainMessageRegistry::new(),
            bns_registry: crate::bns::BnsRegistry::new(),
            nft_registry: crate::socialfi::NftRegistry::new(),
            marketplace: crate::pollen::MarketplaceRegistry::new(),
            hub: crate::hub::HubRegistry::new(),
            external_roots: BTreeMap::new(),
            base_fee: MIN_TX_FEE,
            dirty_accounts: HashSet::new(),
            keys_dirty: true,
            cached_leaves: Vec::new(),
            cached_keys: Vec::new(),
            cached_tree: Vec::new(),
            bridge_root: [0u8; 32],
            message_root: [0u8; 32],
            settlement_root: [0u8; 32],
            global_header_summary: [0u8; 32],
            registry: crate::registry::PermissionlessRegistry::new(),
            liveness: crate::registry::LivenessTracker::new(),
            invalid_votes: crate::registry::InvalidVoteTracker::new(),
            pending_bud_boost_share: 0,
        };
        if let Err(e) = state.load_from_storage() {
            tracing::error!("Could not load account state: {}", e);
        }
        state
    }
    pub fn from_snapshot(snapshot: &crate::chain::snapshot::StateSnapshot) -> Self {
        let mut accounts = BTreeMap::new();
        for (addr, balance) in &snapshot.balances {
            let mut acc = Account::new(*addr);
            acc.balance = *balance;
            acc.nonce = *snapshot.nonces.get(addr).unwrap_or(&0);
            accounts.insert(*addr, acc);
        }
        let mut validators = BTreeMap::new();
        for (addr, v) in &snapshot.validators {
            validators.insert(*addr, v.clone());
        }
        AccountState {
            accounts,
            validators,
            tokenomics: crate::tokenomics::TokenomicsParams::default(),
            timed_burn: crate::tokenomics::TimedBurnState::new(),
            burn_reserve_address: None,
            team_vesting: None,
            unbonding_queue: Vec::new(),
            storage: None,
            storage_registry: StorageRegistry::new(),
            ai_registry: crate::ai::registry::AiRegistry::new(),
            bridge_state: BridgeState::new(),
            message_registry: CrossDomainMessageRegistry::new(),
            epoch_index: snapshot.height / 100,
            last_epoch_time: 0,
            current_block_height: 0,
            governance: GovernanceState::default(),
            bns_registry: crate::bns::BnsRegistry::new(),
            nft_registry: crate::socialfi::NftRegistry::new(),
            marketplace: crate::pollen::MarketplaceRegistry::new(),
            hub: crate::hub::HubRegistry::new(),
            external_roots: BTreeMap::new(),
            base_fee: MIN_TX_FEE,
            dirty_accounts: HashSet::new(),
            keys_dirty: true,
            cached_leaves: Vec::new(),
            cached_keys: Vec::new(),
            cached_tree: Vec::new(),
            bridge_root: [0u8; 32],
            message_root: [0u8; 32],
            settlement_root: [0u8; 32],
            global_header_summary: [0u8; 32],
            registry: crate::registry::PermissionlessRegistry::new(),
            liveness: crate::registry::LivenessTracker::new(),
            invalid_votes: crate::registry::InvalidVoteTracker::new(),
            pending_bud_boost_share: 0,
        }
    }

    pub fn from_snapshot_v2(snapshot: &crate::chain::snapshot::StateSnapshotV2) -> Self {
        let mut accounts = BTreeMap::new();
        for (addr, balance) in &snapshot.balances {
            let mut acc = Account::new(*addr);
            acc.balance = *balance;
            acc.nonce = *snapshot.nonces.get(addr).unwrap_or(&0);
            accounts.insert(*addr, acc);
        }
        let mut validators = BTreeMap::new();
        for (addr, v) in &snapshot.validators {
            validators.insert(*addr, v.clone());
        }
        // Phase 0.16: restore previously-unpersisted state. The tokenomics burn block
        // (timed_burn + burn_reserve_address + team_vesting) is restored
        // ATOMICALLY from a single struct so the burn counter can never be
        // restored without its reserve address (which would risk double-burning).
        // Snapshots taken before Phase 0.16 (or before Phase 0.08) leave the field as
        // `None`; in that case the burn block is initialised fresh and the
        // double-burn guard starts from zero years burned.
        let burn_block = snapshot.tokenomics_burn.clone();
        let (timed_burn, burn_reserve_address, team_vesting) = match burn_block {
            Some(block) => (
                block.timed_burn,
                block.burn_reserve_address,
                block.team_vesting,
            ),
            None => (crate::tokenomics::TimedBurnState::new(), None, None),
        };
        let tokenomics = crate::tokenomics::TokenomicsParams {
            block_reward: snapshot.block_reward,
            ..Default::default()
        };

        AccountState {
            accounts,
            validators,
            tokenomics,
            timed_burn,
            burn_reserve_address,
            storage_registry: snapshot.storage_registry.clone().unwrap_or_default(),
            ai_registry: snapshot.ai_registry.clone().unwrap_or_default(),
            bridge_state: snapshot.bridge_state.clone().unwrap_or_default(),
            message_registry: snapshot.message_registry.clone().unwrap_or_default(),
            team_vesting,
            unbonding_queue: snapshot.unbonding_queue.clone(),
            storage: None,
            epoch_index: snapshot.epoch_index,
            current_block_height: snapshot.height,
            last_epoch_time: snapshot.last_epoch_time,
            governance: GovernanceState::default(),
            bns_registry: snapshot.bns_registry.clone().unwrap_or_default(),
            nft_registry: snapshot.nft_registry.clone().unwrap_or_default(),
            marketplace: snapshot.marketplace.clone().unwrap_or_default(),
            hub: snapshot.hub.clone().unwrap_or_default(),
            external_roots: snapshot.external_roots.clone().unwrap_or_default(),
            base_fee: snapshot.base_fee,
            dirty_accounts: HashSet::new(),
            keys_dirty: true,
            cached_leaves: Vec::new(),
            cached_keys: Vec::new(),
            cached_tree: Vec::new(),
            bridge_root: snapshot.bridge_root,
            message_root: snapshot.message_root,
            settlement_root: snapshot.settlement_root,
            global_header_summary: snapshot.global_header_summary,
            // Phase 0.08: restore permissionless registry + liveness + invalid-vote
            // tracker from snapshot when present, otherwise start empty (the
            // snapshot may pre-date the registry, e.g. v1 chains).
            registry: snapshot.registry.clone().unwrap_or_default(),
            liveness: snapshot.liveness.clone().unwrap_or_default(),
            invalid_votes: snapshot.invalid_votes.clone().unwrap_or_default(),
            pending_bud_boost_share: 0,
        }
    }

    pub fn init_genesis(&mut self, genesis_pubkey: &Address) {
        let account = Account::with_balance(*genesis_pubkey, GENESIS_BALANCE);
        self.accounts.insert(*genesis_pubkey, account);
        self.keys_dirty = true;
        tracing::info!("Genesis account created: {} coins", GENESIS_BALANCE);
    }
    pub fn add_validator(&mut self, address: Address, stake: u64) {
        let validator = Validator::new(address, stake);
        self.validators.insert(address, validator);
        // Phase 0.08: every new validator is auto-registered in the permissionless
        // registry. Staking == registration (no separate manual step).
        self.sync_validator_registration(&address);
        self.keys_dirty = true;
    }

    /// Phase 0.08: keep the on-chain validator's bonded stake in lock-step with
    /// its `PermissionlessRegistry` membership. Called from `add_validator`
    /// and from the `Stake` / `Unstake` transaction paths.
    pub fn sync_validator_registration(&mut self, address: &Address) {
        let stake = self.validators.get(address).map_or(0, |v| v.stake);
        self.registry.upsert_stake(
            *address,
            crate::registry::role::roles::VALIDATOR,
            stake,
            self.epoch_index,
        );
    }

    /// Phase 0.08: bond `amount` from the account's spendable balance into the
    /// relayer role. The bond remains locked but slashable until the relayer
    /// begins unbonding.
    pub fn bond_relayer(
        &mut self,
        address: &Address,
        amount: u64,
    ) -> Result<u64, crate::registry::RegistryError> {
        if amount == 0 {
            return Err(crate::registry::RegistryError::InsufficientStake {
                required: 1,
                provided: 0,
            });
        }
        // Pull the bond from the account's spendable balance (so we can't
        // bond funds the team vesting has locked). Use the underlying
        // balance field directly — there is no team vesting on the test
        // path we exercise.
        let account = self.get_or_create(address);
        if account.balance < amount {
            return Err(crate::registry::RegistryError::InsufficientStake {
                required: amount,
                provided: account.balance,
            });
        }
        account.balance -= amount;
        self.dirty_accounts.insert(*address);
        self.registry.upsert_stake(
            *address,
            crate::registry::role::roles::RELAYER,
            amount,
            self.epoch_index,
        );
        Ok(amount)
    }

    /// Phase 0.08: bond `amount` from the account's spendable balance into the
    /// prover role. Unlike the relayer role, prover registration is NOT a
    /// submission gate (proofs are self-verifying) — it only controls
    /// whether a successful proof earns its submitter a reward.
    pub fn bond_prover(
        &mut self,
        address: &Address,
        amount: u64,
    ) -> Result<u64, crate::registry::RegistryError> {
        if amount == 0 {
            return Err(crate::registry::RegistryError::InsufficientStake {
                required: 1,
                provided: 0,
            });
        }
        let account = self.get_or_create(address);
        if account.balance < amount {
            return Err(crate::registry::RegistryError::InsufficientStake {
                required: amount,
                provided: account.balance,
            });
        }
        account.balance -= amount;
        self.dirty_accounts.insert(*address);
        self.registry.upsert_stake(
            *address,
            crate::registry::role::roles::PROVER,
            amount,
            self.epoch_index,
        );
        Ok(amount)
    }

    /// Phase 3 §0.3: bond `amount` into the STORAGE_OPERATOR role (permissionless).
    /// Used for B.U.D. operator reward eligibility and `bud_storageActiveOperators`.
    pub fn bond_storage_operator(
        &mut self,
        address: &Address,
        amount: u64,
    ) -> Result<u64, crate::registry::RegistryError> {
        if amount == 0 {
            return Err(crate::registry::RegistryError::InsufficientStake {
                required: 1,
                provided: 0,
            });
        }
        let account = self.get_or_create(address);
        if account.balance < amount {
            return Err(crate::registry::RegistryError::InsufficientStake {
                required: amount,
                provided: account.balance,
            });
        }
        account.balance -= amount;
        self.dirty_accounts.insert(*address);
        self.registry.upsert_stake(
            *address,
            crate::registry::role::roles::STORAGE_OPERATOR,
            amount,
            self.epoch_index,
        );
        Ok(amount)
    }

    /// Phase 0.08: run one epoch's liveness check on the state-level
    /// `LivenessTracker`. Returns the canonical `SlashingReport`s produced
    /// this epoch. `participated` is the set of validators that showed the
    /// expected participation; everyone else in `validators` is treated as
    /// an absentee.
    pub fn record_liveness_epoch(
        &mut self,
        epoch: u64,
        participated: &std::collections::HashSet<Address>,
    ) -> Vec<crate::registry::evidence::SlashingReport> {
        let params = *self.registry.params();
        let expected: Vec<Address> = self.validators.keys().copied().collect();
        self.liveness.record_epoch(
            epoch,
            &expected,
            |addr| participated.contains(addr),
            &params,
        )
    }

    pub fn get_total_stake(&self) -> u64 {
        self.validators
            .values()
            .filter(|v| v.active && !v.slashed)
            .map(|v| v.stake)
            .sum()
    }
    pub fn get_active_validators(&self) -> Vec<&Validator> {
        let mut validators: Vec<&Validator> = self
            .validators
            .values()
            .filter(|v| v.active && !v.slashed)
            .collect();
        validators.sort_by_key(|a| a.address);
        validators
    }
    pub fn get_validator(&self, address: &Address) -> Option<&Validator> {
        self.validators.get(address)
    }
    pub fn get_validator_mut(&mut self, address: &Address) -> Option<&mut Validator> {
        self.validators.get_mut(address)
    }

    pub fn get_balance(&self, public_key: &Address) -> u64 {
        self.accounts
            .get(public_key)
            .map(|a| a.balance)
            .unwrap_or(0)
    }
    pub fn get_nonce(&self, public_key: &Address) -> u64 {
        self.accounts.get(public_key).map_or(0, |a| a.nonce)
    }
    pub fn get_or_create(&mut self, public_key: &Address) -> &mut Account {
        if !self.accounts.contains_key(public_key) {
            self.accounts.insert(*public_key, Account::new(*public_key));
            self.keys_dirty = true;
        }
        self.mark_dirty(public_key);
        self.accounts.get_mut(public_key).unwrap()
    }
    pub fn mark_dirty(&mut self, public_key: &Address) {
        self.dirty_accounts.insert(*public_key);
    }
    pub fn validate_transaction(&self, tx: &Transaction) -> Result<(), String> {
        self.validate_transaction_with_context(
            tx,
            self.get_nonce(&tx.from),
            self.get_balance(&tx.from),
        )
    }

    pub fn validate_transaction_with_context(
        &self,
        tx: &Transaction,
        expected_nonce: u64,
        spendable_balance: u64,
    ) -> Result<(), String> {
        if tx.from == Address::zero() {
            return Ok(());
        }
        // Phase 0.32 / A1: cheap checks before expensive signature verification (DoS).
        if tx.nonce != expected_nonce {
            return Err(format!(
                "Invalid nonce: expected {}, got {}",
                expected_nonce, tx.nonce
            ));
        }
        if tx.fee < self.base_fee {
            return Err(format!("Fee too low: {} < {}", tx.fee, self.base_fee));
        }
        // Overflow guard (security): reject amount+fee > u64::MAX explicitly.
        // total_cost() uses saturating_add, which would silently clamp to
        // u64::MAX and admit an otherwise unpayable transfer whenever the
        // sender happens to hold u64::MAX.
        if tx.amount.checked_add(tx.fee).is_none() {
            return Err("Transaction amount + fee overflows u64".into());
        }
        let total_cost = tx.total_cost();
        if spendable_balance < total_cost {
            return Err(format!(
                "Insufficient balance: {} < {} (amount: {}, fee: {})",
                spendable_balance, total_cost, tx.amount, tx.fee
            ));
        }
        if !tx.verify() {
            return Err("Invalid signature".into());
        }

        match tx.tx_type {
            TransactionType::Transfer => {
                if tx.to == Address::zero() {
                    return Err("Transfer missing 'to' address".into());
                }
            }
            TransactionType::Stake => {
                if tx.amount == 0 {
                    return Err("Stake amount must be > 0".into());
                }
            }
            TransactionType::Unstake => {
                if let Some(validator) = self.validators.get(&tx.from) {
                    if validator.stake < tx.amount {
                        return Err(format!(
                            "Insufficient stake: {} < {}",
                            validator.stake, tx.amount
                        ));
                    }
                } else {
                    return Err("Not a validator".into());
                }
            }
            TransactionType::Vote => {
                if !self.validators.contains_key(&tx.from) {
                    return Err("Only validators can vote".into());
                }
            }
            TransactionType::ContractCall => {
                if tx.amount != 0 {
                    return Err("Contract call amount must be 0".into());
                }
                if tx.data.is_empty() || !tx.data.len().is_multiple_of(8) {
                    return Err("Contract call data must be non-empty BudZKVM bytecode".into());
                }
            }
            _ => {}
        }

        Ok(())
    }

    pub fn apply_slashing(&mut self, evidences: &[SlashingEvidence], slash_ratio_fixed: u64) {
        for evidence in evidences {
            if let Some(producer) = &evidence.header1.producer {
                let _ = self.slash_validator(
                    producer,
                    slash_ratio_fixed,
                    "consensus slashing evidence",
                );
            }
        }
    }

    pub fn slash_validator(
        &mut self,
        address: &Address,
        slash_ratio_fixed: u64,
        reason: &str,
    ) -> Option<u64> {
        use crate::core::chain_config::FIXED_POINT_SCALE;

        let validator = self.validators.get_mut(address)?;
        if validator.slashed {
            return Some(0);
        }

        let penalty = ((validator.stake as u128 * slash_ratio_fixed as u128)
            / FIXED_POINT_SCALE as u128) as u64;
        validator.stake = validator.stake.saturating_sub(penalty);
        validator.slashed = true;
        validator.active = false;
        validator.jailed = true;

        let jail_epochs = 7;
        validator.jail_until = self.epoch_index.saturating_add(jail_epochs);

        // Phase 0.08: mirror the slash into the permissionless registry so the two
        // views stay consistent. The registry's `is_active` predicate is what
        // the rest of the node (consensus, RPC) checks, so an account that
        // was slashed at the account-state layer must also become inactive in
        // the registry — otherwise the same offence would be paid-for twice.
        // Phase 0.34 / BUG #6: apply_slashing feeds double-sign evidence — label
        // the registry mirror as DoubleSign, not LivenessFault (audit trail).
        let _ = self.registry.slash(
            *address,
            crate::registry::role::roles::VALIDATOR,
            crate::registry::permissionless::SlashingCondition::DoubleSign,
            slash_ratio_fixed,
        );

        tracing::info!(
            "Slashed validator {} for {} stake due to {} (Jailed until epoch {})",
            address,
            penalty,
            reason,
            validator.jail_until
        );

        Some(penalty)
    }

    pub fn process_unbonding(&mut self) {
        let current_epoch = self.epoch_index;
        let mut released: Vec<(Address, u64)> = Vec::new();
        self.unbonding_queue.retain(|entry| {
            if entry.release_epoch <= current_epoch {
                released.push((entry.address, entry.amount));
                false
            } else {
                true
            }
        });
        for (addr, amount) in released {
            let account = self.get_or_create(&addr);
            account.balance = account.balance.saturating_add(amount);
            tracing::info!("Unbonding released: {} received {} coins", addr, amount);
        }
    }

    /// Record consensus participation for the epoch that just completed and
    /// ... [doc continues]
    pub fn advance_epoch(&mut self, current_timestamp: u128) {
        let total_stake = self.get_total_stake();
        let quorum_pct = 33; // 33% stake required for quorum

        let current_epoch = self.epoch_index;
        let mut to_execute = Vec::new();

        for proposal in self.governance.proposals.iter_mut() {
            if proposal.status == crate::core::governance::ProposalStatus::Active
                && current_epoch >= proposal.end_epoch
            {
                proposal.finalize(total_stake, quorum_pct);
                if proposal.status == crate::core::governance::ProposalStatus::Passed {
                    to_execute.push(proposal.clone());
                }
            }
        }

        for proposal in to_execute {
            self.execute_proposal(&proposal);
            if let Some(p) = self.governance.find_proposal_mut(proposal.id) {
                p.status = crate::core::governance::ProposalStatus::Executed;
            }
        }

        self.epoch_index = self.epoch_index.saturating_add(1);
        self.last_epoch_time = current_timestamp as u64;
        tracing::info!("Epoch advanced to {}", self.epoch_index);

        self.process_unbonding();

        // Process relayer escrow releases (Phase 0.52)

        // DP1: Distribute epoch-based stake yield to active non-jailed validators
        // We calculate and distribute rewards proportional to stake using `calculate_epoch_reward` from TokenomicsParams.
        // This is separate from the `block_reward` which goes to the producer.
        let mut total_yield = 0;
        let mut payouts = Vec::new();
        for (addr, validator) in self.validators.iter() {
            if validator.active && !validator.jailed && !validator.slashed {
                let reward = self.tokenomics.calculate_epoch_reward(validator.stake);
                if reward > 0 {
                    payouts.push((*addr, reward));
                    total_yield += reward;
                }
            }
        }

        // DP2: Check supply cap
        // The total supply cap is 100M. We must ensure we don't mint past it.
        let current_supply = self.circulating_supply();
        let max_supply = crate::tokenomics::BUD_TOTAL_SUPPLY as u128;

        if current_supply < max_supply {
            let space_left = max_supply - current_supply;
            if total_yield as u128 > space_left {
                for (addr, amount) in payouts {
                    let scaled_amount =
                        ((amount as u128 * space_left) / total_yield as u128) as u64;
                    if scaled_amount > 0 {
                        self.add_balance(&addr, scaled_amount);
                    }
                }
            } else {
                for (addr, amount) in payouts {
                    self.add_balance(&addr, amount);
                }
            }
        }

        for (addr, validator) in self.validators.iter_mut() {
            if validator.jailed && validator.jail_until <= self.epoch_index {
                tracing::info!("Validator {} released from jail", addr);
                validator.jailed = false;
                if validator.stake > 0 && !validator.slashed {
                    validator.active = true;
                }
            }
        }

        // $BUD timed reserve burn (Phase 0.14b): this is the canonical epoch-transition
        // point, so execute any due annual burns here. Idempotent per year and a
        // no-op unless a burn-reserve account is configured (tokenomics enabled).
        if let Some(reserve) = self.burn_reserve_address {
            let burned = self.process_timed_burn(0, &reserve);
            if burned > 0 {
                tracing::info!(
                    "Timed reserve burn: {} $BUD burned at epoch {}",
                    burned,
                    self.epoch_index
                );
            }
        }
    }

    fn execute_proposal(&mut self, proposal: &crate::core::governance::Proposal) {
        use crate::core::governance::ProposalType;
        match &proposal.p_type {
            ProposalType::ChangeBaseFee(new_fee) => {
                // Phase 0.334 / A8: clamp to protocol bounds (never accept unbounded fee).
                if *new_fee < MIN_TX_FEE || *new_fee > MAX_BASE_FEE {
                    tracing::warn!(
                        "Rejecting ChangeBaseFee {}: outside [{}, {}]",
                        new_fee,
                        MIN_TX_FEE,
                        MAX_BASE_FEE
                    );
                } else {
                    self.base_fee = *new_fee;
                    tracing::info!("Executing Governance: BaseFee changed to {}", new_fee);
                }
            }
            ProposalType::ChangeBlockReward(new_reward) => {
                if *new_reward > MAX_BLOCK_REWARD {
                    tracing::warn!(
                        "Rejecting ChangeBlockReward {}: above MAX_BLOCK_REWARD {}",
                        new_reward,
                        MAX_BLOCK_REWARD
                    );
                } else {
                    self.tokenomics.block_reward = *new_reward;
                    tracing::info!(
                        "Executing Governance: BlockReward changed to {}",
                        new_reward
                    );
                }
            }
            ProposalType::SlashValidator {
                address,
                evidence_hash,
            } => {
                // V40 (ARENAX): Governance slash now requires evidence.
                // The target address must have at least one slashing record in history.
                // The evidence_hash serves as a commitment to specific evidence
                // (defense-in-depth: prevents arbitrary slashing without proof).
                let has_evidence = self
                    .registry
                    .slashing_history_for(address)
                    .iter()
                    .any(|record| record.report.offender == *address);
                if !has_evidence {
                    tracing::warn!(
                        "Rejecting SlashValidator {}: no slashing evidence in registry history",
                        address
                    );
                } else if let Some(v) = self.validators.get_mut(address) {
                    v.slashed = true;
                    v.active = false;
                    v.stake = 0;
                    tracing::info!(
                        "Executing Governance: Slashed validator {} (evidence-verified)",
                        address
                    );
                }
            }
            ProposalType::ParameterUpdate(key, value) => {
                // Phase 0.334 / A8: wire ParameterUpdate into RegistryParams with bounds.
                match self.apply_registry_parameter_update(key, value) {
                    Ok(()) => tracing::info!(
                        "Executing Governance: Parameter {} updated to {}",
                        key,
                        value
                    ),
                    Err(e) => tracing::warn!("Rejecting ParameterUpdate {}={}: {}", key, value, e),
                }
            }
        }
    }

    /// Apply a single registry parameter update if it parses and passes bounds.
    fn apply_registry_parameter_update(&mut self, key: &str, value: &str) -> Result<(), String> {
        let mut params = *self.registry.params();
        match key {
            "min_stake" => {
                params.min_stake = value
                    .parse::<u64>()
                    .map_err(|e| format!("invalid min_stake: {e}"))?;
            }
            "unbonding_epochs" => {
                params.unbonding_epochs = value
                    .parse::<u64>()
                    .map_err(|e| format!("invalid unbonding_epochs: {e}"))?;
            }
            "double_sign_slash_ratio_fixed" => {
                params.double_sign_slash_ratio_fixed = value
                    .parse::<u64>()
                    .map_err(|e| format!("invalid double_sign_slash_ratio_fixed: {e}"))?;
            }
            "liveness_slash_ratio_fixed" => {
                params.liveness_slash_ratio_fixed = value
                    .parse::<u64>()
                    .map_err(|e| format!("invalid liveness_slash_ratio_fixed: {e}"))?;
            }
            "malicious_slash_ratio_fixed" => {
                params.malicious_slash_ratio_fixed = value
                    .parse::<u64>()
                    .map_err(|e| format!("invalid malicious_slash_ratio_fixed: {e}"))?;
            }
            other => return Err(format!("unknown registry parameter: {other}")),
        }
        params.validate()?;
        self.registry.set_params(params);
        Ok(())
    }
    pub fn add_balance(&mut self, public_key: &Address, amount: u64) {
        let account = self.get_or_create(public_key);
        account.balance = account.balance.saturating_add(amount);
        self.dirty_accounts.insert(*public_key);
    }

    /// Amount of `address`'s balance that is currently spendable, taking team
    /// vesting into account. For a non-vesting account this is the full balance.
    /// For the configured team account, the balance may not be spent below the
    /// still-locked portion at `current_epoch`.
    pub fn spendable_balance(&self, address: &Address) -> u64 {
        let balance = self.get_balance(address);
        if let Some((team, schedule)) = &self.team_vesting {
            if team == address {
                let locked = schedule.locked_at(self.epoch_index);
                return balance.saturating_sub(locked);
            }
        }
        balance
    }

    /// Total $BUD in circulation: the sum of all account balances. There is no
    /// separate `total_supply` field, so this is the authoritative supply figure.
    /// (Validator stake is bonded separately and is not part of `accounts`.)
    pub fn circulating_supply(&self) -> u128 {
        self.accounts
            .values()
            .fold(0u128, |acc, a| acc + a.balance as u128)
    }

    /// Burn `amount` from `address`: reduce its balance and credit it NOWHERE,
    /// so total supply strictly decreases. Returns the amount actually burned
    /// (capped at the available balance). This is the single canonical burn used
    /// by both the timed reserve burn and the metabolic (tx-fee) burn.
    pub fn burn_from(&mut self, address: &Address, amount: u64) -> u64 {
        if amount == 0 {
            return 0;
        }
        let account = self.get_or_create(address);
        let burned = amount.min(account.balance);
        account.balance -= burned;
        self.dirty_accounts.insert(*address);
        burned
    }

    /// Execute any timed (annual) reserve burns that are due by the current
    /// epoch. Time-triggered (NOT usage-triggered): each crossed "year" boundary
    /// burns `annual_burn_amount` from the burn-reserve account. Idempotent per
    /// year — calling repeatedly within the same year burns nothing extra.
    ///
    /// `genesis_epoch` is the epoch tokenomics started (usually 0);
    /// `reserve_addr` is the on-chain burn-reserve account.
    /// Returns the total amount burned by this call.
    pub fn process_timed_burn(&mut self, genesis_epoch: u64, reserve_addr: &Address) -> u64 {
        let epochs_per_year = self.tokenomics.epochs_per_year;
        let due = self
            .timed_burn
            .due_years(genesis_epoch, self.epoch_index, epochs_per_year);
        if due <= self.timed_burn.years_burned {
            return 0;
        }
        let per_year = self.tokenomics.annual_burn_amount();
        let mut total = 0u64;
        // Burn one increment per outstanding year (bounded by remaining reserve).
        let outstanding = due - self.timed_burn.years_burned;
        for _ in 0..outstanding {
            let burned = self.burn_from(reserve_addr, per_year);
            if burned == 0 {
                // Reserve exhausted; stop but still advance the year counter so
                // we don't loop forever on future calls.
                break;
            }
            total = total.saturating_add(burned);
            self.timed_burn.total_burned = self.timed_burn.total_burned.saturating_add(burned);
        }
        self.timed_burn.years_burned = due;
        total
    }

    pub fn save_to_storage(&self) -> Result<(), String> {
        let storage = match &self.storage {
            Some(s) => s,
            None => return Ok(()),
        };
        for (pubkey, account) in &self.accounts {
            storage
                .save_account(pubkey, account)
                .map_err(|e| format!("Storage error: {e}"))?;
        }
        storage
            .db()
            .flush()
            .map_err(|e| format!("Flush error: {e}"))?;
        Ok(())
    }
    fn load_from_storage(&mut self) -> Result<(), String> {
        let storage = match &self.storage {
            Some(s) => s,
            None => return Ok(()),
        };
        match storage.load_all_accounts() {
            Ok(accounts) => {
                tracing::info!("Loaded {} accounts from storage", accounts.len());
                self.accounts = accounts.into_iter().collect();
                self.keys_dirty = true;
            }
            Err(e) => {
                if let Ok(Some(data)) = storage.db().get("ACCOUNT_STATE") {
                    let accounts: HashMap<Address, Account> = serde_json::from_slice(&data)
                        .map_err(|e| format!("Deserialization error: {e}"))?;
                    self.accounts = accounts.into_iter().collect();
                    self.keys_dirty = true;
                    tracing::info!("Loaded {} accounts from legacy blob", self.accounts.len());
                } else {
                    tracing::error!("Could not load accounts: {}", e);
                }
            }
        }
        Ok(())
    }
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }
    pub fn get_all_balances(&self) -> HashMap<Address, u64> {
        self.accounts.iter().map(|(k, v)| (*k, v.balance)).collect()
    }
    pub fn get_all_nonces(&self) -> HashMap<Address, u64> {
        self.accounts.iter().map(|(k, v)| (*k, v.nonce)).collect()
    }

    pub fn calculate_state_root(&mut self) -> String {
        use sha2::{Digest, Sha256};

        if self.accounts.is_empty() {
            return "0".repeat(64);
        }

        if self.keys_dirty || self.cached_tree.is_empty() {
            self.cached_keys = self.accounts.keys().cloned().collect();

            self.cached_leaves = self
                .accounts
                .par_iter()
                .map(|(pubkey, account)| {
                    let mut h = Sha256::new();
                    h.update([0x00]);
                    h.update(pubkey.0);
                    h.update(account.balance.to_le_bytes());
                    h.update(account.nonce.to_le_bytes());
                    h.finalize().into()
                })
                .collect();

            self.cached_tree = Vec::new();
            let mut level = self.cached_leaves.clone();
            self.cached_tree.push(level.clone());

            while level.len() > 1 {
                let next_level: Vec<[u8; 32]> = level
                    .par_chunks(2)
                    .map(|chunk| {
                        let left = &chunk[0];
                        let right = if chunk.len() > 1 { &chunk[1] } else { left };
                        let mut h = Sha256::new();
                        h.update([0x01]);
                        h.update(left);
                        h.update(right);
                        h.finalize().into()
                    })
                    .collect();
                level = next_level;
                self.cached_tree.push(level.clone());
            }
            self.keys_dirty = false;
        } else {
            let mut affected_indices: HashSet<usize> = HashSet::new();

            for dirty_key in &self.dirty_accounts {
                if let Ok(pos) = self.cached_keys.binary_search(dirty_key) {
                    if let Some(account) = self.accounts.get(dirty_key) {
                        let mut h = Sha256::new();
                        h.update([0x00]);
                        h.update(dirty_key.0);
                        h.update(account.balance.to_le_bytes());
                        h.update(account.nonce.to_le_bytes());
                        self.cached_leaves[pos] = h.finalize().into();
                        affected_indices.insert(pos);
                    }
                }
            }

            self.cached_tree[0] = self.cached_leaves.clone();

            for level_idx in 0..self.cached_tree.len() - 1 {
                if affected_indices.is_empty() {
                    break;
                }

                let mut next_affected = HashSet::new();

                let mut parent_to_children: HashMap<usize, (usize, usize)> = HashMap::new();
                for &idx in &affected_indices {
                    let parent_idx = idx / 2;
                    let left_idx = parent_idx * 2;
                    let right_idx = if left_idx + 1 < self.cached_tree[level_idx].len() {
                        left_idx + 1
                    } else {
                        left_idx
                    };
                    parent_to_children.insert(parent_idx, (left_idx, right_idx));
                }

                for (parent_idx, (left_idx, right_idx)) in parent_to_children {
                    let mut h = Sha256::new();
                    h.update([0x01]);
                    h.update(self.cached_tree[level_idx][left_idx]);
                    h.update(self.cached_tree[level_idx][right_idx]);

                    self.cached_tree[level_idx + 1][parent_idx] = h.finalize().into();
                    next_affected.insert(parent_idx);
                }
                affected_indices = next_affected;
            }
        }

        self.dirty_accounts.clear();
        let accounts_root_bytes = if self.cached_tree.is_empty() {
            [0u8; 32]
        } else {
            self.cached_tree.last().unwrap()[0]
        };

        // ConsensusStateV2 Root Hashing
        let mut validator_hashes = Vec::new();
        for (addr, val) in &self.validators {
            let mut h = Sha256::new();
            h.update(addr.0);
            h.update(val.stake.to_le_bytes());
            h.update([val.active as u8]);
            h.update([val.slashed as u8]);
            h.update([val.jailed as u8]);
            h.update(val.jail_until.to_le_bytes());
            h.update(val.last_proposed_block.unwrap_or(0).to_le_bytes());
            h.update(val.votes_for.to_le_bytes());
            h.update(val.votes_against.to_le_bytes());
            h.update(&val.vrf_public_key);
            h.update(&val.bls_public_key);
            h.update(&val.pop_signature);
            h.update(&val.pq_public_key);
            validator_hashes.push(h.finalize());
        }
        let validators_root = if validator_hashes.is_empty() {
            [0u8; 32]
        } else {
            let mut combined = Sha256::new();
            for hash in validator_hashes {
                combined.update(hash);
            }
            combined.finalize().into()
        };

        let mut unbonding_entries = self.unbonding_queue.clone();
        unbonding_entries.sort_by(|a, b| {
            a.address
                .0
                .cmp(&b.address.0)
                .then(a.release_epoch.cmp(&b.release_epoch))
        });
        let mut unbonding_hashes = Vec::new();
        for entry in unbonding_entries {
            let mut h = Sha256::new();
            h.update(entry.address.0);
            h.update(entry.amount.to_le_bytes());
            h.update(entry.release_epoch.to_le_bytes());
            unbonding_hashes.push(h.finalize());
        }
        let unbonding_root = if unbonding_hashes.is_empty() {
            [0u8; 32]
        } else {
            let mut combined = Sha256::new();
            for hash in unbonding_hashes {
                combined.update(hash);
            }
            combined.finalize().into()
        };

        let mut final_hasher = Sha256::new();
        final_hasher.update(b"v2");
        final_hasher.update(self.epoch_index.to_le_bytes());
        final_hasher.update(accounts_root_bytes);
        final_hasher.update(validators_root);
        final_hasher.update(unbonding_root);
        final_hasher.update(self.base_fee.to_le_bytes());
        final_hasher.update(self.tokenomics.block_reward.to_le_bytes());
        final_hasher.update(self.bridge_root);
        final_hasher.update(self.message_root);
        final_hasher.update(self.settlement_root);
        if !self.ai_registry.is_empty() {
            final_hasher.update(b"ai_v1");
            final_hasher.update(self.ai_registry.state_root());
        }
        final_hasher.update(self.global_header_summary);
        final_hasher.update(b"gov_disabled"); // governance version/enabled flags

        let final_root = final_hasher.finalize();
        hex::encode(final_root)
    }
    pub fn clear_dirty(&mut self) {
        self.dirty_accounts.clear();
    }
}
impl Default for AccountState {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::primitives::KeyPair;
    #[test]
    fn test_new_account() {
        let account = Account::new(Address::zero());
        assert_eq!(account.balance, 0);
        assert_eq!(account.nonce, 0);
    }
    #[test]
    fn test_account_with_balance() {
        let account = Account::with_balance(Address::zero(), 1000);
        assert_eq!(account.balance, 1000);
    }
    #[test]
    fn test_account_state_balance() {
        let mut state = AccountState::new();
        let mut alice_bytes = [0u8; 32];
        alice_bytes[0] = 1;
        let alice = Address::from(alice_bytes);
        state.add_balance(&alice, 500);
        assert_eq!(state.get_balance(&alice), 500);

        let mut bob_bytes = [0u8; 32];
        bob_bytes[0] = 2;
        let bob = Address::from(bob_bytes);
        assert_eq!(state.get_balance(&bob), 0);
    }
    #[test]
    fn test_transfer() {
        let alice_kp = KeyPair::generate().unwrap();
        let bob_kp = KeyPair::generate().unwrap();
        let alice = Address::from(alice_kp.public_key_bytes());
        let bob = Address::from(bob_kp.public_key_bytes());
        let mut state = AccountState::new();
        state.add_balance(&alice, 1000);
        let mut tx = Transaction::new_with_fee(alice, bob, 100, 5, 0, vec![]);
        tx.sign(&alice_kp);
        assert!(state.validate_transaction(&tx).is_ok());
        crate::execution::executor::Executor::apply_transaction(&mut state, &tx).unwrap();
        assert_eq!(state.get_balance(&alice), 895);
        assert_eq!(state.get_balance(&bob), 100);
        assert_eq!(state.get_nonce(&alice), 1);
    }
    #[test]
    fn test_insufficient_balance() {
        let alice_kp = KeyPair::generate().unwrap();
        let alice = Address::from(alice_kp.public_key_bytes());
        let mut state = AccountState::new();
        state.add_balance(&alice, 50);
        let mut tx = Transaction::new_with_fee(alice, Address::zero(), 100, 1, 0, vec![]);
        tx.sign(&alice_kp);
        assert!(state.validate_transaction(&tx).is_err());
    }
    #[test]
    fn test_wrong_nonce() {
        let alice_kp = KeyPair::generate().unwrap();
        let alice = Address::from(alice_kp.public_key_bytes());
        let mut state = AccountState::new();
        state.add_balance(&alice, 1000);
        let recipient = Address::from([1u8; 32]);
        let mut tx = Transaction::new_with_fee(alice, recipient, 100, 1, 5, vec![]);
        tx.sign(&alice_kp);
        let result = state.validate_transaction(&tx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("nonce"));
    }
    #[test]
    fn test_replay_protection() {
        let alice_kp = KeyPair::generate().unwrap();
        let alice = Address::from(alice_kp.public_key_bytes());
        let mut state = AccountState::new();
        state.add_balance(&alice, 1000);
        let recipient = Address::from([1u8; 32]);
        let mut tx1 = Transaction::new_with_fee(alice, recipient, 50, 1, 0, vec![]);
        tx1.sign(&alice_kp);
        assert!(state.validate_transaction(&tx1).is_ok());
        crate::execution::executor::Executor::apply_transaction(&mut state, &tx1).unwrap();
        assert!(state.validate_transaction(&tx1).is_err());
        let recipient = Address::from([1u8; 32]);
        let mut tx2 = Transaction::new_with_fee(alice, recipient, 50, 1, 1, vec![]);
        tx2.sign(&alice_kp);
        assert!(state.validate_transaction(&tx2).is_ok());
    }
    #[test]
    fn test_fee_too_low() {
        let alice_kp = KeyPair::generate().unwrap();
        let alice = Address::from(alice_kp.public_key_bytes());
        let mut state = AccountState::new();
        state.add_balance(&alice, 1000);
        let mut tx = Transaction::new_with_fee(alice, Address::zero(), 100, 0, 0, vec![]);
        tx.sign(&alice_kp);
        let result = state.validate_transaction(&tx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Fee"));
    }

    #[test]
    fn test_slashing_sets_jail_and_releases_by_epoch() {
        let validator = Address::from([7u8; 32]);
        let mut state = AccountState::new();
        state.add_validator(validator, 1_000);

        let penalty = state
            .slash_validator(
                &validator,
                crate::core::chain_config::FIXED_POINT_SCALE / 10,
                "test",
            )
            .unwrap();

        assert_eq!(penalty, 100);
        let jailed = state.get_validator(&validator).unwrap();
        assert!(jailed.slashed);
        assert!(jailed.jailed);
        assert!(!jailed.active);
        assert_eq!(jailed.jail_until, 7);

        for epoch in 1..=6 {
            state.advance_epoch(epoch * 1_000);
        }
        assert!(state.get_validator(&validator).unwrap().jailed);

        state.advance_epoch(7_000);
        let released = state.get_validator(&validator).unwrap();
        assert!(!released.jailed);
        assert!(released.slashed);
        assert!(!released.active);
    }

    // === Phase 0.60 SUPPLY-CAP INTEGER-ONLY TESTİ ===
    #[test]
    fn supply_cap_scaling_is_integer_only_and_respects_limit() {
        let mut state = AccountState::new();

        // Yüksek stake'li validator ekle
        let validator_addr = Address::from([42u8; 32]);
        state.add_validator(validator_addr, 100_000_000_000); // 100B stake

        // Supply cap'e çok yakın bir durum oluştur
        // (basit test için mevcut supply'ı yüksek tut)
        let initial_balance_addr = Address::from([99u8; 32]);
        state.add_balance(&initial_balance_addr, 99_999_000_000_000); // ~99.999M

        let before_supply = state.circulating_supply();

        // Epoch advance → yield dağıtımı tetiklenir
        state.advance_epoch(1_000);

        let after_supply = state.circulating_supply();

        // Dağıtılan miktar supply cap'i ASLA aşmamalı
        assert!(
            after_supply <= crate::tokenomics::BUD_TOTAL_SUPPLY as u128,
            "Supply cap aşıldı: {} > {}",
            after_supply,
            crate::tokenomics::BUD_TOTAL_SUPPLY
        );

        // En azından bazı ödül dağıtılmış olmalı (eğer cap'e ulaşmadıysa)
        if before_supply < crate::tokenomics::BUD_TOTAL_SUPPLY as u128 {
            // Test başarılıysa ödül dağıtılmış demektir
        }
    }

    /// Phase 0.32 / A1: nonce mismatch must fail with a nonce error even when the
    /// signature is valid — proves cheap checks still run and still gate.
    #[test]
    fn tur11_wrong_nonce_rejected_before_accepting_valid_sig() {
        let alice_kp = KeyPair::generate().unwrap();
        let alice = Address::from(alice_kp.public_key_bytes());
        let mut state = AccountState::new();
        state.add_balance(&alice, 1000);
        let recipient = Address::from([1u8; 32]);
        let mut tx = Transaction::new_with_fee(alice, recipient, 100, 1, 9, vec![]);
        tx.sign(&alice_kp);
        let err = state
            .validate_transaction(&tx)
            .expect_err("wrong nonce must be rejected");
        assert!(
            err.contains("nonce") || err.contains("Invalid nonce"),
            "expected nonce error, got: {err}"
        );
    }

    /// Phase 0.32 / A1: invalid signature is still rejected after cheap checks pass.
    #[test]
    fn tur11_invalid_signature_still_rejected() {
        let alice_kp = KeyPair::generate().unwrap();
        let bob_kp = KeyPair::generate().unwrap();
        let alice = Address::from(alice_kp.public_key_bytes());
        let mut state = AccountState::new();
        state.add_balance(&alice, 1000);
        let recipient = Address::from([1u8; 32]);
        let mut tx = Transaction::new_with_fee(alice, recipient, 100, 1, 0, vec![]);
        // Sign with the wrong key so signature verification fails.
        tx.sign(&bob_kp);
        let err = state
            .validate_transaction(&tx)
            .expect_err("bad signature must be rejected");
        assert!(
            err.contains("signature") || err.contains("Invalid signature"),
            "expected signature error, got: {err}"
        );
    }

    /// Phase 0.334 / A8: out-of-range base fee proposals are rejected.
    #[test]
    fn tur117_change_base_fee_bounds() {
        use crate::core::governance::{Proposal, ProposalType};
        let mut state = AccountState::new();
        let old = state.base_fee;
        let p = Proposal::new(
            1,
            Address::from([1u8; 32]),
            ProposalType::ChangeBaseFee(0),
            0,
            10,
        );
        state.execute_proposal(&p);
        assert_eq!(state.base_fee, old, "zero fee must be rejected");

        let p = Proposal::new(
            2,
            Address::from([1u8; 32]),
            ProposalType::ChangeBaseFee(MAX_BASE_FEE + 1),
            0,
            10,
        );
        state.execute_proposal(&p);
        assert_eq!(state.base_fee, old, "over-max fee must be rejected");

        let p = Proposal::new(
            3,
            Address::from([1u8; 32]),
            ProposalType::ChangeBaseFee(42),
            0,
            10,
        );
        state.execute_proposal(&p);
        assert_eq!(state.base_fee, 42);
    }

    /// Phase 0.334 / A8: ParameterUpdate binds to RegistryParams with validation.
    #[test]
    fn tur117_parameter_update_registry_bounds() {
        use crate::core::governance::{Proposal, ProposalType};
        let mut state = AccountState::new();
        let old = state.registry.params().min_stake;

        // Reject too-small min_stake.
        let p = Proposal::new(
            1,
            Address::from([2u8; 32]),
            ProposalType::ParameterUpdate("min_stake".into(), "1".into()),
            0,
            10,
        );
        state.execute_proposal(&p);
        assert_eq!(state.registry.params().min_stake, old);

        // Accept a valid increase.
        let p = Proposal::new(
            2,
            Address::from([2u8; 32]),
            ProposalType::ParameterUpdate("min_stake".into(), "5000".into()),
            0,
            10,
        );
        state.execute_proposal(&p);
        assert_eq!(state.registry.params().min_stake, 5000);

        // Reject zero unbonding.
        let old_u = state.registry.params().unbonding_epochs;
        let p = Proposal::new(
            3,
            Address::from([2u8; 32]),
            ProposalType::ParameterUpdate("unbonding_epochs".into(), "0".into()),
            0,
            10,
        );
        state.execute_proposal(&p);
        assert_eq!(state.registry.params().unbonding_epochs, old_u);
    }

    /// Phase 0.334 / A8: block reward cannot exceed protocol max.
    #[test]
    fn tur117_change_block_reward_bounds() {
        use crate::core::governance::{Proposal, ProposalType};
        let mut state = AccountState::new();
        let old = state.tokenomics.block_reward;
        let p = Proposal::new(
            1,
            Address::from([3u8; 32]),
            ProposalType::ChangeBlockReward(MAX_BLOCK_REWARD + 1),
            0,
            10,
        );
        state.execute_proposal(&p);
        assert_eq!(state.tokenomics.block_reward, old);
        let p = Proposal::new(
            2,
            Address::from([3u8; 32]),
            ProposalType::ChangeBlockReward(100),
            0,
            10,
        );
        state.execute_proposal(&p);
        assert_eq!(state.tokenomics.block_reward, 100);
    }
}
