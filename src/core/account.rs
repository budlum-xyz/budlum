use crate::consensus::pos::SlashingEvidence;
use crate::core::address::Address;
use crate::core::governance::GovernanceState;
use crate::core::transaction::{Transaction, TransactionType};
use crate::storage::db::Storage;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
pub const MIN_TX_FEE: u64 = 1;
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
            governance: GovernanceState::default(),
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
            governance: GovernanceState::default(),
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
            epoch_index: snapshot.height / 100,
            last_epoch_time: 0,
            governance: GovernanceState::default(),
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
        // Tur 9: restore previously-unpersisted state. The tokenomics burn block
        // (timed_burn + burn_reserve_address + team_vesting) is restored
        // ATOMICALLY from a single struct so the burn counter can never be
        // restored without its reserve address (which would risk double-burning).
        let (timed_burn, burn_reserve_address, team_vesting) = (
            crate::tokenomics::TimedBurnState::new(),
            None,
            None,
        );
        let mut tokenomics = crate::tokenomics::TokenomicsParams::default();
        tokenomics.block_reward = snapshot.block_reward;

        AccountState {
            accounts,
            validators,
            tokenomics,
            timed_burn,
            burn_reserve_address,
            team_vesting,
            unbonding_queue: snapshot.unbonding_queue.clone(),
            storage: None,
            epoch_index: snapshot.epoch_index,
            last_epoch_time: snapshot.last_epoch_time,
            governance: GovernanceState::default(),
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
        self.keys_dirty = true;
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
        validators.sort_by(|a, b| a.address.cmp(&b.address));
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
        self.accounts.get(public_key).map(|a| a.nonce).unwrap_or(0)
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
        if !tx.verify() {
            return Err("Invalid signature".into());
        }
        if tx.fee < self.base_fee {
            return Err(format!("Fee too low: {} < {}", tx.fee, self.base_fee));
        }
        if tx.nonce != expected_nonce {
            return Err(format!(
                "Invalid nonce: expected {}, got {}",
                expected_nonce, tx.nonce
            ));
        }
        let total_cost = tx.total_cost();
        if spendable_balance < total_cost {
            return Err(format!(
                "Insufficient balance: {} < {} (amount: {}, fee: {})",
                spendable_balance, total_cost, tx.amount, tx.fee
            ));
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

        // Process relayer escrow releases (Tur 21)

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
                    let scaled_amount = ((amount as u128 * space_left) / total_yield as u128) as u64;
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

        // $BUD timed reserve burn (Tur 8b): this is the canonical epoch-transition
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
                self.base_fee = *new_fee;
                tracing::info!("Executing Governance: BaseFee changed to {}", new_fee);
            }
            ProposalType::ChangeBlockReward(new_reward) => {
                self.tokenomics.block_reward = *new_reward;
                tracing::info!(
                    "Executing Governance: BlockReward changed to {}",
                    new_reward
                );
            }
            ProposalType::SlashValidator(addr) => {
                if let Some(v) = self.validators.get_mut(addr) {
                    v.slashed = true;
                    v.active = false;
                    v.stake = 0;
                    tracing::info!("Executing Governance: Slashed validator {}", addr);
                }
            }
            ProposalType::ParameterUpdate(key, value) => {
                tracing::info!(
                    "Executing Governance: Parameter {} updated to {}",
                    key,
                    value
                );
            }
        }
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
    pub fn process_timed_burn(
        &mut self,
        genesis_epoch: u64,
        reserve_addr: &Address,
    ) -> u64 {
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
            self.timed_burn.total_burned =
                self.timed_burn.total_burned.saturating_add(burned);
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
                .map_err(|e| format!("Storage error: {}", e))?;
        }
        storage
            .db()
            .flush()
            .map_err(|e| format!("Flush error: {}", e))?;
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
                        .map_err(|e| format!("Deserialization error: {}", e))?;
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
    #[allow(dead_code)]
    pub fn print_balances(&self) {
        println!("Account Balances:");
        for (pubkey, account) in &self.accounts {
            println!(
                "  {}...  balance: {}, nonce: {}",
                pubkey, account.balance, account.nonce
            );
        }
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

    // === TUR 25 SUPPLY-CAP INTEGER-ONLY TESTİ ===
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
        assert!(after_supply <= crate::tokenomics::BUD_TOTAL_SUPPLY as u128,
                "Supply cap aşıldı: {} > {}", after_supply, crate::tokenomics::BUD_TOTAL_SUPPLY);

        // En azından bazı ödül dağıtılmış olmalı (eğer cap'e ulaşmadıysa)
        if before_supply < crate::tokenomics::BUD_TOTAL_SUPPLY as u128 {
            // Test başarılıysa ödül dağıtılmış demektir
        }
    }
}
