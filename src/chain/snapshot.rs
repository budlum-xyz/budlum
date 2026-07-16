use crate::chain::finality::FinalityCert;
use crate::core::account::AccountState;
use crate::core::address::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub height: u64,
    pub block_hash: String,
    pub chain_id: u64,
    pub created_at: u128,
    pub balances: HashMap<Address, u64>,
    pub nonces: HashMap<Address, u64>,
    pub finalized_height: u64,
    pub finalized_hash: String,
    pub validators: HashMap<Address, crate::core::account::Validator>,
    pub snapshot_hash: String,
}
impl StateSnapshot {
    pub fn from_state(
        height: u64,
        block_hash: String,
        chain_id: u64,
        account_state: &AccountState,
        finalized_height: u64,
        finalized_hash: String,
    ) -> Self {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let balances = account_state.get_all_balances();
        let nonces = account_state.get_all_nonces();
        let validators = account_state.validators.clone().into_iter().collect();
        let mut snapshot = StateSnapshot {
            height,
            block_hash,
            chain_id,
            created_at,
            balances,
            nonces,
            finalized_height,
            finalized_hash,
            validators,
            snapshot_hash: String::new(),
        };
        snapshot.snapshot_hash = snapshot.calculate_hash();
        snapshot
    }
    fn calculate_hash(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.block_hash.as_bytes());
        hasher.update(self.chain_id.to_le_bytes());
        let mut balance_keys: Vec<_> = self.balances.keys().collect();
        balance_keys.sort();
        for key in balance_keys {
            hasher.update(key.0);
            hasher.update(self.balances[key].to_le_bytes());
        }
        let mut nonce_keys: Vec<_> = self.nonces.keys().collect();
        nonce_keys.sort();
        for key in nonce_keys {
            hasher.update(key.0);
            hasher.update(self.nonces[key].to_le_bytes());
        }
        let mut validator_keys: Vec<_> = self.validators.keys().collect();
        validator_keys.sort();
        for key in validator_keys {
            hasher.update(key.0);
            let v = &self.validators[key];
            hasher.update(v.stake.to_le_bytes());
            hasher.update([v.active as u8]);
            hasher.update([v.slashed as u8]);
            hasher.update([v.jailed as u8]);
            hasher.update(v.jail_until.to_le_bytes());
            hasher.update(&v.bls_public_key);
            hasher.update(&v.pop_signature);
            hasher.update(&v.pq_public_key);
        }
        hasher.update(self.finalized_height.to_le_bytes());
        hasher.update(self.finalized_hash.as_bytes());
        hex::encode(hasher.finalize())
    }
    pub fn verify(&self) -> bool {
        self.snapshot_hash == self.calculate_hash()
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        // Tur 11: fail-fast instead of silently serializing to empty bytes (a
        // corrupt persistence blob is worse than a panic). StateSnapshot is a
        // plain data type; a failure here is a deterministic bug.
        serde_json::to_vec(self).expect("BUG: StateSnapshot must serialize to_bytes")
    }
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(data).map_err(|e| format!("Failed to parse snapshot: {e}"))
    }
    pub fn size(&self) -> usize {
        self.to_bytes().len()
    }

    pub fn chunk(&self, chunk_size: usize) -> Vec<Vec<u8>> {
        let data = self.to_bytes();
        data.chunks(chunk_size).map(|c| c.to_vec()).collect()
    }
}
#[derive(Clone)]
pub struct PruningManager {
    pub min_blocks_to_keep: u64,
    pub snapshot_interval: u64,
    pub snapshot_dir: String,
}
impl PruningManager {
    pub fn new(min_blocks: u64, snapshot_interval: u64, snapshot_dir: String) -> Self {
        PruningManager {
            min_blocks_to_keep: min_blocks,
            snapshot_interval,
            snapshot_dir,
        }
    }
    pub fn should_create_snapshot(&self, height: u64) -> bool {
        height > 0 && height.is_multiple_of(self.snapshot_interval)
    }
    pub fn get_prunable_blocks(
        &self,
        chain_length: u64,
        latest_snapshot_height: u64,
        finalized_height: u64,
    ) -> Vec<u64> {
        if chain_length <= self.min_blocks_to_keep {
            return vec![];
        }
        let prune_up_to = chain_length.saturating_sub(self.min_blocks_to_keep);

        let safe_prune_up_to = prune_up_to
            .min(latest_snapshot_height)
            .min(finalized_height);
        if safe_prune_up_to == 0 {
            return vec![];
        }
        (1..safe_prune_up_to).collect()
    }
    pub fn save_snapshot(&self, snapshot: &StateSnapshot) -> Result<(), String> {
        use std::fs;
        use std::path::Path;
        let dir = Path::new(&self.snapshot_dir);
        if !dir.exists() {
            fs::create_dir_all(dir).map_err(|e| format!("Failed to create snapshot dir: {e}"))?;
        }
        let filename = format!("snapshot_{}.json", snapshot.height);
        let path = dir.join(filename);
        let data = serde_json::to_string_pretty(snapshot)
            .map_err(|e| format!("Failed to serialize snapshot: {e}"))?;
        fs::write(&path, data).map_err(|e| format!("Failed to write snapshot: {e}"))?;
        println!(
            "Snapshot saved: {} ({} accounts)",
            path.display(),
            snapshot.balances.len()
        );
        Ok(())
    }
    pub fn load_latest_snapshot(&self) -> Result<Option<StateSnapshot>, String> {
        use std::fs;
        use std::path::Path;
        let dir = Path::new(&self.snapshot_dir);
        if !dir.exists() {
            return Ok(None);
        }
        let mut snapshots: Vec<_> = fs::read_dir(dir)
            .map_err(|e| format!("Failed to read snapshot dir: {e}"))?
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .map(|e| e == "json")
                    .unwrap_or(false)
            })
            .collect();
        if snapshots.is_empty() {
            return Ok(None);
        }
        // Numerical sort by height
        snapshots.sort_by_key(|entry| {
            std::cmp::Reverse(get_snapshot_height(&entry.path()).unwrap_or(0))
        });
        let latest_path = snapshots[0].path();
        let data = fs::read_to_string(&latest_path)
            .map_err(|e| format!("Failed to read snapshot: {e}"))?;
        let snapshot: StateSnapshot = match serde_json::from_str(&data) {
            Ok(s) => s,
            Err(e) => {
                let mut quarantine_path = latest_path.clone();
                quarantine_path.set_extension("json.corrupted");
                let _ = fs::rename(&latest_path, &quarantine_path);
                return Err(format!("Failed to parse snapshot: {e}"));
            }
        };
        if !snapshot.verify() {
            let mut quarantine_path = latest_path.clone();
            quarantine_path.set_extension("json.corrupted");
            let _ = fs::rename(&latest_path, &quarantine_path);
            return Err("Snapshot integrity check failed".to_string());
        }
        println!("Loaded snapshot at height {}", snapshot.height);
        Ok(Some(snapshot))
    }

    pub fn save_snapshot_v2(&self, snapshot: &StateSnapshotV2) -> Result<(), String> {
        use std::fs;
        use std::path::Path;
        let dir = Path::new(&self.snapshot_dir);
        if !dir.exists() {
            fs::create_dir_all(dir).map_err(|e| format!("Failed to create snapshot dir: {e}"))?;
        }
        let filename = format!("snapshot_{}.json", snapshot.height);
        let path = dir.join(filename);
        let data = serde_json::to_string_pretty(snapshot)
            .map_err(|e| format!("Failed to serialize snapshot v2: {e}"))?;
        fs::write(&path, data).map_err(|e| format!("Failed to write snapshot v2: {e}"))?;
        println!(
            "Snapshot V2 saved: {} ({} accounts)",
            path.display(),
            snapshot.balances.len()
        );
        Ok(())
    }

    pub fn load_latest_snapshot_v2(&self) -> Result<Option<StateSnapshotV2>, String> {
        use std::fs;
        use std::path::Path;
        let dir = Path::new(&self.snapshot_dir);
        if !dir.exists() {
            return Ok(None);
        }
        let mut snapshots: Vec<_> = fs::read_dir(dir)
            .map_err(|e| format!("Failed to read snapshot dir: {e}"))?
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .map(|e| e == "json")
                    .unwrap_or(false)
            })
            .collect();
        if snapshots.is_empty() {
            return Ok(None);
        }
        // Numerical sort by height
        snapshots.sort_by_key(|entry| {
            std::cmp::Reverse(get_snapshot_height(&entry.path()).unwrap_or(0))
        });
        let latest_path = snapshots[0].path();
        let data = fs::read_to_string(&latest_path)
            .map_err(|e| format!("Failed to read snapshot: {e}"))?;
        let snapshot: StateSnapshotV2 = match serde_json::from_str(&data) {
            Ok(s) => s,
            Err(e) => {
                let mut quarantine_path = latest_path.clone();
                quarantine_path.set_extension("json.corrupted");
                let _ = fs::rename(&latest_path, &quarantine_path);
                return Err(format!("Failed to parse snapshot V2: {e}"));
            }
        };
        if !snapshot.verify() {
            let mut quarantine_path = latest_path.clone();
            quarantine_path.set_extension("json.corrupted");
            let _ = fs::rename(&latest_path, &quarantine_path);
            return Err("Snapshot V2 integrity check failed".to_string());
        }
        println!("Loaded snapshot V2 at height {}", snapshot.height);
        Ok(Some(snapshot))
    }
}

fn get_snapshot_height(path: &std::path::Path) -> Option<u64> {
    let stem = path.file_stem()?.to_str()?;
    let height_str = stem.strip_prefix("snapshot_")?;
    height_str.parse::<u64>().ok()
}

/// Oldest `StateSnapshotV2` schema that this binary will accept during the
/// staged ConsensusStateV2 migration window. Older snapshots must be restored
/// with an intermediate release first; silently accepting them would risk
/// losing registry/tokenomics metadata that was not present yet.
pub const MIN_SUPPORTED_STATE_SNAPSHOT_SCHEMA_VERSION: u32 = 2;

/// Current durable snapshot schema emitted by this binary. This is the
/// ConsensusStateV2 migration target for ADIM 2 §1.4.
pub const CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSnapshotV2MigrationReport {
    pub original_schema_version: u32,
    pub target_schema_version: u32,
    pub migrated: bool,
    pub requires_backup: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshotV2 {
    pub schema_version: u32,
    pub height: u64,
    pub block_hash: String,
    pub genesis_hash: String,
    pub chain_id: u64,
    pub created_at: u128,
    pub balances: HashMap<Address, u64>,
    pub nonces: HashMap<Address, u64>,
    pub finalized_height: u64,
    pub finalized_hash: String,
    pub validators: HashMap<Address, crate::core::account::Validator>,
    pub unbonding_queue: Vec<crate::core::account::UnbondingEntry>,
    pub finality_certificates: Vec<FinalityCert>,

    // ConsensusStateV2 fields:
    pub epoch_index: u64,
    pub last_epoch_time: u64,
    pub base_fee: u64,
    pub block_reward: u64,
    pub bridge_root: [u8; 32],
    pub message_root: [u8; 32],
    pub settlement_root: [u8; 32],
    pub global_header_summary: [u8; 32],

    // --- schema_version 3 (Tur 9): previously-unpersisted state. All
    // `#[serde(default)]` so schema-2 snapshots still deserialize (the fields
    // simply come back empty/None — meaning "this feature wasn't active when the
    // snapshot was taken", not data loss).
    //
    // TUR 2 GHOST-HUNTING NOTE: `registry`, `liveness`, and `invalid_votes`
    // are NO LONGER persisted on `StateSnapshotV2` because the corresponding
    // fields were removed from `AccountState` (the permissionless-registry
    // feature is being unwound). They are intentionally NOT round-tripped:
    // any caller that needs the live registry state must rebuild it from the
    // chain via `submit_slashing_evidence` / `submit_registry_slashing_report`
    // (those paths now return a "removed" error, see `blockchain.rs`). The
    // `#[serde(default)]` on the (now removed) fields is gone, so V2
    // snapshots written by older builds still deserialize cleanly (the missing
    // fields are filled with `Default`).
    /// $BUD tokenomics parameters. NOTE: this is the source of truth for
    /// `block_reward` in the current build; the top-level `block_reward`
    /// field is kept for wire compatibility but is written from
    /// `account_state.tokenomics.block_reward`.
    #[serde(default)]
    pub tokenomics: crate::tokenomics::TokenomicsParams,
    /// Tokenomics restore block (MUST restore together — see below). The timed
    /// reserve burn counter, the reserve account and team vesting are one atomic
    /// unit: restoring the burn counter without the reserve address (or vice
    /// versa) would risk double-burning already-burned reserve. Kept as a single
    /// optional struct so they can never be split.
    #[serde(default)]
    pub tokenomics_burn: Option<TokenomicsBurnSnapshot>,

    // --- Tur 5: permissionless-registry persistence ---
    //
    // The Tur-2 ghost-hunting pass removed the `registry` / `liveness` /
    // `invalid_votes` fields from `AccountState` and (briefly) from this
    // snapshot. The Tur-5 redesign reinstates them on `AccountState` and
    // also round-trips them through the V2 snapshot so that liveness
    // counters and registry membership survive a restart. `#[serde(default)]`
    // keeps pre-Tur-5 V2 snapshots compatible: their `None` values get
    // materialized as the empty registry/tracker on load.
    #[serde(default)]
    pub registry: Option<crate::registry::PermissionlessRegistry>,
    #[serde(default)]
    pub liveness: Option<crate::registry::LivenessTracker>,
    #[serde(default)]
    pub invalid_votes: Option<crate::registry::InvalidVoteTracker>,

    // --- ADIM6 BNS/NFT/Hub/Marketplace persistence (ARENA3 audit: Q check_snapshot)
    // BNS registry was previously NOT round-tripped, so names were lost on restart from snapshot.
    // Now persisted with #[serde(default)] for backwards compatibility (old snapshots -> empty).
    #[serde(default)]
    pub bns_registry: Option<crate::bns::BnsRegistry>,
    #[serde(default)]
    pub nft_registry: Option<crate::nft::NftRegistry>,
    #[serde(default)]
    pub marketplace: Option<crate::marketplace::MarketplaceRegistry>,
    #[serde(default)]
    pub hub: Option<crate::hub::HubRegistry>,
    #[serde(default)]
    pub external_roots:
        Option<BTreeMap<crate::domain::types::DomainId, crate::domain::types::Hash32>>,

    pub snapshot_hash: String,
}

/// Atomic tokenomics-burn restore block (Tur 9, Decision 2.3). These three
/// values are ALWAYS captured and restored together to avoid double-burning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenomicsBurnSnapshot {
    pub timed_burn: crate::tokenomics::TimedBurnState,
    pub burn_reserve_address: Option<Address>,
    pub team_vesting: Option<(Address, crate::tokenomics::VestingSchedule)>,
}

pub struct StateSnapshotV2Params {
    pub height: u64,
    pub block_hash: String,
    pub genesis_hash: String,
    pub chain_id: u64,
    pub finalized_height: u64,
    pub finalized_hash: String,
    pub finality_certificates: Vec<FinalityCert>,
}

impl StateSnapshotV2 {
    pub fn from_state(account_state: &AccountState, params: StateSnapshotV2Params) -> Self {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let balances = account_state.get_all_balances();
        let nonces = account_state.get_all_nonces();
        let validators = account_state.validators.clone().into_iter().collect();
        let unbonding_queue = account_state.unbonding_queue.clone();

        // Capture the tokenomics burn block atomically (Tur 9).
        let tokenomics_burn = Some(TokenomicsBurnSnapshot {
            timed_burn: account_state.timed_burn.clone(),
            burn_reserve_address: account_state.burn_reserve_address,
            team_vesting: account_state.team_vesting,
        });

        let mut snapshot = StateSnapshotV2 {
            schema_version: CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION,
            height: params.height,
            block_hash: params.block_hash,
            genesis_hash: params.genesis_hash,
            chain_id: params.chain_id,
            created_at,
            balances,
            nonces,
            finalized_height: params.finalized_height,
            finalized_hash: params.finalized_hash,
            validators,
            unbonding_queue,
            finality_certificates: params.finality_certificates,
            epoch_index: account_state.epoch_index,
            last_epoch_time: account_state.last_epoch_time,
            base_fee: account_state.base_fee,
            // `block_reward` is read from the tokenomics module (the top-level
            // `state.block_reward` field no longer exists; see
            // `genesis.rs::build_state` and the Tur 2 tokenomics refactor).
            // We mirror the value here for wire-compat with older consumers
            // that still expect a top-level `block_reward` field.
            block_reward: account_state.tokenomics.block_reward,
            bridge_root: account_state.bridge_root,
            message_root: account_state.message_root,
            settlement_root: account_state.settlement_root,
            global_header_summary: account_state.global_header_summary,
            bns_registry: Some(account_state.bns_registry.clone()),
            nft_registry: Some(account_state.nft_registry.clone()),
            marketplace: Some(account_state.marketplace.clone()),
            hub: Some(account_state.hub.clone()),
            external_roots: Some(account_state.external_roots.clone()),
            // Tur 2: `registry`, `liveness`, and `invalid_votes` are no longer
            // fields on `AccountState` (ghost-hunted). The struct fields were
            // already removed above; the live state is recovered by routing
            // any registry-touching calls through their "removed" mocks in
            // `blockchain.rs` / `chain_actor.rs`.
            tokenomics: account_state.tokenomics,
            tokenomics_burn,
            // Tur 5: round-trip the permissionless registry + liveness +
            // invalid-vote tracker so that liveness counters and registered
            // members survive a snapshot/restore cycle.
            registry: Some(account_state.registry.clone()),
            liveness: Some(account_state.liveness.clone()),
            invalid_votes: Some(account_state.invalid_votes.clone()),
            snapshot_hash: String::new(),
        };
        snapshot.snapshot_hash = snapshot.calculate_hash();
        snapshot
    }

    fn calculate_hash(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(self.schema_version.to_le_bytes());
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.block_hash.as_bytes());
        hasher.update(self.genesis_hash.as_bytes());
        hasher.update(self.chain_id.to_le_bytes());

        let mut balance_keys: Vec<_> = self.balances.keys().collect();
        balance_keys.sort();
        for key in balance_keys {
            hasher.update(key.0);
            hasher.update(self.balances[key].to_le_bytes());
        }

        let mut nonce_keys: Vec<_> = self.nonces.keys().collect();
        nonce_keys.sort();
        for key in nonce_keys {
            hasher.update(key.0);
            hasher.update(self.nonces[key].to_le_bytes());
        }

        let mut validator_keys: Vec<_> = self.validators.keys().collect();
        validator_keys.sort();
        for key in validator_keys {
            hasher.update(key.0);
            let v = &self.validators[key];
            hasher.update(v.stake.to_le_bytes());
            hasher.update([v.active as u8]);
            hasher.update([v.slashed as u8]);
            hasher.update([v.jailed as u8]);
            hasher.update(v.jail_until.to_le_bytes());
            hasher.update(&v.bls_public_key);
            hasher.update(&v.pop_signature);
            hasher.update(&v.pq_public_key);
        }

        for entry in &self.unbonding_queue {
            hasher.update(entry.address.0);
            hasher.update(entry.amount.to_le_bytes());
            hasher.update(entry.release_epoch.to_le_bytes());
        }

        hasher.update(self.finalized_height.to_le_bytes());
        hasher.update(self.finalized_hash.as_bytes());

        hasher.update(self.epoch_index.to_le_bytes());
        hasher.update(self.last_epoch_time.to_le_bytes());
        hasher.update(self.base_fee.to_le_bytes());
        hasher.update(self.block_reward.to_le_bytes());
        hasher.update(self.bridge_root);
        hasher.update(self.message_root);
        hasher.update(self.settlement_root);
        hasher.update(self.global_header_summary);

        hex::encode(hasher.finalize())
    }

    pub fn verify(&self) -> bool {
        self.snapshot_hash == self.calculate_hash()
    }

    /// Fallible serialization for the durable snapshot-production path (Tur 11):
    /// surfaces a serialization error to the caller instead of silently writing
    /// an empty/corrupt snapshot. This is the exact failure class that hid the
    /// Tur-9 registry tuple-key bug.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| format!("Failed to serialize snapshot V2: {e}"))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // Tur 11: fail-fast rather than silently produce empty bytes. StateSnapshotV2
        // is a plain data type post-Tur-9 (no tuple-key maps), so failure is a bug.
        self.try_to_bytes()
            .expect("BUG: StateSnapshotV2 must serialize to_bytes")
    }

    /// Produce the staged migration report used by the offline
    /// `--migrate-v2` gate and by tests. ADIM 2 §1.4 deliberately keeps this
    /// as a *skeleton*: supported schema-2 snapshots deserialize through
    /// `#[serde(default)]` fields and are rewritten as schema 3 by
    /// `from_state`; unsupported versions fail closed instead of being guessed.
    pub fn migration_report(&self) -> Result<StateSnapshotV2MigrationReport, String> {
        if self.schema_version < MIN_SUPPORTED_STATE_SNAPSHOT_SCHEMA_VERSION {
            return Err(format!(
                "Unsupported legacy snapshot schema_version {} (minimum supported is {}; staged migration hook rejected)",
                self.schema_version, MIN_SUPPORTED_STATE_SNAPSHOT_SCHEMA_VERSION
            ));
        }
        if self.schema_version > CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION {
            return Err(format!(
                "Unsupported future snapshot schema_version {} (current max supported is {}; staged migration hook rejected)",
                self.schema_version, CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION
            ));
        }

        let mut notes = Vec::new();
        if self.schema_version < CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION {
            notes.push(
                "schema-2 snapshot accepted through serde defaults; rewrite through current binary to persist schema-3 registry/liveness/tokenomics fields".to_string(),
            );
        } else {
            notes.push("snapshot already at current schema".to_string());
        }

        Ok(StateSnapshotV2MigrationReport {
            original_schema_version: self.schema_version,
            target_schema_version: CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION,
            migrated: self.schema_version < CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION,
            requires_backup: true,
            notes,
        })
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        let snapshot: StateSnapshotV2 = serde_json::from_slice(data)
            .map_err(|e| format!("Failed to parse snapshot V2: {e}"))?;
        snapshot.migration_report()?;
        Ok(snapshot)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_snapshot_creation() {
        let account_state = AccountState::new();
        let snapshot = StateSnapshot::from_state(
            100,
            "blockhash123".to_string(),
            1337,
            &account_state,
            0,
            "genhash".to_string(),
        );
        assert_eq!(snapshot.height, 100);
        assert_eq!(snapshot.chain_id, 1337);
        assert!(!snapshot.snapshot_hash.is_empty());
    }
    #[test]
    fn test_snapshot_verify() {
        let account_state = AccountState::new();
        let snapshot = StateSnapshot::from_state(
            50,
            "hash".to_string(),
            42,
            &account_state,
            10,
            "finalhash".to_string(),
        );
        assert!(snapshot.verify());
    }
    #[test]
    fn test_pruning_manager() {
        let manager = PruningManager::new(100, 1000, "./snapshots".to_string());

        let prunable = manager.get_prunable_blocks(50, 0, 0);
        assert!(prunable.is_empty());

        let prunable = manager.get_prunable_blocks(200, 50, 50);
        assert_eq!(prunable.len(), 49);
    }
    #[test]
    fn test_snapshot_interval() {
        let manager = PruningManager::new(100, 1000, "./snapshots".to_string());
        assert!(!manager.should_create_snapshot(0));
        assert!(!manager.should_create_snapshot(500));
        assert!(manager.should_create_snapshot(1000));
        assert!(manager.should_create_snapshot(2000));
    }

    #[test]
    fn test_snapshot_v2_creation_and_numerical_sorting() {
        let account_state = AccountState::new();
        let snapshot_v2 = StateSnapshotV2::from_state(
            &account_state,
            StateSnapshotV2Params {
                height: 105,
                block_hash: "block_hash_v2".to_string(),
                genesis_hash: "genesis_hash_v2".to_string(),
                chain_id: 42,
                finalized_height: 50,
                finalized_hash: "finalized_hash_v2".to_string(),
                finality_certificates: vec![],
            },
        );

        assert_eq!(
            snapshot_v2.schema_version,
            CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION
        ); // Tur 9: bumped 2->3
        assert_eq!(snapshot_v2.height, 105);
        assert!(snapshot_v2.verify());

        let bytes = snapshot_v2.to_bytes();
        let deserialized = StateSnapshotV2::from_bytes(&bytes).unwrap();
        assert_eq!(deserialized.height, 105);
        assert_eq!(
            deserialized.schema_version,
            CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION
        ); // Tur 9: bumped 2->3
        assert!(deserialized.verify());

        // Test numerical sorting helper
        let path1 = std::path::Path::new("snapshot_100.json");
        let path2 = std::path::Path::new("snapshot_9.json");
        assert_eq!(get_snapshot_height(path1).unwrap(), 100);
        assert_eq!(get_snapshot_height(path2).unwrap(), 9);
    }

    #[test]
    fn test_snapshot_quarantine() {
        use std::fs;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let manager = PruningManager::new(100, 1000, dir.path().to_str().unwrap().to_string());

        // 1. Create a dummy corrupted snapshot file
        let path = dir.path().join("snapshot_50.json");
        fs::write(&path, "corrupted JSON data").unwrap();

        // 2. Try loading it
        let res = manager.load_latest_snapshot();
        assert!(res.is_err());

        // 3. Verify it was quarantined (renamed to snapshot_50.json.corrupted)
        let quarantined_path = dir.path().join("snapshot_50.json.corrupted");
        assert!(quarantined_path.exists());
        assert!(!path.exists());
    }

    #[test]
    fn test_snapshot_v2_migration_hook_rejects_unsupported_versions() {
        let account_state = AccountState::new();
        let mut snapshot = StateSnapshotV2::from_state(
            &account_state,
            StateSnapshotV2Params {
                height: 1,
                block_hash: "h".into(),
                genesis_hash: "g".into(),
                chain_id: 1,
                finalized_height: 0,
                finalized_hash: "".into(),
                finality_certificates: vec![],
            },
        );

        snapshot.schema_version = 1;
        let bytes_v1 = serde_json::to_vec(&snapshot).unwrap();
        assert!(StateSnapshotV2::from_bytes(&bytes_v1)
            .unwrap_err()
            .contains("minimum supported is 2"));

        snapshot.schema_version = 99;
        let bytes_v99 = serde_json::to_vec(&snapshot).unwrap();
        assert!(StateSnapshotV2::from_bytes(&bytes_v99)
            .unwrap_err()
            .contains("current max supported is 3"));

        snapshot.schema_version = 2;
        let report = snapshot.migration_report().unwrap();
        assert_eq!(report.original_schema_version, 2);
        assert_eq!(
            report.target_schema_version,
            CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION
        );
        assert!(report.migrated);
        assert!(report.requires_backup);
        assert!(report.notes[0].contains("schema-2 snapshot accepted"));

        snapshot.schema_version = CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION;
        let bytes_current = serde_json::to_vec(&snapshot).unwrap();
        let current = StateSnapshotV2::from_bytes(&bytes_current).unwrap();
        let report = current.migration_report().unwrap();
        assert!(!report.migrated);
        assert!(report.notes[0].contains("already at current schema"));
    }
}
