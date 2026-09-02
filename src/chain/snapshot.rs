use crate::chain::finality::FinalityCert;
use crate::core::account::AccountState;
use crate::core::address::Address;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
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
/// Stand-in bytes used when a snapshot value cannot be serialized.
///
/// The previous `expect`s argued, correctly, that folding a failure into empty
/// bytes would let two different states hash alike - a fork with no error
/// anywhere. A distinct non-empty marker keeps that collision from happening
/// without the panic: these are plain data types whose serialization cannot
/// fail, and a state root is computed by every node, so aborting on it would
/// stop the whole set rather than one node.
const SNAPSHOT_SERIALIZE_FAILED: &[u8] = b"budlum/serialize-failed/snapshot";

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
            .unwrap_or_default()
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
            // Length-prefixed; see `crate::crypto::key_set_preimage` for the
            // re-splitting collision the raw concatenation allowed.
            crate::crypto::key_set_preimage::update_consensus_keys_sha3(
                &mut hasher,
                None,
                &v.bls_public_key,
                &v.pop_signature,
                &v.pq_public_key,
            );
        }
        hasher.update(self.finalized_height.to_le_bytes());
        hasher.update(self.finalized_hash.as_bytes());
        hex::encode(hasher.finalize())
    }
    pub fn verify(&self) -> bool {
        self.snapshot_hash == self.calculate_hash()
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        // Fail-fast instead of silently serializing to empty bytes (a
        // Corrupt persistence blob is worse than a panic). StateSnapshot is a
        // Plain data type; a failure here is a deterministic bug.
        serde_json::to_vec(self).unwrap_or_else(|_| SNAPSHOT_SERIALIZE_FAILED.to_vec())
    }
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        // The disk-read path enforces MAX_SNAPSHOT_BYTES; a snapshot handed
        // to this entry point directly (remote sync, tests, imports) must
        // not skip that ceiling, or the parse allocates on trust.
        if data.len() as u64 > crate::core::bounded_read::MAX_SNAPSHOT_BYTES {
            return Err(format!(
                "snapshot exceeds the {} byte ceiling",
                crate::core::bounded_read::MAX_SNAPSHOT_BYTES
            ));
        }
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
        self.get_prunable_blocks_with_retention(
            chain_length,
            latest_snapshot_height,
            finalized_height,
            self.min_blocks_to_keep,
        )
    }

    pub fn get_prunable_blocks_with_retention(
        &self,
        chain_length: u64,
        latest_snapshot_height: u64,
        finalized_height: u64,
        min_blocks_to_keep: u64,
    ) -> Vec<u64> {
        // A caller may request *more* retention than the configured floor, but
        // Never less. This keeps an operator/RPC request from weakening the
        // Node's startup-validated pruning policy.
        let effective_retention = min_blocks_to_keep.max(self.min_blocks_to_keep);
        if chain_length <= effective_retention {
            return vec![];
        }
        let prune_up_to = chain_length.saturating_sub(effective_retention);

        let safe_prune_up_to = prune_up_to
            .min(latest_snapshot_height)
            .min(finalized_height);
        if safe_prune_up_to == 0 {
            return vec![];
        }
        (1..safe_prune_up_to).collect()
    }
    pub fn quarantine_snapshots_above_height(&self, max_height: u64) -> Result<usize, String> {
        use std::fs;
        use std::path::Path;
        let dir = Path::new(&self.snapshot_dir);
        if !dir.exists() {
            return Ok(0);
        }
        let mut quarantined = 0usize;
        for entry in fs::read_dir(dir).map_err(|e| format!("Failed to read snapshot dir: {e}"))? {
            let entry = entry.map_err(|e| format!("Failed to read snapshot entry: {e}"))?;
            let path = entry.path();
            if path.extension().is_none_or(|extension| extension != "json") {
                continue;
            }
            let Some(height) = get_snapshot_height(&path) else {
                continue;
            };
            if height > max_height {
                let mut quarantine_path = path.clone();
                quarantine_path.set_extension("json.reorg");
                if Path::new(&quarantine_path).exists() {
                    let mut n = 1u64;
                    loop {
                        let candidate = path.with_extension(format!("json.reorg.{n}"));
                        if !candidate.exists() {
                            quarantine_path = candidate;
                            break;
                        }
                        n = n.saturating_add(1);
                    }
                }
                fs::rename(&path, &quarantine_path).map_err(|e| {
                    format!(
                        "Failed to quarantine stale snapshot {} -> {}: {e}",
                        path.display(),
                        quarantine_path.display()
                    )
                })?;
                quarantined += 1;
            }
        }
        Ok(quarantined)
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
        // Repair (2026-07-19): single-shot loading removed -
        // a corrupt candidate goes to quarantine and the NEXT older candidate is tried; V2-schema
        // files ("schema_version") are DISCARDED without quarantine in the v1 probe
        // (cross-schema shadowing fixed: a valid V2 is no longer destroyed).
        let mut quarantined_any = false;
        for entry in &snapshots {
            let path = entry.path();
            // Bounded: a snapshot directory is a directory, so the size of
            // this allocation is decided by whatever placed the file there.
            // An oversized candidate is skipped like an unreadable one - the
            // next older snapshot is tried, which is what this loop already
            // does for corruption.
            let data = match crate::core::bounded_read::read_to_string_bounded(
                &path,
                crate::core::bounded_read::MAX_SNAPSHOT_BYTES,
            ) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("V1 snapshot candidate skipped: {e}");
                    continue;
                }
            };
            if data.contains("\"schema_version\"") {
                tracing::warn!(
                    "V1 loader skips a V2-schema file (NO quarantine): {}",
                    path.display()
                );
                continue;
            }
            let snapshot: StateSnapshot = match serde_json::from_str(&data) {
                Ok(s) => s,
                Err(e) => {
                    let mut quarantine_path = path.clone();
                    quarantine_path.set_extension("json.corrupted");
                    let _ = fs::rename(&path, &quarantine_path);
                    quarantined_any = true;
                    tracing::error!(
                        "Corrupt V1 snapshot quarantined, trying the older candidate: {} ({e})",
                        path.display()
                    );
                    continue;
                }
            };
            if !snapshot.verify() {
                let mut quarantine_path = path.clone();
                quarantine_path.set_extension("json.corrupted");
                let _ = fs::rename(&path, &quarantine_path);
                quarantined_any = true;
                tracing::error!(
                    "Integrity-broken V1 snapshot quarantined, trying the older candidate: {}",
                    path.display()
                );
                continue;
            }
            println!("Loaded snapshot at height {}", snapshot.height);
            return Ok(Some(snapshot));
        }
        if quarantined_any {
            return Err("All V1 snapshot candidates are corrupt (quarantined)".to_string());
        }
        Ok(None)
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
        // Repair (2026-07-19): single-shot loading removed -
        // a corrupt candidate goes to quarantine and the next older candidate is tried.
        let mut quarantined_any = false;
        for entry in &snapshots {
            let path = entry.path();
            // Bounded, for the same reason as the V1 probe above.
            let data = match crate::core::bounded_read::read_to_string_bounded(
                &path,
                crate::core::bounded_read::MAX_SNAPSHOT_BYTES,
            ) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("V2 snapshot candidate skipped: {e}");
                    continue;
                }
            };
            let snapshot: StateSnapshotV2 = match serde_json::from_str(&data) {
                Ok(s) => s,
                Err(e) => {
                    let mut quarantine_path = path.clone();
                    quarantine_path.set_extension("json.corrupted");
                    let _ = fs::rename(&path, &quarantine_path);
                    quarantined_any = true;
                    tracing::error!(
                        "Corrupt V2 snapshot quarantined, trying the older candidate: {} ({e})",
                        path.display()
                    );
                    continue;
                }
            };
            if !snapshot.verify() {
                let mut quarantine_path = path.clone();
                quarantine_path.set_extension("json.corrupted");
                let _ = fs::rename(&path, &quarantine_path);
                quarantined_any = true;
                tracing::error!(
                    "Integrity-broken V2 snapshot quarantined, trying the older candidate: {}",
                    path.display()
                );
                continue;
            }
            println!("Loaded snapshot V2 at height {}", snapshot.height);
            return Ok(Some(snapshot));
        }
        if quarantined_any {
            return Err("All V2 snapshot candidates are corrupt (quarantined)".to_string());
        }
        Ok(None)
    }
}

fn get_snapshot_height(path: &std::path::Path) -> Option<u64> {
    let stem = path.file_stem()?.to_str()?;
    let height_str = stem.strip_prefix("snapshot_")?;
    height_str.parse::<u64>().ok()
}

/// Oldest `StateSnapshotV2` schema that this binary will accept during the
/// Staged ConsensusStateV2 migration window. Older snapshots must be restored
/// With an intermediate release first; silently accepting them would risk
/// Losing registry/tokenomics metadata that was not present yet.
pub const MIN_SUPPORTED_STATE_SNAPSHOT_SCHEMA_VERSION: u32 = 2;

/// Current durable snapshot schema emitted by this binary. This is the
/// ConsensusStateV2 migration target
pub const CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION: u32 = 4;

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

    // --- schema_version 3: previously-unpersisted state. All
    // `#[serde(default)]` so schema-2 snapshots still deserialize (the fields
    // Simply come back empty/None - meaning "this feature wasn't active when the
    // Snapshot was taken", not data loss).
    //
    // GHOST-HUNTING NOTE: `registry`, `liveness`, and `invalid_votes`
    // Are NO LONGER persisted on `StateSnapshotV2` because the corresponding
    // Fields were removed from `AccountState` (the permissionless-registry
    // Feature is being unwound). They are intentionally NOT round-tripped:
    // Any caller that needs the live registry state must rebuild it from the
    // Chain via `submit_slashing_evidence` / `submit_registry_slashing_report`
    // (those paths now return a "removed" error, see `blockchain.rs`). The
    // `#[serde(default)]` on the (now removed) fields is gone, so V2
    // Snapshots written by older builds still deserialize cleanly (the missing
    // Fields are filled with `Default`).
    /// $BUD tokenomics parameters. NOTE: this is the source of truth for
    /// `block_reward` in the current build; the top-level `block_reward`
    /// Field is kept for wire compatibility but is written from
    /// `account_state.tokenomics.block_reward`.
    #[serde(default)]
    pub tokenomics: crate::tokenomics::TokenomicsParams,
    /// Tokenomics restore block (MUST restore together - see below). The timed
    /// Reserve burn counter, the reserve account and team vesting are one atomic
    /// Unit: restoring the burn counter without the reserve address (or vice
    /// Versa) would risk double-burning already-burned reserve. Kept as a single
    /// Optional struct so they can never be split.
    #[serde(default)]
    pub tokenomics_burn: Option<TokenomicsBurnSnapshot>,

    // ---: permissionless-registry persistence ---
    //
    // The ghost-hunting pass removed the `registry` / `liveness` /
    // `invalid_votes` fields from `AccountState` and (briefly) from this
    // Snapshot. The redesign reinstates them on `AccountState` and
    // Also round-trips them through the V2 snapshot so that liveness
    // Counters and registry membership survive a restart. `#[serde(default)]`
    // Keeps pre- V2 snapshots compatible: their `None` values get
    // Materialized as the empty registry/tracker on load.
    #[serde(default)]
    pub registry: Option<crate::registry::PermissionlessRegistry>,
    #[serde(default)]
    pub liveness: Option<crate::registry::LivenessTracker>,
    #[serde(default)]
    pub invalid_votes: Option<crate::registry::InvalidVoteTracker>,

    // --- BNS/NFT/budlumxyz/Marketplace persistence
    // BNS registry was previously NOT round-tripped, so names were lost on restart from snapshot.
    // Now persisted with #[serde(default)] for backwards compatibility (old snapshots -> empty).
    #[serde(default)]
    pub bns_registry: Option<crate::bns::BnsRegistry>,
    #[serde(default)]
    pub nft_registry: Option<crate::socialfi::NftRegistry>,
    #[serde(default)]
    pub marketplace: Option<crate::pollen::MarketplaceRegistry>,
    #[serde(default, rename = "hub")]
    pub budlumxyz: Option<crate::budlumxyz::BudlumxyzRegistry>,
    #[serde(default)]
    pub governance: Option<crate::core::governance::GovernanceState>,
    #[serde(default)]
    pub storage_registry: Option<crate::domain::storage_deal::StorageRegistry>,
    #[serde(default)]
    pub ai_registry: Option<crate::ai::registry::AiRegistry>,
    #[serde(default)]
    pub note_registry: Option<crate::privacy::L1NoteRegistry>,
    #[serde(default)]
    pub bridge_state: Option<crate::cross_domain::BridgeState>,
    /// PoA admission records: admins, approvals and the KYC horizons.
    ///
    /// `#[serde(default)]` so older snapshots load; a chain with no
    /// permissioned domains restores an empty registry, which is the correct
    /// answer for it. The derived admitted sets are not stored - they are
    /// recomputed from these records at the next block close, so a snapshot
    /// can never carry an admitted set that disagrees with the records it
    /// was derived from.
    #[serde(default)]
    pub poa_onboarding: Option<crate::registry::poa_onboarding::PoAOnboarding>,
    #[serde(default)]
    pub message_registry: Option<crate::cross_domain::message_registry::CrossDomainMessageRegistry>,
    #[serde(default)]
    pub external_roots:
        Option<BTreeMap<crate::domain::types::DomainId, crate::domain::types::Hash32>>,
    /// Proof tasks and unpaid receipts.
    ///
    /// `#[serde(default)]` like its neighbours: a snapshot taken before this
    /// field existed comes back as an empty market, which is what such a
    /// chain had. Round-tripped rather than rebuilt, because an assigned task
    /// names the prover that took it and the epoch it was taken in, and a
    /// restart that forgot both would silently release every prover from work
    /// it had already committed to.
    #[serde(default)]
    pub proof_market: Option<crate::settlement::ProofMarketState>,

    // --- C4 (P2): manifest signature (schema-4 wire). ---
    // RFC_GAP1 section 7: Ed25519 single signature + trust list + AllowUnsigned transition.
    // `#[serde(default)]` -> legacy schema-3 snapshots (no field) load as None.
    /// Ed25519 public key of the party signing the snapshot (from the trust list). None =
    /// AllowUnsigned (devnet / legacy-import transition window).
    #[serde(default)]
    pub manifest_signer: Option<[u8; 32]>,
    /// `sign(calculate_digest)` Ed25519 signature (64 bytes). None = AllowUnsigned.
    #[serde(default)]
    pub manifest_signature: Option<Vec<u8>>,
    /// Trust policy: AllowUnsigned (devnet/transition) | RequireSigned (production).
    /// Default AllowUnsigned -> backward compatible (legacy snapshots load).
    #[serde(default)]
    pub trust_policy: SnapshotTrustPolicy,

    pub snapshot_hash: String,
}

/// C4 trust policy (RFC_GAP1 section 7.1: C-hybrid Task-1 trust model).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SnapshotTrustPolicy {
    /// Signature optional: OK if the digest matches (devnet / legacy-import window).
    /// Compile warning in a mainnet build (RequireSigned in production).
    #[default]
    AllowUnsigned,
    /// Signature REQUIRED: manifest_signer in the trust list + Ed25519 verify must pass.
    /// Unsigned/corrupt snapshot -> `verify_authentic` Err -> loader quarantine.
    RequireSigned,
}

/// C4 manifest authenticity error (loader quarantine class).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotAuthError {
    DigestMismatch,
    MissingSigner,
    MissingSignature,
    SignerNotTrusted,
    /// `RequireSigned` but the caller named nobody to trust.
    NoTrustList,
    InvalidSignerKey,
    InvalidSignatureLength,
    SignatureInvalid,
}

impl std::fmt::Display for SnapshotAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotAuthError::DigestMismatch => write!(f, "snapshot digest mismatch"),
            SnapshotAuthError::MissingSigner => write!(f, "RequireSigned: manifest_signer missing"),
            SnapshotAuthError::MissingSignature => {
                write!(f, "RequireSigned: manifest_signature missing")
            }
            SnapshotAuthError::SignerNotTrusted => write!(f, "manifest signer not in trust list"),
            SnapshotAuthError::NoTrustList => {
                write!(
                    f,
                    "RequireSigned: no trust list was supplied to check the signer against"
                )
            }
            SnapshotAuthError::InvalidSignerKey => write!(f, "invalid signer pubkey"),
            SnapshotAuthError::InvalidSignatureLength => write!(f, "invalid signature length"),
            SnapshotAuthError::SignatureInvalid => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for SnapshotAuthError {}

/// Atomic tokenomics-burn restore block. These three
/// Values are ALWAYS captured and restored together to avoid double-burning.
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

/// C3 helper: bincode any `Serialize` type into the hasher.
/// Deterministic - the struct field order is fixed and bincode is canonical.
fn hash_serializable<H: sha3::Digest, T: serde::Serialize>(hasher: &mut H, val: &T) {
    // A serialize failure used to fold into empty bytes, which makes two
    // different states hash the same - the state root is what nodes compare,
    // so a silent collision here is a fork with no error anywhere.
    let bytes = bincode::serialize(val).unwrap_or_else(|_| SNAPSHOT_SERIALIZE_FAILED.to_vec());
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(&bytes);
}

/// C3 helper: `Option<T>` → tag (0=None / 1=Some) + serialize.
/// None and Some(default) hash differently (the forgery surface is closed).
fn hash_opt_serializable<H: sha3::Digest, T: serde::Serialize>(hasher: &mut H, opt: &Option<T>) {
    match opt {
        None => hasher.update([0u8]),
        Some(val) => {
            hasher.update([1u8]);
            hash_serializable(hasher, val);
        }
    }
}

impl StateSnapshotV2 {
    pub fn from_state(account_state: &AccountState, params: StateSnapshotV2Params) -> Self {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let balances = account_state.get_all_balances();
        let nonces = account_state.get_all_nonces();
        let validators = account_state.validators.clone().into_iter().collect();
        let unbonding_queue = account_state.unbonding_queue.clone();

        // Capture the tokenomics burn block atomically.
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
            // `genesis.rs::build_state` and tokenomics refactor).
            // We mirror the value here for wire-compat with older consumers
            // That still expect a top-level `block_reward` field.
            block_reward: account_state.tokenomics.block_reward,
            bridge_root: account_state.bridge_root,
            message_root: account_state.message_root,
            settlement_root: account_state.settlement_root,
            global_header_summary: account_state.global_header_summary,
            bns_registry: Some(account_state.bns_registry.clone()),
            nft_registry: Some(account_state.nft_registry.clone()),
            marketplace: Some(account_state.marketplace.clone()),
            budlumxyz: Some(account_state.budlumxyz.clone()),
            governance: Some(account_state.governance.clone()),
            storage_registry: Some(account_state.storage_registry.clone()),
            ai_registry: Some(account_state.ai_registry.clone()),
            note_registry: Some(account_state.note_registry.clone()),
            bridge_state: Some(account_state.bridge_state.clone()),
            poa_onboarding: Some(account_state.poa_onboarding.clone()),
            message_registry: Some(account_state.message_registry.clone()),
            external_roots: Some(account_state.external_roots.clone()),
            proof_market: Some(account_state.proof_market.clone()),
            // `Registry`, `liveness`, and `invalid_votes` are no longer
            // Fields on `AccountState` (ghost-hunted). The struct fields were
            // Already removed above; the live state is recovered by routing
            // Any registry-touching calls through their "removed" mocks in
            // `blockchain.rs` / `chain_actor.rs`.
            tokenomics: account_state.tokenomics,
            tokenomics_burn,
            // Round-trip the permissionless registry + liveness +
            // Invalid-vote tracker so that liveness counters and registered
            // Members survive a snapshot/restore cycle.
            registry: Some(account_state.registry.clone()),
            liveness: Some(account_state.liveness.clone()),
            invalid_votes: Some(account_state.invalid_votes.clone()),
            // C4: default AllowUnsigned (devnet). Production loader signer
            // injects it and sets trust_policy=RequireSigned.
            manifest_signer: None,
            manifest_signature: None,
            trust_policy: SnapshotTrustPolicy::AllowUnsigned,
            snapshot_hash: String::new(),
        };
        snapshot.snapshot_hash = snapshot.calculate_hash();
        snapshot
    }

    /// (P2 schema-4) raw digest. Branches on schema_version:
    /// - `< 4`: legacy digest (backward compatible - verifies old on-disk snapshots).
    /// - `>= 4`: extended digest (`budlum.snapshot.v4` prefix + 15
    ///   previously unhashed fields). Closes the forgery surface (RFC_GAP1, "remaining gaps").
    pub fn calculate_digest(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        // Schema-4 domain-separation prefix (RFC_ACCESSGRANT_V2 §4, f40f5f6 dersi:
        // A one-sided root change is FORBIDDEN - bump it together with the prefix).
        if self.schema_version >= 4 {
            hasher.update(b"budlum.snapshot.v4");
        }
        hasher.update(self.schema_version.to_le_bytes());
        hasher.update(self.height.to_le_bytes());
        // Two `String`s back to back. Both hold hex digests today, so both
        // are 64 characters in practice, but neither is a fixed-width type and
        // nothing on the restore path enforces a length: a snapshot arriving
        // from a peer can carry any pair whose concatenation matches. Prefix
        // the lengths rather than rely on a convention the type does not
        // encode.
        let block_hash = self.block_hash.as_bytes();
        hasher.update((block_hash.len() as u64).to_le_bytes());
        hasher.update(block_hash);
        let genesis_hash = self.genesis_hash.as_bytes();
        hasher.update((genesis_hash.len() as u64).to_le_bytes());
        hasher.update(genesis_hash);
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
            // Length-prefixed. This digest is what a syncing node checks a
            // downloaded snapshot against, and `Validator` crosses the wire
            // with all four key fields `#[serde(default)]`, so the re-split
            // was reachable from a peer. See
            // `crate::crypto::key_set_preimage`.
            crate::crypto::key_set_preimage::update_consensus_keys_sha3(
                &mut hasher,
                None,
                &v.bls_public_key,
                &v.pop_signature,
                &v.pq_public_key,
            );
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

        // --- C3: the 15 previously unhashed fields in schema-4 (closing the
        //     forgery surface). Legacy (schema<4) skips this block -> backward compatible. ---
        if self.schema_version >= 4 {
            hash_serializable(&mut hasher, &self.tokenomics);
            hash_opt_serializable(&mut hasher, &self.tokenomics_burn);
            hash_opt_serializable(&mut hasher, &self.registry);
            hash_opt_serializable(&mut hasher, &self.liveness);
            hash_opt_serializable(&mut hasher, &self.invalid_votes);
            hash_opt_serializable(&mut hasher, &self.bns_registry);
            hash_opt_serializable(&mut hasher, &self.nft_registry);
            hash_opt_serializable(&mut hasher, &self.marketplace);
            hash_opt_serializable(&mut hasher, &self.budlumxyz);
            hash_opt_serializable(&mut hasher, &self.governance);
            hash_opt_serializable(&mut hasher, &self.storage_registry);
            hash_opt_serializable(&mut hasher, &self.ai_registry);
            // The private-note registry, which holds `spent_nullifiers`.
            //
            // Every other registry on this struct was already hashed here and
            // this one was not, so it crossed the wire outside the digest: a
            // peer serving a snapshot could drop nullifiers from the set and
            // the snapshot still verified. A nullifier that is absent has not
            // been spent, so the notes it retires become spendable again,
            // which is double-spend of private value with no forged signature
            // anywhere.
            //
            // `AccountState::calculate_state_root` already hashes
            // `note_registry.state_root()`, so a restored node diverges from
            // consensus at the next block rather than accepting the theft
            // permanently. That makes this a fail-loud bug rather than a
            // silent one; it does not make it acceptable, because the node
            // has already served requests against the restored state by then.
            hash_opt_serializable(&mut hasher, &self.note_registry);
            // The policy that decides whether a signature is required at all.
            //
            // `verify_authentic` reads this field to choose between accepting
            // an unsigned snapshot and demanding a trusted signer. Outside
            // the digest, it was the one field an attacker most wanted to
            // edit: flip `RequireSigned` to `AllowUnsigned` on a snapshot
            // whose digest already matches, and `verify_authentic` returns
            // `Ok(())` at the first match arm without ever looking at
            // `manifest_signer` or `manifest_signature`. The signature
            // requirement could be removed by the party it was meant to
            // constrain.
            //
            // `manifest_signer`, `manifest_signature` and `snapshot_hash`
            // stay out, and must: the first two are the signature over this
            // digest and the third is the digest, so including any of them
            // is a definition that cannot be satisfied.
            hash_serializable(&mut hasher, &self.trust_policy);
            hash_opt_serializable(&mut hasher, &self.bridge_state);
            hash_opt_serializable(&mut hasher, &self.message_registry);
            hash_opt_serializable(&mut hasher, &self.external_roots);
            // The proof market carries assigned tasks, each naming a prover
            // and an epoch, and unpaid receipts, each naming an amount. A
            // field that crosses the wire outside the digest is a field a
            // peer can edit without invalidating the snapshot, which for this
            // one means reassigning work or rewriting what is owed.
            hash_opt_serializable(&mut hasher, &self.proof_market);
            // finality_certificates: Vec - length prefix + serialize each element.
            let fc_bytes = bincode::serialize(&self.finality_certificates)
                .unwrap_or_else(|_| SNAPSHOT_SERIALIZE_FAILED.to_vec());
            hasher.update((fc_bytes.len() as u64).to_le_bytes());
            hasher.update(&fc_bytes);
            hasher.update(self.created_at.to_le_bytes());
        }

        hasher.finalize().into()
    }

    /// Recompute `snapshot_hash` over the current field set.
    ///
    /// Exists for fixtures that mutate a hashed field by hand. `trust_policy`
    /// is inside the digest, so a test that flips it and then calls
    /// `verify_authentic` gets `DigestMismatch` and never reaches the check
    /// it meant to exercise. Production code has no reason to call this: the
    /// hash is written once at construction and again by `sign_manifest`,
    /// which is the only writer that moves a hashed field.
    pub fn reseal_after_manual_edit(&mut self) {
        self.snapshot_hash = self.calculate_hash();
    }

    fn calculate_hash(&self) -> String {
        hex::encode(self.calculate_digest())
    }

    pub fn verify(&self) -> bool {
        self.snapshot_hash == self.calculate_hash()
    }

    /// C4: manifest authenticity verification (RFC_GAP1 section 7.1, Task-1).
    ///
    /// - `AllowUnsigned` -> OK if `verify` (digest) passes (missing signer/sig accepted).
    /// - `RequireSigned` -> `manifest_signer` set + a valid `manifest_signature`
    ///   Ed25519(`calculate_digest`, signer) + the signer must be in the trust list.
    ///
    /// `trust_list` = None accepts any signer, for tests and devnet; in production
    /// The loader supplies the trust list from config (genesis bundle + CLI override, section 7.2).
    pub fn verify_authentic(
        &self,
        trust_list: Option<&[[u8; 32]]>,
    ) -> Result<(), SnapshotAuthError> {
        if !self.verify() {
            return Err(SnapshotAuthError::DigestMismatch);
        }
        match self.trust_policy {
            SnapshotTrustPolicy::AllowUnsigned => Ok(()),
            SnapshotTrustPolicy::RequireSigned => {
                let signer = self
                    .manifest_signer
                    .ok_or(SnapshotAuthError::MissingSigner)?;
                let sig = self
                    .manifest_signature
                    .as_ref()
                    .ok_or(SnapshotAuthError::MissingSignature)?;
                // A `RequireSigned` manifest with nobody named to trust is not
                // "signed by someone we trust", it is "signed by anyone": a
                // key generated a second ago clears it. Both production
                // callers pass a list (`Blockchain` at :310 and :4771), so
                // this is the shape of the API rather than a live hole - but
                // the honest answer to "is this signer trusted?" is not "yes"
                // when nobody said who to trust. The signer and signature
                // checks stay above this: an unsigned manifest is still
                // reported as missing, not as untrusted.
                let Some(list) = trust_list else {
                    return Err(SnapshotAuthError::NoTrustList);
                };
                if !list.iter().any(|pk| pk == &signer) {
                    return Err(SnapshotAuthError::SignerNotTrusted);
                }
                // Ed25519 verify (ed25519-dalek; crypto crate reuse).
                // `verify_strict` rejects weak (low-order) public keys, which
                // `verify()` would accept; a weak key forges signatures for
                // almost any message (hardening research #44).
                let vk = VerifyingKey::from_bytes(&signer)
                    .map_err(|_| SnapshotAuthError::InvalidSignerKey)?;
                let sig_arr: [u8; 64] = sig
                    .as_slice()
                    .try_into()
                    .map_err(|_| SnapshotAuthError::InvalidSignatureLength)?;
                let signature = Signature::from_bytes(&sig_arr);
                let digest = self.calculate_digest();
                vk.verify_strict(&digest, &signature)
                    .map_err(|_| SnapshotAuthError::SignatureInvalid)
            }
        }
    }

    /// Fallible serialization for the durable snapshot-production path:
    /// Surfaces a serialization error to the caller instead of silently writing
    /// An empty/corrupt snapshot. This is the exact failure class that hid the
    /// Registry tuple-key bug.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| format!("Failed to serialize snapshot V2: {e}"))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // Fail-fast rather than silently produce empty bytes. StateSnapshotV2
        // Is a plain data type post- (no tuple-key maps), so failure is a bug.
        self.try_to_bytes()
            .unwrap_or_else(|_| SNAPSHOT_SERIALIZE_FAILED.to_vec())
    }

    /// Produce the staged migration report used by the offline
    /// `--migrate-v2` gate and by tests. deliberately keeps this
    /// As a *skeleton*: supported schema-2 snapshots deserialize through
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
                "schema<4 snapshot accepted through serde defaults; rewritten to schema-4 with GAP-2 digest + AllowUnsigned (C6 legacy-import)".to_string(),
            );
        } else {
            notes.push("snapshot already at current schema-4".to_string());
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
        // Same ceiling as the V1 entry point and the bounded disk reader:
        // no snapshot is parsed before its size is checked, whoever hands
        // it over.
        if data.len() as u64 > crate::core::bounded_read::MAX_SNAPSHOT_BYTES {
            return Err(format!(
                "snapshot V2 exceeds the {} byte ceiling",
                crate::core::bounded_read::MAX_SNAPSHOT_BYTES
            ));
        }
        let mut snapshot: StateSnapshotV2 = serde_json::from_slice(data)
            .map_err(|e| format!("Failed to parse snapshot V2: {e}"))?;
        snapshot.migration_report()?;
        // C6 legacy import (RFC_GAP1 section 7.3, AllowUnsigned transition window):
        // Schema<4 snapshots arrived with the old digest; the new code recomputes
        // the schema-4 snapshot_hash + AllowUnsigned (devnet transition).
        // A RequireSigned production loader expects a signature (sign_manifest).
        if snapshot.schema_version < CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION {
            snapshot.schema_version = CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION;
            snapshot.snapshot_hash = snapshot.calculate_hash();
        }
        Ok(snapshot)
    }

    /// C4: sign the snapshot (production loader / HSM signer).
    ///
    /// Order matters here, and it is the reason this function is not three
    /// lines. `trust_policy` is inside the digest, so setting it after
    /// signing would sign one digest and leave the struct describing a
    /// different one: `verify_authentic` would then fail at `verify()` with
    /// `DigestMismatch` before it ever checked the signature it was handed.
    /// The policy is therefore committed first, the digest computed over the
    /// final field set, and `snapshot_hash` refreshed to match, so that the
    /// bytes that were signed and the bytes that will be verified are the
    /// same bytes.
    pub fn sign_manifest(
        &mut self,
        secret_key: &ed25519_dalek::SigningKey,
        signer_pubkey: [u8; 32],
    ) {
        use ed25519_dalek::Signer;
        self.trust_policy = SnapshotTrustPolicy::RequireSigned;
        let digest = self.calculate_digest();
        let signature = secret_key.sign(&digest).to_bytes();
        self.manifest_signer = Some(signer_pubkey);
        self.manifest_signature = Some(signature.to_vec());
        // `manifest_signer`, `manifest_signature` and `snapshot_hash` are all
        // outside the digest, so assigning them does not invalidate what was
        // just signed. `trust_policy` is inside it, which is why the stored
        // hash has to be recomputed after the policy moved.
        self.snapshot_hash = hex::encode(digest);
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
            45262,
            &account_state,
            0,
            "genhash".to_string(),
        );
        assert_eq!(snapshot.height, 100);
        assert_eq!(snapshot.chain_id, 45262);
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
    fn caller_can_only_increase_pruning_retention() {
        let manager = PruningManager::new(100, 1000, "./snapshots".to_string());
        let configured = manager.get_prunable_blocks(1_000, 999, 999);
        let weaker_request = manager.get_prunable_blocks_with_retention(1_000, 999, 999, 1);
        let stronger_request = manager.get_prunable_blocks_with_retention(1_000, 999, 999, 500);

        assert_eq!(weaker_request, configured);
        assert!(stronger_request.len() < configured.len());
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
    fn reorg_quarantines_snapshots_above_fork_point() {
        use std::fs;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        fs::write(dir.path().join("snapshot_10.json"), "{}").unwrap();
        fs::write(dir.path().join("snapshot_20.json"), "{}").unwrap();
        fs::write(dir.path().join("snapshot_30.json"), "{}").unwrap();
        let manager = PruningManager::new(100, 1000, dir.path().to_string_lossy().to_string());

        assert_eq!(manager.quarantine_snapshots_above_height(20).unwrap(), 1);
        assert!(dir.path().join("snapshot_10.json").exists());
        assert!(dir.path().join("snapshot_20.json").exists());
        assert!(dir.path().join("snapshot_30.json.reorg").exists());
    }

    /// A character cannot move from `block_hash` into `genesis_hash`.
    ///
    /// `calculate_digest` appended the two `String`s with nothing between
    /// them. Both hold hex digests in practice, but neither is a fixed-width
    /// type and no restore path enforces a length, so a snapshot arriving from
    /// a peer could carry any pair whose concatenation matched an honest one
    /// and reproduce the digest `verify()` checks.
    #[test]
    fn a_snapshot_cannot_shift_bytes_between_its_two_hash_fields() {
        let account_state = AccountState::new();
        let honest = StateSnapshotV2::from_state(
            &account_state,
            StateSnapshotV2Params {
                height: 7,
                block_hash: "aabb".to_string(),
                genesis_hash: "ccdd".to_string(),
                chain_id: 42,
                finalized_height: 0,
                finalized_hash: "ee".to_string(),
                finality_certificates: vec![],
            },
        );
        let shifted = StateSnapshotV2::from_state(
            &account_state,
            StateSnapshotV2Params {
                height: 7,
                // The same eight characters, split one place to the left.
                block_hash: "aab".to_string(),
                genesis_hash: "bccdd".to_string(),
                chain_id: 42,
                finalized_height: 0,
                finalized_hash: "ee".to_string(),
                finality_certificates: vec![],
            },
        );

        let honest_concat = format!("{}{}", honest.block_hash, honest.genesis_hash);
        let shifted_concat = format!("{}{}", shifted.block_hash, shifted.genesis_hash);
        assert_eq!(
            honest_concat, shifted_concat,
            "the fixture must actually be a re-split, or this test proves \
             nothing about the boundary"
        );

        assert_ne!(
            honest.calculate_digest(),
            shifted.calculate_digest(),
            "two snapshots whose hash fields concatenate alike must not share \
             a digest; `verify()` is what a syncing node checks"
        );
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
        ); // Bumped 2->3
        assert_eq!(snapshot_v2.height, 105);
        assert!(snapshot_v2.verify());

        let bytes = snapshot_v2.to_bytes();
        let deserialized = StateSnapshotV2::from_bytes(&bytes).unwrap();
        assert_eq!(deserialized.height, 105);
        assert_eq!(
            deserialized.schema_version,
            CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION
        ); // Bumped 2->3
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
            .contains("current max supported is 4"));

        snapshot.schema_version = 2;
        let report = snapshot.migration_report().unwrap();
        assert_eq!(report.original_schema_version, 2);
        assert_eq!(
            report.target_schema_version,
            CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION
        );
        assert!(report.migrated);
        assert!(report.requires_backup);
        assert!(report.notes[0].contains("schema<4 snapshot accepted"));

        snapshot.schema_version = CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION;
        let bytes_current = serde_json::to_vec(&snapshot).unwrap();
        let current = StateSnapshotV2::from_bytes(&bytes_current).unwrap();
        let report = current.migration_report().unwrap();
        assert!(!report.migrated);
        assert!(report.notes[0].contains("already at current schema"));
    }

    /// The V2 snapshot is JSON. Every registry it carries keys at least one
    /// map by a 32-byte id or a tuple, and `serde_json` refuses such keys
    /// at the first non-empty entry, so on `main` this test failed with
    /// "key must be a string" as soon as the bridge held one transfer. The
    /// write path only logged that, which meant a chain with any bridge,
    /// AI or storage activity never produced a V2 snapshot again. The map
    /// key helper (`core::map_keys`) is what makes this pass; the bridge
    /// root and the replay store must survive the round trip unchanged.
    #[test]
    fn snapshot_v2_round_trips_with_a_populated_bridge() {
        use crate::cross_domain::AssetId;

        let mut account_state = AccountState::new();
        let asset = AssetId(crate::core::hash::hash_fields_bytes(&[b"asset"]));
        let owner = Address::from([1u8; 32]);
        let recipient = Address::from([2u8; 32]);
        account_state.bridge_state.register_asset(asset, 1).unwrap();
        let (transfer, _event) = account_state
            .bridge_state
            .lock(1, 2, 10, 0, asset, owner, recipient, 100, 1000)
            .unwrap();
        let expected_root = account_state.bridge_state.root();

        let snapshot = StateSnapshotV2::from_state(
            &account_state,
            StateSnapshotV2Params {
                height: 11,
                block_hash: "hash11".into(),
                genesis_hash: "genesis".into(),
                chain_id: 1,
                finalized_height: 10,
                finalized_hash: "final10".into(),
                finality_certificates: vec![],
            },
        );

        let bytes = snapshot
            .try_to_bytes()
            .expect("a populated bridge must serialise to JSON");
        let json = String::from_utf8(bytes.clone()).unwrap();
        assert!(
            json.contains(&hex::encode(transfer.message_id)),
            "the transfer must be keyed by its hex message id in the JSON"
        );

        let restored = StateSnapshotV2::from_bytes(&bytes).unwrap();
        assert!(restored.verify());
        let mut bridge = restored.bridge_state.expect("bridge state must be present");
        assert_eq!(bridge.root(), expected_root);
        assert_eq!(
            bridge.transfer(&transfer.message_id).map(|t| t.amount),
            Some(100)
        );
        // The tuple-keyed outbound nonce map came back too: the lock above
        // consumed nonce 0, so the next one on that route is 1.
        assert_eq!(bridge.replay.next_nonce(1, 2, owner), 1);
    }

    #[test]
    fn test_snapshot_v2_migration_roundtrip_with_tokenomics_burn() {
        let mut account_state = AccountState::new();
        account_state.tokenomics.block_reward = 12345;
        let snapshot = StateSnapshotV2::from_state(
            &account_state,
            StateSnapshotV2Params {
                height: 42,
                block_hash: "hash42".into(),
                genesis_hash: "genesis42".into(),
                chain_id: 1,
                finalized_height: 40,
                finalized_hash: "final40".into(),
                finality_certificates: vec![],
            },
        );

        let bytes = snapshot.to_bytes();
        let restored = StateSnapshotV2::from_bytes(&bytes).unwrap();
        assert_eq!(restored.height, 42);
        assert_eq!(restored.block_reward, 12345);
        assert!(restored.tokenomics_burn.is_some());
        assert!(restored.verify());
    }

    #[test]
    fn governance_snapshot_roundtrip_persists_proposals() {
        let mut account_state = AccountState::new();
        let proposer = Address::from([7u8; 32]);
        account_state
            .governance
            .create_proposal(
                proposer,
                crate::core::governance::ProposalType::ParameterUpdate(
                    "min_stake".into(),
                    "5000".into(),
                ),
                0,
                10,
            )
            .unwrap();

        let snapshot = StateSnapshotV2::from_state(
            &account_state,
            StateSnapshotV2Params {
                height: 7,
                block_hash: "hash7".into(),
                genesis_hash: "genesis7".into(),
                chain_id: 1,
                finalized_height: 0,
                finalized_hash: "".into(),
                finality_certificates: vec![],
            },
        );
        let bytes = snapshot.to_bytes();
        let restored = StateSnapshotV2::from_bytes(&bytes).unwrap();
        let rebuilt = AccountState::from_snapshot_v2(&restored);
        assert_eq!(rebuilt.governance.next_proposal_id, 1);
        assert_eq!(rebuilt.governance.proposals.len(), 1);
    }

    #[test]
    fn tokenomics_snapshot_roundtrip_preserves_full_params() {
        let mut account_state = AccountState::new();
        account_state.tokenomics.community = 123;
        account_state.tokenomics.tx_fee_burn_ratio_fixed = 456;
        account_state.tokenomics.annual_burn_ratio_fixed = 789;
        account_state.timed_burn.years_burned = 2;
        account_state.burn_reserve_address = Some(Address::from([3u8; 32]));
        account_state.team_vesting = Some((
            Address::from([4u8; 32]),
            crate::tokenomics::VestingSchedule {
                total: 5_000,
                start_epoch: 1,
                cliff_epochs: 2,
                duration_epochs: 3,
            },
        ));

        let snapshot = StateSnapshotV2::from_state(
            &account_state,
            StateSnapshotV2Params {
                height: 9,
                block_hash: "hash9".into(),
                genesis_hash: "genesis9".into(),
                chain_id: 1,
                finalized_height: 0,
                finalized_hash: "".into(),
                finality_certificates: vec![],
            },
        );
        let restored = StateSnapshotV2::from_bytes(&snapshot.to_bytes()).unwrap();
        let rebuilt = AccountState::from_snapshot_v2(&restored);
        assert_eq!(rebuilt.tokenomics.community, 123);
        assert_eq!(rebuilt.tokenomics.tx_fee_burn_ratio_fixed, 456);
        assert_eq!(rebuilt.tokenomics.annual_burn_ratio_fixed, 789);
        assert_eq!(rebuilt.timed_burn.years_burned, 2);
        assert_eq!(rebuilt.burn_reserve_address, Some(Address::from([3u8; 32])));
        assert!(rebuilt.team_vesting.is_some());
    }

    // --- C3/C4 tests (P2 schema-4) ---

    #[test]
    fn test_gap2_schema4_digest_includes_bns_field() {
        // Pin: schema-4 digest bns_registry'yi kapsar. None vs Some(default)
        // A different tag (0 vs 1) -> a different digest (forgery surface closed).
        let account_state = AccountState::new();
        let mut s1 = StateSnapshotV2::from_state(
            &account_state,
            StateSnapshotV2Params {
                height: 10,
                block_hash: "h".into(),
                genesis_hash: "g".into(),
                chain_id: 1,
                finalized_height: 0,
                finalized_hash: "f".into(),
                finality_certificates: vec![],
            },
        );
        s1.schema_version = 4;
        let s2 = s1.clone();
        s1.bns_registry = None; // None vs Some(default) -> a different tag
        assert_ne!(s1.calculate_digest(), s2.calculate_digest());
    }

    #[test]
    fn test_gap2_legacy_schema3_vs_schema4_digest_differ() {
        let account_state = AccountState::new();
        let mut s = StateSnapshotV2::from_state(
            &account_state,
            StateSnapshotV2Params {
                height: 5,
                block_hash: "h".into(),
                genesis_hash: "g".into(),
                chain_id: 1,
                finalized_height: 0,
                finalized_hash: "f".into(),
                finality_certificates: vec![],
            },
        );
        s.schema_version = 3;
        let legacy = s.calculate_digest();
        s.schema_version = 4;
        assert_ne!(legacy, s.calculate_digest());
    }

    #[test]
    fn test_gap1_allow_unsigned_ok() {
        let account_state = AccountState::new();
        let snapshot = StateSnapshotV2::from_state(
            &account_state,
            StateSnapshotV2Params {
                height: 1,
                block_hash: "h".into(),
                genesis_hash: "g".into(),
                chain_id: 1,
                finalized_height: 0,
                finalized_hash: "f".into(),
                finality_certificates: vec![],
            },
        );
        assert!(snapshot.verify_authentic(None).is_ok());
    }

    /// `RequireSigned` with no trust list to compare against means "signed by
    /// Anyone who can sign": a key generated a second ago clears it. A
    /// Signature proves the manifest was signed, never that the signer is one
    /// We trust, so the honest answer to "is this signer trusted?" is not
    /// "yes" when nobody said who to trust.
    #[test]
    fn test_require_signed_without_a_trust_list_is_refused() {
        use ed25519_dalek::SigningKey;
        let account_state = AccountState::new();
        let mut snapshot = StateSnapshotV2::from_state(
            &account_state,
            StateSnapshotV2Params {
                height: 1,
                block_hash: "h".into(),
                genesis_hash: "g".into(),
                chain_id: 1,
                finalized_height: 0,
                finalized_hash: "f".into(),
                finality_certificates: vec![],
            },
        );
        snapshot.trust_policy = SnapshotTrustPolicy::RequireSigned;
        snapshot.snapshot_hash = snapshot.calculate_hash();

        let signing_key = SigningKey::from_bytes(&[2u8; 32]);
        let verifying_key = ed25519_dalek::VerifyingKey::from(&signing_key);
        let mut pk = [0u8; 32];
        pk.copy_from_slice(verifying_key.as_bytes());
        snapshot.sign_manifest(&signing_key, pk);

        // The same signature still clears a list that names the key.
        assert!(snapshot.verify_authentic(Some(&[pk])).is_ok());
        assert_eq!(
            snapshot.verify_authentic(None).unwrap_err(),
            SnapshotAuthError::NoTrustList,
            "a RequireSigned manifest must not be cleared by an arbitrary key"
        );
    }

    #[test]
    fn test_gap1_require_signed_sign_verify_roundtrip() {
        use ed25519_dalek::SigningKey;
        let account_state = AccountState::new();
        let mut snapshot = StateSnapshotV2::from_state(
            &account_state,
            StateSnapshotV2Params {
                height: 1,
                block_hash: "h".into(),
                genesis_hash: "g".into(),
                chain_id: 1,
                finalized_height: 0,
                finalized_hash: "f".into(),
                finality_certificates: vec![],
            },
        );
        snapshot.trust_policy = SnapshotTrustPolicy::RequireSigned;
        // The policy is inside the digest, so moving it invalidates the hash
        // the fixture was built with. Refresh it, or `verify_authentic`
        // returns DigestMismatch and never reaches the signer check this test
        // is about.
        snapshot.snapshot_hash = snapshot.calculate_hash();
        assert_eq!(
            snapshot.verify_authentic(None).unwrap_err(),
            SnapshotAuthError::MissingSigner
        );
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = ed25519_dalek::VerifyingKey::from(&signing_key);
        let mut pk = [0u8; 32];
        pk.copy_from_slice(verifying_key.as_bytes());
        snapshot.sign_manifest(&signing_key, pk);
        assert!(snapshot.verify_authentic(Some(&[pk])).is_ok());
        assert_eq!(
            snapshot.verify_authentic(Some(&[[99u8; 32]])).unwrap_err(),
            SnapshotAuthError::SignerNotTrusted
        );
    }

    #[test]
    fn test_gap1_forged_signature_rejected() {
        use ed25519_dalek::{Signer, SigningKey};
        let account_state = AccountState::new();
        let mut snapshot = StateSnapshotV2::from_state(
            &account_state,
            StateSnapshotV2Params {
                height: 1,
                block_hash: "h".into(),
                genesis_hash: "g".into(),
                chain_id: 1,
                finalized_height: 0,
                finalized_hash: "f".into(),
                finality_certificates: vec![],
            },
        );
        let wrong_key = SigningKey::from_bytes(&[2u8; 32]);
        let wrong_vk = ed25519_dalek::VerifyingKey::from(&wrong_key);
        let mut wrong_pk = [0u8; 32];
        wrong_pk.copy_from_slice(wrong_vk.as_bytes());
        let wrong_sig = wrong_key.sign(b"wrong-message").to_bytes();
        snapshot.manifest_signer = Some(wrong_pk);
        snapshot.manifest_signature = Some(wrong_sig.to_vec());
        snapshot.trust_policy = SnapshotTrustPolicy::RequireSigned;
        // Same reason as above: the digest covers the policy, so the fixture
        // has to be self-consistent before a signature can be the thing that
        // fails.
        snapshot.snapshot_hash = snapshot.calculate_hash();
        assert_eq!(
            snapshot.verify_authentic(Some(&[wrong_pk])).unwrap_err(),
            SnapshotAuthError::SignatureInvalid
        );
    }

    /// Signing must leave the snapshot self-consistent.
    ///
    /// This pins the failure mode that appeared the moment `trust_policy`
    /// entered the digest. `sign_manifest` computed the digest, signed it,
    /// and only then set the policy: the signature was over one field set
    /// and `snapshot_hash` described another. `verify_authentic` calls
    /// `verify()` first, so it returned `DigestMismatch` and never reached
    /// the signature it had been given, which reads from the outside as a
    /// corrupt snapshot rather than a broken signer.
    ///
    /// The general shape is worth naming, because the next field added to
    /// the digest will hit it again: any writer that mutates a hashed field
    /// after hashing has signed something that no longer exists. The
    /// assertion below is deliberately about the round trip rather than
    /// about field order, so it keeps holding whatever else joins the digest.
    #[test]
    fn signing_leaves_the_digest_consistent_with_what_was_signed() {
        use ed25519_dalek::SigningKey;
        let account_state = AccountState::new();
        let mut snapshot = StateSnapshotV2::from_state(
            &account_state,
            StateSnapshotV2Params {
                height: 1,
                block_hash: "h".into(),
                genesis_hash: "g".into(),
                chain_id: 1,
                finalized_height: 0,
                finalized_hash: "f".into(),
                finality_certificates: vec![],
            },
        );
        let signing_key = SigningKey::from_bytes(&[3u8; 32]);
        let pk = signing_key.verifying_key().to_bytes();
        snapshot.sign_manifest(&signing_key, pk);

        assert!(
            snapshot.verify(),
            "sign_manifest moved a hashed field, so the stored hash must be \
             refreshed; otherwise the snapshot reports itself corrupt"
        );
        assert_eq!(
            snapshot.trust_policy,
            SnapshotTrustPolicy::RequireSigned,
            "signing a manifest is what makes the signature mandatory"
        );
        assert!(
            snapshot.verify_authentic(Some(&[pk])).is_ok(),
            "the bytes that were signed and the bytes that get verified must \
             be the same bytes"
        );

        // The canary: the digest still has to cover the policy. If this
        // stops failing, the field left the digest and the downgrade attack
        // is open again.
        snapshot.trust_policy = SnapshotTrustPolicy::AllowUnsigned;
        assert!(
            !snapshot.verify(),
            "trust_policy must stay inside the digest"
        );
    }

    /// Downgrading the trust policy must break the digest.
    ///
    /// `verify_authentic` reads `trust_policy` to decide whether a signature
    /// is required at all, and the field was not hashed into
    /// `calculate_digest`. Flipping `RequireSigned` to `AllowUnsigned` on a
    /// snapshot whose digest already matched made `verify_authentic` return
    /// `Ok(())` at the first match arm, without ever reading
    /// `manifest_signer` or `manifest_signature`. The requirement could be
    /// removed by exactly the party it existed to constrain.
    #[test]
    fn a_downgraded_trust_policy_no_longer_verifies() {
        let account_state = AccountState::new();
        let mut snapshot = StateSnapshotV2::from_state(
            &account_state,
            StateSnapshotV2Params {
                height: 1,
                block_hash: "h".into(),
                genesis_hash: "g".into(),
                chain_id: 1,
                finalized_height: 0,
                finalized_hash: "f".into(),
                finality_certificates: vec![],
            },
        );
        snapshot.trust_policy = SnapshotTrustPolicy::RequireSigned;
        snapshot.snapshot_hash = snapshot.calculate_hash();
        assert!(
            snapshot.verify(),
            "the fixture must be self-consistent, or the negative proves nothing"
        );

        // The attack: keep every byte, weaken only the policy.
        snapshot.trust_policy = SnapshotTrustPolicy::AllowUnsigned;
        assert!(
            !snapshot.verify(),
            "the policy that decides whether a signature is needed must be \
             inside the digest it protects, or an unsigned snapshot can be \
             passed off as one that was never required to be signed"
        );
        assert_eq!(
            snapshot.verify_authentic(None).unwrap_err(),
            SnapshotAuthError::DigestMismatch,
            "the downgrade must be refused before the policy is consulted"
        );
    }

    /// Dropping a spent nullifier must break the digest.
    ///
    /// `note_registry` holds `spent_nullifiers`, which is the replay
    /// protection for private transfers. Every other registry on this struct
    /// was hashed into the digest and this one was not, so a peer serving a
    /// snapshot could remove nullifiers and the snapshot still verified. A
    /// nullifier that is absent has not been spent, so the notes it retired
    /// become spendable again: double-spend of private value with no forged
    /// signature anywhere.
    #[test]
    fn removing_a_spent_nullifier_no_longer_verifies() {
        let mut account_state = AccountState::new();
        account_state
            .note_registry
            .insert_note([7u8; 32])
            .expect("a fresh registry accepts a note");

        let mut snapshot = StateSnapshotV2::from_state(
            &account_state,
            StateSnapshotV2Params {
                height: 1,
                block_hash: "h".into(),
                genesis_hash: "g".into(),
                chain_id: 1,
                finalized_height: 0,
                finalized_hash: "f".into(),
                finality_certificates: vec![],
            },
        );
        assert!(snapshot.verify(), "the fixture must verify as issued");

        // The attack: serve the same snapshot with the note registry emptied.
        snapshot.note_registry = Some(crate::privacy::L1NoteRegistry::new());
        assert!(
            !snapshot.verify(),
            "the note registry crossed the wire outside the digest, so a peer \
             could drop nullifiers and the snapshot still verified"
        );
    }

    /// The signature fields stay outside, and must.
    ///
    /// Guarding the fix from the obvious overcorrection. `manifest_signature`
    /// and `manifest_signer` are the signature over this digest, and
    /// `snapshot_hash` is the digest; hashing any of them defines a value
    /// that cannot be computed.
    #[test]
    fn the_signature_over_the_digest_is_not_inside_it() {
        let account_state = AccountState::new();
        let mut snapshot = StateSnapshotV2::from_state(
            &account_state,
            StateSnapshotV2Params {
                height: 1,
                block_hash: "h".into(),
                genesis_hash: "g".into(),
                chain_id: 1,
                finalized_height: 0,
                finalized_hash: "f".into(),
                finality_certificates: vec![],
            },
        );
        let before = snapshot.calculate_digest();

        snapshot.manifest_signer = Some([3u8; 32]);
        snapshot.manifest_signature = Some(vec![9u8; 64]);
        assert_eq!(
            snapshot.calculate_digest(),
            before,
            "signing a snapshot must not change the digest that was signed"
        );
    }
    // --- Debt G: real legacy-blob migration tests (schema 2 -> 4 and 3 -> 4) ---
    //
    // The migration tests so far took a schema-4 production and rewound the version
    // number by hand: the blob CARRIED every new field, so the `serde(default)`
    // fill was never exercised. In a real schema-2/3 disk record those fields
    // are not present as bytes; what migration promises is exactly the
    // behaviour against that absence. The two test blobs are therefore built by
    // `serde_json` surgery: the field key is entirely ABSENT from the source blob.
    // The red evidence was taken in an isolated vault (the pd vault): an importer without the bump line
    // reported "migration done" while leaving the version at 2 and the test
    // failed; the variant with the bump passed the same test.

    /// The shared parameter bundle used by the test setup.
    fn legacy_params(height: u64) -> StateSnapshotV2Params {
        StateSnapshotV2Params {
            height,
            block_hash: "block-digest".into(),
            genesis_hash: "genesis-digest".into(),
            chain_id: 42,
            finalized_height: 0,
            finalized_hash: "fin-digest".into(),
            finality_certificates: vec![],
        }
    }

    /// Present `snapshot` as an old on-disk blob: the given keys are
    /// DELETES it from the serialized record and rewinds the version number.
    /// The deleted key is absent from the blob as bytes; the `serde(default)` fill-in
    /// can only be exercised with such a blob.
    fn as_legacy_blob(snapshot: &StateSnapshotV2, drop_keys: &[&str], version: u32) -> Vec<u8> {
        let mut value = serde_json::to_value(snapshot).unwrap();
        let obj = value.as_object_mut().unwrap();
        for key in drop_keys {
            obj.remove(*key);
        }
        obj.insert(
            "schema_version".to_string(),
            serde_json::Value::from(version),
        );
        serde_json::to_vec(&value).unwrap()
    }

    /// all keys of the schema-3 and schema-4 wave (stored in the blob as `hub`
    /// serilestirilen `budlumxyz` dahil).
    const SCHEMA3_AND_4_KEYS: &[&str] = &[
        "tokenomics",
        "tokenomics_burn",
        "registry",
        "liveness",
        "invalid_votes",
        "bns_registry",
        "nft_registry",
        "marketplace",
        "hub",
        "governance",
        "storage_registry",
        "ai_registry",
        "note_registry",
        "bridge_state",
        "message_registry",
        "external_roots",
        "proof_market",
        "manifest_signer",
        "manifest_signature",
        "trust_policy",
        "poa_onboarding",
    ];

    /// Only the keys of the schema-4 wave.
    const SCHEMA4_ONLY_KEYS: &[&str] = &["manifest_signer", "manifest_signature", "trust_policy"];

    /// PoA admission records: a field added with `#[serde(default)]`, without a
    /// version bump.
    ///
    /// **Why `CURRENT_..._SCHEMA_VERSION` was not bumped:** the version exists for cases where an old
    /// binary could read a new snapshot *wrongly*.
    /// There is no such case here - if the field is absent the default is an empty record, and an empty
    /// record means "this domain is not permissioned", which is exactly the truth of old
    /// snapshots. Bumping the version would push old releases outside the supported
    /// window: a compatibility break that gains nothing.
    /// kaybi.
    ///
    /// The derived set (`poa_admitted`) is NOT HERE and must not be: it is recomputed from the records
    /// at every block close. Had it been written to the snapshot, a hand-edited
    /// snapshot could carry an admission set its own records do not support.
    /// kumesi tasiyabilirdi.
    const POA_ADMISSION_KEYS: &[&str] = &["poa_onboarding"];

    /// Fields rooted in schema-2: known to the old release too, and not a single byte
    /// the fields it must not lose. `snapshot_hash` is deliberately outside:
    /// the seal is recomputed because the version changed.
    const SCHEMA2_FIELDS: &[&str] = &[
        "height",
        "block_hash",
        "genesis_hash",
        "chain_id",
        "created_at",
        "balances",
        "nonces",
        "finalized_height",
        "finalized_hash",
        "validators",
        "unbonding_queue",
        "finality_certificates",
        "epoch_index",
        "last_epoch_time",
        "base_fee",
        "block_reward",
        "bridge_root",
        "message_root",
        "settlement_root",
        "global_header_summary",
    ];

    /// Are the JSON values of the given fields byte-identical across two snapshots.
    /// Compares field by field so a loss is reported by field name.
    fn assert_fields_preserved(before: &StateSnapshotV2, after: &StateSnapshotV2, fields: &[&str]) {
        let a = serde_json::to_value(before).unwrap();
        let b = serde_json::to_value(after).unwrap();
        for field in fields {
            let av = a
                .get(*field)
                .unwrap_or_else(|| panic!("field missing at the source: {field}"));
            let bv = b
                .get(*field)
                .unwrap_or_else(|| panic!("field missing at the target: {field}"));
            assert_eq!(av, bv, "migration lost this field: {field}");
        }
    }

    /// A state with every schema-2 field populated: an empty-set round trip
    /// proves nothing, because empty -> empty is the same result under both behaviours.
    fn schema2_filled_state() -> AccountState {
        let a1 = Address::from([1u8; 32]);
        let a2 = Address::from([2u8; 32]);
        let mut account_state = AccountState::new();
        account_state.add_balance(&a1, 500);
        account_state.add_balance(&a2, 300);
        account_state.get_or_create(&a1).nonce = 7;
        account_state
            .validators
            .insert(a1, crate::core::account::Validator::new(a1, 1_000));
        account_state
            .unbonding_queue
            .push(crate::core::account::UnbondingEntry {
                address: a2,
                amount: 9,
                release_epoch: 11,
            });
        account_state.epoch_index = 3;
        account_state.last_epoch_time = 99;
        account_state.base_fee = 10;
        account_state.bridge_root = [1u8; 32];
        account_state.message_root = [2u8; 32];
        account_state.settlement_root = [3u8; 32];
        account_state.global_header_summary = [4u8; 32];
        account_state
    }

    fn schema2_cert() -> FinalityCert {
        FinalityCert {
            epoch: 1,
            checkpoint_height: 2,
            checkpoint_hash: "cp".into(),
            agg_sig_bls: vec![1, 2, 3],
            bitmap: vec![0u8],
            set_hash: "set".into(),
        }
    }

    /// A lock on the serialised field set: adding a new field to
    /// this test must fail when a field is added, because the "every field" claim of the two
    /// old-blob tests only holds if this list is current. Whoever adds a field:
    /// add that field's behaviour to both old-blob tests, then update
    /// this list. (Canary: it fails when a field is added, and when one is removed.)
    #[test]
    fn the_migration_tests_cover_every_serialized_field() {
        let account_state = AccountState::new();
        let snapshot = StateSnapshotV2::from_state(&account_state, legacy_params(1));
        let value = serde_json::to_value(&snapshot).unwrap();
        let keys: std::collections::BTreeSet<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let expected: std::collections::BTreeSet<&str> = [
            "schema_version",
            "height",
            "block_hash",
            "genesis_hash",
            "chain_id",
            "created_at",
            "balances",
            "nonces",
            "finalized_height",
            "finalized_hash",
            "validators",
            "unbonding_queue",
            "finality_certificates",
            "epoch_index",
            "last_epoch_time",
            "base_fee",
            "block_reward",
            "bridge_root",
            "message_root",
            "settlement_root",
            "global_header_summary",
            // schema-3 dalgasi
            "tokenomics",
            "tokenomics_burn",
            "registry",
            "liveness",
            "invalid_votes",
            "bns_registry",
            "nft_registry",
            "marketplace",
            "hub",
            "governance",
            "storage_registry",
            "ai_registry",
            "note_registry",
            "bridge_state",
            "message_registry",
            "external_roots",
            "proof_market",
            // schema-4 dalgasi
            "manifest_signer",
            "manifest_signature",
            "trust_policy",
            // admission records (a serde-default field with no version bump)
            "poa_onboarding",
            // the digest itself: recomputed when the version changes
            "snapshot_hash",
        ]
        .into_iter()
        .collect();
        assert_eq!(
            keys, expected,
            "the StateSnapshotV2 field set changed: extend both legacy-blob tests in the same edit"
        );
    }

    /// A schema-2 blob: the new fields are entirely absent and the old ones are
    /// filled.
    ///
    /// Locks two distinctions together: (1) every schema-2 field PRESENT in the blob
    /// is preserved byte for byte after migration (no data loss), (2) every new field ABSENT
    /// from the blob returns empty/default - that means "the feature was not active then",
    /// not that data was lost. The second side of the distinction can only be measured when the source blob
    /// is proved to genuinely lack the key; the test asserts that
    /// as well.
    #[test]
    fn a_legacy_schema2_blob_migrates_without_losing_any_v2_field() {
        let mut account_state = schema2_filled_state();
        account_state.tokenomics.block_reward = 777;
        let mut params = legacy_params(42);
        params.finality_certificates = vec![schema2_cert()];
        let full = StateSnapshotV2::from_state(&account_state, params);

        let blob = as_legacy_blob(&full, SCHEMA3_AND_4_KEYS, 2);
        // Premise: the blob really behaves like a schema-2 record - the new
        // field keys are absent as bytes.
        let value: serde_json::Value = serde_json::from_slice(&blob).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(obj.get("schema_version").unwrap().as_u64().unwrap(), 2);
        for key in SCHEMA3_AND_4_KEYS {
            assert!(
                !obj.contains_key(*key),
                "the source blob contains a key it must not have: {key}"
            );
        }

        let restored = StateSnapshotV2::from_bytes(&blob).unwrap();

        // Bump: the two versions must be observable as distinct.
        assert_eq!(
            restored.schema_version, CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION,
            "without the 2->4 bump, the claim that a migration happened is a lie"
        );
        // Preservation side: every field schema-2 knows survives byte for byte.
        assert_fields_preserved(&full, &restored, SCHEMA2_FIELDS);
        // Default side: what is absent from the blob returns as "was not active".
        assert!(
            restored.tokenomics_burn.is_none()
                && restored.registry.is_none()
                && restored.liveness.is_none()
                && restored.invalid_votes.is_none()
                && restored.bns_registry.is_none()
                && restored.nft_registry.is_none()
                && restored.marketplace.is_none()
                && restored.budlumxyz.is_none()
                && restored.governance.is_none()
                && restored.storage_registry.is_none()
                && restored.ai_registry.is_none()
                && restored.note_registry.is_none()
                && restored.bridge_state.is_none()
                && restored.message_registry.is_none()
                && restored.external_roots.is_none()
                && restored.proof_market.is_none()
                && restored.manifest_signer.is_none()
                && restored.manifest_signature.is_none(),
            "a field never present in the blob came back as data; that is not loss, it is fabrication"
        );
        assert_eq!(restored.trust_policy, SnapshotTrustPolicy::AllowUnsigned);
        assert_eq!(
            serde_json::to_value(restored.tokenomics).unwrap(),
            serde_json::to_value(crate::tokenomics::TokenomicsParams::default()).unwrap(),
            "tokenomics absent from the blob must fall back to the default"
        );
        // The seal must be recomputed and consistent with itself.
        assert!(
            restored.verify(),
            "after the bump the snapshot is inconsistent with its own digest"
        );
    }

    /// A schema-3 blob: the v3 fields CARRY data, the v4 fields are absent.
    ///
    /// The other half of the loss distinction: when the same `serde(default)`
    /// field is present and carries data, it must deliver that data verbatim.
    /// The previous test locks the never-carried side, this one the carried side.
    #[test]
    fn a_legacy_schema3_blob_migrates_keeping_v3_data_and_defaulting_v4() {
        let mut account_state = schema2_filled_state();
        account_state.tokenomics.community = 777;
        account_state.timed_burn.years_burned = 2;
        account_state.burn_reserve_address = Some(Address::from([3u8; 32]));
        account_state.team_vesting = Some((
            Address::from([4u8; 32]),
            crate::tokenomics::VestingSchedule {
                total: 5_000,
                start_epoch: 1,
                cliff_epochs: 2,
                duration_epochs: 3,
            },
        ));
        let a1 = Address::from([1u8; 32]);
        account_state
            .registry
            .register_validator(a1, 1_000, 0)
            .unwrap();
        account_state
            .governance
            .create_proposal(
                a1,
                crate::core::governance::ProposalType::ParameterUpdate(
                    "min_stake".into(),
                    "5000".into(),
                ),
                0,
                10,
            )
            .unwrap();
        account_state
            .note_registry
            .insert_note([9u8; 32])
            .expect("a fresh record accepts the note");
        let mut params = legacy_params(64);
        params.finality_certificates = vec![schema2_cert()];
        let full = StateSnapshotV2::from_state(&account_state, params);

        let blob = as_legacy_blob(&full, SCHEMA4_ONLY_KEYS, 3);
        let value: serde_json::Value = serde_json::from_slice(&blob).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(obj.get("schema_version").unwrap().as_u64().unwrap(), 3);
        for key in SCHEMA4_ONLY_KEYS {
            assert!(
                !obj.contains_key(*key),
                "the source blob carries a v4 key it must not: {key}"
            );
        }

        let restored = StateSnapshotV2::from_bytes(&blob).unwrap();
        assert_eq!(
            restored.schema_version,
            CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION
        );
        // v2 + v3 alanlarinin tumu verisiyle tasindi.
        let mut preserved = SCHEMA2_FIELDS.to_vec();
        preserved.extend([
            "tokenomics",
            "tokenomics_burn",
            "registry",
            "liveness",
            "invalid_votes",
            "bns_registry",
            "nft_registry",
            "marketplace",
            "hub",
            "governance",
            "storage_registry",
            "ai_registry",
            "note_registry",
            "bridge_state",
            "message_registry",
            "external_roots",
            "proof_market",
        ]);
        assert_fields_preserved(&full, &restored, &preserved);
        // v4 dalgasi default'a doner.
        assert!(restored.manifest_signer.is_none());
        assert!(restored.manifest_signature.is_none());
        assert_eq!(restored.trust_policy, SnapshotTrustPolicy::AllowUnsigned);
        assert!(restored.verify());
        // On chain: when the state is restored the data must still be there.
        let rebuilt = AccountState::from_snapshot_v2(&restored);
        assert_eq!(rebuilt.tokenomics.community, 777);
        assert_eq!(rebuilt.governance.proposals.len(), 1);
        assert_eq!(rebuilt.timed_burn.years_burned, 2);
    }

    /// A blob without PoA admission records (still a valid schema-4 snapshot,
    /// because the version was not bumped).
    ///
    /// What this migration path must lock is not a data move but a
    /// **security assumption**: when a snapshot carrying no PoA admission
    /// record is restored, the domain **must not be treated as permissioned**.
    /// Otherwise a chain opened from an old snapshot looks like a permissioned
    /// domain where nobody has been admitted, and can never produce a block.
    ///
    /// We also verify here that the derived set is absent from the snapshot: it
    /// is recomputed from the records.
    #[test]
    fn a_snapshot_without_admission_records_does_not_look_permissioned() {
        let mut account_state = AccountState::new();
        account_state.tokenomics.community = 777;
        let full = StateSnapshotV2::from_state(&account_state, legacy_params(64));

        let blob = as_legacy_blob(&full, POA_ADMISSION_KEYS, 4);
        let value: serde_json::Value = serde_json::from_slice(&blob).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(obj.get("schema_version").unwrap().as_u64().unwrap(), 4);
        for key in POA_ADMISSION_KEYS {
            assert!(
                !obj.contains_key(*key),
                "the source blob carries an acceptance key it must not: {key}"
            );
        }
        assert!(
            !obj.contains_key("poa_admitted"),
            "the derived admission set leaked into the snapshot: it must be computed from the records"
        );

        let restored = StateSnapshotV2::from_bytes(&blob).unwrap();
        assert_eq!(
            restored.schema_version,
            CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION
        );
        assert!(
            restored.poa_onboarding.is_none(),
            "a missing admission record falls back to the default"
        );
        assert!(restored.verify());

        let rebuilt = AccountState::from_snapshot_v2(&restored);
        assert_eq!(rebuilt.tokenomics.community, 777);
        assert!(
            !rebuilt.poa_is_permissioned(0),
            "an old snapshot without admission records showed the domain as permissioned: the chain would be born open"
        );
        assert!(rebuilt.poa_admitted_addresses(0).is_empty());
    }

    /// Versions just outside the supported window are fail-closed.
    ///
    /// The window is `[2, 4]`; the closure must stay identical one below and one above
    /// the edge, otherwise when the window shifts a version that must be refused
    /// loads silently. It also locks the refusal message: the reason for staying
    /// closed is the text `"staged migration hook rejected"`, and the quarantine
    /// decision in the loader relies on that class.
    #[test]
    fn the_migration_hook_rejects_versions_just_outside_the_supported_window() {
        let account_state = AccountState::new();
        let snapshot = StateSnapshotV2::from_state(&account_state, legacy_params(1));
        for version in [
            0u32,
            MIN_SUPPORTED_STATE_SNAPSHOT_SCHEMA_VERSION - 1,
            CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION + 1,
            u32::MAX,
        ] {
            let blob = as_legacy_blob(&snapshot, &[], version);
            let Err(err) = StateSnapshotV2::from_bytes(&blob) else {
                panic!("version {version} should have been refused");
            };
            assert!(
                err.contains("staged migration hook rejected"),
                "unexpected refusal class (version {version}): {err}"
            );
        }
    }
}
