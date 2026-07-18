use crate::chain::finality::FinalityCert;
use crate::core::account::AccountState;
use crate::core::address::Address;
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
        // Phase 0.32: fail-fast instead of silently serializing to empty bytes (a
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
        // GAP-3/GAP-4 onarımı (2026-07-19, ARENA3): tek-şans yüklemesi kaldırıldı —
        // bozuk aday karantinaya gider ve bir SONRAKİ eski aday denenir; V2-şema
        // dosyalar ("schema_version") v1 probe'unda karantinasız ISKART edilir
        // (çapraz-şema gölgeleme giderildi: geçerli V2 artık imha edilmiyor).
        let mut quarantined_any = false;
        for entry in &snapshots {
            let path = entry.path();
            let data = match fs::read_to_string(&path) {
                Ok(d) => d,
                Err(_) => continue,
            };
            if data.contains("\"schema_version\"") {
                tracing::warn!(
                    "V1 loader V2-schema dosyasini atliyor (karantina YOK): {}",
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
                        "Bozuk V1 snapshot karantinaya alindi, eski aday deneniyor: {} ({e})",
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
                    "Integrity-bozuk V1 snapshot karantinaya alindi, eski aday deneniyor: {}",
                    path.display()
                );
                continue;
            }
            println!("Loaded snapshot at height {}", snapshot.height);
            return Ok(Some(snapshot));
        }
        if quarantined_any {
            return Err("Tum V1 snapshot adaylari bozuk (karantinalandi)".to_string());
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
        // GAP-3 onarımı (2026-07-19, ARENA3): tek-şans yüklemesi kaldırıldı —
        // bozuk aday karantinaya gider ve bir sonraki eski aday denenir.
        let mut quarantined_any = false;
        for entry in &snapshots {
            let path = entry.path();
            let data = match fs::read_to_string(&path) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let snapshot: StateSnapshotV2 = match serde_json::from_str(&data) {
                Ok(s) => s,
                Err(e) => {
                    let mut quarantine_path = path.clone();
                    quarantine_path.set_extension("json.corrupted");
                    let _ = fs::rename(&path, &quarantine_path);
                    quarantined_any = true;
                    tracing::error!(
                        "Bozuk V2 snapshot karantinaya alindi, eski aday deneniyor: {} ({e})",
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
                    "Integrity-bozuk V2 snapshot karantinaya alindi, eski aday deneniyor: {}",
                    path.display()
                );
                continue;
            }
            println!("Loaded snapshot V2 at height {}", snapshot.height);
            return Ok(Some(snapshot));
        }
        if quarantined_any {
            return Err("Tum V2 snapshot adaylari bozuk (karantinalandi)".to_string());
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
/// staged ConsensusStateV2 migration window. Older snapshots must be restored
/// with an intermediate release first; silently accepting them would risk
/// losing registry/tokenomics metadata that was not present yet.
pub const MIN_SUPPORTED_STATE_SNAPSHOT_SCHEMA_VERSION: u32 = 2;

/// Current durable snapshot schema emitted by this binary. This is the
/// ConsensusStateV2 migration target for Phase 2 §1.4.
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

    // --- schema_version 3 (Phase 0.16): previously-unpersisted state. All
    // `#[serde(default)]` so schema-2 snapshots still deserialize (the fields
    // simply come back empty/None — meaning "this feature wasn't active when the
    // snapshot was taken", not data loss).
    //
    // Phase 0.02 GHOST-HUNTING NOTE: `registry`, `liveness`, and `invalid_votes`
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

    // --- Phase 0.08: permissionless-registry persistence ---
    //
    // The Phase 0.02 ghost-hunting pass removed the `registry` / `liveness` /
    // `invalid_votes` fields from `AccountState` and (briefly) from this
    // snapshot. The Phase 0.08 redesign reinstates them on `AccountState` and
    // also round-trips them through the V2 snapshot so that liveness
    // counters and registry membership survive a restart. `#[serde(default)]`
    // keeps pre-Phase 0.08 V2 snapshots compatible: their `None` values get
    // materialized as the empty registry/tracker on load.
    #[serde(default)]
    pub registry: Option<crate::registry::PermissionlessRegistry>,
    #[serde(default)]
    pub liveness: Option<crate::registry::LivenessTracker>,
    #[serde(default)]
    pub invalid_votes: Option<crate::registry::InvalidVoteTracker>,

    // --- Phase 6 BNS/NFT/Hub/Marketplace persistence (ARENA3 audit: Q check_snapshot)
    // BNS registry was previously NOT round-tripped, so names were lost on restart from snapshot.
    // Now persisted with #[serde(default)] for backwards compatibility (old snapshots -> empty).
    #[serde(default)]
    pub bns_registry: Option<crate::bns::BnsRegistry>,
    #[serde(default)]
    pub nft_registry: Option<crate::socialfi::NftRegistry>,
    #[serde(default)]
    pub marketplace: Option<crate::pollen::MarketplaceRegistry>,
    #[serde(default)]
    pub hub: Option<crate::hub::HubRegistry>,
    #[serde(default)]
    pub storage_registry: Option<crate::domain::storage_deal::StorageRegistry>,
    #[serde(default)]
    pub ai_registry: Option<crate::ai::registry::AiRegistry>,
    #[serde(default)]
    pub bridge_state: Option<crate::cross_domain::BridgeState>,
    #[serde(default)]
    pub message_registry: Option<crate::cross_domain::message_registry::CrossDomainMessageRegistry>,
    #[serde(default)]
    pub external_roots:
        Option<BTreeMap<crate::domain::types::DomainId, crate::domain::types::Hash32>>,

    // --- C4 GAP-1 (Phase 10.5 P2): manifest signature (schema-4 wire). ---
    // RFC_GAP1 §7 (Faz 1: Ed25519 tek-imza + trust-list + AllowUnsigned geçişi).
    // `#[serde(default)]` → legacy schema-3 snapshot'lar (alan yok) None ile yüklenir.
    /// Snapshot'ı imzalayan party'nin Ed25519 pubkey'i (trust-list'ten). None =
    /// AllowUnsigned (devnet / legacy-import geçiş penceresi).
    #[serde(default)]
    pub manifest_signer: Option<[u8; 32]>,
    /// `sign(calculate_digest())` Ed25519 imzası (64 byte). None = AllowUnsigned.
    #[serde(default)]
    pub manifest_signature: Option<Vec<u8>>,
    /// Trust policy: AllowUnsigned (devnet/geçiş) | RequireSigned (production).
    /// Default AllowUnsigned → backward-compat (legacy snapshot'lar yüklenir).
    #[serde(default)]
    pub trust_policy: SnapshotTrustPolicy,

    pub snapshot_hash: String,
}

/// C4 GAP-1 trust policy (RFC_GAP1 §7.1: C-hibrit Faz-1 trust modeli).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SnapshotTrustPolicy {
    /// İmza opsiyonel: digest eşleşiyorsa OK (devnet / legacy-import penceresi).
    /// Mainnet build'inde derleme-uyarısı (production'da RequireSigned).
    #[default]
    AllowUnsigned,
    /// İmza ZORUNLU: manifest_signer trust-list'te + Ed25519 verify geçmeli.
    /// İmzasız/bozuk snapshot → `verify_authentic` Err → loader karantina.
    RequireSigned,
}

/// C4 GAP-1 manifest-authenticity hatası (loader karantina sınıfı).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotAuthError {
    DigestMismatch,
    MissingSigner,
    MissingSignature,
    SignerNotTrusted,
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
            SnapshotAuthError::InvalidSignerKey => write!(f, "invalid signer pubkey"),
            SnapshotAuthError::InvalidSignatureLength => write!(f, "invalid signature length"),
            SnapshotAuthError::SignatureInvalid => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for SnapshotAuthError {}

/// Atomic tokenomics-burn restore block (Phase 0.16, Decision 2.3). These three
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

/// C3 GAP-2 helper: herhangi bir `Serialize` tipini bincode → hasher.
/// Deterministik (struct field order sabit; bincode canonical).
fn hash_serializable<H: sha3::Digest, T: serde::Serialize>(hasher: &mut H, val: &T) {
    let bytes = bincode::serialize(val).unwrap_or_default();
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(&bytes);
}

/// C3 GAP-2 helper: `Option<T>` → tag (0=None / 1=Some) + serialize.
/// None ve Some(default) farklı hash verir (forgery yüzeyi kapalı).
fn hash_opt_serializable<H: sha3::Digest, T: serde::Serialize>(hasher: &mut H, opt: &Option<T>) {
    match opt {
        None => hasher.update(&[0u8]),
        Some(val) => {
            hasher.update(&[1u8]);
            hash_serializable(hasher, val);
        }
    }
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

        // Capture the tokenomics burn block atomically (Phase 0.16).
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
            // `genesis.rs::build_state` and the Phase 0.02 tokenomics refactor).
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
            storage_registry: Some(account_state.storage_registry.clone()),
            ai_registry: Some(account_state.ai_registry.clone()),
            bridge_state: Some(account_state.bridge_state.clone()),
            message_registry: Some(account_state.message_registry.clone()),
            external_roots: Some(account_state.external_roots.clone()),
            // Phase 0.02: `registry`, `liveness`, and `invalid_votes` are no longer
            // fields on `AccountState` (ghost-hunted). The struct fields were
            // already removed above; the live state is recovered by routing
            // any registry-touching calls through their "removed" mocks in
            // `blockchain.rs` / `chain_actor.rs`.
            tokenomics: account_state.tokenomics,
            tokenomics_burn,
            // Phase 0.08: round-trip the permissionless registry + liveness +
            // invalid-vote tracker so that liveness counters and registered
            // members survive a snapshot/restore cycle.
            registry: Some(account_state.registry.clone()),
            liveness: Some(account_state.liveness.clone()),
            invalid_votes: Some(account_state.invalid_votes.clone()),
            // C4 GAP-1: default AllowUnsigned (devnet). Production loader signer
            // enjekte eder + trust_policy=RequireSigned set eder.
            manifest_signer: None,
            manifest_signature: None,
            trust_policy: SnapshotTrustPolicy::AllowUnsigned,
            snapshot_hash: String::new(),
        };
        snapshot.snapshot_hash = snapshot.calculate_hash();
        snapshot
    }

    /// C2/C3 (P2 schema-4): ham digest. schema_version'a göre dallanır:
    /// - `< 4`: legacy digest (backward-compat — eski disk snapshot'ları verify).
    /// - `>= 4`: GAP-2 genişletilmiş digest (`budlum.snapshot.v4` prefix + 15
    ///   önce-hash'lenmemiş alan). Forgery surface kapanması (RFC_GAP1 §"Ek eksik").
    pub fn calculate_digest(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        // Schema-4 domain-separation prefix (RFC_ACCESSGRANT_V2 §4, f40f5f6 dersi:
        // tek-taraflı root değişikliği YASAK — prefix ile koordineli bump).
        if self.schema_version >= 4 {
            hasher.update(b"budlum.snapshot.v4");
        }
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

        // --- C3 GAP-2: schema-4'te önce-hash'lenmemiş 15 alan (forgery surface
        //     kapanması). Legacy (schema<4) bu bloğu atlar → backward-compat. ---
        if self.schema_version >= 4 {
            hash_serializable(&mut hasher, &self.tokenomics);
            hash_opt_serializable(&mut hasher, &self.tokenomics_burn);
            hash_opt_serializable(&mut hasher, &self.registry);
            hash_opt_serializable(&mut hasher, &self.liveness);
            hash_opt_serializable(&mut hasher, &self.invalid_votes);
            hash_opt_serializable(&mut hasher, &self.bns_registry);
            hash_opt_serializable(&mut hasher, &self.nft_registry);
            hash_opt_serializable(&mut hasher, &self.marketplace);
            hash_opt_serializable(&mut hasher, &self.hub);
            hash_opt_serializable(&mut hasher, &self.storage_registry);
            hash_opt_serializable(&mut hasher, &self.ai_registry);
            hash_opt_serializable(&mut hasher, &self.bridge_state);
            hash_opt_serializable(&mut hasher, &self.message_registry);
            hash_opt_serializable(&mut hasher, &self.external_roots);
            // finality_certificates: Vec — len-prefix + her elem serialize.
            let fc_bytes = bincode::serialize(&self.finality_certificates).unwrap_or_default();
            hasher.update((fc_bytes.len() as u64).to_le_bytes());
            hasher.update(&fc_bytes);
            hasher.update(self.created_at.to_le_bytes());
        }

        hasher.finalize().into()
    }

    fn calculate_hash(&self) -> String {
        hex::encode(self.calculate_digest())
    }

    pub fn verify(&self) -> bool {
        self.snapshot_hash == self.calculate_hash()
    }

    /// C4 GAP-1: manifest-authenticity doğrulaması (RFC_GAP1 §7.1 Faz-1).
    ///
    /// - `AllowUnsigned` → `verify()` (digest) geçiyorsa OK (signer/sig yok kabul).
    /// - `RequireSigned` → `manifest_signer` set + `manifest_signature` geçerli
    ///   Ed25519(`calculate_digest()`, signer) + signer trust-list'te olmalı.
    ///
    /// `trust_list` = None → herhangi bir signer kabul (test/devnet); production'da
    /// loader config'ten trust-list verir (genesis bundle + CLI override, §7.2).
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
                if let Some(list) = trust_list {
                    if !list.iter().any(|pk| pk == &signer) {
                        return Err(SnapshotAuthError::SignerNotTrusted);
                    }
                }
                // Ed25519 verify (ed25519-dalek; crypto crate reuse).
                use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                let vk = VerifyingKey::from_bytes(&signer)
                    .map_err(|_| SnapshotAuthError::InvalidSignerKey)?;
                let sig_arr: [u8; 64] = sig
                    .as_slice()
                    .try_into()
                    .map_err(|_| SnapshotAuthError::InvalidSignatureLength)?;
                let signature = Signature::from_bytes(&sig_arr);
                let digest = self.calculate_digest();
                vk.verify(&digest, &signature)
                    .map_err(|_| SnapshotAuthError::SignatureInvalid)
            }
        }
    }

    /// Fallible serialization for the durable snapshot-production path (Phase 0.32):
    /// surfaces a serialization error to the caller instead of silently writing
    /// an empty/corrupt snapshot. This is the exact failure class that hid the
    /// Phase 0.16 registry tuple-key bug.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| format!("Failed to serialize snapshot V2: {e}"))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // Phase 0.32: fail-fast rather than silently produce empty bytes. StateSnapshotV2
        // is a plain data type post-Phase 0.16 (no tuple-key maps), so failure is a bug.
        self.try_to_bytes()
            .expect("BUG: StateSnapshotV2 must serialize to_bytes")
    }

    /// Produce the staged migration report used by the offline
    /// `--migrate-v2` gate and by tests. Phase 2 §1.4 deliberately keeps this
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
        let mut snapshot: StateSnapshotV2 = serde_json::from_slice(data)
            .map_err(|e| format!("Failed to parse snapshot V2: {e}"))?;
        snapshot.migration_report()?;
        // C6 legacy-import (RFC_GAP1 §7.3 AllowUnsigned geçiş penceresi):
        // schema<4 snapshot'lar eski digest ile geldi; yeni kod schema-4 digest
        // verir. snapshot_hash'i recompute + AllowUnsigned (devnet geçişi).
        // RequireSigned production loader imza bekler (sign_manifest).
        if snapshot.schema_version < CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION {
            snapshot.schema_version = CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION;
            snapshot.snapshot_hash = snapshot.calculate_hash();
        }
        Ok(snapshot)
    }

    /// C4 GAP-1: snapshot'ı imzala (production loader/HSM signer).
    pub fn sign_manifest(
        &mut self,
        secret_key: &ed25519_dalek::SigningKey,
        signer_pubkey: [u8; 32],
    ) {
        use ed25519_dalek::Signer;
        let digest = self.calculate_digest();
        let signature = secret_key.sign(&digest).to_bytes();
        self.manifest_signer = Some(signer_pubkey);
        self.manifest_signature = Some(signature.to_vec());
        self.trust_policy = SnapshotTrustPolicy::RequireSigned;
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
        ); // Phase 0.16: bumped 2->3
        assert_eq!(snapshot_v2.height, 105);
        assert!(snapshot_v2.verify());

        let bytes = snapshot_v2.to_bytes();
        let deserialized = StateSnapshotV2::from_bytes(&bytes).unwrap();
        assert_eq!(deserialized.height, 105);
        assert_eq!(
            deserialized.schema_version,
            CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION
        ); // Phase 0.16: bumped 2->3
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

    // --- C3/C4 GAP-1/GAP-2 tests (P2 schema-4) ---

    #[test]
    fn test_gap2_schema4_digest_includes_bns_field() {
        // GAP-2 pin: schema-4 digest bns_registry'yi kapsar. None vs Some(default)
        // farklı tag (0 vs 1) → farklı digest (forgery surface kapalı).
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
        s1.bns_registry = None; // None vs Some(default) → farklı tag
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

    #[test]
    fn test_gap1_require_signed_sign_verify_roundtrip() {
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
        snapshot.trust_policy = SnapshotTrustPolicy::RequireSigned;
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
        assert_eq!(
            snapshot.verify_authentic(Some(&[wrong_pk])).unwrap_err(),
            SnapshotAuthError::SignatureInvalid
        );
    }
}
