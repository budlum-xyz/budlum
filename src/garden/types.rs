use crate::core::chain_config::Network;
use crate::core::hash::hash_fields_bytes;
use crate::crypto::primitives::{verify_signature, KeyPair};
use serde::{Deserialize, Serialize};

/// Domain tag for deriving isolated Garden chain identifiers.
const TAG_GARDEN_CHAIN_ID: &[u8] = b"BDLM_GARDEN_CHAIN_ID_V1";
/// Domain tag for Garden genesis block hashing.
pub const TAG_GARDEN_GENESIS: &[u8] = b"BDLM_GARDEN_GENESIS_V1";
/// Domain tag for Garden transaction signing and hashing.
const TAG_GARDEN_TX: &[u8] = b"BDLM_GARDEN_TX_V1";
/// Domain tag for Garden block header hashing and PoA voting.
pub const TAG_GARDEN_BLOCK: &[u8] = b"BDLM_GARDEN_BLOCK_V1";
/// Domain tag for Garden block PoA vote messages.
const TAG_GARDEN_VOTE: &[u8] = b"BDLM_GARDEN_VOTE_V1";
/// Domain tag for Garden content identifiers (B.U.D. 3.0 aligned).
pub const TAG_GARDEN_CONTENT: &[u8] = b"BDLM_GARDEN_CONTENT_V1";
/// Domain tag for Garden erasure/replica object commitments.
pub const TAG_GARDEN_OBJECT: &[u8] = b"BDLM_GARDEN_OBJECT_V1";
/// Domain tag for Garden host liveness heartbeat signals (7.8 aligned).
pub const TAG_GARDEN_PRESENCE: &[u8] = b"BDLM_GARDEN_PRESENCE_V1";
/// Domain tag for Garden invite payload integrity.
pub const TAG_GARDEN_INVITE: &[u8] = b"BDLM_GARDEN_INVITE_V1";

/// High 16-bit prefix ("GA") reserved exclusively for Garden sovereign chains.
const GARDEN_CHAIN_PREFIX_MASK: u64 = 0x4741_0000_0000_0000;
const GARDEN_CHAIN_LOW_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Sovereign Garden chain identifier, guaranteed disjoint from Budlum Mainnet
/// (45260), Testnet (45261), and Devnet (45262).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GardenChainId(pub u64);

impl GardenChainId {
    /// Derive a deterministic Garden chain ID from the host public key and a
    /// creation nonce. Always carries the `"GA"` prefix so it can never collide
    /// with Budlum primary network chain IDs.
    pub fn derive(host_pubkey: &[u8; 32], nonce: u64) -> Self {
        let digest = hash_fields_bytes(&[TAG_GARDEN_CHAIN_ID, host_pubkey, &nonce.to_le_bytes()]);
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&digest[..8]);
        let mut value =
            GARDEN_CHAIN_PREFIX_MASK | (u64::from_le_bytes(raw) & GARDEN_CHAIN_LOW_MASK);
        if is_primary_budlum_chain(value) || value == 0 {
            value |= 1;
        }
        Self(value)
    }

    pub fn value(self) -> u64 {
        self.0
    }

    /// Returns `true` only when `self` carries the dedicated Garden namespace
    /// prefix and is not any primary Budlum network chain ID.
    pub fn is_valid_garden_id(self) -> bool {
        (self.0 & !GARDEN_CHAIN_LOW_MASK) == GARDEN_CHAIN_PREFIX_MASK
            && !is_primary_budlum_chain(self.0)
    }
}

/// Returns `true` for Budlum primary networks where Garden transactions are
/// strictly forbidden (G-7).
pub fn is_primary_budlum_chain(raw_chain_id: u64) -> bool {
    raw_chain_id == Network::Mainnet.chain_id().value()
        || raw_chain_id == Network::Testnet.chain_id().value()
        || raw_chain_id == Network::Devnet.chain_id().value()
}

/// Verify that a Garden transaction is allowed to execute on `target_chain_id`.
///
/// Explicitly refuses Budlum Testnet (45261), Mainnet (45260), Devnet (45262),
/// and any non-Garden chain ID (G-7).
pub fn verify_garden_execution_chain(target_chain_id: u64) -> Result<GardenChainId, String> {
    if target_chain_id == Network::Testnet.chain_id().value() {
        return Err(format!(
            "garden transactions are closed on Budlum Testnet (chain {})",
            target_chain_id
        ));
    }
    if target_chain_id == Network::Mainnet.chain_id().value() {
        return Err(format!(
            "garden transactions are closed on Budlum Mainnet (chain {})",
            target_chain_id
        ));
    }
    if target_chain_id == Network::Devnet.chain_id().value() {
        return Err(format!(
            "garden transactions are closed on Budlum Devnet (chain {})",
            target_chain_id
        ));
    }
    let cid = GardenChainId(target_chain_id);
    if !cid.is_valid_garden_id() {
        return Err(format!(
            "chain {} is not a valid isolated Garden chain id",
            target_chain_id
        ));
    }
    Ok(cid)
}

/// `TESTNET-DEFAULT` isolation limits for a Garden domain (Directive 3.10).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenLimits {
    /// Maximum number of active PoA validators allowed in one Garden.
    pub max_validators: usize,
    /// Maximum object payload size in bytes (images, posts, messages).
    pub max_object_bytes: usize,
    /// Maximum requests accepted per node per rate-limit window.
    pub max_requests_per_window: u32,
    /// Host absence threshold (in epochs/windows) before freezing the Garden.
    pub host_liveness_timeout_epochs: u64,
    /// Target replica count per stored content object (classless placement).
    pub target_replicas: usize,
}

impl GardenLimits {
    fn testnet_default() -> Self {
        Self {
            max_validators: 32,
            max_object_bytes: 4 * 1024 * 1024,
            max_requests_per_window: 64,
            host_liveness_timeout_epochs: 2,
            target_replicas: 3,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.max_validators == 0 || self.max_validators > 256 {
            return Err("max_validators must be in 1..=256".into());
        }
        if self.max_object_bytes == 0 || self.max_object_bytes > 16 * 1024 * 1024 {
            return Err("max_object_bytes must be in 1..=16MiB".into());
        }
        if self.max_requests_per_window == 0 {
            return Err("max_requests_per_window must be > 0".into());
        }
        if self.host_liveness_timeout_epochs == 0 {
            return Err("host_liveness_timeout_epochs must be > 0".into());
        }
        if self.target_replicas == 0 {
            return Err("target_replicas must be > 0".into());
        }
        Ok(())
    }
}

impl Default for GardenLimits {
    fn default() -> Self {
        Self::testnet_default()
    }
}

/// Classless placement table carried inside `GardenGenesis` (Directive 4.7).
///
/// There are no validator classes, tiers, or storage bonds in Garden. When the
/// validator set is small (for example 1..5 nodes) every object targets
/// `min(active_validators, target_replicas)` replicas and shrinks smoothly
/// down to 1 validator until the last participant leaves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenPlacementTable {
    pub target_replicas: usize,
    pub shrink_to_last_validator: bool,
}

impl GardenPlacementTable {
    fn from_limits(limits: &GardenLimits) -> Self {
        Self {
            target_replicas: limits.target_replicas,
            shrink_to_last_validator: true,
        }
    }

    /// Number of validators that must hold a copy given `active_validator_count`.
    pub fn effective_replicas(&self, active_validator_count: usize) -> usize {
        if active_validator_count == 0 {
            0
        } else {
            active_validator_count.min(self.target_replicas.max(1))
        }
    }
}

/// Genesis configuration of an isolated Garden chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenGenesis {
    pub chain_id: GardenChainId,
    pub title: String,
    pub host_pubkey: [u8; 32],
    pub created_unix_ms: u64,
    pub nonce: u64,
    pub limits: GardenLimits,
    pub placement_table: GardenPlacementTable,
    pub genesis_hash: [u8; 32],
}

impl GardenGenesis {
    pub fn new(
        title: String,
        host_pubkey: [u8; 32],
        created_unix_ms: u64,
        nonce: u64,
        limits: GardenLimits,
    ) -> Result<Self, String> {
        limits.validate()?;
        if title.trim().is_empty() || title.len() > 128 {
            return Err("garden title must be 1..=128 non-empty bytes".into());
        }
        let chain_id = GardenChainId::derive(&host_pubkey, nonce);
        let placement_table = GardenPlacementTable::from_limits(&limits);
        let mut genesis = Self {
            chain_id,
            title,
            host_pubkey,
            created_unix_ms,
            nonce,
            limits,
            placement_table,
            genesis_hash: [0u8; 32],
        };
        genesis.genesis_hash = genesis.compute_hash();
        Ok(genesis)
    }

    /// Recompute the genesis commitment from the canonical genesis fields.
    pub fn compute_hash(&self) -> [u8; 32] {
        hash_fields_bytes(&[
            TAG_GARDEN_GENESIS,
            &self.chain_id.value().to_le_bytes(),
            self.title.as_bytes(),
            &self.host_pubkey,
            &self.created_unix_ms.to_le_bytes(),
            &self.nonce.to_le_bytes(),
            &(self.limits.max_validators as u64).to_le_bytes(),
            &(self.limits.max_object_bytes as u64).to_le_bytes(),
            &(self.limits.max_requests_per_window as u64).to_le_bytes(),
            &self.limits.host_liveness_timeout_epochs.to_le_bytes(),
            &(self.placement_table.target_replicas as u64).to_le_bytes(),
        ])
    }

    /// Verify that a peer-supplied genesis satisfies `GardenLimits`, chain ID
    /// derivation, placement table derivation, and its own commitment hash.
    pub fn verify(&self) -> Result<(), String> {
        if self.title.trim().is_empty() || self.title.len() > 128 {
            return Err("garden title must be 1..=128 non-empty bytes".into());
        }
        self.limits.validate()?;
        if GardenChainId::derive(&self.host_pubkey, self.nonce) != self.chain_id {
            return Err("genesis chain_id does not match host_pubkey and nonce".into());
        }
        if GardenPlacementTable::from_limits(&self.limits) != self.placement_table {
            return Err("genesis placement_table does not match limits".into());
        }
        if self.compute_hash() != self.genesis_hash {
            return Err("genesis_hash verification failed".into());
        }
        Ok(())
    }
}

/// Validate a validator display label so it cannot escape filesystem paths.
pub fn is_safe_validator_label(name: &str) -> bool {
    !name.trim().is_empty()
        && name.len() <= 64
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains(':')
        && !name.contains('\0')
        && !name.chars().any(char::is_control)
}

/// PoA participant entry inside Garden.
///
/// There are intentionally no validator classes, stake amounts, fees,
/// rewards, or BUD minting fields (Directive 4.4, G-3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenValidatorEntry {
    pub pubkey: [u8; 32],
    pub display_name: String,
    pub is_host: bool,
    pub joined_height: u64,
    pub active: bool,
    pub last_presence_epoch: u64,
}

/// Content kind stored in Garden B.U.D. 3.0 storage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GardenContentKind {
    Message,
    Post,
    Image,
}

/// Garden-only transaction variants. Never admitted on primary Budlum chains.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GardenTxKind {
    JoinValidator {
        pubkey: [u8; 32],
        display_name: String,
    },
    LeaveValidator {
        pubkey: [u8; 32],
    },
    ReturnValidator {
        pubkey: [u8; 32],
    },
    HostHeartbeat {
        epoch: u64,
    },
    PublishMessage {
        text: String,
    },
    PublishPost {
        title: String,
        body: String,
        image_content_id: Option<[u8; 32]>,
    },
    PublishImage {
        mime_type: String,
        filename: String,
        content_id: [u8; 32],
        data: Vec<u8>,
    },
}

/// Unsigned Garden transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenTx {
    pub chain_id: u64,
    pub sender: [u8; 32],
    pub nonce: u64,
    pub kind: GardenTxKind,
}

impl GardenTx {
    fn canonical_payload(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| format!("failed to serialize garden tx: {e}"))
    }

    fn signing_digest(&self) -> Result<[u8; 32], String> {
        let payload = self.canonical_payload()?;
        Ok(hash_fields_bytes(&[
            TAG_GARDEN_TX,
            &self.chain_id.to_le_bytes(),
            &self.sender,
            &self.nonce.to_le_bytes(),
            &payload,
        ]))
    }

    pub fn sign(self, keypair: &KeyPair) -> Result<SignedGardenTx, String> {
        if keypair.public_key_bytes() != self.sender {
            return Err("signing keypair does not match transaction sender".into());
        }
        let digest = self.signing_digest()?;
        let signature = keypair.sign(&digest).to_vec();
        Ok(SignedGardenTx {
            tx: self,
            signature,
            tx_hash: digest,
        })
    }
}

/// Signed Garden transaction ready for inclusion in a Garden block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedGardenTx {
    pub tx: GardenTx,
    pub signature: Vec<u8>,
    pub tx_hash: [u8; 32],
}

impl SignedGardenTx {
    pub fn verify(&self, expected_chain_id: GardenChainId) -> Result<(), String> {
        verify_garden_execution_chain(self.tx.chain_id)?;
        if self.tx.chain_id != expected_chain_id.value() {
            return Err(format!(
                "garden tx chain_id {} does not match node chain {}",
                self.tx.chain_id,
                expected_chain_id.value()
            ));
        }
        let expected_digest = self.tx.signing_digest()?;
        if expected_digest != self.tx_hash {
            return Err("garden tx_hash mismatch".into());
        }
        verify_signature(&expected_digest, &self.signature, &self.tx.sender)
            .map_err(|e| format!("invalid garden tx signature: {e}"))?;
        Ok(())
    }
}

/// PoA validator vote on a Garden block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenVote {
    pub validator: [u8; 32],
    pub block_hash: [u8; 32],
    pub height: u64,
    pub round: u64,
    pub signature: Vec<u8>,
}

impl GardenVote {
    pub fn signing_message(
        chain_id: GardenChainId,
        height: u64,
        round: u64,
        block_hash: &[u8; 32],
    ) -> [u8; 32] {
        hash_fields_bytes(&[
            TAG_GARDEN_VOTE,
            &chain_id.value().to_le_bytes(),
            &height.to_le_bytes(),
            &round.to_le_bytes(),
            block_hash,
        ])
    }

    pub fn sign(
        keypair: &KeyPair,
        chain_id: GardenChainId,
        height: u64,
        round: u64,
        block_hash: [u8; 32],
    ) -> Self {
        let msg = Self::signing_message(chain_id, height, round, &block_hash);
        let sig = keypair.sign(&msg).to_vec();
        Self {
            validator: keypair.public_key_bytes(),
            block_hash,
            height,
            round,
            signature: sig,
        }
    }

    pub fn verify(&self, chain_id: GardenChainId) -> Result<(), String> {
        let msg = Self::signing_message(chain_id, self.height, self.round, &self.block_hash);
        verify_signature(&msg, &self.signature, &self.validator)
            .map_err(|e| format!("invalid garden block vote signature: {e}"))
    }
}

/// Finalized or proposed block inside an isolated Garden chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenBlock {
    pub chain_id: GardenChainId,
    pub height: u64,
    pub round: u64,
    pub parent_hash: [u8; 32],
    pub proposer: [u8; 32],
    pub timestamp_ms: u64,
    pub txs: Vec<SignedGardenTx>,
    pub state_root: [u8; 32],
    pub content_root: [u8; 32],
    pub block_hash: [u8; 32],
    pub proposer_sig: Vec<u8>,
    pub votes: Vec<GardenVote>,
}

/// Borrowed header fields hashed into a Garden block hash.
pub struct GardenBlockHashInput<'a> {
    pub chain_id: GardenChainId,
    pub height: u64,
    pub round: u64,
    pub parent_hash: &'a [u8; 32],
    pub proposer: &'a [u8; 32],
    pub timestamp_ms: u64,
    pub tx_hashes: &'a [[u8; 32]],
    pub state_root: &'a [u8; 32],
    pub content_root: &'a [u8; 32],
}

impl GardenBlock {
    pub fn compute_block_hash(input: &GardenBlockHashInput<'_>) -> [u8; 32] {
        let mut flat_tx_hashes = Vec::with_capacity(input.tx_hashes.len() * 32);
        for h in input.tx_hashes {
            flat_tx_hashes.extend_from_slice(h);
        }
        hash_fields_bytes(&[
            TAG_GARDEN_BLOCK,
            &input.chain_id.value().to_le_bytes(),
            &input.height.to_le_bytes(),
            &input.round.to_le_bytes(),
            input.parent_hash,
            input.proposer,
            &input.timestamp_ms.to_le_bytes(),
            &flat_tx_hashes,
            input.state_root,
            input.content_root,
        ])
    }
}

/// Stored message record inside Garden state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenMessageRecord {
    pub content_id: [u8; 32],
    pub tx_hash: [u8; 32],
    pub sender: [u8; 32],
    pub block_height: u64,
    pub text: String,
}

/// Stored social post record inside Garden state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenPostRecord {
    pub content_id: [u8; 32],
    pub tx_hash: [u8; 32],
    pub sender: [u8; 32],
    pub block_height: u64,
    pub title: String,
    pub body: String,
    pub image_content_id: Option<[u8; 32]>,
}

/// Stored image metadata record inside Garden state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenImageRecord {
    pub content_id: [u8; 32],
    pub tx_hash: [u8; 32],
    pub uploader: [u8; 32],
    pub block_height: u64,
    pub mime_type: String,
    pub filename: String,
    pub byte_len: u64,
}

/// Verifiable execution and finality trace for any Garden item (Directive 3.9).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenTrace {
    pub chain_id: u64,
    pub tx_hash_hex: String,
    pub content_id_hex: Option<String>,
    pub kind: String,
    pub sender_hex: String,
    pub block_height: u64,
    pub block_round: u64,
    pub block_hash_hex: String,
    pub proposer_hex: String,
    pub signing_validators_hex: Vec<String>,
    pub budlum_domain_id: Option<u32>,
    pub budlum_anchored_height: Option<u64>,
}
