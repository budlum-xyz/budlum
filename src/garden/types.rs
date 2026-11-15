//! Garden chain types: identifiers, genesis, transactions, headers and votes.
//!
//! Every hash preimage here is built with `hash_fields_bytes`, so each field
//! is length prefixed and carries its own domain tag.

use crate::core::address::Address;
use crate::core::chain_config::Network;
use crate::core::hash::hash_fields_bytes;
use crate::crypto::primitives::{verify_signature, KeyPair};
use crate::domain::types::{ConsensusKind, DomainCommitment, DomainId, DomainStatus, Hash32};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Domain tag for deriving a Garden chain id.
const TAG_GARDEN_CHAIN_ID: &[u8] = b"BDLM_GARDEN_CHAIN_ID_V1";
/// Domain tag for deriving the Budlum domain id of a Garden.
const TAG_GARDEN_DOMAIN: &[u8] = b"BDLM_GARDEN_DOMAIN_V1";
/// Domain tag for the Garden genesis hash.
const TAG_GARDEN_GENESIS: &[u8] = b"BDLM_GARDEN_GENESIS_V1";
/// Domain tag for Garden transaction ids and signatures.
const TAG_GARDEN_TX: &[u8] = b"BDLM_GARDEN_TX_V1";
/// Domain tag for Garden block header hashes.
const TAG_GARDEN_BLOCK: &[u8] = b"BDLM_GARDEN_BLOCK_V1";
/// Domain tag for deriving the invite key from the invite token.
const TAG_GARDEN_INVITE: &[u8] = b"BDLM_GARDEN_INVITE_V1";
/// Domain tag for the message the invite key signs for a joiner.
const TAG_GARDEN_JOIN: &[u8] = b"BDLM_GARDEN_JOIN_V1";
/// Domain tag for presence signals.
const TAG_GARDEN_PRESENCE: &[u8] = b"BDLM_GARDEN_PRESENCE_V1";
/// Domain tag for the rendezvous score that places an object on validators.
const TAG_GARDEN_PLACEMENT: &[u8] = b"BDLM_GARDEN_PLACEMENT_V1";

/// High 16 bits ("GA") that mark a chain id as a Garden chain id.
const GARDEN_CHAIN_PREFIX: u64 = 0x4741_0000_0000_0000;
const GARDEN_CHAIN_LOW_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;
/// High bit that marks a Budlum domain id as derived from a Garden chain id.
const GARDEN_DOMAIN_PREFIX: DomainId = 0x8000_0000;

/// Longest validator display name, in bytes.
pub const MAX_NAME_BYTES: usize = 32;
/// Longest Garden title, in bytes.
const MAX_TITLE_BYTES: usize = 64;
/// Longest announced network address, in bytes.
pub const MAX_ADDRESS_BYTES: usize = 256;
/// Longest MIME type of a published object, in bytes.
pub const MAX_MIME_BYTES: usize = 64;
/// Longest caption of a published object, in bytes.
pub const MAX_CAPTION_BYTES: usize = 128;

/// An ed25519 public key. It is the validator identity, the libp2p identity
/// and the Budlum `PoA` authority address at once.
pub type GardenKey = [u8; 32];

/// Copy the leading bytes of a digest into a fixed array without indexing.
fn leading<const N: usize>(digest: &Hash32) -> [u8; N] {
    let mut out = [0u8; N];
    for (dst, src) in out.iter_mut().zip(digest.iter()) {
        *dst = *src;
    }
    out
}

/// A Garden chain id. It always carries the Garden prefix, so it can never
/// equal a primary Budlum chain id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GardenChainId(u64);

impl GardenChainId {
    /// Derive the chain id from the host key and a creation nonce.
    fn derive(host: &GardenKey, nonce: u64) -> Self {
        let digest = hash_fields_bytes(&[TAG_GARDEN_CHAIN_ID, host, &nonce.to_le_bytes()]);
        let low = u64::from_le_bytes(leading::<8>(&digest)) & GARDEN_CHAIN_LOW_MASK;
        Self(GARDEN_CHAIN_PREFIX | low)
    }

    const fn value(self) -> u64 {
        self.0
    }

    /// True when the id carries the Garden prefix and is not a primary chain.
    fn is_valid_garden_id(self) -> bool {
        (self.0 & !GARDEN_CHAIN_LOW_MASK) == GARDEN_CHAIN_PREFIX && !is_primary_budlum_chain(self.0)
    }
}

/// True for the primary Budlum networks, where Garden transactions are closed.
fn is_primary_budlum_chain(raw_chain_id: u64) -> bool {
    [Network::Mainnet, Network::Testnet, Network::Devnet]
        .iter()
        .any(|network| network.chain_id().value() == raw_chain_id)
}

/// Decide whether a Garden transaction may execute on `target_chain_id`.
///
/// Garden transaction types are open only on a Garden chain id. A primary
/// Budlum chain refuses them with a reason that names the network.
pub fn verify_garden_execution_chain(target_chain_id: u64) -> Result<(), String> {
    for (network, label) in [
        (Network::Testnet, "Testnet"),
        (Network::Mainnet, "Mainnet"),
        (Network::Devnet, "Devnet"),
    ] {
        if network.chain_id().value() == target_chain_id {
            return Err(format!(
                "garden transactions are closed on Budlum {label} (chain {target_chain_id})"
            ));
        }
    }
    if !GardenChainId(target_chain_id).is_valid_garden_id() {
        return Err(format!(
            "chain {target_chain_id} is not a Garden chain id; garden transactions are refused"
        ));
    }
    Ok(())
}

/// The Budlum domain id under which a Garden registers.
///
/// Every validator derives the same id from the chain id, because the id is
/// part of the message the validators sign.
pub fn garden_domain_id(chain_id: u64) -> DomainId {
    let digest = hash_fields_bytes(&[TAG_GARDEN_DOMAIN, &chain_id.to_le_bytes()]);
    GARDEN_DOMAIN_PREFIX | (u32::from_le_bytes(leading::<4>(&digest)) & !GARDEN_DOMAIN_PREFIX)
}

/// Limits of one Garden. Every value is TESTNET-DEFAULT.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenLimits {
    /// Most validators that may be registered (active or suspended).
    pub max_validators: u32,
    /// Largest published object, in bytes.
    pub max_object_bytes: u32,
    /// Most transactions in one block.
    pub max_block_txs: u32,
    /// Most transactions of one sender in one block. This is the request
    /// rate limit: it is counted in blocks, not in wall-clock time.
    pub max_sender_txs_per_block: u32,
    /// Length of a proposer slot in milliseconds. A node paces its own
    /// rounds with it; block validity does not read the clock.
    pub round_ms: u32,
    /// Interval between presence signals in milliseconds.
    pub presence_interval_ms: u32,
    /// Silence after which a node reports the host as absent.
    pub host_timeout_ms: u32,
    /// Silence after which a node proposes to suspend a validator.
    pub suspend_after_ms: u32,
}

impl GardenLimits {
    pub const fn testnet_default() -> Self {
        Self {
            max_validators: 32,
            max_object_bytes: 4 * 1024 * 1024,
            max_block_txs: 64,
            max_sender_txs_per_block: 8,
            round_ms: 3_000,
            presence_interval_ms: 1_000,
            host_timeout_ms: 6_000,
            suspend_after_ms: 12_000,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if !(1..=256).contains(&self.max_validators) {
            return Err("max_validators must be in 1..=256".into());
        }
        if !(1..=16 * 1024 * 1024).contains(&self.max_object_bytes) {
            return Err("max_object_bytes must be in 1..=16 MiB".into());
        }
        if !(1..=1024).contains(&self.max_block_txs) {
            return Err("max_block_txs must be in 1..=1024".into());
        }
        if self.max_sender_txs_per_block == 0 || self.max_sender_txs_per_block > self.max_block_txs
        {
            return Err("max_sender_txs_per_block must be in 1..=max_block_txs".into());
        }
        if self.max_block_txs < self.max_validators {
            // One block must be able to report every absent validator and
            // still carry a transaction.
            return Err("max_block_txs must be at least max_validators".into());
        }
        if !(50..=60_000).contains(&self.round_ms) {
            return Err("round_ms must be in 50..=60000".into());
        }
        if !(20..=60_000).contains(&self.presence_interval_ms) {
            return Err("presence_interval_ms must be in 20..=60000".into());
        }
        if self.host_timeout_ms <= self.presence_interval_ms {
            return Err("host_timeout_ms must exceed presence_interval_ms".into());
        }
        if self.suspend_after_ms <= self.presence_interval_ms {
            return Err("suspend_after_ms must exceed presence_interval_ms".into());
        }
        Ok(())
    }

    fn digest_fields(&self) -> [u8; 32] {
        hash_fields_bytes(&[
            &self.max_validators.to_le_bytes(),
            &self.max_object_bytes.to_le_bytes(),
            &self.max_block_txs.to_le_bytes(),
            &self.max_sender_txs_per_block.to_le_bytes(),
            &self.round_ms.to_le_bytes(),
            &self.presence_interval_ms.to_le_bytes(),
            &self.host_timeout_ms.to_le_bytes(),
            &self.suspend_after_ms.to_le_bytes(),
        ])
    }
}

impl Default for GardenLimits {
    fn default() -> Self {
        Self::testnet_default()
    }
}

/// One row of the placement table: up to `validators_up_to` active
/// validators, an object is held by `holders` of them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct GardenPlacementRow {
    validators_up_to: u32,
    holders: u32,
}

/// The placement table a Garden carries in its genesis.
///
/// The table has no validator class and is computed for a small validator
/// count. Targets follow the lifetime of the Garden: an object needs to
/// survive one sudden departure, not years of churn.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenPlacementTable {
    rows: Vec<GardenPlacementRow>,
}

impl GardenPlacementTable {
    /// One holder for one validator, two for two, three from then on.
    fn for_small_networks(max_validators: u32) -> Self {
        let mut rows = vec![
            GardenPlacementRow {
                validators_up_to: 1,
                holders: 1,
            },
            GardenPlacementRow {
                validators_up_to: 2,
                holders: 2,
            },
        ];
        rows.push(GardenPlacementRow {
            validators_up_to: max_validators.max(3),
            holders: 3,
        });
        Self { rows }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.rows.is_empty() || self.rows.len() > 16 {
            return Err("placement table must have 1..=16 rows".into());
        }
        let mut previous = 0u32;
        for row in &self.rows {
            if row.validators_up_to <= previous {
                return Err("placement rows must be strictly increasing".into());
            }
            if row.holders == 0 || row.holders > row.validators_up_to {
                return Err("placement holders must be in 1..=validators_up_to".into());
            }
            previous = row.validators_up_to;
        }
        Ok(())
    }

    /// How many validators hold an object when `active` validators exist.
    fn holders_for(&self, active: usize) -> usize {
        let active_u32 = u32::try_from(active).unwrap_or(u32::MAX);
        let holders = self
            .rows
            .iter()
            .find(|row| active_u32 <= row.validators_up_to)
            .or_else(|| self.rows.last())
            .map_or(1, |row| row.holders);
        (holders as usize).min(active)
    }

    /// The validators that hold `content_id`, chosen by rendezvous hashing.
    ///
    /// The choice is a pure function of the content id and the active set,
    /// so every validator derives the same holders. When the network shrinks
    /// the table selects the new bucket and the survivors keep their place.
    pub fn holders(&self, content_id: &Hash32, active: &[GardenKey]) -> Vec<GardenKey> {
        let mut scored: Vec<(Hash32, GardenKey)> = active
            .iter()
            .map(|key| {
                (
                    hash_fields_bytes(&[TAG_GARDEN_PLACEMENT, content_id, key]),
                    *key,
                )
            })
            .collect();
        scored.sort_unstable();
        scored
            .into_iter()
            .take(self.holders_for(active.len()))
            .map(|(_, key)| key)
            .collect()
    }

    fn digest_fields(&self) -> Hash32 {
        let mut bytes = Vec::with_capacity(self.rows.len() * 8);
        for row in &self.rows {
            bytes.extend_from_slice(&row.validators_up_to.to_le_bytes());
            bytes.extend_from_slice(&row.holders.to_le_bytes());
        }
        hash_fields_bytes(&[&(self.rows.len() as u64).to_le_bytes(), &bytes])
    }
}

/// True when `label` is safe to show and never looks like a path.
pub fn is_safe_label(label: &str, max_bytes: usize) -> bool {
    !label.trim().is_empty()
        && label.len() <= max_bytes
        && !label.chars().any(char::is_control)
        && !label.contains(['/', '\\'])
        && label != "."
        && label != ".."
}

/// The invite key pair derived from the invite token.
///
/// Genesis carries the public half. Whoever holds the invite can sign a join
/// request with the secret half, and every validator checks that signature
/// against genesis without knowing the token.
pub fn invite_keypair(token: &Hash32) -> Result<KeyPair, String> {
    let seed = hash_fields_bytes(&[TAG_GARDEN_INVITE, token]);
    KeyPair::from_seed(&seed).map_err(|e| format!("garden invite key derivation failed: {e}"))
}

/// The message the invite key signs for `joiner`. It names the chain and the
/// joiner, so a signature cannot be replayed for another key or Garden.
pub fn join_message(chain_id: u64, joiner: &GardenKey) -> Hash32 {
    hash_fields_bytes(&[TAG_GARDEN_JOIN, &chain_id.to_le_bytes(), joiner])
}

/// What the host chooses when it creates a Garden.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GardenFounding {
    pub title: String,
    pub host_name: String,
    pub host_address: String,
    pub limits: GardenLimits,
}

/// The genesis of a Garden chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenGenesis {
    pub chain_id: u64,
    pub title: String,
    pub host: GardenKey,
    pub host_name: String,
    pub host_address: String,
    pub created_unix_ms: u64,
    pub nonce: u64,
    pub limits: GardenLimits,
    pub placement: GardenPlacementTable,
    /// Public half of the invite key. A join request is signed by it.
    pub invite_key: GardenKey,
}

impl GardenGenesis {
    /// Build the genesis of a new Garden for `host`.
    pub fn new(
        founding: GardenFounding,
        host: GardenKey,
        created_unix_ms: u64,
        nonce: u64,
        invite_token: &Hash32,
    ) -> Result<Self, String> {
        let genesis = Self {
            chain_id: GardenChainId::derive(&host, nonce).value(),
            title: founding.title,
            host,
            host_name: founding.host_name,
            host_address: founding.host_address,
            created_unix_ms,
            nonce,
            placement: GardenPlacementTable::for_small_networks(founding.limits.max_validators),
            limits: founding.limits,
            invite_key: invite_keypair(invite_token)?.public_key_bytes(),
        };
        genesis.verify()?;
        Ok(genesis)
    }

    /// Check a genesis received from a peer. Nothing in it is trusted: the
    /// chain id is re-derived and every bound is re-checked.
    pub fn verify(&self) -> Result<(), String> {
        if GardenChainId::derive(&self.host, self.nonce).value() != self.chain_id {
            return Err("garden genesis chain id does not derive from host and nonce".into());
        }
        if !GardenChainId(self.chain_id).is_valid_garden_id() {
            return Err("garden genesis chain id is not a Garden chain id".into());
        }
        if !is_safe_label(&self.title, MAX_TITLE_BYTES) {
            return Err("garden title must be 1..=64 bytes without control characters".into());
        }
        if !is_safe_label(&self.host_name, MAX_NAME_BYTES) {
            return Err("garden host name must be 1..=32 bytes without control characters".into());
        }
        if self.host_address.len() > MAX_ADDRESS_BYTES {
            return Err("garden host address is too long".into());
        }
        self.limits.validate()?;
        self.placement.validate()
    }

    /// The genesis hash. It is computed from the fields on every call and is
    /// never read from a field a peer could set.
    pub fn hash(&self) -> Hash32 {
        hash_fields_bytes(&[
            TAG_GARDEN_GENESIS,
            &self.chain_id.to_le_bytes(),
            self.title.as_bytes(),
            &self.host,
            self.host_name.as_bytes(),
            self.host_address.as_bytes(),
            &self.created_unix_ms.to_le_bytes(),
            &self.nonce.to_le_bytes(),
            &self.limits.digest_fields(),
            &self.placement.digest_fields(),
            &self.invite_key,
        ])
    }
}

/// Where a validator stands in the Garden's `PoA` identity record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GardenValidatorStatus {
    /// Proposes, executes and votes.
    Active,
    /// Its presence signal stopped. It holds no duty and loses nothing.
    Suspended,
    /// It left on its own.
    Left,
}

impl GardenValidatorStatus {
    pub const fn code(self) -> u8 {
        match self {
            Self::Active => 0,
            Self::Suspended => 1,
            Self::Left => 2,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Active => "Active",
            Self::Suspended => "Suspended",
            Self::Left => "Left",
        }
    }
}

/// One entry of the Garden's `PoA` identity record. There is no stake, no
/// class and no reward field, because the Garden chain has none of them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenValidator {
    pub key: GardenKey,
    pub name: String,
    /// The address this validator announced as reachable. Empty when the
    /// validator is behind a NAT and is reached through its peers.
    pub address: String,
    pub status: GardenValidatorStatus,
    pub joined_height: u64,
}

/// What a published object is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GardenContentKind {
    Message,
    Post,
    Image,
}

impl GardenContentKind {
    pub const fn code(self) -> u8 {
        match self {
            Self::Message => 0,
            Self::Post => 1,
            Self::Image => 2,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Post => "post",
            Self::Image => "image",
        }
    }

    pub fn parse(label: &str) -> Result<Self, String> {
        match label {
            "message" => Ok(Self::Message),
            "post" => Ok(Self::Post),
            "image" => Ok(Self::Image),
            other => Err(format!(
                "unknown garden content kind '{other}', expected message, post or image"
            )),
        }
    }
}

/// The Garden transaction types. They exist only on a Garden chain id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GardenTxKind {
    /// The sender becomes a validator. The signature shows it holds the invite.
    Join {
        name: String,
        address: String,
        invite_signature: Vec<u8>,
    },
    /// The sender leaves on its own.
    Leave,
    /// A suspended or departed sender returns.
    Resume { address: String },
    /// The sender reports that `target` stopped answering.
    Suspend { target: GardenKey },
    /// The sender publishes an object. The bytes live in the content store;
    /// the chain carries the content id.
    Publish {
        kind: GardenContentKind,
        content_id: Hash32,
        size: u32,
        mime: String,
        caption: String,
    },
}

impl GardenTxKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Join { .. } => "join",
            Self::Leave => "leave",
            Self::Resume { .. } => "resume",
            Self::Suspend { .. } => "suspend",
            Self::Publish { kind, .. } => kind.label(),
        }
    }

    /// The digest of the kind and every one of its fields.
    fn digest(&self) -> Hash32 {
        match self {
            Self::Join {
                name,
                address,
                invite_signature,
            } => hash_fields_bytes(&[
                &[0u8],
                name.as_bytes(),
                address.as_bytes(),
                invite_signature,
            ]),
            Self::Leave => hash_fields_bytes(&[&[1u8]]),
            Self::Resume { address } => hash_fields_bytes(&[&[2u8], address.as_bytes()]),
            Self::Suspend { target } => hash_fields_bytes(&[&[3u8], target]),
            Self::Publish {
                kind,
                content_id,
                size,
                mime,
                caption,
            } => hash_fields_bytes(&[
                &[4u8],
                &[kind.code()],
                content_id,
                &size.to_le_bytes(),
                mime.as_bytes(),
                caption.as_bytes(),
            ]),
        }
    }
}

/// An unsigned Garden transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenTx {
    pub chain_id: u64,
    pub sender: GardenKey,
    pub nonce: u64,
    pub kind: GardenTxKind,
}

impl GardenTx {
    /// The transaction id. It covers every field, and it is the message the
    /// sender signs.
    pub fn id(&self) -> Hash32 {
        hash_fields_bytes(&[
            TAG_GARDEN_TX,
            &self.chain_id.to_le_bytes(),
            &self.sender,
            &self.nonce.to_le_bytes(),
            &self.kind.digest(),
        ])
    }

    /// Sign the transaction. A key that is not the sender is refused, and so
    /// is a chain id on which Garden transactions are closed.
    pub fn sign(self, keypair: &KeyPair) -> Result<SignedGardenTx, String> {
        verify_garden_execution_chain(self.chain_id)?;
        if keypair.public_key_bytes() != self.sender {
            return Err("garden transaction sender does not match the signing key".into());
        }
        let signature = keypair.sign(&self.id()).to_vec();
        Ok(SignedGardenTx {
            tx: self,
            signature,
        })
    }
}

/// A signed Garden transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedGardenTx {
    pub tx: GardenTx,
    pub signature: Vec<u8>,
}

impl SignedGardenTx {
    pub fn id(&self) -> Hash32 {
        self.tx.id()
    }

    /// Check the chain id and the signature.
    pub fn verify(&self, chain_id: u64) -> Result<(), String> {
        verify_garden_execution_chain(self.tx.chain_id)?;
        if self.tx.chain_id != chain_id {
            return Err(format!(
                "garden transaction is for chain {}, this Garden is chain {chain_id}",
                self.tx.chain_id
            ));
        }
        verify_signature(&self.tx.id(), &self.signature, &self.tx.sender)
            .map_err(|e| format!("garden transaction signature is invalid: {e}"))
    }
}

/// The header of a Garden block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenHeader {
    pub chain_id: u64,
    pub height: u64,
    pub round: u64,
    pub parent_hash: Hash32,
    pub proposer: GardenKey,
    pub timestamp_ms: u64,
    pub tx_root: Hash32,
    pub state_root: Hash32,
    pub content_root: Hash32,
    /// Hash of the electorate that finalizes this block, in the form
    /// Budlum's `PoA` adapter derives it.
    pub authority_set_hash: Hash32,
    /// Hash of the active set once this block is applied.
    pub next_authority_set_hash: Hash32,
    /// Garden status once this block is applied.
    pub status_after: DomainStatus,
}

/// The one-byte code of a domain status inside a hash preimage.
pub const fn status_code(status: DomainStatus) -> u8 {
    match status {
        DomainStatus::Active => 0,
        DomainStatus::Frozen => 1,
        DomainStatus::Retired => 2,
    }
}

/// The label of a domain status in RPC answers.
pub const fn status_label(status: DomainStatus) -> &'static str {
    match status {
        DomainStatus::Active => "Active",
        DomainStatus::Frozen => "Frozen",
        DomainStatus::Retired => "Retired",
    }
}

impl GardenHeader {
    /// The block hash. It covers every header field.
    pub fn hash(&self) -> Hash32 {
        hash_fields_bytes(&[
            TAG_GARDEN_BLOCK,
            &self.chain_id.to_le_bytes(),
            &self.height.to_le_bytes(),
            &self.round.to_le_bytes(),
            &self.parent_hash,
            &self.proposer,
            &self.timestamp_ms.to_le_bytes(),
            &self.tx_root,
            &self.state_root,
            &self.content_root,
            &self.authority_set_hash,
            &self.next_authority_set_hash,
            &[status_code(self.status_after)],
        ])
    }

    /// The Budlum domain commitment this header stands for.
    ///
    /// `finality_proof_hash` is left zero here: the `PoA` signing message does
    /// not cover it, and the settlement link fills it in from the proof.
    pub fn commitment(&self) -> DomainCommitment {
        DomainCommitment {
            domain_id: garden_domain_id(self.chain_id),
            domain_height: self.height,
            domain_block_hash: self.hash(),
            parent_domain_block_hash: self.parent_hash,
            state_root: self.state_root,
            tx_root: self.tx_root,
            event_root: self.content_root,
            finality_proof_hash: [0u8; 32],
            consensus_kind: ConsensusKind::PoA,
            validator_set_hash: self.authority_set_hash,
            timestamp_ms: u128::from(self.timestamp_ms),
            sequence: self.height,
            producer: Some(Address(self.proposer)),
            state_updates: BTreeMap::new(),
        }
    }

    /// The message a validator signs to vote for this block.
    ///
    /// It is Budlum's own `PoA` commit message for the commitment above, so
    /// the votes of a Garden block are a `PoA` finality proof as they stand.
    fn vote_message(&self) -> Vec<u8> {
        crate::domain::finality_adapter::poa_commit_signing_message(
            self.chain_id,
            garden_domain_id(self.chain_id),
            &self.commitment(),
        )
    }
}

/// A Garden block: a header, its transactions and the proposer's signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenBlock {
    pub header: GardenHeader,
    pub txs: Vec<SignedGardenTx>,
    pub proposer_signature: Vec<u8>,
}

impl GardenBlock {
    pub fn hash(&self) -> Hash32 {
        self.header.hash()
    }
}

/// A validator's vote for a block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenVote {
    pub chain_id: u64,
    pub height: u64,
    pub block_hash: Hash32,
    pub voter: GardenKey,
    pub signature: Vec<u8>,
}

impl GardenVote {
    pub fn sign(header: &GardenHeader, keypair: &KeyPair) -> Self {
        Self {
            chain_id: header.chain_id,
            height: header.height,
            block_hash: header.hash(),
            voter: keypair.public_key_bytes(),
            signature: keypair.sign(&header.vote_message()).to_vec(),
        }
    }

    /// Check that the vote is for `header` and that the signature holds.
    pub fn verify(&self, header: &GardenHeader) -> Result<(), String> {
        if self.chain_id != header.chain_id
            || self.height != header.height
            || self.block_hash != header.hash()
        {
            return Err("garden vote does not name this block".into());
        }
        verify_signature(&header.vote_message(), &self.signature, &self.voter)
            .map_err(|e| format!("garden vote signature is invalid: {e}"))
    }
}

/// A finalized block: the block and the votes that finalized it. This is the
/// Garden finality certificate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenCommit {
    pub block: GardenBlock,
    pub votes: Vec<GardenVote>,
}

/// A presence signal. One message per validator per window; the signed
/// message is fixed by the window, so two signals for one window are equal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenPresence {
    pub chain_id: u64,
    pub validator: GardenKey,
    pub window: u64,
    pub signature: Vec<u8>,
}

impl GardenPresence {
    fn message(chain_id: u64, window: u64) -> Hash32 {
        hash_fields_bytes(&[
            TAG_GARDEN_PRESENCE,
            &chain_id.to_le_bytes(),
            &window.to_le_bytes(),
        ])
    }

    pub fn sign(chain_id: u64, window: u64, keypair: &KeyPair) -> Self {
        Self {
            chain_id,
            validator: keypair.public_key_bytes(),
            window,
            signature: keypair.sign(&Self::message(chain_id, window)).to_vec(),
        }
    }

    pub fn verify(&self, chain_id: u64) -> Result<(), String> {
        if self.chain_id != chain_id {
            return Err("garden presence signal is for another chain".into());
        }
        verify_signature(
            &Self::message(self.chain_id, self.window),
            &self.signature,
            &self.validator,
        )
        .map_err(|e| format!("garden presence signature is invalid: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> KeyPair {
        KeyPair::generate().unwrap()
    }

    #[test]
    fn garden_chain_id_never_equals_a_primary_chain() {
        for nonce in 0..64u64 {
            let id = GardenChainId::derive(&keypair().public_key_bytes(), nonce);
            assert!(id.is_valid_garden_id());
            assert!(!is_primary_budlum_chain(id.value()));
        }
    }

    #[test]
    fn garden_chain_id_is_refused_on_every_primary_network() {
        let testnet = Network::Testnet.chain_id().value();
        let refusal = verify_garden_execution_chain(testnet).unwrap_err();
        assert!(refusal.contains("closed on Budlum Testnet"), "{refusal}");
        for network in [Network::Mainnet, Network::Devnet] {
            assert!(verify_garden_execution_chain(network.chain_id().value()).is_err());
        }
        assert!(verify_garden_execution_chain(7).is_err());

        let kp = keypair();
        let tx = GardenTx {
            chain_id: testnet,
            sender: kp.public_key_bytes(),
            nonce: 0,
            kind: GardenTxKind::Leave,
        };
        let refusal = tx.sign(&kp).unwrap_err();
        assert!(refusal.contains("closed on Budlum Testnet"), "{refusal}");
    }

    #[test]
    fn garden_tx_id_covers_every_field() {
        let kp = keypair();
        let chain_id = GardenChainId::derive(&kp.public_key_bytes(), 1).value();
        let base = GardenTx {
            chain_id,
            sender: kp.public_key_bytes(),
            nonce: 3,
            kind: GardenTxKind::Publish {
                kind: GardenContentKind::Post,
                content_id: [7u8; 32],
                size: 10,
                mime: "text/plain".into(),
                caption: "hello".into(),
            },
        };
        let mut other_nonce = base.clone();
        other_nonce.nonce = 4;
        let mut other_kind = base.clone();
        other_kind.kind = GardenTxKind::Publish {
            kind: GardenContentKind::Message,
            content_id: [7u8; 32],
            size: 10,
            mime: "text/plain".into(),
            caption: "hello".into(),
        };
        let mut other_caption = base.clone();
        other_caption.kind = GardenTxKind::Publish {
            kind: GardenContentKind::Post,
            content_id: [7u8; 32],
            size: 10,
            mime: "text/plain".into(),
            caption: "hellp".into(),
        };
        assert_ne!(base.id(), other_nonce.id());
        assert_ne!(base.id(), other_kind.id());
        assert_ne!(base.id(), other_caption.id());

        let signed = base.clone().sign(&kp).unwrap();
        signed.verify(chain_id).unwrap();
        let mut forged = signed;
        forged.tx.nonce = 9;
        assert!(forged.verify(chain_id).is_err());
        assert!(base.sign(&keypair()).is_err());
    }

    #[test]
    fn garden_genesis_hash_is_recomputed_and_bounds_are_checked() {
        let kp = keypair();
        let token = [9u8; 32];
        let genesis = GardenGenesis::new(
            GardenFounding {
                title: "Room".into(),
                host_name: "host".into(),
                host_address: "/ip4/127.0.0.1/tcp/1".into(),
                limits: GardenLimits::default(),
            },
            kp.public_key_bytes(),
            1,
            2,
            &token,
        )
        .unwrap();
        genesis.verify().unwrap();

        let mut wider = genesis.clone();
        wider.limits.max_validators = 200;
        assert_ne!(wider.hash(), genesis.hash());

        let mut broken = genesis.clone();
        broken.limits.max_validators = 0;
        assert!(broken.verify().is_err());

        let mut moved = genesis.clone();
        moved.nonce = 3;
        assert!(moved.verify().is_err());

        let mut path = genesis;
        path.host_name = "../x".into();
        assert!(path.verify().is_err());
    }

    #[test]
    fn garden_placement_shrinks_with_the_network_and_keeps_survivors() {
        let table = GardenPlacementTable::for_small_networks(32);
        table.validate().unwrap();
        assert_eq!(table.holders_for(1), 1);
        assert_eq!(table.holders_for(2), 2);
        assert_eq!(table.holders_for(6), 3);
        assert_eq!(table.holders_for(0), 0);

        let keys: Vec<GardenKey> = (0..6u8).map(|i| [i; 32]).collect();
        let content = [42u8; 32];
        let before = table.holders(&content, &keys);
        assert_eq!(before.len(), 3);
        let gone = before.first().copied().unwrap();
        let rest: Vec<GardenKey> = keys.iter().copied().filter(|k| *k != gone).collect();
        let after = table.holders(&content, &rest);
        assert_eq!(after.len(), 3);
        for survivor in before.iter().filter(|k| **k != gone) {
            assert!(after.contains(survivor));
        }
    }

    #[test]
    fn garden_votes_are_budlum_poa_signatures() {
        let kp = keypair();
        let chain_id = GardenChainId::derive(&kp.public_key_bytes(), 5).value();
        let header = GardenHeader {
            chain_id,
            height: 1,
            round: 0,
            parent_hash: [1u8; 32],
            proposer: kp.public_key_bytes(),
            timestamp_ms: 10,
            tx_root: [2u8; 32],
            state_root: [3u8; 32],
            content_root: [4u8; 32],
            authority_set_hash: [5u8; 32],
            next_authority_set_hash: [5u8; 32],
            status_after: DomainStatus::Active,
        };
        let vote = GardenVote::sign(&header, &kp);
        vote.verify(&header).unwrap();
        let message = crate::domain::finality_adapter::poa_commit_signing_message(
            chain_id,
            garden_domain_id(chain_id),
            &header.commitment(),
        );
        verify_signature(&message, &vote.signature, &vote.voter).unwrap();

        let mut other = header.clone();
        other.status_after = DomainStatus::Frozen;
        assert_ne!(other.hash(), header.hash());
        assert!(vote.verify(&other).is_err());
        assert!(garden_domain_id(chain_id) >= 0x8000_0000);
    }

    #[test]
    fn garden_presence_is_bound_to_chain_and_window() {
        let kp = keypair();
        let signal = GardenPresence::sign(77, 3, &kp);
        signal.verify(77).unwrap();
        assert!(signal.verify(78).is_err());
        let mut later = signal;
        later.window = 4;
        assert!(later.verify(77).is_err());
    }

    #[test]
    fn garden_labels_refuse_paths_and_control_characters() {
        assert!(is_safe_label("alice", MAX_NAME_BYTES));
        for bad in ["", "  ", "..", ".", "a/b", "a\\b", "a\nb"] {
            assert!(!is_safe_label(bad, MAX_NAME_BYTES), "{bad:?}");
        }
        assert!(!is_safe_label(&"x".repeat(33), MAX_NAME_BYTES));
    }

    #[test]
    fn garden_join_signature_is_bound_to_the_joiner_and_the_chain() {
        let token = [1u8; 32];
        let invite = invite_keypair(&token).unwrap();
        let joiner = [2u8; 32];
        let signature = invite.sign(&join_message(7, &joiner));
        let key = invite.public_key_bytes();
        verify_signature(&join_message(7, &joiner), &signature, &key).unwrap();
        assert!(verify_signature(&join_message(7, &[3u8; 32]), &signature, &key).is_err());
        assert!(verify_signature(&join_message(8, &joiner), &signature, &key).is_err());
        assert_ne!(invite_keypair(&[4u8; 32]).unwrap().public_key_bytes(), key);
    }
}
