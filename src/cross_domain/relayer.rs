//! Universal Relayer - permissionless cross-domain relay orchestrator.
//!
//! Architecture:
//! - Any account with the RELAYER role (staked via PermissionlessRegistry) can
//!   relay cross-domain messages. That check is the chain's
//!   (`Blockchain::submit_relay` calls `ensure_active_relayer` before this
//!   module sees the submission); `process_relay` itself does not know the
//!   registry and does not re-check the caller.
//! - The relayer watches for bridge lock/burn events on the source domain and
//!   Submits proofs to the target domain.
//! - Slashing: if a relayer submits an invalid proof or fails to relay within
//!   The expiry window, they can be slashed via the standard evidence path.
//!
//! Trust model: permissionless + economic security (stake + slashing).
//! No whitelist, no admin gate, no team-gated "official relayer" role.

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::event_tree::{DomainEvent, MerkleProof};
use crate::cross_domain::message::{CrossDomainMessage, MessageId};
use crate::domain::types::{DomainId, Hash32};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Errors specific to the Universal Relayer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayerError {
    /// The relayer is not registered or not active in the permissionless registry.
    NotActiveRelayer(Address),
    /// The message was already relayed (replay protection).
    AlreadyRelayed(MessageId),
    /// The proof failed verification.
    InvalidProof(String),
    /// The relay exceeded the transfer's expiry window.
    Expired {
        message_id: MessageId,
        expiry: u64,
        current_height: u64,
    },
    /// The bridge transfer is in an unexpected state for this relay operation.
    InvalidTransferState(MessageId),
    /// The source domain does not match the transfer's source.
    SourceDomainMismatch { expected: DomainId, got: DomainId },
    /// Generic relay error.
    Other(String),
}

impl std::fmt::Display for RelayerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayerError::NotActiveRelayer(addr) => {
                write!(f, "address {} is not an active relayer", addr)
            }
            RelayerError::AlreadyRelayed(id) => {
                write!(f, "message {} already relayed", hex::encode(id))
            }
            RelayerError::InvalidProof(reason) => {
                write!(f, "invalid relay proof: {}", reason)
            }
            RelayerError::Expired {
                message_id,
                expiry,
                current_height,
            } => {
                write!(
                    f,
                    "relay expired: message {}, expiry={}, current={}",
                    hex::encode(message_id),
                    expiry,
                    current_height
                )
            }
            RelayerError::InvalidTransferState(id) => {
                write!(f, "transfer {} in invalid state for relay", hex::encode(id),)
            }
            RelayerError::SourceDomainMismatch { expected, got } => {
                write!(
                    f,
                    "source domain mismatch: expected {}, got {}",
                    expected, got
                )
            }
            RelayerError::Other(msg) => write!(f, "relay error: {}", msg),
        }
    }
}

impl std::error::Error for RelayerError {}

/// Tracks which messages have been relayed and by whom.
/// Used for replay protection and slashing evidence.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelayLedger {
    /// Message_id → (relayer_address, relay_height, proof_hash)
    #[serde(with = "crate::core::map_keys")]
    relayed: BTreeMap<MessageId, RelayRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayRecord {
    pub relayer: Address,
    pub relay_height: u64,
    pub proof_hash: Hash32,
}

impl RelayLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a relay. Returns Err if already relayed (replay).
    pub fn record(
        &mut self,
        message_id: MessageId,
        relayer: Address,
        height: u64,
        proof_hash: Hash32,
    ) -> Result<(), RelayerError> {
        if self.relayed.contains_key(&message_id) {
            return Err(RelayerError::AlreadyRelayed(message_id));
        }
        self.relayed.insert(
            message_id,
            RelayRecord {
                relayer,
                relay_height: height,
                proof_hash,
            },
        );
        Ok(())
    }

    pub fn is_relayed(&self, message_id: &MessageId) -> bool {
        self.relayed.contains_key(message_id)
    }

    pub fn get_record(&self, message_id: &MessageId) -> Option<&RelayRecord> {
        self.relayed.get(message_id)
    }

    /// Drop records of relays that completed at or before `cutoff`.
    ///
    /// The ledger is replay protection for `process_relay`, and a relay can
    /// only be replayed while its pending entry exists. A pending entry is
    /// gone once the relay completed (removed on success) or once it was
    /// swept as expired, so a record older than the longest expiry window
    /// plus the finality depth protects nothing and only makes
    /// [`Self::root`] hash one more leaf per block for the life of the
    /// chain. Called from the same deterministic sweep on every node, so
    /// the root stays consensus-equal.
    fn drop_records_through(&mut self, cutoff: u64) {
        self.relayed.retain(|_, rec| rec.relay_height > cutoff);
    }

    /// Merkle root of all relay records (for on-chain commitment).
    pub fn root(&self) -> Hash32 {
        let leaves: Vec<Hash32> = self
            .relayed
            .iter()
            .map(|(mid, rec)| {
                hash_fields_bytes(&[
                    b"BDLM_RELAY_RECORD_V1",
                    mid,
                    rec.relayer.as_bytes(),
                    &rec.relay_height.to_le_bytes(),
                    &rec.proof_hash,
                ])
            })
            .collect();
        crate::settlement::commitment_tree::merkle_root(&leaves)
    }
}

/// How long an expired pending relay and a completed relay record are kept
/// past the point they stopped mattering. Ten finality depths, the same
/// window the bridge uses for its settled rows.
const RELAY_RETENTION_BLOCKS: u64 = 10 * crate::cross_domain::nonce::FINALITY_PRUNE_DEPTH;

/// Configuration for the Universal Relayer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayerConfig {
    /// Maximum number of blocks a relayer has to relay before expiry.
    pub relay_window_blocks: u64,
    /// Minimum stake required to act as a relayer (in base units).
    pub min_relayer_stake: u64,
    /// Slash ratio for failed/invalid relays (0-100).
    pub slash_ratio_invalid: u64,
    /// Slash ratio for expired (missed deadline) relays (0-100).
    pub slash_ratio_expired: u64,
}

impl Default for RelayerConfig {
    fn default() -> Self {
        Self {
            relay_window_blocks: 100,
            min_relayer_stake: 10_000_000,
            slash_ratio_invalid: 50,
            slash_ratio_expired: 25,
        }
    }
}

/// The Universal Relayer orchestrator.
///
/// Ties the bridge state machine to the relay ledger. Processes lock/burn
/// Events from the source domain and validates relay submissions on the
/// Target domain.
///
/// Permissionless: any staked RELAYER role holder can submit relays.
/// Slashing: invalid proofs or missed deadlines trigger economic penalties.
#[derive(Clone, Serialize, Deserialize)]
pub struct UniversalRelayer {
    pub config: RelayerConfig,
    pub ledger: RelayLedger,
    /// Pending relay requests: message_id → (source_event, target_domain).
    /// Populated when a bridge lock/burn creates a cross-domain message.
    #[serde(with = "crate::core::map_keys")]
    pending: BTreeMap<MessageId, PendingRelay>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PendingRelay {
    pub message_id: MessageId,
    pub source_domain: DomainId,
    pub target_domain: DomainId,
    pub source_event: DomainEvent,
    pub created_height: u64,
    pub expiry_height: u64,
}

impl UniversalRelayer {
    pub fn new(config: RelayerConfig) -> Self {
        Self {
            config,
            ledger: RelayLedger::new(),
            pending: BTreeMap::new(),
        }
    }

    /// Register a new relay request from a bridge lock event.
    /// Called by the bridge state machine when a lock creates a cross-domain message.
    pub fn enqueue_relay(
        &mut self,
        source_event: DomainEvent,
        message: &CrossDomainMessage,
        created_height: u64,
    ) {
        let relay = PendingRelay {
            message_id: message.message_id,
            source_domain: message.source_domain,
            target_domain: message.target_domain,
            source_event,
            created_height,
            expiry_height: message.expiry_height,
        };
        self.pending.insert(message.message_id, relay);
    }

    /// Process a relay submission from a relayer.
    ///
    /// Checks, in this order:
    /// 1. the message has not been relayed already (replay protection);
    /// 2. a pending relay exists for it;
    /// 3. the relay has not expired;
    /// 4. `source_domain`, the domain whose committed event root the caller
    ///    looked up, is the domain the pending relay was enqueued from;
    /// 5. the Merkle proof verifies against `event_tree_root` and its leaf
    ///    is the pending source event's hash;
    /// 6. the message inside the event still hashes to its own id.
    ///
    /// The caller's identity is not checked here; see the module docs. On
    /// success the relay is recorded and the verified cross-domain message is
    /// returned for the target domain's bridge to process (mint/unlock).
    pub fn process_relay(
        &mut self,
        message_id: MessageId,
        relayer: Address,
        proof: &MerkleProof,
        source_domain: DomainId,
        event_tree_root: Hash32,
        current_height: u64,
    ) -> Result<CrossDomainMessage, RelayerError> {
        // 1. Replay check
        if self.ledger.is_relayed(&message_id) {
            return Err(RelayerError::AlreadyRelayed(message_id));
        }

        let pending = self
            .pending
            .get(&message_id)
            .ok_or_else(|| {
                RelayerError::Other(format!(
                    "no pending relay for message {}",
                    hex::encode(message_id)
                ))
            })?
            .clone();

        // 2. Expiry check
        if pending.expiry_height > 0 && current_height > pending.expiry_height {
            return Err(RelayerError::Expired {
                message_id,
                expiry: pending.expiry_height,
                current_height,
            });
        }

        // 3. Source domain. The event root the caller hands in was looked up
        //    for `source_domain`; a root from another domain's commitment is
        //    a real root over the wrong tree, and the leaf check below would
        //    only catch it if the trees happened to differ at that leaf.
        if pending.source_domain != source_domain {
            return Err(RelayerError::SourceDomainMismatch {
                expected: pending.source_domain,
                got: source_domain,
            });
        }

        // 4. Proof verification
        if !proof.verify(event_tree_root) {
            return Err(RelayerError::InvalidProof(
                "Merkle proof does not verify against event tree root".into(),
            ));
        }

        // Verify the proof leaf matches the source event hash
        let expected_leaf = pending.source_event.leaf_hash();
        if proof.leaf != expected_leaf {
            return Err(RelayerError::InvalidProof(
                "proof leaf does not match source event hash".into(),
            ));
        }

        // 5. Record the relay
        // Use checked serialization - if proof cannot
        // Serialize, reject the relay rather than recording a bogus proof_hash.
        let proof_bytes = bincode::serialize(proof)
            .map_err(|e| RelayerError::Other(format!("proof serialization failed: {e}")))?;
        let proof_hash = hash_fields_bytes(&[b"BDLM_RELAY_PROOF_HASH_V1", &proof_bytes]);
        self.ledger
            .record(message_id, relayer, current_height, proof_hash)?;

        // Extract the cross-domain message from the source event
        let message = pending.source_event.message.clone().ok_or_else(|| {
            RelayerError::Other("source event has no cross-domain message".into())
        })?;

        // 6. Final message integrity check
        if !message.verify_id() {
            return Err(RelayerError::InvalidProof(
                "Relayed message ID does not match computed ID (tamper check)".into(),
            ));
        }

        // Remove from pending
        self.pending.remove(&message_id);

        Ok(message)
    }

    /// Get a pending relay by message ID.
    pub fn pending_relay(&self, message_id: &MessageId) -> Option<&PendingRelay> {
        self.pending.get(message_id)
    }

    /// Check if a message has been relayed.
    pub fn is_relayed(&self, message_id: &MessageId) -> bool {
        self.ledger.is_relayed(message_id)
    }

    /// Get the number of pending relays.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Get expired relays that should be slashed.
    pub fn expired_relays(&self, current_height: u64) -> Vec<&PendingRelay> {
        self.pending
            .values()
            .filter(|r| r.expiry_height > 0 && current_height > r.expiry_height)
            .collect()
    }

    /// Height-keyed retention for both maps, run once per applied block.
    ///
    /// Before this, `pending` lost an entry only on a successful relay, so
    /// an expired relay (which `process_relay` refuses for good) stayed
    /// forever; `relayed` had no removal path at all, and [`Self::ledger_root`]
    /// hashed every record ever written on every call. The bridge already
    /// sweeps its own rows on a height key; this is the same discipline.
    ///
    /// Two windows, both measured in blocks past the point at which the
    /// entry stopped mattering:
    ///
    /// * a pending relay whose expiry is more than
    ///   `RELAY_RETENTION_BLOCKS` behind `current_height` is dropped. It
    ///   was refused as expired the whole time, and the window leaves the
    ///   slashing path [`Self::expired_relays`] time to observe it;
    /// * a ledger record older than `RELAY_RETENTION_BLOCKS` is dropped.
    ///   Replay of that relay needs its pending entry, which is long gone.
    ///
    /// Relays without an expiry (`expiry_height == 0`) are kept: nothing
    /// says they stopped mattering.
    ///
    /// Deterministic in `current_height` and the maps' contents, so every
    /// node drops the same entries at the same block and the ledger root
    /// stays consensus-equal. Returns how many entries were dropped.
    pub fn sweep_retired(&mut self, current_height: u64) -> usize {
        let cutoff = current_height.saturating_sub(RELAY_RETENTION_BLOCKS);
        let before = self.pending.len() + self.ledger.relayed.len();
        self.pending
            .retain(|_, r| r.expiry_height == 0 || r.expiry_height > cutoff);
        self.ledger.drop_records_through(cutoff);
        before - (self.pending.len() + self.ledger.relayed.len())
    }

    /// Merkle root of the relay ledger (for on-chain commitment).
    pub fn ledger_root(&self) -> Hash32 {
        self.ledger.root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::event_tree::DomainEventTree;
    use crate::cross_domain::message::{CrossDomainMessageParams, MessageKind};

    fn make_event_and_message(
        source_domain: DomainId,
        target_domain: DomainId,
        height: u64,
    ) -> (DomainEvent, CrossDomainMessage) {
        let payload_hash = hash(b"test-payload");
        let message = CrossDomainMessage::new(CrossDomainMessageParams {
            source_domain,
            target_domain,
            source_height: height,
            event_index: 0,
            nonce: 0,
            sender: Address::from([1u8; 32]),
            recipient: Address::from([2u8; 32]),
            payload_hash,
            kind: MessageKind::BridgeLock,
            expiry_height: height + 100,
        });
        let event = DomainEvent {
            domain_id: source_domain,
            domain_height: height,
            event_index: 0,
            kind: crate::cross_domain::event_tree::DomainEventKind::BridgeLocked,
            emitter: Address::from([1u8; 32]),
            message: Some(message.clone()),
            payload_hash,
        };
        (event, message)
    }

    #[test]
    fn relay_basic_flow() {
        let mut relayer = UniversalRelayer::new(RelayerConfig::default());
        let (event, message) = make_event_and_message(1, 2, 10);

        // Enqueue
        relayer.enqueue_relay(event.clone(), &message, 10);
        assert_eq!(relayer.pending_count(), 1);

        // Build event tree and proof
        let mut tree = DomainEventTree::new();
        tree.push(event.clone());
        let root = tree.root();
        let proof = tree.proof(0).unwrap();

        // Process relay
        let relayer_addr = Address::from([0xAA; 32]);
        let result = relayer.process_relay(
            message.message_id,
            relayer_addr,
            &proof,
            message.source_domain,
            root,
            15,
        );
        assert!(result.is_ok());
        let relayed_msg = result.unwrap();
        assert_eq!(relayed_msg.message_id, message.message_id);
        assert!(relayer.is_relayed(&message.message_id));
        assert_eq!(relayer.pending_count(), 0);
    }

    #[test]
    fn relay_rejects_replay() {
        let mut relayer = UniversalRelayer::new(RelayerConfig::default());
        let (event, message) = make_event_and_message(1, 2, 10);

        relayer.enqueue_relay(event.clone(), &message, 10);

        let mut tree = DomainEventTree::new();
        tree.push(event.clone());
        let root = tree.root();
        let proof = tree.proof(0).unwrap();
        let relayer_addr = Address::from([0xAA; 32]);

        // First relay succeeds
        relayer
            .process_relay(
                message.message_id,
                relayer_addr,
                &proof,
                message.source_domain,
                root,
                15,
            )
            .unwrap();

        // Replay rejected
        let err = relayer
            .process_relay(
                message.message_id,
                relayer_addr,
                &proof,
                message.source_domain,
                root,
                16,
            )
            .unwrap_err();
        assert!(matches!(err, RelayerError::AlreadyRelayed(_)));
    }

    #[test]
    fn relay_rejects_expired() {
        let mut relayer = UniversalRelayer::new(RelayerConfig::default());
        let (event, message) = make_event_and_message(1, 2, 10);

        relayer.enqueue_relay(event.clone(), &message, 10);

        let mut tree = DomainEventTree::new();
        tree.push(event.clone());
        let root = tree.root();
        let proof = tree.proof(0).unwrap();
        let relayer_addr = Address::from([0xAA; 32]);

        // Relay after expiry (expiry = 10 + 100 = 110)
        let err = relayer
            .process_relay(
                message.message_id,
                relayer_addr,
                &proof,
                message.source_domain,
                root,
                111,
            )
            .unwrap_err();
        assert!(matches!(err, RelayerError::Expired { .. }));
    }

    #[test]
    fn relay_rejects_invalid_proof() {
        let mut relayer = UniversalRelayer::new(RelayerConfig::default());
        let (event, message) = make_event_and_message(1, 2, 10);

        relayer.enqueue_relay(event.clone(), &message, 10);

        let relayer_addr = Address::from([0xAA; 32]);
        let bad_proof = MerkleProof {
            leaf: hash(b"bad leaf"),
            index: 0,
            siblings: Vec::new(),
        };
        let root = hash(b"bad root");

        let err = relayer
            .process_relay(
                message.message_id,
                relayer_addr,
                &bad_proof,
                message.source_domain,
                root,
                15,
            )
            .unwrap_err();
        assert!(matches!(err, RelayerError::InvalidProof(_)));
    }

    #[test]
    fn expired_relays_detection() {
        let mut relayer = UniversalRelayer::new(RelayerConfig::default());
        let (event, message) = make_event_and_message(1, 2, 10);

        relayer.enqueue_relay(event, &message, 10);

        // Not expired at height 50
        assert_eq!(relayer.expired_relays(50).len(), 0);

        // Expired at height 111 (expiry = 110)
        assert_eq!(relayer.expired_relays(111).len(), 1);
    }

    #[test]
    fn relay_ledger_root_is_deterministic() {
        let mut ledger = RelayLedger::new();
        let msg_id = hash(b"msg1");
        let relayer = Address::from([0xAA; 32]);
        ledger.record(msg_id, relayer, 100, hash(b"proof")).unwrap();

        let root1 = ledger.root();
        let root2 = ledger.root();
        assert_eq!(root1, root2);
    }

    fn hash(label: &[u8]) -> Hash32 {
        crate::core::hash::hash_fields_bytes(&[label])
    }

    #[test]
    fn relay_config_defaults_are_reasonable() {
        let config = RelayerConfig::default();
        assert_eq!(config.relay_window_blocks, 100);
        assert_eq!(config.min_relayer_stake, 10_000_000);
        assert_eq!(config.slash_ratio_invalid, 50);
        assert_eq!(config.slash_ratio_expired, 25);
    }

    #[test]
    fn relay_ledger_empty_root_is_deterministic() {
        let ledger = RelayLedger::new();
        let root1 = ledger.root();
        let root2 = ledger.root();
        assert_eq!(root1, root2);
        // Empty root should be a specific value (merkle_root of empty vec)
        assert_ne!(root1, [0u8; 32]);
    }

    #[test]
    fn relay_ledger_get_record_returns_none_for_unknown() {
        let ledger = RelayLedger::new();
        assert!(ledger.get_record(&hash(b"unknown")).is_none());
    }

    #[test]
    fn relay_ledger_root_changes_with_different_relayers() {
        let mut ledger = RelayLedger::new();
        let msg_id = hash(b"msg1");
        let relayer1 = Address::from([0xAA; 32]);
        let relayer2 = Address::from([0xBB; 32]);

        ledger
            .record(msg_id, relayer1, 100, hash(b"proof"))
            .unwrap();
        let root1 = ledger.root();

        let mut ledger2 = RelayLedger::new();
        ledger2
            .record(msg_id, relayer2, 100, hash(b"proof"))
            .unwrap();
        let root2 = ledger2.root();

        assert_ne!(root1, root2);
    }

    #[test]
    fn universal_relayer_new_has_empty_state() {
        let relayer = UniversalRelayer::new(RelayerConfig::default());
        assert_eq!(relayer.pending_count(), 0);
        assert!(!relayer.is_relayed(&hash(b"anything")));
        assert_eq!(relayer.expired_relays(1000).len(), 0);
    }

    #[test]
    fn process_relay_fails_for_unknown_message() {
        let mut relayer = UniversalRelayer::new(RelayerConfig::default());
        let proof = MerkleProof {
            leaf: hash(b"test"),
            index: 0,
            siblings: vec![],
        };
        let err = relayer
            .process_relay(
                hash(b"unknown"),
                Address::from([0xAA; 32]),
                &proof,
                1,
                hash(b"root"),
                100,
            )
            .unwrap_err();
        assert!(matches!(err, RelayerError::Other(_)));
    }

    /// The event root the caller looked up has to be the pending relay's
    /// source domain. A valid root over another domain's tree is refused by
    /// name, before the proof is walked.
    #[test]
    fn relay_rejects_a_root_from_another_source_domain() {
        let mut relayer = UniversalRelayer::new(RelayerConfig::default());
        let (event, message) = make_event_and_message(1, 2, 10);
        let mut tree = DomainEventTree::default();
        tree.push(event.clone());
        let root = tree.root();
        let proof = tree.proof(0).unwrap();
        relayer.enqueue_relay(event, &message, 10);

        let err = relayer
            .process_relay(
                message.message_id,
                Address::from([0xAA; 32]),
                &proof,
                3,
                root,
                15,
            )
            .unwrap_err();
        assert_eq!(
            err,
            RelayerError::SourceDomainMismatch {
                expected: 1,
                got: 3
            }
        );
        assert!(!relayer.is_relayed(&message.message_id));
    }

    /// Retention: an expired pending relay and an old ledger record are
    /// dropped once they are `RELAY_RETENTION_BLOCKS` past mattering, and
    /// not one block sooner. A relay without an expiry stays.
    #[test]
    fn sweep_retired_drops_expired_pending_and_old_records_on_a_height_key() {
        let mut relayer = UniversalRelayer::new(RelayerConfig::default());
        let relayer_addr = Address::from([0xAA; 32]);

        // One relay that completes at height 15.
        let (event_a, message_a) = make_event_and_message(1, 2, 10);
        let mut tree = DomainEventTree::default();
        tree.push(event_a.clone());
        let root = tree.root();
        let proof = tree.proof(0).unwrap();
        relayer.enqueue_relay(event_a, &message_a, 10);
        relayer
            .process_relay(message_a.message_id, relayer_addr, &proof, 1, root, 15)
            .unwrap();
        assert!(relayer.is_relayed(&message_a.message_id));

        // One relay that is never relayed and expires at 120 (a different
        // height, so a different message id from the first).
        let (event_b, message_b) = make_event_and_message(1, 2, 20);
        relayer.enqueue_relay(event_b, &message_b, 20);
        // One relay with no expiry at all.
        let (event_c, mut message_c) = make_event_and_message(1, 2, 30);
        message_c.expiry_height = 0;
        relayer.enqueue_relay(event_c, &message_c, 30);
        assert_ne!(message_a.message_id, message_b.message_id);
        assert_eq!(relayer.pending_count(), 2);
        let root_before = relayer.ledger_root();

        // One block short of the record's cutoff: nothing moves.
        assert_eq!(relayer.sweep_retired(14 + RELAY_RETENTION_BLOCKS), 0);
        assert_eq!(relayer.pending_count(), 2);
        assert_eq!(relayer.ledger_root(), root_before);
        assert!(relayer.is_relayed(&message_a.message_id));

        // The record retires first (relayed at 15, so exactly the retention
        // window later), the expired relay a full window after its expiry.
        assert_eq!(relayer.sweep_retired(15 + RELAY_RETENTION_BLOCKS), 1);
        assert!(!relayer.is_relayed(&message_a.message_id));
        assert_ne!(relayer.ledger_root(), root_before);
        assert_eq!(relayer.pending_count(), 2);

        assert_eq!(relayer.sweep_retired(119 + RELAY_RETENTION_BLOCKS), 0);
        assert_eq!(relayer.sweep_retired(120 + RELAY_RETENTION_BLOCKS), 1);
        assert_eq!(relayer.pending_count(), 1, "the relay with no expiry stays");
        assert!(relayer.pending_relay(&message_c.message_id).is_some());
        assert!(relayer.pending_relay(&message_b.message_id).is_none());
    }
}
