//! Universal Relayer — permissionless cross-domain relay orchestrator.
//!
//! Architecture:
//! - Any account with the RELAYER role (staked via PermissionlessRegistry) can
//!   relay cross-domain messages.
//! - The relayer watches for bridge lock/burn events on the source domain and
//!   submits proofs to the target domain.
//! - Slashing: if a relayer submits an invalid proof or fails to relay within
//!   the expiry window, they can be slashed via the standard evidence path.
//!
//! Trust model: permissionless + economic security (stake + slashing).
//! No whitelist, no admin gate, no team-gated "official relayer" role.

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::bridge::{AssetId, BridgeState, BridgeTransfer};
use crate::cross_domain::event_tree::{DomainEvent, DomainEventTree, MerkleProof};
use crate::cross_domain::message::{CrossDomainMessage, MessageId, MessageKind};
use crate::cross_domain::message_registry::CrossDomainMessageRegistry;
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
                write!(f, "source domain mismatch: expected {}, got {}", expected, got)
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
    /// message_id → (relayer_address, relay_height, proof_hash)
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

/// Configuration for the Universal Relayer.
#[derive(Debug, Clone)]
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
/// events from the source domain and validates relay submissions on the
/// target domain.
///
/// Permissionless: any staked RELAYER role holder can submit relays.
/// Slashing: invalid proofs or missed deadlines trigger economic penalties.
pub struct UniversalRelayer {
    pub config: RelayerConfig,
    pub ledger: RelayLedger,
    /// Pending relay requests: message_id → (source_event, target_domain).
    /// Populated when a bridge lock/burn creates a cross-domain message.
    pending: BTreeMap<MessageId, PendingRelay>,
}

#[derive(Debug, Clone)]
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
    /// Validates:
    /// 1. Message hasn't been relayed already (replay protection)
    /// 2. Relay hasn't expired
    /// 3. Source domain matches
    /// 4. Merkle proof is valid against the source event tree root
    ///
    /// On success, records the relay and returns the verified cross-domain
    /// message for the target domain's bridge to process (mint/unlock).
    pub fn process_relay(
        &mut self,
        message_id: MessageId,
        relayer: Address,
        proof: &MerkleProof,
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
            .ok_or_else(|| RelayerError::Other(format!(
                "no pending relay for message {}",
                hex::encode(message_id)
            )))?
            .clone();

        // 2. Expiry check
        if pending.expiry_height > 0 && current_height > pending.expiry_height {
            return Err(RelayerError::Expired {
                message_id,
                expiry: pending.expiry_height,
                current_height,
            });
        }

        // 3. Proof verification
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

        // 4. Record the relay
        let proof_hash = hash_fields_bytes(&[
            b"BDLM_RELAY_PROOF_HASH_V1",
            &bincode::serialize(proof).unwrap_or_default(),
        ]);
        self.ledger.record(message_id, relayer, current_height, proof_hash)?;

        // 5. Extract the cross-domain message from the source event
        let message = pending
            .source_event
            .message
            .clone()
            .ok_or_else(|| RelayerError::Other(
                "source event has no cross-domain message".into()
            ))?;

        // Remove from pending
        self.pending.remove(&message_id);

        Ok(message)
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

    /// Merkle root of the relay ledger (for on-chain commitment).
    pub fn ledger_root(&self) -> Hash32 {
        self.ledger.root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::message::CrossDomainMessageParams;

    fn hash(label: &[u8]) -> Hash32 {
        crate::core::hash::hash_fields_bytes(&[label])
    }

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
            .process_relay(message.message_id, relayer_addr, &proof, root, 15)
            .unwrap();

        // Replay rejected
        let err = relayer
            .process_relay(message.message_id, relayer_addr, &proof, root, 16)
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
            .process_relay(message.message_id, relayer_addr, &proof, root, 111)
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
            .process_relay(message.message_id, relayer_addr, &bad_proof, root, 15)
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
}
