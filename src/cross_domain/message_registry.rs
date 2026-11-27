use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::message::{CrossDomainMessage, MessageId, MessageKind};
use crate::domain::types::Hash32;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Longest `Custom` kind tag the registry accepts. The registry keeps every
/// message and hashes it into the state root, so an unbounded tag lets one
/// message cost memory and hashing time without limit.
const MAX_CUSTOM_KIND_BYTES: usize = 256;

/// Maximum live messages held in the registry (every row is Merkle-hashed into `root()`).
///
/// Convenience: pub so relayer and bridge callers enforce the same global ceiling.
pub const MAX_REGISTERED_MESSAGES: usize = 65_536;

/// Maximum concurrent messages a single sender may hold in the registry so one
/// account cannot saturate [`MAX_REGISTERED_MESSAGES`].
///
/// Convenience: pub so relayer and bridge callers enforce the same per-sender bound.
pub const MAX_MESSAGES_PER_SENDER: usize = 256;

/// Maximum byte length accepted for `sender_public_key` or `sender_signature`
/// (covers FIPS 204 ML-DSA-87 and composite signatures while refusing DoS blobs).
///
/// Convenience: pub so cross-domain message builders stay within the auth ceiling.
pub const MAX_MESSAGE_AUTH_BYTES: usize = 8_192;

/// Longest a message row may be retained. `expiry_height` and `source_height`
/// are chosen by whoever built the message, so a row that names `u64::MAX`
/// would otherwise never be pruned and the registry would grow without bound.
/// Ten years of six-second blocks.
pub(crate) const MAX_MESSAGE_LIFETIME_BLOCKS: u64 = 52_560_000;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CrossDomainMessageRegistry {
    #[serde(with = "crate::core::map_keys")]
    messages: BTreeMap<MessageId, CrossDomainMessage>,
}

impl CrossDomainMessageRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            messages: BTreeMap::new(),
        }
    }

    /// Drops messages whose useful life is over: the
    /// registry hashes EVERY message into the state root, so a registry
    /// that never forgets is unbounded per-block cost and unbounded state.
    /// A message past `expiry_height + retention` can never again be
    /// consumed (mint/unlock refuse expired messages), so keeping it buys
    /// nothing - re-registering a dead id is equally dead. Zero-expiry
    /// messages age from `source_height` instead. Returns the drop count.
    pub fn prune_expired(&mut self, current_height: u64, retention_blocks: u64) -> usize {
        let before = self.messages.len();
        self.messages.retain(|_, m| {
            let horizon = if m.expiry_height != 0 {
                m.expiry_height
            } else {
                m.source_height
            };
            // The horizon is chosen by whoever built the message, so a
            // far-future or `u64::MAX` value would make the row immortal.
            // A horizon beyond the maximum lifetime counts as already
            // expired, so no declared height can outlive the bound.
            horizon <= current_height.saturating_add(MAX_MESSAGE_LIFETIME_BLOCKS)
                && horizon.saturating_add(retention_blocks) > current_height
        });
        before - self.messages.len()
    }

    /// Performs the requested operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn insert(&mut self, message: CrossDomainMessage) -> Result<(), String> {
        if !message.verify_id() {
            return Err("Invalid message id".into());
        }
        if message.source_domain == message.target_domain {
            return Err(format!(
                "Cross-domain message source and target domains must differ (both={})",
                message.source_domain
            ));
        }
        if message.sender == crate::core::address::Address::zero()
            || message.recipient == crate::core::address::Address::zero()
        {
            return Err("Cross-domain message sender and recipient cannot be zero".into());
        }
        if message.payload_hash == [0u8; 32] {
            return Err("Cross-domain message payload_hash cannot be all-zero".into());
        }
        if message.sender_public_key.len() > MAX_MESSAGE_AUTH_BYTES
            || message.sender_signature.len() > MAX_MESSAGE_AUTH_BYTES
        {
            return Err(format!(
                "Cross-domain message auth fields exceed {MAX_MESSAGE_AUTH_BYTES} bytes"
            ));
        }
        if let MessageKind::Custom(tag) = &message.kind {
            if tag.len() > MAX_CUSTOM_KIND_BYTES {
                return Err(format!(
                    "Custom message kind is {} bytes, the limit is {MAX_CUSTOM_KIND_BYTES}",
                    tag.len()
                ));
            }
        }
        if self.messages.contains_key(&message.message_id) {
            return Err(format!(
                "Message {} already registered",
                hex::encode(message.message_id)
            ));
        }
        if self.messages.len() >= MAX_REGISTERED_MESSAGES {
            return Err(format!(
                "Cross-domain message registry is full (max {MAX_REGISTERED_MESSAGES})"
            ));
        }
        let sender_count = self
            .messages
            .values()
            .filter(|existing| existing.sender == message.sender)
            .count();
        if sender_count >= MAX_MESSAGES_PER_SENDER {
            return Err(format!(
                "Sender reached maximum concurrent cross-domain messages ({MAX_MESSAGES_PER_SENDER})"
            ));
        }
        self.messages.insert(message.message_id, message);
        Ok(())
    }

    #[must_use]
    pub fn get(&self, message_id: &MessageId) -> Option<&CrossDomainMessage> {
        self.messages.get(message_id)
    }

    pub(crate) fn remove(&mut self, message_id: &MessageId) -> Option<CrossDomainMessage> {
        self.messages.remove(message_id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    pub fn messages(&self) -> impl Iterator<Item = &CrossDomainMessage> {
        self.messages.values()
    }

    #[must_use]
    pub fn root(&self) -> Hash32 {
        let leaves: Vec<Hash32> = self
            .messages
            .values()
            .map(|msg| {
                let kind = msg.kind.as_bytes();
                let mut corr_tag = Vec::with_capacity(33);
                match msg.correlation_id {
                    Some(id) => {
                        corr_tag.push(1);
                        corr_tag.extend_from_slice(&id);
                    }
                    None => corr_tag.push(0),
                }
                let qclass_tag: u8 = match msg.source_quantum_class {
                    None => 0,
                    Some(crate::crypto::facts::QuantumClass::Classical) => 1,
                    Some(crate::crypto::facts::QuantumClass::Lattice) => 2,
                    Some(crate::crypto::facts::QuantumClass::Hash) => 3,
                };
                hash_fields_bytes(&[
                    b"BDLM_MESSAGE_LEAF_V1",
                    &msg.message_id,
                    &corr_tag,
                    &msg.source_domain.to_le_bytes(),
                    &msg.target_domain.to_le_bytes(),
                    &msg.source_height.to_le_bytes(),
                    &msg.event_index.to_le_bytes(),
                    &msg.nonce.to_le_bytes(),
                    &msg.sender.0,
                    &msg.recipient.0,
                    &msg.payload_hash,
                    &kind,
                    &msg.expiry_height.to_le_bytes(),
                    &msg.sender_public_key,
                    &msg.sender_signature,
                    &[qclass_tag],
                ])
            })
            .collect();
        crate::settlement::commitment_tree::merkle_root(&leaves)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    fn test_addr_from_byte(byte: u8) -> crate::core::address::Address {
        let mut b = [0u8; 32];
        b[0] = byte;
        crate::core::address::Address::from(b)
    }

    use crate::cross_domain::message::CrossDomainMessageParams;

    fn hash(label: &[u8]) -> Hash32 {
        crate::core::hash::hash_fields_bytes(&[label])
    }

    fn make_message(nonce: u64) -> CrossDomainMessage {
        CrossDomainMessage::new(CrossDomainMessageParams {
            source_domain: 1,
            target_domain: 2,
            source_height: 10,
            event_index: 0,
            nonce,
            sender: test_addr_from_byte(1u8),
            recipient: test_addr_from_byte(2u8),
            payload_hash: hash(b"payload"),
            kind: MessageKind::BridgeLock,
            expiry_height: 100,
        })
    }

    #[test]
    fn insert_and_retrieve_message() {
        let mut registry = CrossDomainMessageRegistry::new();
        let msg = make_message(0);
        let id = msg.message_id;
        registry.insert(msg).unwrap();
        assert!(registry.get(&id).is_some());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn duplicate_message_rejected() {
        let mut registry = CrossDomainMessageRegistry::new();
        let msg = make_message(0);
        registry.insert(msg.clone()).unwrap();
        assert!(registry.insert(msg).is_err());
    }

    #[test]
    fn tampered_message_rejected() {
        let mut registry = CrossDomainMessageRegistry::new();
        let mut msg = make_message(0);
        msg.nonce = 999;
        assert!(registry.insert(msg).is_err());
    }

    #[test]
    fn root_changes_with_different_messages() {
        let mut r1 = CrossDomainMessageRegistry::new();
        r1.insert(make_message(0)).unwrap();

        let mut r2 = CrossDomainMessageRegistry::new();
        r2.insert(make_message(1)).unwrap();

        assert_ne!(r1.root(), r2.root());
    }

    /// A Custom kind tag has a length bound.
    #[test]
    fn an_oversized_custom_kind_is_rejected() {
        let mut registry = CrossDomainMessageRegistry::new();
        let make = |len: usize| {
            CrossDomainMessage::new(CrossDomainMessageParams {
                source_domain: 1,
                target_domain: 2,
                source_height: 10,
                event_index: 0,
                nonce: 0,
                sender: test_addr_from_byte(1u8),
                recipient: test_addr_from_byte(2u8),
                payload_hash: hash(b"payload"),
                kind: MessageKind::Custom(vec![7u8; len]),
                expiry_height: 100,
            })
        };
        assert!(registry.insert(make(MAX_CUSTOM_KIND_BYTES + 1)).is_err());
        assert!(registry.is_empty());
        registry.insert(make(MAX_CUSTOM_KIND_BYTES)).unwrap();
    }

    /// Expired messages are pruned; live ones stay.
    #[test]
    fn expired_messages_are_pruned_and_live_ones_stay() {
        let mut registry = CrossDomainMessageRegistry::new();
        let mut old = make_message(1);
        old.expiry_height = 10;
        old.message_id = old.calculate_message_id();
        let mut fresh = make_message(2);
        fresh.expiry_height = 100_000;
        fresh.message_id = fresh.calculate_message_id();
        registry.insert(old).unwrap();
        registry.insert(fresh).unwrap();
        let dropped = registry.prune_expired(100_000, 1_000);
        assert_eq!(dropped, 1);
        assert_eq!(registry.len(), 1);
    }

    /// A horizon the submitter chooses must not buy immortality.
    ///
    /// `expiry_height` and `source_height` come from whoever built the
    /// message, so without a lifetime bound a row declaring `u64::MAX` is
    /// retained at every reachable height and the sweep bounds nothing. The
    /// declared-but-unreachable horizon is treated as already expired.
    #[test]
    fn a_message_declaring_an_immortal_horizon_is_pruned() {
        let mut registry = CrossDomainMessageRegistry::new();
        let mut immortal = make_message(3);
        immortal.expiry_height = u64::MAX;
        immortal.message_id = immortal.calculate_message_id();
        registry.insert(immortal).unwrap();
        assert_eq!(registry.len(), 1);

        // At the current height the row is neither expired nor beyond its
        // retention window, yet it is dropped: its declared horizon is past
        // the farthest height the registry will ever keep a row for.
        let dropped = registry.prune_expired(1_000, 1_000);
        assert_eq!(dropped, 1, "a u64::MAX horizon must not be immortal");
        assert!(registry.is_empty());
    }

    /// The bound is a horizon, not a blanket drop: a message whose declared
    /// expiry sits inside the maximum lifetime is still kept while it lives.
    #[test]
    fn a_horizon_inside_the_lifetime_bound_is_still_retained() {
        let mut registry = CrossDomainMessageRegistry::new();
        let mut far = make_message(4);
        far.expiry_height = MAX_MESSAGE_LIFETIME_BLOCKS - 1;
        far.message_id = far.calculate_message_id();
        registry.insert(far).unwrap();
        assert_eq!(registry.prune_expired(1_000, 1_000), 0);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn registry_refuses_self_domain_and_root_commits_envelope() {
        let mut self_msg = CrossDomainMessage::new(CrossDomainMessageParams {
            source_domain: 7,
            target_domain: 7,
            source_height: 10,
            event_index: 0,
            nonce: 1,
            sender: test_addr_from_byte(1),
            recipient: test_addr_from_byte(2),
            payload_hash: hash(b"self-domain"),
            kind: MessageKind::Custom(b"self".to_vec()),
            expiry_height: 100,
        });
        self_msg.message_id = self_msg.calculate_message_id();
        let mut reg = CrossDomainMessageRegistry::new();
        let err = reg
            .insert(self_msg)
            .expect_err("self-domain message must be refused by registry insert");
        assert!(err.contains("differ"), "got: {err}");

        let mut msg_a = make_message(11);
        msg_a.sender_public_key = vec![0xAA; 32];
        msg_a.sender_signature = vec![0x11; 64];
        let mut msg_b = msg_a.clone();
        msg_b.sender_signature = vec![0x22; 64];

        let mut reg_a = CrossDomainMessageRegistry::new();
        let mut reg_b = CrossDomainMessageRegistry::new();
        reg_a.insert(msg_a).unwrap();
        reg_b.insert(msg_b).unwrap();
        assert_ne!(
            reg_a.root(),
            reg_b.root(),
            "message registry root must bind sender signature envelope"
        );
    }
}
