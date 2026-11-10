use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::message::{CrossDomainMessage, MessageId, MessageKind};
use crate::domain::types::Hash32;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Longest `Custom` kind tag the registry accepts. The registry keeps every
/// message and hashes it into the state root, so an unbounded tag lets one
/// message cost memory and hashing time without limit.
const MAX_CUSTOM_KIND_BYTES: usize = 256;

/// Longest a message row may be retained. `expiry_height` and `source_height`
/// are chosen by whoever built the message, so a row that names `u64::MAX`
/// would otherwise never be pruned and the registry would grow without bound.
/// Ten years of six-second blocks.
const MAX_MESSAGE_LIFETIME_BLOCKS: u64 = 52_560_000;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CrossDomainMessageRegistry {
    #[serde(with = "crate::core::map_keys")]
    messages: BTreeMap<MessageId, CrossDomainMessage>,
}

impl CrossDomainMessageRegistry {
    pub fn new() -> Self {
        Self {
            messages: BTreeMap::new(),
        }
    }

    /// Drops messages whose useful life is over (BLG-0114/P05-F07): the
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

    pub fn insert(&mut self, message: CrossDomainMessage) -> Result<(), String> {
        if !message.verify_id() {
            return Err("Invalid message id".into());
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
        self.messages.insert(message.message_id, message);
        Ok(())
    }

    pub fn get(&self, message_id: &MessageId) -> Option<&CrossDomainMessage> {
        self.messages.get(message_id)
    }

    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    pub fn messages(&self) -> impl Iterator<Item = &CrossDomainMessage> {
        self.messages.values()
    }

    pub fn root(&self) -> Hash32 {
        let leaves: Vec<Hash32> = self
            .messages
            .values()
            .map(|msg| {
                let kind = msg.kind.as_bytes();
                hash_fields_bytes(&[
                    b"BDLM_MESSAGE_LEAF_V1",
                    &msg.message_id,
                    &msg.source_domain.to_le_bytes(),
                    &msg.target_domain.to_le_bytes(),
                    &msg.nonce.to_le_bytes(),
                    &kind,
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

    /// P05-F07: a Custom kind tag has a length bound.
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

    /// BLG-0114 (P05-F07): expired messages are pruned; live ones stay.
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
}
