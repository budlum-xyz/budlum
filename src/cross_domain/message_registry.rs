use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::message::{CrossDomainMessage, MessageId, MessageKind};
use crate::domain::types::Hash32;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Longest `Custom` kind tag the registry accepts. The registry keeps every
/// message and hashes it into the state root, so an unbounded tag lets one
/// message cost memory and hashing time without limit.
const MAX_CUSTOM_KIND_BYTES: usize = 256;

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
}
