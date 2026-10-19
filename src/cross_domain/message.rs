use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::domain::types::{DomainId, Hash32};
use serde::{Deserialize, Serialize};

pub type MessageId = Hash32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MessageKind {
    BridgeLock,
    BridgeMint,
    BridgeBurn,
    BridgeUnlock,
    Custom(Vec<u8>),
}

impl MessageKind {
    /// The variant's name, for error text that reports what arrived.
    pub fn name(&self) -> &'static str {
        match self {
            MessageKind::BridgeLock => "BridgeLock",
            MessageKind::BridgeMint => "BridgeMint",
            MessageKind::BridgeBurn => "BridgeBurn",
            MessageKind::BridgeUnlock => "BridgeUnlock",
            MessageKind::Custom(_) => "Custom",
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            MessageKind::BridgeLock => b"bridge-lock".to_vec(),
            MessageKind::BridgeMint => b"bridge-mint".to_vec(),
            MessageKind::BridgeBurn => b"bridge-burn".to_vec(),
            MessageKind::BridgeUnlock => b"bridge-unlock".to_vec(),
            MessageKind::Custom(bytes) => {
                let mut out = b"custom:".to_vec();
                out.extend_from_slice(bytes);
                out
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrossDomainMessage {
    pub message_id: MessageId,
    #[serde(default)]
    pub correlation_id: Option<MessageId>,
    pub source_domain: DomainId,
    pub target_domain: DomainId,
    pub source_height: u64,
    pub event_index: u32,
    pub nonce: u64,
    pub sender: Address,
    pub recipient: Address,
    pub payload_hash: Hash32,
    pub kind: MessageKind,
    pub expiry_height: u64,
    /// BLG-0113 (P05-F06): the sender's authentication over
    /// [`CrossDomainMessage::message_id`]. Envelope, not payload - the id
    /// binds the fields above and nothing here, exactly like a
    /// transaction's signature over its signing hash. An empty envelope is
    /// refused at the relayed-message door: the self-declared `sender`
    /// field alone let anybody name an active relayer and register
    /// arbitrary messages (or pre-register a predictable lock id).
    #[serde(default)]
    pub sender_public_key: Vec<u8>,
    #[serde(default)]
    pub sender_signature: Vec<u8>,
}

impl CrossDomainMessage {
    pub fn new(params: CrossDomainMessageParams) -> Self {
        let mut message = CrossDomainMessage {
            message_id: [0u8; 32],
            correlation_id: None,
            source_domain: params.source_domain,
            target_domain: params.target_domain,
            source_height: params.source_height,
            event_index: params.event_index,
            nonce: params.nonce,
            sender: params.sender,
            recipient: params.recipient,
            payload_hash: params.payload_hash,
            kind: params.kind,
            expiry_height: params.expiry_height,
            sender_public_key: Vec::new(),
            sender_signature: Vec::new(),
        };
        message.message_id = message.calculate_message_id();
        message
    }

    pub fn new_correlated(params: CrossDomainMessageParams, correlation_id: MessageId) -> Self {
        let mut message = Self::new(params);
        message.correlation_id = Some(correlation_id);
        message.message_id = message.calculate_message_id();
        message
    }

    /// Signs [`CrossDomainMessage::message_id`] with the sender's Ed25519
    /// account key (BLG-0113/P05-F06). The V4 derivation makes the key
    /// bytes the address itself, so the envelope is self-identifying.
    pub fn sign_sender_ed25519(&mut self, keypair: &crate::crypto::primitives::KeyPair) {
        self.sender_public_key = keypair.public_key_bytes().to_vec();
        self.sender_signature = keypair.sign(&self.message_id).to_vec();
    }

    /// Verifies the sender envelope (BLG-0113/P05-F06): the signature must
    /// open over [`CrossDomainMessage::message_id`] under a key that IS the
    /// declared sender - Ed25519 (the key bytes are the address) or
    /// ML-DSA-87 (the wallet address derives from the key). An empty
    /// envelope is a refusal, not a pass: the self-declared `sender` field
    /// alone is what the finding's spoof ran on.
    ///
    /// # Errors
    ///
    /// A message naming what failed: missing envelope, a signer that is
    /// not the sender, or a signature that does not open.
    pub fn verify_sender_signature(&self) -> Result<(), String> {
        if self.sender_public_key.is_empty() || self.sender_signature.is_empty() {
            return Err("cross-domain message carries no sender signature".into());
        }
        // Ed25519: the 32-byte address IS the public key (V4 derivation).
        if self.sender_public_key.len() == 32 {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&self.sender_public_key);
            if Address::from(pk) != self.sender {
                return Err("message signer is not the declared sender".into());
            }
            return crate::crypto::primitives::verify_signature(
                &self.message_id,
                &self.sender_signature,
                &self.sender_public_key,
            )
            .map_err(|e| format!("message sender signature does not verify: {e}"));
        }
        // ML-DSA-87: the wallet address derives from the 2592-byte key.
        let addr = crate::crypto::primitives::wallet_address_from_ml_dsa_87_public_key(
            &self.sender_public_key,
        )
        .map_err(|e| format!("message signer key is invalid: {e}"))?;
        if addr != self.sender {
            return Err("message signer is not the declared sender".into());
        }
        crate::crypto::primitives::verify_ml_dsa_87_signature(
            &self.message_id,
            &self.sender_signature,
            &self.sender_public_key,
        )
        .map_err(|e| format!("message sender signature does not verify: {e}"))
    }

    pub fn calculate_message_id(&self) -> MessageId {
        let kind = self.kind.as_bytes();
        let correlation_id = self.correlation_id.unwrap_or([0u8; 32]);
        hash_fields_bytes(&[
            b"BDLM_CROSS_DOMAIN_MESSAGE_V2",
            &correlation_id,
            &self.source_domain.to_le_bytes(),
            &self.target_domain.to_le_bytes(),
            &self.source_height.to_le_bytes(),
            &self.event_index.to_le_bytes(),
            &self.nonce.to_le_bytes(),
            self.sender.as_bytes(),
            self.recipient.as_bytes(),
            &self.payload_hash,
            &kind,
            &self.expiry_height.to_le_bytes(),
        ])
    }

    pub fn verify_id(&self) -> bool {
        self.message_id == self.calculate_message_id()
    }
}

#[derive(Debug, Clone)]
pub struct CrossDomainMessageParams {
    pub source_domain: DomainId,
    pub target_domain: DomainId,
    pub source_height: u64,
    pub event_index: u32,
    pub nonce: u64,
    pub sender: Address,
    pub recipient: Address,
    pub payload_hash: Hash32,
    pub kind: MessageKind,
    pub expiry_height: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(label: &[u8]) -> Hash32 {
        crate::core::hash::hash_fields_bytes(&[label])
    }

    #[test]
    fn message_id_is_deterministic_and_tamper_evident() {
        let params = CrossDomainMessageParams {
            source_domain: 1,
            target_domain: 2,
            source_height: 42,
            event_index: 7,
            nonce: 3,
            sender: Address::from([1u8; 32]),
            recipient: Address::from([2u8; 32]),
            payload_hash: hash(b"payload"),
            kind: MessageKind::BridgeLock,
            expiry_height: 100,
        };

        let message_a = CrossDomainMessage::new(params.clone());
        let message_b = CrossDomainMessage::new(params);
        assert_eq!(message_a.message_id, message_b.message_id);
        assert!(message_a.verify_id());

        let mut tampered = message_a.clone();
        tampered.nonce += 1;
        assert!(!tampered.verify_id());
    }
}
