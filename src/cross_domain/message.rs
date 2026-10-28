use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::crypto::facts::QuantumClass;
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
    ///
    /// IDENTITY: excluded - the key is the envelope that authenticates the
    /// id, and [`CrossDomainMessage::verify_sender_signature`] requires it
    /// to derive the `sender` the id already binds, so a different key
    /// under the same id proves control of nothing new.
    #[serde(default)]
    pub sender_public_key: Vec<u8>,
    /// IDENTITY: excluded - the signature is computed over the id, so it
    /// cannot be an input to it; the door verifies it against
    /// `sender_public_key` and the id instead.
    #[serde(default)]
    pub sender_signature: Vec<u8>,
    /// The quantum class of the source domain when the message was relayed
    ///: the weakest class among the schemes its adapter has observed,
    /// `None` while nothing is observed. A receiver reads it from the message
    /// and does not have to look the source domain up.
    ///
    /// IDENTITY: included - the id commits to it (envelope version 3).
    ///
    /// SIGNING: included - the relay transaction's preimage carries it, and
    /// the door refuses a class that differs from the one the chain derives
    /// for the source domain.
    #[serde(default)]
    pub source_quantum_class: Option<QuantumClass>,
}

/// The envelope version: the tag the message id is hashed under. Version 3
/// added `source_quantum_class`.
/// WIRING: cross-domain surface — the relayer/bridge doors that read it land with their wiring wave.
pub const MESSAGE_ENVELOPE_VERSION: u8 = 3;

/// The byte a class takes in the id and in the signed relay preimage:
/// `0` for no class, `1` classical, `2` lattice, `3` hash.
#[must_use]
pub const fn quantum_class_code(class: Option<QuantumClass>) -> u8 {
    match class {
        None => 0,
        Some(QuantumClass::Classical) => 1,
        Some(QuantumClass::Lattice) => 2,
        Some(QuantumClass::Hash) => 3,
    }
}

/// The inverse of [`quantum_class_code`]; `None` for a byte that names no
/// class (the caller refuses it rather than reading it as "no class").
#[must_use]
pub const fn quantum_class_from_code(code: u8) -> Option<Option<QuantumClass>> {
    match code {
        0 => Some(None),
        1 => Some(Some(QuantumClass::Classical)),
        2 => Some(Some(QuantumClass::Lattice)),
        3 => Some(Some(QuantumClass::Hash)),
        _ => None,
    }
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
            source_quantum_class: None,
        };
        message.message_id = message.calculate_message_id();
        message
    }

    /// The message with the source domain's quantum class set and the id
    /// recomputed over it.
    #[must_use]
    /// WIRING: cross-domain surface — the relayer/bridge doors that read it land with their wiring wave.
    pub fn with_source_quantum_class(mut self, class: Option<QuantumClass>) -> Self {
        self.source_quantum_class = class;
        self.message_id = self.calculate_message_id();
        self
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
    ///
    /// WIRING: exposed for the sender side of the relayed-message door:
    /// whoever originates a message signs the envelope here before the
    /// chain verifies it; in-tree origination is chain-built, so tests
    /// pin this half.
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
    /// WIRING: called by `register_relayed_on_state`, the body of the
    /// `CrossDomainMessage` transaction, and by the relayer suite that asserts
    /// an unsigned or wrongly signed message is refused.
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
            crate::crypto::ctx::CROSS_DOMAIN_V1,
            &self.message_id,
            &self.sender_signature,
            &self.sender_public_key,
        )
        .map_err(|e| format!("message sender signature does not verify: {e}"))
    }

    pub fn calculate_message_id(&self) -> MessageId {
        let kind = self.kind.as_bytes();
        // BLG-0121 (P05-F14): presence is folded in through the shared
        // `presence_tagged` helper - `None` and `Some([0; 32])` used to
        // hash identically (the zero-id collision class the header fix
        // closed in core/hash.rs:22).
        let correlation_id = crate::core::hash::presence_tagged(self.correlation_id);
        hash_fields_bytes(&[
            b"BDLM_CROSS_DOMAIN_MESSAGE_V3",
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
            &[quantum_class_code(self.source_quantum_class)],
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

/// The consensus half of registering a cross-domain message: what block
/// execution does.
///
/// Chain-built messages (lock, mint, burn, unlock) are the chain's own word and
/// skip the relayer gate; a RELAYED message must clear two more gates first,
/// and [`register_relayed_on_state`] is the one that applies them. Both halves
/// live here so the gates and the insert cannot drift apart.
///
/// # Errors
///
/// The message's own refusals: an id that does not match its fields, a message
/// addressed to its own source domain, one that has already expired, and the
/// registry's duplicate and size limits.
pub fn register_cross_domain_on_state(
    state: &mut crate::core::account::AccountState,
    message: &CrossDomainMessage,
) -> Result<(), String> {
    if !message.verify_id() {
        return Err(
            "Cross-domain message ID does not match canonical preimage (potential forgery)".into(),
        );
    }
    if message.source_domain == message.target_domain {
        return Err(format!(
            "Cross-domain message source and target domains must differ (both={})",
            message.source_domain
        ));
    }
    // Expiry is judged against the block being executed, not against the
    // request's idea of the height: the height is consensus state and the
    // request has none.
    let height = state.current_block_height;
    if message.expiry_height > 0 && height > message.expiry_height {
        return Err(format!(
            "Cross-domain message expired (expiry={}, current={height})",
            message.expiry_height
        ));
    }
    state.message_registry.insert(message.clone())
}

/// Register a RELAYED message, with the relayer gate and the sender's
/// signature.
///
/// `relayer` is the transaction's `from`. The message names its own sender and
/// must prove it (`verify_sender_signature`); `relayer` is who pays for and
/// carries the submission, and it must be an active relayer on this chain. The
/// two are checked separately because they answer different questions: a
/// message signed by an active relayer still has to be delivered by one, and
/// the delivery is what this transaction is.
///
/// # Errors
///
/// [`register_cross_domain_on_state`]'s refusals, plus a relayer that is not
/// active and a message whose sender signature does not verify.
pub fn register_relayed_on_state(
    state: &mut crate::core::account::AccountState,
    message: &CrossDomainMessage,
    relayer: crate::core::address::Address,
) -> Result<(), String> {
    state
        .registry
        .ensure_active_relayer(&relayer)
        .map_err(|e| e.to_string())?;
    // BLG-0113 (P05-F06): the sender must SIGN the message id. The
    // self-declared field alone let anybody name an active relayer and
    // register arbitrary messages - or pre-register a predictable lock id out
    // from under the real one.
    message.verify_sender_signature()?;
    register_cross_domain_on_state(state, message)
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

    ///: the class is part of the identity. Changing it, or removing
    /// it, produces another id, so a relay cannot rewrite what the receiver
    /// reads without the id check failing.
    #[test]
    fn the_source_quantum_class_is_part_of_the_message_id() {
        let params = CrossDomainMessageParams {
            source_domain: 1,
            target_domain: 2,
            source_height: 3,
            event_index: 0,
            nonce: 4,
            sender: Address::from([1u8; 32]),
            recipient: Address::from([2u8; 32]),
            payload_hash: [7u8; 32],
            kind: MessageKind::BridgeLock,
            expiry_height: 500,
        };
        let plain = CrossDomainMessage::new(params);
        assert_eq!(plain.source_quantum_class, None);
        let mut ids = vec![plain.message_id];
        for class in [
            QuantumClass::Classical,
            QuantumClass::Lattice,
            QuantumClass::Hash,
        ] {
            let classed = plain.clone().with_source_quantum_class(Some(class));
            assert_eq!(classed.source_quantum_class, Some(class));
            assert!(classed.verify_id());
            ids.push(classed.message_id);
            let mut rewritten = classed.clone();
            rewritten.source_quantum_class = None;
            assert!(!rewritten.verify_id(), "dropping the class breaks the id");
        }
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 4, "every class names another message");
    }

    #[test]
    fn class_codes_round_trip_and_refuse_unknown_bytes() {
        for class in [
            None,
            Some(QuantumClass::Classical),
            Some(QuantumClass::Lattice),
            Some(QuantumClass::Hash),
        ] {
            assert_eq!(
                quantum_class_from_code(quantum_class_code(class)),
                Some(class)
            );
        }
        assert_eq!(quantum_class_from_code(4), None);
        assert_eq!(MESSAGE_ENVELOPE_VERSION, 3);
    }

    /// BLG-0121 (P05-F14): a `None` correlation and a present one are
    /// DIFFERENT identities - the id folds presence, not just bytes. A
    /// correlated id of all zeros must not collapse into "no correlation".
    #[test]
    fn correlation_presence_changes_the_message_id() {
        let base = CrossDomainMessageParams {
            source_domain: 1,
            target_domain: 2,
            source_height: 3,
            event_index: 0,
            nonce: 4,
            sender: crate::core::address::Address::from([1u8; 32]),
            recipient: crate::core::address::Address::from([2u8; 32]),
            payload_hash: [7u8; 32],
            kind: MessageKind::BridgeLock,
            expiry_height: 500,
        };
        let plain = CrossDomainMessage::new(base.clone());
        let zeros = CrossDomainMessage::new_correlated(base.clone(), [0u8; 32]);
        let real = CrossDomainMessage::new_correlated(base, [5u8; 32]);
        assert_ne!(
            plain.message_id, zeros.message_id,
            "Some(all-zeros) must not equal None"
        );
        assert_ne!(plain.message_id, real.message_id);
        assert_ne!(zeros.message_id, real.message_id);
    }
}
