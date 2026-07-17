//! Bridge ↔ Relayer integration layer.
//!
//! Orchestrates the full cross-domain transfer lifecycle:
//! 1. User initiates lock/burn on source domain → bridge creates event
//! 2. Relayer picks up the event → submits proof on target domain
//! 3. Bridge processes the verified message → mint/unlock on target
//!
//! This module ties `BridgeState`, `UniversalRelayer`, and
//! `CrossDomainMessageRegistry` into a coherent pipeline.

use crate::core::address::Address;
use crate::cross_domain::bridge::{BridgeError, BridgeState};
use crate::cross_domain::event_tree::{DomainEvent, DomainEventTree, MerkleProof};
use crate::cross_domain::message::{CrossDomainMessage, MessageId, MessageKind};
use crate::cross_domain::message_registry::CrossDomainMessageRegistry;
use crate::cross_domain::relayer::{RelayerConfig, RelayerError, UniversalRelayer};
use crate::domain::types::{DomainId, Hash32};

/// Errors from the bridge-relayer integration pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineError {
    Bridge(BridgeError),
    Relayer(RelayerError),
    MessageRegistry(String),
    /// The message kind doesn't match the expected bridge operation.
    UnexpectedMessageKind {
        expected: &'static str,
        got: &'static str,
    },
    /// No event tree built for the source domain.
    NoEventTree(DomainId),
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipelineError::Bridge(e) => write!(f, "bridge error: {}", e),
            PipelineError::Relayer(e) => write!(f, "relayer error: {}", e),
            PipelineError::MessageRegistry(e) => write!(f, "message registry: {}", e),
            PipelineError::UnexpectedMessageKind { expected, got } => {
                write!(f, "expected message kind {}, got {}", expected, got)
            }
            PipelineError::NoEventTree(domain) => {
                write!(f, "no event tree for domain {}", domain)
            }
        }
    }
}

impl std::error::Error for PipelineError {}

impl From<BridgeError> for PipelineError {
    fn from(e: BridgeError) -> Self {
        PipelineError::Bridge(e)
    }
}

impl From<RelayerError> for PipelineError {
    fn from(e: RelayerError) -> Self {
        PipelineError::Relayer(e)
    }
}

/// Orchestrates the full bridge-relayer pipeline.
///
/// Holds references to all the pieces: bridge state, relayer, message registry,
/// and event trees (one per domain). The pipeline methods drive the state
/// machine through each stage of a cross-domain transfer.
pub struct BridgeRelayerPipeline {
    /// The bridge state machine (lock/mint/burn/unlock lifecycle).
    pub bridge: BridgeState,
    /// The universal relayer (pending relays, proof verification).
    pub relayer: UniversalRelayer,
    /// Registry of all cross-domain messages (dedup, root computation).
    pub messages: CrossDomainMessageRegistry,
    /// Event trees per domain (for Merkle proof generation).
    event_trees: std::collections::BTreeMap<DomainId, DomainEventTree>,
}

impl BridgeRelayerPipeline {
    pub fn new(relayer_config: RelayerConfig) -> Self {
        Self {
            bridge: BridgeState::new(),
            relayer: UniversalRelayer::new(relayer_config),
            messages: CrossDomainMessageRegistry::new(),
            event_trees: std::collections::BTreeMap::new(),
        }
    }

    /// Register an asset on a domain.
    pub fn register_asset(
        &mut self,
        asset_id: crate::cross_domain::bridge::AssetId,
        domain: DomainId,
    ) -> Result<(), PipelineError> {
        self.bridge.register_asset(asset_id, domain)?;
        Ok(())
    }

    /// Get or create an event tree for a domain.
    fn get_or_create_tree(&mut self, domain: DomainId) -> &mut DomainEventTree {
        self.event_trees
            .entry(domain)
            .or_insert_with(DomainEventTree::new)
    }

    // ─── Stage 1: Lock (source domain) ────

    /// Initiate a cross-domain lock. Creates the bridge transfer, event, and
    /// enqueues the relay request.
    ///
    /// Returns the event (for the caller's audit log).
    pub fn lock(
        &mut self,
        source_domain: DomainId,
        target_domain: DomainId,
        source_height: u64,
        asset_id: crate::cross_domain::bridge::AssetId,
        owner: Address,
        recipient: Address,
        amount: u128,
        expiry_height: u64,
    ) -> Result<DomainEvent, PipelineError> {
        let event_index = self.get_or_create_tree(source_domain).events().len() as u32;

        let (transfer, event) = self.bridge.lock(
            source_domain,
            target_domain,
            source_height,
            event_index,
            asset_id,
            owner,
            recipient,
            amount,
            expiry_height,
        )?;

        // Register the cross-domain message
        let message = event.message.clone().ok_or_else(|| {
            PipelineError::Relayer(RelayerError::Other("lock event missing message".into()))
        })?;
        self.messages
            .insert(message.clone())
            .map_err(PipelineError::MessageRegistry)?;

        // Enqueue relay
        self.relayer
            .enqueue_relay(event.clone(), &message, source_height);

        // Add to event tree
        self.get_or_create_tree(source_domain).push(event.clone());

        Ok(event)
    }

    // ─── Stage 2: Relay (relayer submits proof on target domain) ───

    /// Process a relay submission. The relayer provides a Merkle proof that
    /// the lock/burn event occurred on the source domain.
    ///
    /// On success, returns the verified cross-domain message for bridge
    /// processing (mint or unlock).
    pub fn relay(
        &mut self,
        message_id: MessageId,
        relayer: Address,
        proof: &MerkleProof,
        source_domain: DomainId,
        current_height: u64,
    ) -> Result<CrossDomainMessage, PipelineError> {
        let tree = self
            .event_trees
            .get(&source_domain)
            .ok_or(PipelineError::NoEventTree(source_domain))?;
        let root = tree.root();

        let message =
            self.relayer
                .process_relay(message_id, relayer, proof, root, current_height)?;

        Ok(message)
    }

    // ─── Stage 3: Mint (target domain) ────

    /// After relay verification, mint the asset on the target domain.
    pub fn mint(&mut self, message: &CrossDomainMessage) -> Result<(), PipelineError> {
        if !matches!(message.kind, MessageKind::BridgeLock) {
            return Err(PipelineError::UnexpectedMessageKind {
                expected: "BridgeLock",
                got: "other",
            });
        }
        self.bridge.mint(message)?;
        Ok(())
    }

    // ─── Stage 4: Burn (target domain) ────

    /// Burn the asset on the target domain to send it back.
    /// Returns the event for relay back to the source domain.
    pub fn burn(
        &mut self,
        message_id: MessageId,
        domain: DomainId,
        domain_height: u64,
        expiry_height: u64,
    ) -> Result<DomainEvent, PipelineError> {
        let event_index = self.get_or_create_tree(domain).events().len() as u32;

        let event = self.bridge.burn_with_event(
            message_id,
            domain,
            domain_height,
            event_index,
            expiry_height,
        )?;

        // Register the burn message
        if let Some(ref message) = event.message {
            self.messages
                .insert(message.clone())
                .map_err(PipelineError::MessageRegistry)?;

            // Enqueue relay back to source
            self.relayer
                .enqueue_relay(event.clone(), message, domain_height);
        }

        // Add to event tree
        self.get_or_create_tree(domain).push(event.clone());

        Ok(event)
    }

    // ─── Stage 5: Unlock (source domain) ─────

    /// After relay verification of a burn, unlock the asset on the source domain.
    pub fn unlock(
        &mut self,
        message: &CrossDomainMessage,
        source_domain: DomainId,
    ) -> Result<(), PipelineError> {
        if !matches!(message.kind, MessageKind::BridgeBurn) {
            return Err(PipelineError::UnexpectedMessageKind {
                expected: "BridgeBurn",
                got: "other",
            });
        }
        self.bridge.unlock(message.message_id, source_domain)?;
        Ok(())
    }

    /// Get the event tree root for a domain (for proof generation).
    pub fn event_tree_root(&self, domain: DomainId) -> Option<Hash32> {
        self.event_trees.get(&domain).map(|t| t.root())
    }

    /// Generate a Merkle proof for an event at a given index in a domain's tree.
    pub fn event_proof(&self, domain: DomainId, index: usize) -> Option<MerkleProof> {
        self.event_trees.get(&domain).and_then(|t| t.proof(index))
    }

    /// Get the bridge state for inspection.
    pub fn bridge_state(&self) -> &BridgeState {
        &self.bridge
    }

    /// Get the relayer for inspection.
    pub fn relayer(&self) -> &UniversalRelayer {
        &self.relayer
    }

    /// Sweep expired bridge locks (DoS prevention).
    pub fn sweep_expired_locks(
        &mut self,
        current_height: u64,
    ) -> Vec<(crate::cross_domain::bridge::AssetId, u128)> {
        self.bridge.sweep_expired_locks(current_height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::hash::hash_fields_bytes;
    use crate::cross_domain::bridge::AssetId;

    fn hash(label: &[u8]) -> Hash32 {
        hash_fields_bytes(&[label])
    }

    fn asset(id: u8) -> AssetId {
        hash(&[id])
    }

    fn pipeline() -> BridgeRelayerPipeline {
        BridgeRelayerPipeline::new(RelayerConfig::default())
    }

    fn owner() -> Address {
        Address::from([0xAA; 32])
    }

    fn recipient() -> Address {
        Address::from([0xBB; 32])
    }

    fn relayer_addr() -> Address {
        Address::from([0xCC; 32])
    }

    // Full lifecycle: lock → relay → mint

    #[test]
    fn full_lock_relay_mint_lifecycle() {
        let mut p = pipeline();
        let a = asset(1);

        // Register asset on domain 1 (source)
        p.register_asset(a, 1).unwrap();

        // Stage 1: Lock on source domain
        let event = p
            .lock(1, 2, 100, a, owner(), recipient(), 1000, 1000)
            .unwrap();
        assert_eq!(p.relayer().pending_count(), 1);
        assert!(p.event_tree_root(1).is_some());

        // Stage 2: Relay with proof
        let msg_id = event.message.as_ref().unwrap().message_id;
        let proof = p.event_proof(1, 0).unwrap();
        let relayed_msg = p
            .relay(msg_id, relayer_addr(), &proof, 1, 150)
            .unwrap();
        assert!(p.relayer().is_relayed(&msg_id));
        assert_eq!(p.relayer().pending_count(), 0);

        // Stage 3: Mint on target domain
        p.mint(&relayed_msg).unwrap();
        let transfer = p.bridge_state().get_transfer(&msg_id).unwrap();
        assert_eq!(
            transfer.status,
            crate::cross_domain::bridge::BridgeStatus::Minted { domain: 2 }
        );
    }

    // ─── ─── Full lifecycle: lock → relay → mint → burn → relay → unlock ─

    #[test]
    fn full_round_trip_lock_mint_burn_unlock() {
        let mut p = pipeline();
        let a = asset(2);

        p.register_asset(a, 1).unwrap();

        // Lock + relay + mint
        let lock_event = p
            .lock(1, 2, 100, a, owner(), recipient(), 500, 1000)
            .unwrap();
        let lock_msg_id = lock_event.message.as_ref().unwrap().message_id;
        let lock_proof = p.event_proof(1, 0).unwrap();
        let mint_msg = p
            .relay(lock_msg_id, relayer_addr(), &lock_proof, 1, 150)
            .unwrap();
        p.mint(&mint_msg).unwrap();

        // Burn on target domain (sends back to source)
        let burn_event = p.burn(lock_msg_id, 2, 200, 1000).unwrap();
        assert!(burn_event.message.is_some());
        assert_eq!(p.relayer().pending_count(), 1); // burn relay pending

        // Relay burn proof back to source
        let burn_msg_id = burn_event.message.as_ref().unwrap().message_id;
        let burn_proof = p.event_proof(2, 0).unwrap();
        let unlock_msg = p
            .relay(burn_msg_id, relayer_addr(), &burn_proof, 2, 250)
            .unwrap();
        assert!(p.relayer().is_relayed(&burn_msg_id));

        // Unlock on source domain
        p.unlock(&unlock_msg, 1).unwrap();
        let transfer = p.bridge_state().get_transfer(&lock_msg_id).unwrap();
        assert_eq!(
            transfer.status,
            crate::cross_domain::bridge::BridgeStatus::Unlocked { domain: 1 }
        );
    }

    // ─── Error cases ──────────────────────

    #[test]
    fn lock_rejects_unknown_asset() {
        let mut p = pipeline();
        let a = asset(99);
        let err = p
            .lock(1, 2, 100, a, owner(), recipient(), 100, 1000)
            .unwrap_err();
        assert!(matches!(err, PipelineError::Bridge(_)));
    }

    #[test]
    fn mint_rejects_wrong_message_kind() {
        let mut p = pipeline();
        let a = asset(3);
        p.register_asset(a, 1).unwrap();

        let event = p.lock(1, 2, 100, a, owner(), recipient(), 100, 1000).unwrap();
        let msg_id = event.message.as_ref().unwrap().message_id;
        let proof = p.event_proof(1, 0).unwrap();
        let mut relayed = p.relay(msg_id, relayer_addr(), &proof, 1, 150).unwrap();

        // Tamper the message kind
        relayed.kind = MessageKind::BridgeBurn;
        let err = p.mint(&relayed).unwrap_err();
        assert!(matches!(err, PipelineError::UnexpectedMessageKind { .. }));
    }

    #[test]
    fn relay_without_event_tree_fails() {
        let mut p = pipeline();
        let bad_proof = MerkleProof {
            leaf: hash(b"bad"),
            index: 0,
            siblings: vec![],
        };
        let err = p
            .relay(hash(b"msg"), relayer_addr(), &bad_proof, 99, 100)
            .unwrap_err();
        assert!(matches!(err, PipelineError::NoEventTree(99)));
    }

    // ─── Event tree consistency ───────────

    #[test]
    fn event_tree_grows_with_locks() {
        let mut p = pipeline();
        let a = asset(10);
        p.register_asset(a, 1).unwrap();

        p.lock(1, 2, 100, a, owner(), recipient(), 100, 1000)
            .unwrap();
        p.lock(1, 2, 101, a, owner(), recipient(), 200, 1000)
            .unwrap();

        let tree_root = p.event_tree_root(1).unwrap();
        let proof0 = p.event_proof(1, 0).unwrap();
        let proof1 = p.event_proof(1, 1).unwrap();

        assert!(proof0.verify(tree_root));
        assert!(proof1.verify(tree_root));
        assert_ne!(proof0.leaf, proof1.leaf);
    }
}
