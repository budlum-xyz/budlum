//! Bridge ↔ Relayer integration layer.
//!
//! Orchestrates the full cross-domain transfer lifecycle:
//! 1. User initiates lock/burn on source domain → bridge creates event
//! 2. Relayer picks up the event → submits proof on target domain
//! 3. Bridge processes the verified message → mint/unlock on target
//!
//! This module ties `BridgeState`, `UniversalRelayer`, and
//! `CrossDomainMessageRegistry` into a coherent pipeline.
//!
//! WIRING: partially wired - the relay-enqueue stage runs in production
//! through `Blockchain::enqueue_bridge_relay` , which builds the
//! pipeline around the chain's own bridge, relayer and registry state. The
//! remaining stages (lock, relay, mint, burn, unlock) still have no
//! production loop sequencing them end to end: the components are reached
//! individually, and who owns that loop and how it is scheduled is a
//! node-lifecycle decision that has not been made.

use crate::core::address::Address;
use crate::cross_domain::bridge::{BridgeError, BridgeState};
use crate::cross_domain::event_tree::{DomainEvent, DomainEventTree, MerkleProof};
use crate::cross_domain::message::{CrossDomainMessage, MessageId, MessageKind};
use crate::cross_domain::message_registry::CrossDomainMessageRegistry;
use crate::cross_domain::relayer::{RelayerError, UniversalRelayer};
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
    /// A correlated message (e.g. bridge burn) is missing its correlation id.
    MissingCorrelationId,
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipelineError::Bridge(e) => write!(f, "bridge error: {e}"),
            PipelineError::Relayer(e) => write!(f, "relayer error: {e}"),
            PipelineError::MessageRegistry(e) => write!(f, "message registry: {e}"),
            PipelineError::UnexpectedMessageKind { expected, got } => {
                write!(f, "expected message kind {expected}, got {got}")
            }
            PipelineError::NoEventTree(domain) => {
                write!(f, "no event tree for domain {domain}")
            }
            PipelineError::MissingCorrelationId => {
                write!(f, "correlated message is missing its correlation id")
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
/// And event trees (one per domain). The pipeline methods drive the state
/// Machine through each stage of a cross-domain transfer.
pub struct BridgeRelayerPipeline<'a> {
    /// The bridge state machine (lock/mint/burn/unlock lifecycle). Borrowed:
    /// production lends the pipeline ITS OWN state , so
    /// there is no second copy of the bridge to keep in sync.
    pub bridge: &'a mut BridgeState,
    /// The universal relayer (pending relays, proof verification).
    pub relayer: &'a mut UniversalRelayer,
    /// Registry of all cross-domain messages (dedup, root computation).
    pub messages: &'a mut CrossDomainMessageRegistry,
    /// Event trees per domain (for Merkle proof generation).
    event_trees: std::collections::BTreeMap<DomainId, DomainEventTree>,
}

impl<'a> BridgeRelayerPipeline<'a> {
    /// Construct the pipeline around existing state - the production
    /// wiring: `Blockchain` builds one of these around
    /// its own bridge/relayer/registry and runs the stage work through it.
    pub fn from_parts(
        bridge: &'a mut BridgeState,
        relayer: &'a mut UniversalRelayer,
        messages: &'a mut CrossDomainMessageRegistry,
    ) -> Self {
        Self {
            bridge,
            relayer,
            messages,
            event_trees: std::collections::BTreeMap::new(),
        }
    }

    /// Stage 2 alone: enqueue the relay for an already-registered message.
    /// This is the step `Blockchain::enqueue_bridge_relay` runs, and it runs
    /// it THROUGH the pipeline ( wiring) rather than around
    /// it.
    pub fn enqueue_stage(
        &mut self,
        source_event: &DomainEvent,
        message: &CrossDomainMessage,
        source_height: u64,
    ) {
        // The stage refuses an event that does not
        // carry the enqueued message.
        if let Err(e) = self
            .relayer
            .enqueue_relay(source_event.clone(), message, source_height)
        {
            tracing::error!(error = %e, "bridge relay enqueue refused");
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
        self.event_trees.entry(domain).or_default()
    }

    // ─── Stage 1: Lock (source domain) ────

    /// Initiate a cross-domain lock. Creates the bridge transfer, event, and
    /// Enqueues the relay request.
    ///
    /// Returns the event (for the caller's audit log).
    #[expect(
        clippy::too_many_arguments,
        reason = ": the pipeline's lock mirrors BridgeState::lock's parameter set one-for-one"
    )]
    pub fn lock(
        &mut self,
        source_domain: DomainId,
        target_domain: DomainId,
        source_height: u64,
        asset_id: crate::cross_domain::bridge::AssetId,
        owner: Address,
        recipient: Address,
        amount: u64,
        expiry_height: u64,
    ) -> Result<DomainEvent, PipelineError> {
        let event_index = self.get_or_create_tree(source_domain).events().len() as u32;

        // The bridge is mutated before the registry is consulted, because
        // the message id is derived inside `lock` (it consumes the replay
        // nonce). If the registry then refuses the message, the row is
        // UNWOUND: `unwind_lock` removes exactly what the
        // lock added - no whole-`BridgeState` clone per call, which cost a
        // full state copy on every stage and was itself a DoS surface.
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
        let message = match event.message.clone() {
            Some(message) => message,
            None => {
                self.bridge.unwind_lock(&transfer.message_id, source_domain);
                return Err(PipelineError::Relayer(RelayerError::Other(
                    "lock event missing message".into(),
                )));
            }
        };
        if let Err(e) = self.messages.insert(message.clone()) {
            self.bridge.unwind_lock(&message.message_id, source_domain);
            return Err(PipelineError::MessageRegistry(e));
        }

        // Enqueue relay
        self.relayer
            .enqueue_relay(event.clone(), &message, source_height)?;

        // Add to event tree
        self.get_or_create_tree(source_domain).push(event.clone());

        Ok(event)
    }

    // ─── Stage 2: Relay (relayer submits proof on target domain) ───

    /// Process a relay submission. The relayer provides a Merkle proof that
    /// The lock/burn event occurred on the source domain.
    ///
    /// On success, returns the verified cross-domain message for bridge
    /// Processing (mint or unlock).
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

        let message = self.relayer.process_relay(
            message_id,
            relayer,
            proof,
            source_domain,
            root,
            current_height,
        )?;

        Ok(message)
    }

    // ─── Stage 3: Mint (target domain) ────

    /// After relay verification, mint the asset on the target domain.
    pub fn mint(
        &mut self,
        message: &CrossDomainMessage,
        current_height: u64,
    ) -> Result<(), PipelineError> {
        if !matches!(message.kind, MessageKind::BridgeLock) {
            return Err(PipelineError::UnexpectedMessageKind {
                expected: "BridgeLock",
                got: message.kind.name(),
            });
        }
        self.bridge.mint(message, current_height)?;
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
        recipient_eth: [u8; 20],
    ) -> Result<DomainEvent, PipelineError> {
        let event_index = self.get_or_create_tree(domain).events().len() as u32;

        // Same shape as `lock`: the burn moves the transfer to `Burned`
        // before the message can be registered, so a registry refusal
        // UNWINDS the burn (`unwind_burn`) instead of
        // restoring a whole-`BridgeState` clone, and instead of leaving a
        // burned transfer whose unlock message nobody holds.
        let previous_expiry = self
            .bridge
            .get_transfer(&message_id)
            .map_or(0, |t| t.expiry_height);
        let event = self.bridge.burn_with_event(
            message_id,
            domain,
            domain_height,
            event_index,
            expiry_height,
            recipient_eth,
        )?;

        // Register the burn message
        if let Some(ref message) = event.message {
            if let Err(e) = self.messages.insert(message.clone()) {
                self.bridge.unwind_burn(
                    &message_id,
                    crate::cross_domain::bridge::BridgeStatus::Minted { domain },
                    previous_expiry,
                );
                return Err(PipelineError::MessageRegistry(e));
            }

            // Enqueue relay back to source
            self.relayer
                .enqueue_relay(event.clone(), message, domain_height)?;
        }

        // Add to event tree
        self.get_or_create_tree(domain).push(event.clone());

        Ok(event)
    }

    // ─── Stage 5: Unlock (source domain) ─────

    /// After relay verification of a burn, unlock the asset on the source domain.
    /// `current_height` is the block the unlock settles in.
    pub fn unlock(
        &mut self,
        message: &CrossDomainMessage,
        source_domain: DomainId,
        current_height: u64,
    ) -> Result<(), PipelineError> {
        if !matches!(message.kind, MessageKind::BridgeBurn) {
            return Err(PipelineError::UnexpectedMessageKind {
                expected: "BridgeBurn",
                got: message.kind.name(),
            });
        }
        // A burn message carries its own id, but the bridge transfer is keyed
        // By the original lock message id. Resolve the transfer through the
        // Burn message's `correlation_id`, mirroring the production unlock
        // Path (blockchain.rs), which mandates it.
        let transfer_id = message
            .correlation_id
            .ok_or(PipelineError::MissingCorrelationId)?;
        self.bridge
            .unlock(transfer_id, source_domain, current_height)?;
        Ok(())
    }

    /// Get the event tree root for a domain (for proof generation).
    pub fn event_tree_root(&self, domain: DomainId) -> Option<Hash32> {
        self.event_trees
            .get(&domain)
            .map(super::event_tree::DomainEventTree::root)
    }

    /// Generate a Merkle proof for an event at a given index in a domain's tree.
    pub fn event_proof(&self, domain: DomainId, index: usize) -> Option<MerkleProof> {
        self.event_trees.get(&domain).and_then(|t| t.proof(index))
    }

    /// Get the bridge state for inspection.
    pub fn bridge_state(&self) -> &BridgeState {
        self.bridge
    }

    /// Get the relayer for inspection.
    pub fn relayer(&self) -> &UniversalRelayer {
        self.relayer
    }

    /// Sweep expired bridge locks (DoS prevention).
    /// Returns (owner, amount) for balance refund.
    pub fn sweep_expired_locks(
        &mut self,
        current_height: u64,
    ) -> Vec<(Address, crate::core::money::Bud)> {
        self.bridge.sweep_expired_locks(current_height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::hash::hash_fields_bytes;
    use crate::cross_domain::bridge::AssetId;

    fn relayer_addr() -> Address {
        Address::from([0xCC; 32])
    }

    // Full lifecycle: lock → relay → mint

    #[test]
    fn full_lock_relay_mint_lifecycle() {
        let mut rig = pipeline();
        let mut p = rig.pipeline();
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
        let relayed_msg = p.relay(msg_id, relayer_addr(), &proof, 1, 150).unwrap();
        assert!(p.relayer().is_relayed(&msg_id));
        assert_eq!(p.relayer().pending_count(), 0);

        // Stage 3: Mint on target domain
        p.mint(&relayed_msg, 0).unwrap();
        let transfer = p.bridge_state().get_transfer(&msg_id).unwrap();
        assert_eq!(
            transfer.status,
            crate::cross_domain::bridge::BridgeStatus::Minted { domain: 2 }
        );
    }

    // ─── ─── Full lifecycle: lock → relay → mint → burn → relay → unlock ─

    #[test]
    fn full_round_trip_lock_mint_burn_unlock() {
        let mut rig = pipeline();
        let mut p = rig.pipeline();
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
        p.mint(&mint_msg, 0).unwrap();

        // Burn on target domain (sends back to source)
        let burn_event = p.burn(lock_msg_id, 2, 200, 1000, [7u8; 20]).unwrap();
        assert!(burn_event.message.is_some());
        assert_eq!(p.relayer().pending_count(), 1); // burn relay pending

        // The burn message is correlated to the original lock transfer; the
        // Pipeline must resolve the transfer through `correlation_id`.
        let burn_msg = burn_event.message.as_ref().unwrap();
        assert_ne!(burn_msg.message_id, lock_msg_id);
        assert_eq!(burn_msg.correlation_id, Some(lock_msg_id));

        // Relay burn proof back to source
        let burn_msg_id = burn_event.message.as_ref().unwrap().message_id;
        let burn_proof = p.event_proof(2, 0).unwrap();
        let unlock_msg = p
            .relay(burn_msg_id, relayer_addr(), &burn_proof, 2, 250)
            .unwrap();
        assert!(p.relayer().is_relayed(&burn_msg_id));

        // Unlock must pass the burn domain (unlock_msg.source_domain = 2),
        // Which the bridge now checks against transfer.target_domain.
        p.unlock(&unlock_msg, 2, 250).unwrap();
        let transfer = p.bridge_state().get_transfer(&lock_msg_id).unwrap();
        assert_eq!(
            transfer.status,
            crate::cross_domain::bridge::BridgeStatus::Unlocked { domain: 1 }
        );
    }

    // ─── Error cases ──────────────────────

    #[test]
    fn lock_rejects_unknown_asset() {
        let mut rig = pipeline();
        let mut p = rig.pipeline();
        let a = asset(99);
        let err = p
            .lock(1, 2, 100, a, owner(), recipient(), 100, 1000)
            .unwrap_err();
        assert!(matches!(err, PipelineError::Bridge(_)));
    }

    #[test]
    fn mint_rejects_wrong_message_kind() {
        let mut rig = pipeline();
        let mut p = rig.pipeline();
        let a = asset(3);
        p.register_asset(a, 1).unwrap();

        let event = p
            .lock(1, 2, 100, a, owner(), recipient(), 100, 1000)
            .unwrap();
        let msg_id = event.message.as_ref().unwrap().message_id;
        let proof = p.event_proof(1, 0).unwrap();
        let mut relayed = p.relay(msg_id, relayer_addr(), &proof, 1, 150).unwrap();

        // Tamper the message kind
        relayed.kind = MessageKind::BridgeBurn;
        let err = p.mint(&relayed, 0).unwrap_err();
        assert!(matches!(err, PipelineError::UnexpectedMessageKind { .. }));
    }

    #[test]
    fn relay_without_event_tree_fails() {
        let mut rig = pipeline();
        let mut p = rig.pipeline();
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
        let mut rig = pipeline();
        let mut p = rig.pipeline();
        let a1 = asset(10);
        let a2 = asset(11);
        p.register_asset(a1, 1).unwrap();
        p.register_asset(a2, 1).unwrap();

        p.lock(1, 2, 100, a1, owner(), recipient(), 100, 1000)
            .unwrap();
        p.lock(1, 2, 101, a2, owner(), recipient(), 200, 1000)
            .unwrap();

        let tree_root = p.event_tree_root(1).unwrap();
        let proof0 = p.event_proof(1, 0).unwrap();
        let proof1 = p.event_proof(1, 1).unwrap();

        assert!(proof0.verify(tree_root));
        assert!(proof1.verify(tree_root));
        assert_ne!(proof0.leaf, proof1.leaf);
    }

    fn hash(label: &[u8]) -> Hash32 {
        hash_fields_bytes(&[label])
    }

    fn asset(id: u8) -> AssetId {
        AssetId(hash(&[id]))
    }

    /// Owned state + a borrow-based pipeline over it: the production shape
    /// - one state, the pipeline borrowing it.
    struct Rig {
        bridge: BridgeState,
        relayer: UniversalRelayer,
        messages: CrossDomainMessageRegistry,
    }

    impl Rig {
        fn new() -> Self {
            Self {
                bridge: BridgeState::new(),
                relayer: UniversalRelayer::new(
                    crate::cross_domain::relayer::RelayerConfig::default(),
                ),
                messages: CrossDomainMessageRegistry::new(),
            }
        }

        fn pipeline(&mut self) -> BridgeRelayerPipeline<'_> {
            BridgeRelayerPipeline::from_parts(
                &mut self.bridge,
                &mut self.relayer,
                &mut self.messages,
            )
        }
    }

    fn pipeline() -> Rig {
        Rig::new()
    }

    fn owner() -> Address {
        Address::from([0xAA; 32])
    }

    fn recipient() -> Address {
        Address::from([0xBB; 32])
    }

    /// A message the registry already holds cannot be registered twice, and
    /// the bridge must not be left holding the lock that produced it. The
    /// duplicate is manufactured by pre-registering the exact message the
    /// next lock will derive (same nonce, same fields), so the registry
    /// refuses it and the lock has to undo itself.
    #[test]
    fn a_lock_whose_message_is_refused_leaves_the_bridge_untouched() {
        let mut rig = pipeline();
        let mut p = rig.pipeline();
        let a = asset(7);
        p.register_asset(a, 1).unwrap();
        let root_before = p.bridge_state().root();

        // Derive the message the lock is about to create and register it
        // first. `lock` consumes nonce 0 for (1, 2, owner), so the derived
        // message uses nonce 0 as well.
        let dry = {
            let mut scratch_rig = pipeline();
            let mut scratch = scratch_rig.pipeline();
            scratch.register_asset(a, 1).unwrap();
            scratch
                .lock(1, 2, 100, a, owner(), recipient(), 1000, 1000)
                .unwrap()
                .message
                .unwrap()
        };
        p.messages.insert(dry.clone()).unwrap();

        let err = p
            .lock(1, 2, 100, a, owner(), recipient(), 1000, 1000)
            .unwrap_err();
        assert!(
            matches!(err, PipelineError::MessageRegistry(ref m) if m.contains("already registered")),
            "got: {err}"
        );
        assert!(
            p.bridge_state().get_transfer(&dry.message_id).is_none(),
            "a refused lock must not leave a transfer row"
        );
        assert_eq!(
            p.bridge_state().root(),
            root_before,
            "the bridge state must be exactly what it was before the refused lock"
        );
        assert_eq!(p.relayer().pending_count(), 0);
        assert!(p.event_proof(1, 0).is_none(), "no event was appended");

        // The asset is still lockable: nothing was consumed.
        p.lock(1, 2, 101, a, owner(), recipient(), 1000, 1000)
            .expect("the asset is still Active on domain 1");
    }

    /// The burn side has the same shape: a refused burn message leaves the
    /// transfer `Minted`, so it can still be burned once the conflict clears.
    #[test]
    fn a_burn_whose_message_is_refused_leaves_the_transfer_minted() {
        let mut rig = pipeline();
        let mut p = rig.pipeline();
        let a = asset(8);
        p.register_asset(a, 1).unwrap();
        let lock_event = p
            .lock(1, 2, 100, a, owner(), recipient(), 500, 1000)
            .unwrap();
        let lock_msg_id = lock_event.message.as_ref().unwrap().message_id;
        let lock_proof = p.event_proof(1, 0).unwrap();
        let mint_msg = p
            .relay(lock_msg_id, relayer_addr(), &lock_proof, 1, 150)
            .unwrap();
        p.mint(&mint_msg, 0).unwrap();

        // Pre-register the burn message the next burn will derive.
        let dry_burn = {
            let mut scratch = p.bridge_state().clone();
            scratch
                .burn_with_event(lock_msg_id, 2, 200, 0, 1000, [7u8; 20])
                .unwrap()
                .message
                .unwrap()
        };
        p.messages.insert(dry_burn.clone()).unwrap();
        let root_before = p.bridge_state().root();

        let err = p.burn(lock_msg_id, 2, 200, 1000, [7u8; 20]).unwrap_err();
        assert!(
            matches!(err, PipelineError::MessageRegistry(_)),
            "got: {err}"
        );
        assert_eq!(
            p.bridge_state().get_transfer(&lock_msg_id).unwrap().status,
            crate::cross_domain::bridge::BridgeStatus::Minted { domain: 2 },
            "a refused burn must not leave the transfer burned"
        );
        assert_eq!(p.bridge_state().root(), root_before);
        assert_eq!(p.relayer().pending_count(), 0);
    }

    /// The error names the kind that arrived, not a placeholder.
    #[test]
    fn an_unexpected_kind_is_reported_by_name() {
        let mut rig = pipeline();
        let mut p = rig.pipeline();
        let a = asset(9);
        p.register_asset(a, 1).unwrap();
        let lock_event = p
            .lock(1, 2, 100, a, owner(), recipient(), 500, 1000)
            .unwrap();
        let lock_msg = lock_event.message.unwrap();
        let err = p.unlock(&lock_msg, 2, 250).unwrap_err();
        assert_eq!(
            err.to_string(),
            "expected message kind BridgeBurn, got BridgeLock"
        );
    }

    #[test]
    fn pipeline_error_display() {
        let err = PipelineError::NoEventTree(99);
        assert!(err.to_string().contains("99"));

        let err = PipelineError::UnexpectedMessageKind {
            expected: "BridgeLock",
            got: "BridgeBurn",
        };
        assert!(err.to_string().contains("BridgeLock"));
        assert!(err.to_string().contains("BridgeBurn"));
    }

    #[test]
    fn pipeline_register_asset_rejects_duplicate() {
        let mut rig = pipeline();
        let mut p = rig.pipeline();
        let a = asset(50);
        p.register_asset(a, 1).unwrap();
        let err = p.register_asset(a, 1).unwrap_err();
        assert!(matches!(err, PipelineError::Bridge(_)));
    }

    #[test]
    fn pipeline_burn_rejects_unminted_transfer() {
        let mut rig = pipeline();
        let mut p = rig.pipeline();
        let a = asset(51);
        p.register_asset(a, 1).unwrap();

        // Lock but don't relay/mint
        let event = p
            .lock(1, 2, 100, a, owner(), recipient(), 100, 1000)
            .unwrap();
        let msg_id = event.message.as_ref().unwrap().message_id;

        // Burn should fail (transfer is Locked, not Minted)
        let err = p.burn(msg_id, 2, 200, 1000, [7u8; 20]).unwrap_err();
        assert!(matches!(err, PipelineError::Bridge(_)));
    }

    #[test]
    fn pipeline_sweep_expired_locks_returns_empty_initially() {
        let mut rig = pipeline();
        let mut p = rig.pipeline();
        let released = p.sweep_expired_locks(10000);
        assert!(released.is_empty());
    }

    #[test]
    fn pipeline_bridge_state_root_is_deterministic() {
        let mut rig = pipeline();
        let mut p = rig.pipeline();
        let a = asset(52);
        p.register_asset(a, 1).unwrap();

        let root1 = p.bridge_state().root();
        let root2 = p.bridge_state().root();
        assert_eq!(root1, root2);
    }
}
