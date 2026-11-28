//! Universal cross-domain event bus.
//!
//! Contracts on a target domain subscribe to filtered events emitted on any
//! settled source domain (for example, an EVM `Transfer(address,address,uint256)`
//! or `BudlumOutbound` log). Delivery requires:
//!   1. An active source domain in [`ConsensusDomainRegistry`].
//!   2. A finalized [`DomainCommitmentRegistry`] entry at `(source_domain, height)`
//!      with a non-zero `event_root`.
//!   3. A valid [`MerkleProof`] binding [`DomainEvent::leaf_hash`] to `event_root`.
//!   4. Filter match on event kind, optional emitter, and optional `topic0` + payload.
//!   5. Strictly once-only delivery per `(subscription_id, event_leaf_hash)`.
//!
//! Honest boundary: delivery latency equals source-domain finality latency;
//! unfinalized or frozen source domains never trigger callbacks.
//!
//! WIRING: held as `SettlementRegistries::event_bus` in
//! `src/settlement/registries.rs`, folded into the settlement state root when
//! non-empty, and verified by `tests/k7g_universal_event_bus_tests.rs`.

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::event_tree::{DomainEvent, DomainEventKind, MerkleProof};
use crate::domain::types::{DomainId, DomainStatus, Hash32};
use crate::domain::{ConsensusDomainRegistry, DomainCommitmentRegistry};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::{BTreeMap, BTreeSet};
use subtle::ConstantTimeEq;

/// Maximum active/historical subscriptions stored in the live bus state.
const MAX_EVENT_SUBSCRIPTIONS: usize = 4_096;

/// Maximum custom event-kind tag length in bytes.
const MAX_CUSTOM_KIND_BYTES: usize = 128;

/// Maximum raw event payload bytes carried into a callback invocation (64 KiB).
const MAX_EVENT_PAYLOAD_BYTES: usize = 65_536;

/// Compute the canonical EVM event `topic0 = Keccak256(signature)`.
#[must_use]
pub fn evm_event_topic0(signature: &str) -> Hash32 {
    Keccak256::digest(signature.as_bytes()).into()
}

/// Bind an event's `topic0` and raw payload into the canonical 32-byte
/// `DomainEvent::payload_hash` checked during topic-filtered delivery.
#[must_use]
pub fn event_bus_payload_hash(topic0: Hash32, raw_payload: &[u8]) -> Hash32 {
    hash_fields_bytes(&[b"BDLM_EVENT_BUS_PAYLOAD_V1", &topic0, raw_payload])
}

/// Filter describing which source-domain events match a subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventTopicFilter {
    /// Required [`DomainEventKind`].
    pub kind: DomainEventKind,
    /// Optional source contract/emitter address (if `Some`, must be non-zero).
    pub emitter: Option<Address>,
    /// Optional 32-byte event topic0 (for example `Keccak256("Transfer(address,address,uint256)")`).
    pub topic0: Option<Hash32>,
}

impl EventTopicFilter {
    /// Convenience constructor for subscribing to an EVM contract event signature.
    #[must_use]
    pub fn evm_event(emitter: Address, signature: &str) -> Self {
        Self {
            kind: DomainEventKind::Custom(b"evm-log".to_vec()),
            emitter: Some(emitter),
            topic0: Some(evm_event_topic0(signature)),
        }
    }

    fn validate(&self) -> Result<(), EventBusError> {
        if let DomainEventKind::Custom(bytes) = &self.kind {
            if bytes.is_empty() || bytes.len() > MAX_CUSTOM_KIND_BYTES {
                return Err(EventBusError::InvalidFilter(
                    "custom event kind must be 1..=128 bytes",
                ));
            }
        }
        if self.emitter.is_some_and(|addr| addr == Address::zero()) {
            return Err(EventBusError::InvalidFilter(
                "filter emitter must not be the zero address",
            ));
        }
        if self.topic0.is_some_and(|t| bool::from(t.ct_eq(&[0u8; 32]))) {
            return Err(EventBusError::InvalidFilter(
                "filter topic0 must not be all-zero",
            ));
        }
        Ok(())
    }

    fn canonical_digest(&self) -> Hash32 {
        let kind_bytes = match &self.kind {
            DomainEventKind::BridgeLocked => b"bridge-locked".to_vec(),
            DomainEventKind::BridgeMinted => b"bridge-minted".to_vec(),
            DomainEventKind::BridgeBurned => b"bridge-burned".to_vec(),
            DomainEventKind::Custom(bytes) => {
                let mut out = b"custom:".to_vec();
                out.extend_from_slice(bytes);
                out
            }
        };
        let has_emitter = [u8::from(self.emitter.is_some())];
        let emitter_bytes = self.emitter.map_or([0u8; 32], |a| *a.as_bytes());
        let has_topic0 = [u8::from(self.topic0.is_some())];
        let topic0_bytes = self.topic0.unwrap_or([0u8; 32]);
        hash_fields_bytes(&[
            b"BDLM_EVENT_FILTER_V1",
            &kind_bytes,
            &has_emitter,
            &emitter_bytes,
            &has_topic0,
            &topic0_bytes,
        ])
    }
}

/// Parameters required to open a cross-domain event subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventSubscriptionRequest {
    /// Settled source domain emitting the watched events.
    pub source_domain: DomainId,
    /// Target domain where `callback_contract` resides.
    pub target_domain: DomainId,
    /// Account owning and authorized to cancel the subscription.
    pub subscriber: Address,
    /// Target contract address to invoke upon finalized event proof delivery.
    pub callback_contract: Address,
    /// Event matching filter.
    pub filter: EventTopicFilter,
    /// Maximum callbacks allowed (`0` means unlimited).
    pub max_deliveries: u64,
}

impl EventSubscriptionRequest {
    /// Deterministic subscription identifier bound to all subscription fields.
    #[must_use]
    pub fn subscription_id(&self) -> Hash32 {
        let filter_digest = self.filter.canonical_digest();
        hash_fields_bytes(&[
            b"BDLM_EVENT_SUB_V1",
            &self.source_domain.to_le_bytes(),
            &self.target_domain.to_le_bytes(),
            self.subscriber.as_bytes(),
            self.callback_contract.as_bytes(),
            &filter_digest,
            &self.max_deliveries.to_le_bytes(),
        ])
    }
}

/// Persisted cross-domain event subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventSubscription {
    pub subscription_id: Hash32,
    pub source_domain: DomainId,
    pub target_domain: DomainId,
    pub subscriber: Address,
    pub callback_contract: Address,
    pub filter: EventTopicFilter,
    pub max_deliveries: u64,
    pub delivered_count: u64,
    pub active: bool,
}

/// Verified, replay-protected callback payload emitted on finalized event delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallbackInvocation {
    pub delivery_key: Hash32,
    pub subscription_id: Hash32,
    pub source_domain: DomainId,
    pub target_domain: DomainId,
    pub callback_contract: Address,
    pub source_height: u64,
    pub event_index: u32,
    pub emitter: Address,
    pub payload_hash: Hash32,
    pub event_leaf_hash: Hash32,
    pub raw_payload: Vec<u8>,
}

/// Borrowed event-delivery envelope submitted to [`UniversalEventBus::deliver_verified`].
#[derive(Debug, Clone, Copy)]
pub struct EventDeliveryProof<'a> {
    pub subscription_id: Hash32,
    pub event: &'a DomainEvent,
    pub proof: &'a MerkleProof,
    pub observed_topic0: Option<Hash32>,
    pub raw_payload: &'a [u8],
}

/// Failure reasons for universal event bus operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EventBusError {
    #[error("invalid domain routing: source={source_domain}, target={target_domain}")]
    InvalidDomainRouting {
        source_domain: DomainId,
        target_domain: DomainId,
    },
    #[error("zero address is not allowed for `{field}`")]
    ZeroAddress { field: &'static str },
    #[error("invalid event filter: {0}")]
    InvalidFilter(&'static str),
    #[error("subscription capacity exceeded (max {MAX_EVENT_SUBSCRIPTIONS})")]
    CapacityExceeded,
    #[error("subscription already exists")]
    DuplicateSubscription,
    #[error("subscription not found")]
    UnknownSubscription,
    #[error("subscription is inactive")]
    SubscriptionInactive,
    #[error("caller is not authorized to modify this subscription")]
    Unauthorized,
    #[error("subscription reached its maximum delivery budget ({max})")]
    DeliveryBudgetExhausted { max: u64 },
    #[error("event payload exceeds {MAX_EVENT_PAYLOAD_BYTES} bytes (got {len})")]
    PayloadTooLarge { len: usize },
    #[error("event source domain {got} does not match subscription source {expected}")]
    DomainMismatch { expected: DomainId, got: DomainId },
    #[error("event kind does not match subscription filter")]
    KindMismatch,
    #[error("event emitter does not match subscription filter")]
    EmitterMismatch,
    #[error("event topic0 does not match subscription filter")]
    TopicMismatch,
    #[error("event payload_hash does not match canonical topic0+payload commitment")]
    PayloadBindingMismatch,
    #[error("source domain {domain_id} is unregistered or not active")]
    SourceDomainNotActive { domain_id: DomainId },
    #[error("no finalized event_root attested for domain {domain_id} at height {height}")]
    UnattestedHeight { domain_id: DomainId, height: u64 },
    #[error("Merkle inclusion proof failed against finalized event_root")]
    InvalidMerkleProof,
    #[error("event already delivered for this subscription (exactly-once invariant)")]
    AlreadyDelivered,
}

/// Deterministic consensus state for cross-domain event subscriptions and
/// exactly-once delivery tracking.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniversalEventBus {
    /// Hex-encoded `subscription_id` -> subscription record (string keys for
    /// JSON/serde determinism).
    subscriptions: BTreeMap<String, EventSubscription>,
    /// Hex-encoded `delivery_key` set enforcing strictly once-only execution.
    delivered: BTreeSet<String>,
}

impl UniversalEventBus {
    /// Construct an empty event bus.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            subscriptions: BTreeMap::new(),
            delivered: BTreeSet::new(),
        }
    }

    /// True when no subscriptions or deliveries have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.subscriptions.is_empty() && self.delivered.is_empty()
    }

    /// Look up a subscription by its 32-byte identifier.
    #[must_use]
    pub fn get_subscription(&self, subscription_id: Hash32) -> Option<&EventSubscription> {
        self.subscriptions.get(&hex::encode(subscription_id))
    }

    /// True if `delivery_key` has already been executed.
    #[must_use]
    pub fn is_delivered(&self, delivery_key: Hash32) -> bool {
        self.delivered.contains(&hex::encode(delivery_key))
    }

    /// Compute the deterministic consensus state root of the event bus.
    #[must_use]
    pub fn root(&self) -> Hash32 {
        let mut fields: Vec<Vec<u8>> =
            Vec::with_capacity(1 + self.subscriptions.len() * 8 + self.delivered.len());
        fields.push(b"BDLM_UNIVERSAL_EVENT_BUS_V1".to_vec());
        fields.push((self.subscriptions.len() as u64).to_le_bytes().to_vec());
        for sub in self.subscriptions.values() {
            fields.push(sub.subscription_id.to_vec());
            fields.push(sub.source_domain.to_le_bytes().to_vec());
            fields.push(sub.target_domain.to_le_bytes().to_vec());
            fields.push(sub.subscriber.as_bytes().to_vec());
            fields.push(sub.callback_contract.as_bytes().to_vec());
            fields.push(sub.filter.canonical_digest().to_vec());
            fields.push(sub.max_deliveries.to_le_bytes().to_vec());
            fields.push(sub.delivered_count.to_le_bytes().to_vec());
            fields.push(vec![u8::from(sub.active)]);
        }
        fields.push((self.delivered.len() as u64).to_le_bytes().to_vec());
        for key in &self.delivered {
            fields.push(key.as_bytes().to_vec());
        }
        let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        hash_fields_bytes(&refs)
    }

    /// Register a new cross-domain event subscription.
    ///
    /// # Errors
    ///
    /// Refuses invalid domain routing, zero addresses, invalid filters,
    /// capacity exhaustion, or duplicate subscription ids before any mutation.
    pub fn subscribe(&mut self, req: EventSubscriptionRequest) -> Result<Hash32, EventBusError> {
        if req.source_domain == 0
            || req.target_domain == 0
            || req.source_domain == req.target_domain
        {
            return Err(EventBusError::InvalidDomainRouting {
                source_domain: req.source_domain,
                target_domain: req.target_domain,
            });
        }
        if req.subscriber == Address::zero() {
            return Err(EventBusError::ZeroAddress {
                field: "subscriber",
            });
        }
        if req.callback_contract == Address::zero() {
            return Err(EventBusError::ZeroAddress {
                field: "callback_contract",
            });
        }
        req.filter.validate()?;
        if self.subscriptions.len() >= MAX_EVENT_SUBSCRIPTIONS {
            return Err(EventBusError::CapacityExceeded);
        }

        let subscription_id = req.subscription_id();
        let key = hex::encode(subscription_id);
        if self.subscriptions.contains_key(&key) {
            return Err(EventBusError::DuplicateSubscription);
        }

        self.subscriptions.insert(
            key,
            EventSubscription {
                subscription_id,
                source_domain: req.source_domain,
                target_domain: req.target_domain,
                subscriber: req.subscriber,
                callback_contract: req.callback_contract,
                filter: req.filter,
                max_deliveries: req.max_deliveries,
                delivered_count: 0,
                active: true,
            },
        );
        Ok(subscription_id)
    }

    /// Deactivate a subscription; only the original subscriber may cancel it.
    ///
    /// # Errors
    ///
    /// Returns [`EventBusError::UnknownSubscription`], [`EventBusError::Unauthorized`],
    /// or [`EventBusError::SubscriptionInactive`].
    pub fn cancel_subscription(
        &mut self,
        subscription_id: Hash32,
        caller: Address,
    ) -> Result<(), EventBusError> {
        let key = hex::encode(subscription_id);
        let sub = self
            .subscriptions
            .get_mut(&key)
            .ok_or(EventBusError::UnknownSubscription)?;
        if sub.subscriber != caller {
            return Err(EventBusError::Unauthorized);
        }
        if !sub.active {
            return Err(EventBusError::SubscriptionInactive);
        }
        sub.active = false;
        Ok(())
    }

    /// Verify a finalized source-domain event against `domains` and `commitments`
    /// and emit a replay-protected [`CallbackInvocation`].
    ///
    /// All checks run before any mutation so any refusal leaves state untouched.
    ///
    /// # Errors
    ///
    /// Fails closed on inactive/unknown subscription, budget exhaustion, filter
    /// mismatch, frozen/unregistered source domain, unattested height, forged
    /// Merkle proof, or replayed delivery.
    pub fn deliver_verified(
        &mut self,
        domains: &ConsensusDomainRegistry,
        commitments: &DomainCommitmentRegistry,
        delivery: &EventDeliveryProof<'_>,
    ) -> Result<CallbackInvocation, EventBusError> {
        let subscription_id = delivery.subscription_id;
        let event = delivery.event;
        let proof = delivery.proof;
        let observed_topic0 = delivery.observed_topic0;
        let raw_payload = delivery.raw_payload;
        if raw_payload.len() > MAX_EVENT_PAYLOAD_BYTES {
            return Err(EventBusError::PayloadTooLarge {
                len: raw_payload.len(),
            });
        }
        if event.emitter == Address::zero() {
            return Err(EventBusError::ZeroAddress { field: "emitter" });
        }

        let sub_key = hex::encode(subscription_id);
        let sub = self
            .subscriptions
            .get(&sub_key)
            .ok_or(EventBusError::UnknownSubscription)?;
        if !sub.active {
            return Err(EventBusError::SubscriptionInactive);
        }
        if sub.max_deliveries > 0 && sub.delivered_count >= sub.max_deliveries {
            return Err(EventBusError::DeliveryBudgetExhausted {
                max: sub.max_deliveries,
            });
        }
        if event.domain_id != sub.source_domain {
            return Err(EventBusError::DomainMismatch {
                expected: sub.source_domain,
                got: event.domain_id,
            });
        }
        if event.kind != sub.filter.kind {
            return Err(EventBusError::KindMismatch);
        }
        if let Some(expected_emitter) = sub.filter.emitter {
            if event.emitter != expected_emitter {
                return Err(EventBusError::EmitterMismatch);
            }
        }
        if let Some(expected_topic0) = sub.filter.topic0 {
            let Some(got_topic0) = observed_topic0 else {
                return Err(EventBusError::TopicMismatch);
            };
            if !bool::from(got_topic0.ct_eq(&expected_topic0)) {
                return Err(EventBusError::TopicMismatch);
            }
            let expected_payload_hash = event_bus_payload_hash(expected_topic0, raw_payload);
            if !bool::from(event.payload_hash.ct_eq(&expected_payload_hash)) {
                return Err(EventBusError::PayloadBindingMismatch);
            }
        } else if bool::from(event.payload_hash.ct_eq(&[0u8; 32])) {
            return Err(EventBusError::PayloadBindingMismatch);
        }

        // Source domain must be registered and actively settling.
        let domain = domains
            .get(event.domain_id)
            .ok_or(EventBusError::SourceDomainNotActive {
                domain_id: event.domain_id,
            })?;
        if domain.status != DomainStatus::Active {
            return Err(EventBusError::SourceDomainNotActive {
                domain_id: event.domain_id,
            });
        }

        // Source height must hold a finalized commitment with a non-zero event_root.
        let commitment = commitments
            .find_by_height(event.domain_id, event.domain_height)
            .ok_or(EventBusError::UnattestedHeight {
                domain_id: event.domain_id,
                height: event.domain_height,
            })?;
        if bool::from(commitment.event_root.ct_eq(&[0u8; 32])) {
            return Err(EventBusError::UnattestedHeight {
                domain_id: event.domain_id,
                height: event.domain_height,
            });
        }

        // Verify exact event leaf binding and Merkle inclusion in finalized event_root.
        let event_leaf = event.leaf_hash();
        if !bool::from(proof.leaf.ct_eq(&event_leaf)) || !proof.verify(commitment.event_root) {
            return Err(EventBusError::InvalidMerkleProof);
        }

        // Exactly-once replay key per (subscription_id, event_leaf).
        let delivery_key =
            hash_fields_bytes(&[b"BDLM_EVENT_BUS_DELIVERY_V1", &subscription_id, &event_leaf]);
        let delivery_hex = hex::encode(delivery_key);
        if self.delivered.contains(&delivery_hex) {
            return Err(EventBusError::AlreadyDelivered);
        }

        // All checks succeeded: commit state mutation.
        let sub_mut = self
            .subscriptions
            .get_mut(&sub_key)
            .ok_or(EventBusError::UnknownSubscription)?;
        let target_domain = sub_mut.target_domain;
        let callback_contract = sub_mut.callback_contract;
        sub_mut.delivered_count = sub_mut.delivered_count.saturating_add(1);
        self.delivered.insert(delivery_hex);

        Ok(CallbackInvocation {
            delivery_key,
            subscription_id,
            source_domain: event.domain_id,
            target_domain,
            callback_contract,
            source_height: event.domain_height,
            event_index: event.event_index,
            emitter: event.emitter,
            payload_hash: event.payload_hash,
            event_leaf_hash: event_leaf,
            raw_payload: raw_payload.to_vec(),
        })
    }
}
