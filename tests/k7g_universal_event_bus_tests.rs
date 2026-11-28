use budlum_core::core::address::Address;
use budlum_core::cross_domain::event_bus::{
    event_bus_payload_hash, evm_event_topic0, EventBusError, EventDeliveryProof,
    EventSubscriptionRequest, EventTopicFilter,
};
use budlum_core::cross_domain::event_tree::{DomainEvent, DomainEventKind, DomainEventTree};
use budlum_core::domain::types::{
    ConsensusDomain, ConsensusKind, DomainCommitment, DomainStatus, RootScheme,
};
use budlum_core::settlement::SettlementRegistries;
use std::collections::BTreeMap;

fn must<T, E: std::fmt::Debug>(res: Result<T, E>, msg: &str) -> T {
    match res {
        Ok(v) => v,
        Err(e) => panic!("{msg}: {e:?}"),
    }
}

fn active_sepolia_domain(domain_id: u32) -> ConsensusDomain {
    ConsensusDomain {
        id: domain_id,
        kind: ConsensusKind::Bft,
        status: DomainStatus::Active,
        domain_chain_id: 11_155_111,
        operator: Some(Address::from([0x11; 32])),
        operator_bond: budlum_core::domain::registry::MIN_DOMAIN_OPERATOR_BOND,
        config_hash: [0xAA; 32],
        validator_set_hash: [0xBB; 32],
        finality_adapter: "ethereum-sync-v1".into(),
        min_confirmations: 1,
        bridge_enabled: true,
        block_hash_scheme: RootScheme::Sha256,
        state_root_scheme: RootScheme::Sha256,
        tx_root_scheme: RootScheme::Sha256,
        last_committed_height: 100,
        last_committed_hash: [0x10; 32],
        pow_parameters: None,
        zk_program_allowlist: Vec::new(),
        plugin_code_hash: None,
        genesis_state_root: [0u8; 32],
    }
}

fn finalized_commitment(domain_id: u32, height: u64, event_root: [u8; 32]) -> DomainCommitment {
    DomainCommitment {
        domain_id,
        domain_height: height,
        domain_block_hash: [0x21; 32],
        parent_domain_block_hash: [0x20; 32],
        state_root: [0x30; 32],
        tx_root: [0x31; 32],
        event_root,
        finality_proof_hash: [0x33; 32],
        consensus_kind: ConsensusKind::Bft,
        validator_set_hash: [0xBB; 32],
        timestamp_ms: 1_700_000_000_000,
        sequence: 1,
        producer: None,
        state_updates: BTreeMap::new(),
    }
}

#[test]
fn universal_event_bus_delivers_finalized_sepolia_transfer_exactly_once_and_updates_state_root() {
    let mut registries = SettlementRegistries::new();
    let empty_root = registries.root();
    assert!(registries.is_empty());
    assert!(registries.event_bus.is_empty());

    let sepolia_domain = 11_155_111u32;
    let budlum_domain = 1u32;
    let token_contract = Address::from([0xCA; 32]);
    let subscriber = Address::from([0x51; 32]);
    let callback_contract = Address::from([0xCB; 32]);

    must(
        registries
            .domains
            .restore_persisted(active_sepolia_domain(sepolia_domain)),
        "register sepolia domain",
    );

    let transfer_sig = "Transfer(address,address,uint256)";
    let topic0 = evm_event_topic0(transfer_sig);
    let sub_req = EventSubscriptionRequest {
        source_domain: sepolia_domain,
        target_domain: budlum_domain,
        subscriber,
        callback_contract,
        filter: EventTopicFilter::evm_event(token_contract, transfer_sig),
        max_deliveries: 2,
    };
    let sub_id = must(
        registries.event_bus.subscribe(sub_req),
        "open cross-domain subscription",
    );
    assert!(!registries.event_bus.is_empty());
    assert_ne!(registries.root(), empty_root);

    let raw_payload = b"from=0x01;to=0x02;amount=500000000000000000".to_vec();
    let transfer_event = DomainEvent {
        domain_id: sepolia_domain,
        domain_height: 100,
        event_index: 1,
        kind: DomainEventKind::Custom(b"evm-log".to_vec()),
        emitter: token_contract,
        message: None,
        payload_hash: event_bus_payload_hash(topic0, &raw_payload),
    };
    let filler_event = DomainEvent {
        domain_id: sepolia_domain,
        domain_height: 100,
        event_index: 0,
        kind: DomainEventKind::BridgeLocked,
        emitter: Address::from([0x77; 32]),
        message: None,
        payload_hash: [0x99; 32],
    };

    let mut tree = DomainEventTree::new();
    tree.push(filler_event);
    tree.push(transfer_event.clone());
    let event_root = tree.root();
    let proof = match tree.proof(1) {
        Some(p) => p,
        None => panic!("expected Merkle proof for index 1"),
    };

    must(
        registries
            .commitments
            .insert(finalized_commitment(sepolia_domain, 100, event_root)),
        "commit finalized Sepolia event_root",
    );

    let root_before_delivery = registries.root();
    let delivery = EventDeliveryProof {
        subscription_id: sub_id,
        event: &transfer_event,
        proof: &proof,
        observed_topic0: Some(topic0),
        raw_payload: &raw_payload,
    };
    let invocation = must(
        registries.event_bus.deliver_verified(
            &registries.domains,
            &registries.commitments,
            &delivery,
        ),
        "finalized event delivery succeeds",
    );

    assert_eq!(invocation.subscription_id, sub_id);
    assert_eq!(invocation.source_domain, sepolia_domain);
    assert_eq!(invocation.target_domain, budlum_domain);
    assert_eq!(invocation.callback_contract, callback_contract);
    assert_eq!(invocation.source_height, 100);
    assert_eq!(invocation.event_index, 1);
    assert_eq!(invocation.emitter, token_contract);
    assert_eq!(invocation.raw_payload, raw_payload);
    assert!(registries.event_bus.is_delivered(invocation.delivery_key));
    assert_ne!(registries.root(), root_before_delivery);

    // Exactly-once invariant: replaying the same finalized event is refused.
    let replay_root_before = registries.root();
    assert_eq!(
        registries.event_bus.deliver_verified(
            &registries.domains,
            &registries.commitments,
            &delivery,
        ),
        Err(EventBusError::AlreadyDelivered)
    );
    assert_eq!(registries.root(), replay_root_before);

    // JSON round-trip preserves deterministic root and replay set.
    let encoded = must(serde_json::to_string(&registries.event_bus), "serialize");
    let decoded: budlum_core::cross_domain::UniversalEventBus =
        must(serde_json::from_str(&encoded), "deserialize");
    assert_eq!(decoded.root(), registries.event_bus.root());
    assert!(decoded.is_delivered(invocation.delivery_key));
}

#[test]
fn universal_event_bus_refuses_forged_unattested_frozen_and_budget_exceeded_deliveries() {
    let mut registries = SettlementRegistries::new();
    let sepolia = 11_155_111u32;
    let budlum = 1u32;
    let emitter = Address::from([0xCA; 32]);
    let subscriber = Address::from([0x51; 32]);
    let callback = Address::from([0xCB; 32]);
    let transfer_sig = "Transfer(address,address,uint256)";
    let topic0 = evm_event_topic0(transfer_sig);

    // 1. Invalid subscriptions fail closed without mutating bus state.
    assert!(matches!(
        registries.event_bus.subscribe(EventSubscriptionRequest {
            source_domain: sepolia,
            target_domain: sepolia,
            subscriber,
            callback_contract: callback,
            filter: EventTopicFilter::evm_event(emitter, transfer_sig),
            max_deliveries: 1,
        }),
        Err(EventBusError::InvalidDomainRouting { .. })
    ));
    assert!(matches!(
        registries.event_bus.subscribe(EventSubscriptionRequest {
            source_domain: sepolia,
            target_domain: budlum,
            subscriber: Address::zero(),
            callback_contract: callback,
            filter: EventTopicFilter::evm_event(emitter, transfer_sig),
            max_deliveries: 1,
        }),
        Err(EventBusError::ZeroAddress { .. })
    ));
    assert!(registries.event_bus.is_empty());

    must(
        registries
            .domains
            .restore_persisted(active_sepolia_domain(sepolia)),
        "register sepolia",
    );

    let sub_id = must(
        registries.event_bus.subscribe(EventSubscriptionRequest {
            source_domain: sepolia,
            target_domain: budlum,
            subscriber,
            callback_contract: callback,
            filter: EventTopicFilter::evm_event(emitter, transfer_sig),
            max_deliveries: 1,
        }),
        "subscribe",
    );

    let payload1 = b"transfer-1".to_vec();
    let ev1 = DomainEvent {
        domain_id: sepolia,
        domain_height: 100,
        event_index: 0,
        kind: DomainEventKind::Custom(b"evm-log".to_vec()),
        emitter,
        message: None,
        payload_hash: event_bus_payload_hash(topic0, &payload1),
    };
    let payload2 = b"transfer-2".to_vec();
    let ev2 = DomainEvent {
        domain_id: sepolia,
        domain_height: 100,
        event_index: 1,
        kind: DomainEventKind::Custom(b"evm-log".to_vec()),
        emitter,
        message: None,
        payload_hash: event_bus_payload_hash(topic0, &payload2),
    };
    let mut tree = DomainEventTree::new();
    tree.push(ev1.clone());
    tree.push(ev2.clone());
    let proof1 = match tree.proof(0) {
        Some(p) => p,
        None => panic!("proof 0"),
    };
    let proof2 = match tree.proof(1) {
        Some(p) => p,
        None => panic!("proof 1"),
    };

    // 2. Unattested height refused before commitment exists.
    assert_eq!(
        registries.event_bus.deliver_verified(
            &registries.domains,
            &registries.commitments,
            &EventDeliveryProof {
                subscription_id: sub_id,
                event: &ev1,
                proof: &proof1,
                observed_topic0: Some(topic0),
                raw_payload: &payload1,
            },
        ),
        Err(EventBusError::UnattestedHeight {
            domain_id: sepolia,
            height: 100
        })
    );

    must(
        registries
            .commitments
            .insert(finalized_commitment(sepolia, 100, tree.root())),
        "commit event_root",
    );

    // 3. Forged / tampered Merkle proof refused.
    let mut bad_proof = proof1.clone();
    bad_proof.siblings[0][0] ^= 0xFF;
    assert_eq!(
        registries.event_bus.deliver_verified(
            &registries.domains,
            &registries.commitments,
            &EventDeliveryProof {
                subscription_id: sub_id,
                event: &ev1,
                proof: &bad_proof,
                observed_topic0: Some(topic0),
                raw_payload: &payload1,
            },
        ),
        Err(EventBusError::InvalidMerkleProof)
    );

    // 4. Tampered payload or wrong topic0 refused.
    assert_eq!(
        registries.event_bus.deliver_verified(
            &registries.domains,
            &registries.commitments,
            &EventDeliveryProof {
                subscription_id: sub_id,
                event: &ev1,
                proof: &proof1,
                observed_topic0: Some(topic0),
                raw_payload: b"tampered-payload",
            },
        ),
        Err(EventBusError::PayloadBindingMismatch)
    );
    assert_eq!(
        registries.event_bus.deliver_verified(
            &registries.domains,
            &registries.commitments,
            &EventDeliveryProof {
                subscription_id: sub_id,
                event: &ev1,
                proof: &proof1,
                observed_topic0: Some([0xEE; 32]),
                raw_payload: &payload1,
            },
        ),
        Err(EventBusError::TopicMismatch)
    );

    // 5. Wrong emitter refused.
    let mut wrong_emitter_ev = ev1.clone();
    wrong_emitter_ev.emitter = Address::from([0x99; 32]);
    assert_eq!(
        registries.event_bus.deliver_verified(
            &registries.domains,
            &registries.commitments,
            &EventDeliveryProof {
                subscription_id: sub_id,
                event: &wrong_emitter_ev,
                proof: &proof1,
                observed_topic0: Some(topic0),
                raw_payload: &payload1,
            },
        ),
        Err(EventBusError::EmitterMismatch)
    );

    // 6. Frozen source domain refuses delivery even with valid Merkle proof.
    must(
        registries.domains.set_status(sepolia, DomainStatus::Frozen),
        "freeze domain",
    );
    assert_eq!(
        registries.event_bus.deliver_verified(
            &registries.domains,
            &registries.commitments,
            &EventDeliveryProof {
                subscription_id: sub_id,
                event: &ev1,
                proof: &proof1,
                observed_topic0: Some(topic0),
                raw_payload: &payload1,
            },
        ),
        Err(EventBusError::SourceDomainNotActive { domain_id: sepolia })
    );
    must(
        registries.domains.set_status(sepolia, DomainStatus::Active),
        "reactivate domain",
    );

    // 7. First delivery succeeds; second distinct event exceeds max_deliveries=1.
    must(
        registries.event_bus.deliver_verified(
            &registries.domains,
            &registries.commitments,
            &EventDeliveryProof {
                subscription_id: sub_id,
                event: &ev1,
                proof: &proof1,
                observed_topic0: Some(topic0),
                raw_payload: &payload1,
            },
        ),
        "first delivery succeeds",
    );
    assert_eq!(
        registries.event_bus.deliver_verified(
            &registries.domains,
            &registries.commitments,
            &EventDeliveryProof {
                subscription_id: sub_id,
                event: &ev2,
                proof: &proof2,
                observed_topic0: Some(topic0),
                raw_payload: &payload2,
            },
        ),
        Err(EventBusError::DeliveryBudgetExhausted { max: 1 })
    );

    // 8. Unauthorized cancellation refused; authorized cancellation marks inactive.
    assert_eq!(
        registries
            .event_bus
            .cancel_subscription(sub_id, Address::from([0x77; 32])),
        Err(EventBusError::Unauthorized)
    );
    must(
        registries.event_bus.cancel_subscription(sub_id, subscriber),
        "subscriber cancels",
    );
    assert_eq!(
        registries
            .event_bus
            .get_subscription(sub_id)
            .map(|s| s.active),
        Some(false)
    );
    assert_eq!(
        registries.event_bus.deliver_verified(
            &registries.domains,
            &registries.commitments,
            &EventDeliveryProof {
                subscription_id: sub_id,
                event: &ev2,
                proof: &proof2,
                observed_topic0: Some(topic0),
                raw_payload: &payload2,
            },
        ),
        Err(EventBusError::SubscriptionInactive)
    );
}
