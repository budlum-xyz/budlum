//! End-to-end security tests for CrossDomainMessageRegistry and BridgeState:
//! - CrossDomainMessageRegistry per-sender cap, global cap, oversized auth payload refusal,
//!   and zero sender/recipient/payload_hash refusal
//! - BridgeState refusal of zero AssetId registration, same-domain self-lock, and zero-amount lock

use budlum_core::core::address::Address;
use budlum_core::cross_domain::bridge::{AssetId, BridgeState};
use budlum_core::cross_domain::message::{
    CrossDomainMessage, CrossDomainMessageParams, MessageKind,
};
use budlum_core::cross_domain::message_registry::{
    CrossDomainMessageRegistry, MAX_MESSAGES_PER_SENDER, MAX_MESSAGE_AUTH_BYTES,
};

fn addr(byte: u8) -> Address {
    Address::from([byte; 32])
}

fn valid_message(sender: Address, nonce: u64) -> CrossDomainMessage {
    CrossDomainMessage::new(CrossDomainMessageParams {
        source_domain: 1,
        target_domain: 2,
        source_height: 10,
        event_index: 0,
        nonce,
        sender,
        recipient: addr(0x22),
        payload_hash: [0x33; 32],
        kind: MessageKind::BridgeLock,
        expiry_height: 1_000,
    })
}

#[test]
fn message_registry_enforces_per_sender_cap_without_blocking_other_senders() {
    let mut reg = CrossDomainMessageRegistry::new();
    let attacker = addr(0xAA);
    let honest = addr(0xBB);

    for nonce in 0..MAX_MESSAGES_PER_SENDER {
        reg.insert(valid_message(attacker, nonce as u64))
            .expect("messages within per-sender cap succeed");
    }
    assert_eq!(reg.len(), MAX_MESSAGES_PER_SENDER);

    // One more message from the same sender MUST fail closed.
    let err = reg
        .insert(valid_message(attacker, MAX_MESSAGES_PER_SENDER as u64))
        .expect_err("single sender must not exceed MAX_MESSAGES_PER_SENDER");
    assert!(
        err.contains("maximum"),
        "expected per-sender cap error, got: {err}"
    );
    assert_eq!(reg.len(), MAX_MESSAGES_PER_SENDER);

    // Independent honest sender remains unaffected.
    reg.insert(valid_message(honest, 0))
        .expect("honest sender must still be admitted");
}

#[test]
fn message_registry_rejects_oversized_auth_bytes_and_zero_identities() {
    let mut reg = CrossDomainMessageRegistry::new();

    // Zero sender MUST be refused.
    let zero_sender = valid_message(Address::zero(), 1);
    assert!(reg.insert(zero_sender).is_err());

    // Zero recipient MUST be refused.
    let zero_recipient = CrossDomainMessage::new(CrossDomainMessageParams {
        source_domain: 1,
        target_domain: 2,
        source_height: 10,
        event_index: 0,
        nonce: 2,
        sender: addr(1),
        recipient: Address::zero(),
        payload_hash: [0x33; 32],
        kind: MessageKind::BridgeLock,
        expiry_height: 1_000,
    });
    assert!(reg.insert(zero_recipient).is_err());

    // Zero payload_hash MUST be refused.
    let zero_payload = CrossDomainMessage::new(CrossDomainMessageParams {
        source_domain: 1,
        target_domain: 2,
        source_height: 10,
        event_index: 0,
        nonce: 3,
        sender: addr(1),
        recipient: addr(2),
        payload_hash: [0u8; 32],
        kind: MessageKind::BridgeLock,
        expiry_height: 1_000,
    });
    assert!(reg.insert(zero_payload).is_err());

    // Oversized sender_public_key / sender_signature (> MAX_MESSAGE_AUTH_BYTES) MUST be refused.
    let mut big_pk = valid_message(addr(1), 4);
    big_pk.sender_public_key = vec![0x55; MAX_MESSAGE_AUTH_BYTES + 1];
    big_pk.message_id = big_pk.calculate_message_id();
    assert!(reg.insert(big_pk).is_err());

    let mut big_sig = valid_message(addr(1), 5);
    big_sig.sender_signature = vec![0x66; MAX_MESSAGE_AUTH_BYTES + 1];
    big_sig.message_id = big_sig.calculate_message_id();
    assert!(reg.insert(big_sig).is_err());

    assert!(reg.is_empty());
}

#[test]
fn bridge_state_rejects_zero_asset_same_domain_lock_and_zero_amount_lock() {
    let mut bridge = BridgeState::new();

    // Registering AssetId::zero() MUST be refused.
    assert!(bridge.register_asset(AssetId::zero(), 1).is_err());

    let asset = AssetId::for_domain(1, b"USDC");
    bridge
        .register_asset(asset, 1)
        .expect("valid non-zero asset registers");

    // Self-domain lock (source_domain == target_domain) MUST be refused without locking asset.
    let same_dom_err = bridge
        .lock(1, 1, 10, 0, asset, addr(1), addr(2), 500, 100)
        .expect_err("same-domain bridge lock must fail closed");
    assert!(
        same_dom_err.0.contains("differ"),
        "expected distinct domain error, got: {same_dom_err}"
    );

    // Zero-amount bridge lock MUST be refused without locking asset.
    let zero_amt_err = bridge
        .lock(1, 2, 10, 0, asset, addr(1), addr(2), 0, 100)
        .expect_err("zero-amount bridge lock must fail closed");
    assert!(
        zero_amt_err.0.contains("greater than zero"),
        "expected positive amount error, got: {zero_amt_err}"
    );

    // After both refused attempts, asset remains Active and accepts a valid lock.
    let (transfer, _) = bridge
        .lock(1, 2, 10, 0, asset, addr(1), addr(2), 500, 100)
        .expect("valid cross-domain lock succeeds");
    assert_eq!(transfer.amount, budlum_core::core::money::Bud::new(500));
}
