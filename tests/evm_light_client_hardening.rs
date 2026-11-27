//! Regression tests for Ethereum RLP receipt status/log invariants and
//! deposit verification key/emitter/header bounds.

use budlum_core::cross_domain::evm::receipt::{decode_receipt, ReceiptError};
use budlum_core::cross_domain::evm::rlp::{encode, Item};
use budlum_core::cross_domain::evm::verify::{verify_evm_receipt, EvmDepositProof, VerifyError};

#[test]
fn reverted_receipt_never_matches_deposit_log_and_zero_poststate_is_refused() {
    let emitter = vec![0xCC; 20];
    let topic0 = [0xAB; 32];
    let log_item = Item::List(vec![
        Item::String(emitter.clone()),
        Item::List(vec![Item::String(topic0.to_vec())]),
        Item::String(b"forged-deposit".to_vec()),
    ]);
    // Status = empty bytes (EIP-658 reverted/failed tx), yet carrying a log entry.
    let reverted_bytes = encode(&Item::List(vec![
        Item::String(Vec::new()),
        Item::String(Vec::new()),
        Item::String(vec![0u8; 256]),
        Item::List(vec![log_item]),
    ]));
    let receipt = decode_receipt(&reverted_bytes).expect("decodes reverted receipt");
    assert!(!receipt.status);
    assert!(
        receipt.find_log(&emitter, &topic0).is_none(),
        "find_log must never match logs on a reverted (status=false) receipt"
    );
    assert!(
        receipt.find_log_indexed(&emitter, &topic0).is_none(),
        "find_log_indexed must never match logs on a reverted (status=false) receipt"
    );

    // Pre-Byzantium 32-byte postState root that is all-zero [0u8; 32] must be refused.
    let zero_poststate = encode(&Item::List(vec![
        Item::String(vec![0u8; 32]),
        Item::String(Vec::new()),
        Item::String(vec![0u8; 256]),
        Item::List(Vec::new()),
    ]));
    assert_eq!(
        decode_receipt(&zero_poststate),
        Err(ReceiptError::InvalidEnvelope),
        "all-zero 32-byte pre-Byzantium postState root must be refused"
    );
}

#[test]
fn verify_evm_receipt_refuses_noncanonical_receipt_key_and_zero_emitter() {
    let dummy_header = encode(&Item::List(vec![
        Item::String(vec![0x11; 32]),
        Item::String(vec![0x22; 32]),
        Item::String(vec![0x33; 20]),
        Item::String(vec![0x44; 32]),
        Item::String(vec![0x55; 32]),
        Item::String(vec![0x66; 32]),
        Item::String(vec![0u8; 256]),
        Item::String(Vec::new()),
        Item::String(vec![0x01]),
    ]));
    let conf_slice: &[&[u8]] = &[dummy_header.as_slice()];
    let topic0 = [0x99; 32];

    // Non-canonical receipt_key = [0x00] (in RLP, integer 0 is [0x80], never [0x00])
    let bad_key_proof = EvmDepositProof {
        target_header: &dummy_header,
        confirmation_headers: conf_slice,
        required_confirmations: 1,
        proof_nodes: &[],
        receipt_key: &[0x00],
        tx_hash: "0x1234",
        emitter_address: &[0xAA; 20],
        deposit_topic0: &topic0,
        sync_attestation: None,
    };
    let err = verify_evm_receipt(&bad_key_proof, Some(&(1, [0x77; 32])))
        .expect_err("non-canonical receipt_key [0x00] must be refused");
    assert!(
        matches!(err, VerifyError::Receipt(_)),
        "expected Receipt error on non-canonical receipt_key before header/MPT work, got: {err:?}"
    );

    // Zero emitter address [0u8; 20] must be refused up front.
    let zero_emitter_proof = EvmDepositProof {
        receipt_key: &[0x80], // canonical RLP(0)
        emitter_address: &[0u8; 20],
        ..bad_key_proof
    };
    let err = verify_evm_receipt(&zero_emitter_proof, Some(&(1, [0x77; 32])))
        .expect_err("all-zero emitter address must be refused");
    assert!(matches!(err, VerifyError::LogNotFound), "got: {err:?}");
}
