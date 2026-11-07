//! Private transfer submit + AI execution guest skeleton tests.

use crate::ai::execution::{
    build_fixed_point_mlp_guest, input_commitment, program_hash_from_words, FixedPointMlpSpec,
};
use crate::core::account::AccountState;
use crate::core::address::Address;
#[cfg(test)]
fn test_addr_from_byte(byte: u8) -> crate::core::address::Address {
    let mut b = [0u8; 32];
    b[0] = byte;
    crate::core::address::Address::from(b)
}

use crate::core::transaction::{Transaction, TransactionType};
use crate::crypto::primitives::KeyPair;
use crate::execution::executor::Executor;
use crate::privacy::{L1NoteRegistry, PrivateTransferSubmit};
use budlum_note_packing::hash_from_field;

fn funded_state(addr: Address, balance: u64) -> AccountState {
    let mut st = AccountState::new();
    let acc = st.get_or_create(&addr);
    acc.balance = balance;
    st
}

#[test]
fn private_transfer_submit_spend_and_create() {
    let kp = KeyPair::generate().unwrap();
    let from = Address::from(kp.public_key_bytes());
    let mut state = funded_state(from, 1_000_000);

    let c_in = hash_from_field(1);
    let proof = budlum_note_packing::hash_from_field(0xA11CE);
    let n1 = crate::privacy::L1NoteRegistry::derive_nullifier(&c_in, &proof);
    let c_out = hash_from_field(3);
    state.note_registry.insert_note(c_in).unwrap();

    let digest = PrivateTransferSubmit::compute_public_digest(&[n1], &[c_out]);
    let auth_msg = PrivateTransferSubmit::authorization_message(
        crate::core::transaction::DEFAULT_CHAIN_ID,
        from.as_bytes(),
        0,
        &digest,
    );
    let sig = kp.sign(&auth_msg).to_vec();
    let sub = PrivateTransferSubmit {
        spent_commitments: vec![c_in],
        nullifiers: vec![n1],
        output_commitments: vec![c_out],
        nullifier_proofs: vec![budlum_note_packing::hash_from_field(0xA11CE)],
        authorization_sig: sig,
        public_digest: digest,
    };
    assert!(sub.verify_digest_matches());

    let mut tx = Transaction::new_with_chain_id(
        from,
        Address::zero(),
        0,
        100,
        0,
        vec![],
        crate::core::transaction::DEFAULT_CHAIN_ID,
        TransactionType::PrivateTransferSubmit(sub),
    );
    tx.sign(&kp);
    Executor::apply_transaction(&mut state, &tx).expect("apply private transfer");
    assert!(!state.note_registry.contains_commitment(&c_in));
    assert!(state.note_registry.contains_commitment(&c_out));
    assert!(state.note_registry.is_nullifier_spent(&n1));
}

#[test]
fn private_transfer_double_spend_fails() {
    let kp = KeyPair::generate().unwrap();
    let from = Address::from(kp.public_key_bytes());
    let mut state = funded_state(from, 1_000_000);
    let c_in = hash_from_field(9);
    let proof = budlum_note_packing::hash_from_field(0xA11CE);
    let n1 = crate::privacy::L1NoteRegistry::derive_nullifier(&c_in, &proof);
    let c_out = hash_from_field(7);
    state.note_registry.insert_note(c_in).unwrap();
    let digest = PrivateTransferSubmit::compute_public_digest(&[n1], &[c_out]);
    let auth_msg = PrivateTransferSubmit::authorization_message(
        crate::core::transaction::DEFAULT_CHAIN_ID,
        from.as_bytes(),
        0,
        &digest,
    );
    let sub = PrivateTransferSubmit {
        spent_commitments: vec![c_in],
        nullifiers: vec![n1],
        output_commitments: vec![c_out],
        nullifier_proofs: vec![budlum_note_packing::hash_from_field(0xA11CE)],
        authorization_sig: kp.sign(&auth_msg).to_vec(),
        public_digest: digest,
    };
    let mut tx = Transaction::new_with_chain_id(
        from,
        Address::zero(),
        0,
        100,
        0,
        vec![],
        crate::core::transaction::DEFAULT_CHAIN_ID,
        TransactionType::PrivateTransferSubmit(sub.clone()),
    );
    tx.sign(&kp);
    Executor::apply_transaction(&mut state, &tx).unwrap();
    // Reuse nullifier with new note
    let c2 = hash_from_field(6);
    let c_out2 = hash_from_field(5);
    state.note_registry.insert_note(c2).unwrap();
    let digest2 = PrivateTransferSubmit::compute_public_digest(&[n1], &[c_out2]);
    let auth_msg2 = PrivateTransferSubmit::authorization_message(
        crate::core::transaction::DEFAULT_CHAIN_ID,
        from.as_bytes(),
        1,
        &digest2,
    );
    let sub2 = PrivateTransferSubmit {
        spent_commitments: vec![c2],
        nullifiers: vec![n1],
        output_commitments: vec![c_out2],
        nullifier_proofs: vec![budlum_note_packing::hash_from_field(0xA11CE)],
        authorization_sig: kp.sign(&auth_msg2).to_vec(),
        public_digest: digest2,
    };
    let mut tx2 = Transaction::new_with_chain_id(
        from,
        Address::zero(),
        0,
        100,
        1,
        vec![],
        crate::core::transaction::DEFAULT_CHAIN_ID,
        TransactionType::PrivateTransferSubmit(sub2),
    );
    tx2.sign(&kp);
    assert!(Executor::apply_transaction(&mut state, &tx2).is_err());
}

#[test]
fn privacy_note_insert_tx() {
    let kp = KeyPair::generate().unwrap();
    let from = Address::from(kp.public_key_bytes());
    let mut state = funded_state(from, 1_000_000);
    let c = hash_from_field(42);
    let mut tx = Transaction::new_with_chain_id(
        from,
        Address::zero(),
        0,
        50,
        0,
        vec![],
        crate::core::transaction::DEFAULT_CHAIN_ID,
        TransactionType::PrivacyNoteInsert(c),
    );
    tx.sign(&kp);
    Executor::apply_transaction(&mut state, &tx).unwrap();
    assert!(state.note_registry.contains_commitment(&c));
}

#[test]
fn ai_mlp_guest_program_hash_stable() {
    let spec = FixedPointMlpSpec {
        dims: vec![2, 2, 1],
        weights: vec![1, 0, 0, 1, 1, 1],
        biases: vec![0, 0, 0],
    };
    let ic = input_commitment(&[1, 2]);
    let w = build_fixed_point_mlp_guest(&spec, &ic).unwrap();
    let h1 = program_hash_from_words(&w);
    let h2 = program_hash_from_words(&w);
    assert_eq!(h1, h2);
    assert_ne!(h1, [0u8; 32]);

    // Different weights give a different program, so a different hash.
    let other = FixedPointMlpSpec {
        dims: vec![2, 2, 1],
        weights: vec![1, 0, 0, 1, 1, 2],
        biases: vec![0, 0, 0],
    };
    let w_other = build_fixed_point_mlp_guest(&other, &ic).unwrap();
    assert_ne!(h1, program_hash_from_words(&w_other));
}

#[test]
fn l1_note_registry_root_changes() {
    let mut r = L1NoteRegistry::new();
    let a = r.state_root();
    r.insert_note([1u8; 32]).unwrap();
    assert_ne!(a, r.state_root());
}

#[test]
fn ai_mlp_host_eval_and_commitments() {
    use crate::ai::execution::{
        eval_fixed_point_mlp, input_commitment, output_commitment, FixedPointMlpSpec,
    };
    let spec = FixedPointMlpSpec {
        dims: vec![2, 1],
        weights: vec![2, 3],
        biases: vec![1],
    };
    let y = eval_fixed_point_mlp(&spec, &[4, 5]).unwrap();
    assert_eq!(y, vec![2 * 4 + 3 * 5 + 1]);
    assert_ne!(input_commitment(&[4, 5]), output_commitment(&y));
}

#[test]
fn ai_require_execution_proof_blocks_finalize_without_proof() {
    use crate::ai::registry::AiRegistry;
    use crate::ai::types::*;

    let owner = test_addr_from_byte(1u8);
    let verifier = test_addr_from_byte(2u8);
    let mut reg = AiRegistry::new();
    let mid = AiModelId::of(&owner, &[9u8; 32], 1);
    let err = reg
        .register_model(AiModelSpec {
            model_id: mid,
            model_hash: [9u8; 32],
            owner,
            min_verifier_count: 1,
            agreement_threshold: 1,
            max_input_ref_bytes: 1024,
            max_output_ref_bytes: 1024,
            request_deadline_blocks: 100,
            result_deadline_blocks: 100,
            version: 1,
            active: true,
            require_execution_proof: true,
            execution_program_hash: Some([7u8; 32]),
            execution_class: 1,
            execution_dims: None,
            execution_weights_digest: Some([11u8; 32]),
            modalities: crate::ai_inference::perception::ModalitySet::text_only(),
        })
        .expect_err(
            "F-04: proof-required models cannot register while STARK verification is not live",
        );
    assert!(
        err.contains("full AI STARK"),
        "registration must name the missing verifier, got {err}"
    );
    let _ = verifier;
}

fn transfer_fixture(
    kp: &KeyPair,
    state: &mut AccountState,
) -> (PrivateTransferSubmit, [u8; 32], [u8; 32]) {
    let c_in = hash_from_field(21);
    let proof = hash_from_field(0xA11CE);
    let n1 = L1NoteRegistry::derive_nullifier(&c_in, &proof);
    let c_out = hash_from_field(23);
    state.note_registry.insert_note(c_in).unwrap();
    let digest = PrivateTransferSubmit::compute_public_digest(&[n1], &[c_out]);
    let from = Address::from(kp.public_key_bytes());
    let auth_msg = PrivateTransferSubmit::authorization_message(
        crate::core::transaction::DEFAULT_CHAIN_ID,
        from.as_bytes(),
        0,
        &digest,
    );
    let sub = PrivateTransferSubmit {
        spent_commitments: vec![c_in],
        nullifiers: vec![n1],
        output_commitments: vec![c_out],
        nullifier_proofs: vec![proof],
        authorization_sig: kp.sign(&auth_msg).to_vec(),
        public_digest: digest,
    };
    (sub, c_in, c_out)
}

fn signed_tx(kp: &KeyPair, chain_id: u64, tx_type: TransactionType) -> Transaction {
    let from = Address::from(kp.public_key_bytes());
    let mut tx =
        Transaction::new_with_chain_id(from, Address::zero(), 0, 100, 0, vec![], chain_id, tx_type);
    tx.sign(kp);
    tx
}

#[test]
fn private_transfer_is_refused_on_mainnet_and_unknown_chain_ids() {
    use crate::core::chain_config::Network;
    for chain_id in [Network::Mainnet.chain_id().value(), 999_999] {
        let kp = KeyPair::generate().unwrap();
        let from = Address::from(kp.public_key_bytes());
        let mut state = funded_state(from, 1_000_000);
        let (sub, c_in, c_out) = transfer_fixture(&kp, &mut state);
        let tx = signed_tx(&kp, chain_id, TransactionType::PrivateTransferSubmit(sub));
        let err = Executor::apply_transaction(&mut state, &tx)
            .expect_err("the privacy gate must refuse this chain id");
        assert!(err.contains("disabled on mainnet"), "got: {err}");
        assert!(state.note_registry.contains_commitment(&c_in));
        assert!(!state.note_registry.contains_commitment(&c_out));
    }
}

#[test]
fn privacy_note_insert_is_refused_on_mainnet_and_unknown_chain_ids() {
    use crate::core::chain_config::Network;
    for chain_id in [Network::Mainnet.chain_id().value(), 999_999] {
        let kp = KeyPair::generate().unwrap();
        let from = Address::from(kp.public_key_bytes());
        let mut state = funded_state(from, 1_000_000);
        let c = hash_from_field(42);
        let tx = signed_tx(&kp, chain_id, TransactionType::PrivacyNoteInsert(c));
        let err = Executor::apply_transaction(&mut state, &tx)
            .expect_err("the privacy gate must refuse this chain id");
        assert!(err.contains("disabled on mainnet"), "got: {err}");
        assert!(!state.note_registry.contains_commitment(&c));
    }
}

#[test]
fn private_transfer_with_a_bad_authorization_signature_is_refused() {
    let kp = KeyPair::generate().unwrap();
    let other = KeyPair::generate().unwrap();
    let from = Address::from(kp.public_key_bytes());
    let mut state = funded_state(from, 1_000_000);
    let (mut sub, c_in, _) = transfer_fixture(&kp, &mut state);
    sub.authorization_sig = other.sign(&sub.public_digest).to_vec();
    let tx = signed_tx(
        &kp,
        crate::core::transaction::DEFAULT_CHAIN_ID,
        TransactionType::PrivateTransferSubmit(sub),
    );
    let err = Executor::apply_transaction(&mut state, &tx).expect_err("a foreign signature");
    assert!(err.contains("authorization_sig invalid"), "got: {err}");
    assert!(state.note_registry.contains_commitment(&c_in));
}

#[test]
fn private_transfer_with_a_mismatched_public_digest_is_refused() {
    let kp = KeyPair::generate().unwrap();
    let from = Address::from(kp.public_key_bytes());
    let mut state = funded_state(from, 1_000_000);
    let (mut sub, c_in, _) = transfer_fixture(&kp, &mut state);
    sub.public_digest[0] ^= 0xFF;
    sub.authorization_sig = kp.sign(&sub.public_digest).to_vec();
    let tx = signed_tx(
        &kp,
        crate::core::transaction::DEFAULT_CHAIN_ID,
        TransactionType::PrivateTransferSubmit(sub),
    );
    let err = Executor::apply_transaction(&mut state, &tx).expect_err("a digest mismatch");
    assert!(err.contains("public_digest does not match"), "got: {err}");
    assert!(state.note_registry.contains_commitment(&c_in));
}

#[test]
fn private_transfer_spending_an_unregistered_commitment_is_refused() {
    let kp = KeyPair::generate().unwrap();
    let from = Address::from(kp.public_key_bytes());
    let mut state = funded_state(from, 1_000_000);
    let (sub, c_in, c_out) = transfer_fixture(&kp, &mut state);
    state.note_registry = L1NoteRegistry::default();
    let tx = signed_tx(
        &kp,
        crate::core::transaction::DEFAULT_CHAIN_ID,
        TransactionType::PrivateTransferSubmit(sub),
    );
    assert!(Executor::apply_transaction(&mut state, &tx).is_err());
    assert!(!state.note_registry.contains_commitment(&c_in));
    assert!(!state.note_registry.contains_commitment(&c_out));
}

#[test]
fn private_transfer_replayed_under_another_nonce_or_bare_digest_is_refused() {
    let kp = KeyPair::generate().unwrap();
    let from = Address::from(kp.public_key_bytes());
    let mut state = funded_state(from, 1_000_000);
    let (mut bare_sub, c_in, _) = transfer_fixture(&kp, &mut state);
    // Signing only the bare `public_digest` (V1 preimage) must be rejected now
    // that the executor enforces `authorization_message(chain_id, sender, nonce, digest)`.
    bare_sub.authorization_sig = kp.sign(&bare_sub.public_digest).to_vec();
    let bare_tx = signed_tx(
        &kp,
        crate::core::transaction::DEFAULT_CHAIN_ID,
        TransactionType::PrivateTransferSubmit(bare_sub.clone()),
    );
    let err = Executor::apply_transaction(&mut state, &bare_tx)
        .expect_err("bare public_digest signature must be rejected");
    assert!(err.contains("authorization_sig invalid"), "got: {err}");

    // Replaying an intent signed for nonce 0 at nonce 1 must also be rejected.
    state.get_or_create(&from).nonce = 1;
    let valid_nonce_zero = PrivateTransferSubmit::authorization_message(
        crate::core::transaction::DEFAULT_CHAIN_ID,
        from.as_bytes(),
        0,
        &bare_sub.public_digest,
    );
    bare_sub.authorization_sig = kp.sign(&valid_nonce_zero).to_vec();
    let mut replayed_tx = Transaction::new_with_chain_id(
        from,
        Address::zero(),
        0,
        100,
        1,
        vec![],
        crate::core::transaction::DEFAULT_CHAIN_ID,
        TransactionType::PrivateTransferSubmit(bare_sub),
    );
    replayed_tx.sign(&kp);
    let err = Executor::apply_transaction(&mut state, &replayed_tx)
        .expect_err("nonce-0 authorization replayed at nonce 1 must be rejected");
    assert!(err.contains("authorization_sig invalid"), "got: {err}");
    assert!(state.note_registry.contains_commitment(&c_in));
}

/// Testnet (`45261`) is a public network: the privacy note surface stays
/// closed there until ownership, value-conservation and membership proofs are
/// wired. The gate is the executor's, so a signed, well-formed
/// transaction is refused before any arm runs.
#[test]
fn private_transfer_is_closed_on_testnet() {
    use crate::core::chain_config::Network;
    let testnet = Network::Testnet.chain_id().value();
    let kp = KeyPair::generate().unwrap();
    let from = Address::from(kp.public_key_bytes());
    let mut state = funded_state(from, 1_000_000);
    let (sub, c_in, c_out) = transfer_fixture(&kp, &mut state);
    let tx = signed_tx(&kp, testnet, TransactionType::PrivateTransferSubmit(sub));
    let err = crate::execution::executor::Executor::apply_transaction_checked(&mut state, &tx)
        .expect_err("testnet must refuse the privacy surface");
    match err {
        crate::error::BudlumError::Validation { code, .. } => {
            assert_eq!(code, "privacy_testnet_closed");
        }
        other => panic!("expected a validation refusal, got {other:?}"),
    }
    assert!(state.note_registry.contains_commitment(&c_in));
    assert!(!state.note_registry.contains_commitment(&c_out));
}

/// The note registry is the other half of the same surface: insertion is
/// refused on testnet for the same reason.
#[test]
fn note_registry_is_closed_on_testnet() {
    use crate::core::chain_config::Network;
    let testnet = Network::Testnet.chain_id().value();
    let kp = KeyPair::generate().unwrap();
    let from = Address::from(kp.public_key_bytes());
    let mut state = funded_state(from, 1_000_000);
    let c = hash_from_field(77);
    let tx = signed_tx(&kp, testnet, TransactionType::PrivacyNoteInsert(c));
    let err = crate::execution::executor::Executor::apply_transaction_checked(&mut state, &tx)
        .expect_err("testnet must refuse note insertion");
    match err {
        crate::error::BudlumError::Validation { code, .. } => {
            assert_eq!(code, "privacy_testnet_closed");
        }
        other => panic!("expected a validation refusal, got {other:?}"),
    }
    assert!(!state.note_registry.contains_commitment(&c));
}

/// AI execution proofs are closed on testnet while full STARK verification
/// and the public-layer prerequisites are not live. The refusal must come
/// from the layer gate, before the
/// attach arm inspects the proof envelope.
#[test]
fn ai_execution_proof_is_closed_on_testnet() {
    use crate::core::chain_config::Network;
    let testnet = Network::Testnet.chain_id().value();
    let kp = KeyPair::generate().unwrap();
    let from = Address::from(kp.public_key_bytes());
    let mut state = funded_state(from, 1_000_000);
    let proof = crate::ai::types::AiExecutionProof {
        model_id: crate::ai::types::AiModelId::new([7u8; 32]),
        input_commitment: [1u8; 32],
        output_commitment: [2u8; 32],
        program_hash: [3u8; 32],
        proof_bytes: vec![0xAB; 16],
        steps: 1,
        gas_used: 1,
        weights_digest: None,
        public_inputs: None,
    };
    let tx = signed_tx(
        &kp,
        testnet,
        TransactionType::AiAttachExecutionProof {
            request_id: crate::ai::types::AiRequestId::new([9u8; 32]),
            proof,
        },
    );
    let err = crate::execution::executor::Executor::apply_transaction_checked(&mut state, &tx)
        .expect_err("testnet must refuse AI execution proofs");
    match err {
        crate::error::BudlumError::Validation { code, .. } => {
            assert_eq!(code, "ai_layer_testnet_closed");
        }
        other => panic!("expected a validation refusal, got {other:?}"),
    }
}

/// Entry to the on-chain AI verification layer is closed on testnet:
/// every entry variant in this fixture is refused with the layer's code,
/// while devnet - the proving ground - is not refused by the gate.
#[test]
fn ai_layer_is_closed_on_testnet() {
    use crate::core::chain_config::Network;
    let testnet = Network::Testnet.chain_id().value();
    let devnet = Network::Devnet.chain_id().value();
    let kp = KeyPair::generate().unwrap();
    let from = Address::from(kp.public_key_bytes());

    let cases: Vec<TransactionType> = vec![
        TransactionType::AiOperatorBond,
        TransactionType::AiModelDeactivate(crate::ai::types::AiModelId::new([7u8; 32])),
        TransactionType::AiModelReactivate(crate::ai::types::AiModelId::new([7u8; 32])),
    ];

    for tx_type in cases {
        let label = format!("{tx_type:?}");
        let mut state = funded_state(from, 1_000_000);
        let tx = signed_tx(&kp, testnet, tx_type);
        let err = crate::execution::executor::Executor::apply_transaction_checked(&mut state, &tx)
            .expect_err("testnet must refuse the AI layer");
        match err {
            crate::error::BudlumError::Validation { code, .. } => {
                assert_eq!(code, "ai_layer_testnet_closed", "case {label}");
            }
            other => panic!("case {label}: expected a validation refusal, got {other:?}"),
        }
    }

    // Devnet is the proving ground: the gate must not refuse there. The arm
    // itself may still refuse (bond rules, escrow rules), but never with the
    // layer's code.
    let mut state = funded_state(from, 1_000_000);
    let tx = signed_tx(&kp, devnet, TransactionType::AiOperatorBond);
    if let Err(err) =
        crate::execution::executor::Executor::apply_transaction_checked(&mut state, &tx)
    {
        match err {
            crate::error::BudlumError::Validation { code, .. } => {
                assert_ne!(code, "ai_layer_testnet_closed");
            }
            _ => {}
        }
    }
}
