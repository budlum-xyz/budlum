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
fn private_transfer_with_composite_authorization_executes() {
    use crate::crypto::ctx::PRIVATE_TRANSFER_V1;
    use crate::crypto::key_derivation::RootSecret;

    let account = RootSecret::derive(&[7u8; 32], "")
        .unwrap()
        .user_account(0, 0)
        .unwrap();
    let from = Address::from(account.address);
    let mut state = funded_state(from, 1_000_000);
    let chain_id = crate::core::transaction::DEFAULT_CHAIN_ID;
    let commitment = hash_from_field(101);
    let proof = hash_from_field(0xA11CE);
    let nullifier = L1NoteRegistry::derive_nullifier(&commitment, &proof);
    let output = hash_from_field(103);
    state
        .note_registry
        .insert_note_for_owner(commitment, from)
        .unwrap();

    let digest = PrivateTransferSubmit::compute_public_digest(&[nullifier], &[output]);
    let auth_message =
        PrivateTransferSubmit::authorization_message(chain_id, from.as_bytes(), 0, &digest);
    let authorization_sig = account
        .signing
        .sign_in(
            &state.scheme_registry,
            PRIVATE_TRANSFER_V1,
            &auth_message,
            &[4u8; 32],
        )
        .unwrap()
        .encode();
    let submit = PrivateTransferSubmit {
        spent_commitments: vec![commitment],
        nullifiers: vec![nullifier],
        output_commitments: vec![output],
        nullifier_proofs: vec![proof],
        authorization_sig,
        public_digest: digest,
    };

    let mut tx = Transaction::new_with_chain_id(
        from,
        Address::zero(),
        0,
        100,
        0,
        vec![],
        chain_id,
        TransactionType::PrivateTransferSubmit(submit),
    );
    tx.sign_v7(
        &state.scheme_registry,
        &account.signing,
        &account.recovery_public_key,
        &[5u8; 32],
    )
    .unwrap();

    assert!(tx.verify_in(&state.scheme_registry));
    Executor::apply_transaction(&mut state, &tx).expect("composite-authorized transfer");
    assert!(!state.note_registry.contains_commitment(&commitment));
    assert!(state.note_registry.contains_commitment(&output));
    assert!(state.note_registry.is_nullifier_spent(&nullifier));
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
    state
        .note_registry
        .insert_note_for_owner(c_in, from)
        .unwrap();

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
    state
        .note_registry
        .insert_note_for_owner(c_in, from)
        .unwrap();
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
    state.note_registry.insert_note_for_owner(c2, from).unwrap();
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
fn testnet_privacy_precheck_reports_closed_feature() {
    use crate::chain::blockchain::Blockchain;
    use crate::consensus::pow::PoWEngine;
    use crate::core::chain_config::Network;
    use std::sync::Arc;

    let keypair = KeyPair::generate().unwrap();
    let from = Address::from(keypair.public_key_bytes());
    let chain_id = Network::Mainnet.chain_id().value();
    let mut chain = Blockchain::new(Arc::new(PoWEngine::new(1)), None, chain_id, None);
    chain.state.add_balance(&from, 1_000_000);

    let tx = signed_tx(
        &keypair,
        chain_id,
        TransactionType::PrivacyNoteInsert(hash_from_field(42)),
    );
    let precheck = chain.tx_precheck(&tx);

    assert_eq!(precheck["accepted"], false);
    assert!(precheck["reasons"].as_array().is_some_and(|reasons| {
        reasons.iter().any(|reason| {
            reason == "privacy_mainnet_disabled"
                || reason == "privacy_testnet_closed"
                || reason == "privacy_disabled"
        })
    }));
    assert!(chain.mempool.is_empty());
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
    r.insert_note_for_owner([1u8; 32], crate::core::address::Address::zero())
        .unwrap();
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
    use crate::ai::execution::{matmul_program_hash, weights_digest, FixedPointMlpSpec};
    use crate::ai::registry::{AiRegistry, MIN_VERIFIER_STAKE};
    use crate::ai::types::*;

    let owner = test_addr_from_byte(1u8);
    let verifier = test_addr_from_byte(2u8);
    let mut reg = AiRegistry::new();
    let spec_mlp = FixedPointMlpSpec {
        dims: vec![2, 1],
        weights: vec![2, 3],
        biases: vec![1],
    };
    let mid = AiModelId::of(&owner, &[9u8; 32], 1);
    reg.register_model(AiModelSpec {
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
        execution_program_hash: Some(matmul_program_hash(&spec_mlp).unwrap()),
        execution_class: 1,
        execution_dims: Some(spec_mlp.dims.clone()),
        execution_weights_digest: Some(weights_digest(&spec_mlp)),
        modalities: crate::ai_inference::perception::ModalitySet::text_only(),
    })
    .expect("proof-required model registers cleanly when FULL_AI_STARK_VERIFICATION_LIVE is true");

    reg.lock_verifier_stake(&verifier, MIN_VERIFIER_STAKE)
        .unwrap();
    let mut req = AiInferenceRequest {
        request_id: AiRequestId::default(),
        requester: owner,
        model_id: mid,
        // This test submits no proof. Its empty input ref still needs the
        // canonical request commitment; the guest-only limb commitment is a
        // different scheme and cannot authenticate a request's input_ref.
        input_commitment: crate::ai::types::canonical_input_commitment(&[]),
        input_ref: BoundedBytes::empty(),
        max_fee: 10,
        callback: None,
        submitted_at_block: 0,
        deadline_block: 100,
        perception: Some(crate::ai_inference::perception::PerceptionRequest {
            asset_id: crate::pollen::AssetId([0xAA; 32]),
            content_id: crate::storage::content_id::ContentId([0xBB; 32]),
            kind: crate::ai_inference::perception::PerceptionKind::Text,
            declared_units: 4,
        }),
        effort: crate::ai_inference::effort::EffortTier::default(),
    };
    req.request_id = req.calculate_id();
    let req_id = reg.submit_request(req, 0).unwrap();

    let res = AiInferenceResult {
        request_id: req_id,
        verifier,
        output_commitment: crate::ai::types::canonical_output_commitment(&[23]),
        output_ref: BoundedBytes::try_new(vec![23]).unwrap(),
        result_nonce: 1,
        signature: Vec::new(),
        submitted_at_block: 0,
    };
    let outcome = reg.submit_result(res, 0).unwrap();
    assert!(
        outcome.is_none(),
        "proof-required model must block finalization before verified STARK proof attach"
    );
    assert!(reg.try_finalize_with_proofs(&req_id).is_none());
}

fn transfer_fixture(
    kp: &KeyPair,
    state: &mut AccountState,
) -> (PrivateTransferSubmit, [u8; 32], [u8; 32]) {
    let c_in = hash_from_field(21);
    let proof = hash_from_field(0xA11CE);
    let n1 = L1NoteRegistry::derive_nullifier(&c_in, &proof);
    let c_out = hash_from_field(23);
    let from = Address::from(kp.public_key_bytes());
    state
        .note_registry
        .insert_note_for_owner(c_in, from)
        .unwrap();
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
fn private_transfer_admission_and_execution_are_closed_on_public_chains() {
    use crate::core::chain_config::Network;
    use crate::crypto::ctx::PRIVATE_TRANSFER_V1;
    use crate::crypto::key_derivation::RootSecret;
    let account = RootSecret::derive(&[7u8; 32], "")
        .unwrap()
        .user_account(0, 0)
        .unwrap();
    let from = Address::from(account.address);
    for chain_id in [Network::Mainnet.chain_id().value(), 999_999] {
        let mut state = funded_state(from, 1_000_000);
        let c_in = hash_from_field(21);
        let proof = hash_from_field(0xA11CE);
        let n1 = L1NoteRegistry::derive_nullifier(&c_in, &proof);
        let c_out = hash_from_field(23);
        state
            .note_registry
            .insert_note_for_owner(c_in, from)
            .unwrap();
        let digest = PrivateTransferSubmit::compute_public_digest(&[n1], &[c_out]);
        let auth_msg =
            PrivateTransferSubmit::authorization_message(chain_id, from.as_bytes(), 0, &digest);
        let authorization_sig = account
            .signing
            .sign_in(
                &state.scheme_registry,
                PRIVATE_TRANSFER_V1,
                &auth_msg,
                &[4u8; 32],
            )
            .unwrap()
            .encode();
        let sub = PrivateTransferSubmit {
            spent_commitments: vec![c_in],
            nullifiers: vec![n1],
            output_commitments: vec![c_out],
            nullifier_proofs: vec![proof],
            authorization_sig,
            public_digest: digest,
        };
        let mut tx = Transaction::new_with_chain_id(
            from,
            Address::zero(),
            0,
            100,
            0,
            vec![],
            chain_id,
            TransactionType::PrivateTransferSubmit(sub),
        );
        tx.sign_v7(
            &state.scheme_registry,
            &account.signing,
            &account.recovery_public_key,
            &[5u8; 32],
        )
        .unwrap();
        let validation_error = state
            .validate_transaction(&tx)
            .expect_err("the transaction admission gate must refuse this chain id");
        assert!(validation_error.contains("transfers are disabled"));
        let err = Executor::apply_transaction(&mut state, &tx)
            .expect_err("the execution gate must refuse this chain id");
        assert!(
            err.contains("closed on") || err.contains("disabled on mainnet"),
            "got: {err}"
        );
        assert!(state.note_registry.contains_commitment(&c_in));
        assert!(!state.note_registry.contains_commitment(&c_out));
    }
}

#[test]
fn note_insert_admission_and_execution_are_closed_on_public_chains() {
    use crate::core::chain_config::Network;
    use crate::crypto::key_derivation::RootSecret;
    let account = RootSecret::derive(&[7u8; 32], "")
        .unwrap()
        .user_account(0, 0)
        .unwrap();
    let from = Address::from(account.address);
    for chain_id in [Network::Mainnet.chain_id().value(), 999_999] {
        let mut state = funded_state(from, 1_000_000);
        let c = hash_from_field(42);
        let mut tx = Transaction::new_with_chain_id(
            from,
            Address::zero(),
            0,
            100,
            0,
            vec![],
            chain_id,
            TransactionType::PrivacyNoteInsert(c),
        );
        tx.sign_v7(
            &state.scheme_registry,
            &account.signing,
            &account.recovery_public_key,
            &[5u8; 32],
        )
        .unwrap();
        let validation_error = state
            .validate_transaction(&tx)
            .expect_err("the transaction admission gate must refuse this chain id");
        assert!(validation_error.contains("transfers are disabled"));
        let err = Executor::apply_transaction(&mut state, &tx)
            .expect_err("the execution gate must refuse this chain id");
        assert!(
            err.contains("closed on") || err.contains("disabled on mainnet"),
            "got: {err}"
        );
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

/// Testnet (`45261`) executes private transfers with authorization and
/// ownership checks; Mainnet (`45260`) keeps the legacy boundary closed.
#[test]
fn private_transfer_is_open_on_testnet() {
    use crate::core::chain_config::Network;
    let mainnet = Network::Mainnet.chain_id().value();
    let testnet = Network::Testnet.chain_id().value();
    let kp = KeyPair::generate().unwrap();
    let from = Address::from(kp.public_key_bytes());
    let mut state = funded_state(from, 1_000_000);
    let c_in = hash_from_field(11);
    let proof = hash_from_field(0xA11CE);
    let n1 = L1NoteRegistry::derive_nullifier(&c_in, &proof);
    let c_out = hash_from_field(12);
    state
        .note_registry
        .insert_note_for_owner(c_in, from)
        .unwrap();
    let digest = PrivateTransferSubmit::compute_public_digest(&[n1], &[c_out]);
    let auth_msg =
        PrivateTransferSubmit::authorization_message(testnet, from.as_bytes(), 0, &digest);
    let sub = PrivateTransferSubmit {
        spent_commitments: vec![c_in],
        nullifiers: vec![n1],
        output_commitments: vec![c_out],
        nullifier_proofs: vec![proof],
        authorization_sig: kp.sign(&auth_msg).to_vec(),
        public_digest: digest,
    };
    let tx_testnet = signed_tx(
        &kp,
        testnet,
        TransactionType::PrivateTransferSubmit(sub.clone()),
    );
    crate::execution::executor::Executor::apply_transaction_checked(&mut state, &tx_testnet)
        .expect("testnet 45261 executes private transfers");
    assert!(!state.note_registry.contains_commitment(&c_in));
    assert!(state.note_registry.contains_commitment(&c_out));

    let tx_mainnet = signed_tx(&kp, mainnet, TransactionType::PrivateTransferSubmit(sub));
    let err =
        crate::execution::executor::Executor::apply_transaction_checked(&mut state, &tx_mainnet)
            .expect_err("mainnet must keep the legacy privacy surface closed");
    match err {
        crate::error::BudlumError::Validation { code, .. } => {
            assert_eq!(code, "privacy_mainnet_disabled");
        }
        other => panic!("expected a validation refusal, got {other:?}"),
    }
}

/// Note insertion executes on testnet (`45261`) and remains refused on mainnet (`45260`).
#[test]
fn note_registry_is_open_on_testnet() {
    use crate::core::chain_config::Network;
    let mainnet = Network::Mainnet.chain_id().value();
    let testnet = Network::Testnet.chain_id().value();
    let kp = KeyPair::generate().unwrap();
    let from = Address::from(kp.public_key_bytes());
    let mut state = funded_state(from, 1_000_000);
    let c = hash_from_field(77);
    let tx_testnet = signed_tx(&kp, testnet, TransactionType::PrivacyNoteInsert(c));
    crate::execution::executor::Executor::apply_transaction_checked(&mut state, &tx_testnet)
        .expect("testnet accepts note insertion");
    assert!(state.note_registry.contains_commitment(&c));

    let c_main = hash_from_field(78);
    let tx_mainnet = signed_tx(&kp, mainnet, TransactionType::PrivacyNoteInsert(c_main));
    let err =
        crate::execution::executor::Executor::apply_transaction_checked(&mut state, &tx_mainnet)
            .expect_err("mainnet must refuse note insertion");
    match err {
        crate::error::BudlumError::Validation { code, .. } => {
            assert_eq!(code, "privacy_mainnet_disabled");
        }
        other => panic!("expected a validation refusal, got {other:?}"),
    }
    assert!(!state.note_registry.contains_commitment(&c_main));
}

/// AI execution proofs are open on testnet (`45261`) and gated on mainnet (`45260`).
#[test]
fn ai_execution_proof_is_open_on_testnet() {
    use crate::core::chain_config::Network;
    let mainnet = Network::Mainnet.chain_id().value();
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
    let tx_testnet = signed_tx(
        &kp,
        testnet,
        TransactionType::AiAttachExecutionProof {
            request_id: crate::ai::types::AiRequestId::new([9u8; 32]),
            proof: proof.clone(),
        },
    );
    let err_testnet =
        crate::execution::executor::Executor::apply_transaction_checked(&mut state, &tx_testnet)
            .expect_err("unknown request must fail request lookup, not layer gate");
    if let crate::error::BudlumError::Validation { code, .. } = err_testnet {
        assert_ne!(code, "ai_layer_testnet_closed");
    }

    let tx_mainnet = signed_tx(
        &kp,
        mainnet,
        TransactionType::AiAttachExecutionProof {
            request_id: crate::ai::types::AiRequestId::new([9u8; 32]),
            proof,
        },
    );
    let err =
        crate::execution::executor::Executor::apply_transaction_checked(&mut state, &tx_mainnet)
            .expect_err("mainnet must refuse AI execution proofs");
    match err {
        crate::error::BudlumError::Validation { code, .. } => {
            assert_eq!(code, "ai_layer_testnet_closed");
        }
        other => panic!("expected a validation refusal, got {other:?}"),
    }
}

/// Entry to the on-chain AI verification layer is open on testnet (`45261`)
/// and devnet (`45262`); mainnet (`45260`) keeps the closure boundary.
#[test]
fn ai_layer_is_open_on_testnet() {
    use crate::core::chain_config::Network;
    let mainnet = Network::Mainnet.chain_id().value();
    let testnet = Network::Testnet.chain_id().value();
    let kp = KeyPair::generate().unwrap();
    let from = Address::from(kp.public_key_bytes());

    let cases: Vec<TransactionType> = vec![
        TransactionType::AiOperatorBond,
        TransactionType::AiModelDeactivate(crate::ai::types::AiModelId::new([7u8; 32])),
        TransactionType::AiModelReactivate(crate::ai::types::AiModelId::new([7u8; 32])),
        TransactionType::RoleBond {
            role: crate::registry::role::roles::AI_VERIFIER.0,
        },
        TransactionType::RoleBond {
            role: crate::registry::role::roles::AI_OPERATOR.0,
        },
    ];

    for tx_type in cases {
        let label = format!("{tx_type:?}");
        let mut state = funded_state(from, 1_000_000);
        let tx = signed_tx(&kp, mainnet, tx_type);
        let err = crate::execution::executor::Executor::apply_transaction_checked(&mut state, &tx)
            .expect_err("mainnet must refuse the AI layer");
        match err {
            crate::error::BudlumError::Validation { code, .. } => {
                assert_eq!(code, "ai_layer_testnet_closed", "case {label}");
            }
            other => panic!("case {label}: expected a validation refusal, got {other:?}"),
        }
    }

    let mut state = funded_state(from, 1_000_000);
    let tx = signed_tx(&kp, testnet, TransactionType::AiOperatorBond);
    if let Err(crate::error::BudlumError::Validation { code, .. }) =
        crate::execution::executor::Executor::apply_transaction_checked(&mut state, &tx)
    {
        assert_ne!(code, "ai_layer_testnet_closed");
    }
}

/// A native contract can submit an AI inference marker on testnet (`45261`),
/// while mainnet (`45260`) still enforces the layer closure before mutation.
#[test]
fn contract_inference_event_is_open_on_testnet() {
    use bud_isa::{Instruction, Opcode};
    let mut program = Vec::new();
    for value in [0x00A1_00A1, 7, 1, 10] {
        program.push(
            Instruction {
                opcode: Opcode::Load,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: value,
            }
            .encode(),
        );
        program.push(
            Instruction {
                opcode: Opcode::Log,
                rd: 0,
                rs1: 1,
                rs2: 0,
                imm: 0,
            }
            .encode(),
        );
    }
    program.push(
        Instruction {
            opcode: Opcode::Halt,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm: 0,
        }
        .encode(),
    );
    let kp = KeyPair::generate().unwrap();
    let from = Address::from(kp.public_key_bytes());
    let bytecode: Vec<u8> = program.into_iter().flat_map(u64::to_le_bytes).collect();

    let mut tx_test = Transaction::new_with_chain_id(
        from,
        Address::zero(),
        0,
        100,
        0,
        bytecode.clone(),
        crate::core::chain_config::Network::Testnet
            .chain_id()
            .value(),
        TransactionType::ContractCall,
    );
    tx_test.sign(&kp);
    let mut state = funded_state(from, 1_000_000);
    if let Err(crate::error::BudlumError::Validation { code, .. }) =
        Executor::apply_transaction_checked(&mut state, &tx_test)
    {
        assert_ne!(code, "ai_layer_testnet_closed");
    }

    let mut tx_main = Transaction::new_with_chain_id(
        from,
        Address::zero(),
        0,
        100,
        0,
        bytecode,
        crate::core::chain_config::Network::Mainnet
            .chain_id()
            .value(),
        TransactionType::ContractCall,
    );
    tx_main.sign(&kp);
    let mut main_state = funded_state(from, 1_000_000);
    let before = main_state.calculate_state_root();
    let error = Executor::apply_transaction_checked(&mut main_state, &tx_main)
        .expect_err("the native inference event must stay closed on mainnet");
    match error {
        crate::error::BudlumError::Validation { code, .. } => {
            assert_eq!(code, "ai_layer_testnet_closed");
        }
        other => panic!("expected a validation refusal, got {other:?}"),
    }
    assert_eq!(main_state.calculate_state_root(), before);
}

#[test]
fn attacker_cannot_spend_victim_live_note_or_inflate_outputs() {
    let victim_kp = KeyPair::generate().unwrap();
    let victim = Address::from(victim_kp.public_key_bytes());
    let attacker_kp = KeyPair::generate().unwrap();
    let attacker = Address::from(attacker_kp.public_key_bytes());

    let mut state = funded_state(victim, 1_000_000);
    state.get_or_create(&attacker).balance = 1_000_000;

    let victim_note = hash_from_field(777);
    state
        .note_registry
        .insert_note_for_owner(victim_note, victim)
        .unwrap();

    // 1. Attacker knows `victim_note` and chooses an arbitrary `proof` + signs with attacker's key.
    let chosen_proof = hash_from_field(0xBADC0DE);
    let n_att = L1NoteRegistry::derive_nullifier(&victim_note, &chosen_proof);
    let stolen_out = hash_from_field(888);
    let digest = PrivateTransferSubmit::compute_public_digest(&[n_att], &[stolen_out]);
    let auth_msg = PrivateTransferSubmit::authorization_message(
        crate::core::chain_config::Network::Devnet
            .chain_id()
            .value(),
        attacker.as_bytes(),
        0,
        &digest,
    );
    let steal_sub = PrivateTransferSubmit {
        spent_commitments: vec![victim_note],
        nullifiers: vec![n_att],
        output_commitments: vec![stolen_out],
        nullifier_proofs: vec![chosen_proof],
        authorization_sig: attacker_kp.sign(&auth_msg).to_vec(),
        public_digest: digest,
    };
    let steal_tx = signed_tx(
        &attacker_kp,
        crate::core::chain_config::Network::Devnet
            .chain_id()
            .value(),
        TransactionType::PrivateTransferSubmit(steal_sub),
    );
    let err = Executor::apply_transaction(&mut state, &steal_tx)
        .expect_err("attacker must not spend victim's note");
    assert!(err.contains("does not own note"), "got: {err}");
    assert!(state.note_registry.contains_commitment(&victim_note));
    assert!(!state.note_registry.contains_commitment(&stolen_out));

    // 2. Even the legitimate owner cannot inflate output note count (1 input -> 2 outputs).
    let owner_proof = hash_from_field(0xA11CE);
    let n_own = L1NoteRegistry::derive_nullifier(&victim_note, &owner_proof);
    let out1 = hash_from_field(901);
    let out2 = hash_from_field(902);
    let inf_digest = PrivateTransferSubmit::compute_public_digest(&[n_own], &[out1, out2]);
    let inf_auth = PrivateTransferSubmit::authorization_message(
        crate::core::chain_config::Network::Devnet
            .chain_id()
            .value(),
        victim.as_bytes(),
        0,
        &inf_digest,
    );
    let inflate_sub = PrivateTransferSubmit {
        spent_commitments: vec![victim_note],
        nullifiers: vec![n_own],
        output_commitments: vec![out1, out2],
        nullifier_proofs: vec![owner_proof],
        authorization_sig: victim_kp.sign(&inf_auth).to_vec(),
        public_digest: inf_digest,
    };
    let inflate_tx = signed_tx(
        &victim_kp,
        crate::core::chain_config::Network::Devnet
            .chain_id()
            .value(),
        TransactionType::PrivateTransferSubmit(inflate_sub),
    );
    let inf_err = Executor::apply_transaction(&mut state, &inflate_tx)
        .expect_err("unconserved 1->2 output inflation must be refused");
    assert!(
        inf_err.contains("value conservation failed"),
        "got: {inf_err}"
    );
    assert!(state.note_registry.contains_commitment(&victim_note));
}

#[test]
fn privacy_confidential_bundle_hiding_stark_and_predicates_on_testnet() {
    use crate::core::chain_config::Network;
    use crate::crypto::primitives::KeyPair;
    use crate::privacy::{L1NoteRegistry, PrivateTransferSubmit};

    let testnet = Network::Testnet.chain_id().value();
    let sender_kp = KeyPair::generate().unwrap();
    let sender = Address::from(sender_kp.public_key_bytes());
    let spent = L1NoteRegistry::derive_commitment(&sender, &hash_from_field(404));
    let proof_note = hash_from_field(505);
    let nf = L1NoteRegistry::derive_nullifier(&spent, &proof_note);
    let out = hash_from_field(606);
    let digest = PrivateTransferSubmit::compute_public_digest(&[nf], &[out]);
    let auth_msg =
        PrivateTransferSubmit::authorization_message(testnet, sender.as_bytes(), 0, &digest);
    let sub = PrivateTransferSubmit {
        spent_commitments: vec![spent],
        nullifiers: vec![nf],
        output_commitments: vec![out],
        nullifier_proofs: vec![proof_note],
        authorization_sig: sender_kp.sign(&auth_msg).to_vec(),
        public_digest: digest,
    };

    let salt = [0x42u8; 32];
    let bundle = sub
        .prove_confidential_bundle(testnet, &salt, 1_000, 1_000)
        .expect("prove Hiding + YK1..YK4 bundle on testnet");
    Executor::process_confidential_transfer_bundle(&sub, &bundle, testnet)
        .expect("full confidential STARK + predicate bundle verifies on testnet 45261");

    // Unrecognized / Mainnet chain_ids fail closed with privacy_mainnet_disabled.
    let err = Executor::process_confidential_transfer_bundle(&sub, &bundle, testnet + 99)
        .expect_err("wrong chain_id must be refused");
    assert_eq!(err.code(), "privacy_mainnet_disabled");
    let mainnet_err = Executor::process_confidential_transfer_bundle(
        &sub,
        &bundle,
        Network::Mainnet.chain_id().value(),
    )
    .expect_err("mainnet must remain refused until launch sign-off");
    assert_eq!(mainnet_err.code(), "privacy_mainnet_disabled");

    // Unconserved input vs output value fails closed during proving.
    assert!(sub
        .prove_confidential_bundle(testnet, &salt, 1_000, 999)
        .is_err());

    // Tampered YK2 conservation proof fails verification.
    let mut tampered = bundle.clone();
    tampered.conservation_proof.statement.lhs ^= 1;
    assert!(Executor::process_confidential_transfer_bundle(&sub, &tampered, testnet).is_err());
}

#[test]
fn privacy_threshold_escrow_7_of_4_unlocks_on_testnet() {
    use crate::core::chain_config::Network;
    use crate::privacy::{
        EscrowCommittee, ThresholdEscrow, ThresholdEscrowError, THRESHOLD_ESCROW_N,
        THRESHOLD_ESCROW_T,
    };

    assert_eq!(THRESHOLD_ESCROW_N, 7);
    assert_eq!(THRESHOLD_ESCROW_T, 4);
    let testnet = Network::Testnet.chain_id().value();
    let recipient = Address::from([0x77u8; 32]);
    let seeds: [[u8; 32]; 7] = std::array::from_fn(|i| {
        let mut s = [0u8; 32];
        s[0] = (i as u8) + 1;
        s[31] = 0x5A;
        s
    });
    let members = (0..THRESHOLD_ESCROW_N)
        .map(|i| EscrowCommittee::member_from_seed(i as u8, &seeds[i]).unwrap())
        .collect();
    let committee = EscrowCommittee {
        escrow_id: [0x19u8; 32],
        chain_id: testnet,
        epoch: 1,
        nonce: 0,
        members,
    };
    let mut escrow = ThresholdEscrow::open(committee, [0x88u8; 32]).unwrap();
    let shares: Vec<_> = (0..4)
        .map(|i| escrow.sign_share(i as u8, &seeds[i], &recipient).unwrap())
        .collect();
    let quorum_proof = escrow.prove_quorum_predicate(4, &recipient).unwrap();

    // Duplicate signer is refused.
    let dup_shares = vec![
        shares[0].clone(),
        shares[0].clone(),
        shares[1].clone(),
        shares[2].clone(),
    ];
    assert_eq!(
        escrow.unlock(&recipient, &dup_shares, &quorum_proof),
        Err(ThresholdEscrowError::DuplicateSigner(0))
    );

    // Fewer than t = 4 valid shares is refused.
    assert_eq!(
        escrow.unlock(&recipient, &shares[..3], &quorum_proof),
        Err(ThresholdEscrowError::InsufficientShares { got: 3, need: 4 })
    );

    // 4 valid ML-DSA-65 committee shares + YK6 STARK unlock cleanly via Executor.
    let receipt =
        Executor::process_threshold_escrow_unlock(&mut escrow, &recipient, &shares, &quorum_proof)
            .expect("7-of-4 threshold escrow unlocks on testnet 45261");
    assert_ne!(receipt, [0u8; 32]);
    assert!(escrow.unlocked);

    // Replay unlock fails closed.
    assert_eq!(
        escrow.unlock(&recipient, &shares, &quorum_proof),
        Err(ThresholdEscrowError::AlreadyUnlocked)
    );
}

#[test]
fn ai_verification_layer_apb_tile64_and_bound_small_model_on_testnet() {
    use crate::ai::answer_proof_bundle::{
        prove_calculator_in_vm, AnswerProofBundle, CalcOp, CandidateSentence, SentenceClaimKind,
    };
    use crate::ai::execution::{input_commitment, FixedPointMlpSpec};
    use crate::ai::types::{AiModelId, AiRequestId};
    use crate::ai::verification_layer::{
        prove_small_model_bound, prove_tile_64x64, DeterministicInferenceProfile, ModelRecordV2,
        TILE_CELLS,
    };
    use crate::ai::{
        audit_answer_proof_markdown, audit_bound_small_model_inference, audit_tile_64x64_proof,
        verification_layer_capabilities,
    };

    assert_eq!(
        verification_layer_capabilities(),
        "vl0_to_vl3_dip_apb_bisection_tile64_wired"
    );

    // 1. ModelRecordV2 + DIP + request-bound small-model proof.
    let spec = FixedPointMlpSpec {
        dims: vec![2, 2, 1],
        weights: vec![1, 2, 3, -1, 2, 1],
        biases: vec![1, 0, 2],
    };
    let dip = DeterministicInferenceProfile {
        quantization_bits: 16,
        fixed_scale_shift: 1,
        sampling_seed: 7,
        tokenizer_digest: [0x11; 32],
        runtime_digest: [0x22; 32],
    };
    let model_id = AiModelId::of(&Address::from([1u8; 32]), &[2u8; 32], 1);
    let model = ModelRecordV2::from_mlp_spec(model_id, &spec, &dip).unwrap();
    let req_id = AiRequestId([0x33; 32]);
    let input = [4, 5];
    let bound = prove_small_model_bound(req_id, &model, &spec, &input).unwrap();
    assert_eq!(bound.input_commit, input_commitment(&input));
    assert!(audit_bound_small_model_inference(&bound, &req_id, &model, &spec, &input).is_ok());

    // 2. 64x64 tile step dispute proof.
    let a = vec![2i32; TILE_CELLS];
    let b = vec![3i32; TILE_CELLS];
    let tile = prove_tile_64x64(&a, &b).unwrap();
    assert!(audit_tile_64x64_proof(&tile, &a, &b).is_ok());

    // 3. Answer Proof Bundle round-trip & prose tamper refusal.
    let calc = prove_calculator_in_vm(6, 7, CalcOp::Mul).unwrap();
    assert_eq!(calc.result_i32, 42);
    let bundle = AnswerProofBundle::build(vec![CandidateSentence {
        text: "Six times seven equals 42.".into(),
        claim_kind: Some(SentenceClaimKind::ComputationBacked(calc)),
    }])
    .unwrap();
    let md = bundle.to_markdown_document().unwrap();
    let audited = audit_answer_proof_markdown(&md).expect("valid APB markdown audits cleanly");
    assert!(audited.is_authentic());
    let tampered_md = md.replace("equals 42.", "equals 43.");
    assert!(audit_answer_proof_markdown(&tampered_md).is_err());
}
