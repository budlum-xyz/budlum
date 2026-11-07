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
        assert!(err.contains("closed on this network"), "got: {err}");
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
        assert!(err.contains("closed on this network"), "got: {err}");
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

/// Compare the persisted note registry as well as account state. A refusal
/// must not spend a note, consume a nonce, charge a fee or create a sender.
fn assert_feature_refusal_unchanged(state: &mut AccountState, tx: &Transaction, code: &str) {
    let root = state.calculate_state_root();
    let balances = state.get_all_balances();
    let nonces = state.get_all_nonces();
    let notes = bincode::serialize(&state.note_registry).unwrap();
    let accounts = state.accounts.len();
    let ai = state.ai_registry.clone();
    let roles = bincode::serialize(&state.registry).unwrap();
    let err = Executor::apply_transaction_checked(state, tx)
        .expect_err("the network policy must refuse the closed feature");
    assert_eq!(err.code(), code);
    assert_eq!(state.ai_registry, ai);
    assert_eq!(bincode::serialize(&state.registry).unwrap(), roles);
    assert_eq!(state.calculate_state_root(), root);
    assert_eq!(state.get_all_balances(), balances);
    assert_eq!(state.get_all_nonces(), nonces);
    assert_eq!(bincode::serialize(&state.note_registry).unwrap(), notes);
    assert_eq!(state.accounts.len(), accounts);
}

#[test]
fn private_transfer_is_closed_on_testnet() {
    let chain_id = crate::core::chain_config::Network::Testnet
        .chain_id()
        .value();
    let kp = KeyPair::generate().unwrap();
    let from = Address::from(kp.public_key_bytes());
    let mut state = funded_state(from, 1_000_000);
    let (mut sub, _, _) = transfer_fixture(&kp, &mut state);
    // The inner authorization must name testnet too. A devnet authorization
    // would test signature rejection rather than the closed-feature policy.
    sub.authorization_sig = kp
        .sign(&PrivateTransferSubmit::authorization_message(
            chain_id,
            from.as_bytes(),
            0,
            &sub.public_digest,
        ))
        .to_vec();
    let tx = signed_tx(&kp, chain_id, TransactionType::PrivateTransferSubmit(sub));
    assert_feature_refusal_unchanged(&mut state, &tx, "privacy_mainnet_disabled");
}

#[test]
fn note_registry_is_closed_on_testnet() {
    let chain_id = crate::core::chain_config::Network::Testnet
        .chain_id()
        .value();
    let kp = KeyPair::generate().unwrap();
    let from = Address::from(kp.public_key_bytes());
    let tx = signed_tx(
        &kp,
        chain_id,
        TransactionType::PrivacyNoteInsert(hash_from_field(77)),
    );
    assert_feature_refusal_unchanged(
        &mut funded_state(from, 1_000_000),
        &tx,
        "privacy_mainnet_disabled",
    );
    // In particular, the general balance check must not create this account.
    assert_feature_refusal_unchanged(&mut AccountState::new(), &tx, "privacy_mainnet_disabled");
}

#[test]
fn privacy_admission_and_precheck_share_the_execution_boundary() {
    use crate::chain::blockchain::Blockchain;
    use crate::consensus::pow::PoWEngine;
    use crate::core::chain_config::Network;
    use std::sync::Arc;

    let kp = KeyPair::generate().unwrap();
    let from = Address::from(kp.public_key_bytes());
    for chain_id in [Network::Testnet.chain_id().value(), 999_999] {
        let mut chain = Blockchain::new(Arc::new(PoWEngine::new(1)), None, chain_id, None);
        chain.state = funded_state(from, 1_000_000);
        let (mut sub, _, _) = transfer_fixture(&kp, &mut chain.state);
        sub.authorization_sig = kp
            .sign(&PrivateTransferSubmit::authorization_message(
                chain_id,
                from.as_bytes(),
                0,
                &sub.public_digest,
            ))
            .to_vec();
        for variant in [
            TransactionType::PrivateTransferSubmit(sub),
            TransactionType::PrivacyNoteInsert(hash_from_field(77)),
        ] {
            let tx = signed_tx(&kp, chain_id, variant);
            let err = chain.state.validate_transaction(&tx).unwrap_err();
            assert!(err.contains("privacy_mainnet_disabled"), "{err}");
            assert_pool_feature_refusal(&mut chain, &kp, tx, "privacy_mainnet_disabled");
        }
    }
}

fn assert_pool_feature_refusal(
    chain: &mut crate::chain::blockchain::Blockchain,
    kp: &KeyPair,
    mut tx: Transaction,
    code: &str,
) {
    let root = chain.state.calculate_state_root();
    let precheck = chain.tx_precheck(&tx);
    assert_eq!(precheck["accepted"], false);
    assert!(precheck["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason == code));
    let err = chain.add_transaction(tx.clone()).unwrap_err();
    assert!(err.contains(code), "{err}");
    assert_eq!(
        chain
            .add_transaction_bundle(vec![tx.clone()])
            .unwrap_err()
            .index,
        0
    );

    // A valid first member must not leak into the pool when the second
    // member reaches the closed feature. This is not a one-member-only test.
    let fee = chain
        .state
        .registry
        .params()
        .required_transfer_fee(1, chain.state.base_fee)
        .max(1);
    let mut ordinary = Transaction::new_with_chain_id(
        tx.from,
        test_addr_from_byte(200),
        1,
        fee,
        0,
        vec![],
        tx.chain_id,
        TransactionType::Transfer,
    );
    ordinary.sign(kp);
    chain
        .state
        .validate_transaction(&ordinary)
        .expect("the bundle prefix must be valid");
    tx.nonce = 1;
    tx.sign(kp);
    let refusal = chain
        .add_transaction_bundle(vec![ordinary, tx])
        .unwrap_err();
    assert_eq!(refusal.index, 1);
    assert!(matches!(refusal.cause,
        crate::mempool::pool::MempoolError::InvalidTransaction(reason) if reason.contains(code)));
    assert_eq!(chain.mempool.len(), 0);
    assert_eq!(chain.state.calculate_state_root(), root);
}

fn ai_feature_variants(from: Address) -> Vec<TransactionType> {
    use crate::ai::types::{
        AiAgentPayment, AiExecutionProof, AiInferenceRequest, AiInferenceResult, AiModelId,
        AiModelSpec, AiRequestId, BoundedBytes,
    };
    let model_id = AiModelId([7; 32]);
    let request_id = AiRequestId([9; 32]);
    let mut cases = vec![
        TransactionType::AiModelRegister(AiModelSpec {
            model_id,
            model_hash: [7; 32],
            owner: from,
            min_verifier_count: 5,
            agreement_threshold: 4,
            max_input_ref_bytes: 1024,
            max_output_ref_bytes: 1024,
            request_deadline_blocks: 100,
            result_deadline_blocks: 100,
            version: 1,
            active: true,
            require_execution_proof: false,
            execution_program_hash: None,
            execution_class: 0,
            execution_weights_digest: None,
            execution_dims: None,
            modalities: crate::ai_inference::perception::ModalitySet::text_only(),
        }),
        TransactionType::AiInferenceRequest(AiInferenceRequest {
            request_id,
            requester: from,
            model_id,
            input_commitment: [1; 32],
            input_ref: BoundedBytes::try_new(vec![]).unwrap(),
            max_fee: 1,
            callback: None,
            submitted_at_block: 0,
            deadline_block: 100,
            perception: None,
            effort: crate::ai_inference::effort::EffortTier::BASELINE,
        }),
        TransactionType::AiInferenceResult(AiInferenceResult {
            request_id,
            verifier: from,
            output_commitment: [2; 32],
            output_ref: BoundedBytes::try_new(vec![]).unwrap(),
            result_nonce: 0,
            signature: vec![],
            submitted_at_block: 0,
        }),
        TransactionType::AiFeeReclaim(request_id),
        TransactionType::AiModelDeactivate(model_id),
        TransactionType::AiModelReactivate(model_id),
        TransactionType::AiRequestCancel(request_id),
        TransactionType::AiDisputeSlash {
            request_id,
            verifier: from,
        },
        TransactionType::AiAgentPayment(AiAgentPayment {
            payment_id: [4; 32],
            from_agent: from,
            to_agent: test_addr_from_byte(2),
            amount: 1,
            request_id: Some(request_id),
            require_proof: true,
            submitted_at_block: 0,
            expiry_block: 100,
        }),
        TransactionType::AiAgentPaymentRelease([4; 32]),
        TransactionType::AiAgentPaymentReclaim([4; 32]),
        TransactionType::AiAttachExecutionProof {
            request_id,
            proof: AiExecutionProof {
                model_id,
                input_commitment: [1; 32],
                output_commitment: [2; 32],
                program_hash: [3; 32],
                proof_bytes: vec![],
                steps: 1,
                gas_used: 1,
                weights_digest: None,
                public_inputs: None,
            },
        },
        TransactionType::AiOperatorBond,
        TransactionType::AiOperatorUnbond,
        TransactionType::AiOperatorWithdraw,
    ];
    for role in [
        crate::registry::role::roles::AI_VERIFIER,
        crate::registry::role::roles::AI_OPERATOR,
    ] {
        cases.extend([
            TransactionType::RoleBond { role: role.0 },
            TransactionType::RoleUnbond { role: role.0 },
            TransactionType::RoleWithdraw { role: role.0 },
        ]);
    }
    assert_eq!(cases.len(), 21, "every AI door belongs in this fixture");
    cases
}

#[test]
fn ai_layer_is_closed_on_testnet() {
    use crate::core::chain_config::Network;
    let kp = KeyPair::generate().unwrap();
    let from = Address::from(kp.public_key_bytes());
    for chain_id in [
        Network::Testnet.chain_id().value(),
        Network::Mainnet.chain_id().value(),
        999_999,
    ] {
        for variant in ai_feature_variants(from) {
            let tx = signed_tx(&kp, chain_id, variant);
            let mut state = funded_state(from, 1_000_000);
            assert_feature_refusal_unchanged(&mut state, &tx, "ai_layer_closed_on_testnet");
            let err = state.validate_transaction(&tx).unwrap_err();
            assert!(err.contains("ai_layer_closed_on_testnet"), "{err}");
            assert_feature_refusal_unchanged(
                &mut AccountState::new(),
                &tx,
                "ai_layer_closed_on_testnet",
            );
        }
    }
}

#[test]
fn ai_execution_proof_is_closed_on_testnet() {
    let kp = KeyPair::generate().unwrap();
    let from = Address::from(kp.public_key_bytes());
    let variant = ai_feature_variants(from)
        .into_iter()
        .find(|tx| matches!(tx, TransactionType::AiAttachExecutionProof { .. }))
        .expect("the fixture must contain the execution-proof door");
    let tx = signed_tx(
        &kp,
        crate::core::chain_config::Network::Testnet
            .chain_id()
            .value(),
        variant,
    );
    assert_feature_refusal_unchanged(
        &mut funded_state(from, 1_000_000),
        &tx,
        "ai_layer_closed_on_testnet",
    );
}

#[test]
fn ai_admission_and_precheck_share_the_execution_boundary() {
    use crate::chain::blockchain::Blockchain;
    use crate::consensus::pow::PoWEngine;
    use std::sync::Arc;
    let chain_id = crate::core::chain_config::Network::Testnet
        .chain_id()
        .value();
    let kp = KeyPair::generate().unwrap();
    let from = Address::from(kp.public_key_bytes());
    let mut chain = Blockchain::new(Arc::new(PoWEngine::new(1)), None, chain_id, None);
    chain.state = funded_state(from, 1_000_000);
    for variant in ai_feature_variants(from) {
        let tx = signed_tx(&kp, chain_id, variant);
        assert_pool_feature_refusal(&mut chain, &kp, tx, "ai_layer_closed_on_testnet");
    }
}

#[test]
fn closed_features_leave_devnet_and_the_data_market_unchanged() {
    use crate::core::chain_config::Network;
    use crate::execution::executor::check_transaction_features;
    let devnet = Network::Devnet.chain_id().value();
    for variant in ai_feature_variants(test_addr_from_byte(3)) {
        assert!(check_transaction_features(devnet, &variant).is_ok());
    }
    for network in [Network::Testnet, Network::Mainnet, Network::Devnet] {
        for variant in [
            TransactionType::Transfer,
            TransactionType::ContractCall,
            TransactionType::AiPurchaseData { offer_id: 0 },
            TransactionType::AiOfferData {
                cid: crate::storage::content_id::ContentId::of(b"market-control"),
                price: 1,
            },
            TransactionType::RoleBond {
                role: crate::registry::role::roles::RELAYER.0,
            },
        ] {
            assert!(check_transaction_features(network.chain_id().value(), &variant).is_ok());
        }
    }
}

#[test]
fn contract_inference_event_is_closed_on_testnet() {
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
    let mut tx = Transaction::new_with_chain_id(
        from,
        Address::zero(),
        0,
        100,
        0,
        program.into_iter().flat_map(u64::to_le_bytes).collect(),
        crate::core::chain_config::Network::Testnet
            .chain_id()
            .value(),
        TransactionType::ContractCall,
    );
    tx.sign(&kp);
    assert_feature_refusal_unchanged(
        &mut funded_state(from, 1_000_000),
        &tx,
        "ai_layer_closed_on_testnet",
    );
}
