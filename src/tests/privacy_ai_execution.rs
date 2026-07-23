//! D2 private transfer submit + AI execution guest skeleton tests.

use crate::ai::execution::{
    build_fixed_point_mlp_guest, input_commitment, program_hash_from_words, FixedPointMlpSpec,
};
use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType};
use crate::crypto::primitives::KeyPair;
use crate::execution::executor::Executor;
use crate::privacy::{L1NoteRegistry, PrivateTransferSubmit};

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

    let c_in = [1u8; 32];
    let n1 = [2u8; 32];
    let c_out = [3u8; 32];
    state.note_registry.insert_note(c_in).unwrap();

    let digest = PrivateTransferSubmit::compute_public_digest(&[n1], &[c_out]);
    let sig = kp.sign(&digest).to_vec();
    let sub = PrivateTransferSubmit {
        spent_commitments: vec![c_in],
        nullifiers: vec![n1],
        output_commitments: vec![c_out],
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
    let c_in = [9u8; 32];
    let n1 = [8u8; 32];
    let c_out = [7u8; 32];
    state.note_registry.insert_note(c_in).unwrap();
    let digest = PrivateTransferSubmit::compute_public_digest(&[n1], &[c_out]);
    let sub = PrivateTransferSubmit {
        spent_commitments: vec![c_in],
        nullifiers: vec![n1],
        output_commitments: vec![c_out],
        authorization_sig: kp.sign(&digest).to_vec(),
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
    // reuse nullifier with new note
    let c2 = [6u8; 32];
    state.note_registry.insert_note(c2).unwrap();
    let digest2 = PrivateTransferSubmit::compute_public_digest(&[n1], &[[5u8; 32]]);
    let sub2 = PrivateTransferSubmit {
        spent_commitments: vec![c2],
        nullifiers: vec![n1],
        output_commitments: vec![[5u8; 32]],
        authorization_sig: kp.sign(&digest2).to_vec(),
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
    let c = [42u8; 32];
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
    use crate::core::address::Address;

    let owner = Address::from([1u8; 32]);
    let verifier = Address::from([2u8; 32]);
    let mut reg = AiRegistry::new();
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
        execution_program_hash: Some([7u8; 32]),
        execution_class: 1,
    })
    .unwrap();

    let mut req = AiInferenceRequest {
        request_id: AiRequestId([0u8; 32]),
        requester: owner,
        model_id: mid,
        input_commitment: [3u8; 32],
        input_ref: BoundedBytes::empty(),
        max_fee: 100,
        callback: None,
        submitted_at_block: 1,
        deadline_block: 50,
    };
    req.request_id = req.calculate_id();
    reg.submit_request(req.clone(), 1).unwrap();

    let res = AiInferenceResult {
        request_id: req.request_id,
        verifier,
        output_commitment: [4u8; 32],
        output_ref: BoundedBytes::empty(),
        result_nonce: 1,
        signature: vec![0; 64],
        submitted_at_block: 2,
    };
    let outcome = reg.submit_result(res.clone(), 2).unwrap();
    assert!(
        outcome.is_none(),
        "must not finalize without execution proof"
    );

    // Attach valid structural proof
    let proof = AiExecutionProof {
        model_id: mid,
        input_commitment: req.input_commitment,
        output_commitment: res.output_commitment,
        program_hash: [7u8; 32],
        proof_bytes: {
            // minimal fake won't deserialize — use real prove for attach path
            vec![1]
        },
        steps: 1,
        gas_used: 1,
    };
    // structural attach requires postcard envelope in executor; registry attach
    // only needs structural with non-empty proof_bytes
    assert!(reg
        .attach_execution_proof(&req.request_id, &verifier, proof)
        .is_ok());
    let fin = reg.try_finalize_with_proofs(&req.request_id);
    assert!(fin.is_some(), "finalize after proof attach");
}
