//! Launch boundaries for features that are not yet admitted on testnet.

use crate::ai::types::{AiExecutionProof, AiModelId, AiRequestId};
use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::chain_config::Network;
use crate::core::transaction::{Transaction, TransactionType};
use crate::execution::executor::{check_transaction_features, Executor};
use crate::privacy::PrivateTransferSubmit;

fn refused_without_mutation(kind: TransactionType) {
    let from = Address::from([21; 32]);
    let mut state = AccountState::new();
    state.add_balance(&from, 1_000);
    let before = state.calculate_state_root();
    let chain = Network::Testnet.chain_id().value();
    let admission = check_transaction_features(chain, &kind).expect_err("admission must close");
    assert_eq!(admission.code(), "privacy_testnet_closed");
    let tx = Transaction::new_with_chain_id(from, Address::zero(), 0, 1, 0, vec![], chain, kind);
    let error =
        Executor::apply_transaction_checked(&mut state, &tx).expect_err("execution must close");
    assert_eq!(error.code(), "privacy_testnet_closed");
    assert_eq!(state.calculate_state_root(), before);
}

#[test]
fn private_transfer_is_closed_on_testnet() {
    refused_without_mutation(TransactionType::PrivateTransferSubmit(
        PrivateTransferSubmit {
            spent_commitments: vec![],
            nullifiers: vec![],
            output_commitments: vec![],
            nullifier_proofs: vec![],
            authorization_sig: vec![],
            public_digest: [0; 32],
        },
    ));
}

#[test]
fn note_registry_is_closed_on_testnet() {
    refused_without_mutation(TransactionType::PrivacyNoteInsert(
        budlum_note_packing::hash_from_field(42),
    ));
}

#[test]
fn ai_execution_proof_is_closed_on_testnet() {
    let tx = TransactionType::AiAttachExecutionProof {
        request_id: AiRequestId::new([8; 32]),
        proof: AiExecutionProof {
            model_id: AiModelId::new([7; 32]),
            input_commitment: [1; 32],
            output_commitment: [2; 32],
            program_hash: [3; 32],
            proof_bytes: vec![0; 8],
            steps: 1,
            gas_used: 1,
            weights_digest: None,
            public_inputs: None,
        },
    };
    let error = check_transaction_features(Network::Testnet.chain_id().value(), &tx)
        .expect_err("unverified execution proofs must not enter testnet");
    assert_eq!(error.code(), "ai_layer_testnet_closed");
    assert!(check_transaction_features(Network::Devnet.chain_id().value(), &tx).is_ok());
}

#[test]
fn ai_layer_is_closed_on_testnet() {
    let tx = TransactionType::AiOperatorBond;
    let error = check_transaction_features(Network::Testnet.chain_id().value(), &tx)
        .expect_err("AI entry must be closed pending its prerequisites");
    assert_eq!(error.code(), "ai_layer_testnet_closed");
    assert!(check_transaction_features(Network::Devnet.chain_id().value(), &tx).is_ok());
}
