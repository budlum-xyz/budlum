//! Integration tests for Task 0.06 permissionless prover integration.
//!
//! Covers the required cases:
//!  - unregistered account: valid proof accepted, but NO reward
//!  - registered prover: valid proof accepted AND rewarded
//!  - invalid proof: fee burned, state unchanged
//!  - conflicting proof claim for same (domain, height): rejected
//!  - idempotent re-submission of same claim
//!
//! Uses real STARK proofs produced by `execution::zkvm::prove_bytecode`.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use crate::cross_domain::message::{CrossDomainMessage, CrossDomainMessageParams};
use crate::cross_domain::MessageKind;
use crate::execution::zkvm::{prove_bytecode, DEFAULT_CONTRACT_GAS_LIMIT};
use crate::prover::{ProofAcceptance, ZkProofSubmission};
use bud_isa::{Instruction, Opcode};
use bud_proof::{ExecutionPublicInputs, ProofEnvelope};
use std::sync::Arc;

fn addr(b: u8) -> Address {
    Address::from([b; 32])
}

fn fresh_chain() -> Blockchain {
    let consensus = Arc::new(PoWEngine::new(0));
    Blockchain::new(consensus, None, 1337, None)
}

/// A tiny valid program: Load imm 7 -> reg1, Log reg1, Halt.
fn sample_bytecode() -> Vec<u8> {
    let program = vec![
        Instruction {
            opcode: Opcode::Load,
            rd: 1,
            rs1: 0,
            rs2: 0,
            imm: 7,
        }
        .encode(),
        Instruction {
            opcode: Opcode::Log,
            rd: 0,
            rs1: 1,
            rs2: 0,
            imm: 0,
        }
        .encode(),
        Instruction {
            opcode: Opcode::Halt,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm: 0,
        }
        .encode(),
    ];
    program.into_iter().flat_map(|i| i.to_le_bytes()).collect()
}

fn real_proof() -> (ProofEnvelope, ExecutionPublicInputs, Vec<u64>) {
    prove_bytecode(&sample_bytecode(), DEFAULT_CONTRACT_GAS_LIMIT).expect("proving must succeed")
}

/// Build a submission whose message payload_hash correctly binds the proof.
fn submission(
    sender: Address,
    domain: u32,
    height: u64,
    proof: &ProofEnvelope,
    pi: &ExecutionPublicInputs,
    program: &[u64],
) -> ZkProofSubmission {
    let payload_hash = ZkProofSubmission::payload_binding_hash(proof, pi, program);
    let message = CrossDomainMessage::new(CrossDomainMessageParams {
        source_domain: domain,
        target_domain: domain,
        source_height: height,
        event_index: 0,
        nonce: height,
        sender,
        recipient: Address::zero(),
        payload_hash,
        kind: MessageKind::Custom(b"zk-proof".to_vec()),
        expiry_height: 1000,
    });
    ZkProofSubmission {
        message,
        proof: proof.clone(),
        public_inputs: pi.clone(),
        program: program.to_vec(),
    }
}

#[test]
fn unregistered_account_valid_proof_accepted_but_not_rewarded() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    let sender = addr(0x01);
    let fee = bc.state.registry.params().proof_submission_fee;
    bc.state.add_balance(&sender, fee); // enough only for the (refunded) fee

    let before = bc.state.get_balance(&sender);
    let outcome = bc
        .submit_zk_proof(submission(sender, 1, 10, &proof, &pi, &program))
        .unwrap();
    assert_eq!(
        outcome,
        ProofAcceptance::Accepted {
            rewarded: false,
            reward: 0
        }
    );
    // Fee refunded (valid proof), no reward => balance unchanged.
    assert_eq!(bc.state.get_balance(&sender), before);
    assert_eq!(bc.proof_claims.len(), 1);
}

#[test]
fn registered_prover_valid_proof_accepted_and_rewarded() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    let prover = addr(0x02);
    // Fund + register as prover.
    bc.state.add_balance(&prover, 5_000);
    bc.state.bond_prover(&prover, 2_000).unwrap();
    assert!(bc.state.registry.is_active_prover(&prover));

    let reward = bc.state.registry.params().prover_reward;
    let before = bc.state.get_balance(&prover);
    let outcome = bc
        .submit_zk_proof(submission(prover, 1, 10, &proof, &pi, &program))
        .unwrap();
    assert_eq!(
        outcome,
        ProofAcceptance::Accepted {
            rewarded: true,
            reward
        }
    );
    // Fee refunded + reward paid => balance increased by exactly `reward`.
    assert_eq!(bc.state.get_balance(&prover), before + reward);
}

#[test]
fn invalid_proof_burns_fee_and_leaves_state_unchanged() {
    let mut bc = fresh_chain();
    let (mut proof, pi, program) = real_proof();
    // Corrupt the proof bytes so verification fails.
    if let Some(b) = proof.proof_bytes.first_mut() {
        *b ^= 0xFF;
    } else {
        proof.proof_bytes.push(0xFF);
    }
    let sender = addr(0x03);
    let fee = bc.state.registry.params().proof_submission_fee;
    bc.state.add_balance(&sender, fee);

    let err = bc
        .submit_zk_proof(submission(sender, 1, 10, &proof, &pi, &program))
        .unwrap_err();
    assert!(err.contains("invalid proof"), "got: {err}");
    // Fee burned.
    assert_eq!(bc.state.get_balance(&sender), 0);
    // No claim recorded, no message stored.
    assert_eq!(bc.proof_claims.len(), 0);
    assert_eq!(bc.state.message_registry.len(), 0);
}

#[test]
fn insufficient_fee_rejected_without_verification() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    let sender = addr(0x04); // no balance
    let err = bc
        .submit_zk_proof(submission(sender, 1, 10, &proof, &pi, &program))
        .unwrap_err();
    assert!(err.contains("insufficient balance"), "got: {err}");
    assert_eq!(bc.proof_claims.len(), 0);
}

#[test]
fn payload_hash_mismatch_rejected() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    let sender = addr(0x05);
    bc.state.add_balance(&sender, 1_000);
    let mut sub = submission(sender, 1, 10, &proof, &pi, &program);
    // Tamper the binding.
    sub.message.payload_hash = [0xAAu8; 32];
    let err = bc.submit_zk_proof(sub).unwrap_err();
    assert!(err.contains("payload hash"), "got: {err}");
    // Fee not charged (rejected before fee).
    assert_eq!(bc.state.get_balance(&sender), 1_000);
}

#[test]
fn wrong_message_kind_rejected() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    let sender = addr(0x06);
    bc.state.add_balance(&sender, 1_000);
    let mut sub = submission(sender, 1, 10, &proof, &pi, &program);
    sub.message = CrossDomainMessage::new(CrossDomainMessageParams {
        source_domain: 1,
        target_domain: 1,
        source_height: 10,
        event_index: 0,
        nonce: 10,
        sender,
        recipient: Address::zero(),
        payload_hash: sub.message.payload_hash,
        kind: MessageKind::BridgeLock, // wrong kind
        expiry_height: 1000,
    });
    let err = bc.submit_zk_proof(sub).unwrap_err();
    assert!(err.contains("not a ZK proof"), "got: {err}");
}

#[test]
fn idempotent_resubmission_same_claim() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    let prover = addr(0x07);
    bc.state.add_balance(&prover, 5_000);
    bc.state.bond_prover(&prover, 2_000).unwrap();
    let reward = bc.state.registry.params().prover_reward;

    // First submission: accepted + rewarded.
    let first = bc
        .submit_zk_proof(submission(prover, 1, 10, &proof, &pi, &program))
        .unwrap();
    assert_eq!(
        first,
        ProofAcceptance::Accepted {
            rewarded: true,
            reward
        }
    );
    let after_first = bc.state.get_balance(&prover);

    // Second identical submission: idempotent, NO extra reward.
    let second = bc
        .submit_zk_proof(submission(prover, 1, 10, &proof, &pi, &program))
        .unwrap();
    assert_eq!(second, ProofAcceptance::Idempotent);
    assert_eq!(bc.state.get_balance(&prover), after_first);
    // Still one claim.
    assert_eq!(bc.proof_claims.len(), 1);
}

#[test]
fn conflicting_claim_same_domain_height_rejected() {
    use crate::prover::{AcceptedProofClaim, ProofClaimKey};
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();

    // Pre-seed an accepted claim for (domain=1, height=10) with a DIFFERENT
    // final state root than the proof we are about to submit. (Seeding directly
    // makes the conflict deterministic regardless of VM state-root semantics.)
    let key = ProofClaimKey {
        domain_id: 1,
        target_height: 10,
    };
    let conflicting_root = {
        let mut r = pi.final_state_root;
        r[0] ^= 0xFF; // guaranteed different
        r
    };
    bc.proof_claims.record(AcceptedProofClaim {
        key,
        final_state_root: conflicting_root,
        prover: addr(0x08),
        rewarded: false,
    });
    assert_eq!(bc.proof_claims.len(), 1);

    // A genuinely valid proof asserting a different root for the same
    // (domain, height) must be rejected as conflicting...
    let prover_b = addr(0x09);
    bc.state.add_balance(&prover_b, 1_000);
    let before_b = bc.state.get_balance(&prover_b);
    let err = bc
        .submit_zk_proof(submission(prover_b, 1, 10, &proof, &pi, &program))
        .unwrap_err();
    assert!(err.contains("conflicting"), "got: {err}");
    // ...and the honest prover's fee is refunded (protocol-level rejection).
    assert_eq!(bc.state.get_balance(&prover_b), before_b);
    // No new claim recorded.
    assert_eq!(bc.proof_claims.len(), 1);
}
