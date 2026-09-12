//! Integration tests permissionless prover integration.
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
use crate::prover::{ProofAcceptance, ProofClaimKey, ZkProofSubmission};
use crate::storage::db::Storage;
use bud_isa::{Instruction, Opcode};
use bud_proof::{ExecutionPublicInputs, ProofEnvelope};
use std::sync::Arc;
use tempfile::tempdir;

fn addr(b: u8) -> Address {
    Address::from([b; 32])
}

fn fresh_chain() -> Blockchain {
    let consensus = Arc::new(PoWEngine::new(0));
    Blockchain::new(consensus, None, 45262, None)
}

/// Registers the domain and writes the given program into the zk allowlist.
///
/// This helper exists because a proof is no longer accepted merely for being valid:
/// the domain must have explicitly allowed that program. The allowlist
/// is born empty, so registration alone is not enough.
fn register_domain_allowing(bc: &mut Blockchain, id: u32, program: &[u64]) {
    let mut domain = crate::domain::plugin::default_domain(
        id,
        crate::domain::ConsensusKind::Zk,
        45262 + id as u64,
        "zk-proof-verification",
        0,
    );
    domain
        .zk_program_allowlist
        .push(crate::prover::zk_program_hash(program));
    bc.domain_registry.register(domain).expect("register");
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
    let payload_hash = ZkProofSubmission::payload_binding_hash(proof, pi, program, domain, height);
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
    register_domain_allowing(&mut bc, 1, &program);
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
    // Valid proof fee is burned under fee-only fixed-supply policy.
    assert_eq!(bc.state.get_balance(&sender), before - fee);
    assert_eq!(bc.proof_claims.len(), 1);
}

#[test]
fn registered_prover_valid_proof_is_fee_only_without_mint() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let prover = addr(0x02);
    // Fund + register as prover.
    bc.state.add_balance(&prover, 5_000);
    bc.state.bond_prover(&prover, 2_000).unwrap();
    assert!(bc.state.registry.is_active_prover(&prover));

    let fee = bc.state.registry.params().proof_submission_fee;
    let before = bc.state.get_balance(&prover);
    let outcome = bc
        .submit_zk_proof(submission(prover, 1, 10, &proof, &pi, &program))
        .unwrap();
    assert_eq!(
        outcome,
        ProofAcceptance::Accepted {
            rewarded: false,
            reward: 0
        }
    );
    assert_eq!(bc.state.get_balance(&prover), before - fee);
}

#[test]
fn invalid_proof_burns_fee_and_leaves_state_unchanged() {
    let mut bc = fresh_chain();
    let (mut proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
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
    assert!(err.contains("invalid proof"));
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
    register_domain_allowing(&mut bc, 1, &program);
    let sender = addr(0x04); // no balance
    let err = bc
        .submit_zk_proof(submission(sender, 1, 10, &proof, &pi, &program))
        .unwrap_err();
    assert!(err.contains("insufficient balance"));
    assert_eq!(bc.proof_claims.len(), 0);
}

#[test]
fn payload_hash_mismatch_rejected() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let sender = addr(0x05);
    bc.state.add_balance(&sender, 1_000);
    let mut sub = submission(sender, 1, 10, &proof, &pi, &program);
    // Tamper the binding.
    sub.message.payload_hash = [0xAAu8; 32];
    let err = bc.submit_zk_proof(sub).unwrap_err();
    assert!(err.contains("payload hash"));
    // Fee not charged (rejected before fee).
    assert_eq!(bc.state.get_balance(&sender), 1_000);
}

#[test]
fn wrong_message_kind_rejected() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
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
    assert!(err.contains("not a ZK proof"));
}

#[test]
fn idempotent_resubmission_same_claim() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let prover = addr(0x07);
    bc.state.add_balance(&prover, 5_000);
    bc.state.bond_prover(&prover, 2_000).unwrap();
    let fee = bc.state.registry.params().proof_submission_fee;

    // First submission: accepted without minting.
    let first = bc
        .submit_zk_proof(submission(prover, 1, 10, &proof, &pi, &program))
        .unwrap();
    assert_eq!(
        first,
        ProofAcceptance::Accepted {
            rewarded: false,
            reward: 0
        }
    );
    let after_first = bc.state.get_balance(&prover);

    // Second identical submission: idempotent, NO extra reward.
    let second = bc
        .submit_zk_proof(submission(prover, 1, 10, &proof, &pi, &program))
        .unwrap();
    assert_eq!(second, ProofAcceptance::Idempotent);
    assert_eq!(bc.state.get_balance(&prover), after_first - fee);
    // Still one claim.
    assert_eq!(bc.proof_claims.len(), 1);
}

#[test]
fn conflicting_claim_same_domain_height_rejected() {
    use crate::prover::AcceptedProofClaim;
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);

    // Pre-seed an accepted claim for (domain=1, height=10) with a DIFFERENT
    // Final state root than the proof we are about to submit. (Seeding directly
    // Makes the conflict deterministic regardless of VM state-root semantics.)
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
    assert!(err.contains("conflicting"));
    // ...and the honest prover's fee is refunded (protocol-level rejection).
    assert_eq!(bc.state.get_balance(&prover_b), before_b);
    // No new claim recorded.
    assert_eq!(bc.proof_claims.len(), 1);
}

#[test]
fn proof_claim_registry_persists_across_restart() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("prover.db");
    let db_path = db_path.to_string_lossy().to_string();

    let mut bc = Blockchain::new(
        Arc::new(PoWEngine::new(0)),
        Some(Storage::new(&db_path).unwrap()),
        45262,
        None,
    );
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let prover = addr(0x0A);
    let fee = bc.state.registry.params().proof_submission_fee;
    bc.state.add_balance(&prover, fee);

    bc.submit_zk_proof(submission(prover, 1, 10, &proof, &pi, &program))
        .unwrap();
    assert_eq!(bc.proof_claims.len(), 1);
    drop(bc);

    let restarted = Blockchain::new(
        Arc::new(PoWEngine::new(0)),
        Some(Storage::new(&db_path).unwrap()),
        45262,
        None,
    );
    let key = ProofClaimKey {
        domain_id: 1,
        target_height: 10,
    };
    assert!(restarted.proof_claims.get(&key).is_some());
    assert_eq!(restarted.proof_claims.len(), 1);
}

/// A proof produced for another chain must not be accepted here.
///
/// `public_inputs.chain_id` comes from the sender. The STARK only says "the program ran
/// this way with these public inputs"; it does not constrain **which chain** the inputs
/// belong to. Without a check in the verifier, a proof entirely valid on its own chain
/// would pass here too and advance a domain.
#[test]
fn a_proof_bound_to_another_chain_is_refused() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let sender = addr(0x09);
    let fee = bc.state.registry.params().proof_submission_fee;
    bc.state.add_balance(&sender, fee);

    // The same proof, only chain_id points at another chain.
    let mut foreign = pi.clone();
    foreign.chain_id = pi.chain_id + 1;

    let before = bc.state.get_balance(&sender);
    let err = bc
        .submit_zk_proof(submission(sender, 1, 11, &proof, &foreign, &program))
        .expect_err("a proof bound to another chain must be refused");
    assert!(
        err.contains("chain"),
        "the error must describe the chain binding: {err}"
    );
    assert_eq!(
        bc.state.get_balance(&sender),
        before,
        "a refused proof must not burn a fee: the check comes before the fee"
    );

    // Control: with the right chain_id the same proof is accepted.
    bc.submit_zk_proof(submission(sender, 1, 11, &proof, &pi, &program))
        .expect("a proof bound to the right chain must be accepted");
}

/// A proof produced for one height must not be submittable at another height.
///
/// The accepted claim is keyed by `(domain, height)`. The binding hash
/// does not cover both, a single valid proof can be submitted to every
/// pair not yet claimed: the attacker only rebuilds the transport message and
/// never touches the proof. A proof says "a program ran this way"; it does not say
/// "this is the transition at this height".
#[test]
fn a_proof_claimed_at_one_height_cannot_be_replayed_at_another() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let sender = addr(0x0a);
    let fee = bc.state.registry.params().proof_submission_fee;
    bc.state.add_balance(&sender, fee * 4);

    // A valid claim for height 20.
    bc.submit_zk_proof(submission(sender, 1, 20, &proof, &pi, &program))
        .expect("the first claim must be accepted");

    // The same proof submitted at height 21: the message is rebuilt but
    // the binding hash now covers the height too, so it does not hold.
    let mut replayed = submission(sender, 1, 20, &proof, &pi, &program);
    replayed.message.source_height = 21;
    let err = bc
        .submit_zk_proof(replayed)
        .expect_err("a proof with an altered height must be refused");
    assert!(
        err.contains("payload hash"),
        "the error must describe the binding: {err}"
    );

    // Changing the domain must fail the same way.
    let mut cross_domain = submission(sender, 1, 20, &proof, &pi, &program);
    cross_domain.message.target_domain = 2;
    let err = bc
        .submit_zk_proof(cross_domain)
        .expect_err("a proof with an altered domain must be refused");
    assert!(
        err.contains("payload hash"),
        "the error must describe the binding: {err}"
    );
}

/// The proof is flawless, the program unauthorized: it must be refused.
///
/// The shape of the attack: the attacker writes their own program, runs it honestly
/// and produces a real STARK. The proof is valid - no cryptographic
/// check can catch it, because the lie is not in the proof but in the code that was
/// run. The `program_hash` check does not help either: since the sender supplies both the program
/// and the hash, that check always passes.
///
/// The only thing that produces the refusal is the allowlist the domain declared beforehand.
#[test]
fn a_valid_proof_over_an_unauthorized_program_is_refused() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();

    // The domain is registered and accepts zk, but allows a DIFFERENT program.
    let mut other_program = program.clone();
    other_program.push(0);
    register_domain_allowing(&mut bc, 1, &other_program);

    let sender = addr(0x21);
    let fee = bc.state.registry.params().proof_submission_fee;
    bc.state.add_balance(&sender, fee * 4);
    let before = bc.state.get_balance(&sender);

    let err = bc
        .submit_zk_proof(submission(sender, 1, 10, &proof, &pi, &program))
        .unwrap_err();
    assert!(
        err.contains("not on the zk allowlist"),
        "an unauthorized program must be refused for the allowlist reason, got: {err}"
    );

    // The gate comes before the fee: a refused submission must not burn money.
    assert_eq!(
        bc.state.get_balance(&sender),
        before,
        "the allowlist refusal must come before the fee"
    );

    // And no claim must be recorded.
    assert!(bc
        .proof_claims
        .get(&ProofClaimKey {
            domain_id: 1,
            target_height: 10,
        })
        .is_none());
}

/// An empty allowlist is a closed gate.
///
/// The direction of the default matters: a new or migrated domain must not be
/// advanceable by zk until somebody has granted it a program. A fail-open
/// default would leave that domain unguarded.
#[test]
fn a_domain_with_an_empty_allowlist_accepts_no_proof() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();

    let domain = crate::domain::plugin::default_domain(
        2,
        crate::domain::ConsensusKind::Zk,
        45264,
        "zk-proof-verification",
        0,
    );
    assert!(
        domain.zk_program_allowlist.is_empty(),
        "a domain must be born closed to zk proofs"
    );
    bc.domain_registry.register(domain).expect("register");

    let sender = addr(0x22);
    let fee = bc.state.registry.params().proof_submission_fee;
    bc.state.add_balance(&sender, fee * 4);

    let err = bc
        .submit_zk_proof(submission(sender, 2, 10, &proof, &pi, &program))
        .unwrap_err();
    assert!(err.contains("not on the zk allowlist"), "gelen: {err}");
}

/// An unregistered domain: the proof is refused without being evaluated.
#[test]
fn a_proof_for_an_unknown_domain_is_refused() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    let sender = addr(0x23);
    let fee = bc.state.registry.params().proof_submission_fee;
    bc.state.add_balance(&sender, fee * 4);

    let err = bc
        .submit_zk_proof(submission(sender, 77, 10, &proof, &pi, &program))
        .unwrap_err();
    assert!(err.contains("unknown domain 77"), "gelen: {err}");
}

/// 1d (freshness): if a public input claims a height that is too old the proof is refused
/// before the proof system itself verifies it.
#[test]
fn a_proof_claiming_a_stale_block_height_is_rejected() {
    let mut bc = fresh_chain();
    let (proof, mut pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let sender = addr(0x31);
    pi.block_height = 100_000;

    let err = bc
        .submit_zk_proof(submission(sender, 1, 10, &proof, &pi, &program))
        .unwrap_err();
    assert!(
        err.contains("block height"),
        "the error must state the reason: {err}"
    );
}

/// 1e (continuity): an accepted proof carries the domain progress to its own final
/// root; a claim behind that progress is refused.
#[test]
fn acceptance_advances_the_domain_and_stale_claims_are_rejected() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let sender = addr(0x32);
    let fee = bc.state.registry.params().proof_submission_fee;
    bc.state.add_balance(&sender, fee * 4);

    let out = bc
        .submit_zk_proof(submission(sender, 1, 10, &proof, &pi, &program))
        .unwrap();
    assert!(matches!(out, ProofAcceptance::Accepted { .. }));

    let d = bc.domain_registry.get(1).expect("the domain is registered");
    assert_eq!(
        d.last_committed_height, 10,
        "acceptance has to carry the domain forward"
    );
    assert_eq!(
        d.last_committed_hash, pi.final_state_root,
        "the final root has to bind to the domain"
    );

    // The same proof claimed at an earlier height: refused at gate 1e without burning a fee.
    let err = bc
        .submit_zk_proof(submission(sender, 1, 9, &proof, &pi, &program))
        .unwrap_err();
    assert!(
        err.contains("stale zk claim"),
        "the error must state the reason: {err}"
    );

    // After the first acceptance that carries the progress, resubmitting at the same height
    // stays idempotent (gate 1e does not touch equality; the work belongs to the claim layer).
    let again = bc
        .submit_zk_proof(submission(sender, 1, 10, &proof, &pi, &program))
        .unwrap();
    assert_eq!(again, ProofAcceptance::Idempotent);
}

/// Exceeding the declared budget is refused.
///
/// `gas_limit` and `gas_used` are inside the public inputs and the binding hash:
/// the sender cannot change either afterwards. But nothing checked them **against each
/// went unchecked, a consistently signed overrun would be accepted.
///
/// The proof system does not constrain this relation - the STARK says "this program ran
/// this way with these inputs", not that the declared ceiling was respected. Nor does the allowlist:
/// it checks **which code** may run, whereas this checks whether that code stayed inside
/// the bound it declared.
#[test]
fn gas_used_above_the_declared_limit_is_refused() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let sender = addr(0x01);
    let fee = bc.state.registry.params().proof_submission_fee;
    bc.state.add_balance(&sender, fee * 4);
    let before = bc.state.get_balance(&sender);

    let mut overspent = pi.clone();
    overspent.gas_limit = 1_000;
    overspent.gas_used = 1_001;

    let err = bc
        .submit_zk_proof(submission(sender, 1, 10, &proof, &overspent, &program))
        .expect_err("exceeding the declared budget must be refused");
    assert!(
        err.contains("gas"),
        "the refusal must say that the budget was exceeded: {err}"
    );
    // The refusal comes before the fee: a refused proof does not touch the balance.
    assert_eq!(bc.state.get_balance(&sender), before);
}

/// 1g: the committed root has to be the value the proof constrains.
///
/// `final_state_root` becomes the domain's `last_committed_hash`; the AIR binds
/// it only to itself, so a prover can put anything there. The proven value is
/// `state_writes_digest`. A submission where the two differ is refused before the
/// fee, and the domain record does not move.
#[test]
fn a_final_root_that_is_not_the_proven_write_digest_is_refused() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let sender = addr(0x03);
    let fee = bc.state.registry.params().proof_submission_fee;
    bc.state.add_balance(&sender, fee * 4);
    let before = bc.state.get_balance(&sender);
    assert_eq!(
        pi.final_state_root, pi.state_writes_digest,
        "the producer must set the two equal, or this test measures the producer"
    );

    let mut forged = pi.clone();
    forged.final_state_root[0] ^= 0xFF;

    let err = bc
        .submit_zk_proof(submission(sender, 1, 10, &proof, &forged, &program))
        .expect_err("a root the circuit does not constrain must not be committed");
    assert!(
        err.contains("state_writes_digest"),
        "the refusal must name the proven field: {err}"
    );
    assert_eq!(
        bc.state.get_balance(&sender),
        before,
        "a shape refusal does not charge the fee"
    );
    let d = bc.domain_registry.get(1).expect("the domain is registered");
    assert_ne!(
        d.last_committed_hash, forged.final_state_root,
        "the forged root must not become the domain's root"
    );
    assert!(
        bc.proof_claims.is_empty(),
        "a refused submission must not leave a claim behind"
    );
}

/// Spending exactly at the ceiling is accepted: the bound was not exceeded.
///
/// Writing `>=` instead of `>` would refuse an honest program that spends exactly what it
/// reddederdi.
#[test]
fn spending_exactly_the_declared_limit_is_allowed() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let sender = addr(0x02);
    let fee = bc.state.registry.params().proof_submission_fee;
    bc.state.add_balance(&sender, fee * 4);

    let mut exact = pi.clone();
    exact.gas_limit = 5_000;
    exact.gas_used = 5_000;

    // The budget check must let this proof through. Proof verification may fail for other
    // reasons; what is measured is that the budget gate does not refuse wrongly.
    let outcome = bc.submit_zk_proof(submission(sender, 1, 10, &proof, &exact, &program));
    if let Err(e) = &outcome {
        assert!(
            !e.contains("declared limit"),
            "spending exactly at the ceiling must not trip the budget gate: {e}"
        );
    }
}
