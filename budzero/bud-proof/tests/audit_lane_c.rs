//! Lane C live-verification regression tests for `bud-proof` (WP-03).
//!
//! Previously fixed findings only: every test is green and stays permanent
//! (directive section 14.1 rule 7).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use bud_isa::{Instruction, MainnetActivation, Opcode};
use bud_proof::adapter::{ExecutionPublicInputs, ProofEnvelope, ProverAdapter};
use bud_proof::{DefaultAdapter as Prover, Plonky3Adapter};
use bud_vm::Vm;
use tiny_keccak::{Hasher, Keccak};

const GOLDILOCKS_P: u64 = 0xFFFF_FFFF_0000_0001;

fn inst(opcode: Opcode, rd: u8, rs1: u8, rs2: u8, imm: i32) -> u64 {
    Instruction { opcode, rd, rs1, rs2, imm }.encode()
}

fn program_hash(program: &[u64]) -> [u8; 32] {
    let mut bytes = Vec::new();
    for w in program {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    let mut out = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(&bytes);
    k.finalize(&mut out);
    out
}

fn honest_inputs(vm: &Vm, program: &[u64], events: &[u64]) -> ExecutionPublicInputs {
    ExecutionPublicInputs {
        chain_id: 1,
        program_hash: program_hash(program),
        initial_state_root: bud_proof::initial_state_root_of(
            bud_proof::memory_image_commitment_of_reads(&bud_proof::initial_memory_reads(&vm.trace)),
            bud_proof::register_image_commitment_of_reads(&bud_proof::initial_register_reads(&vm.trace)),
        ),
        final_state_root: [0u8; 32],
        sender: vm.context.sender,
        nonce: vm.context.nonce,
        block_height: vm.context.block_height,
        gas_limit: vm.gas_limit,
        gas_used: vm.gas_used,
        exit_code: 0,
        trace_len: vm.trace.len() as u64,
        event_digest: bud_proof::event_digest_from_events(events),
        state_writes_digest: [0u8; 32],
    }
}

fn logging_run() -> (Vec<u64>, Vm, Vec<u64>) {
    let program = vec![
        inst(Opcode::Load, 1, 0, 0, 7),
        inst(Opcode::Log, 0, 1, 0, 0),
        inst(Opcode::Halt, 0, 0, 0, 0),
    ];
    let mut vm = Vm::new(1024);
    let receipt = vm.run_receipt(&program);
    assert!(receipt.success, "the honest program must run");
    let events = receipt.events.clone();
    (program, vm, events)
}

/// Prove with the (possibly forged) inputs baked in, then verify with the same inputs.
fn prove_and_verify(vm: &Vm, pi: &ExecutionPublicInputs, program: &[u64]) -> Result<(), String> {
    let envelope = Prover::prove(&vm.trace, pi, program).map_err(|e| format!("prove refused: {e:?}"))?;
    Prover::verify(&envelope, pi, program).map_err(|e| format!("verify refused: {e:?}"))
}

#[test]
fn audit_lane_c_blg_039_control_honest_logging_proof_is_accepted() {
    let (program, vm, events) = logging_run();
    let pi = honest_inputs(&vm, &program, &events);
    prove_and_verify(&vm, &pi, &program).expect("control: the honest proof must verify");
}

/// BLG-037: no trace containing the reserved VerifyInference opcode can be proven.
#[test]
fn audit_lane_c_blg_037_verify_inference_is_refused_in_any_trace() {
    let model_c = 0xABCD_EF01_2345_6789u64;
    let input_c = 0x1122_3344_5566_7788u64;
    let output_c = bud_vm::poseidon4_hash(model_c, input_c);
    let program = vec![
        inst(Opcode::VerifyInference, 2, 1, 0, 0),
        inst(Opcode::Halt, 0, 0, 0, 0),
    ];
    let mut vm = Vm::new(1024);
    vm.memory[64..72].copy_from_slice(&model_c.to_le_bytes());
    vm.memory[72..80].copy_from_slice(&input_c.to_le_bytes());
    vm.memory[80..88].copy_from_slice(&output_c.to_le_bytes());
    vm.registers[1] = 64;
    let receipt = vm.run_receipt(&program);
    assert!(receipt.success);
    assert!(vm.trace.iter().any(|s| s.instruction.opcode == Opcode::VerifyInference));
    let pi = honest_inputs(&vm, &program, &receipt.events);
    let res = Plonky3Adapter::prove(&vm.trace, &pi, &program)
        .map_err(|e| format!("prove refused: {e:?}"))
        .and_then(|envelope| {
            Plonky3Adapter::verify_with_activation(&envelope, &pi, &program, MainnetActivation::full())
                .map_err(|e| format!("verify refused: {e:?}"))
        });
    let err = res.expect_err("a trace with VerifyInference must be refused");
    assert!(err.starts_with("verify refused"), "the AIR must refuse it, got {err}");
}

/// BLG-039 / BLG-142: absurd claimed sizes are refused, never a panic.
#[test]
fn audit_lane_c_blg_039_oversized_claims_are_refused_not_fatal() {
    let (program, vm, events) = logging_run();
    let pi = honest_inputs(&vm, &program, &events);
    let envelope = Prover::prove(&vm.trace, &pi, &program).expect("honest proof");
    let mut huge = pi.clone();
    huge.trace_len = u64::MAX;
    let mut forged: ProofEnvelope = envelope.clone();
    forged.public_inputs_hash = huge.hash();
    assert!(Prover::verify(&forged, &huge, &program).is_err(), "trace_len = u64::MAX must be refused");
    let mut deep = envelope.clone();
    deep.degree_bits = 255;
    assert!(Prover::verify(&deep, &pi, &program).is_err(), "degree_bits = 255 must be refused");
}

/// BLG-186: a public scalar at or above the Goldilocks modulus aliases `x - p`.
#[test]
fn audit_lane_c_blg_186_non_canonical_public_scalars_are_refused() {
    let (program, vm, events) = logging_run();
    let pi = honest_inputs(&vm, &program, &events);
    let envelope = Prover::prove(&vm.trace, &pi, &program).expect("honest proof");
    type Alias = fn(&mut ExecutionPublicInputs);
    let aliases: Vec<(&str, Alias)> = vec![
        ("sender", |p| p.sender = p.sender.wrapping_add(GOLDILOCKS_P)),
        ("nonce", |p| p.nonce = p.nonce.wrapping_add(GOLDILOCKS_P)),
        ("block_height", |p| p.block_height = p.block_height.wrapping_add(GOLDILOCKS_P)),
        ("gas_used", |p| p.gas_used = p.gas_used.wrapping_add(GOLDILOCKS_P)),
    ];
    for (name, alias) in aliases {
        let mut forged_pi = pi.clone();
        alias(&mut forged_pi);
        let mut forged = envelope.clone();
        forged.public_inputs_hash = forged_pi.hash();
        assert!(
            Prover::verify(&forged, &forged_pi, &program).is_err(),
            "`{name} + p` verified as an alias of `{name}`"
        );
    }
}
