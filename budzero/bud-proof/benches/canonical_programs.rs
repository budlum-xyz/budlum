// Canonical-program benchmark: prove/verify times for the three programs the
// regeneration gate reproduces from the specification.
//
//   * storage challenge      (VerifyMerkle + Halt, 2 instructions)
//   * private-transfer check (bud-vm canonical schema, 12 instructions)
//   * matmul guest [2,3,2]   (90 instructions)
//
// The matmul stream is reproduced here by a small independent emitter (the
// layout and emission rules of `build_matmul_guest_program`), so this file
// stays free of the `budlum-core` dependency; it is a measurement harness,
// not a fourth producer — the canonical identity is pinned in the tree and
// the regeneration gate, not here.
//
// Output is one JSON line per program so CI or the workspace can record the
// numbers: {"benchmark":"budzero-canonical-<name>-v1","trace_rows":..,
// "proof_bytes":..,"prove_seconds_mean":..,"verify_seconds_mean":..}
//
// Integration bench: an unwrap here reports a broken invariant, so the
// workspace-wide panic gate does not apply.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use bud_isa::{Instruction, Opcode};
use bud_proof::{ExecutionPublicInputs, Plonky3Adapter, ProverAdapter};
use bud_vm::{private_transfer, Vm};
use std::time::{Duration, Instant};
use tiny_keccak::{Hasher, Keccak};

fn instruction(opcode: Opcode, rd: u8, rs1: u8, rs2: u8, imm: i32) -> u64 {
    Instruction {
        opcode,
        rd,
        rs1,
        rs2,
        imm,
    }
    .encode()
}

fn program_hash(program: &[u64]) -> [u8; 32] {
    let bytes: Vec<u8> = program.iter().flat_map(|word| word.to_le_bytes()).collect();
    let mut hasher = Keccak::v256();
    hasher.update(&bytes);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

fn average(total: Duration, samples: u32) -> f64 {
    total.as_secs_f64() / f64::from(samples)
}

fn storage_challenge_program() -> Vec<u64> {
    vec![
        instruction(Opcode::VerifyMerkle, 1, 2, 3, 256),
        instruction(Opcode::Halt, 0, 0, 0, 0),
    ]
}

/// Independent mini-emitter of the matmul guest program for dims [2, 3, 2]
/// (weights 2x3 + 3x2, biases 3 + 2). Same layout and emission rules as the
/// canonical builder; used here only to drive the prover.
fn matmul_guest_program_2_3_2() -> Vec<u64> {
    const R_ZERO: u8 = 1;
    const R_ONE: u8 = 2;
    const R_HALF: u8 = 3;
    const R_ACC: u8 = 4;
    const R_W: u8 = 5;
    const R_X: u8 = 6;
    const R_T: u8 = 7;
    const R_SEL: u8 = 8;
    const R_HASH: u8 = 9;
    const MAX_WIDTH: usize = 64;

    let byte_addr = |word: usize| -> i32 {
        let addr = word * 8;
        assert!(addr + 8 <= 8192, "guest address out of memory");
        i32::try_from(addr).unwrap()
    };

    let mut prog: Vec<u64> = Vec::new();
    // Prologue: r0=0 via Load+Sub, r1=1, r3=(P-1)/2, r9=0.
    prog.push(instruction(Opcode::Load, R_ZERO, 0, 0, 0));
    prog.push(instruction(Opcode::Sub, R_ZERO, R_ZERO, R_ZERO, 0));
    prog.push(instruction(Opcode::Load, R_ONE, 0, 0, 1));
    let pow30: i32 = 1 << 30;
    prog.push(instruction(Opcode::Load, R_HALF, 0, 0, pow30));
    prog.push(instruction(Opcode::Mul, R_HALF, R_HALF, R_HALF, 0));
    prog.push(instruction(Opcode::Load, R_T, 0, 0, 8));
    prog.push(instruction(Opcode::Mul, R_HALF, R_HALF, R_T, 0));
    prog.push(instruction(Opcode::Load, R_T, 0, 0, i32::MAX));
    prog.push(instruction(Opcode::Add, R_T, R_T, R_ONE, 0));
    prog.push(instruction(Opcode::Sub, R_HALF, R_HALF, R_T, 0));
    prog.push(instruction(Opcode::Add, R_HASH, R_ZERO, R_ZERO, 0));

    // dims [2,3,2]: input 0..2, weights 2..14, biases 14..19,
    // act_in 19..83, act_out 83..147, output 147..149.
    let weight_base = 2usize;
    let bias_base = 14usize;
    let act_in_base = 19usize;
    let act_out_base = act_in_base + MAX_WIDTH;
    let output_base = act_out_base + MAX_WIDTH;

    // Hidden layer: 2 -> 3.
    let mut w_off = 0usize;
    for o in 0..3usize {
        let bias = byte_addr(bias_base + o);
        prog.push(instruction(Opcode::Load, R_ACC, R_ZERO, 0, bias));
        for i in 0..2usize {
            let w = byte_addr(weight_base + w_off + o * 2 + i);
            let x = byte_addr(act_in_base + i);
            prog.push(instruction(Opcode::Load, R_W, R_ZERO, 0, w));
            prog.push(instruction(Opcode::Load, R_X, R_ZERO, 0, x));
            prog.push(instruction(Opcode::Mul, R_T, R_W, R_X, 0));
            prog.push(instruction(Opcode::Add, R_ACC, R_ACC, R_T, 0));
        }
        // ReLU.
        prog.push(instruction(Opcode::Gt, R_SEL, R_ACC, R_HALF, 0));
        prog.push(instruction(Opcode::Sub, R_SEL, R_ONE, R_SEL, 0));
        prog.push(instruction(Opcode::Mul, R_ACC, R_ACC, R_SEL, 0));
        let dst = byte_addr(act_out_base + o);
        prog.push(instruction(Opcode::Store, 0, R_ZERO, R_ACC, dst));
    }
    // pong -> ping.
    for o in 0..3usize {
        let src = byte_addr(act_out_base + o);
        let dst = byte_addr(act_in_base + o);
        prog.push(instruction(Opcode::Load, R_T, R_ZERO, 0, src));
        prog.push(instruction(Opcode::Store, 0, R_ZERO, R_T, dst));
    }
    w_off += 2 * 3;

    // Output layer: 3 -> 2.
    for o in 0..2usize {
        let bias = byte_addr(bias_base + 3 + o);
        prog.push(instruction(Opcode::Load, R_ACC, R_ZERO, 0, bias));
        for i in 0..3usize {
            let w = byte_addr(weight_base + w_off + o * 3 + i);
            let x = byte_addr(act_in_base + i);
            prog.push(instruction(Opcode::Load, R_W, R_ZERO, 0, w));
            prog.push(instruction(Opcode::Load, R_X, R_ZERO, 0, x));
            prog.push(instruction(Opcode::Mul, R_T, R_W, R_X, 0));
            prog.push(instruction(Opcode::Add, R_ACC, R_ACC, R_T, 0));
        }
        let dst = byte_addr(act_out_base + o);
        prog.push(instruction(Opcode::Store, 0, R_ZERO, R_ACC, dst));
        let out = byte_addr(output_base + o);
        prog.push(instruction(Opcode::Store, 0, R_ZERO, R_ACC, out));
        prog.push(instruction(Opcode::Poseidon, R_HASH, R_HASH, R_ACC, 0));
    }

    prog.push(instruction(Opcode::Log, 0, R_HASH, 0, 0));
    prog.push(instruction(Opcode::Halt, 0, 0, 0, 0));
    assert_eq!(prog.len(), 90, "matmul [2,3,2] must be 90 instructions");
    prog
}

fn run_one(name: &str, program: &[u64], samples: u32) {
    let mut prove_total = Duration::ZERO;
    let mut verify_total = Duration::ZERO;
    let mut proof_bytes = 0usize;
    let mut trace_rows = 0usize;

    for _ in 0..samples {
        let mut vm = Vm::new(8192);
        let receipt = vm.run_receipt(program);
        assert!(receipt.success, "{name} execution failed");
        trace_rows = vm.trace.len();

        let initial_state_root = bud_proof::initial_state_root_of(
            bud_proof::memory_image_commitment_of_reads(&bud_proof::initial_memory_reads(
                &vm.trace,
            )),
            bud_proof::register_image_commitment_of_reads(&bud_proof::initial_register_reads(
                &vm.trace,
            )),
        );

        let inputs = ExecutionPublicInputs {
            chain_id: 1,
            program_hash: program_hash(program),
            initial_state_root,
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: receipt.exit_code,
            trace_len: vm.trace.len() as u64,
            event_digest: bud_proof::event_digest_from_events(&receipt.events),
            state_writes_digest: receipt.state_writes_digest,
        };

        let started = Instant::now();
        let proof = Plonky3Adapter::prove(&vm.trace, &inputs, program)
            .expect("canonical proof generation failed");
        prove_total += started.elapsed();
        proof_bytes = proof.proof_bytes.len();

        let started = Instant::now();
        Plonky3Adapter::verify(&proof, &inputs, program)
            .expect("canonical proof verification failed");
        verify_total += started.elapsed();
    }

    println!(
        "{{\"benchmark\":\"budzero-canonical-{name}-v1\",\"samples\":{samples},\"trace_rows\":{trace_rows},\"proof_bytes\":{proof_bytes},\"prove_seconds_mean\":{:.6},\"verify_seconds_mean\":{:.6}}}",
        average(prove_total, samples),
        average(verify_total, samples),
    );
}

fn main() {
    let samples = std::env::var("BUDZERO_BENCH_SAMPLES")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(1)
        .clamp(1, 20);

    run_one("storage-challenge", &storage_challenge_program(), samples);
    run_one(
        "private-transfer",
        &private_transfer::build_private_transfer_check_program().unwrap(),
        samples,
    );
    run_one("matmul-2-3-2", &matmul_guest_program_2_3_2(), samples);
}
