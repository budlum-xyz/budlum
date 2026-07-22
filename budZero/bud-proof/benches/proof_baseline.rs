use bud_isa::{Instruction, Opcode};
use bud_proof::{ExecutionPublicInputs, Plonky3Adapter, ProverAdapter};
use bud_vm::Vm;
use std::time::{Duration, Instant};
use tiny_keccak::{Hasher, Keccak};

fn instruction(opcode: Opcode, rd: u8, rs1: u8, rs2: u8) -> u64 {
    Instruction {
        opcode,
        rd,
        rs1,
        rs2,
        imm: 0,
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

fn main() {
    let samples = std::env::var("BUDZERO_BENCH_SAMPLES")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(1)
        .clamp(1, 20);
    let program = vec![
        instruction(Opcode::Add, 1, 2, 3),
        instruction(Opcode::Mul, 4, 1, 3),
        instruction(Opcode::Halt, 0, 0, 0),
    ];

    let mut prove_total = Duration::ZERO;
    let mut verify_total = Duration::ZERO;
    let mut proof_bytes = 0usize;
    let mut trace_rows = 0usize;

    for _ in 0..samples {
        let mut vm = Vm::new(64);
        vm.registers[2] = 10;
        vm.registers[3] = 20;
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success, "baseline VM execution failed");
        trace_rows = vm.trace.len();

        let inputs = ExecutionPublicInputs {
            chain_id: 1,
            program_hash: program_hash(&program),
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: receipt.exit_code,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
        };

        let started = Instant::now();
        let proof = Plonky3Adapter::prove(&vm.trace, &inputs, &program)
            .expect("baseline proof generation failed");
        prove_total += started.elapsed();
        proof_bytes = proof.proof_bytes.len();

        let started = Instant::now();
        Plonky3Adapter::verify(&proof, &inputs, &program)
            .expect("baseline proof verification failed");
        verify_total += started.elapsed();
    }

    println!(
        "{{\"benchmark\":\"budzero-proof-baseline-v1\",\"samples\":{samples},\"trace_rows\":{trace_rows},\"proof_bytes\":{proof_bytes},\"prove_seconds_mean\":{:.6},\"verify_seconds_mean\":{:.6}}}",
        average(prove_total, samples),
        average(verify_total, samples),
    );
}
