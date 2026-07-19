#![no_main]

//! Phase 11.2 Görev 3 — ZK ProofEnvelope decode + verify robustness.
//!
//! Untrusted relayers/provers may submit arbitrary envelopes. Outcomes:
//! `Ok(())` (valid) or `Err(VerifyError)` are fine. Panic/abort/sanitizer
//! findings are not. STARK verify on garbage input must fail closed.

use bud_proof::adapter::VerifyError;
use bud_proof::{DefaultAdapter as Prover, ExecutionPublicInputs, ProofEnvelope, ProverAdapter};
use libfuzzer_sys::fuzz_target;

fn take(data: &[u8], i: &mut usize) -> u8 {
    let b = data.get(*i).copied().unwrap_or(0);
    *i = i.saturating_add(1);
    b
}

fn take_n(data: &[u8], i: &mut usize, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(take(data, i));
    }
    out
}

fn take_32(data: &[u8], i: &mut usize) -> [u8; 32] {
    let mut a = [0u8; 32];
    for byte in &mut a {
        *byte = take(data, i);
    }
    a
}

fn take_u64(data: &[u8], i: &mut usize) -> u64 {
    let mut b = [0u8; 8];
    for slot in &mut b {
        *slot = take(data, i);
    }
    u64::from_le_bytes(b)
}

fn take_u32(data: &[u8], i: &mut usize) -> u32 {
    let mut b = [0u8; 4];
    for slot in &mut b {
        *slot = take(data, i);
    }
    u32::from_le_bytes(b)
}

fuzz_target!(|data: &[u8]| {
    let mut i = 0usize;
    let mode = take(data, &mut i);

    // Mode 0: raw bincode deserialize of entire leftover buffer as ProofEnvelope.
    if mode % 3 == 0 {
        let rest = if i < data.len() { &data[i..] } else { &[] };
        let _ = bincode::deserialize::<ProofEnvelope>(rest);
        // Also try ExecutionPublicInputs
        let _ = bincode::deserialize::<ExecutionPublicInputs>(rest);
        return;
    }

    // Mode 1/2: structured envelope + public inputs + short program.
    let proof_len = (take(data, &mut i) as usize % 64) + (take(data, &mut i) as usize % 256);
    // Cap proof bytes to keep STARK path bounded (invalid proofs exit early).
    let proof_len = proof_len.min(512);
    let proof_bytes = take_n(data, &mut i, proof_len);

    let envelope = ProofEnvelope {
        proof_format_version: take_u32(data, &mut i),
        backend: {
            let n = (take(data, &mut i) % 16) as usize;
            String::from_utf8_lossy(&take_n(data, &mut i, n)).into_owned()
        },
        p3_version: {
            let n = (take(data, &mut i) % 12) as usize;
            String::from_utf8_lossy(&take_n(data, &mut i, n)).into_owned()
        },
        fri_params_id: {
            let n = (take(data, &mut i) % 12) as usize;
            String::from_utf8_lossy(&take_n(data, &mut i, n)).into_owned()
        },
        public_inputs_hash: take_32(data, &mut i),
        proof_bytes,
        degree_bits: (take_u32(data, &mut i) % 32).max(1),
    };

    let inputs = ExecutionPublicInputs {
        chain_id: take_u64(data, &mut i),
        program_hash: take_32(data, &mut i),
        initial_state_root: take_32(data, &mut i),
        final_state_root: take_32(data, &mut i),
        sender: take_u64(data, &mut i),
        nonce: take_u64(data, &mut i),
        block_height: take_u64(data, &mut i),
        gas_limit: take_u64(data, &mut i),
        gas_used: take_u64(data, &mut i),
        exit_code: take_u64(data, &mut i),
        trace_len: take_u64(data, &mut i) % 1024,
        event_digest: take_32(data, &mut i),
    };

    let prog_len = (take(data, &mut i) as usize % 16).min(8);
    let mut program = Vec::with_capacity(prog_len);
    for _ in 0..prog_len {
        program.push(take_u64(data, &mut i));
    }

    // Serialize round-trip must not panic.
    if let Ok(bytes) = bincode::serialize(&envelope) {
        let _ = bincode::deserialize::<ProofEnvelope>(&bytes);
    }
    let _ = inputs.hash();
    let _ = inputs.to_canonical_bytes();

    // Verify: expect Err on garbage; Ok only if somehow valid (still fine).
    match Prover::verify(&envelope, &inputs, &program) {
        Ok(()) => {}
        Err(VerifyError::DeserializationError(_))
        | Err(VerifyError::InvalidEnvelope(_))
        | Err(VerifyError::PublicInputsMismatch)
        | Err(VerifyError::InvalidProof) => {}
    }
});
