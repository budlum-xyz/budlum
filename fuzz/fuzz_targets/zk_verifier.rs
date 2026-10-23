#![no_main]

//! ZK ProofEnvelope decode + verify robustness.
//!
//! Untrusted relayers/provers may submit arbitrary envelopes. Outcomes:
//! `Ok` (valid) or `Err(VerifyError)` are fine. Panic/abort/sanitizer
//! Findings are not. STARK verify on garbage input must fail closed.

use bud_proof::adapter::{VerifyError, PROOF_FORMAT_VERSION};
use bud_proof::canonical_set::program_hash_of;
use bud_proof::{DefaultAdapter as Prover, ExecutionPublicInputs, ProofEnvelope, ProverAdapter};
use libfuzzer_sys::fuzz_target;

// The exact strings `Plonky3Adapter::verify` requires.
const BACKEND: &str = "Plonky3-Keccak-Goldilocks";
const P3_VERSION: &str = "0.5.2";
const FRI_ID: &str = "test_fri_params";

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

fn take_text(data: &[u8], i: &mut usize, cap: usize) -> String {
    let n = take(data, i) as usize % cap;
    String::from_utf8_lossy(&take_n(data, i, n)).into_owned()
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

    // Mode 1 builds an envelope that passes every pre-STARK check, so the
    // proof bytes reach `postcard::from_bytes` and the STARK verifier. Mode 2
    // corrupts the stages named by a mask, so each early reject is also hit.
    let corrupt = if mode % 3 == 1 { 0u8 } else { take(data, &mut i) };
    let fuzz_version = take_u32(data, &mut i);
    let fuzz_backend = take_text(data, &mut i, 40);
    let fuzz_p3 = take_text(data, &mut i, 16);
    let fuzz_fri = take_text(data, &mut i, 24);
    let fuzz_hash = take_32(data, &mut i);
    let fuzz_degree = (take_u32(data, &mut i) % 32).max(1);

    let mut envelope = ProofEnvelope {
        proof_format_version: if corrupt & 1 != 0 { fuzz_version } else { PROOF_FORMAT_VERSION },
        backend: if corrupt & 2 != 0 { fuzz_backend } else { BACKEND.to_string() },
        p3_version: if corrupt & 4 != 0 { fuzz_p3 } else { P3_VERSION.to_string() },
        fri_params_id: if corrupt & 8 != 0 { fuzz_fri } else { FRI_ID.to_string() },
        public_inputs_hash: [0u8; 32],
        proof_bytes,
        degree_bits: fuzz_degree,
    };

    let mut inputs = ExecutionPublicInputs {
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
        trace_len: take_u64(data, &mut i) % 256,
        event_digest: take_32(data, &mut i),
        state_writes_digest: take_32(data, &mut i),
    };

    let prog_len = (take(data, &mut i) as usize % 16).min(8);
    let mut program = Vec::with_capacity(prog_len);
    for _ in 0..prog_len {
        program.push(take_u64(data, &mut i));
    }
    if corrupt & 16 == 0 {
        inputs.program_hash = program_hash_of(&program);
    }
    envelope.public_inputs_hash = if corrupt & 32 != 0 { fuzz_hash } else { inputs.hash() };

    // Serialize round-trip must not panic.
    if let Ok(bytes) = bincode::serialize(&envelope) {
        let _ = bincode::deserialize::<ProofEnvelope>(&bytes);
    }
    let _ = inputs.to_canonical_bytes();

    // Verify: expect Err on garbage; Ok only if somehow valid (still fine).
    let result = Prover::verify(&envelope, &inputs, &program);
    // A fully well-formed envelope must get past the metadata, public inputs
    // hash and program hash checks. If it does not, this target has stopped
    // reaching the proof decoder and the STARK verifier.
    // The verifier refuses non-canonical Goldilocks scalars before any hash
    // check, so a well-formed envelope is one whose scalars are canonical.
    const GOLDILOCKS_P: u64 = 0xFFFF_FFFF_0000_0001;
    let canonical = [
        inputs.chain_id,
        inputs.sender,
        inputs.nonce,
        inputs.block_height,
        inputs.gas_limit,
        inputs.gas_used,
        inputs.exit_code,
        inputs.trace_len,
    ]
    .iter()
    .all(|&v| v < GOLDILOCKS_P);
    if corrupt & 0x3f == 0 && canonical {
        match &result {
            Err(VerifyError::PublicInputsMismatch) => {
                panic!("well-formed envelope stopped at a hash check")
            }
            Err(VerifyError::InvalidEnvelope(msg)) => assert!(
                !msg.starts_with("Unsupported"),
                "well-formed envelope stopped at the metadata check: {msg}"
            ),
            _ => {}
        }
    }
    match result {
        Ok(()) => {}
        Err(VerifyError::DeserializationError(_))
        | Err(VerifyError::InvalidEnvelope(_))
        | Err(VerifyError::PublicInputsMismatch)
        | Err(VerifyError::InvalidProof)
        // A report pinned to a non-canonical program set is a legitimate
        // rejection, not a sanitizer event; the relayer folds it into an
        // alarm instead of panicking, so the fuzzer accepts it.
        | Err(VerifyError::NonCanonicalProgram(_)) => {}
    }
});
