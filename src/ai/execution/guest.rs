//! Fixed-point MLP guest + host evaluator for BudZKVM AI execution.
//!
//! Hardening goals:
//! - Bit-exact host forward pass (i32 MAC, ReLU)
//! - Domain-separated input/output commitments
//! - Guest bytecode computes the forward pass in-VM over a host-published
//!   memory image, and its result is checked against the host evaluator
//! - Optional STARK prove/verify via ZkVmExecutor / DefaultAdapter

use super::model_class::{AiExecutionModelClass, MAX_MLP_LAYERS, MAX_MLP_PARAMS, MAX_MLP_WIDTH};
use bud_isa::{Instruction, Opcode};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

pub const MLP_GUEST_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixedPointMlpSpec {
    /// Layer sizes: input_dim, hidden..., output_dim (len = layers+1).
    pub dims: Vec<u16>,
    /// Row-major weights per layer, concatenated.
    pub weights: Vec<i32>,
    pub biases: Vec<i32>,
}

impl FixedPointMlpSpec {
    pub fn validate(&self) -> Result<(), String> {
        if self.dims.len() < 2 || self.dims.len() > MAX_MLP_LAYERS + 1 {
            return Err(format!(
                "dims length must be 2..={} (got {})",
                MAX_MLP_LAYERS + 1,
                self.dims.len()
            ));
        }
        for &d in &self.dims {
            if d == 0 || d as usize > MAX_MLP_WIDTH {
                return Err(format!("layer dim {d} out of 1..={MAX_MLP_WIDTH}"));
            }
        }
        let mut expected_w = 0usize;
        let mut expected_b = 0usize;
        for w in self.dims.windows(2) {
            expected_w = expected_w
                .checked_add(w[0] as usize * w[1] as usize)
                .ok_or("weights size overflow")?;
            expected_b = expected_b
                .checked_add(w[1] as usize)
                .ok_or("bias size overflow")?;
        }
        if self.weights.len() != expected_w {
            return Err(format!(
                "weights len {} != expected {expected_w}",
                self.weights.len()
            ));
        }
        if self.biases.len() != expected_b {
            return Err(format!(
                "biases len {} != expected {expected_b}",
                self.biases.len()
            ));
        }
        if self.weights.len() + self.biases.len() > MAX_MLP_PARAMS {
            return Err("total params exceed MAX_MLP_PARAMS".into());
        }
        // The class limits (width, layers, params) are not the binding
        // constraint - guest memory is, and it bites much earlier. A 32x32
        // layer is 1056 params (well under MAX_MLP_PARAMS) but needs 9984
        // bytes of guest memory against the VM's 8192. Rejecting here means a
        // spec that validates can always be built and run; otherwise the
        // failure surfaced later as a truncated or zero-filled forward pass.
        let words = self.guest_memory_words()?;
        if words * WORD_BYTES > GUEST_MEMORY_BYTES {
            return Err(format!(
                "model needs {} bytes of guest memory > GUEST_MEMORY_BYTES {} \
                 (params {} are within MAX_MLP_PARAMS {}, memory is the binding limit)",
                words * WORD_BYTES,
                GUEST_MEMORY_BYTES,
                self.weights.len() + self.biases.len(),
                MAX_MLP_PARAMS
            ));
        }
        Ok(())
    }

    /// Total guest memory words this model needs, in the layout
    /// [`GuestMemoryLayout`] publishes. Shape-only: callable before the rest
    /// of `validate` has run.
    fn guest_memory_words(&self) -> Result<usize, String> {
        let input = self.input_dim();
        let output = self.output_dim();
        input
            .checked_add(self.weights.len())
            .and_then(|v| v.checked_add(self.biases.len()))
            .and_then(|v| v.checked_add(2 * MAX_MLP_WIDTH))
            .and_then(|v| v.checked_add(output))
            .ok_or_else(|| "guest memory word count overflow".to_string())
    }

    pub fn model_class(&self) -> AiExecutionModelClass {
        AiExecutionModelClass::FixedPointMlpV1
    }

    // `dims` is deserialized from a registered model spec, so an empty vector is
    // Representable on the wire even though `validate` rejects it. Indexing
    // With `[0]` / `.last.unwrap` therefore turns a malformed spec into a
    // Panic in whichever task touches it first. Both accessors now fold the
    // Empty case to 0, which callers already treat as an invalid dimension -
    // The spec is rejected instead of taking the process down.
    pub fn input_dim(&self) -> usize {
        self.dims.first().copied().unwrap_or(0) as usize
    }

    pub fn output_dim(&self) -> usize {
        self.dims.last().copied().unwrap_or(0) as usize
    }
}

/// Bit-exact fixed-point forward pass: y = ReLU(W x + b) per hidden layer;
/// Final layer is linear (no ReLU) so regression outputs can be negative.
pub fn eval_fixed_point_mlp(spec: &FixedPointMlpSpec, input: &[i32]) -> Result<Vec<i32>, String> {
    spec.validate()?;
    if input.len() != spec.input_dim() {
        return Err(format!(
            "input len {} != expected {}",
            input.len(),
            spec.input_dim()
        ));
    }
    let mut activations = input.to_vec();
    let mut w_off = 0usize;
    let mut b_off = 0usize;
    let n_layers = spec.dims.len() - 1;
    for (layer_idx, w) in spec.dims.windows(2).enumerate() {
        let in_d = w[0] as usize;
        let out_d = w[1] as usize;
        let mut next = vec![0i32; out_d];
        for (o, slot) in next.iter_mut().enumerate() {
            let mut acc = i64::from(spec.biases[b_off + o]);
            for (i, act) in activations.iter().take(in_d).enumerate() {
                let weight = spec.weights[w_off + o * in_d + i];
                acc = acc
                    .checked_add(i64::from(weight) * i64::from(*act))
                    .ok_or("MAC overflow")?;
            }
            // Saturate to i32
            let mut v = acc.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32;
            // ReLU on hidden layers only
            if layer_idx + 1 < n_layers && v < 0 {
                v = 0;
            }
            *slot = v;
        }
        w_off += in_d * out_d;
        b_off += out_d;
        activations = next;
    }
    Ok(activations)
}

/// Domain-separated commitment over i32 limbs (LE).
pub fn commit_i32_limbs(tag: &[u8], limbs: &[i32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(tag);
    h.update((limbs.len() as u64).to_le_bytes());
    for x in limbs {
        h.update(x.to_le_bytes());
    }
    h.finalize().into()
}

pub fn input_commitment(limbs: &[i32]) -> [u8; 32] {
    commit_i32_limbs(b"BDLM_AI_INPUT_V1", limbs)
}

pub fn output_commitment(limbs: &[i32]) -> [u8; 32] {
    commit_i32_limbs(b"BDLM_AI_OUTPUT_V1", limbs)
}

fn inst(op: Opcode, rd: u8, rs1: u8, rs2: u8, imm: i32) -> u64 {
    Instruction {
        opcode: op,
        rd,
        rs1,
        rs2,
        imm,
    }
    .encode()
}

pub fn weights_digest(spec: &FixedPointMlpSpec) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_AI_MLP_WEIGHTS_V1");
    h.update(MLP_GUEST_VERSION.to_le_bytes());
    h.update((spec.dims.len() as u64).to_le_bytes());
    for d in &spec.dims {
        h.update(d.to_le_bytes());
    }
    for w in &spec.weights {
        h.update(w.to_le_bytes());
    }
    for b in &spec.biases {
        h.update(b.to_le_bytes());
    }
    h.finalize().into()
}

/// Commitment-only guest: binds `weights_digest` and `input_commitment` into
/// the execution trace via Poseidon, then halts. It does **not** compute the
/// forward pass - [`build_matmul_guest_program`] does that.
///
/// A digest limb is 64 bits and `imm` is 32, so each limb is loaded in two
/// halves and recombined (`hi * 2^32 + lo`). The previous version masked each
/// limb down to its low 31 bits, which left ~31 bits of the commitment bound
/// instead of 64 and put a birthday collision within reach of roughly 2^15.5
/// attempts.
pub fn build_fixed_point_mlp_guest(
    spec: &FixedPointMlpSpec,
    input_commit: &[u8; 32],
) -> Result<Vec<u64>, String> {
    spec.validate()?;
    let wdig = weights_digest(spec);
    // Pack first 8 bytes of each digest as u64 LE field elements for Poseidon.
    // Both digests are 32-byte arrays, so the first eight bytes always exist;
    // read them as fixed-size arrays so there is no fallible conversion.
    let mut w_head = [0u8; 8];
    w_head.copy_from_slice(&wdig[0..8]);
    let mut i_head = [0u8; 8];
    i_head.copy_from_slice(&input_commit[0..8]);
    let w_limb = u64::from_le_bytes(w_head);
    let i_limb = u64::from_le_bytes(i_head);

    let mut prog = Vec::with_capacity(16);
    // r10 = 2^32, the shift used to rebuild a 64-bit limb from two halves.
    prog.push(inst(Opcode::Load, 10, 0, 0, i32::MAX));
    prog.push(inst(Opcode::Load, 11, 0, 0, 1));
    prog.push(inst(Opcode::Add, 10, 10, 11, 0)); // 2^31
    prog.push(inst(Opcode::Add, 10, 10, 10, 0)); // 2^32
    emit_load_u64_limb(&mut prog, 1, w_limb);
    emit_load_u64_limb(&mut prog, 2, i_limb);
    prog.push(inst(Opcode::Poseidon, 3, 1, 2, 0));
    prog.push(inst(Opcode::Log, 0, 3, 0, 0));
    prog.push(inst(Opcode::Halt, 0, 0, 0, 0));
    Ok(prog)
}

/// Emit `dst = value` for a full 64-bit `value`, using r10 = 2^32 and r11 as
/// scratch. Both halves are loaded as non-negative 32-bit chunks so the
/// two's-complement / field-encoding mismatch cannot appear.
fn emit_load_u64_limb(prog: &mut Vec<u64>, dst: u8, value: u64) {
    let hi = (value >> 32) as u32;
    let lo = (value & 0xffff_ffff) as u32;
    let split = |half: u32, prog: &mut Vec<u64>, reg: u8| {
        // A u32 does not fit in i32 when its top bit is set, so load it as
        // (half - 2^31) + 2^31 when needed.
        if half <= i32::MAX as u32 {
            prog.push(inst(Opcode::Load, reg, 0, 0, half as i32));
        } else {
            prog.push(inst(Opcode::Load, reg, 0, 0, (half - (1 << 31)) as i32));
            prog.push(inst(Opcode::Load, 12, 0, 0, i32::MAX));
            prog.push(inst(Opcode::Add, 12, 12, 11, 0));
            prog.push(inst(Opcode::Add, reg, reg, 12, 0));
        }
    };
    split(hi, prog, dst);
    prog.push(inst(Opcode::Mul, dst, dst, 10, 0));
    split(lo, prog, 13);
    prog.push(inst(Opcode::Add, dst, dst, 13, 0));
}

pub fn program_hash_from_words(words: &[u64]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_AI_GUEST_PROGRAM_V1");
    h.update(MLP_GUEST_VERSION.to_le_bytes());
    for w in words {
        h.update(w.to_le_bytes());
    }
    h.finalize().into()
}

/// The program hash the STARK actually binds.
///
/// [`program_hash_from_words`] is a *registry* identifier: SHA3-256 over a
/// domain tag, the guest version and the words, so a model's registration can
/// name its guest program without colliding with anything else in the tree.
/// The proof system uses a different one - `ExecutionPublicInputs::program_hash`
/// is an unlabelled Keccak-256 over the same words
/// (`crate::execution::zkvm`), and that is the value the AIR is checked
/// against.
///
/// Both are legitimate, and they are not interchangeable. `prove_mlp_inference`
/// used to put the registry hash in `AiExecutionProof::program_hash` while the
/// envelope carried the proof-system one, so `verify_execution_proof_stark`
/// compared the two and failed every time:
///
/// ```text
/// SONUC: Err("execution proof program_hash != public_inputs.program_hash")
/// ```
///
/// Everything else in that measurement lined up, the verifier rebuilt the
/// program, the public-inputs hash matched, and the independently derived
/// `initial_state_root` matched - so this single mismatch was the whole reason
/// the STARK path could not run.
#[must_use]
pub fn stark_program_hash_from_words(words: &[u64]) -> [u8; 32] {
    use sha3::Keccak256;
    let mut hasher = Keccak256::new();
    for word in words {
        hasher.update(word.to_le_bytes());
    }
    hasher.finalize().into()
}

pub fn words_to_bytecode(words: &[u64]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// End-to-end: eval MLP, build guest, STARK-prove, package AiExecutionProof.
pub fn prove_mlp_inference(
    spec: &FixedPointMlpSpec,
    model_id: crate::ai::types::AiModelId,
    input: &[i32],
    gas_limit: u64,
) -> Result<(crate::ai::types::AiExecutionProof, Vec<i32>), String> {
    let host_output = eval_fixed_point_mlp(spec, input)?;

    // Prove the forward pass itself, not a commitment stub. The guest is run
    // over the host-populated memory image and its result is compared with the
    // host evaluator before anything is packaged: a mismatch means the proof
    // would attest to a different computation than the one being claimed.
    let (guest_output, _receipt) = run_matmul_guest(spec, input, gas_limit)?;
    if guest_output != host_output {
        return Err(format!(
            "guest output {guest_output:?} != host output {host_output:?}"
        ));
    }

    let in_c = input_commitment(input);
    let out_c = output_commitment(&host_output);
    let words = build_matmul_guest_program(spec)?;
    // The proof carries the hash the STARK binds, not the registry
    // identifier: `verify_execution_proof_stark` compares this field against
    // `public_inputs.program_hash`, and the two used to come from different
    // schemes, so that comparison could never succeed.
    let program_hash = stark_program_hash_from_words(&words);
    let bytecode = words_to_bytecode(&words);

    let (envelope, pi, _prog) =
        crate::execution::zkvm::prove_bytecode_with_memory(&bytecode, gas_limit, |memory| {
            setup_guest_memory(memory, spec, input).map(|_| ())
        })?;
    let proof_bytes =
        postcard::to_allocvec(&envelope).map_err(|e| format!("postcard serialize proof: {e}"))?;

    let proof = crate::ai::types::AiExecutionProof {
        model_id,
        input_commitment: in_c,
        output_commitment: out_c,
        program_hash,
        proof_bytes,
        // `degree_bits` is the log2 of the padded trace domain, not a step
        // count; the AIR-bound row count lives in the public inputs.
        steps: pi.trace_len,
        gas_used: pi.gas_used,
        // States which weights were run. The guest reads them from a memory
        // image the AIR does not constrain, so `program_hash` - which depends
        // on the architecture alone - cannot carry this.
        weights_digest: Some(weights_digest(spec)),
        // Ship the public inputs the STARK was produced against. Without them
        // a verifier holding only the request (which carries an input
        // *commitment*, not the input) cannot rebuild `initial_state_root` or
        // the gas counters, and so cannot check the proof at all.
        public_inputs: Some(crate::ai::types::AiExecutionPublicInputs::from_execution_inputs(&pi)),
    };
    Ok((proof, host_output))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn tiny_mlp() -> FixedPointMlpSpec {
        // 2 -> 1: y = 2*x0 + 3*x1 + 1
        FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![2, 3],
            biases: vec![1],
        }
    }

    #[test]
    fn eval_linear_layer() {
        let spec = tiny_mlp();
        let y = eval_fixed_point_mlp(&spec, &[4, 5]).unwrap();
        assert_eq!(y, vec![2 * 4 + 3 * 5 + 1]);
    }

    #[test]
    fn eval_relu_hidden() {
        let spec = FixedPointMlpSpec {
            dims: vec![1, 1, 1],
            weights: vec![-2, 1], // h = ReLU(-2x), y = h
            biases: vec![0, 0],
        };
        assert_eq!(eval_fixed_point_mlp(&spec, &[3]).unwrap(), vec![0]);
        assert_eq!(eval_fixed_point_mlp(&spec, &[-3]).unwrap(), vec![6]);
    }

    #[test]
    fn commitments_domain_separated() {
        let a = input_commitment(&[1, 2]);
        let b = output_commitment(&[1, 2]);
        assert_ne!(a, b);
    }

    #[test]
    fn guest_hash_stable() {
        let spec = tiny_mlp();
        let ic = input_commitment(&[1, 2]);
        let w = build_fixed_point_mlp_guest(&spec, &ic).unwrap();
        let h1 = program_hash_from_words(&w);
        assert_eq!(h1, program_hash_from_words(&w));
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn rejects_oversized() {
        let bad = FixedPointMlpSpec {
            dims: vec![200, 1],
            weights: vec![0; 200],
            biases: vec![0],
        };
        assert!(bad.validate().is_err());
    }
}

// ── (2026-07-23): Production gas metering for AI execution proofs ──
//
// Dynamic gas model for L1 verification of AI execution proofs.
// The VM opcode gas (flat 10) covers the instruction execution; this
// Covers the L1 structural + STARK verification cost which scales with
// Model complexity and proof size.

/// Base gas cost for structural verification (commitment checks, model binding).
pub const GAS_BASE_STRUCTURAL: u64 = 500;

/// Per-parameter gas cost (weights + biases) for MLP execution verification.
pub const GAS_PER_PARAM: u64 = 2;

/// Per-layer gas cost for MLP forward pass commitment chain.
pub const GAS_PER_LAYER: u64 = 50;

/// Base gas cost for STARK proof verification (deserialize + FRI check).
pub const GAS_BASE_STARK: u64 = 10_000;

/// Per-KiB gas cost for proof_bytes (STARK proof size).
pub const GAS_PER_KIB_PROOF: u64 = 100;

/// Maximum allowed proof_bytes size (256 KiB).
pub const MAX_PROOF_BYTES: usize = 256 * 1024;

/// Estimated gas for structural verification of an AI execution proof.
pub fn estimate_structural_gas(spec: &FixedPointMlpSpec) -> u64 {
    let total_params = spec.weights.len().saturating_add(spec.biases.len()) as u64;
    let n_layers = spec.dims.len().saturating_sub(1) as u64;
    GAS_BASE_STRUCTURAL
        .saturating_add(GAS_PER_PARAM.saturating_mul(total_params))
        .saturating_add(GAS_PER_LAYER.saturating_mul(n_layers))
}

/// Estimated gas for full verification (structural + STARK).
/// `proof_bytes_len` is the size of the serialized ProofEnvelope.
pub fn estimate_full_gas(spec: &FixedPointMlpSpec, proof_bytes_len: usize) -> u64 {
    let structural = estimate_structural_gas(spec);
    let proof_kib = (proof_bytes_len as u64).saturating_add(1023) / 1024;
    let stark = GAS_BASE_STARK.saturating_add(GAS_PER_KIB_PROOF.saturating_mul(proof_kib));
    structural.saturating_add(stark)
}

/// Refuse a proof this model cannot have produced honestly.
///
/// Two checks, and only one of them is wired. The distinction is measured,
/// not stylistic.
///
/// The size bound is wired: `proof_bytes_len` against [`MAX_PROOF_BYTES`],
/// bytes against bytes.
///
/// The gas comparison is NOT wired, deliberately, and the parameter is named
/// `max_fee_same_unit_as_gas` to say why at every call site. `max_fee` on an
/// `AiInferenceRequest` is a balance escrowed from the requester's account
/// (`executor.rs` checks `sender_balance < max_fee` and deducts it). The
/// values `estimate_full_gas` returns are gas units, and this tree has no
/// conversion between the two: no `gas_price` multiplication reaches this
/// path, and nothing turns a gas figure into a debit. Comparing them is a
/// unit error that happens to typecheck because both are `u64`.
///
/// Measured before deciding: `GAS_BASE_STARK` alone is 10_000, while every
/// `max_fee` in the tree is at most 500. Wiring the comparison would have
/// rejected every valid inference request on the chain, and recalibrating the
/// gas table until the numbers stopped colliding would be fitting the
/// constants to the test fixtures rather than to any measurement of work.
///
/// Pricing verification is real work and belongs in a change that introduces
/// a gas price. Until then, the caller passes `u64::MAX`, which is visible at
/// the call site and cannot be mistaken for a budget that was checked.
///
/// # Errors
///
/// The bound the proof exceeded, naming both numbers.
pub fn validate_gas_budget(
    spec: &FixedPointMlpSpec,
    proof_bytes_len: usize,
    max_fee_same_unit_as_gas: u64,
) -> Result<u64, String> {
    if proof_bytes_len > MAX_PROOF_BYTES {
        return Err(format!(
            "proof_bytes {} exceeds MAX_PROOF_BYTES {}",
            proof_bytes_len, MAX_PROOF_BYTES
        ));
    }
    let gas = estimate_full_gas(spec, proof_bytes_len);
    if gas > max_fee_same_unit_as_gas {
        return Err(format!(
            "estimated gas {gas} exceeds the supplied ceiling \
             {max_fee_same_unit_as_gas}"
        ));
    }
    Ok(gas)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod gas_tests {
    use super::*;

    /// The size bound is wired; the gas ceiling is not, and the names say so.
    ///
    /// Measured before deciding: `GAS_BASE_STARK` is 10_000 on its own, and
    /// every `max_fee` in the tree is at most 500. `max_fee` is a balance
    /// escrowed from the requester's account, `estimate_full_gas` returns gas
    /// units, and nothing converts between them. Comparing them typechecks,
    /// because both are `u64`, and is still a unit error that would reject
    /// every valid inference request.
    ///
    /// This test pins the arithmetic that makes the claim true, so a future
    /// change to the constants has to confront it.
    #[test]
    fn the_gas_estimate_is_not_denominated_in_the_request_fee() {
        let spec = FixedPointMlpSpec {
            dims: vec![4, 2],
            weights: vec![0; 8],
            biases: vec![0; 2],
        };

        // The largest fee any request in the tree carries.
        let largest_max_fee_in_tree: u64 = 500;
        let gas = estimate_full_gas(&spec, 1024);

        assert!(
            gas > largest_max_fee_in_tree,
            "if the smallest possible gas estimate ever drops below the largest \
             fee in the tree, the two might plausibly share a unit and this \
             decision needs revisiting: gas={gas}, fee={largest_max_fee_in_tree}"
        );
        assert!(
            GAS_BASE_STARK > largest_max_fee_in_tree,
            "the STARK base alone exceeds every fee, which is what makes the \
             comparison a unit error rather than a tight budget"
        );

        // And the wired half still refuses what it is meant to refuse.
        let err = validate_gas_budget(&spec, MAX_PROOF_BYTES + 1, u64::MAX)
            .expect_err("an oversized proof must be refused whatever the ceiling");
        assert!(err.contains("MAX_PROOF_BYTES"), "got: {err}");

        // A proof within bounds passes when no ceiling is asserted.
        validate_gas_budget(&spec, 1024, u64::MAX)
            .expect("a well-sized proof must pass when no gas ceiling is claimed");
    }

    /// The executor asks for the size bound and asserts no gas ceiling.
    ///
    /// Pinned at the source, because passing the real `max_fee` here is the
    /// mistake this decision exists to prevent and it would look correct.
    #[test]
    fn the_execution_path_does_not_compare_gas_against_the_escrowed_fee() {
        let executor_src = include_str!("../../execution/executor.rs");
        let production = executor_src
            .split_once("#[cfg(test)]")
            .map(|(before, _)| before)
            .unwrap_or(executor_src);

        let at = production
            .find("validate_gas_budget(")
            .expect("the executor must ask for the size bound");
        let call = &production[at..(at + 200).min(production.len())];

        assert!(
            call.contains("u64::MAX"),
            "the executor is supplying a real ceiling to a gas estimate. \
             `max_fee` is an escrowed balance and the estimate is in gas \
             units; there is no conversion between them in this tree"
        );
    }

    #[test]
    fn gas_scales_with_model_size() {
        let small = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![1, 2],
            biases: vec![0],
        };
        let large = FixedPointMlpSpec {
            dims: vec![32, 16, 8],
            weights: vec![0; 32 * 16 + 16 * 8],
            biases: vec![0; 16 + 8],
        };
        let g_small = estimate_structural_gas(&small);
        let g_large = estimate_structural_gas(&large);
        assert!(g_large > g_small, "larger model must cost more gas");
    }

    #[test]
    fn gas_stark_dominates_structural() {
        let spec = FixedPointMlpSpec {
            dims: vec![4, 2],
            weights: vec![0; 8],
            biases: vec![0; 2],
        };
        let structural = estimate_structural_gas(&spec);
        let full = estimate_full_gas(&spec, 50_000); // ~50 KiB proof
        assert!(full > structural * 5, "STARK cost should dominate");
    }

    #[test]
    fn gas_budget_rejects_oversized_proof() {
        let spec = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![1, 2],
            biases: vec![0],
        };
        assert!(validate_gas_budget(&spec, MAX_PROOF_BYTES + 1, u64::MAX).is_err());
    }

    #[test]
    fn gas_budget_rejects_insufficient_fee() {
        let spec = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![1, 2],
            biases: vec![0],
        };
        assert!(validate_gas_budget(&spec, 10_000, 1).is_err());
    }

    #[test]
    fn gas_budget_accepts_sufficient_fee() {
        let spec = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![1, 2],
            biases: vec![0],
        };
        let gas = validate_gas_budget(&spec, 10_000, 1_000_000);
        assert!(gas.is_ok());
        assert!(gas.unwrap() > 0);
    }
}

// ── Full matmul-in-guest ──
//
// Build a BudZKVM guest program that actually computes the MLP forward pass
// using VM instructions (Load, Mul, Add). The STARK proof then attests to
// the correctness of the computation itself, not just the commitment chain.
//
// Field encoding. The VM's Add/Sub/Mul are Goldilocks field operations
// (`GOLDILOCKS_P = 2^64 - 2^32 + 1`), so a negative i32 `v` is represented as
// the field element `P + v`, **not** as `v as u64` (two's complement). Those
// two differ: `(-5i32) as u64` is `2^64 - 5`, while the field's `-5` is
// `P - 5 = 2^64 - 2^32 - 4`. Every value the host writes into guest memory,
// and every immediate the guest loads, goes through [`i32_to_field`].
//
// Sign test. Field elements have no order, so `Lt(acc, 0)` is vacuous: no
// u64 is less than 0, and the old guest's ReLU therefore never fired. A field
// element is treated as negative when it is greater than `HALF = (P-1)/2`,
// which is the standard signed embedding for prime fields. `HALF` does not
// fit in the 32-bit `imm`, so the guest materialises it arithmetically (see
// [`emit_load_half`]).
//
// Branchless ReLU. `Jnz` skipped an instruction, which the Program CTL
// argument in BudL_SPEC §9 does not model (every fetched row must be the
// row the program table holds at that pc). ReLU is therefore computed as a
// multiplication by a selector bit - no control flow at all:
//
//     is_neg = Gt(acc, HALF)      // 1 when acc encodes a negative value
//     keep   = Sub(one, is_neg)   // 1 when acc is non-negative
//     acc    = Mul(acc, keep)
//
// Memory layout (word-addressed; the VM's Load/Store take **byte** offsets,
// so every index below is multiplied by 8 when emitted):
//   word [0 .. input_dim)                      input values
//   word [weight_base .. weight_base+W)        weights, row-major per layer
//   word [bias_base .. bias_base+B)            biases
//   word [act_base .. act_base+MAX_WIDTH)      layer input scratch (ping)
//   word [act_base+MAX_WIDTH .. +2*MAX_WIDTH)  layer output scratch (pong)
//   word [output_base .. output_base+out_dim)  final outputs
//
// The host must publish that layout with [`setup_guest_memory`] before the
// program runs; the previous guest read from all-zero memory because nothing
// ever wrote the weights in.

/// Maximum supported total operations for in-guest matmul.
/// Beyond this, the guest program would exceed practical trace size limits.
pub const MAX_GUEST_OPS: usize = 50_000;

/// Bytes per VM memory word. `Load`/`Store` address memory in bytes and read
/// or write eight bytes at a time, so word `i` lives at byte `i * WORD_BYTES`.
pub const WORD_BYTES: usize = 8;

/// Guest memory size in bytes, matching `Vm::with_gas_limit(8192, ..)` used by
/// `crate::execution::zkvm::prove_bytecode`.
pub const GUEST_MEMORY_BYTES: usize = 8192;

/// Goldilocks modulus used by the VM's field arithmetic.
pub const GOLDILOCKS_P: u64 = 18_446_744_069_414_584_321;

/// Values above this encode negative integers in the signed field embedding.
pub const FIELD_HALF: u64 = (GOLDILOCKS_P - 1) / 2;

/// Encode an i32 as a Goldilocks field element (`v >= 0 ? v : P + v`).
///
/// This is **not** `v as u64`: two's complement and the field representation
/// disagree for negative values, and mixing them silently corrupts every
/// downstream Add/Mul.
pub fn i32_to_field(v: i32) -> u64 {
    if v >= 0 {
        v as u64
    } else {
        GOLDILOCKS_P - (v.unsigned_abs() as u64)
    }
}

/// Decode a Goldilocks field element back to i32, rejecting anything that is
/// not a faithful i32 in the signed embedding.
pub fn field_to_i32(f: u64) -> Result<i32, String> {
    if f >= GOLDILOCKS_P {
        return Err(format!("field element {f} is not canonical"));
    }
    if f <= FIELD_HALF {
        i32::try_from(f).map_err(|_| format!("field element {f} exceeds i32::MAX"))
    } else {
        let neg = GOLDILOCKS_P - f;
        if neg > (i32::MAX as u64) + 1 {
            return Err(format!("field element {f} is below i32::MIN"));
        }
        Ok((neg as i64).wrapping_neg() as i32)
    }
}

/// Word offsets of every region the guest touches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestMemoryLayout {
    pub input_base: usize,
    pub weight_base: usize,
    pub bias_base: usize,
    /// Scratch for the current layer's input activations.
    pub act_in_base: usize,
    /// Scratch for the current layer's output activations.
    pub act_out_base: usize,
    pub output_base: usize,
    pub total_words: usize,
}

impl GuestMemoryLayout {
    pub fn for_spec(spec: &FixedPointMlpSpec) -> Result<Self, String> {
        spec.validate()?;
        let input_base = 0usize;
        let weight_base = input_base + spec.input_dim();
        let bias_base = weight_base + spec.weights.len();
        let act_in_base = bias_base + spec.biases.len();
        let act_out_base = act_in_base + MAX_MLP_WIDTH;
        let output_base = act_out_base + MAX_MLP_WIDTH;
        let total_words = output_base + spec.output_dim();
        // `spec.validate()` above already rejects anything that does not fit;
        // this is the belt to that braces, so a layout can never hand out an
        // address past the end of guest memory.
        if total_words * WORD_BYTES > GUEST_MEMORY_BYTES {
            return Err(format!(
                "guest memory layout needs {} bytes > GUEST_MEMORY_BYTES {}",
                total_words * WORD_BYTES,
                GUEST_MEMORY_BYTES
            ));
        }
        Ok(Self {
            input_base,
            weight_base,
            bias_base,
            act_in_base,
            act_out_base,
            output_base,
            total_words,
        })
    }

    /// Byte address of a word index, as the `imm` operand of Load/Store.
    fn byte_addr(&self, word: usize) -> Result<i32, String> {
        let addr = word
            .checked_mul(WORD_BYTES)
            .ok_or("guest address overflow")?;
        if addr + WORD_BYTES > GUEST_MEMORY_BYTES {
            return Err(format!("guest address {addr} out of memory"));
        }
        i32::try_from(addr).map_err(|_| "guest address exceeds i32".to_string())
    }
}

/// Write the weights, biases and input into a VM's memory in the layout the
/// guest program expects.
///
/// Without this the guest reads zeroes: the previous version documented a
/// layout that nothing ever populated, so every proof attested to a forward
/// pass over an all-zero model.
pub fn setup_guest_memory(
    memory: &mut [u8],
    spec: &FixedPointMlpSpec,
    input: &[i32],
) -> Result<GuestMemoryLayout, String> {
    let layout = GuestMemoryLayout::for_spec(spec)?;
    if input.len() != spec.input_dim() {
        return Err(format!(
            "input len {} != expected {}",
            input.len(),
            spec.input_dim()
        ));
    }
    if memory.len() < layout.total_words * WORD_BYTES {
        return Err(format!(
            "vm memory {} bytes < required {}",
            memory.len(),
            layout.total_words * WORD_BYTES
        ));
    }
    let mut put = |word: usize, value: u64| {
        let at = word * WORD_BYTES;
        memory[at..at + WORD_BYTES].copy_from_slice(&value.to_le_bytes());
    };
    for (i, v) in input.iter().enumerate() {
        put(layout.input_base + i, i32_to_field(*v));
        // The first layer reads its activations from the scratch area, so seed
        // it with the input as well.
        put(layout.act_in_base + i, i32_to_field(*v));
    }
    for (i, w) in spec.weights.iter().enumerate() {
        put(layout.weight_base + i, i32_to_field(*w));
    }
    for (i, b) in spec.biases.iter().enumerate() {
        put(layout.bias_base + i, i32_to_field(*b));
    }
    Ok(layout)
}

/// Read the guest's output words back as i32.
pub fn read_guest_output(
    memory: &[u8],
    layout: &GuestMemoryLayout,
    output_dim: usize,
) -> Result<Vec<i32>, String> {
    let mut out = Vec::with_capacity(output_dim);
    for o in 0..output_dim {
        let at = (layout.output_base + o) * WORD_BYTES;
        if at + WORD_BYTES > memory.len() {
            return Err("output word out of memory".into());
        }
        let mut b = [0u8; WORD_BYTES];
        b.copy_from_slice(&memory[at..at + WORD_BYTES]);
        out.push(field_to_i32(u64::from_le_bytes(b))?);
    }
    Ok(out)
}

// Register allocation. Everything is loaded from memory, so no register is
// tied to an input index and the old "max 19 inputs" ceiling disappears.
const R_ZERO: u8 = 1; // constant 0
const R_ONE: u8 = 2; // constant 1
const R_HALF: u8 = 3; // (P-1)/2, the sign threshold
const R_ACC: u8 = 4; // accumulator
const R_W: u8 = 5; // weight
const R_X: u8 = 6; // activation
const R_T: u8 = 7; // product / temporary
const R_SEL: u8 = 8; // ReLU selector bit
const R_HASH: u8 = 9; // rolling Poseidon commitment over outputs

/// Emit the instruction sequence that materialises `FIELD_HALF` in `R_HALF`.
///
/// `(P-1)/2 = 2^63 - 2^31`, and `imm` is only 32 bits wide, so the constant is
/// built from `2^30`: square it to get `2^60`, multiply by 8 for `2^63`, then
/// subtract `2^31`.
fn emit_load_half(prog: &mut Vec<u64>) {
    const POW30: i32 = 1 << 30;
    prog.push(inst(Opcode::Load, R_HALF, 0, 0, POW30)); // 2^30
    prog.push(inst(Opcode::Mul, R_HALF, R_HALF, R_HALF, 0)); // 2^60
    prog.push(inst(Opcode::Load, R_T, 0, 0, 8));
    prog.push(inst(Opcode::Mul, R_HALF, R_HALF, R_T, 0)); // 2^63
    prog.push(inst(Opcode::Load, R_T, 0, 0, i32::MAX)); // 2^31 - 1
    prog.push(inst(Opcode::Add, R_T, R_T, R_ONE, 0)); // 2^31
    prog.push(inst(Opcode::Sub, R_HALF, R_HALF, R_T, 0)); // 2^63 - 2^31
}

/// Estimate the number of VM instructions for a full matmul guest program.
///
/// Kept exact: [`build_matmul_guest_program`] asserts the emitted length
/// equals this estimate, so the two cannot drift apart.
pub fn estimate_guest_instruction_count(spec: &FixedPointMlpSpec) -> Result<usize, String> {
    spec.validate()?;
    // Prologue: Load 0, Sub->zero, Load 1, 7 rows for FIELD_HALF, 1 row to
    // zero the rolling commitment.
    let mut ops = 3usize + 7 + 1;
    let n_layers = spec.dims.len() - 1;
    for (layer_idx, w) in spec.dims.windows(2).enumerate() {
        let in_d = w[0] as usize;
        let out_d = w[1] as usize;
        let is_hidden = layer_idx + 1 < n_layers;
        for _o in 0..out_d {
            // Load bias, then per input: Load w, Load x, Mul, Add.
            ops = ops
                .checked_add(1 + in_d.checked_mul(4).ok_or("ops overflow")?)
                .ok_or("ops overflow")?;
            if is_hidden {
                // Branchless ReLU: Gt, Sub, Mul.
                ops = ops.checked_add(3).ok_or("ops overflow")?;
            }
            // Store into the next layer's scratch.
            ops = ops.checked_add(1).ok_or("ops overflow")?;
            if !is_hidden {
                // Final layer also stores into the output region and folds the
                // value into the rolling commitment.
                ops = ops.checked_add(2).ok_or("ops overflow")?;
            }
        }
        if is_hidden {
            // Copy pong -> ping for the next layer: Load + Store per neuron.
            ops = ops
                .checked_add(out_d.checked_mul(2).ok_or("ops overflow")?)
                .ok_or("ops overflow")?;
        }
    }
    // Log + Halt.
    ops = ops.checked_add(2).ok_or("ops overflow")?;
    if ops > MAX_GUEST_OPS {
        return Err(format!(
            "guest program too large: {ops} ops > MAX_GUEST_OPS {MAX_GUEST_OPS}"
        ));
    }
    Ok(ops)
}

/// Build a BudZKVM guest program that computes the MLP forward pass.
///
/// The program reads weights, biases and inputs from the memory image that
/// [`setup_guest_memory`] writes, accumulates each neuron in the Goldilocks
/// field, applies a branchless ReLU on hidden layers, stores the outputs and
/// folds them into a Poseidon commitment that is logged before `Halt`.
pub fn build_matmul_guest_program(spec: &FixedPointMlpSpec) -> Result<Vec<u64>, String> {
    let expected_ops = estimate_guest_instruction_count(spec)?;
    let layout = GuestMemoryLayout::for_spec(spec)?;

    let mut prog: Vec<u64> = Vec::with_capacity(expected_ops);

    // Prologue: constants.
    prog.push(inst(Opcode::Load, R_ZERO, 0, 0, 0));
    prog.push(inst(Opcode::Sub, R_ZERO, R_ZERO, R_ZERO, 0));
    prog.push(inst(Opcode::Load, R_ONE, 0, 0, 1));
    emit_load_half(&mut prog);
    // The rolling commitment starts at zero.
    prog.push(inst(Opcode::Add, R_HASH, R_ZERO, R_ZERO, 0));

    let mut w_off = 0usize;
    let mut b_off = 0usize;
    let n_layers = spec.dims.len() - 1;

    for (layer_idx, w) in spec.dims.windows(2).enumerate() {
        let in_d = w[0] as usize;
        let out_d = w[1] as usize;
        let is_hidden = layer_idx + 1 < n_layers;

        for o in 0..out_d {
            // acc = bias[o]
            let bias_addr = layout.byte_addr(layout.bias_base + b_off + o)?;
            prog.push(inst(Opcode::Load, R_ACC, R_ZERO, 0, bias_addr));

            for i in 0..in_d {
                let w_addr = layout.byte_addr(layout.weight_base + w_off + o * in_d + i)?;
                let x_addr = layout.byte_addr(layout.act_in_base + i)?;
                prog.push(inst(Opcode::Load, R_W, R_ZERO, 0, w_addr));
                prog.push(inst(Opcode::Load, R_X, R_ZERO, 0, x_addr));
                prog.push(inst(Opcode::Mul, R_T, R_W, R_X, 0));
                prog.push(inst(Opcode::Add, R_ACC, R_ACC, R_T, 0));
            }

            if is_hidden {
                // Branchless ReLU: acc *= (1 - (acc > HALF)).
                prog.push(inst(Opcode::Gt, R_SEL, R_ACC, R_HALF, 0));
                prog.push(inst(Opcode::Sub, R_SEL, R_ONE, R_SEL, 0));
                prog.push(inst(Opcode::Mul, R_ACC, R_ACC, R_SEL, 0));
            }

            // Store the neuron into the next layer's scratch.
            let dst = layout.byte_addr(layout.act_out_base + o)?;
            prog.push(inst(Opcode::Store, 0, R_ZERO, R_ACC, dst));

            if !is_hidden {
                let out_addr = layout.byte_addr(layout.output_base + o)?;
                prog.push(inst(Opcode::Store, 0, R_ZERO, R_ACC, out_addr));
                // Fold the output into the rolling Poseidon commitment so the
                // logged value depends on every output, not on a pointer.
                prog.push(inst(Opcode::Poseidon, R_HASH, R_HASH, R_ACC, 0));
            }
        }

        if is_hidden {
            // pong -> ping, so the next layer reads from act_in_base.
            for o in 0..out_d {
                let src = layout.byte_addr(layout.act_out_base + o)?;
                let dst = layout.byte_addr(layout.act_in_base + o)?;
                prog.push(inst(Opcode::Load, R_T, R_ZERO, 0, src));
                prog.push(inst(Opcode::Store, 0, R_ZERO, R_T, dst));
            }
        }

        w_off += in_d * out_d;
        b_off += out_d;
    }

    prog.push(inst(Opcode::Log, 0, R_HASH, 0, 0));
    prog.push(inst(Opcode::Halt, 0, 0, 0, 0));

    let emitted = prog.len();
    if emitted != expected_ops {
        return Err(format!(
            "guest instruction estimate {expected_ops} != emitted {emitted}"
        ));
    }
    Ok(prog)
}

/// Compute program hash for a matmul guest program.
/// Rebuild the guest program words for a registered model.
///
/// The verifier side of `prove_mlp_inference`. A fixed-point MLP guest depends
/// only on the layer shape - weights are read from memory, not baked into
/// immediates - so `execution_dims` is enough to reproduce the exact
/// instruction words a proof was produced against, which is what
/// `Prover::verify` needs alongside the envelope and the public inputs.
///
/// Weights are not needed here and are not registered: they are bound
/// separately by `execution_weights_digest`. The placeholder values below
/// never reach the program, because `build_matmul_guest_program` emits loads
/// rather than constants; `guest_program_for_model_ignores_weight_values`
/// pins that.
///
/// # Errors
///
/// Returns an error when the model registers no `execution_dims`, or when the
/// architecture those dims describe fails `FixedPointMlpSpec::validate`.
pub fn guest_program_for_model(model: &crate::ai::types::AiModelSpec) -> Result<Vec<u64>, String> {
    let dims = model
        .execution_dims
        .as_ref()
        .ok_or("model does not register execution_dims; cannot rebuild its guest program")?;
    let spec = FixedPointMlpSpec {
        dims: dims.clone(),
        // Sized to match the architecture so `validate` passes. The values are
        // irrelevant: the program loads weights from memory.
        weights: vec![0i32; weight_count(dims)],
        biases: vec![0i32; bias_count(dims)],
    };
    spec.validate()?;
    build_matmul_guest_program(&spec)
}

#[must_use]
fn weight_count(dims: &[u16]) -> usize {
    dims.windows(2).map(|w| w[0] as usize * w[1] as usize).sum()
}

#[must_use]
fn bias_count(dims: &[u16]) -> usize {
    dims.iter().skip(1).map(|d| *d as usize).sum()
}

pub fn matmul_program_hash(spec: &FixedPointMlpSpec) -> Result<[u8; 32], String> {
    let words = build_matmul_guest_program(spec)?;
    // Registration and proofs have to name the guest program the same way, and
    // the proof side is fixed by the AIR, so this follows it. Using the
    // registry hash here while proofs carried the proof-system one made
    // `execution_program_hash` unmatchable for any real proof.
    Ok(stark_program_hash_from_words(&words))
}

/// Run the matmul guest inside the VM over a host-populated memory image and
/// return the outputs the guest actually wrote.
///
/// This is the bridge that was missing: the guest program, the memory layout
/// and the host evaluator are now checked against each other instead of each
/// being tested in isolation.
pub fn run_matmul_guest(
    spec: &FixedPointMlpSpec,
    input: &[i32],
    gas_limit: u64,
) -> Result<(Vec<i32>, bud_vm::ExecutionReceipt), String> {
    let prog = build_matmul_guest_program(spec)?;
    let mut vm = bud_vm::Vm::with_gas_limit(GUEST_MEMORY_BYTES, gas_limit);
    let layout = setup_guest_memory(&mut vm.memory, spec, input)?;
    let receipt = vm.run_receipt(&prog);
    if !receipt.success {
        return Err(format!("guest execution failed: {:?}", receipt.error));
    }
    let out = read_guest_output(&vm.memory, &layout, spec.output_dim())?;
    Ok((out, receipt))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod matmul_tests {
    use super::*;

    /// The whole point of the guest: what the VM computes must equal what the
    /// host evaluator computes, for the same weights and the same input.
    fn assert_guest_matches_host(spec: &FixedPointMlpSpec, input: &[i32]) {
        let host = eval_fixed_point_mlp(spec, input).expect("host eval");
        let (guest, receipt) = run_matmul_guest(spec, input, 10_000_000).expect("guest run");
        assert_eq!(
            guest, host,
            "guest output {guest:?} != host output {host:?} for input {input:?}"
        );
        assert!(receipt.success);
        assert_eq!(
            receipt.trace_len as usize,
            build_matmul_guest_program(spec).unwrap().len(),
            "every emitted instruction must execute exactly once (no branches)"
        );
    }

    #[test]
    fn guest_matches_host_single_linear_layer() {
        let spec = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![2, 3],
            biases: vec![1],
        };
        assert_guest_matches_host(&spec, &[4, 5]);
    }

    /// Regression for the ReLU that never fired. `Lt` is unsigned, so
    /// `Lt(acc, 0)` was always 0 and hidden-layer negatives passed through.
    /// Layer 1 raw output is `[-5, 5]`; with ReLU the result is 5, without it
    /// the negative branch cancels and the result is 0.
    #[test]
    fn guest_relu_actually_clamps_negative_activations() {
        let spec = FixedPointMlpSpec {
            dims: vec![2, 2, 1],
            weights: vec![1, -1, -1, 1, 1, 1],
            biases: vec![0, 0, 0],
        };
        let input = [5i32, 10i32];
        let host = eval_fixed_point_mlp(&spec, &input).unwrap();
        assert_eq!(host, vec![5], "host ReLU clamps -5 to 0");
        let (guest, _) = run_matmul_guest(&spec, &input, 10_000_000).unwrap();
        assert_eq!(
            guest, host,
            "guest ReLU must clamp the negative activation the same way"
        );
        assert_ne!(
            guest,
            vec![0],
            "0 is the answer a guest without a working ReLU produces"
        );
    }

    #[test]
    fn guest_matches_host_on_negative_weights_and_inputs() {
        let spec = FixedPointMlpSpec {
            dims: vec![3, 3, 2],
            weights: vec![
                1, -2, 3, -4, 5, -6, 7, -8, 9, // layer 1 (3x3)
                -1, 2, -3, 4, -5, 6, // layer 2 (2x3)
            ],
            biases: vec![-1, 0, 2, 5, -7],
        };
        for input in [
            [0, 0, 0],
            [1, 2, 3],
            [-1, -2, -3],
            [7, -11, 13],
            [-100, 250, -3],
        ] {
            assert_guest_matches_host(&spec, &input);
        }
    }

    #[test]
    fn guest_matches_host_three_layers() {
        let spec = FixedPointMlpSpec {
            dims: vec![2, 4, 3, 1],
            weights: vec![
                1, -1, 2, -2, 3, -3, 4, -4, // 4x2
                1, 0, -1, 2, 0, 1, 1, -1, 2, -2, 0, 1, // 3x4
                1, -1, 1, // 1x3
            ],
            biases: vec![0, 1, -1, 2, 0, -3, 1, 4],
        };
        assert_guest_matches_host(&spec, &[6, -9]);
    }

    /// The old guest allocated one register per input and refused anything
    /// wider than 19. Weights and activations now live in memory, so the
    /// class limit (`MAX_MLP_WIDTH`) is the only ceiling.
    #[test]
    fn guest_accepts_inputs_beyond_the_old_register_ceiling() {
        let in_d = 24usize;
        let spec = FixedPointMlpSpec {
            dims: vec![in_d as u16, 1],
            weights: (0..in_d).map(|i| (i as i32) - 12).collect(),
            biases: vec![3],
        };
        let input: Vec<i32> = (0..in_d).map(|i| (i as i32) - 5).collect();
        assert_guest_matches_host(&spec, &input);
    }

    /// The guest must run at the widest shape the model class advertises,
    /// otherwise `MAX_MLP_WIDTH` is a promise the prover cannot keep.
    #[test]
    fn guest_runs_at_max_model_class_width() {
        let w = MAX_MLP_WIDTH;
        let spec = FixedPointMlpSpec {
            dims: vec![w as u16, 1],
            weights: (0..w).map(|i| ((i % 7) as i32) - 3).collect(),
            biases: vec![1],
        };
        let input: Vec<i32> = (0..w).map(|i| ((i % 11) as i32) - 5).collect();
        assert_guest_matches_host(&spec, &input);
    }

    #[test]
    fn field_encoding_round_trips() {
        for v in [
            i32::MIN,
            i32::MIN + 1,
            -70_000,
            -1,
            0,
            1,
            70_000,
            i32::MAX - 1,
            i32::MAX,
        ] {
            let f = i32_to_field(v);
            assert!(f < GOLDILOCKS_P, "encoding must stay canonical for {v}");
            assert_eq!(field_to_i32(f).unwrap(), v, "round trip failed for {v}");
        }
    }

    /// Two's complement is not the field encoding. Conflating them is what
    /// made the old sign test meaningless.
    #[test]
    fn field_encoding_differs_from_twos_complement() {
        assert_ne!(i32_to_field(-5), (-5i32) as u64);
        assert_eq!(i32_to_field(-5), GOLDILOCKS_P - 5);
    }

    #[test]
    fn field_half_is_the_sign_threshold() {
        assert_eq!(FIELD_HALF, (GOLDILOCKS_P - 1) / 2);
        assert!(i32_to_field(-1) > FIELD_HALF);
        assert!(i32_to_field(i32::MIN) > FIELD_HALF);
        assert!(i32_to_field(i32::MAX) <= FIELD_HALF);
        assert!(i32_to_field(0) <= FIELD_HALF);
    }

    /// `FIELD_HALF` does not fit in a 32-bit immediate, so the guest builds it
    /// arithmetically. If that sequence drifts, every ReLU silently breaks.
    #[test]
    fn guest_materialises_field_half_exactly() {
        let mut prog = vec![
            inst(Opcode::Load, R_ZERO, 0, 0, 0),
            inst(Opcode::Sub, R_ZERO, R_ZERO, R_ZERO, 0),
            inst(Opcode::Load, R_ONE, 0, 0, 1),
        ];
        emit_load_half(&mut prog);
        prog.push(inst(Opcode::Halt, 0, 0, 0, 0));
        let mut vm = bud_vm::Vm::with_gas_limit(GUEST_MEMORY_BYTES, 1_000_000);
        let receipt = vm.run_receipt(&prog);
        assert!(receipt.success);
        assert_eq!(
            vm.registers[R_HALF as usize], FIELD_HALF,
            "guest-materialised threshold must equal (P-1)/2"
        );
    }

    /// The instruction estimate is the gas/limit input, so it must be exact.
    #[test]
    fn instruction_estimate_matches_emitted_length() {
        for spec in [
            FixedPointMlpSpec {
                dims: vec![2, 1],
                weights: vec![1, 2],
                biases: vec![0],
            },
            FixedPointMlpSpec {
                dims: vec![4, 4, 2],
                weights: vec![1; 4 * 4 + 4 * 2],
                biases: vec![0; 4 + 2],
            },
            FixedPointMlpSpec {
                dims: vec![3, 5, 4, 2],
                weights: vec![1; 3 * 5 + 5 * 4 + 4 * 2],
                biases: vec![0; 5 + 4 + 2],
            },
        ] {
            let est = estimate_guest_instruction_count(&spec).unwrap();
            let prog = build_matmul_guest_program(&spec).unwrap();
            assert_eq!(est, prog.len(), "estimate must equal emitted length");
        }
    }

    /// No `Jnz`/`Jmp`: the Program CTL argument (BudL_SPEC §9) models a
    /// straight-line fetch, and the old ReLU jumped over an instruction.
    #[test]
    fn guest_program_is_branchless() {
        let spec = FixedPointMlpSpec {
            dims: vec![3, 3, 2],
            weights: vec![1; 3 * 3 + 3 * 2],
            biases: vec![0; 3 + 2],
        };
        let prog = build_matmul_guest_program(&spec).unwrap();
        for (i, word) in prog.iter().enumerate() {
            let d = Instruction::decode(*word).unwrap();
            assert!(
                !matches!(
                    d.opcode,
                    Opcode::Jmp | Opcode::Jnz | Opcode::Call | Opcode::Ret
                ),
                "instruction {i} is a branch ({:?}); the guest must stay straight-line",
                d.opcode
            );
        }
    }

    /// The logged commitment must depend on the outputs. The old guest logged
    /// `Poseidon(output_base_pointer, output_dim)` - the same value for two
    /// models with the same shape and completely different results.
    #[test]
    fn logged_commitment_depends_on_the_outputs() {
        let spec = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![2, 3],
            biases: vec![0],
        };
        let prog = build_matmul_guest_program(&spec).unwrap();

        let run = |input: &[i32]| -> Vec<u64> {
            let mut vm = bud_vm::Vm::with_gas_limit(GUEST_MEMORY_BYTES, 10_000_000);
            setup_guest_memory(&mut vm.memory, &spec, input).unwrap();
            let receipt = vm.run_receipt(&prog);
            assert!(receipt.success);
            receipt.events
        };

        let a = run(&[1, 1]);
        let b = run(&[7, 9]);
        assert!(!a.is_empty(), "guest must log its commitment");
        assert_ne!(
            a, b,
            "different outputs must produce a different logged commitment"
        );
    }

    /// The memory image is what the guest reads; if the host does not write
    /// it, the guest proves a forward pass over an all-zero model.
    #[test]
    fn guest_without_host_memory_setup_computes_zero() {
        let spec = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![2, 3],
            biases: vec![1],
        };
        let prog = build_matmul_guest_program(&spec).unwrap();
        let layout = GuestMemoryLayout::for_spec(&spec).unwrap();
        let mut vm = bud_vm::Vm::with_gas_limit(GUEST_MEMORY_BYTES, 10_000_000);
        // Deliberately skip setup_guest_memory.
        let receipt = vm.run_receipt(&prog);
        assert!(receipt.success);
        let out = read_guest_output(&vm.memory, &layout, spec.output_dim()).unwrap();
        assert_eq!(
            out,
            vec![0],
            "an unpopulated memory image yields zeros, not the model's output"
        );
        assert_ne!(
            out,
            eval_fixed_point_mlp(&spec, &[4, 5]).unwrap(),
            "which is exactly why setup_guest_memory has to run"
        );
    }

    #[test]
    fn memory_layout_regions_do_not_overlap() {
        let spec = FixedPointMlpSpec {
            dims: vec![4, 4, 2],
            weights: vec![1; 4 * 4 + 4 * 2],
            biases: vec![0; 4 + 2],
        };
        let l = GuestMemoryLayout::for_spec(&spec).unwrap();
        assert!(l.weight_base >= l.input_base + spec.input_dim());
        assert!(l.bias_base >= l.weight_base + spec.weights.len());
        assert!(l.act_in_base >= l.bias_base + spec.biases.len());
        assert_eq!(l.act_out_base, l.act_in_base + MAX_MLP_WIDTH);
        assert_eq!(l.output_base, l.act_out_base + MAX_MLP_WIDTH);
        assert!(l.total_words * WORD_BYTES <= GUEST_MEMORY_BYTES);
    }

    #[test]
    fn validate_rejects_models_that_do_not_fit_in_guest_memory() {
        // A 32x32 layer is 1056 params - a quarter of MAX_MLP_PARAMS - and
        // still needs 9984 bytes against the VM's 8192. Guest memory, not the
        // parameter budget, is what actually caps model size.
        let n = 32usize;
        let spec = FixedPointMlpSpec {
            dims: vec![n as u16, n as u16],
            weights: vec![1; n * n],
            biases: vec![0; n],
        };
        assert!(spec.weights.len() + spec.biases.len() <= MAX_MLP_PARAMS);
        let err = spec.validate().unwrap_err();
        assert!(err.contains("guest memory"), "got: {err}");
        assert!(
            GuestMemoryLayout::for_spec(&spec).is_err(),
            "the layout must refuse it too"
        );
    }

    /// Anything `validate` accepts must be buildable and runnable, no shape
    /// may pass validation and then fail inside the guest.
    #[test]
    fn every_valid_shape_can_be_built_and_run() {
        for dims in [
            vec![1u16, 1],
            vec![8, 8, 8],
            vec![20, 20, 20],
            vec![28, 28],
            vec![64, 1],
        ] {
            let w: usize = dims.windows(2).map(|d| d[0] as usize * d[1] as usize).sum();
            let b: usize = dims[1..].iter().map(|d| *d as usize).sum();
            let spec = FixedPointMlpSpec {
                dims: dims.clone(),
                weights: (0..w).map(|i| ((i % 5) as i32) - 2).collect(),
                biases: (0..b).map(|i| ((i % 3) as i32) - 1).collect(),
            };
            spec.validate()
                .unwrap_or_else(|e| panic!("shape {dims:?} must validate: {e}"));
            let input: Vec<i32> = (0..spec.input_dim())
                .map(|i| ((i % 7) as i32) - 3)
                .collect();
            let host = eval_fixed_point_mlp(&spec, &input).unwrap();
            let (guest, _) = run_matmul_guest(&spec, &input, 50_000_000)
                .unwrap_or_else(|e| panic!("validated shape {dims:?} failed to run: {e}"));
            assert_eq!(guest, host, "shape {dims:?}");
        }
    }

    #[test]
    fn matmul_program_hash_deterministic() {
        let spec = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![1, 2],
            biases: vec![0],
        };
        let h1 = matmul_program_hash(&spec).unwrap();
        let h2 = matmul_program_hash(&spec).unwrap();
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn matmul_program_hash_differs_by_architecture() {
        let spec1 = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![1, 2],
            biases: vec![0],
        };
        let spec2 = FixedPointMlpSpec {
            dims: vec![3, 1],
            weights: vec![1, 2, 3],
            biases: vec![0],
        };
        assert_ne!(
            matmul_program_hash(&spec1).unwrap(),
            matmul_program_hash(&spec2).unwrap(),
            "different architecture = different program"
        );
    }

    /// Weights live in memory, so the program hash alone cannot bind them.
    /// This is a documented property, not an accident: `weights_digest` is the
    /// binding, and `prove_mlp_inference` commits to it separately.
    #[test]
    fn matmul_program_hash_does_not_bind_weights() {
        let spec1 = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![1, 2],
            biases: vec![0],
        };
        let spec2 = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![3, 4],
            biases: vec![0],
        };
        assert_eq!(
            matmul_program_hash(&spec1).unwrap(),
            matmul_program_hash(&spec2).unwrap(),
            "same architecture = same program words"
        );
        assert_ne!(
            weights_digest(&spec1),
            weights_digest(&spec2),
            "weights must be bound by weights_digest instead"
        );
    }

    #[test]
    fn instruction_count_scales_with_model_size() {
        let small = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![1, 2],
            biases: vec![0],
        };
        let large = FixedPointMlpSpec {
            dims: vec![4, 4, 2],
            weights: vec![0; 4 * 4 + 4 * 2],
            biases: vec![0; 4 + 2],
        };
        assert!(
            estimate_guest_instruction_count(&large).unwrap()
                > estimate_guest_instruction_count(&small).unwrap()
        );
    }

    /// `prove_mlp_inference` must produce a proof that actually verifies.
    ///
    /// It never did. `Prover::prove` succeeds whenever it can build a trace,
    /// it does not check the trace against the AIR, and `prove_bytecode` did
    /// not verify what it produced, so the function returned an envelope no
    /// verifier would accept.
    ///
    /// The AIR requires the first access to any address to read zero
    /// (`plonky3_air.rs`, "first-read default zero in memory"). The matmul
    /// guest reads weights the host wrote before execution, so its very first
    /// memory event is a non-zero read and the constraint rejects it. Nothing
    /// noticed, because nobody verified.
    ///
    /// The AIR now commits to the initial memory image, so a guest that reads
    /// host-written weights can be proven - and the proof verifies.
    #[test]
    fn prove_mlp_inference_produces_a_verifiable_proof() {
        let spec = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![2, 3],
            biases: vec![1],
        };
        let owner = crate::core::address::Address::from([1u8; 32]);
        let model_id = crate::ai::types::AiModelId::of(&owner, &[9u8; 32], 1);

        let (proof, output) = prove_mlp_inference(&spec, model_id, &[4, 5], 10_000_000)
            .expect("a host-seeded guest must now prove and verify");
        assert_eq!(output, eval_fixed_point_mlp(&spec, &[4, 5]).unwrap());
        assert!(!proof.proof_bytes.is_empty());
        assert_eq!(proof.weights_digest, Some(weights_digest(&spec)));
    }

    /// The commitment is what makes the exemption safe: seeding different
    /// weights must land on a different `initial_state_root`, so a proof for
    /// one image cannot be presented as a proof for another.
    #[test]
    fn different_weights_commit_to_different_memory_images() {
        let a = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![2, 3],
            biases: vec![1],
        };
        let b = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![9, -9],
            biases: vec![1],
        };
        let commit = |spec: &FixedPointMlpSpec| {
            let prog = build_matmul_guest_program(spec).unwrap();
            let mut vm = bud_vm::Vm::with_gas_limit(GUEST_MEMORY_BYTES, 10_000_000);
            setup_guest_memory(&mut vm.memory, spec, &[4, 5]).unwrap();
            assert!(vm.run_receipt(&prog).success);
            bud_proof::memory_image_commitment_of_reads(&bud_proof::initial_memory_reads(&vm.trace))
        };
        assert_ne!(
            commit(&a),
            commit(&b),
            "two weight sets must not share a memory commitment"
        );
    }

    /// An untouched image still commits to zero, so every program that seeds
    /// nothing keeps the behaviour it had.
    #[test]
    fn a_program_that_reads_no_seeded_memory_commits_to_zero() {
        let prog = vec![
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Log, 0, 1, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = bud_vm::Vm::with_gas_limit(GUEST_MEMORY_BYTES, 1_000_000);
        assert!(vm.run_receipt(&prog).success);
        assert_eq!(
            bud_proof::memory_image_commitment_of_reads(&bud_proof::initial_memory_reads(
                &vm.trace
            )),
            [0u8; 32],
            "nothing pre-written was read, so the commitment stays zero"
        );
    }

    /// The commitment-only guest must produce a proof that verifies.
    ///
    /// It did not, for a reason that had nothing to do with memory: the AIR
    /// accumulates each `Log` row's whole `rs1` into the event digest, while
    /// the prover and the host both summed only its low 32 bits. Every test
    /// logged a small constant, so the two agreed by accident; a Poseidon
    /// output never fits in 32 bits, so the one guest that logged one produced
    /// an envelope no verifier would accept - and nothing checked, because
    /// `prove_bytecode` did not verify its own output.
    #[test]
    fn commitment_guest_proof_verifies() {
        let spec = FixedPointMlpSpec {
            dims: vec![2, 1],
            weights: vec![2, 3],
            biases: vec![1],
        };
        let ic = input_commitment(&[4, 5]);
        let words = build_fixed_point_mlp_guest(&spec, &ic).unwrap();
        let bytecode = words_to_bytecode(&words);
        crate::execution::zkvm::prove_bytecode(&bytecode, 10_000_000)
            .expect("a guest that logs a Poseidon output must still verify");
    }

    /// Logging a value above 2^32 must not break proving. This is the
    /// regression in its smallest form.
    #[test]
    fn logging_a_value_above_2_32_still_verifies() {
        let big = (1i64 << 40) as i32; // truncates, so build it in-guest
        let _ = big;
        let prog = vec![
            inst(Opcode::Load, 1, 0, 0, i32::MAX),
            inst(Opcode::Load, 2, 0, 0, 1),
            inst(Opcode::Add, 1, 1, 2, 0),
            inst(Opcode::Mul, 1, 1, 1, 0), // (2^31)^2 = 2^62, well above 2^32
            inst(Opcode::Log, 0, 1, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        crate::execution::zkvm::prove_bytecode(&words_to_bytecode(&prog), 1_000_000)
            .expect("a large logged value must verify");
    }

    /// And a small one keeps working, so the fix is not a one-way swap.
    #[test]
    fn logging_a_small_value_still_verifies() {
        let prog = vec![
            inst(Opcode::Load, 1, 0, 0, 7),
            inst(Opcode::Log, 0, 1, 0, 0),
            inst(Opcode::Halt, 0, 0, 0, 0),
        ];
        crate::execution::zkvm::prove_bytecode(&words_to_bytecode(&prog), 1_000_000)
            .expect("a small logged value must still verify");
    }
}
