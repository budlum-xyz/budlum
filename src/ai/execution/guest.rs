//! Fixed-point MLP guest + host evaluator for BudZKVM AI execution.
//!
//! Hardening goals:
//! - Bit-exact host forward pass (i32 MAC, ReLU)
//! - Domain-separated input/output commitments
//! - Guest bytecode commits to weights (program_hash) and binds input limb
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
        Ok(())
    }

    pub fn model_class(&self) -> AiExecutionModelClass {
        AiExecutionModelClass::FixedPointMlpV1
    }

    pub fn input_dim(&self) -> usize {
        self.dims[0] as usize
    }

    pub fn output_dim(&self) -> usize {
        *self.dims.last().unwrap() as usize
    }
}

/// Bit-exact fixed-point forward pass: y = ReLU(W x + b) per hidden layer;
/// final layer is linear (no ReLU) so regression outputs can be negative.
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
        for o in 0..out_d {
            let mut acc = i64::from(spec.biases[b_off + o]);
            for i in 0..in_d {
                let weight = spec.weights[w_off + o * in_d + i];
                acc = acc
                    .checked_add(i64::from(weight) * i64::from(activations[i]))
                    .ok_or("MAC overflow")?;
            }
            // Saturate to i32
            let mut v = acc.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32;
            // ReLU on hidden layers only
            if layer_idx + 1 < n_layers && v < 0 {
                v = 0;
            }
            next[o] = v;
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

/// Guest binds weights_digest and input_commitment into the execution trace
/// via Poseidon, then Halts. Full dense matmul stays on host (gas); the STARK
/// attests the guest program (weight commitment) ran — L1 binds host
/// input/output commitments structurally + optional STARK of this guest.
pub fn build_fixed_point_mlp_guest(
    spec: &FixedPointMlpSpec,
    input_commit: &[u8; 32],
) -> Result<Vec<u64>, String> {
    spec.validate()?;
    let wdig = weights_digest(spec);
    // Pack first 8 bytes of each digest as u64 LE field elements for Poseidon.
    let w_limb = u64::from_le_bytes(wdig[0..8].try_into().unwrap());
    let i_limb = u64::from_le_bytes(input_commit[0..8].try_into().unwrap());
    // Clamp to imm i32 for Load path: use low 31 bits positive
    let w_imm = (w_limb & 0x7fff_ffff) as i32;
    let i_imm = (i_limb & 0x7fff_ffff) as i32;

    let mut prog = Vec::new();
    // r1 = weights limb, r2 = input limb, r3 = Poseidon(r1,r2), Log r3, Halt
    prog.push(inst(Opcode::Load, 1, 0, 0, w_imm));
    prog.push(inst(Opcode::Load, 2, 0, 0, i_imm));
    prog.push(inst(Opcode::Poseidon, 3, 1, 2, 0));
    prog.push(inst(Opcode::Log, 0, 3, 0, 0));
    prog.push(inst(Opcode::Halt, 0, 0, 0, 0));
    Ok(prog)
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
    let output = eval_fixed_point_mlp(spec, input)?;
    let in_c = input_commitment(input);
    let out_c = output_commitment(&output);
    let words = build_fixed_point_mlp_guest(spec, &in_c)?;
    let program_hash = program_hash_from_words(&words);
    let bytecode = words_to_bytecode(&words);

    let (envelope, _pi, _prog) = crate::execution::zkvm::prove_bytecode(&bytecode, gas_limit)?;
    let proof_bytes =
        postcard::to_allocvec(&envelope).map_err(|e| format!("postcard serialize proof: {e}"))?;

    let proof = crate::ai::types::AiExecutionProof {
        model_id,
        input_commitment: in_c,
        output_commitment: out_c,
        program_hash,
        proof_bytes,
        steps: envelope.degree_bits as u64, // coarse; real steps in PI
        gas_used: _pi.gas_used,
    };
    Ok((proof, output))
}

#[cfg(test)]
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

// ── ARENA2 (2026-07-23): Production gas metering for AI execution proofs ──
//
// Dynamic gas model for L1 verification of AI execution proofs.
// The VM opcode gas (flat 10) covers the instruction execution; this
// covers the L1 structural + STARK verification cost which scales with
// model complexity and proof size.

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

/// Validate that a proof's gas cost is within the request's max_fee budget.
/// Returns `Ok(estimated_gas)` or `Err` if the proof is oversized.
pub fn validate_gas_budget(
    spec: &FixedPointMlpSpec,
    proof_bytes_len: usize,
    max_fee: u64,
) -> Result<u64, String> {
    if proof_bytes_len > MAX_PROOF_BYTES {
        return Err(format!(
            "proof_bytes {} exceeds MAX_PROOF_BYTES {}",
            proof_bytes_len, MAX_PROOF_BYTES
        ));
    }
    let gas = estimate_full_gas(spec, proof_bytes_len);
    if gas > max_fee {
        return Err(format!("estimated gas {} exceeds max_fee {}", gas, max_fee));
    }
    Ok(gas)
}

#[cfg(test)]
mod gas_tests {
    use super::*;

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
