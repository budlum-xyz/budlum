//! On-chain AI **execution** primitives (paradigm shift #5 — Agentic Economy).
//!
//! Hardened surface:
//! - bounded model-class whitelist
//! - host bit-exact fixed-point MLP eval + domain commitments
//! - guest bytecode (weights+input limb Poseidon bind) + program_hash
//! - structural verify + optional STARK verify (postcard ProofEnvelope)
//! - prove_mlp_inference packages AiExecutionProof for L1 attach

mod guest;
mod model_class;
mod verify;

pub use guest::{
    build_fixed_point_mlp_guest, build_matmul_guest_program, estimate_full_gas,
    estimate_guest_instruction_count, estimate_structural_gas, eval_fixed_point_mlp,
    input_commitment, matmul_program_hash, output_commitment, program_hash_from_words,
    prove_mlp_inference, validate_gas_budget, weights_digest, words_to_bytecode, FixedPointMlpSpec,
    GAS_BASE_STARK, GAS_BASE_STRUCTURAL, GAS_PER_KIB_PROOF, GAS_PER_LAYER, GAS_PER_PARAM,
    MAX_GUEST_OPS, MAX_PROOF_BYTES, MLP_GUEST_VERSION,
};
pub use model_class::{
    AiExecutionModelClass, ModelClassLimits, DEFAULT_EXECUTION_CLASS, MAX_MLP_LAYERS,
    MAX_MLP_PARAMS, MAX_MLP_WIDTH,
};
pub use verify::{
    verify_execution_proof_full, verify_execution_proof_stark, verify_execution_proof_structural,
    verify_execution_proof_structural_with_model, ExecutionVerifyReport,
};
