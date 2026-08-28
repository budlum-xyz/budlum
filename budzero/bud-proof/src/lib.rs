// Unsafe kilidi: bu crate su an 0 unsafe. Bir `unsafe` blok girdigi an
// the build FAILs (a regression gate). The same policy as the main crate.
#![forbid(unsafe_code)]
pub mod adapter;
pub mod bud_stark;
pub mod canonical_set;
pub mod plonky3_air;
pub mod plonky3_prover;
pub mod relayer;

#[cfg(test)]
// Test-only module: it holds three `#[test]` functions and a helper they
// share, and nothing outside it references the module. It was compiled into
// the production build, which both grew the binary and exempted it from
// nothing - the panic gate flagged its `expect`s as production code.
#[cfg(test)]
pub mod trace_layout_tests;

pub use adapter::{
    event_digest_from_events, initial_state_root_of, memory_image_commitment_of_reads,
    register_image_commitment_of_reads, ExecutionPublicInputs, ProofEnvelope, ProverAdapter,
};
pub use plonky3_prover::Plonky3Adapter;
pub use plonky3_prover::Plonky3Adapter as DefaultAdapter;

pub use plonky3_prover::{initial_memory_reads, initial_register_reads};
