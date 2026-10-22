//! Quantum-safe account abstraction (the KQ-* gates).
//!
//! # The history of this directory
//!
//! This directory was never declared in `lib.rs`, so none of its five files
//! compiled. That was measured, not guessed: invalid Rust was written into
//! `threshold_mldsa.rs` and `cargo check --lib` still passed. Because it did
//! not compile, neither clippy nor the gates nor the tests were looking at this
//! code; the three "verification" functions inside were in no position to
//! refuse anything, and nobody had noticed.
//!
//! The `no-orphan-source-files` gate could not see it either: the gate exempted
//! any file named `mod.rs` unconditionally, so the `mod.rs` of an unreachable
//! directory counted as exempt, and its sibling files counted as "declared" by
//! that exempt file. The gate now follows reachability from the crate roots.
//!
//! # Scope
//!
//! The types here verify signatures and policy. They do not change chain state
//! and they do not stand in for a proof system; the header of each module
//! states separately what it does and does not claim.

pub mod private_transfer_auth;
pub mod quantum_account;
pub mod registry;
pub mod tee_attestation;
pub mod threshold_mldsa;

pub use private_transfer_auth::{PrivateTransferAuth, PrivateTransferError, PrivateTransferGates};
pub use quantum_account::{
    BftGuardianFinality, GuardianVote, Pact, PactRegistry, QuantumAccount, RecoveryProposal,
};
pub use registry::{QuantumAccountRegistry, QuantumAccountRegistryError};
pub use tee_attestation::{
    TeeAttestation, TeeBackendKind, TeeError, TeeGates, TeeRuntime, TeeRuntimeStatus,
};
pub use threshold_mldsa::{
    MultisigAuthorization, MultisigPolicy, OwnerSignature, ThresholdError, ThresholdGates,
};
