//! The aggregation layer: claims, frames and one master proof.
//!
//! # What this module is
//!
//! The directive says the chain must stop storing heavy objects. It stores the
//! *statement* each object proves - a claim of about 64 to 96 bytes - plus one
//! proof that every claim was checked. This module is the half of that system
//! that decides what a claim is, what a frame is, and what makes a frame valid:
//!
//! - [`types`] - the data model of directive section 4, and the parameters of
//!   section 9.
//! - [`digest`] - every tagged digest, the Merkle root, and `fold_shape`, which
//!   is the one function that turns a proof tree into a public input.
//! - [`backend`] - the [`AggBackend`](backend::AggBackend) trait, the claim
//!   derivation that makes a claim unforgeable from the wire, the frame rules of
//!   directive section 5, and the reference backend of Phase 1.
//! - [`pool`] - the admission and eviction rules of directive section 6.1.
//!
//! # What this module is not, yet
//!
//! Phase 2 (a BudZKVM `AggTick` program), Phase 3 (recursive merge and
//! `StarkBackend`), Phase 4 (program claims) and Phase 5 (PCS claims) are not
//! here. The claim enum carries their shapes, and the frame rules already refuse
//! a claim whose domain, count, root, shape or parameters do not line up, so the
//! later phases replace a proof, not a rule. The honest status is one sentence:
//! **the rules are implemented and tested; the proof system behind them is the
//! reference backend, which proves nothing about signatures.**
//!
//! # Determinism and fail-closed
//!
//! Nothing in this module reads a clock, an RNG, a file or the network. The
//! object pool is the only stateful type, and its state changes only from
//! arguments its caller passes. Every refusal is a distinct
//! [`AggError`](types::AggError) variant; no function returns a default, an empty
//! value or a boolean on an error path, and `tests::errors_are_all_refusals`
//! walks the variants to keep it that way.

pub mod backend;
pub mod digest;
pub mod pool;
pub mod types;

#[cfg(test)]
mod tests;

pub use backend::{
    claim_from_envelope, combine, object_size_ceiling, pool_item, verify_frame, verify_frame_hash,
    AggBackend, ObjectVerifier, TickCtx, BLOCK_RULES_NOT_IN_THIS_LAYER,
};
pub use digest::{
    adapter_binding, agg_merge_program_hash, agg_tick_program_hash, auth_ok, claim_digest,
    claims_root, claims_root_of, finality_claim, fold_shape, frame_hash, master_pi, merge_pi,
    object_id, params_hash, tick_pi, ALL_TAGS,
};
pub use pool::AggPool;
pub use types::{
    Address, AggError, AggMode, AggParams, Claim, ClaimFrame, DomainId, Envelope, Ext, Hash,
    ObjectKind, PoolItem, SchemeDef, SchemeId, SchemeRegistry, Segment,
};
