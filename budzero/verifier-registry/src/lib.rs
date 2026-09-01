// Unsafe lock: this crate is at 0 unsafe today. The moment an `unsafe` block
// enters, the build FAILs (a regression gate). The same policy as the main crate.
#![forbid(unsafe_code)]
//! # Verifier Registry - Generic RoleId-based Staking + Slashing Primitive
//!
//! A standalone, domain-agnostic registry for Budlum's multi-domain L1.
//! Any role - Master Verifier, Relayer, Attester, Storage Operator, AI Verifier,
//! Or a future caller-defined role - shares **one** registry, **one** staking
//! Mechanism, and **one** slashing pipeline. There is no per-role bespoke code.
//!
//! ## Design principles
//!
//! 1. **Permissionless entry.** The ONLY gate is meeting the `min_stake` floor.
//!    There is no whitelist, no admin approval, no central gate.
//! 2. **Open role set.** [`RoleId`] is a `u32` newtype, not an enum. New roles
//!    Can be introduced without changing this crate.
//! 3. **Cross-role slashing.** Slashing one role automatically jails all other
//!    Roles held by the same address - economic security is per-address, not
//!    Per-role.
//! 4. **Evidence-gated slashing.** Slashing requires a structurally valid AND
//!    Consensus-verified [`SlashingReport`]. Unverified reports are accepted
//!    (for the permissionless RPC endpoint) but never acted on.
//! 5. **Deterministic state root.** `state_root` produces a domain-separated
//!    SHA-256 hash suitable for snapshot and consensus commitment.

pub mod address;
pub mod alarm_log;
pub mod evidence;
pub mod params;
pub mod quarantine;
pub mod registry;
pub mod role;
pub mod transfer_verdict;

pub use address::Address;
pub use alarm_log::{
    genesis_link, AlarmEntry, AlarmKind, AlarmLog, ALARM_LOG_DOMAIN, MAX_ALARM_DETAIL_LEN,
    MAX_ALARM_LOG_ENTRIES,
};
pub use evidence::{EvidenceError, ProofProvenance, SlashingProof, SlashingReport};
pub use params::RegistryParams;
pub use quarantine::{
    QuarantineEntry, QuarantineLedger, QuarantineReason, MAX_QUARANTINE_ENTRIES, QUARANTINE_DOMAIN,
};
pub use registry::{
    MemberStatus, Registration, RegistryError, SlashOutcome, SlashingCondition, VerifierRegistry,
    MIN_REGISTRATION_STAKE, UNBONDING_EPOCHS,
};
pub use role::{roles, RoleId};
pub use transfer_verdict::{
    verdict_of, TransferFlags, TransferVerdict, CANONICAL_TRANSFER_EVENT_COUNT,
};
