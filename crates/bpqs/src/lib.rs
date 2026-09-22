//! # Budlum-BPQS - research line F2 (RESEARCH ONLY)
//!
//! Epoch-chained Winternitz few-time signatures for the cold-committee
//! anchor flow. Decision record: workspace
//! `ARASTIRMA-2026-09-19 (BPQS F2 design pre-registration)`; promotion bar:
//! budlum `docs/PQ_ANCHOR_RESEARCH.md` section 3 (four items, all mandatory).
//!
//! WIRING: unwired - research line F2. The dedicated algorithm slot
//! (`AnchorSignatureAlgorithm::BudlumBpqsReserved` in
//! `src/settlement/pq_anchor.rs`) stays fail-closed until the four bar items
//! land: (1) written security argument, (2) this reference implementation
//! plus the differential test battery, (3) one independent review, (4)
//! VerifyMerkle-audit expressibility of the verify chain. Until item (2)
//! completes, nothing outside this crate calls it.
//!
//! There is deliberately no `std`: the cold-committee devices and a future
//! HSM target both want a no-stdlib signing path; `alloc` suffices.
//!
//! ## Milestones
//!
//! - M1: Winternitz core, epoch-bound Merkle key evolution, quota-bounded
//!   signing, self-consistency and refusal batteries, SHA3-256 reference
//!   backend.
//! - M2 (this file set): canonical Poseidon2-Goldilocks-16 backend over the
//!   [`hash::BpqsHash`] seam (p3 parameters, straightline in-crate port);
//!   SHAKE-256 XOF cross-check backend on the `keccak` permutation
//!   (FIPS 202 domain suffix 0x1F); the backend differential battery
//!   (same scheme, three hash families); frozen KAT vector file under
//!   `kat/`; differential bench example vs the in-tree `ml-dsa` and the
//!   `slh-dsa` crate; BPQS fuzz harness in the repo fuzz workspace.
//!   `Sha3_256Hash` is cross-check 1 from here on.
//!
//! ## Honesty box
//!
//! This is not reviewed cryptography yet. Every public type carries
//! `RESEARCH` in its docs, the crate name says `bpqs` (not `anchor`), and
//! the production anchor code has no dependency on this crate (`bpqs-research`
//! is a non-default cargo feature in the root package).

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

/// Bindings from message digest, epoch digest, leaf and node domains: domain
/// separation constants shared by every construction step.
pub mod domains {
    /// PRF derivation of the per-epoch seed from the member root seed.
    pub const PRF_EPOCH_SEED: &[u8] = b"BPQS-PRF-EPOCH-SEED-v0";
    /// Expansion of the per-epoch seed into Winternitz secret chains.
    pub const WOTS_CHAIN_SEED: &[u8] = b"BPQS-WOTS-CHAIN-SEED-v0";
    /// Winternitz chain step hash.
    pub const WOTS_CHAIN_STEP: &[u8] = b"BPQS-WOTS-CHAIN-STEP-v0";
    /// Compression of a chain-head vector into one verification digest.
    pub const WOTS_VK_COMPRESS: &[u8] = b"BPQS-WOTS-VK-COMPRESS-v0";
    /// Merkle leaf label: leaf = H(DOM_LEAF, epoch_vk_digest).
    pub const MERKLE_LEAF: &[u8] = b"BPQS-MERKLE-LEAF-v0";
    /// Merkle node label: node = H(DOM_NODE, left, right).
    pub const MERKLE_NODE: &[u8] = b"BPQS-MERKLE-NODE-v0";
    /// Domain the anchor digest is bound to before WOTS signing.
    pub const MESSAGE_BIND: &[u8] = b"BPQS-MESSAGE-BIND-v0";
}

pub mod epoch;
pub mod error;
pub mod hash;
pub mod merkle;
pub mod params;
pub mod poseidon2;
pub mod shake256;
pub mod sign;
pub mod wots;

pub use epoch::{epoch_of, EpochWindow};
pub use hash::{BpqsHash, Sha3_256Hash};
pub use params::{BpqsParams, ParamsL3, ParamsL5};
pub use poseidon2::Poseidon2GoldilocksHash;
pub use shake256::Shake256Hash;
pub use sign::{keygen_root, sign_at_height, verify_at_height, BpqsSignature};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_backends;
