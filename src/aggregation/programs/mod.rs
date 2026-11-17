//! The `BudZKVM` programs of the aggregation layer.
//!
//! A tick proof says: every claim of this segment stands for an object
//! that was verified. What "verified" means is fixed by a program, and
//! this module is that program, as bytecode for the virtual machine the
//! proofs are made over:
//!
//! * [`verify_sig`]: one signature object. The signer is the address of
//!   the public key and the signature is a valid ML-DSA-87 signature of
//!   the message hash.
//! * [`agg_tick`]: a list of objects. Each is verified, the digest of its
//!   claim is computed, and the program publishes `tick_pi`, the public
//!   input of the tick proof.
//!
//! These are the reference programs: plain instructions of the machine, no
//! chips. They are what a chip must reproduce, and what the step counts
//! that decide where chips go are measured on. One signature takes about
//! twelve million steps, nine tenths of them in `Keccak-f[1600]`; the prover
//! of the machine takes about forty thousand steps a proof, so no tick is
//! proven from these programs as they are.
//!
//! The programs are generated: [`asm`] is a small assembler, [`keccak`]
//! and [`mldsa`] emit the hashing and the lattice arithmetic, and the
//! tests run the result on the virtual machine against the native
//! verifier, the native backend and the digests of the claim layer.

pub mod agg_tick;
pub mod asm;
pub mod bytes;
pub mod chip_offload;
pub mod keccak;
pub mod mldsa;
pub mod object;
pub mod verify_sig;

use super::claim::SIG_CLAIM_PREFIX;
use super::hash::{TAG_AGG_TICK, TAG_CLAIM, TAG_CLAIM_ROOT};
use super::merkle::{LEAF_PREFIX, NODE_PREFIX};

/// The rules the programs of this chain are built for: how an address is
/// derived, which context a V5 transaction is signed under, and the tags
/// and prefixes of the claim layer. Every value is the constant the native
/// code uses, so the programs cannot drift from it unnoticed.
///
/// WIRING: the STARK backend of phase 3 builds its programs from these
/// rules; until it exists the tests and `benches/agg_tick_steps` do.
#[must_use]
pub const fn chain_rules() -> agg_tick::TickRules<'static> {
    agg_tick::TickRules {
        object: object::ObjectRules {
            address_tag: crate::crypto::primitives::ADDRESS_DOMAIN_V2,
            context: crate::crypto::ctx::TX_V5,
        },
        tag_claim: TAG_CLAIM,
        tag_claim_root: TAG_CLAIM_ROOT,
        tag_tick: TAG_AGG_TICK,
        claim_prefix: &SIG_CLAIM_PREFIX,
        leaf_prefix: LEAF_PREFIX,
        node_prefix: NODE_PREFIX,
    }
}
