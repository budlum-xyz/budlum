//! The hash `H` and the domain tags of the aggregation layer.
//!
//! `H` is Keccak-256 (the original padding, not SHA3-256): it is the hash the
//! `BudZKVM` STARK configuration commits with, so the node and the proving
//! program agree on every digest without a second hash inside the circuit.
//!
//! Every preimage starts with one of the tags below. The tags are constants,
//! they differ from each other and none is a prefix of another, and every
//! field after a tag has a fixed width except the last one, so two different
//! inputs never share a preimage.

use sha3::{Digest, Keccak256};

use crate::domain::types::Hash32;

/// Tag of a claim digest.
pub const TAG_CLAIM: &[u8] = b"BDLM_CLAIM_V1";
/// Tag of the claim Merkle tree, for leaves and inner nodes.
pub const TAG_CLAIM_ROOT: &[u8] = b"BDLM_CLAIM_ROOT_V1";
/// Tag of the public input of a tick proof.
pub const TAG_AGG_TICK: &[u8] = b"BDLM_AGG_TICK_V1";
/// Tag of the public input of a merge proof.
pub const TAG_AGG_MERGE: &[u8] = b"BDLM_AGG_MERGE_V1";
/// Tag of an object id.
pub const TAG_OBJECT: &[u8] = b"BDLM_OBJECT_V1";
/// Tag of a frame hash.
pub const TAG_FRAME: &[u8] = b"BDLM_FRAME_V1";
/// Tag of the output a successful authorization program writes.
const TAG_AUTH_OK: &[u8] = b"BDLM_AUTH_OK_V1";

/// `H` over the concatenation of `parts`.
#[must_use]
pub fn h(parts: &[&[u8]]) -> Hash32 {
    let mut hasher = Keccak256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// `AUTH_OK = H("BDLM_AUTH_OK_V1")`: the output hash an authorization program
/// writes when it accepts.
///
/// WIRING: the account rule of program accounts compares the output hash of
/// a `Claim::Prog` with this value. Program accounts arrive with the program
/// claims of Phase 4.
#[must_use]
pub fn auth_ok() -> Hash32 {
    h(&[TAG_AUTH_OK])
}
