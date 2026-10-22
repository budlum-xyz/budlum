//! One length-prefixed preimage for a validator's consensus key set.
//!
//! # The collision
//!
//! Four consensus digests hash a validator's keys by appending them one after
//! another with nothing between:
//!
//! ```text
//! hasher.update(&v.vrf_public_key);
//! hasher.update(&v.bls_public_key);
//! hasher.update(&v.pop_signature);
//! hasher.update(&v.pq_public_key);
//! ```
//!
//! Each field is a `Vec<u8>` whose length is not written down. Concatenation
//! without lengths is not injective: a 96-byte BLS key followed by a 48-byte
//! `PoP` produces the same bytes as a 144-byte BLS key followed by an empty `PoP`,
//! and the same bytes again as an empty BLS key followed by a 144-byte `PoP`.
//! Every one of those hashes identically.
//!
//! The four sites are `AccountState::calculate_state_root`,
//! `AccountState::consensus_validator_set_hash`,
//! `ValidatorSetSnapshot::compute_hash` and the validator loop inside
//! `StateSnapshotV2::calculate_digest`. The first is the state root two nodes
//! compare to agree they are on the same chain, and the last is what a syncing
//! node checks a downloaded snapshot against.
//!
//! # Why it is reachable
//!
//! `Validator` is a plain `serde` struct with `#[serde(default)]` on all four
//! key fields, and it crosses the wire inside a snapshot. Nothing in
//! `from_snapshot_v2` or `AccountState::from_snapshot` re-derives the split:
//! the restore copies the four vectors verbatim.
//!
//! So a snapshot carrying `bls = real_bls || real_pop, pop = []` reproduces the
//! honest state root exactly, passes `verify()`, passes the block-hash and
//! state-root comparisons in `apply_v2_snapshot`, and installs a validator set
//! in which that validator has no `PoP`. `is_consensus_ready` then excludes it
//! from `build_validator_snapshot_from_state`, so the restoring node computes a
//! different active set and a different `set_hash` from its peers while both
//! agree on the state root. That is a partition with no error message pointing
//! at its cause.
//!
//! The gap between "the digest agrees" and "the set agrees" is the whole
//! problem: the digest was never a commitment to the split.
//!
//! # The fix
//!
//! Write each field's length before the field. `(96, bls) (48, pop)` and
//! `(144, bls) (0, pop)` then differ in the first eight bytes, and no
//! re-splitting survives.
//!
//! Length prefixes rather than a validity check, because the four sites hash
//! validators that are *not* consensus-ready on purpose. A bonded validator
//! that has not registered keys yet has four empty vectors and has to be in the
//! state root; rejecting it would be a different and much larger change. The
//! encoding has to be injective over every shape the type can hold, not only
//! over the valid ones.
//!
//! One function rather than four copies, because four copies is how the tree
//! got here: the sites were written at different times and none of them
//! carried the reasoning.
//!
//! # Consensus surface
//!
//! This changes the preimage of the state root, so it is a breaking change for
//! any chain with a non-empty validator set. There is no compatibility branch:
//! a versioned digest would mean carrying the collision forward under a flag,
//! and a flag that selects a colliding encoding is a flag an attacker chooses.

/// Append a length-prefixed byte string to a hasher.
///
/// The length goes in as a little-endian `u64`, matching every other integer
/// in the consensus preimages in this tree.
fn update_with_length(hasher: &mut impl sha3::Digest, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Same, for the `sha2` hasher used by `calculate_state_root`.
fn update_with_length_sha2(hasher: &mut impl sha2::Digest, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Hash a validator's four consensus key fields, length-prefixed.
///
/// `vrf` is `None` at the two sites whose preimage never carried it
/// (`ValidatorSetSnapshot::compute_hash` and the `StateSnapshotV2` validator
/// loop both hash BLS, `PoP` and PQ only). Passing `None` keeps those preimages
/// at three fields rather than silently widening them, which would be a second
/// consensus change riding along with this one.
pub fn update_consensus_keys_sha3(
    hasher: &mut impl sha3::Digest,
    vrf: Option<&[u8]>,
    bls: &[u8],
    pop: &[u8],
    pq: &[u8],
) {
    if let Some(vrf) = vrf {
        update_with_length(hasher, vrf);
    }
    update_with_length(hasher, bls);
    update_with_length(hasher, pop);
    update_with_length(hasher, pq);
}

/// The `sha2` twin of [`update_consensus_keys_sha3`].
///
/// `AccountState::calculate_state_root` builds its per-validator leaf with
/// `Sha256` from the `sha2` crate while the other three sites use `Sha3_256`.
/// The two hasher traits do not unify, and reaching for a generic bound over
/// both pulls `digest` version skew into a consensus path. Two functions with
/// one body each is the cheaper honesty.
pub fn update_consensus_keys_sha2(
    hasher: &mut impl sha2::Digest,
    vrf: Option<&[u8]>,
    bls: &[u8],
    pop: &[u8],
    pq: &[u8],
) {
    if let Some(vrf) = vrf {
        update_with_length_sha2(hasher, vrf);
    }
    update_with_length_sha2(hasher, bls);
    update_with_length_sha2(hasher, pop);
    update_with_length_sha2(hasher, pq);
}

#[cfg(test)]
mod tests {
    use super::*;
    // One `Digest` import covers both hashers. `sha2` 0.11 and `sha3` 0.12
    // re-export the same trait from the `digest` crate, so importing the
    // second is an unused import and `-D warnings` refuses it. The two
    // production functions still take their bounds separately, because the
    // bound is what documents which hasher each call site uses.
    use sha2::{Digest, Sha256};
    use sha3::Sha3_256;

    /// The collision this module exists to close, in the shape it had.
    ///
    /// A 96-byte BLS key and a 48-byte `PoP` concatenate to the same 144 bytes as
    /// a 144-byte BLS key and an empty `PoP`. Under the old encoding both hashed
    /// identically; under this one they must not.
    #[test]
    fn refolding_a_key_into_its_neighbour_changes_the_digest() {
        let bls = vec![2u8; 96];
        let pop = vec![3u8; 48];
        let pq = vec![4u8; 2592];

        let mut honest = Sha3_256::new();
        update_consensus_keys_sha3(&mut honest, None, &bls, &pop, &pq);

        let mut refolded_bytes = bls.clone();
        refolded_bytes.extend_from_slice(&pop);
        let mut refolded = Sha3_256::new();
        update_consensus_keys_sha3(&mut refolded, None, &refolded_bytes, &[], &pq);

        assert_ne!(
            honest.finalize(),
            refolded.finalize(),
            "a 96+48 split and a 144+0 split must not share a preimage; that \
             collision let a snapshot reproduce the honest state root while \
             carrying a validator with no proof of possession"
        );
    }

    /// And the other direction: the whole pair folded into the `PoP`.
    #[test]
    fn folding_the_other_way_also_changes_the_digest() {
        let bls = vec![2u8; 96];
        let pop = vec![3u8; 48];
        let pq = vec![4u8; 32];

        let mut honest = Sha3_256::new();
        update_consensus_keys_sha3(&mut honest, None, &bls, &pop, &pq);

        let mut all_in_pop = bls.clone();
        all_in_pop.extend_from_slice(&pop);
        let mut forged = Sha3_256::new();
        update_consensus_keys_sha3(&mut forged, None, &[], &all_in_pop, &pq);

        assert_ne!(honest.finalize(), forged.finalize());
    }

    /// The boundary between the last key and whatever the caller hashes next.
    ///
    /// `pq` is the final field at three of the four sites, and at two of them
    /// the loop immediately hashes the next validator. Without a length on
    /// `pq`, a long key on one validator and a short key on the next could
    /// trade bytes across the boundary.
    #[test]
    fn the_last_field_cannot_bleed_into_the_next_validator() {
        let mut a = Sha3_256::new();
        update_consensus_keys_sha3(&mut a, None, &[1], &[2], &[3, 4]);
        update_consensus_keys_sha3(&mut a, None, &[5], &[6], &[7]);

        let mut b = Sha3_256::new();
        update_consensus_keys_sha3(&mut b, None, &[1], &[2], &[3]);
        update_consensus_keys_sha3(&mut b, None, &[4, 5], &[6], &[7]);

        assert_ne!(
            a.finalize(),
            b.finalize(),
            "two validators must not be able to trade bytes across the \
             boundary between them"
        );
    }

    /// The same properties on the `sha2` side, because `calculate_state_root`
    /// is the digest nodes compare to decide they are on the same chain and it
    /// uses the other hasher.
    #[test]
    fn the_sha2_encoding_is_injective_over_the_same_refolding() {
        let bls = vec![2u8; 96];
        let pop = vec![3u8; 48];

        let mut honest = Sha256::new();
        update_consensus_keys_sha2(&mut honest, Some(&[1u8; 32]), &bls, &pop, &[]);

        let mut refolded_bytes = bls.clone();
        refolded_bytes.extend_from_slice(&pop);
        let mut refolded = Sha256::new();
        update_consensus_keys_sha2(&mut refolded, Some(&[1u8; 32]), &refolded_bytes, &[], &[]);

        assert_ne!(honest.finalize(), refolded.finalize());
    }

    /// The VRF field is the one that moves between call sites, so refolding
    /// across the VRF boundary has to be caught too.
    #[test]
    fn the_vrf_field_cannot_absorb_the_bls_key() {
        let vrf = vec![1u8; 32];
        let bls = vec![2u8; 96];

        let mut honest = Sha256::new();
        update_consensus_keys_sha2(&mut honest, Some(&vrf), &bls, &[], &[]);

        let mut absorbed = vrf.clone();
        absorbed.extend_from_slice(&bls);
        let mut forged = Sha256::new();
        update_consensus_keys_sha2(&mut forged, Some(&absorbed), &[], &[], &[]);

        assert_ne!(honest.finalize(), forged.finalize());
    }

    /// Omitting the VRF field must not produce the preimage of a present but
    /// empty one, or the two call-site shapes collide with each other.
    #[test]
    fn an_omitted_vrf_is_not_an_empty_vrf() {
        let mut omitted = Sha3_256::new();
        update_consensus_keys_sha3(&mut omitted, None, &[2], &[3], &[4]);

        let mut empty = Sha3_256::new();
        update_consensus_keys_sha3(&mut empty, Some(&[]), &[2], &[3], &[4]);

        assert_ne!(
            omitted.finalize(),
            empty.finalize(),
            "the three-field and four-field shapes must stay distinct; a \
             collision between them would let a snapshot digest be read as a \
             validator-set digest"
        );
    }

    /// The honest path agrees with itself; otherwise the result is a fork.
    /// extra steps rather than a fix.
    #[test]
    fn the_same_keys_hash_the_same_way_twice() {
        let make = || {
            let mut h = Sha3_256::new();
            update_consensus_keys_sha3(&mut h, Some(&[1u8; 32]), &[2u8; 96], &[3u8; 48], &[4u8; 8]);
            h.finalize()
        };
        assert_eq!(make(), make());
    }
}
