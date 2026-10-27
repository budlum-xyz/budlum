//! Field-native Poseidon helpers matching in-repo `budzero/bud-vm`.
//!
//! The permutation is not written here. It is the Poseidon parameter set
//! (Goldilocks, width 12, 8 full and 22 partial rounds, capacity 4), defined once in
//! `budlum-note-packing` and read by `budzero/bud-vm`, by the `budzero/bud-proof` AIR
//! and by this wallet. A wallet that computed a commitment with a different function
//! than the VM proves would produce notes and nullifiers no proof can open, so there is
//! no copy to drift: `budzero/bud-proof/tests/poseidon_parity.rs` checks the shared
//! definition against Plonky3's own permutation, and the tests below pin this file to
//! the shared definition.

use budlum_note_packing::poseidon;

/// Domain separator for nullifier derivation, ASCII "NULLIFER".
pub const DOMAIN_NULLIFIER: u64 = 0x4e55_4c4c_4946_4552;

/// Lane 0 of the permutation of a 12-lane state: the value the VM `Poseidon`
/// opcode writes. It keeps its historical name so call sites do not churn.
#[must_use]
pub fn poseidon4_hash_state(state: [u64; poseidon::WIDTH]) -> u64 {
    poseidon::permute(state)[0]
}

/// Absorb up to the first lanes and zero the rest, as the VM does.
fn lanes(head: &[u64]) -> [u64; poseidon::WIDTH] {
    let mut state = [0u64; poseidon::WIDTH];
    for (lane, word) in state.iter_mut().zip(head.iter()) {
        *lane = *word;
    }
    state
}

#[must_use]
pub fn poseidon4_hash(a: u64, b: u64) -> u64 {
    poseidon4_hash_state(lanes(&[a, b]))
}

/// PrivacyCommit absorption: Poseidon3(amount, blinding, recipient).
#[must_use]
pub fn poseidon4_hash3(a: u64, b: u64, c: u64) -> u64 {
    poseidon4_hash_state(lanes(&[a, b, c]))
}

/// Commitment = Poseidon3(amount, blinding, recipient_tag)
#[must_use]
/// Parameter order matches VM PrivacyCommit opcode:
/// `poseidon4_hash3(amount, blinding, recipient_tag)`. Blinding is full u64
/// From register (no u32 truncation). Recipient tag from imm field (i32).
pub fn privacy_commit(amount: u64, blinding: u64, recipient_tag: u64) -> u64 {
    poseidon4_hash3(amount, blinding, recipient_tag)
}

/// Nullifier = Poseidon2(secret, DOMAIN_NULLIFIER)
#[must_use]
pub fn privacy_nullifier(secret: u64) -> u64 {
    poseidon4_hash(secret, DOMAIN_NULLIFIER)
}

// Packing is `budlum-note-packing`'s single definition, re-exported under the
// names the wallet already used. The chain indexes commitments and nullifiers
// by exactly these bytes, so the wallet must not hold its own copy of the
// rule: a one-byte divergence produces a nullifier the chain never recorded,
// and the spend it was meant to prevent goes through.
pub use budlum_note_packing::{field_from_hash, hash_from_field, is_packed};

/// Map a 32-byte Budlum address into a Goldilocks field tag (first 8 LE bytes
/// Reduced mod P). Used as PrivacyCommit recipient limb when full address
/// Does not fit in one field element.
#[must_use]
pub fn address_to_recipient_tag(addr: &[u8; 32]) -> u64 {
    // Destructured rather than sliced-and-`try_into`-ed. Both express "take
    // the first eight bytes", but slicing leaves a panic branch that the
    // compiler cannot see is dead, so the honest `.expect()` on it is a claim
    // a reader has to verify. A pattern on a fixed-size array is checked when
    // the crate is built: there is no branch left to reason about.
    let [b0, b1, b2, b3, b4, b5, b6, b7, ..] = *addr;
    let raw = u64::from_le_bytes([b0, b1, b2, b3, b4, b5, b6, b7]);
    // BLG-0282 (P17-F16, accepted with documentation): `%` is not a
    // constant-time modular reduction and this fold consumes secret note
    // material. Accepted because wallet-core is unwired to any network or
    // consensus path (the node's own fold lives in bud-state, matching this
    // one byte-for-byte), so there is no remote observer to time against.
    // A constant-time rewrite happens in BOTH places together, if this ever
    // joins a hot path - changing one alone would split the two folds,
    // which is the worse bug.
    raw % budlum_note_packing::GOLDILOCKS_P
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_nullifier_constant_matches_spec() {
        assert_eq!(DOMAIN_NULLIFIER, 0x4e55_4c4c_4946_4552);
    }

    #[test]
    fn poseidon_two_vs_three_absorb_differ() {
        let a = poseidon4_hash(1, 2);
        let b = poseidon4_hash3(1, 2, 0);
        // State [1,2,0,...] vs [1,2,0,...] - hash3 with c=0 equals hash2
        assert_eq!(a, b);
        assert_ne!(poseidon4_hash3(1, 2, 3), a);
    }

    #[test]
    fn commit_nullifier_roundtrip_shapes() {
        let c = privacy_commit(100, 99, 7); // S1: (amount, blinding, recipient_tag)
        let n = privacy_nullifier(0xA11CE);
        assert_ne!(c, 0);
        assert_ne!(n, 0);
        assert_eq!(field_from_hash(&hash_from_field(c)), c);
    }

    /// The wallet computes exactly what the shared definition computes: lane 0 of the
    /// permutation of the zero-padded state. The shared definition is what the VM runs.
    #[test]
    fn the_wallet_hash_is_the_shared_k14_permutation() {
        let mut state = [0u64; poseidon::WIDTH];
        state[..3].copy_from_slice(&[1, 2, 3]);
        assert_eq!(poseidon4_hash3(1, 2, 3), poseidon::permute(state)[0]);
        state[2] = 0;
        assert_eq!(poseidon4_hash(1, 2), poseidon::permute(state)[0]);
        assert_eq!(privacy_nullifier(9), poseidon4_hash(9, DOMAIN_NULLIFIER));
    }

    /// The round schedule the wallet runs is the one: 8 full and 22 partial rounds
    /// over a 12-lane state with a capacity of 4.
    #[test]
    fn the_schedule_is_k14() {
        assert_eq!(poseidon::WIDTH, 12);
        assert_eq!(poseidon::CAPACITY, 4);
        assert_eq!(poseidon::FULL_ROUNDS, 8);
        assert_eq!(poseidon::PARTIAL_ROUNDS, 22);
        assert_eq!(poseidon::ROUNDS, 30);
    }
}
