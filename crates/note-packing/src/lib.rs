//! How a privacy note's field element becomes a 32-byte hash, defined once.
//!
//! The zkVM produces Goldilocks field elements. The chain stores 32-byte
//! hashes. Something has to say how one becomes the other, and until this
//! crate existed three places said it independently:
//!
//! - `budzero/bud-state/src/note.rs`, where the zkVM state layer builds a
//!   `PrivacyNote` out of the commitment and nullifier the VM computed,
//! - `wallet-core/src/privacy_crypto.rs`, where the wallet builds the same
//!   two values before it signs a transfer,
//! - `src/privacy/note_registry.rs`, which stores neither field elements nor
//!   the packing itself, but consumes its output as `NoteHash` and compares
//!   it for equality against what the wallet sent.
//!
//! The three agreed. Nothing made them agree. The failure that shape invites
//! is not a compile error and not a failing test: if the wallet's packing and
//! the chain's packing ever diverge by one byte, the wallet computes a
//! nullifier the chain has never seen, `is_nullifier_spent` answers false for
//! a note that was already spent, and `contains_commitment` answers false for
//! a note that exists. The transfer is refused, or worse, accepted twice. The
//! money is gone quietly, and every individual crate's tests still pass,
//! because each one tests its own copy against itself.
//!
//! A round-trip test does not catch it either. Each copy round-trips
//! perfectly; that is exactly the property a copy preserves while drifting.
//! Only a single definition removes the failure, so this crate is the
//! definition and the other three call it.
//!
//! # The rule
//!
//! A field element occupies the low eight bytes, little-endian. The upper
//! twenty-four bytes are zero. This is a packing, not a hash: it is
//! injective, reversible, and carries no collision resistance of its own. The
//! collision resistance belongs to the Poseidon call that produced the field
//! element in the first place.
//!
//! # Why the high bytes are zero rather than a domain tag
//!
//! Zero padding means the hash space of packed notes is a sparse subset of
//! the full 32-byte space, which is a virtue here: the note subtree is
//! isolated from the account, NFT, B.U.D. and Pollen state, so a packed note
//! hash cannot be confused with a hash from another subtree by construction
//! rather than by convention. A domain tag in the high bytes would add
//! nothing this isolation does not already provide, and would silently
//! invalidate every note already recorded under the current rule.

#![forbid(unsafe_code)]
#![no_std]

/// A packed note hash: commitment or nullifier, as stored on chain.
pub type NoteHash = [u8; 32];

/// Bytes a field element occupies. The rest of a [`NoteHash`] is zero.
pub const FIELD_BYTES: usize = 8;

/// The Goldilocks prime, `2^64 - 2^32 + 1`.
///
/// Present so callers can ask [`is_canonical_field`] whether a value they are
/// about to pack is one the field can actually represent. Packing itself does
/// not reduce: a caller handing over a non-canonical value has a bug upstream
/// in its own arithmetic, and quietly reducing it here would hide that bug
/// behind a hash that looks fine.
pub const GOLDILOCKS_P: u64 = 0xFFFF_FFFF_0000_0001;

/// Pack a field element into a note hash.
///
/// The inverse is [`field_from_hash`], exactly for hashes this produced.
#[must_use]
pub const fn hash_from_field(fe: u64) -> NoteHash {
    let b = fe.to_le_bytes();
    [
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]
}

/// Read the field element back out of a note hash.
///
/// Reads the low eight bytes and ignores the rest, which is lossless for any
/// hash [`hash_from_field`] produced. For a hash from anywhere else the upper
/// bytes carry information this drops, so a caller comparing notes for
/// identity must compare the full [`NoteHash`] and not the field elements:
/// two distinct foreign hashes can share their low eight bytes, and treating
/// them as the same note is how a double spend gets through. [`is_packed`]
/// answers whether a given hash is one this module could have produced.
#[must_use]
pub fn field_from_hash(h: &NoteHash) -> u64 {
    let mut b = [0u8; FIELD_BYTES];
    b.copy_from_slice(&h[..FIELD_BYTES]);
    u64::from_le_bytes(b)
}

/// Whether a hash is one [`hash_from_field`] could have produced.
///
/// False means the upper bytes are non-zero, so [`field_from_hash`] would
/// silently discard them.
#[must_use]
pub fn is_packed(h: &NoteHash) -> bool {
    let mut i = FIELD_BYTES;
    while i < 32 {
        if h[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

/// Whether a value is a canonical Goldilocks field element.
///
/// The VM should never emit a non-canonical one. This exists so a caller can
/// assert that rather than assume it.
#[must_use]
pub const fn is_canonical_field(fe: u64) -> bool {
    fe < GOLDILOCKS_P
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_is_exact_across_the_whole_range() {
        for fe in [
            0,
            1,
            u64::from(u32::MAX),
            GOLDILOCKS_P - 1,
            GOLDILOCKS_P,
            u64::MAX,
        ] {
            assert_eq!(field_from_hash(&hash_from_field(fe)), fe, "fe = {fe}");
        }
    }

    #[test]
    fn the_packing_is_little_endian_and_the_rest_is_zero() {
        // Written out by hand rather than derived from the function, so this
        // test fails if the rule changes rather than following it.
        let h = hash_from_field(0x0807_0605_0403_0201);
        assert_eq!(&h[..8], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert!(h[8..].iter().all(|b| *b == 0));
    }

    #[test]
    fn packing_is_injective() {
        // Distinct field elements never share a hash, which is what lets the
        // registry treat hash equality as note identity.
        let mut seen = [[0u8; 32]; 64];
        for (i, slot) in seen.iter_mut().enumerate() {
            *slot = hash_from_field(1u64 << (i % 64));
        }
        for i in 0..seen.len() {
            for j in (i + 1)..seen.len() {
                if (i % 64) != (j % 64) {
                    assert_ne!(seen[i], seen[j]);
                }
            }
        }
    }

    #[test]
    fn is_packed_rejects_a_hash_with_a_high_byte_set() {
        let mut h = hash_from_field(42);
        assert!(is_packed(&h));
        h[31] = 1;
        assert!(!is_packed(&h));
        // And this is the case where reading the field back would lie: the
        // two hashes are different notes and report the same element.
        assert_eq!(field_from_hash(&h), 42);
    }

    #[test]
    fn canonical_check_matches_the_field() {
        assert!(is_canonical_field(GOLDILOCKS_P - 1));
        assert!(!is_canonical_field(GOLDILOCKS_P));
        assert!(!is_canonical_field(u64::MAX));
    }
}
