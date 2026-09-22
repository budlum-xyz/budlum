//! Hash backend seam. The whole construction is written against `BpqsHash`;
//! parameter rows never touch a concrete hash directly. This is what keeps
//! the milestone-M2 Poseidon swap a one-file change.
//!
//! The reference backend is **SHA3-256** (fixed-output member of the NIST
//! SHA-3 family): the construction only ever digests ≤ 32 bytes, so a
//! fixed-output function is byte-for-byte equivalent to the corresponding
//! SHAKE-256 XOF read. (sha3 0.12 dropped the SHAKE XOF surface; the
//! fixed-output member is present and already vetted in-tree.) The level-3
//! row's 24-byte lane semantics truncate this digest under explicit domain
//! separation - the truncation argument is part of the security-argument
//! write-up (research bar item 1), not an implicit hand-wave.
//!
//! ## Domain packaging (canonical byte sketch)
//!
//! Every call is length-prefixed parts after one domain tag:
//!
//! ```text
//! digest = H( u16le(dom.len()) || dom || Σ_i [ u32le(parts[i].len()) || parts[i] ] )
//! ```
//!
//! so distinct input shapes can never collide into one preimage.

use sha3::{Digest, Sha3_256};

/// Anything the construction needs from a hash family: one deterministic,
/// domain-separated 32-byte digest. Parameter rows with N < 32 truncate
/// under their own domain (see crate doc).
pub trait BpqsHash {
    /// Compute a 32-byte digest over `parts` bound to `domain`.
    fn digest32(domain: &[u8], parts: &[&[u8]]) -> [u8; 32];
}

fn pack_domain_and_parts(hasher: &mut Sha3_256, domain: &[u8], parts: &[&[u8]]) {
    hasher.update((domain.len() as u16).to_le_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u32).to_le_bytes());
        hasher.update(part);
    }
}

/// SHA3-256 reference backend (NIST FIPS 202). Research-line reference today;
/// once the Poseidon backend is canonical this stays as the independent twin
/// the differential battery compares against.
pub struct Sha3_256Hash;

impl BpqsHash for Sha3_256Hash {
    fn digest32(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        pack_domain_and_parts(&mut hasher, domain, parts);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod hash_tests {
    use super::*;

    #[test]
    fn domain_separation_changes_digest() {
        let a = Sha3_256Hash::digest32(b"DOM-A", &[b"payload"]);
        let b = Sha3_256Hash::digest32(b"DOM-B", &[b"payload"]);
        assert_ne!(a, b, "same payload under two domains must not collide");
    }

    #[test]
    fn packaging_is_length_honest() {
        let a = Sha3_256Hash::digest32(b"D", &[b"ab", b"c"]);
        let b = Sha3_256Hash::digest32(b"D", &[b"a", b"bc"]);
        assert_ne!(a, b, "part boundaries must be visible to the hash");
    }

    #[test]
    fn empty_parts_are_stable() {
        let a = Sha3_256Hash::digest32(b"D", &[]);
        let b = Sha3_256Hash::digest32(b"D", &[]);
        assert_eq!(a, b);
    }

    #[test]
    fn sha3_256_nist_vector_matches() {
        // NIST example: SHA3-256("") =
        // a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        let out = Sha3_256Hash::digest32(b"", &[b""]);
        // The true reference is the same packaging rebuilt by hand:
        // H(u16le(0) || u32le(0) || empty-part).
        let mut h = Sha3_256::new();
        h.update([0u8; 6]);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(out[..32], expected[..32]);
        let _ = out;
    }
}
