//! Hash backend seam. The whole construction is written against `BpqsHash`;
//! parameter rows never touch a concrete hash directly. Milestone M2 landed
//! the swap this seam was cut for: the canonical backend is now
//! [`super::poseidon2::Poseidon2GoldilocksHash`] (Poseidon2 over Goldilocks,
//! p3 parameters), with the two FIPS-202 members kept as the audit
//! cross-checks the differential battery compares against.
//!
//! ## Backends
//!
//! - **Canonical**: [`super::poseidon2::Poseidon2GoldilocksHash`] -
//!   Poseidon2-Goldilocks-16 with the BPQS-POSEIDON2-SPONGE-v0 byte binding
//!   (see the poseidon2 module header for the full binding proof sketch).
//! - **Cross-check 1**: [`Sha3_256Hash`] - NIST FIPS 202 fixed-output member,
//!   present and vetted in-tree since M1.
//! - **Cross-check 2**: [`super::shake256::Shake256Hash`] - the FIPS 202
//!   XOF member (domain suffix 0x1F, 32-byte read), implemented in-crate on
//!   the `keccak` permutation because sha3 0.12 ships no SHAKE surface.
//!
//! Research-line usage note: parameter rows with N < 32 truncate the 32-byte
//! digest under their own domain separation; the truncation argument remains
//! part of the security-argument write-up (research bar item 1).
//!
//! ## Domain packaging (canonical byte sketch)
//!
//! Every call is length-prefixed parts after one domain tag:
//!
//! ```text
//! frame = u16le(dom.len()) || dom || S_i [ u32le(parts[i].len()) || parts[i] ]
//! ```
//!
//! so distinct input shapes can never collide into one preimage. All three
//! backends digest this one frame, built once by [`frame_bytes`]; there is a
//! single source for the framing contract and the battery asserts the
//! property matrix per backend.

use alloc::vec::Vec;

use sha3::{Digest, Sha3_256};

/// Anything the construction needs from a hash family: one deterministic,
/// domain-separated 32-byte digest. Parameter rows with N < 32 truncate
/// under their own domain (see crate doc).
pub trait BpqsHash {
    /// Compute a 32-byte digest over `parts` bound to `domain`.
    fn digest32(domain: &[u8], parts: &[&[u8]]) -> [u8; 32];
}

/// Build the canonical framing bytes every backend digests. Single source of
/// the packaging contract; backends differ only in what they do to these
/// bytes afterwards.
pub(crate) fn frame_bytes(domain: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut frame =
        Vec::with_capacity(2 + domain.len() + parts.iter().map(|p| 4 + p.len()).sum::<usize>());
    frame.extend_from_slice(&(domain.len() as u16).to_le_bytes());
    frame.extend_from_slice(domain);
    for part in parts {
        frame.extend_from_slice(&(part.len() as u32).to_le_bytes());
        frame.extend_from_slice(part);
    }
    frame
}

/// SHA3-256 reference backend (NIST FIPS 202). M1's only backend; since M2
/// this is cross-check 1 for the differential battery.
pub struct Sha3_256Hash;

impl BpqsHash for Sha3_256Hash {
    fn digest32(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(frame_bytes(domain, parts));
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
    fn frame_matches_the_documented_sketch() {
        // The byte-level contract auditors re-derive by hand:
        // frame = u16le(dom.len) || dom || u32le(part.len) || part (per part).
        let frame = frame_bytes(b"AB", &[b"xy", b"z"]);
        let expected: &[u8] = &[
            2, 0, b'A', b'B', // u16le(2) || dom
            2, 0, 0, 0, b'x', b'y', // u32le(2) || part 1
            1, 0, 0, 0, b'z', // u32le(1) || part 2
        ];
        assert_eq!(frame, expected);
    }

    #[test]
    fn sha3_256_fips_vector_over_framed_empty_parts() {
        // Framing of H("", [""]) is six zero bytes; the digest must equal the
        // FIPS-202 function applied to those six bytes directly.
        let out = Sha3_256Hash::digest32(b"", &[b""]);
        let mut h = Sha3_256::new();
        h.update([0u8; 6]);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(out, expected);
    }
}
