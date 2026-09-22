//! Cross-check backend 2: SHAKE-256 (the FIPS 202 extendable-output member).
//!
//! ## Why this module exists at all
//!
//! The 2026-09-19 decision named "SHAKE-256 cross-reference" for a reason:
//! the canonical Poseidon backend carries the weakest PQ-hash literature
//! (risk R3 in the pre-registration), so an auditor wants the construction
//! re-scored against a sponge whose analysis base is public and old. The
//! sha3 0.12 crate ships no SHAKE surface (M1 fell back to the SHA3-256
//! fixed-output member for exactly that reason), so this module builds the
//! XOF directly on the vetted `keccak` permutation crate: Keccak-f[1600]
//! sponge, rate 1088 (136 bytes), capacity 512, SHAKE domain suffix 0x1F,
//! pad10*1, 32-byte output read. Nothing here is new cryptography; it is the
//! FIPS 202 algorithm transcribed with the permutation left to the library.
//!
//! Cross-vectors: the unit tests pin outputs generated independently with
//! Python `hashlib.shake_256` (CPython 3, OpenSSL EVP) over edge-length
//! messages, including the exact rate boundaries.

use keccak::Keccak;

use super::hash::{frame_bytes, BpqsHash};

/// Sponge rate for SHAKE-256 in bytes (rate 1088 bits).
const RATE: usize = 136;

/// Run the FIPS 202 sponge over `frame` with the SHAKE suffix and return the
/// first 32 bytes of the XOF stream.
fn shake256_32(frame: &[u8]) -> [u8; 32] {
    let keccak = Keccak::new();
    let mut st = [0u64; 25];
    let mut offset = 0usize;
    while frame.len() - offset >= RATE {
        xor_block(&mut st, &frame[offset..offset + RATE]);
        keccak.with_f1600(|f1600| f1600(&mut st));
        offset += RATE;
    }
    // Final partial block: suffix 0x1F (SHAKE), then pad10*1 with the
    // mandatory terminator bit on the last rate byte. 0x1F < 0x80, so the
    // "suffix fills the last byte" edge (which would need one extra
    // permutation before the terminator) never occurs for SHAKE.
    let rem = &frame[offset..];
    let mut block = [0u8; RATE];
    block[..rem.len()].copy_from_slice(rem);
    block[rem.len()] ^= 0x1F;
    block[RATE - 1] ^= 0x80;
    xor_block(&mut st, &block);
    keccak.with_f1600(|f1600| f1600(&mut st));
    // 32 output bytes < 136-byte rate: the read never crosses a boundary,
    // so no re-permutation on this path ever.
    let mut out = [0u8; 32];
    for (i, lane) in st[..4].iter().enumerate() {
        out[8 * i..8 * i + 8].copy_from_slice(&lane.to_le_bytes());
    }
    out
}

fn xor_block(st: &mut [u64; 25], block: &[u8]) {
    debug_assert_eq!(block.len(), RATE);
    for (i, chunk) in block.chunks(8).enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        st[i] ^= u64::from_le_bytes(buf);
    }
}

/// SHAKE-256 backend behind the [`BpqsHash`] seam: FIPS 202 XOF with the
/// 0x1F suffix. Distinct function from [`super::hash::Sha3_256Hash`] (their
/// domain suffixes differ by construction); both stay in the tree as the
/// audit cross-checks of the canonical Poseidon2 backend.
pub struct Shake256Hash;

impl BpqsHash for Shake256Hash {
    fn digest32(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        shake256_32(&frame_bytes(domain, parts))
    }
}

#[cfg(test)]
mod shake256_tests {
    use super::*;
    use crate::hash::BpqsHash;

    fn hx(s: &str) -> [u8; 32] {
        let bytes: alloc::vec::Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex literal"))
            .collect();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    fn pattern(len: usize) -> alloc::vec::Vec<u8> {
        (0..len).map(|i| ((i * 7 + 3) % 256) as u8).collect()
    }

    #[test]
    fn nist_empty_message_vector() {
        // Cross-implementation anchor (Python hashlib.shake_256):
        // shake256("")[:32] = 46b9dd2b0ba88d13...6ed5762f
        assert_eq!(
            shake256_32(b""),
            hx("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"),
        );
    }

    #[test]
    fn abc_vector() {
        assert_eq!(
            shake256_32(b"abc"),
            hx("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"),
        );
    }

    #[test]
    fn rate_boundary_vectors() {
        // A sponge is one padding branch away from a silent wrong answer;
        // pin each boundary of the 136-byte rate.
        assert_eq!(
            shake256_32(&pattern(135)),
            hx("0213fc98352f009fafdf8ee1ea36391485a85aa6f6c07a5cd81266d21eb17f9a"),
            "rate - 1",
        );
        assert_eq!(
            shake256_32(&pattern(136)),
            hx("c00f43811e5b4a38e14e3c06d8a5ce34115a19cd604ce5bac6c3823b76046d5c"),
            "rate",
        );
        assert_eq!(
            shake256_32(&pattern(137)),
            hx("3c983983487bcbe74feba53b35bb1e05812379cb4116d9761f78d2ce3177866e"),
            "rate + 1",
        );
        assert_eq!(
            shake256_32(&pattern(272)),
            hx("fbb7df100461f5db3224c3b715603b5a52f92bd0f761d9361d4aa0613d47033b"),
            "two full rates",
        );
    }

    #[test]
    fn shake_is_not_sha3_over_the_same_frame() {
        // The suffix differs (0x1F vs 0x06), so the two FIPS-202 members must
        // not alias: a backend mixup has to scream here.
        let frame = frame_bytes(b"DOM", &[b"payload"]);
        assert_ne!(
            shake256_32(&frame),
            crate::hash::Sha3_256Hash::digest32(b"DOM", &[b"payload"]),
        );
    }

    #[test]
    fn hash_face_matches_contract() {
        let a = Shake256Hash::digest32(b"DOM-A", &[b"payload"]);
        let b = Shake256Hash::digest32(b"DOM-B", &[b"payload"]);
        assert_ne!(a, b);
        let x = Shake256Hash::digest32(b"D", &[b"ab", b"c"]);
        let y = Shake256Hash::digest32(b"D", &[b"a", b"bc"]);
        assert_ne!(x, y);
    }
}
