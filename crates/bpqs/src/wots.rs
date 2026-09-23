//! Winternitz core, in the shape every hash-based signature's reference
//!
//! WIRING: `chain_step`, `digits_of` and `vk_compress` are the auditable
//! primitives of the chain math; the signing surface composes them, and the
//! anchor family integration (research line F2, bar item 2) completes the
//! production call chain.
//! implementation carries. Message encoding: the digest (its first
//! `P::N` bytes; lanes are 32-byte wide with the tail zeroed) becomes
//! `P::LEN1` base-16 digits (nibbles, high nibble first); a checksum over
//! the digits fills `P::LEN2` more digits, so a forger that needs to raise
//! one digit must lower another - which the one-way chains refuse.
//!
//! Sign step for digit value `d`: chain segment starting at step `d`.
//! Verify step: continue the segment to the chain end and compare.
//!
//! Width discipline: every lane is a 32-byte value whose meaningful prefix
//! is `P::N` bytes; all hashes read exactly that prefix and zero-fill the
//! rest, so `w=16` chains of level-3 lanes stay canonically padded.

use alloc::vec::Vec;

use crate::domains;
use crate::hash::BpqsHash;
use crate::params::BpqsParams;

fn lane<P: BpqsParams>(x: &[u8; 32]) -> [u8; 32] {
    debug_assert!(
        x[P::N..].iter().all(|b| *b == 0),
        "lanes are canonically padded"
    );
    *x
}

/// Expand the per-epoch seed into the `P::LEN` secret chain roots (the epoch
/// secret key material).
pub fn epoch_secret_chains<H: BpqsHash, P: BpqsParams>(epoch_seed: &[u8; 32]) -> [[u8; 32]; 256] {
    // Production parameter rows have LEN <= 96 (L5 67, L3 51); the flat
    // buffer is indexed so the function is panic-free.
    let mut out = [[0u8; 32]; 256];
    for (i, slot) in out.iter_mut().take(P::LEN).enumerate() {
        let wide = H::digest32(
            domains::WOTS_CHAIN_SEED,
            &[epoch_seed, &(i as u32).to_le_bytes()],
        );
        slot[..P::N].copy_from_slice(&wide[..P::N]);
        debug_assert!(slot[P::N..].iter().all(|b| *b == 0));
    }
    out
}

/// One step of a chain: hash the lane's meaningful prefix with the chain id.
pub fn chain_step<H: BpqsHash, P: BpqsParams>(x: &[u8; 32], chain: u32) -> [u8; 32] {
    let lane = lane::<P>(x);
    let wide = H::digest32(
        domains::WOTS_CHAIN_STEP,
        &[&lane[..P::N], &chain.to_le_bytes()],
    );
    let mut out = [0u8; 32];
    out[..P::N].copy_from_slice(&wide[..P::N]);
    out
}

fn chain_repeat<H: BpqsHash, P: BpqsParams>(x: &[u8; 32], steps: usize, chain: u32) -> [u8; 32] {
    let mut cur = lane::<P>(x);
    for _ in 0..steps {
        cur = chain_step::<H, P>(&cur, chain);
    }
    cur
}

fn chain_walk<H: BpqsHash, P: BpqsParams>(x: &[u8; 32], steps: usize, chain: u32) -> [u8; 32] {
    chain_repeat::<H, P>(x, steps, chain)
}

/// Message digest -> digits (message nibbles + checksum nibbles).
pub fn digits_of<P: BpqsParams>(msg: &[u8; 32]) -> [u8; 256] {
    let mut digits = [0u8; 256];
    let mut cursor = 0usize;
    for byte in msg[..P::N].iter().take(P::N) {
        digits[cursor] = byte >> 4;
        digits[cursor + 1] = byte & 0x0f;
        cursor += 2;
    }
    debug_assert_eq!(cursor, P::LEN1);
    let mut checksum: u32 = 0;
    for d in digits.iter().take(P::LEN1) {
        checksum += P::WIN - 1 - *d as u32;
    }
    for i in 0..P::LEN2 {
        let shift = 4 * (P::LEN2 - 1 - i);
        digits[cursor + i] = ((checksum >> shift) & 0x0f) as u8;
    }
    digits
}

/// Compress chain heads into the single epoch verification digest (the Merkle
/// leaf's committed value).
pub fn vk_compress<H: BpqsHash, P: BpqsParams>(heads: &[[u8; 32]; 256]) -> [u8; 32] {
    let mut concat = Vec::with_capacity(P::LEN * P::N);
    for h in heads.iter().take(P::LEN) {
        concat.extend_from_slice(&h[..P::N]);
    }
    let wide = H::digest32(domains::WOTS_VK_COMPRESS, &[&concat]);
    let mut out = [0u8; 32];
    out[..P::N].copy_from_slice(&wide[..P::N]);
    out
}

/// The verification digest of the epoch key: every chain walked to its end.
pub fn vk_of_chains<H: BpqsHash, P: BpqsParams>(chains: &[[u8; 32]; 256]) -> [u8; 32] {
    let mut heads = [[0u8; 32]; 256];
    for (i, head) in heads.iter_mut().take(P::LEN).enumerate() {
        *head = chain_walk::<H, P>(&chains[i], P::WIN as usize - 1, i as u32);
    }
    vk_compress::<H, P>(&heads)
}

/// Sign the bound message with the epoch chains: the signature segment of
/// chain `i` starts at digit `d_i`.
pub fn sign_chains<H: BpqsHash, P: BpqsParams>(
    chains: &[[u8; 32]; 256],
    msg_digest: &[u8; 32],
) -> [[u8; 32]; 256] {
    let digits = digits_of::<P>(msg_digest);
    let mut seg = [[0u8; 32]; 256];
    for (i, part) in seg.iter_mut().take(P::LEN).enumerate() {
        *part = chain_walk::<H, P>(&chains[i], digits[i] as usize, i as u32);
    }
    seg
}

/// Rebuild the epoch verification digest from a signature: every chain
/// segment is continued by `w - 1 - d_i` steps to the head, then compressed.
/// Refusal class: the rebuilt digest not matching the Merkle leaf's
/// committed value becomes `BadAuthPath` at the caller (chain verification
/// shows up as a leaf mismatch upstream).
pub fn verify_chains<H: BpqsHash, P: BpqsParams>(
    sig_chains: &[[u8; 32]; 256],
    msg_digest: &[u8; 32],
) -> [u8; 32] {
    let digits = digits_of::<P>(msg_digest);
    let mut heads = [[0u8; 32]; 256];
    for (i, head) in heads.iter_mut().take(P::LEN).enumerate() {
        let remaining = (P::WIN as usize - 1) - digits[i] as usize;
        *head = chain_walk::<H, P>(&sig_chains[i], remaining, i as u32);
    }
    vk_compress::<H, P>(&heads)
}

#[cfg(test)]
mod wots_tests {
    use super::*;
    use crate::hash::Sha3_256Hash;
    use crate::params::ParamsTestFast;

    type P = ParamsTestFast;

    fn test_chains() -> [[u8; 32]; 256] {
        epoch_secret_chains::<Sha3_256Hash, P>(&[9u8; 32])
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let chains = test_chains();
        let msg = [0xAB; 32];
        let sig = sign_chains::<Sha3_256Hash, P>(&chains, &msg);
        let rebuilt = verify_chains::<Sha3_256Hash, P>(&sig, &msg);
        let expected = vk_of_chains::<Sha3_256Hash, P>(&chains);
        assert_eq!(rebuilt, expected);
    }

    #[test]
    fn a_tampered_segment_breaks_the_digest() {
        let chains = test_chains();
        let msg = [0x11; 32];
        let mut sig = sign_chains::<Sha3_256Hash, P>(&chains, &msg);
        sig[3][0] ^= 0x01;
        let rebuilt = verify_chains::<Sha3_256Hash, P>(&sig, &msg);
        let expected = vk_of_chains::<Sha3_256Hash, P>(&chains);
        assert_ne!(
            rebuilt, expected,
            "tampered chain segment must change the vk digest"
        );
    }

    #[test]
    fn a_different_message_refuses() {
        let chains = test_chains();
        let sig = sign_chains::<Sha3_256Hash, P>(&chains, &[0x22; 32]);
        let rebuilt = verify_chains::<Sha3_256Hash, P>(&sig, &[0x33; 32]);
        let expected = vk_of_chains::<Sha3_256Hash, P>(&chains);
        assert_ne!(rebuilt, expected);
    }

    #[test]
    fn checksum_digits_are_present() {
        let d = digits_of::<P>(&[0xFF; 32]);
        assert!(d[..P::LEN1].iter().all(|x| *x == 15));
        assert!(d[P::LEN1..P::LEN].iter().all(|x| *x == 0));
    }

    #[test]
    fn lanes_are_canonically_padded_after_every_walk() {
        let chains = test_chains();
        let head = chain_walk::<Sha3_256Hash, P>(&chains[0], 3, 0);
        assert!(head[P::N..].iter().all(|b| *b == 0));
    }
}
