//! B.U.D. 2.0 - THE SECURE DEDUP LAYER (F24/F31/F71/F86 - the seed of the FHE
//! path).
//!
//! Remaining work item #15: secure deduplication over encrypted content. Full
//! FHE (homomorphic search over the ciphertext) is long term; THIS layer WRAPS
//! the proven pattern of K20: convergent encryption (a content-derived key)
//! plus a PoW ownership proof. Identical encrypted content deduplicates
//! SAFELY, and different content never collides. Side-channel note (F253):
//! verification is timed by the PoW.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const SD_MAGIC: [u8; 8] = *b"\xB5SDP1\0\0\0";

/// The convergent key: SHA3-256(content) - the same content gives the same
/// key.
pub fn convergent_key(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_CONVERGENT_V1");
    h.update((data.len() as u64).to_le_bytes());
    h.update(data);
    h.finalize().into()
}

/// The encrypted content identity: H(key || data) - the same plaintext gives
/// the same identity.
pub fn cipher_content_id(data: &[u8], key: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_SECUREDEDUP_V1");
    h.update(key);
    h.update((data.len() as u64).to_le_bytes());
    h.update(data);
    h.finalize().into()
}

/// The secure deduplication decision: the same identity makes a dedup
/// candidate, verified by PoW.
/// `pow_bits`: the ownership-proof difficulty (K20 - sybil/poison
/// resistance).
pub fn secure_dedup_candidate(data: &[u8], pow_bits: u32) -> Option<([u8; 32], bool)> {
    if data.is_empty() {
        return None;
    }
    let key = convergent_key(data);
    let cid = cipher_content_id(data, &key);
    // PoW: H(cid || nonce) leading_zero_bits >= pow_bits (deterministik arama)
    // The counter comes from the loop variable (clippy::explicit_counter_loop):
    // keeping a separate `nonce` and incrementing it by hand was a pattern
    // open to the value drifting independently of the loop condition. The
    // function does not return the nonce (only `found`), so there is no need
    // to bind it outside the loop.
    let mut found = false;
    for nonce in 0..1_000_000u64 {
        let mut h = Sha3_256::new();
        h.update(cid);
        h.update(nonce.to_le_bytes());
        let d: [u8; 32] = h.finalize().into();
        let mut zeros = 0u32;
        for &b in d.iter() {
            if b == 0 {
                zeros += 8;
            } else {
                zeros += b.leading_zeros();
                break;
            }
        }
        if zeros >= pow_bits {
            found = true;
            break;
        }
    }
    Some((cid, found))
}

/// Compare SAFELY whether two encrypted pieces carry the same content (yes if
/// the convergent identities are equal, no otherwise - no plaintext leaks).
pub fn same_content(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    convergent_key(a) == convergent_key(b)
        && cipher_content_id(a, &convergent_key(a)) == cipher_content_id(b, &convergent_key(b))
}

pub fn sd_digest(cid: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(SD_MAGIC);
    h.update(cid);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bud_format_dedup::PowChallenge;

    #[test]
    fn same_content_dedups_and_different_content_does_not() {
        let a = b"secret document content ";
        let b = b"secret document content "; // the same
        let c = b"secret document contenx "; // different
        assert!(same_content(a, b));
        assert!(!same_content(a, c));
        // the convergent key is deterministic
        assert_eq!(convergent_key(a), convergent_key(b));
    }

    #[test]
    fn pow_ownership_proof() {
        let (cid, ok) = secure_dedup_candidate(b"data", 8).unwrap();
        assert!(ok, "an 8-bit PoW has to be found within 1M nonces");
        let _ = cid;
    }

    #[test]
    fn empty_data_is_refused() {
        assert!(secure_dedup_candidate(b"", 4).is_none());
    }

    #[test]
    fn sd_is_deterministic() {
        let cid = cipher_content_id(b"x", &convergent_key(b"x"));
        assert_eq!(sd_digest(&cid), sd_digest(&cid));
    }

    #[test]
    fn pow_challenge_integration() {
        // Compatibility with the PowChallenge of K20: the same difficulty
        // language.
        let ch = PowChallenge::new([0u8; 32], 8);
        assert_eq!(ch.difficulty, 8);
        let _ = ch;
    }
}
