//! Wallet-side blinded consent confirmation screen, Padme size buckets, and
//! threshold Shamir key-escrow primitives (WP-56 Steps 9-10 / TK7, TSO8, TSO9,
//! TSO10, TSO12).
//!
//! WIRING: unwired - staged for wallet UI consent confirmation integration (WP-56).

use sha3::{Digest, Sha3_256};

const TAG_CONSENT_GRANT_V1: &[u8] = b"budlum/consent/blind-grant/v1";
const TAG_CONSENT_HANDLE_V1: &[u8] = b"budlum/consent/revocation/v1";
const HASH_SUITE_SHA3_256_V1: u8 = 0x02;

fn hash_prefixed(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update((tag.len() as u64).to_le_bytes());
    h.update(tag);
    for p in parts {
        h.update((p.len() as u64).to_le_bytes());
        h.update(*p);
    }
    h.finalize().into()
}

/// Padme length-hiding bucket size (`O(log log L)` leakage bound, WP-56 TSO12).
///
/// Every sealed object payload and key envelope pads to `padme_bucket_len`
/// before encryption so observed ciphertext sizes fall strictly onto Padme
/// buckets.
/// exposed for: wallet and sealed-object builders under WP-56.
#[must_use]
pub const fn padme_bucket_len(raw_len: u64) -> u64 {
    if raw_len <= 1 {
        return raw_len;
    }
    let e = 63 - raw_len.leading_zeros();
    let s = if e == 0 {
        1
    } else {
        (31 - e.leading_zeros()) + 1
    };
    if e <= s {
        return raw_len;
    }
    let last_bits = e - s;
    let mask = (1u64 << last_bits) - 1;
    match raw_len.checked_add(mask) {
        Some(sum) => sum & !mask,
        None => u64::MAX & !mask,
    }
}

/// Consent mode displayed on the wallet confirmation screen (WP-56 Step 9).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConsentMode {
    /// Default blinded consent (`TSO9`): hides issuer, grantee, and content ID on chain.
    #[default]
    BlindGrant,
    /// Explicit consent opening witness exclusively to a designated prover.
    ProverOpen,
    /// Transition from sealed storage to public publication (requires YK6 proof).
    PublicPublish { yk6_verified: bool },
}

/// Human-readable consent prompt rendered locally on the user's wallet screen
/// prior to signing (WP-56 Step 9). Never serialized onto the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentScreenPrompt {
    pub issuer_address: [u8; 32],
    pub grantee_address: [u8; 32],
    pub content_id: [u8; 32],
    pub scope_label: String,
    pub expiry_epoch: u64,
    pub mode: ConsentMode,
}

/// Blinded on-chain consent record carrying zero plaintext `issuer`, `grantee`,
/// or `content_id` fields (`KP-9` / `TSO9`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlindedConsentRecord {
    pub hash_suite: u8,
    pub grant_commitment: [u8; 32],
    pub revocation_handle: [u8; 32],
    pub expiry_epoch: u64,
}

impl ConsentScreenPrompt {
    /// Seal a wallet-confirmed prompt into a blinded on-chain record using
    /// 32 bytes of caller randomness (`TSO9`).
    ///
    /// # Errors
    ///
    /// Refuses empty scope labels, zero blinding salt, or `PublicPublish`
    /// without a verified `YK6` non-blacklist predicate proof.
    /// exposed for: wallet consent confirmation flow (WP-56 Step 9).
    pub fn seal_for_chain(&self, blinding_salt: &[u8; 32]) -> Result<BlindedConsentRecord, String> {
        if self.scope_label.trim().is_empty() {
            return Err("consent scope_label must not be empty".to_string());
        }
        if blinding_salt.iter().all(|&b| b == 0) {
            return Err("consent blinding_salt must be non-zero".to_string());
        }
        if matches!(self.mode, ConsentMode::PublicPublish { yk6_verified: false }) {
            return Err("public publication requires a verified YK6 predicate proof".to_string());
        }
        let mode_byte = match self.mode {
            ConsentMode::BlindGrant => [0x01u8],
            ConsentMode::ProverOpen => [0x02u8],
            ConsentMode::PublicPublish { .. } => [0x03u8],
        };
        let expiry_le = self.expiry_epoch.to_le_bytes();
        let grant_commitment = hash_prefixed(
            TAG_CONSENT_GRANT_V1,
            &[
                &self.issuer_address,
                &self.grantee_address,
                &self.content_id,
                self.scope_label.as_bytes(),
                &expiry_le,
                &mode_byte,
                blinding_salt,
            ],
        );
        let revocation_handle = hash_prefixed(
            TAG_CONSENT_HANDLE_V1,
            &[&grant_commitment, &self.issuer_address, blinding_salt],
        );
        Ok(BlindedConsentRecord {
            hash_suite: HASH_SUITE_SHA3_256_V1,
            grant_commitment,
            revocation_handle,
            expiry_epoch: self.expiry_epoch,
        })
    }
}

impl BlindedConsentRecord {
    /// Verify whether a consent proof may open a new session at `current_epoch`
    /// against `revoked_handles` and `deleted_commitments` (`TSO8`, `TSO11`).
    /// exposed for: consent session gate verification (WP-56).
    #[must_use]
    pub fn allows_new_session(
        &self,
        current_epoch: u64,
        revoked_handles: &[[u8; 32]],
        deleted_commitments: &[[u8; 32]],
    ) -> bool {
        if current_epoch > self.expiry_epoch {
            return false;
        }
        if revoked_handles.iter().any(|h| h == &self.revocation_handle) {
            return false;
        }
        if deleted_commitments
            .iter()
            .any(|c| c == &self.grant_commitment)
        {
            return false;
        }
        true
    }
}

/// One `GF(256)` Shamir share of a 32-byte key (`x = index != 0`, WP-56 TK7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShamirShare32 {
    pub index: u8,
    pub value: [u8; 32],
}

const fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    let mut i = 0;
    while i < 8 {
        let mask = (b & 1).wrapping_neg();
        p ^= a & mask;
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
        i += 1;
    }
    p
}

const fn gf256_inv(a: u8) -> u8 {
    let mut res = 1u8;
    let mut base = a;
    let mut exp = 254u8;
    while exp > 0 {
        if (exp & 1) != 0 {
            res = gf256_mul(res, base);
        }
        base = gf256_mul(base, base);
        exp >>= 1;
    }
    res
}

/// Split a 32-byte key into `total` threshold shares requiring `threshold`
/// shares to reconstruct (`TK7`, `TSO10`).
///
/// `coeff_entropy` must provide `(threshold - 1) * 32` random bytes.
///
/// # Errors
///
/// Refuses `threshold < 2`, `threshold > total`, `total == 255`, or insufficient
/// `coeff_entropy`.
/// exposed for: threshold escrow key splitting (WP-56 Step 10).
pub fn shamir_split_32(
    secret: &[u8; 32],
    threshold: u8,
    total: u8,
    coeff_entropy: &[u8],
) -> Result<Vec<ShamirShare32>, String> {
    if threshold < 2 || threshold > total || total == u8::MAX {
        return Err("invalid Shamir (threshold, total) parameters".to_string());
    }
    let needed = usize::from(threshold - 1) * 32;
    if coeff_entropy.len() < needed {
        return Err("insufficient coeff_entropy for Shamir polynomial".to_string());
    }
    let mut out = Vec::with_capacity(usize::from(total));
    for idx in 1..=total {
        let mut share = [0u8; 32];
        for (byte_pos, slot) in share.iter_mut().enumerate() {
            let mut acc = 0u8;
            for deg in (1..usize::from(threshold)).rev() {
                let c = coeff_entropy[(deg - 1) * 32 + byte_pos];
                acc = gf256_mul(acc, idx) ^ c;
            }
            *slot = gf256_mul(acc, idx) ^ secret[byte_pos];
        }
        out.push(ShamirShare32 {
            index: idx,
            value: share,
        });
    }
    Ok(out)
}

/// Reconstruct a 32-byte key from at least `threshold` distinct Shamir shares
/// via Lagrange interpolation at `x = 0` (`TK7`, `TSO10`).
///
/// # Errors
///
/// Refuses `< threshold` shares, `index == 0`, or duplicate share indices.
/// exposed for: threshold escrow recovery (WP-56 Step 10).
pub fn shamir_reconstruct_32(
    shares: &[ShamirShare32],
    threshold: u8,
) -> Result<[u8; 32], String> {
    let t = usize::from(threshold);
    if threshold < 2 || shares.len() < t {
        return Err("fewer shares than threshold".to_string());
    }
    let subset = &shares[..t];
    for (i, s) in subset.iter().enumerate() {
        if s.index == 0 {
            return Err("Shamir share index 0 is forbidden".to_string());
        }
        if subset[i + 1..].iter().any(|other| other.index == s.index) {
            return Err("duplicate Shamir share index".to_string());
        }
    }
    let mut secret = [0u8; 32];
    for (i, si) in subset.iter().enumerate() {
        let mut num = 1u8;
        let mut den = 1u8;
        for (j, sj) in subset.iter().enumerate() {
            if i != j {
                num = gf256_mul(num, sj.index);
                den = gf256_mul(den, si.index ^ sj.index);
            }
        }
        let basis = gf256_mul(num, gf256_inv(den));
        for (b, out_byte) in secret.iter_mut().enumerate() {
            *out_byte ^= gf256_mul(si.value[b], basis);
        }
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tso12_all_observed_sizes_are_padme_buckets() {
        let mut prev = 0u64;
        for raw in 0..4096u64 {
            let bucket = padme_bucket_len(raw);
            assert!(bucket >= raw, "bucket {bucket} < raw {raw}");
            assert!(bucket >= prev, "Padme must be monotonic");
            assert_eq!(padme_bucket_len(bucket), bucket, "bucket is idempotent");
            prev = bucket;
        }
    }

    #[test]
    fn tso8_tso9_tso11_blinded_consent_hides_identities_and_enforces_revocation() {
        let prompt = ConsentScreenPrompt {
            issuer_address: [0x11; 32],
            grantee_address: [0x22; 32],
            content_id: [0x33; 32],
            scope_label: "read:dataset:chunk-0..15".to_string(),
            expiry_epoch: 50,
            mode: ConsentMode::default(),
        };
        let r1 = prompt.seal_for_chain(&[0xAA; 32]).unwrap();
        let r2 = prompt.seal_for_chain(&[0xBB; 32]).unwrap();
        assert_ne!(r1.grant_commitment, r2.grant_commitment);
        assert_ne!(r1.revocation_handle, r2.revocation_handle);
        assert_ne!(r1.grant_commitment, prompt.content_id);
        assert_ne!(r1.grant_commitment, prompt.grantee_address);
        assert_ne!(r1.grant_commitment, prompt.issuer_address);

        assert!(r1.allows_new_session(50, &[], &[]));
        assert!(!r1.allows_new_session(51, &[], &[]));
        assert!(!r1.allows_new_session(10, &[r1.revocation_handle], &[]));
        assert!(!r1.allows_new_session(10, &[], &[r1.grant_commitment]));

        let bad_pub = ConsentScreenPrompt {
            mode: ConsentMode::PublicPublish {
                yk6_verified: false,
            },
            ..prompt
        };
        assert!(bad_pub.seal_for_chain(&[0xCC; 32]).is_err());
    }

    #[test]
    fn tk7_tso10_shamir_threshold_recovers_at_t_and_refuses_below_t() {
        let secret = [0x5Au8; 32];
        let entropy = [0x3Cu8; 128];
        let shares = shamir_split_32(&secret, 3, 5, &entropy).unwrap();
        assert_eq!(shares.len(), 5);

        // Fewer than t shares is refused (`t - 1` never yields key).
        assert!(shamir_reconstruct_32(&shares[..2], 3).is_err());
        // Any 2 shares interpolated as if threshold=2 do NOT yield the 3-of-5 key.
        assert_ne!(shamir_reconstruct_32(&shares[..2], 2).unwrap(), secret);

        // Any t=3 distinct subsets reconstruct the exact 32-byte key.
        let sub_a = [shares[0], shares[2], shares[4]];
        let sub_b = [shares[1], shares[3], shares[4]];
        assert_eq!(shamir_reconstruct_32(&sub_a, 3).unwrap(), secret);
        assert_eq!(shamir_reconstruct_32(&sub_b, 3).unwrap(), secret);
    }
}
