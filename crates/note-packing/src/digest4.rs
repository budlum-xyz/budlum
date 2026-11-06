//! 256-bit four-limb Goldilocks digest (`Digest4`) and suite-tagged commitments
//! for `note-packing` V2 (WP-56 Step 1, KP-2 `no_64bit_commitments`, KP-5
//! `commitments_carry_hash_suite`).

use crate::{is_canonical_field, NoteHash};

/// Canonical hash suite identifier carried alongside V2 commitments (WP-56).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HashSuiteId {
    /// Goldilocks width-12 Poseidon (`POSEIDON_G12_V1`).
    PoseidonG12V1 = 0x01,
    /// NIST FIPS 202 SHA3-256 (`SHA3_256_V1`).
    Sha3_256V1 = 0x02,
    /// BLAKE3-256 (`BLAKE3_256_V1`).
    Blake3_256V1 = 0x03,
}

impl HashSuiteId {
    /// Wire byte for this hash suite.
    ///
    /// WIRING: exposed for BudZero V2 commitment encoders and wallet consent records.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Decode a hash suite tag, refusing unknown or zero suite bytes.
    ///
    /// WIRING: exposed for BudZero V2 commitment decoders and wallet consent records.
    #[must_use]
    pub const fn from_byte(tag: u8) -> Option<Self> {
        match tag {
            0x01 => Some(Self::PoseidonG12V1),
            0x02 => Some(Self::Sha3_256V1),
            0x03 => Some(Self::Blake3_256V1),
            _ => None,
        }
    }
}

/// Four canonical Goldilocks field elements (`4 * 64 = 256` bits), replacing
/// 64-bit single-limb commitments (WP-56 Step 1 / KP-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Digest4([u64; 4]);

impl Digest4 {
    /// Construct a `Digest4` iff every limb is strictly below `GOLDILOCKS_P`
    /// and at least one upper limb is non-zero when checked by callers that
    /// forbid 64-bit-only commitments.
    ///
    /// WIRING: exposed for V2 note, manifest, and consent commitment builders.
    #[must_use]
    pub const fn try_new(limbs: [u64; 4]) -> Option<Self> {
        if is_canonical_field(limbs[0])
            && is_canonical_field(limbs[1])
            && is_canonical_field(limbs[2])
            && is_canonical_field(limbs[3])
        {
            Some(Self(limbs))
        } else {
            None
        }
    }

    /// Return the four canonical Goldilocks limbs.
    ///
    /// WIRING: exposed for in-circuit public-input wiring and V2 state trees.
    #[must_use]
    pub const fn limbs(&self) -> [u64; 4] {
        self.0
    }

    /// True when the upper three limbs are all zero (the legacy V1 64-bit shape
    /// refused by `no_64bit_commitments` on V2 paths unless the whole digest is
    /// zero).
    ///
    /// WIRING: exposed for V2 commitment gates that reject 64-bit truncated digests.
    #[must_use]
    pub const fn is_single_limb_truncated(&self) -> bool {
        self.0[0] != 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    /// Pack the four canonical limbs into 32 little-endian bytes (`NoteHash`).
    ///
    /// WIRING: exposed for V2 note commitment and Merkle root serialization.
    #[must_use]
    pub const fn to_bytes(&self) -> NoteHash {
        let mut out = [0u8; 32];
        let mut limb_idx = 0usize;
        while limb_idx < 4 {
            let le = self.0[limb_idx].to_le_bytes();
            let base = limb_idx * 8;
            let mut b = 0usize;
            while b < 8 {
                out[base + b] = le[b];
                b += 1;
            }
            limb_idx += 1;
        }
        out
    }

    /// Unpack 32 little-endian bytes into four canonical Goldilocks limbs,
    /// returning `None` if any 8-byte limb is `>= GOLDILOCKS_P`.
    ///
    /// WIRING: exposed for V2 commitment deserialization across chain and wallet.
    #[must_use]
    pub fn from_bytes_checked(bytes: &NoteHash) -> Option<Self> {
        let mut limbs = [0u64; 4];
        let mut idx = 0usize;
        while idx < 4 {
            let start = idx * 8;
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[start..start + 8]);
            limbs[idx] = u64::from_le_bytes(buf);
            idx += 1;
        }
        Self::try_new(limbs)
    }
}

/// 33-byte suite-tagged V2 commitment (`[suite_id, digest[0..32]]`, KP-5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuiteTaggedCommitment {
    pub suite: HashSuiteId,
    pub digest: NoteHash,
}

impl SuiteTaggedCommitment {
    /// Build a Poseidon G12 V2 commitment from a canonical `Digest4`, refusing
    /// 64-bit single-limb truncated digests (`KP-2`).
    ///
    /// WIRING: exposed for V2 privacy note and consent commitment producers.
    #[must_use]
    pub const fn from_poseidon_digest4(d: Digest4) -> Option<Self> {
        if d.is_single_limb_truncated() {
            return None;
        }
        Some(Self {
            suite: HashSuiteId::PoseidonG12V1,
            digest: d.to_bytes(),
        })
    }

    /// Encode as `[suite_byte, digest[0..32]]`.
    ///
    /// WIRING: exposed for V2 wire encoding.
    #[must_use]
    pub fn encode(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        out[0] = self.suite.as_byte();
        out[1..].copy_from_slice(&self.digest);
        out
    }

    /// Decode `[suite_byte, digest[0..32]]`, validating canonical Goldilocks
    /// limbs and non-truncation when `suite == PoseidonG12V1`.
    ///
    /// WIRING: exposed for V2 wire decoding.
    #[must_use]
    pub fn decode(raw: &[u8; 33]) -> Option<Self> {
        let suite = HashSuiteId::from_byte(raw[0])?;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&raw[1..]);
        if matches!(suite, HashSuiteId::PoseidonG12V1) {
            let d4 = Digest4::from_bytes_checked(&digest)?;
            if d4.is_single_limb_truncated() {
                return None;
            }
        }
        Some(Self { suite, digest })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GOLDILOCKS_P;

    #[test]
    fn digest4_round_trips_and_refuses_non_canonical_limbs() {
        let valid = Digest4::try_new([11, 22, 33, GOLDILOCKS_P - 1]).unwrap();
        let bytes = valid.to_bytes();
        assert_eq!(Digest4::from_bytes_checked(&bytes), Some(valid));

        assert!(Digest4::try_new([0, 0, 0, GOLDILOCKS_P]).is_none());
        let mut bad_bytes = bytes;
        bad_bytes[24..32].copy_from_slice(&GOLDILOCKS_P.to_le_bytes());
        assert_eq!(Digest4::from_bytes_checked(&bad_bytes), None);
    }

    #[test]
    fn suite_tagged_commitment_enforces_suite_and_no_64bit_truncation() {
        let truncated = Digest4::try_new([42, 0, 0, 0]).unwrap();
        assert!(truncated.is_single_limb_truncated());
        assert!(SuiteTaggedCommitment::from_poseidon_digest4(truncated).is_none());

        let full = Digest4::try_new([42, 7, 9, 13]).unwrap();
        let tagged = SuiteTaggedCommitment::from_poseidon_digest4(full).unwrap();
        let wire = tagged.encode();
        assert_eq!(wire[0], HashSuiteId::PoseidonG12V1.as_byte());
        assert_eq!(SuiteTaggedCommitment::decode(&wire), Some(tagged));

        let mut unknown_suite = wire;
        unknown_suite[0] = 0xFF;
        assert_eq!(SuiteTaggedCommitment::decode(&unknown_suite), None);
    }
}
