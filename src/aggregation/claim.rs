//! Claims: the short statements the chain stores in place of heavy objects.
//!
//! A claim carries only hashes and field elements. Its encoding is canonical:
//! one kind byte, then fixed-width fields, so a claim has exactly one byte
//! form and that form is 67, 97 or 81 bytes long.
//!
//! WIRING: [`Ext`] is named only by the polynomial claim until the PCS
//! objects of Phase 5 construct one from an opening.

use super::hash::{h, TAG_CLAIM};
use crate::core::address::Address;
use crate::crypto::scheme::SchemeId;
use crate::domain::types::{DomainId, Hash32};

/// The Goldilocks prime `2^64 - 2^32 + 1`, the base field of the `BudZKVM`
/// STARK configuration.
pub const GOLDILOCKS_MODULUS: u64 = 0xFFFF_FFFF_0000_0001;
/// Degree of the extension field of the STARK configuration (cubic).
const EXT_DEGREE: usize = 3;
/// Encoded bytes of one extension field element.
const EXT_BYTES: usize = EXT_DEGREE * 8;

/// Kind byte of a signature claim.
const KIND_SIG: u8 = 1;
/// Kind byte of a program claim.
const KIND_PROG: u8 = 2;
/// Kind byte of a polynomial claim.
const KIND_POLY: u8 = 3;

/// The first bytes of the encoding of an ML-DSA-87 signature claim: the
/// kind byte and the scheme id. The tick program writes them as constants.
pub(super) const SIG_CLAIM_PREFIX: [u8; 3] = {
    let scheme = SchemeId::ML_DSA_87.0.to_be_bytes();
    [KIND_SIG, scheme[0], scheme[1]]
};

const SIG_LEN: usize = 1 + 2 + 32 + 32;
const PROG_LEN: usize = 1 + 32 + 32 + 32;
const POLY_LEN: usize = 1 + 32 + EXT_BYTES + EXT_BYTES;

/// Why claim bytes were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimError {
    /// The bytes end before the claim does.
    Truncated,
    /// The kind byte names no claim kind.
    UnknownKind(u8),
    /// A limb of a field element is not below the modulus. Accepting it would
    /// give one field element two encodings and one claim two digests.
    NonCanonicalFieldElement,
}

impl std::fmt::Display for ClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "claim bytes are truncated"),
            Self::UnknownKind(kind) => write!(f, "unknown claim kind {kind}"),
            Self::NonCanonicalFieldElement => {
                write!(f, "a field element limb is not below the modulus")
            }
        }
    }
}

impl std::error::Error for ClaimError {}

/// An element of the extension field of the `BudZKVM` STARK configuration:
/// three Goldilocks limbs, each below the modulus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ext([u64; EXT_DEGREE]);

impl Ext {
    /// An element from its limbs.
    ///
    /// # Errors
    ///
    /// [`ClaimError::NonCanonicalFieldElement`] when a limb is not below the
    /// modulus.
    pub fn new(limbs: [u64; EXT_DEGREE]) -> Result<Self, ClaimError> {
        if limbs.iter().any(|limb| *limb >= GOLDILOCKS_MODULUS) {
            return Err(ClaimError::NonCanonicalFieldElement);
        }
        Ok(Self(limbs))
    }

    /// The limbs, each below the modulus.
    #[must_use]
    pub const fn limbs(&self) -> [u64; EXT_DEGREE] {
        self.0
    }

    fn write(&self, out: &mut Vec<u8>) {
        for limb in &self.0 {
            out.extend_from_slice(&limb.to_le_bytes());
        }
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self, ClaimError> {
        let mut limbs = [0u64; EXT_DEGREE];
        for limb in &mut limbs {
            *limb = u64::from_le_bytes(reader.array()?);
        }
        Self::new(limbs)
    }
}

/// A forward-only reader over claim bytes.
struct Reader<'a> {
    rest: &'a [u8],
    taken: usize,
}

impl Reader<'_> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ClaimError> {
        let (head, tail) = self
            .rest
            .split_first_chunk::<N>()
            .ok_or(ClaimError::Truncated)?;
        self.rest = tail;
        self.taken = self.taken.saturating_add(N);
        Ok(*head)
    }
}

/// A short statement that a heavy object was valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    /// `signer` signed the message whose hash is `msg_hash` under `scheme`.
    Sig {
        /// The signature scheme.
        scheme: SchemeId,
        /// The account that signed.
        signer: Address,
        /// Hash of the signed message.
        msg_hash: Hash32,
    },
    /// The program `program_hash` ran on the input `input_hash` and wrote the
    /// output `output_hash`.
    Prog {
        /// Hash of the program.
        program_hash: Hash32,
        /// Hash of its input.
        input_hash: Hash32,
        /// Hash of its output.
        output_hash: Hash32,
    },
    /// The polynomial committed as `poly_hash` takes `value` at `point`.
    Poly {
        /// Commitment to the polynomial.
        poly_hash: Hash32,
        /// The opening point.
        point: Ext,
        /// The value at the point.
        value: Ext,
    },
}

impl Claim {
    /// The kind byte of this claim.
    #[must_use]
    pub const fn kind(&self) -> u8 {
        match self {
            Self::Sig { .. } => KIND_SIG,
            Self::Prog { .. } => KIND_PROG,
            Self::Poly { .. } => KIND_POLY,
        }
    }

    /// Length of the canonical encoding.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        match self {
            Self::Sig { .. } => SIG_LEN,
            Self::Prog { .. } => PROG_LEN,
            Self::Poly { .. } => POLY_LEN,
        }
    }

    /// The canonical encoding: the kind byte, then the fields in order.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.write(&mut out);
        out
    }

    /// Append the canonical encoding to `out`.
    pub fn write(&self, out: &mut Vec<u8>) {
        out.push(self.kind());
        match self {
            Self::Sig {
                scheme,
                signer,
                msg_hash,
            } => {
                out.extend_from_slice(&scheme.to_be_bytes());
                out.extend_from_slice(signer.as_bytes());
                out.extend_from_slice(msg_hash);
            }
            Self::Prog {
                program_hash,
                input_hash,
                output_hash,
            } => {
                out.extend_from_slice(program_hash);
                out.extend_from_slice(input_hash);
                out.extend_from_slice(output_hash);
            }
            Self::Poly {
                poly_hash,
                point,
                value,
            } => {
                out.extend_from_slice(poly_hash);
                point.write(out);
                value.write(out);
            }
        }
    }

    /// Decode one claim from the front of `bytes` and report how many bytes
    /// it took. Bytes after the claim are left to the caller.
    ///
    /// # Errors
    ///
    /// [`ClaimError`] when the bytes are truncated, the kind is unknown or a
    /// field element is not canonical.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), ClaimError> {
        let mut reader = Reader {
            rest: bytes,
            taken: 0,
        };
        let [kind] = reader.array::<1>()?;
        let claim = match kind {
            KIND_SIG => Self::Sig {
                scheme: SchemeId(u16::from_be_bytes(reader.array()?)),
                signer: Address::from(reader.array::<32>()?),
                msg_hash: reader.array()?,
            },
            KIND_PROG => Self::Prog {
                program_hash: reader.array()?,
                input_hash: reader.array()?,
                output_hash: reader.array()?,
            },
            KIND_POLY => Self::Poly {
                poly_hash: reader.array()?,
                point: Ext::read(&mut reader)?,
                value: Ext::read(&mut reader)?,
            },
            other => return Err(ClaimError::UnknownKind(other)),
        };
        Ok((claim, reader.taken))
    }

    /// `claim_digest = H("BDLM_CLAIM_V1" || domain || kind || values)`.
    ///
    /// The domain is part of the preimage, so a claim made for one domain is
    /// a different claim in every other domain.
    #[must_use]
    pub fn digest(&self, domain: DomainId) -> Hash32 {
        h(&[TAG_CLAIM, &domain.to_be_bytes(), &self.encode()])
    }
}
