//! The common finality-evidence envelope.
//!
//! Every external-family verifier in this repository eventually emits one kind
//! of object for the settlement layer to ingest: a *finality evidence
//! envelope*: who vouches for which header of which chain at which height,
//! plus an opaque family attestation. The envelope is the only thing the
//! aggregation/settlement path must understand; the family attestation is
//! decoded by the family adapter, never by the envelope codec.
//!
//! # Layout (canonical, all integers little-endian)
//!
//! ```text
//!   0.. 8  magic        = "BUDLMEV1"
//!   8      version      = 1
//!   9      family       (non-zero; the family tag of the emitting adapter)
//!  10..18  chain_id     (non-zero)
//!  18..26  height
//!  26..58  header_digest  (family-canonical block digest)
//!  58..62  attestation_len (1 ..= MAX_ATTESTATION)
//!  62..    attestation  (family-defined bytes)
//!   ..+32  tag          = SHA-256(everything before tag)
//! ```
//!
//! # Contract
//!
//! Encoding is deterministic: the same envelope always encodes to the same
//! bytes, so envelopes can be hashed, chained and stored content-addressed.
//! Decoding is fail-closed: any deviation from the layout, any zeroed
//! mandatory field, any tag mismatch is a typed rejection, never a panic,
//! never a best-effort repair.
//!
//! WIRING: unwired - the codec is the shared container every family adapter will
//! emit. It is called from `src/cross_domain/external/` once an adapter depends
//! on this crate; until then its items are named only by its own tests.

use sha2::{Digest, Sha256};
use std::fmt;

use crate::Hash32;

/// Fixed magic prefix; an envelope that does not start with this is refused.
pub const MAGIC: &[u8; 8] = b"BUDLMEV1";
/// The only version this codec understands.
pub const VERSION: u8 = 1;
/// Attestations larger than this are refused before allocation.
pub const MAX_ATTESTATION: usize = 1 << 20;

const HEADER_LEN: usize = 8 + 1 + 1 + 8 + 8 + 32;
const LEN_FIELD: usize = 4;
const TAG_LEN: usize = 32;
const CHAIN_OFF: usize = 10;
const HEIGHT_OFF: usize = 18;
const DIGEST_OFF: usize = 26;
const LEN_OFF: usize = HEADER_LEN;
const ATT_OFF: usize = HEADER_LEN + LEN_FIELD;

/// The canonical evidence container shared by every family adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceEnvelope {
    /// Non-zero family tag of the emitting adapter.
    pub family: u8,
    /// Non-zero chain id (e.g. 45260 / 45261 for this network).
    pub chain_id: u64,
    /// Height of the header the evidence binds.
    pub height: u64,
    /// Family-canonical digest of the bound header.
    pub header_digest: Hash32,
    /// Family-defined attestation bytes (opaque to the codec, non-empty).
    pub attestation: Vec<u8>,
}

/// Every way decoding can fail. A typed rejection, never a panic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The eight magic bytes do not match.
    WrongMagic,
    /// The version byte is not [`VERSION`].
    UnsupportedVersion,
    /// `family`, `chain_id` or `attestation` is zero/empty.
    UnsetField,
    /// The declared attestation length exceeds [`MAX_ATTESTATION`].
    AttestationTooLarge,
    /// The byte slice ends before the declared envelope does.
    Truncated,
    /// The byte slice carries bytes past the declared envelope.
    LengthMismatch,
    /// The trailing tag does not match the recomputed digest.
    TagMismatch,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::WrongMagic => "wrong magic",
            Self::UnsupportedVersion => "unsupported version",
            Self::UnsetField => "a mandatory field is zero or empty",
            Self::AttestationTooLarge => "attestation exceeds the cap",
            Self::Truncated => "truncated envelope",
            Self::LengthMismatch => "trailing bytes past the envelope",
            Self::TagMismatch => "tag does not match the body",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for DecodeError {}

impl EvidenceEnvelope {
    /// Deterministic canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ATT_OFF + self.attestation.len() + TAG_LEN);
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(self.family);
        out.extend_from_slice(&self.chain_id.to_le_bytes());
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.header_digest);
        out.extend_from_slice(&(self.attestation.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.attestation);
        let tag = tag_of(&out);
        out.extend_from_slice(&tag);
        out
    }

    /// Fail-closed decode. Recomputes and checks the trailing tag; rejects
    /// any layout deviation with a typed error.
    pub fn decode(src: &[u8]) -> Result<Self, DecodeError> {
        if src.len() < ATT_OFF + TAG_LEN {
            return Err(DecodeError::Truncated);
        }
        if &src[..8] != MAGIC {
            return Err(DecodeError::WrongMagic);
        }
        if src[8] != VERSION {
            return Err(DecodeError::UnsupportedVersion);
        }
        let family = src[9];
        let chain_id = u64::from_le_bytes(
            src[CHAIN_OFF..CHAIN_OFF + 8]
                .try_into()
                .map_err(|_| DecodeError::Truncated)?,
        );
        let height = u64::from_le_bytes(
            src[HEIGHT_OFF..HEIGHT_OFF + 8]
                .try_into()
                .map_err(|_| DecodeError::Truncated)?,
        );
        let mut header_digest = [0u8; 32];
        header_digest.copy_from_slice(&src[DIGEST_OFF..DIGEST_OFF + 32]);
        let att_len = u32::from_le_bytes(
            src[LEN_OFF..LEN_OFF + 4]
                .try_into()
                .map_err(|_| DecodeError::Truncated)?,
        ) as usize;
        if att_len > MAX_ATTESTATION {
            return Err(DecodeError::AttestationTooLarge);
        }
        if att_len == 0 {
            return Err(DecodeError::UnsetField);
        }
        let expected = ATT_OFF + att_len + TAG_LEN;
        if src.len() < expected {
            return Err(DecodeError::Truncated);
        }
        if src.len() > expected {
            return Err(DecodeError::LengthMismatch);
        }
        let tag_body = &src[..ATT_OFF + att_len];
        if tag_of(tag_body) != src[ATT_OFF + att_len..] {
            return Err(DecodeError::TagMismatch);
        }
        if family == 0 || chain_id == 0 {
            return Err(DecodeError::UnsetField);
        }
        Ok(Self {
            family,
            chain_id,
            height,
            header_digest,
            attestation: src[ATT_OFF..ATT_OFF + att_len].to_vec(),
        })
    }
}

fn tag_of(body: &[u8]) -> Hash32 {
    let out = Sha256::digest(body);
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    tag
}
