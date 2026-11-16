//! Envelopes: how a heavy object travels to the aggregators.
//!
//! An envelope carries the object itself and names the transaction that will
//! use the claim. It never enters a block. Its encoding is canonical, so the
//! object id is a function of the object alone.
//!
//! WIRING: the `agg/object` topic decodes an [`Envelope`] from a peer and
//! maps an [`EnvelopeError`] to the peer penalty of the network layer.

use super::hash::{h, TAG_OBJECT};
use crate::crypto::scheme::SchemeId;
use crate::domain::types::{DomainId, Hash32};

/// Bytes of an envelope before its payload: kind, scheme, transaction hash,
/// domain and payload length.
const ENVELOPE_HEADER_BYTES: usize = 1 + 2 + 32 + 4 + 4;

/// The kind of a heavy object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectKind {
    /// A signature with its public key.
    Signature,
    /// A STARK proof of a program run.
    StarkProof,
    /// A polynomial commitment opening.
    PcsOpening,
}

impl ObjectKind {
    /// The wire byte of this kind.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Signature => 0,
            Self::StarkProof => 1,
            Self::PcsOpening => 2,
        }
    }

    /// The kind a wire byte names, if any.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Signature),
            1 => Some(Self::StarkProof),
            2 => Some(Self::PcsOpening),
            _ => None,
        }
    }
}

/// Why envelope bytes were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The bytes end before the envelope does.
    Truncated,
    /// Bytes follow the envelope.
    TrailingBytes,
    /// The kind byte names no object kind.
    UnknownKind(u8),
    /// The payload is longer than the caller allows.
    PayloadTooLarge(usize),
    /// A proof or opening carries a scheme. Only a signature names one, so
    /// any other value would be a second encoding of the same object.
    SchemeOnNonSignature,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "envelope bytes are truncated"),
            Self::TrailingBytes => write!(f, "bytes follow the envelope"),
            Self::UnknownKind(kind) => write!(f, "unknown object kind {kind}"),
            Self::PayloadTooLarge(len) => write!(f, "payload of {len} bytes is over the limit"),
            Self::SchemeOnNonSignature => write!(f, "only a signature object names a scheme"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// A heavy object on its way to the aggregators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// What the payload is.
    pub kind: ObjectKind,
    /// The signature scheme. Zero unless `kind` is a signature.
    pub scheme: SchemeId,
    /// The signature with its public key, the proof or the opening.
    pub payload: Vec<u8>,
    /// The transaction that will use the claim.
    pub tx_hash: Hash32,
    /// The domain the claim is made for.
    pub domain: DomainId,
}

impl Envelope {
    /// The canonical encoding: kind, scheme, transaction hash, domain, the
    /// payload length and the payload. Every field before the payload has a
    /// fixed width and the payload carries its length.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENVELOPE_HEADER_BYTES.saturating_add(self.payload.len()));
        out.push(self.kind.to_byte());
        out.extend_from_slice(&self.scheme.to_be_bytes());
        out.extend_from_slice(&self.tx_hash);
        out.extend_from_slice(&self.domain.to_be_bytes());
        // A payload never reaches 4 GiB: every admission limit is far below it.
        let len = u32::try_from(self.payload.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode an envelope that fills `bytes` exactly and whose payload is at
    /// most `max_payload` bytes. The limit is checked before the payload is
    /// read.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError`] when the bytes are malformed or over the limit.
    pub fn decode(bytes: &[u8], max_payload: usize) -> Result<Self, EnvelopeError> {
        let (&[kind], rest) = bytes
            .split_first_chunk::<1>()
            .ok_or(EnvelopeError::Truncated)?;
        let (scheme, rest) = rest
            .split_first_chunk::<2>()
            .ok_or(EnvelopeError::Truncated)?;
        let (tx_hash, rest) = rest
            .split_first_chunk::<32>()
            .ok_or(EnvelopeError::Truncated)?;
        let (domain, rest) = rest
            .split_first_chunk::<4>()
            .ok_or(EnvelopeError::Truncated)?;
        let (len, payload) = rest
            .split_first_chunk::<4>()
            .ok_or(EnvelopeError::Truncated)?;
        let kind = ObjectKind::from_byte(kind).ok_or(EnvelopeError::UnknownKind(kind))?;
        let scheme = SchemeId(u16::from_be_bytes(*scheme));
        if kind != ObjectKind::Signature && scheme.0 != 0 {
            return Err(EnvelopeError::SchemeOnNonSignature);
        }
        let len = usize::try_from(u32::from_be_bytes(*len)).unwrap_or(usize::MAX);
        if len > max_payload {
            return Err(EnvelopeError::PayloadTooLarge(len));
        }
        match payload.len().cmp(&len) {
            std::cmp::Ordering::Less => return Err(EnvelopeError::Truncated),
            std::cmp::Ordering::Greater => return Err(EnvelopeError::TrailingBytes),
            std::cmp::Ordering::Equal => {}
        }
        Ok(Self {
            kind,
            scheme,
            payload: payload.to_vec(),
            tx_hash: *tx_hash,
            domain: u32::from_be_bytes(*domain),
        })
    }

    /// `object_id = H("BDLM_OBJECT_V1" || envelope bytes)`.
    #[must_use]
    pub fn object_id(&self) -> Hash32 {
        h(&[TAG_OBJECT, &self.encode()])
    }
}
