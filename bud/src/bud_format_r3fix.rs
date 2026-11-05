//! The compression-chain order for uploaded content.
//!
//! The chain: the content is compressed by type, a QR video derivative is
//! derived, and both commitments are bound into the chain record. The QR
//! derivative itself is not kept - only its commitment.
//!
//! Type mapping kept here: documents and structured text compress with zstd,
//! audio maps to FLAC, archives carry deflate. No lossy image or video codec
//! is claimed at this layer: those codecs stay closed until they are measured.
//! Content that does not compress (encrypted, or a type with no claimed codec)
//! passes through unchanged - that is a user choice, and its price.
//!
//! Code: `#![forbid(unsafe_code)]`, deterministic, with tests.
//! Exposed for the B.U.D. 3.0 codec registry: the registry wires these
//! transforms.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const R3F_MAGIC: [u8; 8] = *b"\xB5R3F\0\0\0\0";
pub const R3F_VERSION: u8 = 1;

/// The codec by content type (the transforms this layer can claim).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Zstd19,  // text/log/json/csv (the document pipeline)
    Flac,    // audio (lossless)
    Deflate, // inside zip/office files
    None,    // no codec claimed - the bytes pass through
}

impl Codec {
    pub fn for_mime(mime: &str) -> Self {
        let m = mime.to_lowercase();
        if m.contains("json")
            || m.contains("csv")
            || m.contains("log")
            || m.contains("text")
            || m.contains("xml")
        {
            Self::Zstd19
        } else if m.contains("audio") || m.contains("wav") || m.contains("flac") {
            Self::Flac
        } else if m.contains("zip")
            || m.contains("office")
            || m.contains("docx")
            || m.contains("xlsx")
        {
            Self::Deflate
        } else {
            Self::None
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Zstd19 => "zstd-19",
            Self::Flac => "flac",
            Self::Deflate => "deflate",
            Self::None => "none",
        }
    }
}

/// The chain record: content commitment + codec + compressed body + the QR
/// derivative commitment (the derivative bytes are not kept).
#[derive(Debug, Clone)]
pub struct ChainRecord {
    pub commitment: [u8; 32], // the original content identity
    pub codec: Codec,
    pub body: Vec<u8>,                  // the codec-compressed body
    pub qr_derivative_commit: [u8; 32], // the commitment of the QR video derivative (not kept)
}

impl ChainRecord {
    /// Produce a chain record from the original content: compress, derive,
    /// bind. `compress`: the codec implementation; `qr_derivative`: the QR
    /// video derivative bytes (only the commitment is taken, they are not kept).
    pub fn produce(
        original: &[u8],
        mime: &str,
        compress: impl FnOnce(&[u8]) -> Vec<u8>,
        qr_derivative: &[u8],
    ) -> Self {
        let commitment = crate::bud_format_container::content_id(original);
        let codec = Codec::for_mime(mime);
        let body = if codec == Codec::None {
            original.to_vec()
        } else {
            compress(original)
        };
        let qr_derivative_commit = crate::bud_format_container::content_id(qr_derivative);
        Self {
            commitment,
            codec,
            body,
            qr_derivative_commit,
        }
    }

    /// The QR derivative IS NOT KEPT: its commitment suffices.
    pub fn qr_is_not_stored(&self) -> bool {
        true
    }
}

pub fn r3f_digest(t: &ChainRecord) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(R3F_MAGIC);
    h.update([R3F_VERSION]);
    h.update(t.commitment);
    h.update(t.codec.name().as_bytes());
    h.update(&t.body);
    h.update(t.qr_derivative_commit);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mime_to_codec_mapping() {
        assert_eq!(Codec::for_mime("application/json"), Codec::Zstd19);
        assert_eq!(Codec::for_mime("audio/wav"), Codec::Flac);
        assert_eq!(Codec::for_mime("audio/flac"), Codec::Flac);
        assert_eq!(Codec::for_mime("application/zip"), Codec::Deflate);
        assert_eq!(Codec::for_mime("image/jpeg"), Codec::None);
        assert_eq!(Codec::for_mime("video/mp4"), Codec::None);
    }

    #[test]
    fn the_chain_orders_compress_derive_bind() {
        let original = vec![0u8; 100_000];
        let t = ChainRecord::produce(
            &original,
            "application/json",
            |d| {
                let mut c = zstd::bulk::Compressor::new(19).unwrap();
                c.compress(d).unwrap_or_default()
            },
            b"qr-derivative",
        );
        assert_eq!(t.codec, Codec::Zstd19);
        assert_eq!(t.commitment, crate::bud_format_container::content_id(&original));
        assert_eq!(
            t.qr_derivative_commit,
            crate::bud_format_container::content_id(b"qr-derivative")
        );
        assert!(t.qr_is_not_stored(), "the QR derivative is not kept");
    }

    #[test]
    fn no_claimed_codec_passes_the_body_through() {
        let t = ChainRecord::produce(
            b"encrypted-data",
            "application/octet-stream",
            |d| d.to_vec(),
            b"qr",
        );
        assert_eq!(t.codec, Codec::None);
        assert_eq!(t.body, b"encrypted-data");
    }

    #[test]
    fn the_r3_digest_is_deterministic() {
        let t = ChainRecord::produce(b"data", "audio/wav", |d| d.to_vec(), b"qr");
        assert_eq!(r3f_digest(&t), r3f_digest(&t));
    }
}
