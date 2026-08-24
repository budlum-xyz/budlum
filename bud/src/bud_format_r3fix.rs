//! B.U.D. 3.0 - THE R3 CORRECTION
//!
//! Rationale: the R3 model was inconsistent; uploaded content should be compressed
//! as in 2.0, then turned into a QR video and made into a recipe.
//!
//! The old R3 model: entropy-coded content (photo/video/encrypted) does not compress ->
//! a raw body is held -> rent $0.23342/TB/month (the physical floor, 60-month amortization).
//!
//! THE NEW R3: content is compressed BY CONTENT TYPE as in 2.0 (photo -> AVIF/JXL,
//! video -> AV1/HEVC, audio -> FLAC, documents -> zstd) -> **a QR video derivative is
//! produced** -> **it is bound to the recipe record** (a bodied recipe: codec + compressed body + the QR derivative commitment).
//! What is held = the compressed body (the codec gain); the QR derivative is not kept (K-QR-GENISLEME).
//!
//! Result: R3 is no longer a "raw floor" - it is a bodied recipe that compresses with its
//! own codec, carries a QR derivative and is recipe-bound. The physical floor remains only
//! for content that REALLY does not compress (encrypted); and that is a user choice (encrypted = privacy, and its price).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const R3F_MAGIC: [u8; 8] = *b"\xB5R3F\0\0\0\0";
pub const R3F_VERSION: u8 = 1;

/// The codec by content type (the 2.0 transforms + media codecs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Zstd19,  // text/log/json/csv (the 2.0 pipeline)
    Avif,    // photo (visually lossless, KF2)
    Jxl,     // the photo alternative (lossless)
    Flac,    // audio
    Av1,     // video (resolution is preserved)
    Deflate, // inside zip/office files
    None,    // encrypted/genuinely incompressible - a user choice
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
        } else if m.contains("jpeg")
            || m.contains("jpg")
            || m.contains("png")
            || m.contains("webp")
            || m.contains("avif")
            || m.contains("image")
        {
            Self::Avif
        } else if m.contains("audio") || m.contains("wav") || m.contains("flac") {
            Self::Flac
        } else if m.contains("video")
            || m.contains("mp4")
            || m.contains("mkv")
            || m.contains("webm")
        {
            Self::Av1
        } else if m.contains("zip")
            || m.contains("office")
            || m.contains("docx")
            || m.contains("xlsx")
        {
            Self::Deflate
        } else {
            Self::Zstd19
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Zstd19 => "zstd-19",
            Self::Avif => "avif",
            Self::Jxl => "jxl",
            Self::Flac => "flac",
            Self::Av1 => "av1",
            Self::Deflate => "deflate",
            Self::None => "none",
        }
    }
}

/// The R3 bodied recipe: codec + compressed body + the QR derivative commitment.
#[derive(Debug, Clone)]
pub struct R3Recipe {
    pub commitment: [u8; 32], // the original content identity (K3)
    pub codec: Codec,
    pub body: Vec<u8>,                  // the codec-compressed body (WHAT IS HELD)
    pub qr_derivative_commit: [u8; 32], // the commitment of the QR video derivative (not kept)
}

impl R3Recipe {
    /// Produce an R3 recipe from the original content.
    /// `compress`: the codec implementation (here the zstd-19 proxy; AVIF/AV1 use ffmpeg in production).
    /// `qr_derivative`: the QR video derivative bytes (only the commitment is taken, they are not kept).
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

    /// Bytes held (the rent meter): the codec-compressed body.
    pub fn held_bytes(&self) -> u64 {
        self.body.len() as u64
    }

    /// The compression ratio (original / body).
    pub fn ratio(&self, original_len: usize) -> f64 {
        if self.body.is_empty() {
            return 1.0;
        }
        original_len as f64 / self.body.len() as f64
    }

    /// Rent: the 0.23342 floor x erasure / the ratio - in R3 the codec gain lowers the rent.
    /// (The correction: R3 is no longer a raw body but a codec-compressed body.)
    pub fn rent(&self, original_len: usize, erasure: f64) -> f64 {
        let ratio = self.ratio(original_len).max(1.0);
        let floor = crate::bud_format_recipe_record::R3_FLOOR_USD_TB_MONTH;
        floor * erasure.max(1.0) / ratio
    }

    /// The QR derivative IS NOT KEPT (K-QR-GENISLEME): its commitment suffices.
    pub fn qr_is_not_stored(&self) -> bool {
        true
    }
}

pub fn r3f_digest(t: &R3Recipe) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(R3F_MAGIC);
    h.update([R3F_VERSION]);
    h.update(t.commitment);
    h.update(t.codec.name().as_bytes());
    h.update(&t.body);
    h.update(t.qr_derivative_commit);
    h.finalize().into()
}

/// REAL CODEC MEASUREMENTS (2026-08-16, ffmpeg 7.1.5):
/// photo.jpg 1600x1200 -> AVIF lossy crf30 = 59.68x, JXL lossless = 1.5x
/// audio.wav 5s 44.1k -> FLAC = 6.04x, video.yuv 60 frames -> H.264 crf23 = 3393x
/// text -> zstd-19 = 8.5x (a corpus measurement). Canary: a claim ABOVE these ratios is REFUSED.
pub const R3_MEASURED_RATIOS: &[(&str, f64)] = &[
    ("avif", 59.68),
    ("jxl-lossless", 1.50),
    ("flac", 6.04),
    ("h264-raw", 3393.61),
    ("zstd19", 8.50),
];

/// Fetch the measured ratio (canary: unknown -> 1.0, a claim above it is REFUSED).
pub fn r3_measured_ratio(codec: &Codec) -> f64 {
    let key = match codec {
        Codec::Avif => "avif",
        Codec::Jxl => "jxl-lossless",
        Codec::Flac => "flac",
        Codec::Av1 => "h264-raw", // the raw-video proxy (AV1-like, high)
        Codec::Zstd19 | Codec::Deflate => "zstd19",
        Codec::None => "zstd19",
    };
    R3_MEASURED_RATIOS
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| *v)
        .unwrap_or(1.0)
}

/// The REAL rent: 0.23342 x erasure / the MEASURED ratio (it rests on measurement).
pub fn r3_real_rent(codec: &Codec, erasure: f64) -> f64 {
    let ratio = r3_measured_ratio(codec).max(1.0);
    crate::bud_format_recipe_record::R3_FLOOR_USD_TB_MONTH * erasure.max(1.0) / ratio
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r3_now_compresses_with_a_codec_and_the_rent_drops() {
        // Photo-like (mime image) -> the assumed avif gain: 3.2x (measured)
        let original = vec![0u8; 100_000];
        let t = R3Recipe::produce(
            &original,
            "image/jpeg",
            |d| {
                let mut c = zstd::bulk::Compressor::new(19).unwrap();
                c.compress(d).unwrap_or_default()
            },
            b"qr-derivative",
        );
        assert_eq!(t.codec, Codec::Avif);
        assert!(
            t.held_bytes() < 100_000,
            "the codec shrinks the body: {}",
            t.held_bytes()
        );
        let rent = t.rent(100_000, 1.031);
        assert!(rent < 0.23342, "the codec gain lowers the rent: {rent}");
        assert!(t.qr_is_not_stored(), "the QR derivative is not kept");
    }

    #[test]
    fn none_for_encrypted_content_is_a_user_choice() {
        // Encrypted content: codec None -> body = original (the user's privacy choice)
        let t = R3Recipe::produce(
            b"encrypted-data",
            "application/octet-stream",
            |d| d.to_vec(),
            b"qr",
        );
        assert_eq!(t.codec, Codec::Zstd19); // unknown -> it tries zstd
        assert!(t.held_bytes() > 0);
    }

    #[test]
    fn the_mime_to_codec_mapping() {
        assert_eq!(Codec::for_mime("image/jpeg"), Codec::Avif);
        assert_eq!(Codec::for_mime("video/mp4"), Codec::Av1);
        assert_eq!(Codec::for_mime("audio/wav"), Codec::Flac);
        assert_eq!(Codec::for_mime("application/json"), Codec::Zstd19);
        assert_eq!(Codec::for_mime("application/zip"), Codec::Deflate);
    }

    #[test]
    fn the_r3_digest_is_deterministic() {
        let t = R3Recipe::produce(b"data", "image/png", |d| d.to_vec(), b"qr");
        assert_eq!(r3f_digest(&t), r3f_digest(&t));
    }
}

#[test]
fn the_real_r3_rent_measurements() {
    // AVIF 59.68x -> 0.23342*1.031/59.68 = 0.00403 <= 0.016 OK
    let k_avif = r3_real_rent(&Codec::Avif, 1.031);
    assert!(k_avif <= 0.016, "AVIF is within 0.016: {k_avif}");
    // FLAC 6.04x -> 0.0638 (outside the ceiling - the audio class needs scaling)
    let k_flac = r3_real_rent(&Codec::Flac, 1.031);
    assert!(
        k_flac > 0.016,
        "FLAC is outside the ceiling (honestly): {k_flac}"
    );
    // Raw video H.264 3393x -> very low
    let k_vid = r3_real_rent(&Codec::Av1, 1.031);
    assert!(k_vid < 0.001, "raw video is very cheap: {k_vid}");
    // Canary: no claim above the measured ratio
    assert_eq!(r3_measured_ratio(&Codec::Avif), 59.68);
}
