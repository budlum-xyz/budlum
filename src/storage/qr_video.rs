//! Three **QR-video** container (plan CI A4 root).
//!
//! In-tree lab container `BDLV`: ordered deterministic QR-PNG frames bound to a
//! stream commitment. This **is** the QR-video object the recipe re-emits.
//! H.264/VP9 remain optional external channels behind [`crate::storage::qr_codec`];
//! they are not required for the product claim "recipe -> QR video -> content".
//!
//! # Wire
//!
//! ```text
//! magic[4] = BDLV
//! version u8 = 1
//! flags u8 = 0
//! fps u16 LE
//! frame_count u32 LE
//! stream_commitment [32]
//! recipe_commitment [32]
//! repeated:
//!   png_len u32 LE
//!   png [png_len]
//! ```

use crate::core::hash::hash_fields_bytes;
use crate::storage::qr_png::{frame_to_qr_png, QrPngError};
use crate::storage::qr_recipe::ThreeRecipePublic;

/// Wire magic.
pub const VIDEO_MAGIC: [u8; 4] = *b"BDLV";
pub const VIDEO_VERSION: u8 = 1;
/// Default fps for progressive playback pacing (display hint; not consensus time).
pub const DEFAULT_FPS: u16 = 10;
/// Max frames in one lab video (`DoS` bound).
pub const MAX_VIDEO_FRAMES: u32 = 50_000;

/// Errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QrVideoError {
    /// Empty frame list.
    Empty,
    /// Too many frames.
    TooMany(u32),
    /// Truncated / bad magic.
    BadBlob,
    /// Nested PNG/QR.
    Png(String),
    /// Stream / recipe mismatch on open.
    CommitmentMismatch,
    /// Decode of a QR PNG failed.
    Decode(String),
}

impl std::fmt::Display for QrVideoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "qr video empty"),
            Self::TooMany(n) => write!(f, "qr video too many frames {n}"),
            Self::BadBlob => write!(f, "qr video bad blob"),
            Self::Png(s) => write!(f, "qr video png: {s}"),
            Self::CommitmentMismatch => write!(f, "qr video commitment mismatch"),
            Self::Decode(s) => write!(f, "qr video decode: {s}"),
        }
    }
}

impl std::error::Error for QrVideoError {}

impl From<QrPngError> for QrVideoError {
    fn from(e: QrPngError) -> Self {
        Self::Png(e.to_string())
    }
}

/// Built QR-video.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrVideo {
    pub fps: u16,
    pub stream_commitment: [u8; 32],
    pub recipe_commitment: [u8; 32],
    /// Deterministic QR PNG frames in order.
    pub png_frames: Vec<Vec<u8>>,
}

impl QrVideo {
    /// Mux optical A3 frames into QR PNGs + BDLV blob fields.
    /// # Errors
    ///
    /// Propagates `QrVideoError` from the step that failed; its variants name the refused
    /// conditions.
    pub fn from_optical_frames(
        recipe: &ThreeRecipePublic,
        stream_commitment: &[u8; 32],
        optical_frames: &[Vec<u8>],
        fps: u16,
    ) -> Result<Self, QrVideoError> {
        if optical_frames.is_empty() {
            return Err(QrVideoError::Empty);
        }
        if optical_frames.len() as u32 > MAX_VIDEO_FRAMES {
            return Err(QrVideoError::TooMany(optical_frames.len() as u32));
        }
        let recipe_commitment = crate::storage::qr_recipe::three_recipe_digest(recipe);
        let mut png_frames = Vec::with_capacity(optical_frames.len());
        for fr in optical_frames {
            png_frames.push(frame_to_qr_png(fr)?);
        }
        Ok(Self {
            fps,
            stream_commitment: *stream_commitment,
            recipe_commitment,
            png_frames,
        })
    }

    /// Serialize to BDLV bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&VIDEO_MAGIC);
        out.push(VIDEO_VERSION);
        out.push(0);
        out.extend_from_slice(&self.fps.to_le_bytes());
        out.extend_from_slice(&(self.png_frames.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.stream_commitment);
        out.extend_from_slice(&self.recipe_commitment);
        for png in &self.png_frames {
            out.extend_from_slice(&(png.len() as u32).to_le_bytes());
            out.extend_from_slice(png);
        }
        out
    }

    /// Parse BDLV.
    /// # Errors
    ///
    /// Propagates `QrVideoError` from the step that failed; its variants name the refused
    /// conditions.
    pub fn from_bytes(blob: &[u8]) -> Result<Self, QrVideoError> {
        if blob.len() < 4 + 1 + 1 + 2 + 4 + 32 + 32 {
            return Err(QrVideoError::BadBlob);
        }
        if blob.get(0..4) != Some(VIDEO_MAGIC.as_slice()) {
            return Err(QrVideoError::BadBlob);
        }
        if blob.get(4).copied() != Some(VIDEO_VERSION) {
            return Err(QrVideoError::BadBlob);
        }
        let fps = u16_le(blob, 6)?;
        let n = u32_le(blob, 8)? as usize;
        if n == 0 || n as u32 > MAX_VIDEO_FRAMES {
            return Err(QrVideoError::BadBlob);
        }
        let mut stream = [0u8; 32];
        stream.copy_from_slice(blob.get(12..44).ok_or(QrVideoError::BadBlob)?);
        let mut recipe = [0u8; 32];
        recipe.copy_from_slice(blob.get(44..76).ok_or(QrVideoError::BadBlob)?);
        let mut off = 76usize;
        let mut png_frames = Vec::with_capacity(n);
        for _ in 0..n {
            let len = u32_le(blob, off)? as usize;
            off += 4;
            let png = blob
                .get(off..off + len)
                .ok_or(QrVideoError::BadBlob)?
                .to_vec();
            off += len;
            png_frames.push(png);
        }
        Ok(Self {
            fps,
            stream_commitment: stream,
            recipe_commitment: recipe,
            png_frames,
        })
    }

    /// Commitment over the full BDLV bytes (NFT / recipe pin optional).
    #[must_use]
    pub fn blob_commitment(blob: &[u8]) -> [u8; 32] {
        hash_fields_bytes(&[b"BDLM_THREE_QR_VIDEO_V1", blob])
    }
}

fn u16_le(b: &[u8], off: usize) -> Result<u16, QrVideoError> {
    let s = b.get(off..off + 2).ok_or(QrVideoError::BadBlob)?;
    let mut a = [0u8; 2];
    a.copy_from_slice(s);
    Ok(u16::from_le_bytes(a))
}
fn u32_le(b: &[u8], off: usize) -> Result<u32, QrVideoError> {
    let s = b.get(off..off + 4).ok_or(QrVideoError::BadBlob)?;
    let mut a = [0u8; 4];
    a.copy_from_slice(s);
    Ok(u32::from_le_bytes(a))
}

/// Decode one QR PNG back to optical frame bytes via rqrr.
/// # Errors
///
/// Propagates `QrVideoError` from the step that failed; its variants name the refused
/// conditions.
pub fn png_to_optical_frame(png: &[u8]) -> Result<Vec<u8>, QrVideoError> {
    let (w, h, grey) = decode_png_grey(png).map_err(QrVideoError::Decode)?;
    // rqrr wants a flat grid; use PreparedImage
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| {
        grey.get(y * w + x).copied().unwrap_or(255)
    });
    let grids = img.detect_grids();
    if grids.is_empty() {
        return Err(QrVideoError::Decode("no qr grid".into()));
    }
    let grid = grids
        .first()
        .ok_or_else(|| QrVideoError::Decode("no qr grid".into()))?;
    // Binary optical frames: decode_to writes raw bytes (not UTF-8 String).
    let mut data = Vec::new();
    grid.decode_to(&mut data)
        .map_err(|e| QrVideoError::Decode(format!("{e:?}")))?;
    Ok(data)
}

/// Demux BDLV → optical frames (ordered).
/// # Errors
///
/// Propagates `QrVideoError` from the step that failed; its variants name the refused
/// conditions.
pub fn demux_optical_frames(video: &QrVideo) -> Result<Vec<Vec<u8>>, QrVideoError> {
    let mut out = Vec::with_capacity(video.png_frames.len());
    for png in &video.png_frames {
        out.push(png_to_optical_frame(png)?);
    }
    Ok(out)
}

/// Minimal greyscale decode for **our** stored-filter RGB PNGs only.
fn decode_png_grey(png: &[u8]) -> Result<(usize, usize, Vec<u8>), String> {
    if png.len() < 8 {
        return Err("png magic".into());
    }
    let magic = png.get(0..8).ok_or_else(|| "png magic".to_string())?;
    if magic != [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a] {
        return Err("png magic".into());
    }
    let mut off = 8usize;
    let mut width = 0u32;
    let mut height = 0u32;
    let mut idat = Vec::new();
    while off + 8 <= png.len() {
        let len_bytes = png.get(off..off + 4).ok_or_else(|| "png len".to_string())?;
        let mut lb = [0u8; 4];
        lb.copy_from_slice(len_bytes);
        let len = u32::from_be_bytes(lb) as usize;
        let ty = png
            .get(off + 4..off + 8)
            .ok_or_else(|| "png ty".to_string())?;
        let data = png
            .get(off + 8..off + 8 + len)
            .ok_or_else(|| "png chunk".to_string())?;
        off = off + 12 + len;
        if ty == b"IHDR" {
            if data.len() < 8 {
                return Err("ihdr".into());
            }
            let mut wb = [0u8; 4];
            let mut hb = [0u8; 4];
            wb.copy_from_slice(data.get(0..4).ok_or_else(|| "w".to_string())?);
            hb.copy_from_slice(data.get(4..8).ok_or_else(|| "h".to_string())?);
            width = u32::from_be_bytes(wb);
            height = u32::from_be_bytes(hb);
        } else if ty == b"IDAT" {
            idat.extend_from_slice(data);
        } else if ty == b"IEND" {
            break;
        }
    }
    if width == 0 || height == 0 {
        return Err("no ihdr".into());
    }
    let raw = inflate_zlib_stored(&idat)?;
    let w = width as usize;
    let h = height as usize;
    let row = 1 + w * 3;
    if raw.len() != h * row {
        return Err(format!("raw len {} != {}", raw.len(), h * row));
    }
    let mut grey = vec![0u8; w * h];
    for y in 0..h {
        let base = y * row;
        let filter = raw.get(base).copied().unwrap_or(1);
        if filter != 0 {
            return Err("filter".into());
        }
        for x in 0..w {
            let r = raw.get(base + 1 + x * 3).copied().unwrap_or(0);
            if let Some(slot) = grey.get_mut(y * w + x) {
                *slot = r;
            }
        }
    }
    Ok((w, h, grey))
}

fn inflate_zlib_stored(z: &[u8]) -> Result<Vec<u8>, String> {
    // Our encoder writes zlib stored only - parse that; also accept flate2 for safety.
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    let mut d = ZlibDecoder::new(z);
    let mut out = Vec::new();
    d.read_to_end(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::qr_carousel::CarouselParams;
    use crate::storage::three_pipe::{encode_qr_video, PIPE_DEFAULT_BLOCK_LEN};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Golden vector: the header of a single-frame BDLV blob and its full sha256.
    /// Frame modules now come from our fixed-mask qr_encode, so
    /// this vector pins the byte-level behaviour of the encoder and the mux.
    #[test]
    fn video_wire_matches_the_golden_vectors() {
        let pc = [
            0x7eu8, 0x38, 0x0b, 0x6b, 0x1a, 0x1e, 0x98, 0x17, 0x93, 0xbc, 0x14, 0xe8, 0x97, 0x0f,
            0xef, 0xe3, 0xa2, 0x5c, 0xff, 0x38, 0x95, 0xba, 0xc6, 0x5b, 0x5e, 0x5c, 0xc2, 0xc9,
            0xf8, 0x55, 0xac, 0x0d,
        ];
        let recipe = ThreeRecipePublic {
            payload_commitment: pc,
            carousel: CarouselParams {
                k: 3,
                block_len: 8,
                total_len: 24,
            },
            stream_id: [0u8; 32],
            block_len: 8,
        };
        let v = QrVideo::from_optical_frames(&recipe, &pc, &[b"vektor kare".to_vec()], 10).unwrap();
        let blob = v.to_bytes();
        assert_eq!(blob.len(), 503);
        assert_eq!(
            hex(&blob[..76]),
            "42444c5601000a00010000007e380b6b1a1e981793bc14e8970fefe3a25cff3895bac65b5e5cc2c9f855ac0dba46b1eab74314497ca00de7ae9ee2d4976fdaa64bd1e51f397c7eedcbce8962"
        );
        use sha2::Digest as _;
        let mut h = sha2::Sha256::new();
        h.update(&blob);
        assert_eq!(
            hex(&h.finalize()),
            "bab09b692296eb54e81010842ab0d000e91553f86e0a4a4e7242bbecfc2fbe3e"
        );
    }

    #[test]
    fn foreign_video_version_is_gated() {
        let pc = [0u8; 32];
        let recipe = ThreeRecipePublic {
            payload_commitment: pc,
            carousel: CarouselParams {
                k: 1,
                block_len: 8,
                total_len: 8,
            },
            stream_id: [0u8; 32],
            block_len: 8,
        };
        let v = QrVideo::from_optical_frames(&recipe, &pc, &[b"kare".to_vec()], 10).unwrap();
        let mut blob = v.to_bytes();
        blob[4] = 2;
        assert_eq!(
            QrVideo::from_bytes(&blob).unwrap_err(),
            QrVideoError::BadBlob
        );
    }

    #[test]
    fn video_round_trip_optical() {
        let content = b"qr-video-root-content".repeat(8);
        let enc = encode_qr_video(&content, PIPE_DEFAULT_BLOCK_LEN, None)
            .unwrap()
            .pipe;
        // Use a short prefix of frames for speed in unit test (systematic enough for small)
        let frames: Vec<_> = enc
            .frames
            .iter()
            .take(enc.frames.len().min(40))
            .cloned()
            .collect();
        let video =
            QrVideo::from_optical_frames(&enc.recipe, &enc.stream_commitment, &frames, DEFAULT_FPS)
                .unwrap();
        let blob = video.to_bytes();
        let parsed = QrVideo::from_bytes(&blob).unwrap();
        assert_eq!(parsed.png_frames.len(), frames.len());
        // Decode first QR PNG back to optical frame
        let got0 = png_to_optical_frame(&parsed.png_frames[0]).unwrap();
        assert_eq!(got0, frames[0]);
    }

    /// The lossy half of the K10 claim, measured here rather than asserted.
    ///
    /// Two things are checked, because the claim has two halves and they run
    /// through different code. A drop's body is 4000 bytes at the low level, so
    /// that half is measured on the drop stream itself; the container half is
    /// measured at the block length the QR PNG encoder can actually carry.
    ///
    /// The channel model is deterministic: one frame in ten is gone, and half of
    /// those are gone because a flipped bit inside the body tripped the drop's
    /// FNV check, which is what a frame that arrives damaged does. Under that
    /// channel a single cycle of `k` frames cannot finish, and the redundancy
    /// `CarouselFrame::drops_for_loss` prescribes does.
    ///
    /// Not measured here, and not claimed: what an H.264 encoder at CRF 28 keeps
    /// of a QR frame. This container muxes PNGs, so no codec sits on this path.
    /// The prescribed redundancy for a given loss rate is `CarouselFrame`'s own
    /// claim and is measured in the `bud` crate, which owns that type.
    #[test]
    fn k10_channel_loss_survives_the_video_container() {
        use crate::storage::qr_carousel::{CarouselDecoder, CarouselEncoder, CarouselError, Drop};

        // (a) The low-level half: 4000 bytes per drop body, no container.
        let block = 4000usize;
        let payload: Vec<u8> = (0..block * 16).map(|i| (i % 251) as u8).collect();
        let enc = CarouselEncoder::new(&payload, block).unwrap();
        let k = usize::from(enc.params().k);
        assert_eq!(k, 16, "sixteen blocks of 4000 bytes is the claim's k");
        let raw: Vec<Vec<u8>> = (0..(4 * k) as u32)
            .map(|s| enc.drop_at(s).to_bytes())
            .collect();
        let (survivors, dropped, refused) = channel(&raw);
        assert!(
            dropped + refused >= 3,
            "the channel must actually damage the stream, measured {dropped} dropped and {refused} refused"
        );
        assert!(
            refused > 0,
            "a flipped body bit must be refused by the drop's own check"
        );
        let mut tek = CarouselDecoder::new();
        for f in survivors.iter().take(k) {
            if let Ok(d) = Drop::from_bytes(f) {
                let _ = tek.push(&d);
            }
        }
        assert!(
            !tek.is_complete(),
            "k frames with a tenth lost cannot be complete; that is what the factor is for"
        );
        let mut cift = CarouselDecoder::new();
        for f in &survivors {
            if let Ok(d) = Drop::from_bytes(f) {
                let _ = cift.push(&d);
            }
        }
        assert!(cift.is_complete(), "missing {}", cift.missing());
        assert_eq!(
            cift.finish().unwrap(),
            payload,
            "recovery must be byte-exact"
        );

        // (b) The container half: the same channel applied after a BDLV mux, so
        // the mux itself is proven lossless and the frames that arrive are the
        // frames that were sent.
        let small = CarouselEncoder::new(&payload, 1000).unwrap();
        let frames: Vec<Vec<u8>> = (0..(4 * usize::from(small.params().k)) as u32)
            .map(|s| small.drop_at(s).to_bytes())
            .collect();
        let pc = [0x5au8; 32];
        let recipe = ThreeRecipePublic {
            payload_commitment: pc,
            carousel: *small.params(),
            stream_id: [0u8; 32],
            block_len: 1000,
        };
        let video = QrVideo::from_optical_frames(&recipe, &pc, &frames, DEFAULT_FPS).unwrap();
        let parsed = QrVideo::from_bytes(&video.to_bytes()).unwrap();
        let demuxed = demux_optical_frames(&parsed).unwrap();
        assert_eq!(demuxed.len(), frames.len(), "the mux loses a frame");
        for (got, sent) in demuxed.iter().zip(&frames) {
            assert_eq!(got, sent, "a frame must come back byte-identical");
        }
        let (survivors, _, _) = channel(&demuxed);
        let mut dec = CarouselDecoder::new();
        for f in &survivors {
            if let Ok(d) = Drop::from_bytes(f) {
                let _ = dec.push(&d);
            }
        }
        assert!(
            dec.is_complete(),
            "the same loss through the container must still recover, missing {}",
            dec.missing()
        );
        assert_eq!(
            dec.finish().unwrap(),
            payload,
            "container recovery must be exact"
        );
    }

    /// One frame in ten is taken by the channel: every other one by bit rot in
    /// the body, the rest by disappearing. Returns what a receiver would hand to
    /// the decoder plus the two counts.
    fn channel(frames: &[Vec<u8>]) -> (Vec<Vec<u8>>, usize, usize) {
        let mut out = Vec::with_capacity(frames.len());
        let mut dropped = 0usize;
        let mut refused = 0usize;
        for (i, f) in frames.iter().enumerate() {
            if i % 10 != 0 {
                out.push(f.clone());
                continue;
            }
            if (i / 10) % 2 == 0 {
                dropped += 1;
                continue;
            }
            let mut hurt = f.clone();
            let mid = hurt.len() / 2;
            hurt[mid] ^= 0x80;
            match Drop::from_bytes(&hurt) {
                Err(CarouselError::BodyHashMismatch) => refused += 1,
                Err(other) => panic!("a flipped body bit must fail the hash, not {other:?}"),
                Ok(_) => panic!("a flipped body bit slipped past the drop check"),
            }
        }
        (out, dropped, refused)
    }
}
