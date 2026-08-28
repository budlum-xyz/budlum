//! Real ISO QR module matrix for Three optical frames (plan §CI / K-QR §7).
//!
//! Pin: byte mode, EC=L, mask 0 - matrices come from our own `qr_encode`, so a
//! recipe regenerates the exact same modules on every machine and every future
//! dependency bump.
//! `block_len` 200 lab default stays on the carousel side; here we encode one
//! A3 optical frame wire into one QR symbol.
//!
//! Decimen/AGPL source is not copied - only the measured rules.

use qrcode::types::EcLevel;

use super::qr_encode;

/// Lab-default: EC level L (fountain handles erasure; QR ECC handles damage).
pub const THREE_QR_EC: EcLevel = EcLevel::L;
/// Quiet zone modules (ISO).
pub const QUIET_ZONE: u32 = 4;
/// Pixels per module in the deterministic PNG raster.
pub const MODULE_PX: u32 = 4;
/// Hard cap on optical frame bytes stuffed into one QR (version 40 ~2.9KB EC-L).
pub const MAX_QR_PAYLOAD: usize = 2953;

/// Errors building or reading a QR matrix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QrMatrixError {
    /// Payload empty.
    Empty,
    /// Payload larger than ISO QR can carry at EC=L.
    TooLarge {
        /// Observed.
        len: usize,
        /// Max.
        max: usize,
    },
    /// qrcode crate refused the data.
    Encode(String),
    /// Matrix geometry inconsistent.
    Geometry,
}

impl std::fmt::Display for QrMatrixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "qr matrix empty payload"),
            Self::TooLarge { len, max } => write!(f, "qr payload {len} > max {max}"),
            Self::Encode(s) => write!(f, "qr encode: {s}"),
            Self::Geometry => write!(f, "qr matrix geometry"),
        }
    }
}

impl std::error::Error for QrMatrixError {}

/// Encoded QR symbol: module grid + version pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrMatrix {
    /// ISO version 1..=40.
    pub version: i16,
    /// Modules per side (21 + 4*(v-1)).
    pub width: u32,
    /// Row-major colors: true = dark module.
    pub dark: Vec<bool>,
}

impl QrMatrix {
    /// Encode `payload` (typically one A3 optical frame) into a QR matrix.
    ///
    /// # Errors
    ///
    /// Empty / oversized / encode failure.
    pub fn encode(payload: &[u8]) -> Result<Self, QrMatrixError> {
        if payload.is_empty() {
            return Err(QrMatrixError::Empty);
        }
        if payload.len() > MAX_QR_PAYLOAD {
            return Err(QrMatrixError::TooLarge {
                len: payload.len(),
                max: MAX_QR_PAYLOAD,
            });
        }
        let m = qr_encode::encode(payload).map_err(|e| QrMatrixError::Encode(e.to_string()))?;
        let version = i16::from(m.version());
        let width = m.side_len() as u32;
        let mut dark = Vec::with_capacity((width * width) as usize);
        for y in 0..m.side_len() {
            for x in 0..m.side_len() {
                dark.push(m.is_dark(y, x));
            }
        }
        Ok(Self {
            version,
            width,
            dark,
        })
    }

    /// Module at (x,y) dark?
    #[must_use]
    pub fn is_dark(&self, x: u32, y: u32) -> bool {
        if x >= self.width || y >= self.width {
            return false;
        }
        let i = (y * self.width + x) as usize;
        self.dark.get(i).copied().unwrap_or(false)
    }

    /// Full raster side including quiet zone, in modules.
    #[must_use]
    pub const fn raster_modules(&self) -> u32 {
        self.width.saturating_add(QUIET_ZONE.saturating_mul(2))
    }

    /// Pixel side of the deterministic PNG.
    #[must_use]
    pub const fn pixel_side(&self) -> u32 {
        self.raster_modules().saturating_mul(MODULE_PX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_small_frame() {
        let m = QrMatrix::encode(b"BDL3-test-optical-frame-bytes").unwrap();
        assert!(m.width >= 21);
        assert_eq!(m.dark.len(), (m.width * m.width) as usize);
    }

    #[test]
    fn empty_refused() {
        assert_eq!(QrMatrix::encode(b"").unwrap_err(), QrMatrixError::Empty);
    }

    #[test]
    fn matrix_is_the_pinned_encoder_output() {
        let payload = b"BDL3-deterministic-frame";
        let m = QrMatrix::encode(payload).unwrap();
        assert_eq!(m.version, 2);
        assert_eq!(m.width, 25);
        // ayni yuk, ayni moduller: kodlayici bizim, secim sabit
        let again = QrMatrix::encode(payload).unwrap();
        assert_eq!(m, again);
    }

    #[test]
    fn wrapper_matrix_decodes_through_rqrr() {
        let payload = b"BDL3-wrapper-roundtrip-payload-bytes";
        let m = QrMatrix::encode(payload).unwrap();
        let raster = m.raster_modules() as usize;
        let scale = MODULE_PX as usize;
        let img = raster * scale;
        let mut prepared = rqrr::PreparedImage::prepare_from_bitmap(img, img, |x, y| {
            let (col, row) = (x / scale, y / scale);
            let inside = QUIET_ZONE as usize..QUIET_ZONE as usize + m.width as usize;
            inside.contains(&row)
                && inside.contains(&col)
                && m.is_dark(
                    (col - QUIET_ZONE as usize) as u32,
                    (row - QUIET_ZONE as usize) as u32,
                )
        });
        let grids = prepared.detect_grids();
        assert_eq!(grids.len(), 1);
        let mut out = Vec::new();
        grids[0]
            .decode_to(&mut out)
            .expect("wrapper matrix must decode");
        assert_eq!(out, payload);
    }
}
