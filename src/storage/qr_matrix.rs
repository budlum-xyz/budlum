//! Real ISO QR module matrix for Three optical frames (plan §CI / K-QR §7).
//!
//! Pin: byte mode, EC=L, mask chosen by the encoder for the version that fits.
//! `block_len` 200 lab default stays on the carousel side; here we encode one
//! A3 optical frame wire into one QR symbol.
//!
//! Decimen/AGPL source is not copied — only the measured rules.

use qrcode::types::{EcLevel, Version};
use qrcode::{Color, QrCode};

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
        let code = QrCode::with_error_correction_level(payload, THREE_QR_EC)
            .map_err(|e| QrMatrixError::Encode(format!("{e:?}")))?;
        let version = match code.version() {
            Version::Normal(v) => v,
            Version::Micro(v) => {
                return Err(QrMatrixError::Encode(format!("micro QR not used: {v}")));
            }
        };
        let width = code.width() as u32;
        let mut dark = Vec::with_capacity((width * width) as usize);
        for y in 0..code.width() {
            for x in 0..code.width() {
                dark.push(code[(x, y)] == Color::Dark);
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
}
