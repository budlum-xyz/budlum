//! Real ISO QR module matrix for Three optical frames (plan §CI / K-QR §7).
//!
//! Pin: byte mode, EC=L, mask 0 - matrices come from our own `qr_encode`, so a
//! recipe regenerates the exact same modules on every machine and every future
//! dependency bump.
//! `block_len` 200 lab default stays on the carousel side; here we encode one
//! A3 optical frame wire into one QR symbol.
//!
//! No external QR library is linked into this module; only the measured rules are used.

use qrcode::types::EcLevel;

use super::qr_encode::{self, EncodedMatrix, QrError};

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
    /// The encoder refused the payload. Carried as the encoder's own error so the
    /// reason (which version was reached, how long the payload was) survives to
    /// the caller instead of being flattened into a string.
    Encode(QrError),
    /// A level other than the pinned one was asked for. The encoder carries one
    /// capacity table, so another level cannot be honoured: refusing is the only
    /// honest answer, and it is what keeps a report from naming a level the
    /// symbol does not carry.
    UnsupportedEc(EcLevel),
    /// Matrix geometry inconsistent.
    Geometry,
}

impl std::fmt::Display for QrMatrixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "qr matrix empty payload"),
            Self::TooLarge { len, max } => write!(f, "qr payload {len} > max {max}"),
            Self::Encode(e) => write!(f, "qr encode: {e}"),
            Self::UnsupportedEc(got) => {
                write!(
                    f,
                    "qr encoder is pinned to {THREE_QR_EC:?}, {got:?} was asked"
                )
            }
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
    /// Error-correction level the symbol was actually built at. Carried on the
    /// matrix so a report describes the symbol rather than the level someone
    /// intended, which is what the pinned constant alone could not promise.
    pub ec: EcLevel,
}

impl QrMatrix {
    /// Encode `payload` (typically one A3 optical frame) into a QR matrix.
    ///
    /// # Errors
    ///
    /// Empty / oversized / encode failure.
    pub fn encode(payload: &[u8]) -> Result<Self, QrMatrixError> {
        Self::encode_at(payload, THREE_QR_EC)
    }

    /// Encode at a caller-named EC level, refusing one this encoder cannot honour.
    ///
    /// A caller that reports the level names it here, so the reported symbol and
    /// the requested one are one object rather than two claims about a table.
    ///
    /// # Errors
    ///
    /// Empty / oversized / encode failure / [`QrMatrixError::UnsupportedEc`].
    pub fn encode_at(payload: &[u8], ec: EcLevel) -> Result<Self, QrMatrixError> {
        if ec != THREE_QR_EC {
            return Err(QrMatrixError::UnsupportedEc(ec));
        }
        if payload.is_empty() {
            return Err(QrMatrixError::Empty);
        }
        if payload.len() > MAX_QR_PAYLOAD {
            return Err(QrMatrixError::TooLarge {
                len: payload.len(),
                max: MAX_QR_PAYLOAD,
            });
        }
        Self::from_encoded(
            qr_encode::encode(payload).map_err(QrMatrixError::Encode)?,
            ec,
        )
    }

    /// Flatten the encoder's own grid into the row-major form a raster wants.
    ///
    /// # Errors
    ///
    /// [`QrMatrixError::Geometry`] when the symbol has no modules.
    #[must_use]
    fn rows_of(m: &EncodedMatrix) -> Vec<bool> {
        let side = m.side_len();
        let mut dark = Vec::with_capacity(side * side);
        for y in 0..side {
            for x in 0..side {
                dark.push(m.is_dark(y, x));
            }
        }
        dark
    }

    /// Build a matrix from the encoder's symbol at the level it was asked for.
    ///
    /// # Errors
    ///
    /// [`QrMatrixError::Geometry`] when the grid is empty.
    fn from_encoded(m: EncodedMatrix, ec: EcLevel) -> Result<Self, QrMatrixError> {
        let side = m.side_len();
        if side == 0 {
            return Err(QrMatrixError::Geometry);
        }
        Ok(Self {
            version: i16::from(m.version()),
            width: side as u32,
            dark: Self::rows_of(&m),
            ec,
        })
    }

    /// Level this symbol carries.
    #[must_use]
    pub const fn ec_level(&self) -> EcLevel {
        self.ec
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
