//! Deterministic PNG raster of a [`QrMatrix`] (K-QR-DETERMINIZM).
//!
//! Same discipline as catalogue PNG: filter 0, zlib **stored**, table CRC/Adler.
//! Bit-equal across machines; no floating point.

use crate::storage::qr_matrix::{QrMatrix, QrMatrixError, MODULE_PX, QUIET_ZONE};

/// PNG encode errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QrPngError {
    /// Nested matrix error.
    Matrix(QrMatrixError),
    /// Geometry overflow.
    Geometry,
}

impl std::fmt::Display for QrPngError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Matrix(e) => write!(f, "qr png: {e}"),
            Self::Geometry => write!(f, "qr png geometry"),
        }
    }
}

impl std::error::Error for QrPngError {}

impl From<QrMatrixError> for QrPngError {
    fn from(e: QrMatrixError) -> Self {
        Self::Matrix(e)
    }
}

/// Render matrix to a deterministic RGB8 PNG.
pub fn matrix_to_png(matrix: &QrMatrix) -> Result<Vec<u8>, QrPngError> {
    let side_m = matrix.raster_modules();
    let side_px = side_m.saturating_mul(MODULE_PX);
    if side_px == 0 || side_px > 8192 {
        return Err(QrPngError::Geometry);
    }
    let w = side_px as usize;
    let h = w;
    // RGB raw + filter byte per row
    let mut raw = Vec::with_capacity(h * (1 + w * 3));
    for py in 0..h {
        raw.push(0); // filter None
        let my = (py as u32) / MODULE_PX;
        for px in 0..w {
            let mx = (px as u32) / MODULE_PX;
            let dark = if my >= QUIET_ZONE
                && mx >= QUIET_ZONE
                && my < QUIET_ZONE + matrix.width
                && mx < QUIET_ZONE + matrix.width
            {
                matrix.is_dark(mx - QUIET_ZONE, my - QUIET_ZONE)
            } else {
                false
            };
            let v = if dark { 0u8 } else { 255u8 };
            raw.push(v);
            raw.push(v);
            raw.push(v);
        }
    }
    Ok(write_png_rgb8(side_px, side_px, &raw))
}

/// Encode optical frame bytes → QR → PNG in one step.
pub fn frame_to_qr_png(frame: &[u8]) -> Result<Vec<u8>, QrPngError> {
    let m = QrMatrix::encode(frame)?;
    matrix_to_png(&m)
}

fn write_png_rgb8(width: u32, height: u32, filtered_raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.push(8); // bit depth
    ihdr.push(2); // color RGB
    ihdr.push(0);
    ihdr.push(0);
    ihdr.push(0);
    write_chunk(&mut out, b"IHDR", &ihdr);
    let idat = zlib_stored(filtered_raw);
    write_chunk(&mut out, b"IDAT", &idat);
    write_chunk(&mut out, b"IEND", &[]);
    out
}

fn write_chunk(out: &mut Vec<u8>, ty: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(ty);
    out.extend_from_slice(data);
    let mut crc_input = Vec::with_capacity(4 + data.len());
    crc_input.extend_from_slice(ty);
    crc_input.extend_from_slice(data);
    out.extend_from_slice(&crc32_png(&crc_input).to_be_bytes());
}

fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 16);
    out.push(0x78);
    out.push(0x01);
    let mut pos = 0usize;
    while pos < data.len() {
        let final_block = pos + 65535 >= data.len();
        let block_len = (data.len() - pos).min(65535);
        out.push(u8::from(final_block));
        let block16 = block_len as u16;
        out.extend_from_slice(&block16.to_le_bytes());
        out.extend_from_slice(&(!block16).to_le_bytes());
        out.extend_from_slice(&data[pos..pos + block_len]);
        pos += block_len;
    }
    let mut a = 1u32;
    let mut b = 0u32;
    for &byte in data {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    out.extend_from_slice(&((b << 16) | a).to_be_bytes());
    out
}

fn crc32_png(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, entry) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *entry = c;
    }
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        let idx = ((crc ^ u32::from(b)) & 0xFF) as usize;
        let te = table.get(idx).copied().unwrap_or(0);
        crc = te ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn png_magic_and_stable() {
        let a = frame_to_qr_png(b"stable-qr-png-payload-001").unwrap();
        let b = frame_to_qr_png(b"stable-qr-png-payload-001").unwrap();
        assert_eq!(a, b);
        assert_eq!(&a[0..8], &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
    }
}
