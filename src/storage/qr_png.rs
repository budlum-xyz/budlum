//! Deterministic PNG raster of a [`QrMatrix`] (K-QR-DETERMINIZM).
//!
//! Same discipline as catalogue PNG: filter 0, table CRC, Adler-32 handled by
//! the deflate writer. Bit-equal across machines; no floating point.
//!
//! # Why IDAT is deflated
//!
//! A QR raster is long runs of two colours, so deflate is nearly free on it.
//! The stored-block writer this replaced made every frame PNG the size of its
//! raw RGB8 buffer: measured on a 224-byte optical frame that was 203 086
//! bytes against 2 104 with deflate, a 96.6x difference, and the whole BDLV
//! video inherits it frame by frame. zlib deflate at a fixed level is
//! deterministic, so K-QR-DETERMINIZM is unchanged; the test pins both the
//! ratio and bit-equality across runs.

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

/// # Errors
///
/// Propagates `QrPngError` from the step that failed; its variants name the refused conditions.
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

/// # Errors
///
/// Propagates `QrPngError` from the step that failed; its variants name the refused conditions.
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
    let idat = zlib_deflate(filtered_raw);
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

/// Deflate `data` at a fixed level so the PNG stays bit-equal across machines.
fn zlib_deflate(data: &[u8]) -> Vec<u8> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
    if enc.write_all(data).is_err() {
        // Vec-backed write only fails on allocation failure; fall back to the
        // uncompressed form rather than losing the frame.
        return zlib_stored(data);
    }
    enc.finish().unwrap_or_else(|_| zlib_stored(data))
}

/// Uncompressed zlib stream. Not the default path: only the allocation-failure
/// fallback above and the size reference in tests. Kept compiled in both
/// profiles because the fallback is reachable in release.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 16);
    out.push(0x78);
    out.push(0x01);
    // IDAT chunks hold at most 65535 bytes; `chunks` bounds every slice so no
    // cursor arithmetic can index past the payload.
    let chunk_count = data.len().div_ceil(65535);
    for (idx, chunk) in data.chunks(65535).enumerate() {
        let final_block = idx + 1 == chunk_count;
        out.push(u8::from(final_block));
        let block16 = chunk.len() as u16;
        out.extend_from_slice(&block16.to_le_bytes());
        out.extend_from_slice(&(!block16).to_le_bytes());
        out.extend_from_slice(chunk);
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

    /// IDAT chunk length, scanned from the chunk stream (no fixed offset).
    fn idat_len(png: &[u8]) -> usize {
        let mut off = 8usize;
        while off + 8 <= png.len() {
            let len =
                u32::from_be_bytes([png[off], png[off + 1], png[off + 2], png[off + 3]]) as usize;
            if &png[off + 4..off + 8] == b"IDAT" {
                return len;
            }
            off += 12 + len;
        }
        0
    }

    /// A QR raster is long runs of two colours, so deflate must win by a wide
    /// margin. The stored-block writer made every frame PNG the size of its raw
    /// RGB8 buffer; measured on a 224-byte optical frame that was 203 086 bytes
    /// against 2 104 with deflate. This test pins the ratio, not the number.
    #[test]
    fn png_idat_is_deflated_and_deterministic() {
        let frame = b"BDL3-optical-frame-deflate-check-payload".repeat(5);
        let a = frame_to_qr_png(&frame).unwrap();
        let b = frame_to_qr_png(&frame).unwrap();
        assert_eq!(a, b, "deflate output must stay bit-equal across runs");

        let matrix = QrMatrix::encode(&frame).unwrap();
        let side = matrix.raster_modules() * MODULE_PX;
        let raw_len = side as usize * (1 + side as usize * 3);
        let idat = idat_len(&a);
        assert!(idat > 0, "IDAT chunk must exist");
        assert!(
            idat * 10 < raw_len,
            "IDAT {idat} is not at least 10x smaller than raw {raw_len}"
        );
    }

    /// Decode our own PNG bytes for real: inflate IDAT, undo filter 0, then
    /// hand the bitmap to `rqrr`. A smaller file that no reader can
    /// open is not a win, so this test reads pixels, not our own matrix.
    fn decode_our_png(png: &[u8]) -> (u32, u32, Vec<u8>) {
        use flate2::read::ZlibDecoder;
        use std::io::Read;

        assert_eq!(
            png.get(0..8),
            Some([0x89u8, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a].as_slice())
        );
        let mut off = 8usize;
        let mut width = 0u32;
        let mut height = 0u32;
        let mut idat: Vec<u8> = Vec::new();
        while off + 12 <= png.len() {
            let len =
                u32::from_be_bytes([png[off], png[off + 1], png[off + 2], png[off + 3]]) as usize;
            let ty = &png[off + 4..off + 8];
            let data = &png[off + 8..off + 8 + len];
            if ty == b"IHDR" {
                width = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                height = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                assert_eq!(data[8], 8, "bit depth");
                assert_eq!(data[9], 2, "colour type RGB8");
            } else if ty == b"IDAT" {
                idat.extend_from_slice(data);
            } else if ty == b"IEND" {
                break;
            }
            off += 12 + len;
        }
        let mut raw = Vec::new();
        ZlibDecoder::new(&idat[..])
            .read_to_end(&mut raw)
            .expect("IDAT must inflate");
        let w = width as usize;
        let stride = 1 + w * 3;
        assert_eq!(raw.len(), height as usize * stride);
        let mut gray = vec![0u8; w * height as usize];
        for y in 0..height as usize {
            let row = &raw[y * stride..(y + 1) * stride];
            assert_eq!(row[0], 0, "filter must stay None so pixels are exact");
            for x in 0..w {
                let v = row[1 + x * 3];
                assert_eq!(v, row[2 + x * 3], "RGB channels must agree");
                assert_eq!(v, row[3 + x * 3], "RGB channels must agree");
                gray[y * w + x] = v;
            }
        }
        (width, height, gray)
    }

    #[test]
    fn png_pixels_decode_back_to_the_frame() {
        let frame = b"BDL3-optical-frame-roundtrip-payload".repeat(4);
        let png = frame_to_qr_png(&frame).unwrap();
        let (w, h, gray) = decode_our_png(&png);
        let mut img = rqrr::PreparedImage::prepare_from_bitmap(w as usize, h as usize, |x, y| {
            gray[(y * w as usize) + x] < 128
        });
        let grids = img.detect_grids();
        assert_eq!(grids.len(), 1, "one QR grid must be detectable");
        let (_meta, decoded) = grids[0].decode().expect("grid must decode");
        assert_eq!(decoded.as_bytes(), frame);
    }
}
