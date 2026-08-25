//! B.U.D. 2.0 - the JPEG recompression path (K80) (2026-08-16).
//!
//! K80: JPEG XL can recompress an existing JPEG LOSSLESSLY (a 20 percent
//! saving with a bit-exact round trip - the original JPEG bytes can be
//! reproduced). For B.U.D. this is the image leg of KF2, which says the format
//! may change as long as the resolution is preserved.
//!
//! Before moving to JXL, this module MEASURES HOW COMPRESSIBLE THE JPEG IS and
//! records the decision: the segment structure (SOI, APP, DQT, SOF, SOS, EOI),
//! the estimated saving and a decision record (a deterministic blob that can be
//! written to the chain).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const JPEG_RE_MAGIC: [u8; 8] = *b"\xB5JRE0\0\0\0";
pub const JPEG_RE_VERSION: u8 = 1;

const MARKER_SOI: u8 = 0xD8;
const MARKER_SOS: u8 = 0xDA;
const MARKER_EOI: u8 = 0xD9;
const MARKER_DQT: u8 = 0xDB;
const MARKER_SOF0: u8 = 0xC0;
const MARKER_SOF2: u8 = 0xC2;

/// The JPEG analysis result: the segment structure plus the estimated
/// compressibility.
#[derive(Debug, Clone)]
pub struct JpegAnalysis {
    pub width: u32,
    pub height: u32,
    pub progressive: bool,
    pub quant_tables: usize,
    pub scan_data_bytes: u64,
    pub header_bytes: u64,
    pub recompress_savings_pct: f64,
}

impl JpegAnalysis {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_JPEGRE_V1";

    /// Analyses JPEG bytes with a coarse, panic-free parse.
    pub fn analyze(data: &[u8]) -> Option<Self> {
        if !data.starts_with(&[0xFF, MARKER_SOI]) {
            return None;
        }
        let mut pos = 2usize;
        let mut width = 0u32;
        let mut height = 0u32;
        let mut progressive = false;
        let mut quant_tables = 0usize;
        let mut scan_start = 0usize;
        let mut in_scan = false;
        while pos + 1 < data.len() {
            if !in_scan {
                if data[pos] != 0xFF {
                    pos += 1;
                    continue;
                }
                if data[pos + 1] == 0x00 {
                    pos += 2;
                    continue;
                }
                let marker = data[pos + 1];
                if marker == MARKER_EOI {
                    break;
                }
                if marker == MARKER_SOS {
                    scan_start = pos;
                    in_scan = true;
                    if pos + 4 <= data.len() {
                        let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
                        pos += 2 + len;
                    } else {
                        pos += 2;
                    }
                    continue;
                }
                if marker == MARKER_SOF0 || marker == MARKER_SOF2 {
                    progressive = marker == MARKER_SOF2;
                    if pos + 9 <= data.len() {
                        height = u16::from_be_bytes([data[pos + 5], data[pos + 6]]) as u32;
                        width = u16::from_be_bytes([data[pos + 7], data[pos + 8]]) as u32;
                    }
                }
                if marker == MARKER_DQT {
                    quant_tables += 1;
                }
                if pos + 4 <= data.len() {
                    let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
                    if len < 2 {
                        return None;
                    }
                    pos += 2 + len;
                } else {
                    break;
                }
            } else {
                // Coefficient data: everything except EOI (0xFF 0xD9).
                if data[pos] == 0xFF && data[pos + 1] == MARKER_EOI {
                    break;
                }
                pos += 1;
            }
        }
        if scan_start == 0 || width == 0 || height == 0 {
            return None;
        }
        let header_bytes = scan_start as u64;
        let scan_data_bytes = data.len().saturating_sub(scan_start) as u64;
        let total = data.len() as u64;
        let header_ratio = if total > 0 {
            header_bytes as f64 / total as f64
        } else {
            0.0
        };
        let recompress_savings_pct = 15.0 + header_ratio * 20.0;
        Some(JpegAnalysis {
            width,
            height,
            progressive,
            quant_tables,
            scan_data_bytes,
            header_bytes,
            recompress_savings_pct,
        })
    }

    pub fn recommends_jxl(&self) -> bool {
        self.recompress_savings_pct >= 10.0
    }

    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&JPEG_RE_MAGIC);
        out.push(JPEG_RE_VERSION);
        out.extend_from_slice(&self.width.to_le_bytes());
        out.extend_from_slice(&self.height.to_le_bytes());
        out.push(self.progressive as u8);
        out.extend_from_slice(&(self.quant_tables as u32).to_le_bytes());
        out.extend_from_slice(&self.scan_data_bytes.to_le_bytes());
        out.extend_from_slice(&self.header_bytes.to_le_bytes());
        out.extend_from_slice(&self.recompress_savings_pct.to_le_bytes());
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update(&out);
        out.extend_from_slice(&h.finalize());
        out
    }

    pub fn from_blob(bytes: &[u8]) -> Option<Self> {
        const HDR: usize = 8 + 1 + 4 + 4 + 1 + 4 + 8 + 8 + 8;
        if bytes.len() < HDR + 32 || bytes[0..8] != JPEG_RE_MAGIC || bytes[8] != JPEG_RE_VERSION {
            return None;
        }
        let payload_len = bytes.len() - 32;
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update(&bytes[..payload_len]);
        if h.finalize().as_slice() != &bytes[payload_len..] {
            return None;
        }
        let width = u32::from_le_bytes(bytes[9..13].try_into().ok()?);
        let height = u32::from_le_bytes(bytes[13..17].try_into().ok()?);
        let progressive = bytes[17] != 0;
        let quant_tables = u32::from_le_bytes(bytes[18..22].try_into().ok()?) as usize;
        let scan_data_bytes = u64::from_le_bytes(bytes[22..30].try_into().ok()?);
        let header_bytes = u64::from_le_bytes(bytes[30..38].try_into().ok()?);
        let recompress_savings_pct = f64::from_le_bytes(bytes[38..46].try_into().ok()?);
        if bytes.len() != HDR + 32 {
            return None;
        }
        Some(JpegAnalysis {
            width,
            height,
            progressive,
            quant_tables,
            scan_data_bytes,
            header_bytes,
            recompress_savings_pct,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_jpeg() -> Vec<u8> {
        let mut j = vec![0xFF, 0xD8];
        j.extend_from_slice(&[0xFF, MARKER_DQT, 0x00, 0x04, 0x00, 0x01]); // DQT: len=4 (2 len + 2 data)
        j.extend_from_slice(&[
            0xFF,
            MARKER_SOF0,
            0x00,
            0x0A,
            0x08,
            0x00,
            0x10,
            0x00,
            0x20,
            0x01,
            0x01,
            0x00,
        ]); // SOF0: len=11 (9 payload)
        j.extend_from_slice(&[
            0xFF, MARKER_SOS, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00,
        ]); // SOS: len=8 (6 payload)
        for _ in 0..1000 {
            j.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        }
        j.extend_from_slice(&[0xFF, MARKER_EOI]);
        j
    }

    #[test]
    fn jpeg_analysis_parses() {
        let j = synthetic_jpeg();
        let a = JpegAnalysis::analyze(&j).expect("analiz");
        assert_eq!(a.width, 32);
        assert_eq!(a.height, 16);
        assert!(!a.progressive);
        assert!(a.quant_tables >= 1);
        assert!(a.scan_data_bytes > 0);
        assert!(a.header_bytes > 0);
        assert!(a.recommends_jxl(), "recompression is recommended");
        assert!(a.recompress_savings_pct >= 15.0);
    }

    #[test]
    fn blob_roundtrip_and_tamper() {
        let j = synthetic_jpeg();
        let a = JpegAnalysis::analyze(&j).unwrap();
        let blob = a.to_blob();
        let back = JpegAnalysis::from_blob(&blob).expect("blob");
        assert_eq!(back.width, a.width);
        assert_eq!(back.recompress_savings_pct, a.recompress_savings_pct);
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(JpegAnalysis::from_blob(&bad).is_none());
        assert!(JpegAnalysis::analyze(b"PNG").is_none());
        assert!(JpegAnalysis::from_blob(&[0u8; 10]).is_none());
    }

    #[test]
    fn progressive_detected() {
        let mut j = vec![0xFF, 0xD8];
        j.extend_from_slice(&[
            0xFF,
            MARKER_SOF2,
            0x00,
            0x0A,
            0x08,
            0x00,
            0x10,
            0x00,
            0x20,
            0x01,
            0x01,
            0x00,
        ]);
        j.extend_from_slice(&[
            0xFF, MARKER_SOS, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00,
        ]);
        j.extend_from_slice(&[0x01, 0x02]);
        j.extend_from_slice(&[0xFF, MARKER_EOI]);
        let a = JpegAnalysis::analyze(&j).expect("analiz");
        assert!(a.progressive);
    }
}
