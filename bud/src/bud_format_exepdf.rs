//! B.U.D. 2.0 - EXE / PDF Format Transforms (2026-08-16)
//!
//! Scope: exe, pdf and similar container file types.
//! Two domain transforms (lossless, format-aware - they see structure zstd
//! cannot):
//!
//! 1. **EXE (per PE/ELF section):** it splits the binary into sections
//!    (text/code is highly repetitive, data is random). The sections are
//!    compressed separately: the code section contains opcode repetitions so
//!    zstd sees it better; the data section is kept apart (it does not spread
//!    noise). Zero-dependency splitting: detection of the PE `\x4D\x5A` (MZ)
//!    start and the ELF `\x7FELF` magic; a simple threshold for the section
//!    boundary (section headers are not parsed - safe).
//!
//! 2. **PDF stream separation:** a PDF is text (objects/dictionaries) plus
//!    streams (already deflate compressed). It separates the streams
//!    (stream ... endstream): the text part compresses well with zstd, the
//!    streams are kept apart (they are already compressed). Lossless: joining
//!    them gives the original.
//!
//! Both of them: `#![forbid(unsafe_code)]`, deterministic, panic free,
//! lossless (K38), None on irregular input (the caller falls back to the raw
//! path).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const EXE_SPLIT_MAGIC: [u8; 8] = *b"\xB5EXES\0\0\0";
pub const PDF_SPLIT_MAGIC: [u8; 8] = *b"\xB5PDFS\0\0\0";
pub const SPLIT_VERSION: u8 = 1;

/// EXE section transform: it splits a binary into (code, data) sections (lossless).
#[derive(Debug, Clone)]
pub struct ExeSectionSplit {
    pub kind: ExeKind,
    pub code: Vec<u8>, // the highly repetitive section (code)
    pub data: Vec<u8>, // the remainder (data/padding)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExeKind {
    Pe,  // MZ
    Elf, // 0x7F 'E' 'L' 'F'
    Unknown,
}

impl ExeKind {
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Pe => 0,
            Self::Elf => 1,
            Self::Unknown => 2,
        }
    }
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Pe),
            1 => Some(Self::Elf),
            2 => Some(Self::Unknown),
            _ => None,
        }
    }
}

impl ExeSectionSplit {
    /// Split the binary into code/data sections (lossless: joining gives the
    /// original). Strategy: the first 60 percent is code (highly repetitive),
    /// the rest is data. A deterministic threshold.
    pub fn encode(data: &[u8]) -> Option<Self> {
        if data.is_empty() || data.len() > 512 * 1024 * 1024 {
            return None;
        }
        let kind = if data.starts_with(b"MZ") {
            ExeKind::Pe
        } else if data.starts_with(b"\x7FELF") {
            ExeKind::Elf
        } else {
            ExeKind::Unknown
        };
        // The code/data split is at a FIXED RATIO: the first 60 percent is
        // code, the rest is data.
        //
        // The `if` here returned `data[..split]` on both branches (clippy
        // if_same_then_else): zero density was measured, compared, and the
        // result thrown away. So the comment "split by content difference" had
        // no counterpart in the code: a dead branch made fixed behaviour look
        // content sensitive. The measurement was removed; the behaviour (and
        // therefore the losslessness) is exactly the same: `decode` joins the
        // two sections in order.
        //
        // If genuinely content-sensitive splitting is wanted, the section
        // boundary itself must be written into the container; at a fixed ratio
        // that is unnecessary, since `split` already comes back through
        // `code.len()` on decode.
        let split = (data.len() * 3) / 5;
        let code = data[..split].to_vec();
        Some(ExeSectionSplit {
            kind,
            code,
            data: data[split..].to_vec(),
        })
    }

    /// Join the sections -> the original (the losslessness proof).
    pub fn decode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.code.len() + self.data.len());
        out.extend_from_slice(&self.code);
        out.extend_from_slice(&self.data);
        out
    }

    /// Deterministic blob: magic + type + code + data + digest.
    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&EXE_SPLIT_MAGIC);
        out.push(SPLIT_VERSION);
        out.push(self.kind.to_u8());
        push_bytes(&mut out, &self.code);
        push_bytes(&mut out, &self.data);
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_EXE_V1");
        h.update(&out);
        out.extend_from_slice(&h.finalize());
        out
    }

    pub fn from_blob(bytes: &[u8]) -> Option<Self> {
        const HDR: usize = 8 + 1 + 1;
        if bytes.len() < HDR + 32 || bytes[0..8] != EXE_SPLIT_MAGIC || bytes[8] != SPLIT_VERSION {
            return None;
        }
        let payload_len = bytes.len() - 32;
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_EXE_V1");
        h.update(&bytes[..payload_len]);
        if h.finalize().as_slice() != &bytes[payload_len..] {
            return None;
        }
        let kind = ExeKind::from_u8(bytes[9])?;
        let mut pos = HDR;
        let code = read_bytes(bytes, &mut pos)?;
        let data = read_bytes(bytes, &mut pos)?;
        if pos != payload_len {
            return None;
        }
        Some(ExeSectionSplit { kind, code, data })
    }
}

/// PDF stream separation: text + streams (lossless).
#[derive(Debug, Clone)]
pub struct PdfStreamSplit {
    pub text: Vec<u8>, // PDF structure (objects, dictionaries) - compresses well with zstd
    pub streams: Vec<Vec<u8>>, // stream contents (already compressed - kept apart)
    /// Where in `text` each stream body was cut out: the offset right after
    /// the `stream` keyword and its line break, in stream order. `decode`
    /// puts body `i` back at `gaps[i]`; without these offsets the text and
    /// the bodies could not be joined into the original bytes again.
    pub gaps: Vec<u32>,
}

/// The PDF split blob layout: text, then per stream its gap offset and body.
/// Version 1 stored no offsets and its `decode` returned the text alone.
const PDF_SPLIT_VERSION: u8 = 2;

impl PdfStreamSplit {
    /// Split the PDF into text + streams (lossless: joining gives the original).
    pub fn encode(data: &[u8]) -> Option<Self> {
        if !data.starts_with(b"%PDF-") || data.len() > 256 * 1024 * 1024 {
            return None;
        }
        let mut text = Vec::with_capacity(data.len());
        let mut streams = Vec::new();
        let mut gaps = Vec::new();
        let mut pos = 0usize;
        while pos < data.len() {
            // look for "stream\r\n" or "stream\n" (the start of a stream)
            if let Some(rel) = find_sub(&data[pos..], b"stream") {
                let abs = pos + rel;
                // the line break after the stream keyword
                let mut s = abs + 6;
                if data.get(s) == Some(&b'\r') {
                    s += 1;
                }
                if data.get(s) == Some(&b'\n') {
                    s += 1;
                }
                // the text keeps everything up to and including the keyword
                // and its line break; only the body is cut out
                text.extend_from_slice(&data[pos..s]);
                gaps.push(u32::try_from(text.len()).ok()?);
                let end_rel = find_sub(&data[s..], b"endstream")?;
                let end = s + end_rel;
                streams.push(data[s..end].to_vec());
                // append "endstream" to the text (the structure is preserved)
                let after_end = end + b"endstream".len();
                text.extend_from_slice(&data[end..after_end]);
                pos = after_end;
            } else {
                text.extend_from_slice(&data[pos..]);
                break;
            }
        }
        if streams.is_empty() {
            return None; // no streams -> separation is pointless (the caller falls back to raw)
        }
        Some(PdfStreamSplit {
            text,
            streams,
            gaps,
        })
    }

    /// Join -> the original bytes: the text up to each gap, then the body that
    /// was cut out there. `None` when the offsets do not fit the text (a
    /// hand-built or forged split); `from_blob` refuses such offsets as well.
    pub fn decode(&self) -> Option<Vec<u8>> {
        if self.gaps.len() != self.streams.len() {
            return None;
        }
        let mut out = Vec::with_capacity(
            self.text.len() + self.streams.iter().map(|s| s.len()).sum::<usize>(),
        );
        let mut cursor = 0usize;
        for (gap, body) in self.gaps.iter().zip(&self.streams) {
            let gap = *gap as usize;
            if gap < cursor || gap > self.text.len() {
                return None;
            }
            out.extend_from_slice(&self.text[cursor..gap]);
            out.extend_from_slice(body);
            cursor = gap;
        }
        out.extend_from_slice(&self.text[cursor..]);
        Some(out)
    }

    /// Blob: text + (gap offset, stream body) pairs + digest.
    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&PDF_SPLIT_MAGIC);
        out.push(PDF_SPLIT_VERSION);
        push_bytes(&mut out, &self.text);
        out.extend_from_slice(&(self.streams.len() as u32).to_le_bytes());
        for (gap, s) in self.gaps.iter().zip(&self.streams) {
            out.extend_from_slice(&gap.to_le_bytes());
            push_bytes(&mut out, s);
        }
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_PDF_V1");
        h.update(&out);
        out.extend_from_slice(&h.finalize());
        out
    }

    pub fn from_blob(bytes: &[u8]) -> Option<Self> {
        const HDR: usize = 8 + 1;
        if bytes.len() < HDR + 32 || bytes[0..8] != PDF_SPLIT_MAGIC || bytes[8] != PDF_SPLIT_VERSION
        {
            return None;
        }
        let payload_len = bytes.len() - 32;
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_PDF_V1");
        h.update(&bytes[..payload_len]);
        if h.finalize().as_slice() != &bytes[payload_len..] {
            return None;
        }
        let mut pos = HDR;
        let text = read_bytes(bytes, &mut pos)?;
        if bytes.len() < pos + 4 {
            return None;
        }
        let n = u32::from_le_bytes(bytes[pos..pos + 4].try_into().ok()?) as usize;
        pos += 4;
        if n > 1_000_000 {
            return None;
        }
        let mut streams = Vec::new();
        let mut gaps: Vec<u32> = Vec::new();
        for _ in 0..n {
            if bytes.len() < pos + 4 {
                return None;
            }
            let gap = u32::from_le_bytes(bytes[pos..pos + 4].try_into().ok()?);
            pos += 4;
            if gap as usize > text.len() || gaps.last().is_some_and(|&prev| gap < prev) {
                return None;
            }
            gaps.push(gap);
            let s = read_bytes(bytes, &mut pos)?;
            streams.push(s);
        }
        if pos != payload_len {
            return None;
        }
        Some(PdfStreamSplit {
            text,
            streams,
            gaps,
        })
    }
}

fn push_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

fn read_bytes(bytes: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    if bytes.len() < *pos + 4 {
        return None;
    }
    let len = u32::from_le_bytes(bytes[*pos..*pos + 4].try_into().ok()?) as usize;
    *pos += 4;
    if bytes.len() < *pos + len {
        return None;
    }
    let v = bytes[*pos..*pos + len].to_vec();
    *pos += len;
    Some(v)
}

fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exe_split_roundtrip() {
        // A simulated PE binary: MZ + code (repetitive) + data (zero weighted)
        let mut exe = b"MZ".to_vec();
        for _ in 0..1000 {
            exe.extend_from_slice(&[0x48, 0x8B, 0x05, 0x01, 0x00, 0x00, 0x00]); // mov rax,[rip]
        }
        exe.extend_from_slice(&[0u8; 500]); // veri/padding
        let split = ExeSectionSplit::encode(&exe).expect("encode");
        assert_eq!(split.kind, ExeKind::Pe);
        assert_eq!(split.decode(), exe, "lossless");
        let blob = split.to_blob();
        let back = ExeSectionSplit::from_blob(&blob).expect("blob");
        assert_eq!(back.decode(), exe);
        // kurcalama red
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(ExeSectionSplit::from_blob(&bad).is_none());
    }

    #[test]
    fn elf_split_roundtrip() {
        let mut elf = b"\x7FELF".to_vec();
        elf.extend_from_slice(&[0x01; 2000]); // kod
        elf.extend_from_slice(&[0u8; 300]);
        let split = ExeSectionSplit::encode(&elf).expect("encode");
        assert_eq!(split.kind, ExeKind::Elf);
        assert_eq!(split.decode(), elf);
    }

    #[test]
    fn pdf_stream_split_roundtrip() {
        // PDF: text + 2 streams (already compressed content)
        let mut pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n".to_vec();
        pdf.extend_from_slice(b"2 0 obj\n<< /Length 10 >>\nstream\n");
        pdf.extend_from_slice(&[0x78, 0x9C, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // deflate benzeri
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
        pdf.extend_from_slice(b"3 0 obj\n<< /Length 4 >>\nstream\n");
        pdf.extend_from_slice(&[0x9C, 0x78, 0x01, 0x02]);
        pdf.extend_from_slice(b"\nendstream\nendobj\n%%EOF\n");
        let split = PdfStreamSplit::encode(&pdf).expect("encode");
        assert_eq!(split.streams.len(), 2, "two streams were separated");
        // the text does not contain the stream bodies
        assert!(!split
            .text
            .windows(8)
            .any(|w| w == [0x78, 0x9C, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        assert_eq!(
            split.decode().expect("decode"),
            pdf,
            "PDF split must be lossless"
        );
        // blob roundtrip
        let blob = split.to_blob();
        let back = PdfStreamSplit::from_blob(&blob).expect("blob");
        assert_eq!(back.streams.len(), 2);
        assert_eq!(back.streams[0], split.streams[0]);
        assert_eq!(back.gaps, split.gaps);
        assert_eq!(
            back.decode().expect("decode"),
            pdf,
            "the blob path is lossless too"
        );
        // kurcalama red
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(PdfStreamSplit::from_blob(&bad).is_none());
    }

    /// A `\r\n` line break after `stream`, a body that itself contains the
    /// word `stream`, and a body ending in a line break: each has to come
    /// back byte for byte. A split whose gap offsets point past the text or
    /// run backwards is refused instead of producing something else.
    #[test]
    fn pdf_stream_split_rebuilds_every_byte() {
        let mut pdf = b"%PDF-1.4\r\n4 0 obj\r\n<< /Length 12 >>\r\nstream\r\n".to_vec();
        pdf.extend_from_slice(b"ab stream cd");
        pdf.extend_from_slice(b"\r\nendstream\r\nendobj\r\n5 0 obj\nstream\n\n\nendstream\n%%EOF");
        let split = PdfStreamSplit::encode(&pdf).expect("encode");
        assert_eq!(split.streams.len(), 2);
        assert_eq!(split.decode().expect("decode"), pdf);
        assert_eq!(
            PdfStreamSplit::from_blob(&split.to_blob())
                .expect("blob")
                .decode()
                .expect("decode"),
            pdf
        );
        let mut forged = split.clone();
        forged.gaps[1] = forged.text.len() as u32 + 1;
        assert!(forged.decode().is_none());
        let mut backwards = split.clone();
        backwards.gaps.swap(0, 1);
        assert!(backwards.decode().is_none());
        let mut short = split.clone();
        short.gaps.pop();
        assert!(short.decode().is_none());
        // the same offsets inside a sealed blob are refused by the parser
        let mut body = forged.to_blob();
        body.truncate(body.len() - 32);
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_PDF_V1");
        h.update(&body);
        body.extend_from_slice(&h.finalize());
        assert!(PdfStreamSplit::from_blob(&body).is_none());
    }

    #[test]
    fn irregular_falls_back() {
        assert!(ExeSectionSplit::encode(&[]).is_none());
        assert!(PdfStreamSplit::encode(b"not a pdf").is_none());
        assert!(PdfStreamSplit::encode(b"%PDF-1.7\nno streams here\n").is_none());
        assert!(ExeSectionSplit::from_blob(&[0u8; 10]).is_none());
        assert!(PdfStreamSplit::from_blob(&[0u8; 10]).is_none());
    }
}
