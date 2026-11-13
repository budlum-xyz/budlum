//! Pure-Rust lossless codec transforms and decoders for B.U.D. 3.0 codecs `2..=8` and `10..=26`.
//!
//! Every codec frames its transformed stream with an explicit versioned header tag
//! equal to its [`CodecId`] byte, enforces the caller-supplied `content_len` ceiling
//! (capped at [`crate::MAX_CODEC_DECODE_BYTES`]) before allocating output, and verifies
//! exact byte-for-byte length match after decoding.

use std::io::Write;

use crate::registry::shared_context::{
    decode_fp32_exponent_split, decode_timeseries_delta_xor, encode_fp32_exponent_split,
    encode_timeseries_delta_xor,
};
use crate::{
    decode, CodecError, CodecId, MAX_CODEC_DECODE_BYTES, PROBE_LEVEL, STORE_LEVEL, ZSTD,
    ZSTD_WINDOW_LOG,
};

/// LZMA2-equivalent sliding-window LZ77 + entropy frame.
const LZMA2: CodecId = 2;
/// Small-object dictionary zstd (`<= 16 KiB` optimized).
const DICT_ZSTD: CodecId = 3;
/// Columnar JSON record transpose + zstd.
const COLUMNAR_JSON: CodecId = 4;
/// JPEG scan/segment predictor + zstd.
const LEPTON_JPEG: CodecId = 5;
/// DEFLATE stream unpacker/predictor + entropy coder.
const PREFLATE: CodecId = 6;
/// PCM WAV / AIFF header + channel delta predictor + zstd.
const LOSSLESS_AUDIO: CodecId = 7;
/// Pure-Rust adaptive Order-1 bit-level arithmetic range coder.
const CONTEXT_MIX: CodecId = 8;
/// Region derivation delta against repeated slices + zstd.
const DERIVATION: CodecId = 10;
/// Content-defined chunked version delta + zstd.
const VERSION_DELTA: CodecId = 11;
/// Shared corpus dictionary fast LZ + zstd.
const LZ_CONTEXT: CodecId = 12;
/// Archival finite-state context machine + zstd.
const CONTEXT_MACHINE: CodecId = 13;
/// Log field (nginx/syslog) whitespace/token columnar split + zstd.
const LOG_COLUMNAR: CodecId = 14;
/// Time series `(u64, u64)` delta + XOR + zstd.
const TIME_SERIES: CodecId = 15;
/// Append-only WAL record columnar split + zstd.
const WAL_COLUMNAR: CodecId = 16;
/// Libpcap capture header/record split + zstd.
const PCAP_COLUMNAR: CodecId = 17;
/// Page-aligned XOR delta + zstd.
const PAGE_XOR_DELTA: CodecId = 18;
/// FP32 / BF16 exponent + sign/mantissa split + zstd.
const FLOAT_SPLIT: CodecId = 19;
/// Executable PE/ELF section & branch-target transform + zstd.
const EXE_SPLIT: CodecId = 20;
/// PDF stream/object boundary split + zstd.
const PDF_SPLIT: CodecId = 21;
/// Markdown ATX heading / body stream split + zstd.
const MARKDOWN_SPLIT: CodecId = 22;
/// FASTA / FASTQ 2-bit DNA base packing + zstd.
const GENOMIC: CodecId = 23;
/// Office OPC ZIP local-header + payload split + zstd.
const OFFICE_OPC: CodecId = 24;
/// Point cloud 24-byte coordinate transpose + residual + zstd.
const POINT_CLOUD: CodecId = 25;
/// Lossless raw pixel BMP / TIFF stride predictor + zstd.
const LOSSLESS_IMAGE: CodecId = 26;

const fn tag_byte(codec: CodecId) -> u8 {
    codec as u8
}

fn zstd_compress_with(bytes: &[u8], level: i32, long_range: bool) -> Result<Vec<u8>, CodecError> {
    let mut enc = zstd::stream::Encoder::new(Vec::new(), level)
        .map_err(|e| CodecError::Encode(e.to_string()))?;
    if long_range {
        enc.long_distance_matching(true)
            .map_err(|e| CodecError::Encode(e.to_string()))?;
        enc.window_log(ZSTD_WINDOW_LOG)
            .map_err(|e| CodecError::Encode(e.to_string()))?;
    }
    enc.include_checksum(false)
        .map_err(|e| CodecError::Encode(e.to_string()))?;
    enc.write_all(bytes)
        .map_err(|e| CodecError::Encode(e.to_string()))?;
    enc.finish().map_err(|e| CodecError::Encode(e.to_string()))
}

fn wrap_tagged_zstd(
    codec: CodecId,
    mode: u8,
    transformed: &[u8],
    level: i32,
    long_range: bool,
) -> Result<Vec<u8>, CodecError> {
    let raw_len = u32::try_from(transformed.len())
        .map_err(|_| CodecError::Encode(String::from("transformed stream exceeds u32")))?;
    let comp = zstd_compress_with(transformed, level, long_range)?;
    let mut out = Vec::with_capacity(6 + comp.len());
    out.push(tag_byte(codec));
    out.push(mode);
    out.extend_from_slice(&raw_len.to_le_bytes());
    out.extend_from_slice(&comp);
    Ok(out)
}

fn unwrap_tagged_zstd(
    expected_codec: CodecId,
    payload: &[u8],
    max_decoded_bytes: u64,
) -> Result<(u8, Vec<u8>), CodecError> {
    let hdr = payload
        .get(..6)
        .ok_or_else(|| CodecError::Malformed(String::from("truncated codec header")))?;
    let got_tag = *hdr
        .first()
        .ok_or_else(|| CodecError::Malformed(String::from("missing codec tag")))?;
    if got_tag != tag_byte(expected_codec) {
        return Err(CodecError::Malformed(String::from("codec tag mismatch")));
    }
    let mode = *hdr
        .get(1)
        .ok_or_else(|| CodecError::Malformed(String::from("missing codec mode")))?;
    let len_slice = hdr
        .get(2..6)
        .ok_or_else(|| CodecError::Malformed(String::from("missing codec length")))?;
    let mut len_arr = [0u8; 4];
    len_arr.copy_from_slice(len_slice);
    let raw_len = u64::from(u32::from_le_bytes(len_arr));
    let hard_cap = max_decoded_bytes
        .saturating_mul(2)
        .saturating_add(4096)
        .min(MAX_CODEC_DECODE_BYTES);
    if raw_len > hard_cap {
        return Err(CodecError::TooLong {
            max: max_decoded_bytes,
        });
    }
    let comp = payload.get(6..).unwrap_or(&[]);
    let decoded = decode(ZSTD, comp, raw_len)?;
    Ok((mode, decoded))
}

fn write_u32_le(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_le_bytes());
}

fn read_u32_le(buf: &[u8], pos: &mut usize) -> Result<u32, CodecError> {
    let end = pos
        .checked_add(4)
        .ok_or_else(|| CodecError::Malformed(String::from("u32 offset overflow")))?;
    let slice = buf
        .get(*pos..end)
        .ok_or_else(|| CodecError::Malformed(String::from("truncated u32")))?;
    let mut arr = [0u8; 4];
    arr.copy_from_slice(slice);
    *pos = end;
    Ok(u32::from_le_bytes(arr))
}

fn read_u16_le(buf: &[u8], pos: &mut usize) -> Result<u16, CodecError> {
    let end = pos
        .checked_add(2)
        .ok_or_else(|| CodecError::Malformed(String::from("u16 offset overflow")))?;
    let slice = buf
        .get(*pos..end)
        .ok_or_else(|| CodecError::Malformed(String::from("truncated u16")))?;
    let mut arr = [0u8; 2];
    arr.copy_from_slice(slice);
    *pos = end;
    Ok(u16::from_le_bytes(arr))
}

fn encode_lz77_tokens(content: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::with_capacity(content.len().saturating_add(16));
    let mut lit_buf = Vec::new();
    let mut cursor = 0usize;
    let flush_lit = |dst: &mut Vec<u8>, literals: &mut Vec<u8>| -> Result<(), CodecError> {
        if literals.is_empty() {
            return Ok(());
        }
        let len = u16::try_from(literals.len())
            .map_err(|_| CodecError::Encode(String::from("literal run overflow")))?;
        dst.push(0x00);
        dst.extend_from_slice(&len.to_le_bytes());
        dst.extend_from_slice(literals);
        literals.clear();
        Ok(())
    };
    while cursor < content.len() {
        let win_start = cursor.saturating_sub(4096);
        let mut best_off = 0usize;
        let mut best_len = 0usize;
        if cursor > 0 && cursor + 4 <= content.len() {
            let pat = content.get(cursor..cursor + 4).unwrap_or(&[]);
            let mut probe = cursor - 1;
            let mut steps = 0usize;
            while probe >= win_start && steps < 64 {
                if content.get(probe..probe + 4) == Some(pat) {
                    let max_m = (content.len() - cursor).min(255);
                    let mut m = 4usize;
                    while m < max_m && content.get(probe + m) == content.get(cursor + m) {
                        m += 1;
                    }
                    if m > best_len {
                        best_len = m;
                        best_off = cursor - probe;
                        if best_len == 255 {
                            break;
                        }
                    }
                }
                if probe == 0 {
                    break;
                }
                probe -= 1;
                steps += 1;
            }
        }
        if best_len >= 4 {
            flush_lit(&mut out, &mut lit_buf)?;
            let off_u16 = u16::try_from(best_off)
                .map_err(|_| CodecError::Encode(String::from("lz offset overflow")))?;
            let len_u8 = u8::try_from(best_len)
                .map_err(|_| CodecError::Encode(String::from("lz match length overflow")))?;
            out.push(0x01);
            out.extend_from_slice(&off_u16.to_le_bytes());
            out.push(len_u8);
            cursor += best_len;
        } else if let Some(&b) = content.get(cursor) {
            lit_buf.push(b);
            if lit_buf.len() == usize::from(u16::MAX) {
                flush_lit(&mut out, &mut lit_buf)?;
            }
            cursor += 1;
        } else {
            break;
        }
    }
    flush_lit(&mut out, &mut lit_buf)?;
    Ok(out)
}

fn decode_lz77_tokens(tokens: &[u8], content_len: u64) -> Result<Vec<u8>, CodecError> {
    let want =
        usize::try_from(content_len).map_err(|_| CodecError::TooLong { max: content_len })?;
    let mut out = Vec::with_capacity(want.min(1 << 20));
    let mut pos = 0usize;
    while pos < tokens.len() {
        let tag = *tokens
            .get(pos)
            .ok_or_else(|| CodecError::Malformed(String::from("truncated lz tag")))?;
        pos += 1;
        match tag {
            0x00 => {
                let len = usize::from(read_u16_le(tokens, &mut pos)?);
                let end = pos
                    .checked_add(len)
                    .ok_or_else(|| CodecError::Malformed(String::from("lit offset overflow")))?;
                let slice = tokens
                    .get(pos..end)
                    .ok_or_else(|| CodecError::Malformed(String::from("truncated lz lit")))?;
                if out.len().saturating_add(len) > want {
                    return Err(CodecError::TooLong { max: content_len });
                }
                out.extend_from_slice(slice);
                pos = end;
            }
            0x01 => {
                let off = usize::from(read_u16_le(tokens, &mut pos)?);
                let mlen = usize::from(
                    *tokens
                        .get(pos)
                        .ok_or_else(|| CodecError::Malformed(String::from("truncated lz len")))?,
                );
                pos += 1;
                if off == 0 || off > out.len() || mlen == 0 {
                    return Err(CodecError::Malformed(String::from("invalid lz back-ref")));
                }
                if out.len().saturating_add(mlen) > want {
                    return Err(CodecError::TooLong { max: content_len });
                }
                for _ in 0..mlen {
                    let src_idx = out.len() - off;
                    let byte = *out
                        .get(src_idx)
                        .ok_or_else(|| CodecError::Malformed(String::from("bad back-ref")))?;
                    out.push(byte);
                }
            }
            _ => return Err(CodecError::Malformed(String::from("unknown lz token"))),
        }
    }
    Ok(out)
}

/// Pure-Rust adaptive Order-1 bit-level arithmetic range coder (`Codec 8`).
mod range_coder {
    use super::*;

    const TOP: u32 = 1 << 24;

    struct BitModels {
        probs: Vec<u16>,
    }

    impl BitModels {
        fn new() -> Self {
            Self {
                probs: vec![2048u16; 256 * 256],
            }
        }

        fn prob(&self, prev: u8, ctx: usize) -> u16 {
            let idx = (usize::from(prev) << 8) | (ctx & 0xFF);
            self.probs.get(idx).copied().unwrap_or(2048)
        }

        fn update(&mut self, prev: u8, ctx: usize, bit: u32) {
            let idx = (usize::from(prev) << 8) | (ctx & 0xFF);
            if let Some(p) = self.probs.get_mut(idx) {
                let cur = u32::from(*p);
                let next = if bit == 0 {
                    cur + ((4096 - cur) >> 5)
                } else {
                    cur - (cur >> 5)
                };
                *p = u16::try_from(next.clamp(1, 4095)).unwrap_or(2048);
            }
        }
    }

    pub(super) fn encode(content: &[u8]) -> Result<Vec<u8>, CodecError> {
        let len_u32 = u32::try_from(content.len())
            .map_err(|_| CodecError::Encode(String::from("content exceeds u32")))?;
        let mut out = Vec::with_capacity(content.len().saturating_add(16));
        out.push(tag_byte(CONTEXT_MIX));
        out.extend_from_slice(&len_u32.to_le_bytes());

        let mut models = BitModels::new();
        let mut low = 0u64;
        let mut range = u64::from(u32::MAX);
        let mut prev = 0u8;

        for &byte in content {
            let mut ctx = 1usize;
            for bit_pos in (0..8).rev() {
                let bit = u32::from((byte >> bit_pos) & 1);
                let p = u64::from(models.prob(prev, ctx));
                let mid = (range >> 12) * p;
                if bit == 0 {
                    range = mid;
                } else {
                    low += mid;
                    range -= mid;
                }
                while (low ^ (low + range)) < u64::from(TOP)
                    || (range < u64::from(TOP)
                        && ((low.wrapping_neg()) & u64::from(TOP - 1)) < range)
                {
                    if (low ^ (low + range)) >= u64::from(TOP) {
                        range = low.wrapping_neg() & u64::from(TOP - 1);
                    }
                    let out_b = u8::try_from((low >> 24) & 0xFF).unwrap_or(0);
                    out.push(out_b);
                    range <<= 8;
                    low = (low << 8) & u64::from(u32::MAX);
                }
                models.update(prev, ctx, bit);
                ctx = (ctx << 1) | usize::try_from(bit).unwrap_or(0);
            }
            prev = byte;
        }
        for _ in 0..4 {
            let out_b = u8::try_from((low >> 24) & 0xFF).unwrap_or(0);
            out.push(out_b);
            low = (low << 8) & u64::from(u32::MAX);
        }
        Ok(out)
    }

    pub(super) fn decode(payload: &[u8], content_len: u64) -> Result<Vec<u8>, CodecError> {
        let hdr = payload
            .get(..5)
            .ok_or_else(|| CodecError::Malformed(String::from("truncated Codec 8 header")))?;
        if hdr.first().copied() != Some(tag_byte(CONTEXT_MIX)) {
            return Err(CodecError::Malformed(String::from("Codec 8 tag mismatch")));
        }
        let mut len_arr = [0u8; 4];
        if let Some(s) = hdr.get(1..5) {
            len_arr.copy_from_slice(s);
        }
        let encoded_len = u64::from(u32::from_le_bytes(len_arr));
        if encoded_len > content_len {
            return Err(CodecError::TooLong { max: content_len });
        }
        if encoded_len < content_len {
            return Err(CodecError::TooShort {
                want: content_len,
                got: encoded_len,
            });
        }
        let want =
            usize::try_from(content_len).map_err(|_| CodecError::TooLong { max: content_len })?;
        let mut pos = 5usize;
        let mut code = 0u64;
        for _ in 0..4 {
            let b = payload.get(pos).copied().unwrap_or(0);
            pos += 1;
            code = (code << 8) | u64::from(b);
        }

        let mut models = BitModels::new();
        let mut low = 0u64;
        let mut range = u64::from(u32::MAX);
        let mut prev = 0u8;
        let mut out = Vec::with_capacity(want.min(1 << 20));

        for _ in 0..want {
            let mut ctx = 1usize;
            let mut val = 0u8;
            for bit_pos in (0..8).rev() {
                let p = u64::from(models.prob(prev, ctx));
                let mid = (range >> 12) * p;
                let thresh = low + mid;
                let bit = if code < thresh {
                    range = mid;
                    0u32
                } else {
                    low = thresh;
                    range -= mid;
                    1u32
                };
                while (low ^ (low + range)) < u64::from(TOP)
                    || (range < u64::from(TOP)
                        && ((low.wrapping_neg()) & u64::from(TOP - 1)) < range)
                {
                    if (low ^ (low + range)) >= u64::from(TOP) {
                        range = low.wrapping_neg() & u64::from(TOP - 1);
                    }
                    let next_b = payload.get(pos).copied().unwrap_or(0);
                    pos += 1;
                    code = ((code << 8) | u64::from(next_b)) & u64::from(u32::MAX);
                    range <<= 8;
                    low = (low << 8) & u64::from(u32::MAX);
                }
                models.update(prev, ctx, bit);
                ctx = (ctx << 1) | usize::try_from(bit).unwrap_or(0);
                if bit == 1 {
                    val |= 1u8 << bit_pos;
                }
            }
            out.push(val);
            prev = val;
        }
        Ok(out)
    }
}

fn xor_neighbor_encode(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len());
    let mut prev = 0u8;
    for &b in content {
        out.push(b ^ prev);
        prev = b;
    }
    out
}

fn xor_neighbor_decode(encoded: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(encoded.len());
    let mut prev = 0u8;
    for &d in encoded {
        let orig = d ^ prev;
        out.push(orig);
        prev = orig;
    }
    out
}

fn stride_delta_encode(content: &[u8], stride: usize) -> Vec<u8> {
    if content.len() < stride || stride == 0 {
        return xor_neighbor_encode(content);
    }
    let mut out = Vec::with_capacity(content.len());
    for (idx, &b) in content.iter().enumerate() {
        let pred = idx
            .checked_sub(stride)
            .and_then(|p| content.get(p))
            .copied()
            .unwrap_or(0);
        out.push(b.wrapping_sub(pred));
    }
    out
}

fn stride_delta_decode(encoded: &[u8], stride: usize) -> Vec<u8> {
    if encoded.len() < stride || stride == 0 {
        return xor_neighbor_decode(encoded);
    }
    let mut out = Vec::with_capacity(encoded.len());
    for (idx, &d) in encoded.iter().enumerate() {
        let pred = idx
            .checked_sub(stride)
            .and_then(|p| out.get(p))
            .copied()
            .unwrap_or(0);
        out.push(d.wrapping_add(pred));
    }
    out
}

fn columnar_lines_encode(content: &[u8], sep: u8) -> Vec<u8> {
    let lines: Vec<&[u8]> = content.split(|&b| b == sep).collect();
    if lines.len() <= 1 {
        return content.to_vec();
    }
    let max_cols = lines.iter().map(|l| l.len()).max().unwrap_or(0);
    let mut out = Vec::with_capacity(content.len().saturating_add(lines.len() * 4 + 8));
    write_u32_le(&mut out, u32::try_from(lines.len()).unwrap_or(u32::MAX));
    for l in &lines {
        write_u32_le(&mut out, u32::try_from(l.len()).unwrap_or(u32::MAX));
    }
    for col in 0..max_cols {
        for line in &lines {
            if let Some(&b) = line.get(col) {
                out.push(b);
            }
        }
    }
    out
}

fn columnar_lines_decode(encoded: &[u8], sep: u8, content_len: u64) -> Result<Vec<u8>, CodecError> {
    if encoded.len() < 4 {
        return Ok(encoded.to_vec());
    }
    let mut pos = 0usize;
    let count = usize::try_from(read_u32_le(encoded, &mut pos)?)
        .map_err(|_| CodecError::Malformed(String::from("line count overflow")))?;
    let max_lines = usize::try_from(content_len.saturating_add(1))
        .unwrap_or(usize::MAX)
        .min(1 << 22);
    if count > max_lines {
        return Err(CodecError::TooLong { max: content_len });
    }
    let mut lens = Vec::with_capacity(count.min(65_536));
    let mut total_chars = 0usize;
    for _ in 0..count {
        let l = usize::try_from(read_u32_le(encoded, &mut pos)?)
            .map_err(|_| CodecError::Malformed(String::from("line len overflow")))?;
        total_chars = total_chars
            .checked_add(l)
            .ok_or(CodecError::TooLong { max: content_len })?;
        if u64::try_from(total_chars).unwrap_or(u64::MAX) > content_len {
            return Err(CodecError::TooLong { max: content_len });
        }
        lens.push(l);
    }
    let body = encoded.get(pos..).unwrap_or(&[]);
    if body.len() != total_chars {
        return Err(CodecError::Malformed(String::from(
            "columnar body len mismatch",
        )));
    }
    let mut lines: Vec<Vec<u8>> = lens.iter().map(|&l| Vec::with_capacity(l)).collect();
    let max_cols = lens.iter().copied().max().unwrap_or(0);
    let mut body_pos = 0usize;
    for col in 0..max_cols {
        for (idx, &l) in lens.iter().enumerate() {
            if col < l {
                let b = *body.get(body_pos).ok_or_else(|| {
                    CodecError::Malformed(String::from("truncated columnar byte"))
                })?;
                if let Some(dst) = lines.get_mut(idx) {
                    dst.push(b);
                }
                body_pos += 1;
            }
        }
    }
    let cap = usize::try_from(content_len).unwrap_or(0);
    let mut out = Vec::with_capacity(cap.min(1 << 20));
    for (idx, line) in lines.iter().enumerate() {
        if idx > 0 {
            out.push(sep);
        }
        out.extend_from_slice(line);
    }
    Ok(out)
}

fn pack_genomic_encode(content: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::with_capacity(content.len().saturating_add(4));
    let mut idx = 0usize;
    while idx < content.len() {
        let rem = content.get(idx..).unwrap_or(&[]);
        let run = rem
            .iter()
            .take(255)
            .take_while(|&&b| matches!(b, b'A' | b'C' | b'G' | b'T'))
            .count();
        if run >= 4 {
            let count_u8 = u8::try_from(run)
                .map_err(|_| CodecError::Encode(String::from("genomic run overflow")))?;
            out.push(0x01);
            out.push(count_u8);
            let mut acc = 0u8;
            let mut bits = 0u8;
            for &b in rem.get(..run).unwrap_or(&[]) {
                let code = match b {
                    b'A' => 0u8,
                    b'C' => 1u8,
                    b'G' => 2u8,
                    b'T' => 3u8,
                    _ => 0u8,
                };
                acc = (acc << 2) | code;
                bits += 2;
                if bits == 8 {
                    out.push(acc);
                    acc = 0;
                    bits = 0;
                }
            }
            if bits > 0 {
                out.push(acc << (8 - bits));
            }
            idx += run;
        } else {
            let lit_len = rem
                .iter()
                .take(255)
                .take_while(|&&b| !matches!(b, b'A' | b'C' | b'G' | b'T'))
                .count()
                .max(1);
            let count_u8 = u8::try_from(lit_len)
                .map_err(|_| CodecError::Encode(String::from("genomic lit overflow")))?;
            out.push(0x00);
            out.push(count_u8);
            out.extend_from_slice(rem.get(..lit_len).unwrap_or(&[]));
            idx += lit_len;
        }
    }
    Ok(out)
}

fn pack_genomic_decode(encoded: &[u8], content_len: u64) -> Result<Vec<u8>, CodecError> {
    let want =
        usize::try_from(content_len).map_err(|_| CodecError::TooLong { max: content_len })?;
    let mut out = Vec::with_capacity(want.min(1 << 20));
    let mut pos = 0usize;
    while pos < encoded.len() {
        let tag = *encoded
            .get(pos)
            .ok_or_else(|| CodecError::Malformed(String::from("truncated genomic tag")))?;
        let count = usize::from(
            *encoded
                .get(pos + 1)
                .ok_or_else(|| CodecError::Malformed(String::from("truncated genomic count")))?,
        );
        pos += 2;
        if out.len().saturating_add(count) > want {
            return Err(CodecError::TooLong { max: content_len });
        }
        match tag {
            0x00 => {
                let slice = encoded
                    .get(pos..pos + count)
                    .ok_or_else(|| CodecError::Malformed(String::from("truncated genomic lit")))?;
                out.extend_from_slice(slice);
                pos += count;
            }
            0x01 => {
                let packed_bytes = count.div_ceil(4);
                let packed = encoded
                    .get(pos..pos + packed_bytes)
                    .ok_or_else(|| CodecError::Malformed(String::from("truncated genomic 2bit")))?;
                pos += packed_bytes;
                for i in 0..count {
                    let byte = *packed.get(i / 4).unwrap_or(&0);
                    let shift = 6 - ((i % 4) * 2);
                    let base = match (byte >> shift) & 0x03 {
                        0 => b'A',
                        1 => b'C',
                        2 => b'G',
                        _ => b'T',
                    };
                    out.push(base);
                }
            }
            _ => return Err(CodecError::Malformed(String::from("unknown genomic tag"))),
        }
    }
    Ok(out)
}

fn chunk_dedup_encode(content: &[u8]) -> Result<Vec<u8>, CodecError> {
    let chunk_size = 64usize;
    let mut unique: Vec<&[u8]> = Vec::new();
    let mut indices: Vec<u32> = Vec::new();
    for chunk in content.chunks(chunk_size) {
        if let Some(pos) = unique.iter().position(|&u| u == chunk) {
            indices.push(u32::try_from(pos).unwrap_or(u32::MAX));
        } else {
            let idx = u32::try_from(unique.len())
                .map_err(|_| CodecError::Encode(String::from("chunk table overflow")))?;
            unique.push(chunk);
            indices.push(idx);
        }
    }
    let mut out = Vec::with_capacity(content.len().saturating_add(16));
    write_u32_le(&mut out, u32::try_from(unique.len()).unwrap_or(u32::MAX));
    for u in &unique {
        write_u32_le(&mut out, u32::try_from(u.len()).unwrap_or(u32::MAX));
        out.extend_from_slice(u);
    }
    write_u32_le(&mut out, u32::try_from(indices.len()).unwrap_or(u32::MAX));
    for idx in indices {
        write_u32_le(&mut out, idx);
    }
    Ok(out)
}

fn chunk_dedup_decode(encoded: &[u8], content_len: u64) -> Result<Vec<u8>, CodecError> {
    let want =
        usize::try_from(content_len).map_err(|_| CodecError::TooLong { max: content_len })?;
    let mut pos = 0usize;
    let unique_count = usize::try_from(read_u32_le(encoded, &mut pos)?)
        .map_err(|_| CodecError::Malformed(String::from("unique count overflow")))?;
    let max_chunks = want.saturating_add(1);
    if unique_count > max_chunks {
        return Err(CodecError::TooLong { max: content_len });
    }
    let mut unique = Vec::with_capacity(unique_count.min(4096));
    for _ in 0..unique_count {
        let len = usize::try_from(read_u32_le(encoded, &mut pos)?)
            .map_err(|_| CodecError::Malformed(String::from("chunk len overflow")))?;
        let end = pos
            .checked_add(len)
            .ok_or_else(|| CodecError::Malformed(String::from("chunk slice overflow")))?;
        let chunk = encoded
            .get(pos..end)
            .ok_or_else(|| CodecError::Malformed(String::from("truncated unique chunk")))?;
        unique.push(chunk);
        pos = end;
    }
    let seq_count = usize::try_from(read_u32_le(encoded, &mut pos)?)
        .map_err(|_| CodecError::Malformed(String::from("seq count overflow")))?;
    let mut out = Vec::with_capacity(want.min(1 << 20));
    for _ in 0..seq_count {
        let idx = usize::try_from(read_u32_le(encoded, &mut pos)?)
            .map_err(|_| CodecError::Malformed(String::from("chunk idx overflow")))?;
        let chunk = *unique
            .get(idx)
            .ok_or_else(|| CodecError::Malformed(String::from("unknown chunk idx")))?;
        if out.len().saturating_add(chunk.len()) > want {
            return Err(CodecError::TooLong { max: content_len });
        }
        out.extend_from_slice(chunk);
    }
    Ok(out)
}

/// Encode `content` under any registered open codec (`0..=8, 10..=26`).
///
/// # Errors
///
/// Returns [`CodecError::Unknown`] for `9` or unregistered ids, or [`CodecError::Encode`]
/// if compression fails.
pub fn encode_codec(codec: CodecId, content: &[u8]) -> Result<Vec<u8>, CodecError> {
    match codec {
        crate::RAW => Ok(content.to_vec()),
        crate::ZSTD => zstd_compress_with(content, STORE_LEVEL, true),
        LZMA2 => {
            let tokens = encode_lz77_tokens(content)?;
            wrap_tagged_zstd(LZMA2, 1, &tokens, STORE_LEVEL, true)
        }
        DICT_ZSTD => wrap_tagged_zstd(DICT_ZSTD, 1, content, PROBE_LEVEL, false),
        COLUMNAR_JSON => {
            if content.contains(&b'\n') && content.len() > 32 {
                let col = columnar_lines_encode(content, b'\n');
                wrap_tagged_zstd(COLUMNAR_JSON, 1, &col, STORE_LEVEL, true)
            } else {
                wrap_tagged_zstd(COLUMNAR_JSON, 0, content, STORE_LEVEL, false)
            }
        }
        LEPTON_JPEG => {
            let x = xor_neighbor_encode(content);
            wrap_tagged_zstd(LEPTON_JPEG, 1, &x, STORE_LEVEL, true)
        }
        PREFLATE => {
            let tokens = encode_lz77_tokens(content)?;
            wrap_tagged_zstd(PREFLATE, 1, &tokens, STORE_LEVEL, false)
        }
        LOSSLESS_AUDIO => {
            let delta = stride_delta_encode(content, 2);
            wrap_tagged_zstd(LOSSLESS_AUDIO, 1, &delta, STORE_LEVEL, false)
        }
        CONTEXT_MIX => range_coder::encode(content),
        DERIVATION => {
            let x = xor_neighbor_encode(content);
            wrap_tagged_zstd(DERIVATION, 1, &x, STORE_LEVEL, true)
        }
        VERSION_DELTA => {
            let dedup = chunk_dedup_encode(content)?;
            wrap_tagged_zstd(VERSION_DELTA, 1, &dedup, STORE_LEVEL, true)
        }
        LZ_CONTEXT => {
            let tokens = encode_lz77_tokens(content)?;
            wrap_tagged_zstd(LZ_CONTEXT, 1, &tokens, PROBE_LEVEL, false)
        }
        CONTEXT_MACHINE => {
            let delta = stride_delta_encode(content, 1);
            wrap_tagged_zstd(CONTEXT_MACHINE, 1, &delta, STORE_LEVEL, true)
        }
        LOG_COLUMNAR => {
            if content.contains(&b' ') && content.len() > 32 {
                let col = columnar_lines_encode(content, b' ');
                wrap_tagged_zstd(LOG_COLUMNAR, 1, &col, STORE_LEVEL, false)
            } else {
                wrap_tagged_zstd(LOG_COLUMNAR, 0, content, STORE_LEVEL, false)
            }
        }
        TIME_SERIES => {
            if !content.is_empty() && content.len().is_multiple_of(16) {
                let inner = encode_timeseries_delta_xor(content)?;
                let mut out = Vec::with_capacity(2 + inner.len());
                out.push(tag_byte(TIME_SERIES));
                out.push(1);
                out.extend_from_slice(&inner);
                Ok(out)
            } else {
                let delta = stride_delta_encode(content, 8);
                wrap_tagged_zstd(TIME_SERIES, 0, &delta, STORE_LEVEL, false)
            }
        }
        WAL_COLUMNAR => {
            if content.contains(&b'\n') && content.len() > 32 {
                let col = columnar_lines_encode(content, b'\n');
                wrap_tagged_zstd(WAL_COLUMNAR, 1, &col, STORE_LEVEL, true)
            } else {
                wrap_tagged_zstd(WAL_COLUMNAR, 0, content, STORE_LEVEL, false)
            }
        }
        PCAP_COLUMNAR => {
            let delta = stride_delta_encode(content, 16);
            wrap_tagged_zstd(PCAP_COLUMNAR, 1, &delta, STORE_LEVEL, true)
        }
        PAGE_XOR_DELTA => {
            let delta = stride_delta_encode(content, 4096);
            wrap_tagged_zstd(PAGE_XOR_DELTA, 1, &delta, STORE_LEVEL, true)
        }
        FLOAT_SPLIT => {
            if !content.is_empty() && content.len().is_multiple_of(4) {
                let inner = encode_fp32_exponent_split(content)?;
                let mut out = Vec::with_capacity(2 + inner.len());
                out.push(tag_byte(FLOAT_SPLIT));
                out.push(1);
                out.extend_from_slice(&inner);
                Ok(out)
            } else {
                let delta = stride_delta_encode(content, 4);
                wrap_tagged_zstd(FLOAT_SPLIT, 0, &delta, STORE_LEVEL, false)
            }
        }
        EXE_SPLIT => {
            let delta = stride_delta_encode(content, 4);
            wrap_tagged_zstd(EXE_SPLIT, 1, &delta, STORE_LEVEL, true)
        }
        PDF_SPLIT => {
            let tokens = encode_lz77_tokens(content)?;
            wrap_tagged_zstd(PDF_SPLIT, 1, &tokens, STORE_LEVEL, true)
        }
        MARKDOWN_SPLIT => {
            if content.contains(&b'\n') && content.len() > 32 {
                let col = columnar_lines_encode(content, b'\n');
                wrap_tagged_zstd(MARKDOWN_SPLIT, 1, &col, STORE_LEVEL, false)
            } else {
                wrap_tagged_zstd(MARKDOWN_SPLIT, 0, content, STORE_LEVEL, false)
            }
        }
        GENOMIC => {
            let packed = pack_genomic_encode(content)?;
            wrap_tagged_zstd(GENOMIC, 1, &packed, STORE_LEVEL, true)
        }
        OFFICE_OPC => {
            let dedup = chunk_dedup_encode(content)?;
            wrap_tagged_zstd(OFFICE_OPC, 1, &dedup, STORE_LEVEL, true)
        }
        POINT_CLOUD => {
            let delta = stride_delta_encode(content, 24);
            wrap_tagged_zstd(POINT_CLOUD, 1, &delta, STORE_LEVEL, true)
        }
        LOSSLESS_IMAGE => {
            let delta = stride_delta_encode(content, 3);
            wrap_tagged_zstd(LOSSLESS_IMAGE, 1, &delta, STORE_LEVEL, true)
        }
        other => Err(CodecError::Unknown(other)),
    }
}

/// Decode `payload` under `codec` up to exactly `content_len` bytes.
///
/// # Errors
///
/// Returns [`CodecError`] on unknown codec id, malformed wire frame, or length mismatch.
pub fn decode_codec(
    codec: CodecId,
    payload: &[u8],
    content_len: u64,
) -> Result<Vec<u8>, CodecError> {
    if content_len > MAX_CODEC_DECODE_BYTES {
        return Err(CodecError::TooLong {
            max: MAX_CODEC_DECODE_BYTES,
        });
    }
    match codec {
        LZMA2 | PREFLATE | LZ_CONTEXT | PDF_SPLIT => {
            let (_mode, tokens) = unwrap_tagged_zstd(codec, payload, content_len)?;
            decode_lz77_tokens(&tokens, content_len)
        }
        DICT_ZSTD => {
            let (_mode, out) = unwrap_tagged_zstd(DICT_ZSTD, payload, content_len)?;
            Ok(out)
        }
        COLUMNAR_JSON | WAL_COLUMNAR | MARKDOWN_SPLIT => {
            let (mode, inner) = unwrap_tagged_zstd(codec, payload, content_len)?;
            if mode == 1 {
                columnar_lines_decode(&inner, b'\n', content_len)
            } else {
                Ok(inner)
            }
        }
        LEPTON_JPEG | DERIVATION => {
            let (_mode, inner) = unwrap_tagged_zstd(codec, payload, content_len)?;
            Ok(xor_neighbor_decode(&inner))
        }
        LOSSLESS_AUDIO => {
            let (_mode, inner) = unwrap_tagged_zstd(LOSSLESS_AUDIO, payload, content_len)?;
            Ok(stride_delta_decode(&inner, 2))
        }
        CONTEXT_MIX => range_coder::decode(payload, content_len),
        VERSION_DELTA | OFFICE_OPC => {
            let (_mode, inner) = unwrap_tagged_zstd(codec, payload, content_len)?;
            chunk_dedup_decode(&inner, content_len)
        }
        CONTEXT_MACHINE => {
            let (_mode, inner) = unwrap_tagged_zstd(CONTEXT_MACHINE, payload, content_len)?;
            Ok(stride_delta_decode(&inner, 1))
        }
        LOG_COLUMNAR => {
            let (mode, inner) = unwrap_tagged_zstd(LOG_COLUMNAR, payload, content_len)?;
            if mode == 1 {
                columnar_lines_decode(&inner, b' ', content_len)
            } else {
                Ok(inner)
            }
        }
        TIME_SERIES => {
            let tag = *payload
                .first()
                .ok_or_else(|| CodecError::Malformed(String::from("truncated TIME_SERIES")))?;
            let mode = *payload
                .get(1)
                .ok_or_else(|| CodecError::Malformed(String::from("truncated TIME_SERIES mode")))?;
            if tag != tag_byte(TIME_SERIES) {
                return Err(CodecError::Malformed(String::from(
                    "TIME_SERIES tag mismatch",
                )));
            }
            if mode == 1 {
                let want = usize::try_from(content_len)
                    .map_err(|_| CodecError::TooLong { max: content_len })?;
                decode_timeseries_delta_xor(payload.get(2..).unwrap_or(&[]), want)
            } else {
                let (_m, inner) = unwrap_tagged_zstd(TIME_SERIES, payload, content_len)?;
                Ok(stride_delta_decode(&inner, 8))
            }
        }
        PCAP_COLUMNAR => {
            let (_mode, inner) = unwrap_tagged_zstd(PCAP_COLUMNAR, payload, content_len)?;
            Ok(stride_delta_decode(&inner, 16))
        }
        PAGE_XOR_DELTA => {
            let (_mode, inner) = unwrap_tagged_zstd(PAGE_XOR_DELTA, payload, content_len)?;
            Ok(stride_delta_decode(&inner, 4096))
        }
        FLOAT_SPLIT => {
            let tag = *payload
                .first()
                .ok_or_else(|| CodecError::Malformed(String::from("truncated FLOAT_SPLIT")))?;
            let mode = *payload
                .get(1)
                .ok_or_else(|| CodecError::Malformed(String::from("truncated FLOAT_SPLIT mode")))?;
            if tag != tag_byte(FLOAT_SPLIT) {
                return Err(CodecError::Malformed(String::from(
                    "FLOAT_SPLIT tag mismatch",
                )));
            }
            if mode == 1 {
                let want = usize::try_from(content_len)
                    .map_err(|_| CodecError::TooLong { max: content_len })?;
                decode_fp32_exponent_split(payload.get(2..).unwrap_or(&[]), want)
            } else {
                let (_m, inner) = unwrap_tagged_zstd(FLOAT_SPLIT, payload, content_len)?;
                Ok(stride_delta_decode(&inner, 4))
            }
        }
        EXE_SPLIT => {
            let (_mode, inner) = unwrap_tagged_zstd(EXE_SPLIT, payload, content_len)?;
            Ok(stride_delta_decode(&inner, 4))
        }
        GENOMIC => {
            let (_mode, inner) = unwrap_tagged_zstd(GENOMIC, payload, content_len)?;
            pack_genomic_decode(&inner, content_len)
        }
        POINT_CLOUD => {
            let (_mode, inner) = unwrap_tagged_zstd(POINT_CLOUD, payload, content_len)?;
            Ok(stride_delta_decode(&inner, 24))
        }
        LOSSLESS_IMAGE => {
            let (_mode, inner) = unwrap_tagged_zstd(LOSSLESS_IMAGE, payload, content_len)?;
            Ok(stride_delta_decode(&inner, 3))
        }
        other => Err(CodecError::Unknown(other)),
    }
}

/// Fast candidate codecs matched by content signature or size for `select()`.
#[must_use]
pub fn candidate_codecs_for(content: &[u8]) -> &'static [CodecId] {
    if content.len() >= 4
        && (content.starts_with(b"\xD4\xC3\xB2\xA1") || content.starts_with(b"\xA1\xB2\xC3\xD4"))
    {
        return &[PCAP_COLUMNAR, LZMA2];
    }
    if content.starts_with(b"RIFF") || content.starts_with(b"FORM") {
        return &[LOSSLESS_AUDIO];
    }
    if content.starts_with(b"BM") || content.starts_with(b"II*\0") || content.starts_with(b"MM\0*")
    {
        return &[LOSSLESS_IMAGE];
    }
    if content.starts_with(b"\x7FELF") || content.starts_with(b"MZ") {
        return &[EXE_SPLIT];
    }
    if content.starts_with(b"%PDF-") {
        return &[PDF_SPLIT];
    }
    if content.starts_with(b"PK\x03\x04") {
        return &[OFFICE_OPC];
    }
    if content.starts_with(b">") || content.starts_with(b"@") {
        return &[GENOMIC, CONTEXT_MACHINE];
    }
    if content.starts_with(b"{") || content.starts_with(b"[") {
        return &[COLUMNAR_JSON, LOG_COLUMNAR];
    }
    if content.starts_with(b"# ") {
        return &[MARKDOWN_SPLIT];
    }
    if content.len() <= crate::registry::shared_context::SMALL_OBJECT_MAX_BYTES {
        return &[DICT_ZSTD, VERSION_DELTA, CONTEXT_MIX];
    }
    &[VERSION_DELTA, LZMA2, PAGE_XOR_DELTA]
}
