//! B.U.D. 3.0 A0: the codec registry.
//!
//! A0 finds the shortest complete representation of the content: the
//! payload of the object. Each codec is a registered, frozen representation.
//! Only the decoder is frozen: compressor output may change between versions,
//! but every payload a past encoder wrote decodes the same way forever.
//!
//! Open in this crate:
//!
//! | Id | Codec | Encoder | Decoder |
//! |---|---|---|---|
//! | 0 | Raw | identity | identity |
//! | 1 | zstd, level 19, long distance matching, fixed 8 MiB window | `zstd` (libzstd) | `ruzstd` (pure Rust) |
//!
//! The decoders are pure Rust because content is decoded on the viewer's
//! device. A decoder never writes more than the declared content length and
//! refuses a stream that would.
//!
//! Selection: every candidate is decoded and compared with the content before
//! it counts; the smallest verified candidate wins and a tie goes to the
//! smaller id. Content above 7.9 bits of entropy per byte skips the general
//! compressor and stays raw. The quick probe: when zstd level 3 saves 5 % or
//! less, the slow candidates are not run.

use std::io::Read;

/// A codec id.
pub type CodecId = u16;

/// Raw: the payload is the content.
pub const RAW: CodecId = 0;
/// zstd.
pub const ZSTD: CodecId = 1;

/// The zstd window: 2^23 bytes, so a phone decodes with at most 8 MiB of
/// history.
pub const ZSTD_WINDOW_LOG: u32 = 23;

/// The level of the probe.
pub const PROBE_LEVEL: i32 = 3;
/// The level of the stored candidate.
pub const STORE_LEVEL: i32 = 19;

/// Why a payload did not decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// The codec is not open in this registry.
    Unknown(CodecId),
    /// The stream is malformed.
    Malformed(String),
    /// The stream decodes to more than the declared length.
    TooLong { max: u64 },
    /// The stream decodes to fewer bytes than declared.
    TooShort { want: u64, got: u64 },
    /// The encoder failed.
    Encode(String),
}

/// Whether `id` decodes in this registry.
#[must_use]
pub const fn is_open(id: CodecId) -> bool {
    matches!(id, RAW | ZSTD)
}

/// Decode `payload` with `codec` to exactly `content_len` bytes.
///
/// # Errors
///
/// [`CodecError`] for an unknown codec, a malformed stream, or a stream
/// whose length is not `content_len`. The output never grows past
/// `content_len`, whatever the stream claims.
pub fn decode(codec: CodecId, payload: &[u8], content_len: u64) -> Result<Vec<u8>, CodecError> {
    let cap = usize::try_from(content_len).map_err(|_| CodecError::TooLong { max: content_len })?;
    let out = match codec {
        RAW => payload.to_vec(),
        ZSTD => {
            let mut dec = ruzstd::decoding::StreamingDecoder::new(payload)
                .map_err(|e| CodecError::Malformed(e.to_string()))?;
            let mut out = Vec::with_capacity(cap.min(1 << 24));
            // Read one byte past the declared length to detect a longer stream.
            let limit = content_len.saturating_add(1);
            (&mut dec)
                .take(limit)
                .read_to_end(&mut out)
                .map_err(|e| CodecError::Malformed(e.to_string()))?;
            out
        }
        other => return Err(CodecError::Unknown(other)),
    };
    let got = out.len() as u64;
    if got > content_len {
        return Err(CodecError::TooLong { max: content_len });
    }
    if got < content_len {
        return Err(CodecError::TooShort {
            want: content_len,
            got,
        });
    }
    Ok(out)
}

fn zstd_encode(content: &[u8], level: i32) -> Result<Vec<u8>, CodecError> {
    let mut enc = zstd::stream::Encoder::new(Vec::new(), level)
        .map_err(|e| CodecError::Encode(e.to_string()))?;
    enc.long_distance_matching(true)
        .map_err(|e| CodecError::Encode(e.to_string()))?;
    enc.window_log(ZSTD_WINDOW_LOG)
        .map_err(|e| CodecError::Encode(e.to_string()))?;
    enc.include_checksum(false)
        .map_err(|e| CodecError::Encode(e.to_string()))?;
    std::io::Write::write_all(&mut enc, content).map_err(|e| CodecError::Encode(e.to_string()))?;
    enc.finish().map_err(|e| CodecError::Encode(e.to_string()))
}

/// Shannon entropy of `bytes` in millibits per byte, integers only.
#[must_use]
pub fn entropy_millibits(bytes: &[u8]) -> u32 {
    if bytes.is_empty() {
        return 0;
    }
    let mut counts = [0u64; 256];
    for b in bytes {
        if let Some(c) = counts.get_mut(usize::from(*b)) {
            *c += 1;
        }
    }
    let n = bytes.len() as f64;
    // Off the consensus path: selection runs on the uploader's side and
    // only its verified output is recorded.
    let h: f64 = counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / n;
            -p * p.log2()
        })
        .sum();
    (h * 1000.0) as u32
}

/// The selected codec and payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selected {
    /// The codec.
    pub codec: CodecId,
    /// The payload.
    pub payload: Vec<u8>,
}

/// Pick the shortest verified representation of `content`. An encoder
/// failure only drops that candidate; raw always remains.
#[must_use]
pub fn select(content: &[u8]) -> Selected {
    let raw = Selected {
        codec: RAW,
        payload: content.to_vec(),
    };
    if content.is_empty() || entropy_millibits(content) > 7_900 {
        return raw;
    }
    let len = content.len() as u64;
    let verified = |codec: CodecId, payload: Vec<u8>| -> Option<Selected> {
        (decode(codec, &payload, len).ok()? == content).then_some(Selected { codec, payload })
    };
    let Some(probe) = zstd_encode(content, PROBE_LEVEL)
        .ok()
        .and_then(|p| verified(ZSTD, p))
    else {
        return raw;
    };
    let mut best = if probe.payload.len() < content.len() {
        probe
    } else {
        raw.clone()
    };
    // Quick probe: a gain of 5 % or less does not justify the slow levels.
    let gain_ok = (best.payload.len() as u64) * 100 < len * 95;
    if gain_ok {
        if let Some(c) = zstd_encode(content, STORE_LEVEL)
            .ok()
            .and_then(|p| verified(ZSTD, p))
        {
            if c.payload.len() < best.payload.len() {
                best = c;
            }
        }
    }
    if best.payload.len() >= raw.payload.len() {
        // A tie goes to the smaller id.
        return raw;
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(n: usize) -> Vec<u8> {
        b"Budlum stores the shortest complete representation. "
            .iter()
            .copied()
            .cycle()
            .take(n)
            .collect()
    }

    fn noise(n: usize) -> Vec<u8> {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn text_selects_zstd_and_round_trips() {
        let c = text(100_000);
        let s = select(&c);
        assert_eq!(s.codec, ZSTD);
        assert!(s.payload.len() * 20 < c.len(), "{}", s.payload.len());
        assert_eq!(decode(s.codec, &s.payload, c.len() as u64).unwrap(), c);
    }

    #[test]
    fn random_bytes_stay_raw() {
        let c = noise(50_000);
        assert!(entropy_millibits(&c) > 7_900);
        assert_eq!(select(&c).codec, RAW);
        assert_eq!(select(b"").codec, RAW);
    }

    #[test]
    fn the_decoder_never_writes_past_the_declared_length() {
        let c = text(10_000);
        let s = zstd_encode(&c, 3).unwrap();
        assert_eq!(
            decode(ZSTD, &s, 9_999),
            Err(CodecError::TooLong { max: 9_999 })
        );
        assert!(matches!(
            decode(ZSTD, &s, 10_001),
            Err(CodecError::TooShort { .. })
        ));
        assert!(matches!(
            decode(ZSTD, b"not zstd", 8),
            Err(CodecError::Malformed(_))
        ));
        assert_eq!(decode(7, b"", 0), Err(CodecError::Unknown(7)));
        assert!(!is_open(2));
    }

    #[test]
    fn a_small_bomb_is_refused_without_growing() {
        // 64 MiB of zeros compresses to a few kilobytes; declared as 1 KiB it
        // is refused after at most 1 KiB + 1 of output.
        let bomb = zstd_encode(&vec![0u8; 64 << 20], 3).unwrap();
        assert!(bomb.len() < 64 << 10);
        assert_eq!(
            decode(ZSTD, &bomb, 1024),
            Err(CodecError::TooLong { max: 1024 })
        );
    }
}
