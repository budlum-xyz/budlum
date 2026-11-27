//! Security regression tests for `bud-codec`:
//! 1. Reject unknown mode bytes across tagged codecs (no malleable encodings).
//! 2. Reject trailing bytes and zero-length chunk amplification in `VERSION_DELTA` / `OFFICE_OPC`.
//! 3. Reject zero-length no-op tokens in LZ77 and genomic decoders.
//! 4. Decode sparse columnar payloads in linear O(content_len) time (no quadratic CPU bomb).

use bud_codec::codecs::encode_codec;
use bud_codec::{decode, CodecError};
use std::io::Write;
use std::time::Instant;

fn wrap_zstd(codec_byte: u8, mode: u8, inner: &[u8]) -> Vec<u8> {
    let Ok(mut enc) = zstd::stream::Encoder::new(Vec::new(), 3) else {
        panic!("zstd encoder init failed");
    };
    if enc.include_checksum(false).is_err() || enc.write_all(inner).is_err() {
        panic!("zstd write failed");
    }
    let Ok(comp) = enc.finish() else {
        panic!("zstd finish failed");
    };
    let mut out = Vec::with_capacity(6 + comp.len());
    out.push(codec_byte);
    out.push(mode);
    out.extend_from_slice(&(inner.len() as u32).to_le_bytes());
    out.extend_from_slice(&comp);
    out
}

#[test]
fn tagged_codecs_refuse_unknown_mode_bytes() {
    let sample = b"{\"a\":1}\n{\"b\":2}\n{\"c\":3}\n{\"d\":4}\n{\"e\":5}\n";
    for codec_id in [
        2u16, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    ] {
        let mut encoded = encode_codec(codec_id, sample).expect("encode");
        assert!(
            decode(codec_id, &encoded, sample.len() as u64).is_ok(),
            "honest payload for codec {codec_id} must decode"
        );
        // Flip mode byte to an unregistered value (0x7F).
        encoded[1] = 0x7F;
        let err = decode(codec_id, &encoded, sample.len() as u64).expect_err(&format!(
            "codec {codec_id} must refuse unknown mode byte 0x7F"
        ));
        assert!(
            matches!(err, CodecError::Malformed(_)),
            "codec {codec_id} returned unexpected error for unknown mode: {err:?}"
        );
    }
}

#[test]
fn chunk_dedup_refuses_zero_len_chunks_and_trailing_bytes() {
    // 1. Zero-length unique chunk referenced repeatedly -> amplification attack.
    let mut inner_zero = Vec::new();
    inner_zero.extend_from_slice(&1u32.to_le_bytes()); // unique_count = 1
    inner_zero.extend_from_slice(&0u32.to_le_bytes()); // chunk[0] len = 0 (invalid!)
    inner_zero.extend_from_slice(&4u32.to_le_bytes()); // seq_count = 4
    for _ in 0..4 {
        inner_zero.extend_from_slice(&0u32.to_le_bytes());
    }
    let payload_zero = wrap_zstd(11, 1, &inner_zero);
    assert!(
        matches!(decode(11, &payload_zero, 0), Err(CodecError::Malformed(_))),
        "zero-length unique chunk must fail closed"
    );

    // 2. Trailing garbage bytes after valid chunk sequence -> malleable encoding.
    let mut inner_trailing = Vec::new();
    inner_trailing.extend_from_slice(&1u32.to_le_bytes()); // unique_count = 1
    inner_trailing.extend_from_slice(&4u32.to_le_bytes()); // chunk[0] len = 4
    inner_trailing.extend_from_slice(b"ABCD");
    inner_trailing.extend_from_slice(&1u32.to_le_bytes()); // seq_count = 1
    inner_trailing.extend_from_slice(&0u32.to_le_bytes()); // idx = 0
    inner_trailing.extend_from_slice(b"EXTRA_GARBAGE");
    let payload_trailing = wrap_zstd(11, 1, &inner_trailing);
    assert!(
        matches!(
            decode(11, &payload_trailing, 4),
            Err(CodecError::Malformed(_))
        ),
        "trailing bytes after chunk_dedup sequence must fail closed"
    );
}

#[test]
fn lz77_and_genomic_refuse_zero_length_noop_tokens() {
    // LZ77: 0x00 literal run with len=0 followed by real literal "hi".
    let lz_inner = [0x00, 0x00, 0x00, 0x00, 0x02, 0x00, b'h', b'i'];
    let lz_payload = wrap_zstd(2, 1, &lz_inner);
    assert!(
        matches!(decode(2, &lz_payload, 2), Err(CodecError::Malformed(_))),
        "zero-length LZ77 literal token must fail closed"
    );

    // Genomic: 0x00 literal run with count=0 followed by real literal "hi".
    let gen_inner = [0x00, 0x00, 0x00, 0x02, b'h', b'i'];
    let gen_payload = wrap_zstd(23, 1, &gen_inner);
    assert!(
        matches!(decode(23, &gen_payload, 2), Err(CodecError::Malformed(_))),
        "zero-length genomic literal token must fail closed"
    );
}

#[test]
fn columnar_decode_handles_sparse_lines_in_linear_time() {
    // Sparse columnar payload: 1 line of length 50_000 and 9_999 empty lines.
    // Total content length = 50_000 + 9_999 separators = 59_999 bytes,
    // inner transformed length = 4 + 40_000 + 50_000 = 90_004 <= 2*content_len + 4096.
    // A quadratic O(count * max_cols) decoder executes 500_000_000 iterations;
    // a linear O(total_chars) decoder finishes in a few milliseconds.
    let count: u32 = 10_000;
    let first_len: u32 = 50_000;
    let content_len: u64 = u64::from(first_len) + u64::from(count - 1);

    let mut inner = Vec::with_capacity(4 + (count as usize) * 4 + (first_len as usize));
    inner.extend_from_slice(&count.to_le_bytes());
    inner.extend_from_slice(&first_len.to_le_bytes());
    for _ in 1..count {
        inner.extend_from_slice(&0u32.to_le_bytes());
    }
    inner.extend(std::iter::repeat_n(b'x', first_len as usize));

    let payload = wrap_zstd(4, 1, &inner);
    let started = Instant::now();
    let decoded = decode(4, &payload, content_len).expect("valid sparse columnar stream");
    let elapsed = started.elapsed();

    assert_eq!(decoded.len() as u64, content_len);
    assert!(decoded[..first_len as usize].iter().all(|&b| b == b'x'));
    assert!(decoded[first_len as usize..].iter().all(|&b| b == b'\n'));
    assert!(
        elapsed.as_millis() < 250,
        "sparse columnar decode took {}ms (quadratic CPU DoS regression)",
        elapsed.as_millis()
    );
}
