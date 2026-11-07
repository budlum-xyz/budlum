//! Fuzzing harness for the adopted codec transforms.
//!
//! Kapsam:
//!   1) HuffmanCoder::decompress - no panic on untrusted bytes
//!   2) Huffman roundtrip - the losslessness property (a break is a fuzz crash)
//!   3) structural chunking is lossless for every kind (split+join == d)
#![no_main]
use bud_codec::container::{
    structural_join, structural_split, structural_split_compact, StructuralKind,
};
use bud_codec::huffman::HuffmanCoder;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1) Huffman decompress - no panic on untrusted bytes.
    let _ = HuffmanCoder::decompress(data);

    // 2) Huffman roundtrip: compress -> decompress == d. If the equality
    //    breaks the ASSERT crashes, so the fuzzer catches the property
    //    violation (the COMPLETENESS of losslessness).
    if data.len() <= 4096 {
        let comp = HuffmanCoder::compress(data);
        if let Some(back) = HuffmanCoder::decompress(&comp) {
            assert_eq!(&back[..], data, "the Huffman roundtrip has to be lossless");
        }
    }

    // 3) Structural chunking is lossless for every kind (split+join == d).
    for kind in [
        StructuralKind::Json,
        StructuralKind::Csv,
        StructuralKind::Log,
        StructuralKind::Text,
        StructuralKind::Binary,
    ] {
        let chunks = structural_split(kind, data);
        let joined = structural_join(kind, &chunks);
        assert_eq!(
            &joined[..],
            data,
            "structural chunking is lossless (K38): {kind:?}"
        );
        let _ = structural_split_compact(kind, data, 64 * 1024);
    }
});
