//! Fuzzing harness for the .bud format - V14 (extended for K25/K38).
//!
//! Kapsam:
//!   1) v1 BudFile from_bytes/decode/decode_streaming (the K25 stream limits)
//!   2) BudV2File decode + restore_original + a Huffman roundtrip (the
//!      losslessness property)
//!   3) HuffmanCoder::decompress - no panic on untrusted bytes
//!   4) pipe store/restore - the K38 property: restore(store(d)) == d (the
//!      assert is a fuzz crash)
//!   5) PoR respond/verify - no panic on out-of-bounds indices (K38)
//!   6) structural chunking is lossless for every kind (split+join == d)
#![no_main]
use libfuzzer_sys::fuzz_target;
use bud_core::bud_format::{BudFile, BudFormatClass, BudFlags};
use bud_core::bud_format_container::{
    BudV2File, FormatCodec, MultiHash, StructuralKind, content_id, structural_join,
    structural_split, structural_split_compact,
};
use bud_core::bud_format_huffman::HuffmanCoder;
use bud_core::bud_format_por::{PorChallenge, PorKey};
use bud_core::bud_format_pipe::{restore, store, store_zstd};

fuzz_target!(|data: &[u8]| {
    // 1) The v1 format (bud_format.rs) - K25 stream plus limits.
    if let Ok(file) = BudFile::from_bytes(data) {
        let _ = file.decode();
        let _ = file.decode_streaming(|_| Ok(()));
    }
    if data.len() < 1024 {
        let _ = BudFile::encode(data, BudFormatClass::Json, "application/json", 0, 0, 3, BudFlags::new(true, true, false, false, false, false), data.to_vec());
    }

    // 2) The .bud v2 container - the decode/parse paths must not panic.
    let _ = BudV2File::decode(data);
    let _ = MultiHash::decode(data);
    if let Some(file) = BudV2File::decode(data) {
        let _ = file.restore_original(); // automatic Raw/Huffman expansion - no panic
    }

    // 3) Huffman decompress - no panic on untrusted bytes.
    let _ = HuffmanCoder::decompress(data);

    // 4) The pipe K38 property: restore(store(d)) == d. On small inputs store
    //    always succeeds (the size limits only bite on large inputs); if the
    //    equality breaks the ASSERT crashes, so the fuzzer catches the
    //    property violation (the COMPLETENESS of losslessness).
    if data.len() <= 4096 {
        if let Some(bud) = store(data) {
            let back = restore(&bud).expect("a valid container can be restored");
            assert_eq!(&back[..], data, "K38: restore(store(d)) == d ihlali");
        }
        // The zstd property: store_zstd -> restore == d (V21, K38).
        if let Some(bud) = store_zstd(data) {
            let back = restore(&bud).expect("a zstd container can be restored");
            assert_eq!(&back[..], data, "K38: zstd restore(store(d)) == d ihlali");
        }
        // Huffman roundtrip: new_compressed -> decode -> restore_original == d
        let chunks = structural_split_compact(StructuralKind::Binary, data, 128);
        if let Some(comp) = BudV2File::new_compressed(FormatCodec::Unknown, chunks.clone()) {
            if let Some(dec) = BudV2File::decode(&comp.encode()) {
                let back = dec.restore_original().expect("the Huffman expansion succeeds");
                assert_eq!(&back[..], data, "the Huffman roundtrip has to be lossless");
            }
        }
    }

    // 5) PoR bounds safety: a random block set plus a challenge, with no panic
    //    from respond/verify.
    let blocks: Vec<Vec<u8>> = data.chunks(16).map(|c| c.to_vec()).collect();
    if !blocks.is_empty() {
        let key = PorKey::new(content_id(data));
        let ch = PorKey::challenge(blocks.len() as u64, 4, 7);
        if let Some(resp) = key.respond(&blocks, &ch) {
            let _ = key.verify(&blocks, &ch, &resp);
        }
        // a challenge with an out-of-bounds index -> respond None, NO PANIC
        let bad = PorChallenge { indices: vec![999_999], nonce: [0u8; 32] };
        let _ = key.respond(&blocks, &bad);
    }

    // 6) Structural chunking is lossless for every kind (split+join == d).
    for kind in [
        StructuralKind::Json,
        StructuralKind::Csv,
        StructuralKind::Log,
        StructuralKind::Text,
        StructuralKind::Binary,
    ] {
        let chunks = structural_split(kind, data);
        let joined = structural_join(kind, &chunks);
        assert_eq!(&joined[..], data, "structural chunking is lossless (K38): {kind:?}");
        let _ = structural_split_compact(kind, data, 64 * 1024);
    }
});
