//! Fuzzing harness for .bud format - V14 (K25/K38 genişletilmiş)
//!
//! Kapsam:
//!   1) v1 BudFile from_bytes/decode/decode_streaming (K25 stream limitleri)
//!   2) BudV2File decode + restore_original + Huffman roundtrip (kayıpsızlık mülkiyeti)
//!   3) HuffmanCoder::decompress - güvenilmez baytlarda panik'sizlik
//!   4) pipe store/restore - K38 mülkiyeti: restore(store(d)) == d (assert = fuzz çökmesi)
//!   5) PoR respond/verify - sınır dışı indekslerde panik yok (K38)
//!   6) yapısal parçalama tüm türlerde kayıpsız (split+join == d)
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
    // 1) v1 format (bud_format.rs) - K25 stream + limitler
    if let Ok(file) = BudFile::from_bytes(data) {
        let _ = file.decode();
        let _ = file.decode_streaming(|_| Ok(()));
    }
    if data.len() < 1024 {
        let _ = BudFile::encode(data, BudFormatClass::Json, "application/json", 0, 0, 3, BudFlags::new(true, true, false, false, false, false), data.to_vec());
    }

    // 2) .bud v2 konteyner - decode/parse yolları panik'siz olmalı
    let _ = BudV2File::decode(data);
    let _ = MultiHash::decode(data);
    if let Some(file) = BudV2File::decode(data) {
        let _ = file.restore_original(); // Raw/Huffman otomatik açma - panik yok
    }

    // 3) Huffman decompress - güvenilmez baytlarda panik'siz
    let _ = HuffmanCoder::decompress(data);

    // 4) pipe K38 mülkiyeti: restore(store(d)) == d - küçük girdilerde store her zaman
    //    başarılıdır (boyut limitleri yalnız büyük girdilerde); eşitlik bozulursa ASSERT
    //    çöker → fuzz mülkiyet ihlalini yakalar (kayıpsızlık TAMLIĞI).
    if data.len() <= 4096 {
        if let Some(bud) = store(data) {
            let back = restore(&bud).expect("geçerli konteyner restore edilebilir");
            assert_eq!(&back[..], data, "K38: restore(store(d)) == d ihlali");
        }
        // zstd mülkiyeti: store_zstd -> restore == d (V21, K38)
        if let Some(bud) = store_zstd(data) {
            let back = restore(&bud).expect("zstd konteyner restore edilebilir");
            assert_eq!(&back[..], data, "K38: zstd restore(store(d)) == d ihlali");
        }
        // Huffman roundtrip: new_compressed -> decode -> restore_original == d
        let chunks = structural_split_compact(StructuralKind::Binary, data, 128);
        if let Some(comp) = BudV2File::new_compressed(FormatCodec::Unknown, chunks.clone()) {
            if let Some(dec) = BudV2File::decode(&comp.encode()) {
                let back = dec.restore_original().expect("Huffman açma başarılı");
                assert_eq!(&back[..], data, "Huffman roundtrip kayıpsız olmalı");
            }
        }
    }

    // 5) PoR sınır güvenliği: rastgele blok seti + challenge → respond/verify panik'siz
    let blocks: Vec<Vec<u8>> = data.chunks(16).map(|c| c.to_vec()).collect();
    if !blocks.is_empty() {
        let key = PorKey::new(content_id(data));
        let ch = PorKey::challenge(blocks.len() as u64, 4, 7);
        if let Some(resp) = key.respond(&blocks, &ch) {
            let _ = key.verify(&blocks, &ch, &resp);
        }
        // sınır dışı indeksli challenge → respond None, PANİK YOK
        let bad = PorChallenge { indices: vec![999_999], nonce: [0u8; 32] };
        let _ = key.respond(&blocks, &bad);
    }

    // 6) yapısal parçalama tüm türlerde kayıpsız (split+join == d)
    for kind in [
        StructuralKind::Json,
        StructuralKind::Csv,
        StructuralKind::Log,
        StructuralKind::Text,
        StructuralKind::Binary,
    ] {
        let chunks = structural_split(kind, data);
        let joined = structural_join(kind, &chunks);
        assert_eq!(&joined[..], data, "yapısal parçalama kayıpsız (K38): {kind:?}");
        let _ = structural_split_compact(kind, data, 64 * 1024);
    }
});
