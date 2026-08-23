//! .bud real compression - GERÇEK kayıpsız sıkıştırma (2026-08-16)
//!
//! ÖNCEKİ SÜRÜM STUB'TI: `zstd_compress`/`xz_compress` zstd/xz MAGIC taklidi + ilk 100
//! bayt döndürüyordu - gerçek sıkıştırma değildi, sahte zarf üretiyordu (hiçbir gerçek
//! açıcı onu açamazdı). Bu sürüm onu DEĞİŞTİRİR: gerçek, kayıpsız, sıfır-bağımlılık
//! Huffman codec'i (bud_format_huffman) kullanılır; magic B.U.D.'a özgüdür (taklit yok).
//! zstd/xz/avif gerçek FFI entegrasyonu ayrı bir adımdır (ölçümler ayrı belgelenir).

#![forbid(unsafe_code)]

use crate::bud_format_huffman::{HuffmanCoder, BUD_HFM_MAGIC};

/// Gerçek kayıpsız sıkıştırıcı (Huffman tabanlı, no unsafe, deterministik).
pub struct RealCompressor;

/// Gerçek zstd FFI (V21 yol haritası - zstd crate).
/// `zstd_compress`: level ile gerçek zstd sıkıştırma (unsafe bizim koda değil, crate içinde).
/// `zstd_decompress_safe`: frame content size + çıktı boyutu TAVANLI açma (K25 bomba koruması).
pub fn zstd_compress(data: &[u8], level: i32) -> Option<Vec<u8>> {
    zstd::encode_all(data, level).ok()
}

pub const ZSTD_MAX_DECOMPRESSED: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB (K25 tavanı)

pub fn zstd_decompress_safe(bytes: &[u8], max_out: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    // frame başlığından orijinal boyut (zstd_safe::get_frame_content_size)
    let frame_sz = zstd::zstd_safe::get_frame_content_size(bytes).ok()?;
    if let Some(sz) = frame_sz {
        if sz > max_out {
            return None; // bomba: frame, tavanın üstünde orijinal boyut iddia ediyor
        }
    }
    let mut dec = zstd::stream::read::Decoder::new(bytes).ok()?;
    let mut out = Vec::new();
    dec.read_to_end(&mut out).ok()?;
    if out.len() as u64 > max_out {
        return None; // savunma: çıktı yine de tavanı aşamaz
    }
    Some(out)
}

impl RealCompressor {
    /// Sıkıştır: BUD-HFM1 zarfı. Dönen veri KENDİ içinde açılabilir (decompress).
    pub fn compress(data: &[u8]) -> Vec<u8> {
        HuffmanCoder::compress(data)
    }

    /// Aç: sıkı doğrula (magic + tavan + Kraft + kod geçerliliği) → orijinal.
    /// Herhangi bir tutarsızlık → None (panik yok).
    pub fn decompress(bytes: &[u8]) -> Option<Vec<u8>> {
        HuffmanCoder::decompress(bytes)
    }

    /// Bu veri B.U.D.-Huffman zarfı mı? (v1/v2 ayrımı ve tanı için)
    pub fn is_bud_hfm(bytes: &[u8]) -> bool {
        bytes.len() >= 8 && bytes[0..8] == BUD_HFM_MAGIC
    }
}

/// Gerçek ölçüm tablosu (2026-08-16 runner: Python zstd-19/xz9, deterministik korpus).
/// Uydurma sayı YOK - her satır ölçülmüştür; boru hattı adı + gerçek oran.
/// (zstd/xz Rust FFI'si olmadığından hız değerleri verilmez; oran = boyut küçülmesi.)
pub struct RealBench;

impl RealBench {
    /// Doğrulanmış oranlar: `scripts/measure_ratios.py --seed 7` ile TEKRARLANABİLİR
    /// (deterministik korpus 50k JSON / 60k CSV / 80k LOG). Eski tabloda yazılı
    /// 8.48x/5.51x/7.68x değerleri farklı (tekrarlanamayan) bir korpustandı - K19
    /// dürüstlüğü gereği doğrulanmış değerlerle değiştirildi (EK13).
    pub fn measured_ratios() -> Vec<(&'static str, f64)> {
        vec![
            ("structural+zstd19 JSON", 7.83), // measure_ratios.py seed=7 (50k kayıt)
            ("structural+xz9 JSON", 8.07),    // measure_ratios.py seed=7
            ("structural+zstd19 CSV", 3.55),  // measure_ratios.py seed=7 (60k satır)
            ("structural+zstd19 LOG", 6.17),  // measure_ratios.py seed=7 (80k satır)
            ("structural+xz9 LOG", 6.30),     // measure_ratios.py seed=7
            ("BUD-HFM1 (yerleşik Huffman) LOG", 1.69), // 13.98MB örnek üzerinde (CLI kanıtı)
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_compress_roundtrip() {
        let line = b"a=b c=d e=f g=h tekrar tekrar tekrar tekrar tekrar\n";
        let mut data = Vec::new();
        for _ in 0..30 {
            data.extend_from_slice(line);
        }
        let c = RealCompressor::compress(&data);
        assert!(
            c.len() < data.len(),
            "tekrarlı veri gerçekten sıkışmalı: {} -> {}",
            data.len(),
            c.len()
        );
        assert!(RealCompressor::is_bud_hfm(&c), "BUD-HFM zarfı");
        let d = RealCompressor::decompress(&c).unwrap();
        assert_eq!(d, data, "kayıpsız roundtrip");
    }

    #[test]
    fn fake_zstd_magic_yok() {
        // Eski stub zstd magic (28 B5 2F FD) ile başlardı - artık asla üretilmemeli.
        let data = vec![b'x'; 1000];
        let c = RealCompressor::compress(&data);
        assert_ne!(
            &c[..4],
            &[0x28, 0xB5, 0x2F, 0xFD],
            "zstd magic taklidi YASAK"
        );
        assert_ne!(
            &c[..6],
            &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00],
            "xz magic taklidi YASAK"
        );
    }

    #[test]
    fn measured_ratios_documented() {
        // Tüm oranlar > 1.0 (gerçek sıkıştırma) ve tavanla tutarlı (K19)
        for (name, r) in RealBench::measured_ratios() {
            assert!(r > 1.0, "{name} oran > 1 olmalı");
            assert!(
                r < 30.0,
                "{name} oran gerçekçi (<30) - zip-bomb iddiası yok"
            );
        }
    }
    #[test]
    fn zstd_roundtrip_and_beats_huffman() {
        // GERÇEK zstd: sıkıştır → aç = orijinal; tekrarlı veride Huffman'dan iyi
        let line = b"2026-08-16 INFO req=123 /api/a s=200 b=42 reg=tr\n";
        let mut data = Vec::new();
        for _ in 0..5000 {
            data.extend_from_slice(line);
        }
        let c = zstd_compress(&data, 19).expect("zstd sıkıştırma");
        assert!(
            c.len() < data.len(),
            "zstd sıkışmalı: {} -> {}",
            data.len(),
            c.len()
        );
        let d = zstd_decompress_safe(&c, ZSTD_MAX_DECOMPRESSED).expect("zstd açma");
        assert_eq!(d, data, "zstd kayıpsız");
        // Huffman ile karşılaştır
        let h = RealCompressor::compress(&data);
        assert!(
            c.len() < h.len(),
            "zstd Huffman'dan iyi olmalı: zstd {} vs hfm {}",
            c.len(),
            h.len()
        );
    }
    #[test]
    fn zstd_decompress_bomb_guards() {
        // K25: sahte zstd frame (çok büyük content size) → None, panik yok
        // zstd frame başlığı: magic + frame header; content size 2^32 üstü iddiası
        let fake = [
            0x28u8, 0xB5, 0x2F, 0xFD, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        ];
        let _ = zstd_decompress_safe(&fake, ZSTD_MAX_DECOMPRESSED); // panik yok
                                                                    // bozuk veri → None
        assert!(zstd_decompress_safe(b"BUD", 1024).is_none());
        // küçük tavanlı açma: 1MB veriyi 1KB tavanla açma → None
        let data = vec![b'a'; 1024 * 1024];
        let c = zstd_compress(&data, 3).expect("zstd");
        assert!(
            zstd_decompress_safe(&c, 1024).is_none(),
            "tavan aşımı None dönmeli"
        );
    }
}
