//! B.U.D. 2.0 Icat - Uçtan Uca Kayıpsız Boru Hattı (format algılama + konteyner)
//!
//! K38 sertleştirme: ham baytlardan .bud v2 konteynerine, oradan geriye.
//! `store(data) -> Option<Vec<u8>>` ve `restore(bytes) -> Option<Vec<u8>>` ile
//! KAYIPSIZLIK GARANTİSİ: `restore(store(d)) == d` HER `d` için (K38 mülkiyeti).
//!
//! Katman modeli:
//!   1. Format algılama (heuristik, deterministik) - yanlış algılama güvenlik sorunu
//!      DEĞİLDİR çünkü kayıpsızlık türden bağımsızdır; tür yalnız parça tanecikliğini
//!      (dedup/kanıt verimi) etkiler.
//!   2. Yapısal parçalama + compaction (K35: küçük-parça amplifikasyonuna karşı).
//!   3. BudV2File tam dosya: başlık + her parça content_id + bomba korumaları.
//!
//! Sıkıştırma bu katmanda DEĞİLDİR: uzman boru hattı (structural+zstd19 vb.) ayrı
//! adımdır ve runner'da ölçülür; bu modül bütünlük + kayıpsızlık + dedup-uyumluluğu
//! garanti eden konteyner katmanıdır.
//!
//! Kod: no unsafe, deterministik, mülkiyet testleriyle. #![forbid(unsafe_code)] korunur.

#![forbid(unsafe_code)]

use crate::bud_format_container::{BudV2File, FormatCodec, structural_split_compact};
use crate::bud_format_columnar::{ColumnarMode, columnar_decode, columnar_encode, columnar_to_blob};

/// Varsayılan compaction eşiği (K35): 64 KiB altı bitişik parçalar birleştirilir.
pub const DEFAULT_MIN_CHUNK: usize = 64 * 1024;

/// Format algılama (heuristik, deterministik, kayıpsızlıktan bağımsız).
/// Sıra: JSON (ilk anlamlı karakter `[`/`{`) → CSV (virgül+satır) → LOG (yıl başlangıçlı
/// satır) → Text (satır içeren) → Unknown (ikili). Yanlış eşleşme güvenli: parçalama
/// her türde kayıpsız (K38), yalnız taneciklik değişir.
pub fn detect(data: &[u8]) -> FormatCodec {
    if data.is_empty() {
        return FormatCodec::Unknown;
    }
    // JSON: baştaki boşlukları at, `[` veya `{` ile başla
    let t = String::from_utf8_lossy(data);
    let first = t.trim_start();
    if first.starts_with('[') || first.starts_with('{') {
        return FormatCodec::Json;
    }
    // CSV: virgül + satır içeren düz metin
    let mut comm = 0u32;
    let mut nl = 0u32;
    for b in data.iter().take(4096) {
        match b {
            b',' => comm += 1,
            b'\n' => nl += 1,
            _ => {}
        }
    }
    if comm > 0 && nl > 0 {
        return FormatCodec::Csv;
    }
    // LOG: ilk satır dört haneli yıl ile başlar (2026-...)
    if let Some(fl) = t.lines().next() {
        let fl = fl.trim_start();
        let b = fl.as_bytes();
        if b.len() >= 4
            && b[0].is_ascii_digit()
            && b[1].is_ascii_digit()
            && b[2].is_ascii_digit()
            && b[3].is_ascii_digit()
        {
            return FormatCodec::Log;
        }
    }
    if nl > 0 {
        return FormatCodec::Text;
    }
    // Son sinyal: tamamı yazdırılabilir ASCII (satır sonları dahil) ise düz metin.
    // Yanlış eşleşme güvenli - kayıpsızlık türden bağımsız (K38), yalnız taneciklik değişir.
    let printable = data
        .iter()
        .all(|b| (0x20..0x7F).contains(b) || *b == b'\n' || *b == b'\t' || *b == b'\r');
    if printable {
        return FormatCodec::Text;
    }
    FormatCodec::Unknown // Binary (jpeg/png/mp4/pdf vb. tespit edilemezse binary varsayılır)
}

/// Kaydet (RAW): algıla → yapısal parçala (compact) → BudV2File serileştir.
pub fn store(data: &[u8]) -> Option<Vec<u8>> {
    store_with_min(data, DEFAULT_MIN_CHUNK)
}

/// `store` ile aynı, compaction eşiği parametreli (test/esneklik için).
pub fn store_with_min(data: &[u8], min_chunk: usize) -> Option<Vec<u8>> {
    let codec = detect(data);
    let kind = codec.structural_kind();
    let chunks = structural_split_compact(kind, data, min_chunk);
    let file = BudV2File::new(codec, chunks)?;
    Some(file.encode())
}

/// Kaydet (HUFFMAN): her parça gerçek kayıpsız Huffman ile sıkıştırılır - .bud dosyası
/// tekrarlı içerikte GERÇEKTEN küçülür (K38). Kayıpsızlık: `restore` orijinali döner.
pub fn store_compressed(data: &[u8]) -> Option<Vec<u8>> {
    store_compressed_with_min(data, DEFAULT_MIN_CHUNK)
}

/// `store_compressed` ile aynı, compaction eşiği parametreli.
pub fn store_compressed_with_min(data: &[u8], min_chunk: usize) -> Option<Vec<u8>> {
    let codec = detect(data);
    let kind = codec.structural_kind();
    let chunks = structural_split_compact(kind, data, min_chunk);
    let file = BudV2File::new_compressed(codec, chunks)?;
    Some(file.encode())
}

/// Kaydet (ZSTD): her parça gerçek zstd level 19 ile sıkıştırılır (V21 yol haritası).
/// Huffman'dan iyi oran; açma K25 tavanıyla güvenli. Kayıpsızlık: `restore` orijinali döner.
pub fn store_zstd(data: &[u8]) -> Option<Vec<u8>> {
    store_zstd_with_min(data, DEFAULT_MIN_CHUNK)
}

/// `store_zstd` ile aynı, compaction eşiği parametreli.
pub fn store_zstd_with_min(data: &[u8], min_chunk: usize) -> Option<Vec<u8>> {
    let codec = detect(data);
    let kind = codec.structural_kind();
    let chunks = structural_split_compact(kind, data, min_chunk);
    let file = BudV2File::new_zstd(codec, chunks)?;
    Some(file.encode())
}

/// Geri yükle: sıkı doğrula + parçaları (RAW/Huffman/Zstd otomatik) aç + birleştir → ORİJİNAL.
/// KAYIPSIZ JSON COLUMNAR boru hattı (İcat): JSON dizisini sütunlara ayırıp zstd ile
/// sıkıştırılmış konteyner yazar. Exact → byte-identical (K38); OrderFree → kayıt kümesi
/// korunur (KF2) ve daha yüksek oran (ölçüm: 7.83x → 8.53x / 11.49x, seed=7).
/// Düzensiz JSON → None (kayıpsızlık korunur, çağıran ham yola düşer).
pub fn store_json_columnar(data: &[u8], mode: ColumnarMode, _min_chunk: usize) -> Option<Vec<u8>> {
    let col = columnar_encode(data, mode)?;
    let blob = columnar_to_blob(&col);
    let chunk = crate::bud_format_container::StructuralChunk {
        content_id: crate::bud_format_container::content_id(&blob),
        data: blob,
    };
    let file = BudV2File::new_zstd(FormatCodec::Json, vec![chunk])?;
    Some(file.encode())
}

/// Columnar konteynerden geri yükle: zstd aç → columnar decode → JSON.
pub fn restore_json_columnar(bytes: &[u8], mode: ColumnarMode) -> Option<Vec<u8>> {
    let file = BudV2File::decode(bytes)?;
    let raw = file.restore_original()?;
    let col = crate::bud_format_columnar::columnar_from_blob(&raw)?;
    if col.mode != mode {
        return None; // mod uyuşmazlığı → red
    }
    columnar_decode(&col)
}

pub fn restore(bytes: &[u8]) -> Option<Vec<u8>> {
    let file = BudV2File::decode(bytes)?;
    file.restore_original()
}

/// Parça sayısı (dedup/kanıt verimi izleme için yardımcı).
pub fn chunk_count(bytes: &[u8]) -> Option<usize> {
    BudV2File::decode(bytes).map(|f| f.chunks.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLES: &[&[u8]] = &[
        // JSON
        br#"[{"user":"u1","ts":"2026-08-16","a":"r","v":42}]"#,
        br#"{"tek":"nesne"}"#,
        br#"[1,2,3,4]"#,
        // CSV
        b"u,ts,a,v\nu1,2026-08-16,r,42\nu2,2026-08-16,w,7\n",
        b"a,b\n1,2\n",
        // LOG
        b"2026-08-16T10:00:00Z INFO req=1 /a s=200\n2026-08-16T10:01:00Z WARN req=2 /b s=404\n",
        // TEXT
        b"satir 1\nsatir 2\nsatir 3\n",
        b"tek satir sonu yok",
        // BINARY
        &[0x89, 0x50, 0x4E, 0x47, 0x00, 0x01, 0x02, 0xFF],
        b"",
    ];

    #[test]
    fn detect_classifies_samples() {
        // JSON
        assert_eq!(detect(SAMPLES[0]), FormatCodec::Json);
        assert_eq!(detect(SAMPLES[1]), FormatCodec::Json);
        assert_eq!(detect(SAMPLES[2]), FormatCodec::Json);
        // CSV
        assert_eq!(detect(SAMPLES[3]), FormatCodec::Csv);
        assert_eq!(detect(SAMPLES[4]), FormatCodec::Csv);
        // LOG
        assert_eq!(detect(SAMPLES[5]), FormatCodec::Log);
        // TEXT
        assert_eq!(detect(SAMPLES[6]), FormatCodec::Text);
        assert_eq!(detect(SAMPLES[7]), FormatCodec::Text);
        // BINARY
        assert_eq!(detect(SAMPLES[8]), FormatCodec::Unknown);
        assert_eq!(detect(SAMPLES[9]), FormatCodec::Unknown);
    }

    #[test]
    fn store_restore_roundtrip_all_samples() {
        // K38: HER örnekte restore(store(d)) == d
        for (i, data) in SAMPLES.iter().enumerate() {
            let enc = store(data).unwrap_or_else(|| panic!("örnek {i} store edilemeli"));
            let dec = restore(&enc).unwrap_or_else(|| panic!("örnek {i} restore edilemeli"));
            assert_eq!(&dec[..], *data, "örnek {i} kayıpsız olmalı");
            // her örnek en az 1 parça içermeli (boş girdi hariç 0 parça)
            let cc = chunk_count(&enc).unwrap();
            if data.is_empty() {
                assert_eq!(cc, 0);
            } else {
                assert!(cc >= 1, "örnek {i} en az 1 parça");
            }
        }
    }

    #[test]
    fn store_restore_property_random() {
        // Deterministik PRNG ile 150 rastgele girdi - kayıpsızlık mülkiyeti (K38)
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                self.0 = x;
                x.wrapping_mul(0x2545_F491_4F6C_DD1D)
            }
            fn below(&mut self, n: usize) -> usize {
                (self.next() % n as u64) as usize
            }
        }
        let mut rng = Rng(0x50_1F_2026_0816_0001);
        for round in 0..150u32 {
            let mut data = Vec::new();
            let n = rng.below(4000);
            for _ in 0..n {
                match rng.below(5) {
                    0 => data.push(b'\n'),
                    1 => data.push(b','),
                    2 => data.push(b'"'),
                    3 => data.push(b'a' + (rng.below(26) as u8)),
                    _ => data.push((rng.next() & 0xff) as u8),
                }
            }
            let enc = store_with_min(&data, 1 + rng.below(1024)).expect("store");
            let dec = restore(&enc).expect("restore");
            assert_eq!(dec, data, "round {round} kayıpsız olmalı");
        }
    }

    #[test]
    fn store_compressed_roundtrip_all_samples() {
        // K38: sıkıştırılmış boru hattı da HER örnekte kayıpsız; restore RAW/HFM/Zstd otomatik
        for (i, data) in SAMPLES.iter().enumerate() {
            let enc = store_compressed(data).unwrap_or_else(|| panic!("örnek {i} store edilemeli"));
            let dec = restore(&enc).unwrap_or_else(|| panic!("örnek {i} restore edilemeli"));
            assert_eq!(&dec[..], *data, "örnek {i} sıkıştırılmış turda kayıpsız");
            // zstd turu
            let encz = store_zstd(data).unwrap_or_else(|| panic!("örnek {i} store_zstd edilemeli"));
            let decz = restore(&encz).unwrap_or_else(|| panic!("örnek {i} restore_zstd edilemeli"));
            assert_eq!(&decz[..], *data, "örnek {i} zstd turunda kayıpsız");
        }
        // tekrarlı log: sıkıştırılmış .bud RAW'dan küçük olmalı (gerçek sıkışma)
        let line = b"2026-08-16 INFO req=1 /api/a s=200 b=42 reg=tr\n";
        let mut log = Vec::new();
        for _ in 0..2000 {
            log.extend_from_slice(line);
        }
        let raw = store(&log).unwrap();
        let comp = store_compressed(&log).unwrap();
        assert!(comp.len() < raw.len(), "sıkıştırılmış .bud küçülmeli: {} vs {}", raw.len(), comp.len());
        assert_eq!(restore(&comp).unwrap(), log);
        let z = store_zstd(&log).unwrap();
        assert!(z.len() < comp.len(), "zstd Huffman'dan küçük: {} vs {}", z.len(), comp.len());
        assert_eq!(restore(&z).unwrap(), log);
    }

    #[test]
    fn restore_rejects_corruption_and_bombs() {
        let data = br#"[{"a":1},{"a":2},{"a":3}]"#;
        let enc = store(data).unwrap();
        // payload kurcalama
        let mut t1 = enc.clone();
        *t1.last_mut().unwrap() ^= 0x40;
        assert!(restore(&t1).is_none());
        // truncation
        let mut t2 = enc.clone();
        t2.truncate(enc.len() - 2);
        assert!(restore(&t2).is_none());
        // çöp
        assert!(restore(&[0xFF; 64]).is_none());
        assert!(restore(&[]).is_none());
    }
}
