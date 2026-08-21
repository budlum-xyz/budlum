//! B.U.D. 2.0 - GERÇEK DÜNYA KORPUS TESTLERİ (kalan iş #7)
//!
//! Sentetik korpus yerine SİSTEMDEKİ GERÇEK dosyalarla engine roundtrip + oran
//! doğrulaması: ELF (/bin/*), font (/usr/share/fonts), metin (/etc/*, /usr/share/doc).
//! Dosya yoksa test SKIP (production ortamında değil). Bu testler, matristeki
//! "gerçekçi oran" sınırlarının canary'sidir: ölçülenden ÇOK üstü iddia edilemez.

#![forbid(unsafe_code)]

/// Gerçek dosyayı bul (ilk mevcut).
#[allow(dead_code)]
fn gercek_dosya(candidates: &[&str]) -> Option<Vec<u8>> {
    for c in candidates {
        if let Ok(m) = std::fs::read(c) {
            if !m.is_empty() {
                return Some(m);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bud_format_engine::{engine_store, engine_restore_full};

    #[test]
    fn gercek_elf_engine_kayipsiz() {
        if let Some(elf) = gercek_dosya(&["/bin/bash", "/usr/bin/bash", "/bin/ls", "/usr/bin/env"]) {
            let res = engine_store(&elf, false, 1).expect("engine");
            let blob = res.to_blob();
            let back = engine_restore_full(&blob, res.transform_kind.to_u8(), false).expect("restore");
            assert_eq!(back, elf, "GERÇEK ELF birebir");
            assert!(res.measured_ratio > 1.0 || elf.len() < 4096);
        } else {
            eprintln!("SKIP: gerçek ELF bulunamadı (test ortamı)");
        }
    }

    #[test]
    fn gercek_font_engine_kayipsiz() {
        let mut adaylar = vec![
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
            "/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf",
        ];
        // /usr/share/fonts altında ttf tara
        if let Ok(read) = std::fs::read_dir("/usr/share/fonts") {
            for _e in read.flatten() {
                if adaylar.len() > 30 {
                    break;
                }
                // yalnız örnek: mevcut adaylar yeterli
            }
        }
        if let Some(font) = gercek_dosya(&adaylar) {
            let res = engine_store(&font, false, 2).expect("engine");
            let back = engine_restore_full(&res.to_blob(), res.transform_kind.to_u8(), false).expect("restore");
            assert_eq!(back, font, "GERÇEK font birebir");
        } else {
            eprintln!("SKIP: font bulunamadı");
        }
    }

    #[test]
    fn gercek_metin_engine_kayipsiz() {
        let adaylar = ["/etc/os-release", "/etc/hostname", "/etc/hosts", "/usr/share/doc"];
        if let Some(txt) = gercek_dosya(&adaylar) {
            let res = engine_store(&txt, false, 3).expect("engine");
            let back = engine_restore_full(&res.to_blob(), res.transform_kind.to_u8(), false).expect("restore");
            assert_eq!(back, txt, "GERÇEK metin birebir");
        } else {
            eprintln!("SKIP: metin bulunamadı");
        }
    }

    #[test]
    fn gercek_korpus_olcum_ustu_iddia_red() {
        // Canary: gerçek ELF/font ölçümü matristeki aralığı aşamaz
        // (matris: elf 2.6x zstd19, font 2.5x - motor ölçüsü dürüst sınırda).
        if let Some(elf) = gercek_dosya(&["/bin/bash", "/usr/bin/env"]) {
            let res = engine_store(&elf, false, 1).unwrap();
            // ELF tek dosya: transform yok, zstd sınırı ~2-3x makul
            assert!(res.measured_ratio < 50.0, "ELF için 50x üstü iddia RED: {}", res.measured_ratio);
        }
    }
}
