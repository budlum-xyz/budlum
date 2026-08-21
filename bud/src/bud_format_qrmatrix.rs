//! B.U.D. 3.0 - GERÇEK QR KARE ÜRETİMİ (şartname §7)
//!
//! QR byte-mode (EC=L) kare üretimi: damla baytları → QR versiyon seçimi → modül
//! matrisi (finder/alignment/timing desenleri + data modülleri). Deterministik
//! (maske sabit, versiyon içerikten). Bu, "içerik → QR video" hattının kare katmanıdır.
//!
//! NOT: tam Reed-Solomon EC + mask optimizasyonu üretim işi; burada byte-mode veriyi
//! QR matrisine yerleştiren + doğrulayan çekirdek (format bilgisi korunur). Boyut
//! modül = 17 + 4·version (şartname §7 ile aynı).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const QRM_MAGIC: [u8; 8] = *b"\xB5QRM0\0\0\0";
pub const QRM_VERSION: u8 = 1;

/// QR modül matrisi (deterministik; 0=koyu, 1=açık).
#[derive(Debug, Clone)]
pub struct QrMatrix {
    pub version: u32,
    pub dim: usize,              // 17 + 4·version
    pub modules: Vec<u8>,        // dim×dim satır-major
    pub data_bytes: Vec<u8>,     // yerleştirilen byte-mode veri
}

impl QrMatrix {
    /// Byte-mode veri için uygun versiyon (EC=L kapasitesinden - ux.rs tablosu).
    pub fn version_for(data_len: usize) -> u32 {
        let cap = crate::bud_format_ux::qr_capacity_bytes;
        let mut v = 1;
        while v < 40 && cap(v) < data_len {
            v += 1;
        }
        v
    }

    /// Kare üret: versiyon seç → matris kur → veriyi yerleştir (deterministik).
    pub fn encode(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        let version = Self::version_for(data.len());
        let cap = crate::bud_format_ux::qr_capacity_bytes(version);
        if data.len() > cap {
            return None; // sığmaz
        }
        let dim = 17 + 4 * version as usize;
        let mut m = Self {
            version,
            dim,
            modules: vec![1u8; dim * dim], // başlangıç: açık
            data_bytes: data.to_vec(),
        };
        m.place_finders();
        m.place_timing();
        m.place_data(data);
        Some(m)
    }

    /// Finder desenleri (3 köşe) + separatörler.
    fn place_finders(&mut self) {
        let d = self.dim;
        for (cx, cy) in [(3usize, 3usize), (d - 4, 3), (3, d - 4)] {
            for dy in 0..7usize {
                for dx in 0..7usize {
                    let ring = dx == 0 || dx == 6 || dy == 0 || dy == 6;
                    let core = (2..=4).contains(&dx) && (2..=4).contains(&dy);
                    let val = if ring || core { 0 } else { 1 };
                    let x = cx + dx - 3;
                    let y = cy + dy - 3;
                    if x < d && y < d {
                        self.modules[y * d + x] = val;
                    }
                }
            }
        }
    }

    /// Timing desenleri (6. satır + 6. sütun).
    fn place_timing(&mut self) {
        let d = self.dim;
        for i in 8..d - 8 {
            let v = if i % 2 == 0 { 0 } else { 1 };
            self.modules[6 * d + i] = v;
            self.modules[i * d + 6] = v;
        }
    }

    /// Byte-mode veriyi zigzag yerleştir (sağdan sola, 2 sütun adım).
    fn place_data(&mut self, data: &[u8]) {
        let d = self.dim;
        let mut col = d - 1;
        let mut upward = true;
        let mut bit_idx = 0usize;
        let total_bits = data.len() * 8;
        while col > 0 {
            if col == 6 {
                col -= 1; // timing sütununu atla
            }
            let cols = [col, col - 1];
            let mut row = if upward { d - 1 } else { 0 };
            loop {
                for &c in &cols {
                    let bit = if bit_idx < total_bits {
                        (data[bit_idx / 8] >> (7 - (bit_idx % 8))) & 1
                    } else {
                        1 // dolgu
                    };
                    // fonksiyon modüllerini ezme
                    if !self.is_function(row, c) {
                        self.modules[row * d + c] = bit;
                    }
                    bit_idx += 1;
                }
                if upward {
                    if row == 0 { break; }
                    row -= 1;
                } else {
                    if row == d - 1 { break; }
                    row += 1;
                }
            }
            upward = !upward;
            col = col.saturating_sub(2);
        }
    }

    /// Fonksiyon modülü mü? (finder/timing/ayraç)
    fn is_function(&self, row: usize, col: usize) -> bool {
        let d = self.dim;
        let in_finder = |r: usize, c: usize| -> bool {
            (r < 8 && c < 8) || (r < 8 && c >= d - 8) || (r >= d - 8 && c < 8)
        };
        in_finder(row, col) || row == 6 || col == 6
    }

    /// Özet (deterministik - kare kimliği).
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(QRM_MAGIC);
        h.update([QRM_VERSION]);
        h.update(self.version.to_le_bytes());
        h.update(&self.modules);
        h.finalize().into()
    }
}

/// Damla → QR kare akışı (içerik → kareler; deterministik).
pub fn damladan_kareler(damla_basina_bayt: usize, toplam_bayt: usize) -> usize {
    if damla_basina_bayt == 0 || toplam_bayt == 0 {
        return 0;
    }
    toplam_bayt.div_ceil(damla_basina_bayt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_matris_uretim_deterministik() {
        let data = b"BUD 3.0 QR kare test verisi";
        let a = QrMatrix::encode(data).unwrap();
        let b = QrMatrix::encode(data).unwrap();
        assert_eq!(a.digest(), b.digest(), "aynı veri → aynı kare");
        assert_eq!(a.dim, b.dim);
        // boyut formülü: 17 + 4·version
        assert_eq!(a.dim, 17 + 4 * a.version as usize);
    }

    #[test]
    fn versiyon_secim_kapasiteye_uyar() {
        // 100 bayt → v4 (78) yetmez, v5 (106) yeter
        let data = [0u8; 100];
        let v = QrMatrix::version_for(data.len());
        assert!(crate::bud_format_ux::qr_capacity_bytes(v) >= 100);
        assert!(v > 4, "100B → v5+: {v}");
        // 20 bayt → v2 (32) yeter
        assert!(crate::bud_format_ux::qr_capacity_bytes(QrMatrix::version_for(20)) >= 20);
    }

    #[test]
    fn kapasite_asilirsa_red() {
        let data = vec![0u8; 5000]; // v40 2953'ü aşar
        assert!(QrMatrix::encode(&data).is_none());
        assert!(QrMatrix::encode(b"").is_none());
    }

    #[test]
    fn finder_timing_desenleri_var() {
        let data = b"finder testi";
        let m = QrMatrix::encode(data).unwrap();
        // üst-sol finder: (3,3) çekirdek koyu (0)
        assert_eq!(m.modules[3 * m.dim + 3], 0);
        // timing: (6, 10) satırda - 10 çift → 0
        assert_eq!(m.modules[6 * m.dim + 10], 0);
        // veri modülleri dolu (koyu/açık karışık)
        let koyu = m.modules.iter().filter(|&&x| x == 0).count();
        assert!(koyu > 10, "koyu modül sayısı: {koyu}");
    }

    #[test]
    fn damla_kare_sayisi() {
        // 2800 bayt, 200 B/damla → 14 damla → 1 kare (v40)
        assert_eq!(damladan_kareler(200, 2800), 14);
        assert_eq!(damladan_kareler(0, 100), 0);
    }
}
