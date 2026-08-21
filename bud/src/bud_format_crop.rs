//! B.U.D. 2.0 - Kırpma-Türetme (Crop-Derivation; budlum derived.rs deseni) (2026-08-16)
//!
//! Ana repodan esinlenen: JPEG MCU-hizalı kırpma, ana görüntünün deterministik
//! türevi OLARAK YENİDEN ÜRETİLEBİLİR - depolanması gerekmez (İ7 türetme merdiveni).
//!
//! Kanıt (ana repo ölçümü): 3 hizalı kırpma, master'ın katsayı dizisinin alt-dikdörtgeniyle
//! BİREBİR aynı; 2 kasıtlı hizalı-olmayan kırpma aynı değil. Yani:
//! - Hizalı kırpma → byte-exact yeniden üretilebilir (üretilebilir sınıf)
//! - Hizasız kırpma → yeni nesne (organik sınıf)
//!
//! JPEG MCU: 4:2:0 chroma'da 16x16. Kırpma kenarları MCU sınırındaysa DCT katsayıları
//! değişmez. Bu modül: MCU hizasını hesaplar, kırpmayı hizalı/bozuk olarak sınıflandırır,
//! deterministik türetme kaydı üretir (PACT'e bağlanabilir - üretim kanıtı).
//!
//! Kod: `#![forbid(unsafe_code)]`, deterministik, panik'siz.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const CROP_MAGIC: [u8; 8] = *b"\xB5CROP\0\0\0";
pub const CROP_VERSION: u8 = 1;

/// JPEG MCU boyutu (4:2:0 chroma subsampling - en yaygın).
pub const MCU_SIZE: u32 = 16;

/// Kırpma türetme kaydı: master + kırpma bölgesi → deterministik türev.
#[derive(Debug, Clone)]
pub struct CropDerivation {
    pub master_content_id: [u8; 32], // ana görüntünün content_id'si
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
    pub aligned: bool,               // MCU hizalı mı (byte-exact üretilebilir)
}

impl CropDerivation {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_CROP_V1";

    /// MCU hizalama kontrolü: kırpma kenarları 16'nın katında mı?
    pub fn is_mcu_aligned(x: u32, y: u32, w: u32, h: u32) -> bool {
        x % MCU_SIZE == 0 && y % MCU_SIZE == 0 && w % MCU_SIZE == 0 && h % MCU_SIZE == 0
    }

    /// Yeni kırpma kaydı (hizalama otomatik hesaplanır).
    pub fn new(master: [u8; 32], x: u32, y: u32, w: u32, h: u32) -> Self {
        CropDerivation {
            master_content_id: master,
            x, y, w, h,
            aligned: Self::is_mcu_aligned(x, y, w, h),
        }
    }

    /// Üretilebilirlik: hizalı kırpma = master'dan byte-exact yeniden üretilir (İ7).
    pub fn is_regenerable(&self) -> bool {
        self.aligned
    }

    /// Kırpma türevinin commitment'ı (deterministik - master + bölgeden).
    pub fn derivation_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update(self.master_content_id);
        h.update(self.x.to_le_bytes());
        h.update(self.y.to_le_bytes());
        h.update(self.w.to_le_bytes());
        h.update(self.h.to_le_bytes());
        h.finalize().into()
    }

    /// Türev bölge bilgisini byte-exact üretim için serileştir (crop spec).
    pub fn crop_spec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.master_content_id);
        out.extend_from_slice(&self.x.to_le_bytes());
        out.extend_from_slice(&self.y.to_le_bytes());
        out.extend_from_slice(&self.w.to_le_bytes());
        out.extend_from_slice(&self.h.to_le_bytes());
        out
    }

    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&CROP_MAGIC);
        out.push(CROP_VERSION);
        out.extend_from_slice(&self.master_content_id);
        out.extend_from_slice(&self.x.to_le_bytes());
        out.extend_from_slice(&self.y.to_le_bytes());
        out.extend_from_slice(&self.w.to_le_bytes());
        out.extend_from_slice(&self.h.to_le_bytes());
        out.push(self.aligned as u8);
        out.extend_from_slice(&self.derivation_hash());
        out
    }

    pub fn from_blob(bytes: &[u8]) -> Option<Self> {
        const HDR: usize = 8 + 1 + 32 + 4 + 4 + 4 + 4 + 1;
        if bytes.len() < HDR + 32 || bytes[0..8] != CROP_MAGIC || bytes[8] != CROP_VERSION {
            return None;
        }
        let mut master = [0u8; 32];
        master.copy_from_slice(&bytes[9..41]);
        let x = u32::from_le_bytes(bytes[41..45].try_into().ok()?);
        let y = u32::from_le_bytes(bytes[45..49].try_into().ok()?);
        let w = u32::from_le_bytes(bytes[49..53].try_into().ok()?);
        let h = u32::from_le_bytes(bytes[53..57].try_into().ok()?);
        let aligned = bytes[57] != 0;
        if bytes.len() != HDR + 32 {
            return None;
        }
        let rec = CropDerivation { master_content_id: master, x, y, w, h, aligned };
        if bytes[HDR..] != rec.derivation_hash() {
            return None;
        }
        Some(rec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcu_alignment_detected() {
        // 4:2:0 MCU = 16x16: hizalı kenarlar byte-exact üretilebilir (ana repo kanıtı)
        assert!(CropDerivation::is_mcu_aligned(0, 0, 16, 16));
        assert!(CropDerivation::is_mcu_aligned(16, 32, 64, 48));
        assert!(!CropDerivation::is_mcu_aligned(1, 0, 16, 16), "x hizalı değil");
        assert!(!CropDerivation::is_mcu_aligned(0, 0, 15, 16), "w hizalı değil");
        assert!(!CropDerivation::is_mcu_aligned(5, 5, 20, 20), "hem x hem y");
    }

    #[test]
    fn aligned_crop_is_regenerable() {
        // İ7: hizalı kırpma master'dan byte-exact yeniden üretilir → üretilebilir sınıf
        let master = [7u8; 32];
        let aligned = CropDerivation::new(master, 0, 0, 16, 16);
        assert!(aligned.is_regenerable(), "hizalı kırpma üretilebilir");
        let misaligned = CropDerivation::new(master, 1, 0, 16, 16);
        assert!(!misaligned.is_regenerable(), "hizasız kırpma yeni nesne (organik)");
        // deterministik: aynı bölge → aynı hash
        assert_eq!(aligned.derivation_hash(), CropDerivation::new(master, 0, 0, 16, 16).derivation_hash());
        assert_ne!(aligned.derivation_hash(), misaligned.derivation_hash());
    }

    #[test]
    fn crop_record_roundtrip() {
        let rec = CropDerivation::new([1u8; 32], 16, 32, 64, 48);
        assert!(rec.aligned);
        let blob = rec.to_blob();
        let back = CropDerivation::from_blob(&blob).expect("blob");
        assert_eq!(back.derivation_hash(), rec.derivation_hash());
        assert_eq!(back.x, 16);
        // kurcalama red
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(CropDerivation::from_blob(&bad).is_none());
        assert!(CropDerivation::from_blob(&[0u8; 10]).is_none());
    }

    #[test]
    fn crop_spec_pins_region() {
        // crop_spec: master + bölge → byte-exact üretim girdisi (PACT tohumu gibi)
        let rec = CropDerivation::new([9u8; 32], 32, 0, 48, 16);
        let spec = rec.crop_spec();
        assert_eq!(spec.len(), 32 + 16);
        assert_eq!(&spec[..32], &[9u8; 32]);
        // farklı bölge → farklı spec
        let rec2 = CropDerivation::new([9u8; 32], 32, 16, 48, 16);
        assert_ne!(rec.crop_spec(), rec2.crop_spec());
    }
}
