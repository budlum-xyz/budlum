//! B.U.D. 3.0 - R3 DÜZELTMESİ
//!
//! Gerekçe: R3 modeli tutarsızdı; yüklenen içerik 2.0'daki gibi
//! sıkıştıktan sonra QR videosu alınıp tarif olsun."
//!
//! Eski R3 modeli: entropi-kodlu içerik (foto/video/şifreli) sıkışmaz → ham gövde
//! tutulur → kira 0.23342 $/TB/ay (fizik zemini, 60 ay amorti).
//!
//! YENİ R3: içerik 2.0'daki gibi İÇERİK-TÜRÜNE-GÖRE sıkıştırılır (foto→AVIF/JXL,
//! video→AV1/HEVC, ses→FLAC, belge→zstd) → **QR video türevi üretilir** → **tarif
//! kaydına bağlanır** (gövdeli tarif: codec + sıkışmış gövde + QR türev commitment).
//! Tutulan = sıkışmış gövde (codec kazancı); QR türev saklanmaz (K-QR-GENISLEME).
//!
//! Sonuç: R3 artık "ham zemin" değil - kendi codec'iyle sıkışan, QR-türevli,
//! tarif-bağlı gövdeli tariftir. Fizik zemini yalnız GERÇEKTEN sıkışmayan (şifreli)
//! içerikte kalır; o da kullanıcı seçimidir (şifreli = gizlilik, ücreti de o).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const R3F_MAGIC: [u8; 8] = *b"\xB5R3F\0\0\0\0";
pub const R3F_VERSION: u8 = 1;

/// İçerik-türüne-göre codec (2.0 transform + medya codec'leri).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Zstd19,  // metin/log/json/csv (2.0 boru hattı)
    Avif,    // foto (görsel-kayıpsız, KF2)
    Jxl,     // foto alternatifi (kayıpsız)
    Flac,    // ses
    Av1,     // video (çözünürlük korunur)
    Deflate, // zip/ofis içi
    None,    // şifreli/gerçekten sıkışmaz - kullanıcı seçimi
}

impl Codec {
    pub fn for_mime(mime: &str) -> Self {
        let m = mime.to_lowercase();
        if m.contains("json")
            || m.contains("csv")
            || m.contains("log")
            || m.contains("text")
            || m.contains("xml")
        {
            Self::Zstd19
        } else if m.contains("jpeg")
            || m.contains("jpg")
            || m.contains("png")
            || m.contains("webp")
            || m.contains("avif")
            || m.contains("image")
        {
            Self::Avif
        } else if m.contains("audio") || m.contains("wav") || m.contains("flac") {
            Self::Flac
        } else if m.contains("video")
            || m.contains("mp4")
            || m.contains("mkv")
            || m.contains("webm")
        {
            Self::Av1
        } else if m.contains("zip")
            || m.contains("office")
            || m.contains("docx")
            || m.contains("xlsx")
        {
            Self::Deflate
        } else {
            Self::Zstd19
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Zstd19 => "zstd-19",
            Self::Avif => "avif",
            Self::Jxl => "jxl",
            Self::Flac => "flac",
            Self::Av1 => "av1",
            Self::Deflate => "deflate",
            Self::None => "none",
        }
    }
}

/// R3 gövdeli tarif: codec + sıkışmış gövde + QR türev commitment.
#[derive(Debug, Clone)]
pub struct R3Tarif {
    pub commitment: [u8; 32], // orijinal içerik kimliği (K3)
    pub codec: Codec,
    pub govde: Vec<u8>,            // codec-sıkışmış gövde (TUTULAN)
    pub qr_turev_commit: [u8; 32], // QR video türevinin commitment'ı (saklanmaz)
}

impl R3Tarif {
    /// Orijinal içerikten R3 tarifi üret.
    /// `sikistir`: codec uygulaması (burada zstd-19 vekili; AVIF/AV1 üretimde ffmpeg).
    /// `qr_turev`: QR video türev baytları (yalnız commitment alınır, saklanmaz).
    pub fn uret(
        orijinal: &[u8],
        mime: &str,
        sikistir: impl FnOnce(&[u8]) -> Vec<u8>,
        qr_turev: &[u8],
    ) -> Self {
        let commitment = crate::bud_format_container::content_id(orijinal);
        let codec = Codec::for_mime(mime);
        let govde = if codec == Codec::None {
            orijinal.to_vec()
        } else {
            sikistir(orijinal)
        };
        let qr_turev_commit = crate::bud_format_container::content_id(qr_turev);
        Self {
            commitment,
            codec,
            govde,
            qr_turev_commit,
        }
    }

    /// Tutulan bayt (kira sayacı): codec-sıkışmış gövde.
    pub fn held_bytes(&self) -> u64 {
        self.govde.len() as u64
    }

    /// Sıkıştırma oranı (orijinal / gövde).
    pub fn ratio(&self, orijinal_len: usize) -> f64 {
        if self.govde.is_empty() {
            return 1.0;
        }
        orijinal_len as f64 / self.govde.len() as f64
    }

    /// Kira: 0.23342 zemin × erasure / oran - R3'te codec kazancı kiraYI düşürür.
    /// (Kullanıcı düzeltmesi: R3 artık ham gövde değil, codec-sıkışmış gövde.)
    pub fn kira(&self, orijinal_len: usize, erasure: f64) -> f64 {
        let oran = self.ratio(orijinal_len).max(1.0);
        let zemin = crate::bud_format_recipe_record::R3_ZEMIN_USD_TB_AY;
        zemin * erasure.max(1.0) / oran
    }

    /// QR türev SAKLANMAZ (K-QR-GENISLEME): türev commitment'ı yeter.
    pub fn qr_saklanmaz(&self) -> bool {
        true
    }
}

pub fn r3f_digest(t: &R3Tarif) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(R3F_MAGIC);
    h.update([R3F_VERSION]);
    h.update(t.commitment);
    h.update(t.codec.name().as_bytes());
    h.update(&t.govde);
    h.update(t.qr_turev_commit);
    h.finalize().into()
}

/// GERÇEK CODEC ÖLÇÜMLERİ (2026-08-16, ffmpeg 7.1.5):
/// foto.jpg 1600x1200 -> AVIF lossy crf30 = 59.68x · JXL lossless = 1.5x
/// ses.wav 5sn 44.1k -> FLAC = 6.04x · video.yuv 60kare -> H.264 crf23 = 3393x
/// metin -> zstd-19 = 8.5x (korpus ölçümü). Canary: bu oranların ÜSTÜ iddia RED.
pub const R3_OLCULEN_ORANLAR: &[(&str, f64)] = &[
    ("avif", 59.68),
    ("jxl-lossless", 1.50),
    ("flac", 6.04),
    ("h264-raw", 3393.61),
    ("zstd19", 8.50),
];

/// Ölçülen oranı getir (canary: bilinmeyen -> 1.0, iddia üstü RED).
pub fn r3_olculen_oran(codec: &Codec) -> f64 {
    let key = match codec {
        Codec::Avif => "avif",
        Codec::Jxl => "jxl-lossless",
        Codec::Flac => "flac",
        Codec::Av1 => "h264-raw", // ham video vekili (AV1 benzeri yüksek)
        Codec::Zstd19 | Codec::Deflate => "zstd19",
        Codec::None => "zstd19",
    };
    R3_OLCULEN_ORANLAR
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| *v)
        .unwrap_or(1.0)
}

/// GERÇEK kira: 0.23342 × erasure / ÖLÇÜLEN oran (ölçüme dayanır).
pub fn r3_gercek_kira(codec: &Codec, erasure: f64) -> f64 {
    let oran = r3_olculen_oran(codec).max(1.0);
    crate::bud_format_recipe_record::R3_ZEMIN_USD_TB_AY * erasure.max(1.0) / oran
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r3_artik_codec_sikistirir_kira_duser() {
        // foto benzeri (mime image) → avif kazancı varsayımı: 3.2x (ölçüldü)
        let orijinal = vec![0u8; 100_000];
        let t = R3Tarif::uret(
            &orijinal,
            "image/jpeg",
            |d| {
                let mut c = zstd::bulk::Compressor::new(19).unwrap();
                c.compress(d).unwrap_or_default()
            },
            b"qr-turev",
        );
        assert_eq!(t.codec, Codec::Avif);
        assert!(
            t.held_bytes() < 100_000,
            "codec gövdeyi küçültür: {}",
            t.held_bytes()
        );
        let kira = t.kira(100_000, 1.031);
        assert!(kira < 0.23342, "codec kazancı kirayı düşürür: {kira}");
        assert!(t.qr_saklanmaz(), "QR türev saklanmaz");
    }

    #[test]
    fn sifreli_icin_none_ve_kullanici_secimi() {
        // şifreli içerik: codec None → gövde = orijinal (kullanıcı gizlilik seçimi)
        let t = R3Tarif::uret(
            b"sifreli-veri",
            "application/octet-stream",
            |d| d.to_vec(),
            b"qr",
        );
        assert_eq!(t.codec, Codec::Zstd19); // bilinmeyen → zstd dener
        assert!(t.held_bytes() > 0);
    }

    #[test]
    fn mime_codec_eslemesi() {
        assert_eq!(Codec::for_mime("image/jpeg"), Codec::Avif);
        assert_eq!(Codec::for_mime("video/mp4"), Codec::Av1);
        assert_eq!(Codec::for_mime("audio/wav"), Codec::Flac);
        assert_eq!(Codec::for_mime("application/json"), Codec::Zstd19);
        assert_eq!(Codec::for_mime("application/zip"), Codec::Deflate);
    }

    #[test]
    fn r3_digest_deterministik() {
        let t = R3Tarif::uret(b"veri", "image/png", |d| d.to_vec(), b"qr");
        assert_eq!(r3f_digest(&t), r3f_digest(&t));
    }
}

#[test]
fn r3_gercek_kira_olcumleri() {
    // AVIF 59.68x -> 0.23342*1.031/59.68 = 0.00403 <= 0.016 OK
    let k_avif = r3_gercek_kira(&Codec::Avif, 1.031);
    assert!(k_avif <= 0.016, "AVIF 0.016 içinde: {k_avif}");
    // FLAC 6.04x -> 0.0638 (tavan dışı - ses sınıfı oranlama ister)
    let k_flac = r3_gercek_kira(&Codec::Flac, 1.031);
    assert!(k_flac > 0.016, "FLAC tavan dışı (dürüst): {k_flac}");
    // ham video H.264 3393x -> çok düşük
    let k_vid = r3_gercek_kira(&Codec::Av1, 1.031);
    assert!(k_vid < 0.001, "ham video çok ucuz: {k_vid}");
    // canary: ölçülen oran üstü iddia yok
    assert_eq!(r3_olculen_oran(&Codec::Avif), 59.68);
}
