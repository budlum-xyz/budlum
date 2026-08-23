//! B.U.D. 2.0 - WIRE FORMAT SÜRÜMLEME + GOLDEN VECTORS (optik transfer codec'i)
//!
//! Alınan desen (2026-08-16, optik aktarım codec incelemesi):
//! - Wire format version byte: her .bud, format sürümünü taşır.
//! - must-understand / ignorable bayraklar: eski okuyucu yeni bir alan gördüğünde
//!   "anlamak zorunda" alanı görürse RED (kayıpsızlık/doğruluk korunur), "yok sayılabilir"
//!   alanı görürse güvenle atlar (geriye uyumluluk).
//! - GOLDEN VECTORS: deterministik girdi→çıktı sabitleri; sürüm değişimi golden'ı kırarsa
//!   bilinçli karar istenir (uydurma değil, kanıtlı).
//! - CONFORMANCE: aynı girdi, aynı codec, aynı sürüm → AYNI baytlar (determinizm kapısı).
//!
//! B.U.D. etkisi: .bud konteyner formatı EVRİLEBİLİR ama kayıpsızlık/determinizm korunur;
//! eski cihaz yeni .bud'u ya reddeder (must) ya da güvenle okur (ignorable).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const WIRE_MAGIC: [u8; 8] = *b"\xB5WIRE\0\0\0";
pub const WIRE_VERSION: u8 = 1;

/// Alan anlama gereksinimi (wire v3 deseni).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldPolicy {
    MustUnderstand, // eski okuyucu görürse RED - doğruluk/kayıpsızlık kritik
    Ignorable,      // eski okuyucu güvenle atlar - geriye uyumluluk
}

/// Format alanı tanımı (sürümleme sözleşmesi).
#[derive(Debug, Clone)]
pub struct WireField {
    pub id: u8,
    pub policy: FieldPolicy,
    pub since_version: u8,
}

/// Wire format sürüm sözleşmesi: hangi alan hangi sürümden itibaren var.
pub const WIRE_CONTRACT: &[WireField] = &[
    WireField {
        id: 0x01,
        policy: FieldPolicy::MustUnderstand,
        since_version: 1,
    }, // content_id (K3)
    WireField {
        id: 0x02,
        policy: FieldPolicy::MustUnderstand,
        since_version: 1,
    }, // chunk_codec
    WireField {
        id: 0x03,
        policy: FieldPolicy::MustUnderstand,
        since_version: 1,
    }, // erasure_param
    WireField {
        id: 0x04,
        policy: FieldPolicy::Ignorable,
        since_version: 1,
    }, // mime (kayıpsızlık dışı)
    WireField {
        id: 0x05,
        policy: FieldPolicy::Ignorable,
        since_version: 1,
    }, // width/height (KF2 meta)
    WireField {
        id: 0x06,
        policy: FieldPolicy::Ignorable,
        since_version: 2,
    }, // future: culling_plan
    WireField {
        id: 0x07,
        policy: FieldPolicy::MustUnderstand,
        since_version: 3,
    }, // future: pq_signature (güvenlik)
];

/// Okuyucu sürümü verilen bir alanı anlayabilir mi?
/// - alan sürümü okuyucu sürümüne eşit/küçükse → anlar.
/// - alan daha yeni ve MustUnderstand ise → RED (güvenli red).
/// - alan daha yeni ve Ignorable ise → atla (uyumlu).
pub fn field_verdict(field: &WireField, reader_version: u8) -> Result<FieldPolicy, &'static str> {
    if field.since_version <= reader_version {
        Ok(field.policy) // anlıyor - kural çağıranda
    } else if field.policy == FieldPolicy::MustUnderstand {
        Err("K-WIRE: bilinmeyen zorunlu alan - sürüm yükselt")
    } else {
        Ok(FieldPolicy::Ignorable) // atlanabilir
    }
}

/// Konteyner sürüm denetimi: `.bud` başlığındaki sürüm, codec'in desteklediğiyle uyumlu mu?
pub fn version_compatible(container_version: u8, codec_version: u8) -> bool {
    container_version <= codec_version
}

/// GOLDEN VECTOR: deterministik girdi → sabit özet (sürüm sabitlemesi).
/// Bu sabitler "aynı girdi + aynı sürüm → AYNI çıktı"yı kanıtlar (İ5).
pub struct GoldenVector {
    pub name: &'static str,
    pub input: &'static [u8],
    pub expected_digest: [u8; 32],
}

/// Golden vectors tablosu (deterministik; sürüm değişimi bilinçli günceller).
pub const GOLDEN_VECTORS: &[GoldenVector] = &[
    GoldenVector {
        name: "empty-content-v1",
        input: b"",
        expected_digest: [
            0x7a, 0x20, 0x33, 0x86, 0x70, 0xab, 0x69, 0x5d, 0xa0, 0xaa, 0x6e, 0xdc, 0xd5, 0x63,
            0xd7, 0x74, 0x12, 0xe0, 0x97, 0x32, 0x9a, 0x1a, 0xd2, 0x0b, 0xec, 0xf6, 0xc3, 0x4f,
            0xaa, 0x60, 0x9f, 0x00,
        ],
    },
    GoldenVector {
        name: "hello-v1",
        input: b"hello budlum",
        expected_digest: [
            0x2d, 0xfb, 0x6e, 0x9f, 0xad, 0x00, 0xc6, 0x26, 0x6f, 0x1d, 0x88, 0x67, 0x1e, 0xbf,
            0xe7, 0xb0, 0x53, 0x89, 0x14, 0x18, 0xe1, 0x85, 0xd1, 0x72, 0x27, 0x78, 0xd5, 0x40,
            0x8c, 0x42, 0xab, 0x73,
        ],
    },
    GoldenVector {
        name: "wire-contract-v1",
        input: b"wire-contract-v1",
        expected_digest: [
            0x5d, 0xd8, 0xce, 0x41, 0x92, 0x96, 0x40, 0x04, 0x9f, 0xb8, 0x8a, 0x0f, 0xf7, 0x21,
            0x60, 0x77, 0xda, 0x38, 0x88, 0xda, 0x8a, 0x0e, 0xe3, 0xd6, 0x67, 0xe4, 0x43, 0xa8,
            0xdd, 0x99, 0x22, 0x2a,
        ],
    },
];

fn golden(input: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_GOLDEN_V1");
    h.update((input.len() as u64).to_le_bytes());
    h.update(input);
    h.finalize().into()
}

/// Conformance: golden vector hâlâ doğru mu? (determinizm kapısı)
pub fn conformance_pass() -> bool {
    GOLDEN_VECTORS
        .iter()
        .all(|g| golden(g.input) == g.expected_digest)
}

/// Yeni alan ekleme kuralı: sürüm contract'ına uymalı (test ile zorlanır).
pub fn contract_ok(fields: &[WireField]) -> bool {
    // id benzersiz + since_version >= 1
    let mut ids: Vec<u8> = fields.iter().map(|f| f.id).collect();
    ids.sort_unstable();
    ids.windows(2).all(|w| w[0] != w[1]) && fields.iter().all(|f| f.since_version >= 1)
}

pub fn wire_digest() -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(WIRE_MAGIC);
    h.update([WIRE_VERSION]);
    for f in WIRE_CONTRACT {
        h.update([f.id]);
        h.update([match f.policy {
            FieldPolicy::MustUnderstand => 0,
            FieldPolicy::Ignorable => 1,
        }]);
        h.update([f.since_version]);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn must_understand_yeni_alan_reddedilir() {
        // okuyucu v1, alan v3 (pq_signature, MustUnderstand) → RED
        let pq = WIRE_CONTRACT.iter().find(|f| f.id == 0x07).unwrap();
        assert!(
            field_verdict(pq, 1).is_err(),
            "v1 okuyucu pq alanını anlamaz → RED"
        );
        // okuyucu v3 → anlar (Ok döner)
        assert!(field_verdict(pq, 3).is_ok());
    }

    #[test]
    fn ignorable_yeni_alan_atlanir() {
        // okuyucu v1, alan v2 (culling_plan, Ignorable) → Ok(Ignorable) = atla
        let cull = WIRE_CONTRACT.iter().find(|f| f.id == 0x06).unwrap();
        assert_eq!(field_verdict(cull, 1).unwrap(), FieldPolicy::Ignorable);
    }

    #[test]
    fn eski_alan_her_zaman_anlasilir() {
        let cid = WIRE_CONTRACT.iter().find(|f| f.id == 0x01).unwrap();
        assert!(field_verdict(cid, 1).is_ok());
        assert!(field_verdict(cid, 3).is_ok());
    }

    #[test]
    fn sürüm_uyumluluğu() {
        assert!(version_compatible(1, 3));
        assert!(
            !version_compatible(4, 3),
            "container sürümü codec'ten büyük → RED"
        );
        assert!(version_compatible(3, 3));
    }

    #[test]
    fn golden_vectors_deterministik() {
        assert!(
            conformance_pass(),
            "golden vector kırıldı - sürüm değişimi bilinçli olmalı"
        );
        // aynı girdi → aynı özet
        assert_eq!(golden(b"hello budlum"), golden(b"hello budlum"));
        assert_ne!(golden(b"hello budlum"), golden(b"hello budlumX"));
    }

    #[test]
    fn contract_benzersiz_id() {
        assert!(contract_ok(WIRE_CONTRACT));
        let bozuk = vec![
            WireField {
                id: 1,
                policy: FieldPolicy::MustUnderstand,
                since_version: 1,
            },
            WireField {
                id: 1,
                policy: FieldPolicy::Ignorable,
                since_version: 2,
            }, // çift id
        ];
        assert!(!contract_ok(&bozuk));
        let sifir = vec![WireField {
            id: 2,
            policy: FieldPolicy::Ignorable,
            since_version: 0,
        }];
        assert!(!contract_ok(&sifir), "since_version >= 1 olmalı");
    }

    #[test]
    fn wire_digest_deterministik() {
        assert_eq!(wire_digest(), wire_digest());
    }
}
