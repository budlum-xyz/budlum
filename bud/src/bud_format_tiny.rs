//! B.U.D. 2.0 - KÜÇÜK NESNE SINIFI + SÖZLÜK VESAYETİ (fikirler3.0 Y5/Y4)
//!
//! Y5: PACT kaydı ~100-128 B iken < 1 KB nesnelerde kayıt yükü nesnenin kendisine
//! yaklaşır → "doğrudan blok içi" sınıf: küçük nesneler inline taşınır (dedup+delta
//! ile), eşik üstü PACT. Eşik `tiny_object_threshold` yönetişim parametresi.
//! Şifreli inline nesnelerde dedup YOK (tenant anahtarı) - Pollen strict kuralı.
//!
//! Y4: kohort sözlüğü bir PACT gibi zincirde yaşar; "sözlük bekçisi" kohortun
//! denetim turunu yapan bekçidir; sözlük baytı hiçbir yerde saklanmaz
//! (COVER(kohort_commitment, tohum) - yeniden eğitim CPU işi, İ4 bütçesinde).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const TINY_MAGIC: [u8; 8] = *b"\xB5TNY1\0\0\0";

/// Y5 varsayılan eşik (yönetişimce oylanabilir): 1 KB.
pub const TINY_OBJECT_THRESHOLD: usize = 1024;

/// Y5: nesne küçük mü? (inline blok içi sınıf)
pub fn is_tiny(size: usize, threshold: usize) -> bool {
    threshold > 0 && size <= threshold
}

/// Y5: inline nesne kaydı (blok gövdesine yazılır; dedup+delta ile sıkışır).
#[derive(Debug, Clone)]
pub struct TinyInline {
    pub content_id: [u8; 32],
    pub data: Vec<u8>,
    pub encrypted: bool, // Pollen strict: şifreli inline'da cross-tenant dedup YOK
}

/// Y5: inline nesne sığdırma - 128 KB blokta kaç nesne sığar (tavan koruması).
pub fn fits_in_block(tiny: &[TinyInline], block_capacity: usize) -> bool {
    let total: usize = tiny.iter().map(|t| 32 + t.data.len() + 1).sum();
    total <= block_capacity
}

/// Y4: sözlük vesayeti - COVER(kohort_commitment, tohum).
/// kohort_commitment = H(sıralı nesne hash'leri); sözlük baytı saklanmaz.
pub fn cover(cohort_commitment: &[u8; 32], seed: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_DICT_COVER_V1");
    h.update(cohort_commitment);
    h.update(seed);
    h.finalize().into()
}

/// Y4: kohort commitment - sıralı nesne hash'lerinden (deterministik).
pub fn cohort_commitment(object_hashes: &[[u8; 32]]) -> Option<[u8; 32]> {
    if object_hashes.is_empty() {
        return None;
    }
    let mut h = Sha3_256::new();
    h.update(b"BDLM_DICT_COHORT_V1");
    h.update((object_hashes.len() as u32).to_le_bytes());
    for o in object_hashes {
        h.update(o);
    }
    Some(h.finalize().into())
}

/// Y4: sözlük yeniden eğitim determinizmi - aynı kohort → aynı COVER
/// (farklı makinede; sürüm+parametre+girdi sabitleme koşulu, İ5).
pub fn dict_reproducible(c1: &[u8; 32], c2: &[u8; 32]) -> bool {
    c1 == c2
}

pub fn tiny_digest(t: &TinyInline) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(TINY_MAGIC);
    h.update(t.content_id);
    h.update(&t.data);
    h.update([t.encrypted as u8]);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::Digest;

    fn hof(b: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b);
        h.finalize().into()
    }

    #[test]
    fn y5_tiny_esik_ve_sigdirma() {
        assert!(is_tiny(500, TINY_OBJECT_THRESHOLD));
        assert!(!is_tiny(5000, TINY_OBJECT_THRESHOLD));
        assert!(!is_tiny(100, 0), "eşik 0 → sınıf yok");
        let nesneler = vec![
            TinyInline {
                content_id: hof(b"a"),
                data: vec![0u8; 100],
                encrypted: false,
            },
            TinyInline {
                content_id: hof(b"b"),
                data: vec![0u8; 200],
                encrypted: true,
            },
        ];
        assert!(fits_in_block(&nesneler, 1024));
        assert!(!fits_in_block(&nesneler, 200));
    }

    #[test]
    fn y4_cover_ve_kohort() {
        let hashes: Vec<[u8; 32]> = vec![hof(b"n1"), hof(b"n2"), hof(b"n3")];
        let cc = cohort_commitment(&hashes).unwrap();
        let c1 = cover(&cc, &[1u8; 32]);
        let c2 = cover(&cc, &[1u8; 32]);
        assert!(dict_reproducible(&c1, &c2), "aynı kohort → aynı COVER");
        // farklı sıra → farklı commitment (sıralı hash kuralı)
        let mut rev = hashes.clone();
        rev.reverse();
        assert_ne!(cohort_commitment(&rev).unwrap(), cc);
        assert!(cohort_commitment(&[]).is_none());
    }

    #[test]
    fn tiny_deterministik() {
        let t = TinyInline {
            content_id: [1u8; 32],
            data: b"veri".to_vec(),
            encrypted: false,
        };
        assert_eq!(tiny_digest(&t), tiny_digest(&t));
    }
}
