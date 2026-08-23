//! B.U.D. 2.0 - BIT ROT + SCRUB (F50 - checksum bütünlüğü + tarama çizelgesi)
//!
//! Kalan iş: bit rot + scrub. SHA3 content_id'leri zaten her .bud'da; bu modül
//! TARAMA çizelgesini verir: hangi küme ne zaman doğrulanır (tier + yaşa göre),
//! bozuk kayıt RED. Deterministik; panik'siz.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const SCRUB_MAGIC: [u8; 8] = *b"\xB5SCRS\0\0\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrubTier {
    Hot,     // sık erişilen - nadir tarama (okuma zaten doğrular)
    Warm,    // arada - aylık
    Cold,    // nadir - haftalık
    Archive, // uzun - günlük dilim
}

/// Tarama aralığı (saniye) - tier'e göre.
pub fn scrub_interval_sec(tier: ScrubTier) -> u64 {
    match tier {
        ScrubTier::Hot => 90 * 24 * 3600,
        ScrubTier::Warm => 30 * 24 * 3600,
        ScrubTier::Cold => 7 * 24 * 3600,
        ScrubTier::Archive => 24 * 3600,
    }
}

/// Küme şimdi taranmalı mı? (son_tarama + aralık ≤ şimdi)
pub fn due(tier: ScrubTier, last_scrub_sec: u64, now_sec: u64) -> bool {
    last_scrub_sec.saturating_add(scrub_interval_sec(tier)) <= now_sec
}

/// Kayıt doğrulama: beklenen content_id ile uyuşuyor mu? (bit rot tespiti)
pub fn verify_content(data: &[u8], expected: &[u8; 32]) -> bool {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_BUD_CONTENT_V1");
    h.update((data.len() as u64).to_le_bytes());
    h.update(data);
    let digest: [u8; 32] = h.finalize().into();
    &digest == expected
}

pub fn scrub_digest(t: ScrubTier, last: u64, now: u64) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(SCRUB_MAGIC);
    h.update([match t {
        ScrubTier::Hot => 0,
        ScrubTier::Warm => 1,
        ScrubTier::Cold => 2,
        ScrubTier::Archive => 3,
    }]);
    h.update(last.to_le_bytes());
    h.update(now.to_le_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn araliklar_tier_sirali() {
        assert!(scrub_interval_sec(ScrubTier::Hot) > scrub_interval_sec(ScrubTier::Cold));
    }

    #[test]
    fn due_hesabi_dogru() {
        assert!(due(ScrubTier::Cold, 0, scrub_interval_sec(ScrubTier::Cold)));
        assert!(!due(ScrubTier::Cold, 1_000_000, 1_000_001));
    }

    #[test]
    fn bit_rot_tespiti() {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_CONTENT_V1");
        h.update((7u64).to_le_bytes());
        h.update(b"merhaba");
        let cid: [u8; 32] = h.finalize().into();
        assert!(verify_content(b"merhaba", &cid));
        assert!(!verify_content(b"merhabX", &cid), "bit rot yakalanır");
    }
}
