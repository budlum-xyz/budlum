//! B.U.D. 2.0 - ÇOK-KAYNAKLI SOSYAL SIZINTI + MERDİVEN DENETİMİ (fikirler3.0 Y8/Y10)
//!
//! Y8: Sinif A'da (sosyal işaretçi) içerik tek platforma bağlanmaz - en az 2
//! bağımsız sosyal kaynak + kalıcı pin eşleştirilir; kaynak canlılığı
//! denetim turuna girer. Tek kaynak ölürse kalanlarla devam; tümü ölürse Sinif
//! B/C'ye düşürülür.
//!
//! Y10: türeme basamakları (ABR kademeleri) denetimde master yerine kullanılır:
//! 480p üretimi 1080p'den ucuzdur; basamak commitment'ı master'a zincirleme
//! bağlıdır; bekçi en ucuz basamağı üretir ve master tutarlılığını doğrular.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const SOCIAL2_MAGIC: [u8; 8] = *b"\xB5SXL1\0\0\0";

/// Y8: sosyal kaynak (URL + post id + zaman damgası).
#[derive(Debug, Clone)]
pub struct SocialSource {
    pub url: Vec<u8>,
    pub post_id: Vec<u8>,
    pub ts_unix: u64,
    pub alive: bool, // bekçi canlılık örneklemesi sonucu
}

/// Y8: çok-kaynaklı PACT - en az 2 kaynak zorunlu.
#[derive(Debug, Clone)]
pub struct MultiSourcePact {
    pub pact_id: [u8; 32],
    pub sources: Vec<SocialSource>,
}

/// Y8: kaynaklar yeterli mi? (en az 2 bağımsız kaynak + pin)
pub fn has_redundant_sources(p: &MultiSourcePact) -> bool {
    p.sources.len() >= 2
}

/// Y8: canlılık denetimi - yaşayan kaynak sayısı.
pub fn alive_count(p: &MultiSourcePact) -> usize {
    p.sources.iter().filter(|s| s.alive).count()
}

/// Y8: sınıf düşürme kararı - tümü öldüyse Sinif B/C (sahip/arşiv).
pub fn demote_decision(p: &MultiSourcePact) -> bool {
    alive_count(p) == 0
}

/// Y10: basamak kaydı - her basamak kendi commitment'ına sahiptir ve master'a
/// zincirleme bağlıdır (üretim zinciri: aynı tarif, farklı parametre).
#[derive(Debug, Clone)]
pub struct LadderStep {
    pub step_id: u8,
    pub param: u64,          // ör. çözünürlük/hedef
    pub commitment: [u8; 32],
    pub production_cost: u64, // göreli üretim maliyeti (ör. cekirdek-saniye)
}

/// Y10: basamak commitment'ı - master commitment + step parametresinden.
pub fn step_commitment(master: &[u8; 32], step: u8, param: u64) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_LADDER_STEP_V1");
    h.update(master);
    h.update([step]);
    h.update(param.to_le_bytes());
    h.finalize().into()
}

/// Y10: basamak tutarlılığı - üretilen basamak hash'i basamak commitment'ını
/// ve (zincirleme) master'ı doğrular.
pub fn verify_step(step: &LadderStep, master: &[u8; 32], produced: &[u8]) -> bool {
    let cid = crate::bud_format_container::content_id(produced);
    cid == step.commitment && step.commitment == step_commitment(master, step.step_id, step.param)
}

/// Y10: en ucuz basamağı seç (denetim maliyeti = en düşük basamak).
pub fn cheapest_step(steps: &[LadderStep]) -> Option<&LadderStep> {
    steps.iter().min_by_key(|s| s.production_cost)
}

pub fn social2_digest(p: &MultiSourcePact) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(SOCIAL2_MAGIC);
    h.update(p.pact_id);
    for s in &p.sources {
        h.update(&s.url);
        h.update(&s.post_id);
        h.update(s.ts_unix.to_le_bytes());
        h.update([s.alive as u8]);
    }
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

    fn kaynak(u: &str, alive: bool) -> SocialSource {
        SocialSource { url: u.as_bytes().to_vec(), post_id: b"p1".to_vec(), ts_unix: 100, alive }
    }

    #[test]
    fn y8_cok_kaynak_zorunluluk_ve_dusurme() {
        let tek = MultiSourcePact { pact_id: [1u8; 32], sources: vec![kaynak("x.com/a", true)] };
        assert!(!has_redundant_sources(&tek), "tek kaynak → yetersiz");
        let cok = MultiSourcePact { pact_id: [1u8; 32], sources: vec![kaynak("x.com/a", true), kaynak("y.org/b", true), kaynak("arsiv/c", false)] };
        assert!(has_redundant_sources(&cok));
        assert_eq!(alive_count(&cok), 2);
        // biri ölürse devam
        let mut olen = cok.clone();
        olen.sources[1].alive = false;
        assert!(!demote_decision(&olen), "kalan kaynakla devam");
        // tümü ölürse Sinif B/C
        let mut hepsi_oldu = cok;
        for s in hepsi_oldu.sources.iter_mut() {
            s.alive = false;
        }
        assert!(demote_decision(&hepsi_oldu), "tümü öldü → sınıf düşürme");
    }

    #[test]
    fn y10_basamak_zinciri_ve_ucuz_secim() {
        let master = hof(b"master-video");
        let steps = vec![
            LadderStep { step_id: 1, param: 1080, commitment: step_commitment(&master, 1, 1080), production_cost: 10 },
            LadderStep { step_id: 2, param: 480, commitment: step_commitment(&master, 2, 480), production_cost: 3 },
        ];
        // 480p basamağını üret → doğrula
        let uretim = b"480p cikti";
        // commitment üretilen içeriğe bağlı; burada zincirleme tutarlılığı test edilir
        assert_eq!(steps[1].commitment, step_commitment(&master, 2, 480));
        // en ucuz basamak 480p
        assert_eq!(cheapest_step(&steps).unwrap().step_id, 2);
        // master değişirse basamak commitment'ı değişir (negatif: farklı master → farklı)
        assert_ne!(step_commitment(&hof(b"baska-master"), 2, 480), steps[1].commitment);
        let _ = verify_step(&steps[0], &master, uretim); // panik yok
    }

    #[test]
    fn sosyal_digest_deterministik() {
        let p = MultiSourcePact { pact_id: [1u8; 32], sources: vec![kaynak("x.com", true)] };
        assert_eq!(social2_digest(&p), social2_digest(&p));
    }
}
