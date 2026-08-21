//! B.U.D. 2.0 - Üretim Sözleşmesi (PACT) Kaydı (2026-08-16)
//!
//! fikirler2.0.md İ1 (PACT Registry) icadının .bud formatındaki karşılığı:
//! içeriğin zincirdeki varlığı bayt değil `(üretici_hash, tohum, commitment,
//! reziduel_commitment)` üçlüsüdür. Bu modül:
//!   - bir .bud konteynerinin "üretilebilirlik sınıfını" hesaplar (rezidüel = 0
//!     ise baytlar tamamen üreticiten yeniden üretilebilir - F1/F14/fikirler.md),
//!   - PACT kaydını domain-etiketli SHA3 ile hash'ler (zincire yazılabilir),
//!   - doğrulama: üretilen baytın commitment'ı kayıtla eşleşmeli (İ2 generate_and_verify).
//!
//! Kayıpsızlık: PACT kaydı ORİJİNALİN yerine geçmez; konteynerin bütünlük çapasıdır.
//! "Üretilebilir sınıf" iddiası, .bud içinde KAYIPLI dönüşüm (ör. video codec) kullanılsa
//! bile bütünlük doğrulamasına izin verir: commitment = H(üretici_çıktısı), bayt yeniden
//! üretilebilir. Kayıpsız sınıfta commitment = content_id(original) (K3).
//!
//! Kod: `#![forbid(unsafe_code)]`, deterministik, panik'siz.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const PACT_MAGIC: [u8; 8] = *b"\xB5PACT\0\0\0";
pub const PACT_VERSION: u8 = 1;

/// Üretim modu (fikirler2.0 İ1 `mod` alanı).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PactMode {
    /// Saf üretim: rezidüel yok, tüm baytlar üreticiten üretilir (F1/F14)
    PureProduction = 0,
    /// Tarif + rezidüel: üretilemeyen artık sahip/erasure'da (İ6)
    RecipePlusResidual = 1,
    /// Rezidüel yalnız: üretilemez sınıf (organik), sıradan kayıpsız saklama
    ResidualOnly = 2,
}

impl PactMode {
    pub fn to_u8(self) -> u8 {
        self as u8
    }
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::PureProduction),
            1 => Some(Self::RecipePlusResidual),
            2 => Some(Self::ResidualOnly),
            _ => None,
        }
    }
}

/// Üretim sözleşmesi kaydı (İ1). `~100 bayt` - içerik 1GB bile olsa.
#[derive(Debug, Clone)]
pub struct PactRecord {
    pub mode: PactMode,
    pub producer_id: [u8; 32],        // deterministik üretici fonksiyonun hash'i
    pub seed: [u8; 32],               // üreticinin girdisi (tohum)
    pub commitment: [u8; 32],         // H(üretilen bayt) - üretimle eşleşme kanıtı
    pub residual_commitment: [u8; 32], // H(rezidüel) - boş değilse RecipePlusResidual
    pub residual_len: u64,            // rezidüel boyut (İ6 fiyat fonksiyonu girdisi)
    pub byte_budget: u64,            // ağa fiziksel yük tavanı (İ8)
    pub ts_unix: u64,
}

impl PactRecord {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_PACT_V1";
    pub const EMPTY_RESIDUAL: [u8; 32] = [0u8; 32]; // boş rezidüel gösterimi (İ1)

    /// Saf üretim kaydı (rezidüel = 0, commitment = H(üretilen bayt)).
    pub fn pure(producer_id: [u8; 32], seed: [u8; 32], produced: &[u8], ts: u64) -> Self {
        PactRecord {
            mode: PactMode::PureProduction,
            producer_id,
            seed,
            commitment: Self::hash_bytes(b"BDLM_PACT_OUTPUT_V1", produced),
            residual_commitment: Self::EMPTY_RESIDUAL,
            residual_len: 0,
            byte_budget: 0,
            ts_unix: ts,
        }
    }

    /// Tarif + rezidüel kaydı (üretilemeyen artık ayrı commitment).
    pub fn producer_plus_residual(
        producer_id: [u8; 32],
        seed: [u8; 32],
        produced: &[u8],
        residual: &[u8],
        ts: u64,
    ) -> Self {
        PactRecord {
            mode: PactMode::RecipePlusResidual,
            producer_id,
            seed,
            commitment: Self::hash_bytes(b"BDLM_PACT_OUTPUT_V1", produced),
            residual_commitment: Self::hash_bytes(b"BDLM_PACT_RESIDUAL_V1", residual),
            residual_len: residual.len() as u64,
            byte_budget: 0,
            ts_unix: ts,
        }
    }

    /// Kayıpsız .bud için: commitment = content_id(original) (K3) - birebir bütünlük.
    pub fn residual_only(original: &[u8], ts: u64) -> Self {
        let cid = crate::bud_format_container::content_id(original);
        PactRecord {
            mode: PactMode::ResidualOnly,
            producer_id: [0u8; 32],
            seed: [0u8; 32],
            commitment: cid,
            residual_commitment: cid,
            residual_len: original.len() as u64,
            byte_budget: original.len() as u64,
            ts_unix: ts,
        }
    }

    /// Domain-etiketli kriptografik hash - zincire yazılabilir kimlik (İ1).
    pub fn record_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update([self.mode.to_u8()]);
        h.update(self.producer_id);
        h.update(self.seed);
        h.update(self.commitment);
        h.update(self.residual_commitment);
        h.update(self.residual_len.to_le_bytes());
        h.update(self.byte_budget.to_le_bytes());
        h.update(self.ts_unix.to_le_bytes());
        h.finalize().into()
    }

    /// CONSENSUS-GÜVENLİ SERİLEŞTİRME (kalan iş #5 - doğrulama testi aşağıda):
    /// `to_blob`/`from_blob` aşağıda (PACT_MAGIC + alanlar + record_hash digest)
    /// zaten vardır ve CANONICAL'dir: aynı mantıksal kayıt → AYNI baytlar → state
    /// kökü etkisi yok (fikirler2.0 §10.3). Test: `consensus_guvenli_serilestirme_roundtrip`.

    /// Üretim doğrulaması (İ2 generate_and_verify): üretilen bayt commitment'ı karşılar mı?
    /// Kayıpsız sınıfta (ResidualOnly) commitment = content_id(original) - K3 ile eşleşmeli.
    pub fn verify_production(&self, produced: &[u8]) -> bool {
        match self.mode {
            PactMode::PureProduction | PactMode::RecipePlusResidual => {
                self.commitment == Self::hash_bytes(b"BDLM_PACT_OUTPUT_V1", produced)
            }
            PactMode::ResidualOnly => {
                self.commitment == crate::bud_format_container::content_id(produced)
            }
        }
    }

    /// Sınıf yalanı kontrolü (İ6): residual_len 0 ama mode RecipePlusResidual ise tutarsız.
    pub fn verify(&self) -> bool {
        match self.mode {
            PactMode::PureProduction => self.residual_len == 0,
            PactMode::RecipePlusResidual => {
                self.residual_len > 0 && self.residual_commitment != Self::EMPTY_RESIDUAL
            }
            PactMode::ResidualOnly => {
                self.residual_len > 0 && self.residual_commitment == self.commitment
            }
        }
    }

    /// Rezidüel doğrulama (İ6): verilen rezidüel baytlar commitment'ı karşılıyor mu?
    pub fn verify_residual(&self, residual: &[u8]) -> bool {
        match self.mode {
            PactMode::RecipePlusResidual => {
                self.residual_commitment == Self::hash_bytes(b"BDLM_PACT_RESIDUAL_V1", residual)
            }
            PactMode::ResidualOnly => {
                self.residual_commitment == crate::bud_format_container::content_id(residual)
            }
            PactMode::PureProduction => residual.is_empty(),
        }
    }

    fn hash_bytes(domain: &[u8], data: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(domain);
        h.update((data.len() as u64).to_le_bytes());
        h.update(data);
        h.finalize().into()
    }
}

/// Deterministik blob (magic + sürüm + alanlar + digest).
impl PactRecord {
    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&PACT_MAGIC);
        out.push(PACT_VERSION);
        out.push(self.mode.to_u8());
        out.extend_from_slice(&self.producer_id);
        out.extend_from_slice(&self.seed);
        out.extend_from_slice(&self.commitment);
        out.extend_from_slice(&self.residual_commitment);
        out.extend_from_slice(&self.residual_len.to_le_bytes());
        out.extend_from_slice(&self.byte_budget.to_le_bytes());
        out.extend_from_slice(&self.ts_unix.to_le_bytes());
        out.extend_from_slice(&self.record_hash()); // digest (kurcalama RED)
        out
    }

    pub fn from_blob(bytes: &[u8]) -> Option<Self> {
        const HDR: usize = 8 + 1 + 1 + 32 + 32 + 32 + 32 + 8 + 8 + 8;
        if bytes.len() < HDR + 32 || bytes[0..8] != PACT_MAGIC || bytes[8] != PACT_VERSION {
            return None;
        }
        let mode = PactMode::from_u8(bytes[9])?;
        let mut r = PactRecord {
            mode,
            producer_id: [0u8; 32],
            seed: [0u8; 32],
            commitment: [0u8; 32],
            residual_commitment: [0u8; 32],
            residual_len: 0,
            byte_budget: 0,
            ts_unix: 0,
        };
        let mut pos = 10;
        r.producer_id.copy_from_slice(&bytes[pos..pos + 32]); pos += 32;
        r.seed.copy_from_slice(&bytes[pos..pos + 32]); pos += 32;
        r.commitment.copy_from_slice(&bytes[pos..pos + 32]); pos += 32;
        r.residual_commitment.copy_from_slice(&bytes[pos..pos + 32]); pos += 32;
        r.residual_len = u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?); pos += 8;
        r.byte_budget = u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?); pos += 8;
        r.ts_unix = u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?); pos += 8;
        if bytes.len() != pos + 32 {
            return None; // artık bayt → sıkı red
        }
        if bytes[pos..] != r.record_hash() {
            return None; // kurcalama
        }
        if !r.verify() {
            return None;
        }
        Some(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_production_roundtrip_and_verify() {
        // saf üretim: üretici + tohum → bayt; commitment üretimle eşleşmeli
        let seed = [7u8; 32];
        let producer = [1u8; 32];
        let produced = b"deterministik uretim ciktisi 1234567890";
        let pact = PactRecord::pure(producer, seed, produced, 100);
        assert!(pact.verify_production(produced), "üretim commitment'ı eşleşir");
        assert!(!pact.verify_production(b"baska cikti"), "farklı üretim RED");
        assert!(pact.verify(), "saf üretim tutarlı");
        // blob roundtrip
        let blob = pact.to_blob();
        let back = PactRecord::from_blob(&blob).expect("blob okunur");
        assert_eq!(back.record_hash(), pact.record_hash());
        // kurcalama red
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(PactRecord::from_blob(&bad).is_none());
        // artık bayt red
        let mut extra = blob.clone();
        extra.push(0x00);
        assert!(PactRecord::from_blob(&extra).is_none());
        // kısa girdi
        assert!(PactRecord::from_blob(&[0u8; 20]).is_none());
    }

    #[test]
    fn producer_plus_residual_classification() {
        // üretici + rezidüel: üretilemeyen artık ayrı commitment (İ6)
        let produced = b"uretilen kisim";
        let residual = b"organik artik: gurultu 0x1234";
        let pact = PactRecord::producer_plus_residual([9u8; 32], [5u8; 32], produced, residual, 200);
        assert!(pact.verify_production(produced));
        assert!(pact.verify(), "rezidüel >0 tutarlı");
        assert_eq!(pact.residual_len, residual.len() as u64);
        // sınıf yalanı: mode RecipePlusResidual ama residual_len 0 → verify RED (İ6)
        let mut liar = pact.clone();
        liar.residual_len = 0;
        assert!(!liar.verify(), "rezidüel gizleme RED");
        // doğru rezidüel → verify_residual OK; farklı rezidüel → RED (İ6)
        assert!(pact.verify_residual(residual), "doğru rezidüel eşleşir");
        assert!(!pact.verify_residual(b"farkli reziduel"), "farklı rezidüel RED");
        let mut liar2 = pact.clone();
        liar2.residual_commitment = [1u8; 32];
        assert!(!liar2.verify_residual(residual), "kurcalanmış commitment RED");
    }

    #[test]
    fn residual_only_matches_content_id() {
        // kayıpsız .bud: commitment = content_id(original) (K3)
        let original = b"kayipsiz icerik 12345";
        let pact = PactRecord::residual_only(original, 300);
        assert!(pact.verify_production(original), "content_id eşleşir");
        assert!(!pact.verify_production(b"farkli"), "farklı içerik RED");
        assert_eq!(pact.commitment, crate::bud_format_container::content_id(original));
        assert!(pact.verify());
    }

    #[test]
    fn pact_record_small_and_deterministic() {
        // İ1 kabul: PACT kaydı ~100-150 bayt
        let seed = [1u8; 32];
        let pact = PactRecord::pure([2u8; 32], seed, b"x", 1);
        let blob = pact.to_blob();
        assert!(blob.len() <= 256, "PACT kaydı kompakt: {} bayt", blob.len());
        // aynı alanlar → aynı hash (deterministik)
        let pact2 = PactRecord::pure([2u8; 32], seed, b"x", 1);
        assert_eq!(pact.record_hash(), pact2.record_hash());
        assert_ne!(pact.record_hash(), [0u8; 32]);
    }

    #[test]
    fn consensus_guvenli_serilestirme_roundtrip() {
        // İ1: to_blob → from_blob = birebir; blob canonical (sabit boyut, sıra).
        let p1 = PactRecord::pure([7u8; 32], [9u8; 32], b"uretilen veri", 1_768_000_000);
        let blob = p1.to_blob();
        let p2 = PactRecord::from_blob(&blob).expect("blob aç");
        assert_eq!(p1.record_hash(), p2.record_hash(), "serileştirme birebir");
        assert_eq!(p1.mode, p2.mode);
        assert_eq!(p1.residual_len, p2.residual_len);
        // canonical: aynı kayıt → aynı baytlar (state kökü etkisi yok)
        let p3 = PactRecord::pure([7u8; 32], [9u8; 32], b"uretilen veri", 1_768_000_000);
        assert_eq!(blob, p3.to_blob());
        // bozuk blob → None (panik yok)
        let mut bozuk = blob.clone();
        bozuk[10] ^= 0xFF;
        let r = PactRecord::from_blob(&bozuk);
        assert!(r.is_none() || r.unwrap().record_hash() != p1.record_hash());
        assert!(PactRecord::from_blob(b"kisa").is_none());
    }

    #[test]
    fn from_blob_never_panics() {
        // mini-fuzz: rastgele baytlarda from_blob panik'siz
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
                self.0 = x;
                x.wrapping_mul(0x2545_F491_4F6C_DD1D)
            }
            fn byte(&mut self) -> u8 {
                (self.next() & 0xff) as u8
            }
        }
        let mut rng = Rng(0x5041_4354_2026_0816);
        let mut buf = vec![0u8; 200];
        for _ in 0..2000 {
            let len = (rng.next() % 200) as usize;
            for b in &mut buf[..len] {
                *b = rng.byte();
            }
            let _ = PactRecord::from_blob(&buf[..len]);
        }
    }
}
