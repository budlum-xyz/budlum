//! .bud economics - fee market, global dedup, Merkle trie integration
//! V6 advanced

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct BudEconomics {
    pub physical_usd: f64, // 0.23342
    pub expansion: f64,    // 1.286
    pub ratio: f64,
    pub device_only: bool,
}

impl BudEconomics {
    /// Aylık TB maliyeti. K38: geçersiz oran (<=0 veya sonlu değil) → +inf (tavanı ASLA
    /// tutamaz - dürüst RED), IEEE bölmesine güvenilmez. device_only → 0 (cihaz içi bedava).
    pub fn cost_per_tb_month(&self) -> f64 {
        if self.device_only {
            return 0.0;
        }
        if !self.ratio.is_finite() || self.ratio <= 0.0 {
            return f64::INFINITY;
        }
        self.physical_usd * self.expansion / self.ratio
    }

    pub fn fee(&self, size_bytes: usize) -> f64 {
        // fee = base + size * per_byte + sig_len * per_sig
        let base = 0.0001;
        let per_byte = 0.000000001; // $ per byte per month
        let sig_cost = if self.ratio > 10.0 { 0.00002 } else { 0.00005 }; // PQ sig
        base + (size_bytes as f64) * per_byte + sig_cost
    }

    pub fn holds_price(&self, ceiling: f64) -> bool {
        self.cost_per_tb_month() <= ceiling + 1e-12
    }
}

/// K60 sıfır-egress modeli (araştırma: R2 benzeri sıfır-egress CDN, S.190):
/// Ağ İÇİ erişim (aynı B.U.D. ağı, CDN önbelleği, peer) EGREss 0'dır; yalnız
/// İnternet'e çıkış ücretlidir. Depolama maliyetine egress eklenmez (iş modeli avantajı).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressZone {
    InNetwork, // aynı ağ/CDN - egress 0 (K60)
    Internet,  // dış çıkış - rate ile ücretli
}

/// Egress maliyeti: InNetwork her zaman 0 (sıfır-egress garantisi, K60).
pub fn egress_cost(zone: EgressZone, tb: f64, rate_usd_per_tb: f64) -> f64 {
    match zone {
        EgressZone::InNetwork => 0.0,
        EgressZone::Internet => {
            if !rate_usd_per_tb.is_finite() || rate_usd_per_tb < 0.0 {
                f64::INFINITY // bozuk oran → dürüst RED (K38)
            } else {
                tb.max(0.0) * rate_usd_per_tb
            }
        }
    }
}

/// Kapı: egress bütçeyi tutuyor mu? InNetwork her zaman tutar (egress 0).
pub fn holds_egress(zone: EgressZone, tb: f64, rate_usd_per_tb: f64, budget: f64) -> bool {
    egress_cost(zone, tb, rate_usd_per_tb) <= budget + 1e-12
}

/// İ6 REZİDÜEL SINIF EKONOMİSİ (fikirler2.0 İ6; pay-as-you-go yerine):
/// ücret yalnız REZİDÜEL bayta bağlanır; üretilebilir kısım depolama ücreti ÖDEMEZ
/// (yalnız üretim piyasası üzerinden okuma ücreti - İ3).
/// Üretilebilir sınıf (rezidüel = 0) → aylık depolama maliyeti 0.
pub fn residual_price(
    residual_tb: f64,
    erasure_multiplier: f64,
    coldness: f64,
    physical_usd_per_tb_month: f64,
) -> f64 {
    if !residual_tb.is_finite()
        || residual_tb < 0.0
        || !erasure_multiplier.is_finite()
        || erasure_multiplier < 1.0
        || !coldness.is_finite()
        || coldness < 0.0
        || !physical_usd_per_tb_month.is_finite()
        || physical_usd_per_tb_month < 0.0
    {
        return f64::INFINITY;
    }
    if residual_tb == 0.0 {
        return 0.0;
    }
    let cold_discount = 1.0 - coldness * 0.5;
    residual_tb * erasure_multiplier * physical_usd_per_tb_month * cold_discount
}

/// İ6 kapısı: üretilebilir sınıf (rezidüel 0) taahhüdü her zaman tutar.
pub fn residual_holds_price(
    residual_tb: f64,
    erasure_multiplier: f64,
    coldness: f64,
    physical: f64,
    ceiling: f64,
) -> bool {
    residual_price(residual_tb, erasure_multiplier, coldness, physical) <= ceiling + 1e-12
}

/// Ekonomi kararı: TEK FİYAT.
/// "tek fiyat olacak, CPU gibi masraflar hali hazırda validatör tarafından karşılanıyor."
/// → Kullanıcıya yansıyan TEK kalem depolama fiyatıdır; üretim/CPU/erasure onarım maliyeti
/// validatörün yüküdür (fiyata girmez). Pay-as-you-go zaten kaldırıldı; İ6 rezidüel
/// sınıf ekonomisi de bu kararla SADELEŞTİ: her içerik sınıfı aynı taban fiyattan.
/// Fiyat = fiziksel taban × erasure çarpanı / ölçülen oran (tek formül, herkes için).
pub fn flat_price(
    physical_usd_per_tb_month: f64,
    erasure_multiplier: f64,
    measured_ratio: f64,
) -> f64 {
    if !physical_usd_per_tb_month.is_finite()
        || physical_usd_per_tb_month < 0.0
        || !erasure_multiplier.is_finite()
        || erasure_multiplier < 1.0
        || !measured_ratio.is_finite()
        || measured_ratio <= 0.0
    {
        return f64::INFINITY; // K38: bozuk girdi → dürüst RED
    }
    physical_usd_per_tb_month * erasure_multiplier / measured_ratio
}

/// TEK FİYAT kapısı: tavanı tutuyor mu? (K19 - ölçülen oranla)
pub fn flat_holds_ceiling(physical: f64, erasure: f64, ratio: f64, ceiling: f64) -> bool {
    flat_price(physical, erasure, ratio) <= ceiling + 1e-12
}

// ===========================================================================
// BORU HATTI EKONOMİSİ: tek fiyat, 0.016 $/TB tavanına kadar.
// ===========================================================================
// Her format sınıfı için: boru_hatti_orani = tek_dosya × çarpan; çarpanlar
// ÖLÇÜLMÜŞ tavanların içinde tutulur (bud_format_matrix::matrix_honesty_check).

/// Ölçülmüş çarpan tavanları (matrix canary'sinin dayandığı sabitler).
pub const CORPUS_DEDUP_MEASURED: f64 = 9.67; // korpus geneli 16KB SHA256
pub const FLEET_DEDUP_MEASURED: f64 = 25.43; // 25 özdeş ELF (dosya-içi parçalama)
pub const CULLING_MULT_MEASURED: f64 = 2.52; // 1/(1-0.603) erişim deseni

/// Ölçülmüş medya codec oranları (bud_format_media canary'si).
pub const AVIF_LOSSLESS_BMP_MEASURED: f64 = 15.84;
pub const JXL_LOSSLESS_PNG_MEASURED: f64 = 4.20;
pub const AVIF_LOSSY_JPEG_MEASURED: f64 = 3.20;
pub const AVIF_LOSSY_GIF_MEASURED: f64 = 16.75;
pub const FLAC_WAV_MEASURED: f64 = 6.26;
pub const AV1_YUV_MEASURED: f64 = 904.0;

/// Boru hattı oranı: transform × codec × dedup × culling (her bileşen ölçülü).
pub fn pipeline_ratio(transform: f64, codec: f64, dedup: f64, culling: f64) -> f64 {
    let p = transform.max(1.0) * codec.max(1.0) * dedup.max(1.0) * culling.max(1.0);
    if p.is_finite() && p > 0.0 {
        p
    } else {
        f64::INFINITY
    }
}

/// Boru hattı $/TB/ay: 0.23342 × erasure / boru_hatti_orani.
pub fn pipeline_price(
    physical_usd_per_tb_month: f64,
    erasure_multiplier: f64,
    transform: f64,
    codec: f64,
    dedup: f64,
    culling: f64,
) -> f64 {
    flat_price(
        physical_usd_per_tb_month,
        erasure_multiplier,
        pipeline_ratio(transform, codec, dedup, culling),
    )
}

/// Boru hattı tavan kapısı.
pub fn pipeline_holds_ceiling(
    physical: f64,
    erasure: f64,
    ceiling: f64,
    transform: f64,
    codec: f64,
    dedup: f64,
    culling: f64,
) -> bool {
    pipeline_price(physical, erasure, transform, codec, dedup, culling) <= ceiling + 1e-12
}
/// F3/F1151 TAPE ARŞİV SINIFI - soğuk içerik bantta (idle 0W):
/// LTO-9 ~$5/TB (30 yıl), 1PB 10 yıl $30K vs disk $480K; güç/soğutma ~%1.
/// 0.003 $/GB/yıl = 0.00025 $/TB/ay. Erişim gecikmesi kabul (bant dakikalar).
pub const TAPE_USD_PER_TB_MONTH: f64 = 0.00025; // F3 ölçümü

/// Arşiv sınıfı maliyeti: bantta soğuk içerik (TB başına).
pub fn tape_cost_per_tb_month(tb: f64) -> f64 {
    if !tb.is_finite() || tb < 0.0 {
        return f64::INFINITY;
    }
    tb * TAPE_USD_PER_TB_MONTH
}

/// Arşiv kapısı: bantta soğuk içerik $0.016/TB/ay altında mı?
pub fn tape_holds_ceiling(tb: f64, ceiling: f64) -> bool {
    tape_cost_per_tb_month(tb) <= ceiling + 1e-12
}

/// Medya merdiveni (F1153): sıcak NVMe → QLC → refurb HDD → bant (TCO azalan).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveTier {
    HotNvme,   // pahalı, düşük gecikme
    Qlc,       // sıcak-tier
    RefurbHdd, // $10/TB
    Tape,      // $5/TB, 30 yıl
}

impl ArchiveTier {
    pub fn usd_per_tb_month(&self) -> f64 {
        match self {
            Self::HotNvme => 0.5,
            Self::Qlc => 0.05,
            Self::RefurbHdd => 0.02,
            Self::Tape => TAPE_USD_PER_TB_MONTH,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GlobalDedup {
    pub chunk_hashes: HashSet<[u8; 32]>,
    pub total_saved_bytes: u64,
}

impl Default for GlobalDedup {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalDedup {
    pub fn new() -> Self {
        Self {
            chunk_hashes: HashSet::new(),
            total_saved_bytes: 0,
        }
    }

    pub fn insert_chunk(&mut self, hash: [u8; 32], size: usize) -> bool {
        if self.chunk_hashes.contains(&hash) {
            self.total_saved_bytes += size as u64;
            false // duplicate, not inserted
        } else {
            self.chunk_hashes.insert(hash);
            true
        }
    }

    pub fn dedup_ratio(&self, original_bytes: u64) -> f64 {
        if original_bytes == 0 {
            return 1.0;
        }
        original_bytes as f64 / (original_bytes as f64 - self.total_saved_bytes as f64).max(1.0)
    }
}

#[derive(Debug, Clone)]
pub struct MerkleTrie {
    pub root: [u8; 32],
    pub entries: HashMap<[u8; 32], Vec<u8>>,
}

impl Default for MerkleTrie {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTrie {
    pub fn new() -> Self {
        Self {
            root: [0u8; 32],
            entries: HashMap::new(),
        }
    }

    pub fn insert(&mut self, key: [u8; 32], value: Vec<u8>) {
        self.entries.insert(key, value);
        // root = hash of all keys sorted
        let mut hashes: Vec<_> = self.entries.keys().cloned().collect();
        hashes.sort();
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_TRIE_V1");
        for hk in hashes {
            h.update(hk);
        }
        self.root = h.finalize().into();
    }

    pub fn get(&self, key: &[u8; 32]) -> Option<&Vec<u8>> {
        self.entries.get(key)
    }
}

pub struct EconomicsGates;

impl EconomicsGates {
    pub fn k_bud_economics(econ: &BudEconomics, ceiling: f64) -> Result<(), &'static str> {
        if econ.holds_price(ceiling) {
            Ok(())
        } else {
            Err("KF: economics cost > ceiling")
        }
    }
    pub fn k_bud_global_dedup(
        dedup: &GlobalDedup,
        expected_saved: u64,
    ) -> Result<(), &'static str> {
        if dedup.total_saved_bytes >= expected_saved {
            Ok(())
        } else {
            Err("K-BUD-DEDUP: saved less than expected")
        }
    }
    pub fn k_bud_trie_root(trie: &MerkleTrie) -> Result<(), &'static str> {
        if trie.root != [0u8; 32] {
            Ok(())
        } else {
            Err("K-BUD-TRIE: root zero")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn economics_holds() {
        // JSON 17.19x Düz 7+1 (e=1.143) ile 0.016 tutar: 0.23342*1.143/17.19 = 0.01552 <= 0.016
        let econ = BudEconomics {
            physical_usd: 0.23342,
            expansion: 1.143,
            ratio: 17.19,
            device_only: false,
        };
        assert!(econ.holds_price(0.016));
        // EVENODD (e=1.286) ile TUTMAZ: 0.23342*1.286/17.19 = 0.01747 > 0.016 - bu gerçek ölçümdür (kanarya)
        let econ2 = BudEconomics {
            physical_usd: 0.23342,
            expansion: 1.286,
            ratio: 17.19,
            device_only: false,
        };
        assert!(!econ2.holds_price(0.016));
        let econ3 = BudEconomics {
            physical_usd: 0.23342,
            expansion: 1.286,
            ratio: 2.53,
            device_only: false,
        };
        assert!(!econ3.holds_price(0.016));
        let econ4 = BudEconomics {
            physical_usd: 0.23342,
            expansion: 1.286,
            ratio: 2.53,
            device_only: true,
        };
        assert!(econ4.holds_price(0.016));
    }
    #[test]
    fn k60_egress_zero_in_network() {
        // K60: ağ içi erişim egress 0 - 10TB bile bedava
        assert_eq!(egress_cost(EgressZone::InNetwork, 10.0, 0.005), 0.0);
        assert!(
            holds_egress(EgressZone::InNetwork, 10.0, 0.005, 0.0),
            "InNetwork her zaman bütçeyi tutar"
        );
        // İnternet çıkışı ücretli
        assert!((egress_cost(EgressZone::Internet, 1.0, 0.005) - 0.005).abs() < 1e-12);
        assert!(
            !holds_egress(EgressZone::Internet, 1.0, 0.005, 0.001),
            "1TB internet çıkışı 0.001 bütçeyi tutmaz"
        );
        // bozuk oran → +inf (K38)
        assert_eq!(egress_cost(EgressZone::Internet, 1.0, -1.0), f64::INFINITY);
        assert_eq!(
            egress_cost(EgressZone::Internet, 1.0, f64::NAN),
            f64::INFINITY
        );
        // negatif TB → 0 egress (mantıklı sınır)
        assert_eq!(egress_cost(EgressZone::Internet, -5.0, 0.005), 0.0);
    }

    #[test]
    fn tape_archive_tier_f3() {
        // F3/F1151: bantta soğuk içerik 0.00025 $/TB/ay - 0.016 taahhüdünün soğuk yolu
        assert!((TAPE_USD_PER_TB_MONTH - 0.00025).abs() < 0.00001);
        assert!(tape_holds_ceiling(1.0, 0.016), "bant her zaman tavan altı");
        assert!(tape_holds_ceiling(10.0, 0.016), "10TB bant bile");
        // medya merdiveni: bant en ucuz, sıcak en pahalı
        assert!(ArchiveTier::Tape.usd_per_tb_month() < ArchiveTier::RefurbHdd.usd_per_tb_month());
        assert!(ArchiveTier::RefurbHdd.usd_per_tb_month() < ArchiveTier::Qlc.usd_per_tb_month());
        assert!(ArchiveTier::Qlc.usd_per_tb_month() < ArchiveTier::HotNvme.usd_per_tb_month());
        // bozuk girdi → +inf
        assert_eq!(tape_cost_per_tb_month(-1.0), f64::INFINITY);
        assert_eq!(tape_cost_per_tb_month(f64::NAN), f64::INFINITY);
    }

    #[test]
    fn flat_single_price_user_decision() {
        // TEK FİYAT: CPU/üretim maliyeti validatörde; kullanıcıya tek kalem depolama.
        // JSON OrderFree 12.07x + LRC 1.031x → tek fiyat
        let p = flat_price(0.23342, 1.031, 12.07);
        assert!((p - 0.0199).abs() < 0.001, "tek fiyat ~0.0199: {p}");
        // video hareketli 101x → çok altı
        let pv = flat_price(0.23342, 1.031, 101.0);
        assert!(pv < 0.005, "video tek fiyat: {pv}");
        // statik 1394x → ~0
        let ps = flat_price(0.23342, 1.031, 1394.0);
        assert!(ps < 0.0005, "statik: {ps}");
        // tavan: 12.07x + LRC 0.016 tutmaz, 0.02 tutar
        assert!(!flat_holds_ceiling(0.23342, 1.031, 12.07, 0.016));
        assert!(flat_holds_ceiling(0.23342, 1.031, 12.07, 0.02));
        // bozuk girdi → +inf
        assert_eq!(flat_price(-1.0, 1.031, 12.07), f64::INFINITY);
        assert_eq!(flat_price(0.23342, 1.031, 0.0), f64::INFINITY);
    }
    #[test]
    fn residual_class_economy_i6() {
        // İ6: üretilebilir sınıf (rezidüel 0) → depolama maliyeti 0
        assert_eq!(
            residual_price(0.0, 1.143, 0.0, 0.23342),
            0.0,
            "üretilebilir bedava"
        );
        assert!(
            residual_holds_price(0.0, 1.143, 0.0, 0.23342, 0.016),
            "üretilebilir tavanı her zaman tutar"
        );
        // rezidüel sınıf: boyut × erasure × soğukluk
        let p1 = residual_price(1.0, 1.143, 0.0, 0.23342);
        assert!((p1 - 0.2668).abs() < 0.01, "1TB rezidüel ~0.267: {p1}");
        // soğukluk indirimi: coldness 1 → %50 düşük
        let pcold = residual_price(1.0, 1.143, 1.0, 0.23342);
        assert!(
            (p1 / pcold - 2.0).abs() < 0.05,
            "soğuk %50 ucuz: {p1} vs {pcold}"
        );
        // bozuk girdi → +inf (K38)
        assert_eq!(residual_price(-1.0, 1.143, 0.0, 0.23342), f64::INFINITY);
        assert_eq!(residual_price(1.0, 0.5, 0.0, 0.23342), f64::INFINITY);
        assert_eq!(residual_price(f64::NAN, 1.143, 0.0, 0.23342), f64::INFINITY);
    }
    #[test]
    fn invalid_ratio_is_honest_inf() {
        // K38: oran <=0 / NaN → +inf (tavan asla tutmaz, panik/NaN yok)
        let zero = BudEconomics {
            physical_usd: 0.23342,
            expansion: 1.286,
            ratio: 0.0,
            device_only: false,
        };
        assert_eq!(zero.cost_per_tb_month(), f64::INFINITY);
        assert!(!zero.holds_price(0.016));
        let nan = BudEconomics {
            physical_usd: 0.23342,
            expansion: 1.286,
            ratio: f64::NAN,
            device_only: false,
        };
        assert_eq!(nan.cost_per_tb_month(), f64::INFINITY);
        let neg = BudEconomics {
            physical_usd: 0.23342,
            expansion: 1.286,
            ratio: -3.0,
            device_only: false,
        };
        assert_eq!(neg.cost_per_tb_month(), f64::INFINITY);
        // device_only her zaman 0
        let d = BudEconomics {
            physical_usd: 0.23342,
            expansion: 1.286,
            ratio: 0.0,
            device_only: true,
        };
        assert_eq!(d.cost_per_tb_month(), 0.0);
    }
    #[test]
    fn global_dedup() {
        let mut dedup = GlobalDedup::new();
        let h1 = [1u8; 32];
        assert!(dedup.insert_chunk(h1, 100));
        assert!(!dedup.insert_chunk(h1, 100)); // duplicate
        assert_eq!(dedup.total_saved_bytes, 100);
    }
    #[test]
    fn merkle_trie() {
        let mut trie = MerkleTrie::new();
        let k = [1u8; 32];
        trie.insert(k, vec![1, 2, 3]);
        assert!(trie.get(&k).is_some());
        assert!(EconomicsGates::k_bud_trie_root(&trie).is_ok());
    }
}
