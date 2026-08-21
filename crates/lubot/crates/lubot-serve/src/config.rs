//! Serving yapılandırması ve atıf politikası denetimi.

use lubot_core::tier::ModelTier;

/// Çıkarım motoru (araştırma §1.4: vLLM ve SGLang gün-0 destekli).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeEngine {
    Vllm,
    Sglang,
    LlamaCpp,
    /// Colibrì (Apache-2.0): ağırlıkları diskten akıtan MoE motoru.
    ///
    /// vLLM ve SGLang modelin tamamının VRAM'de yerleşik olmasını ister; bu,
    /// operatörün veri merkezi sınıfı GPU'ya sahip olmasını şart koşar ve
    /// `src/lubot/effort.rs`'in ilkesiyle çelişir: "A Lubot operator answers
    /// with the machine it actually owns." Colibrì VRAM/RAM/NVMe'yi tek bir
    /// yerleşim hiyerarşisi gibi kullandığı için tüketici donanımı da
    /// operatör olabilir.
    ///
    /// Ayrı süreç olarak, OpenAI-uyumlu uç üzerinden konuşulur; kod
    /// kopyalanmaz, crate bağımlılığı eklenmez. Atıf `NOTICE.md`'ye yazılır.
    Colibri,
}

impl ServeEngine {
    /// Bu motorun aynı girdi için bit-birebir aynı çıktıyı üretmesi garanti
    /// edilebilir mi?
    ///
    /// **Neden önemli:** `AiRegistry::try_finalize_with_proofs` sonuçları
    /// `output_commitment: [u8; 32]` değerine göre gruplar. İki operatör tek
    /// bit farklı üretirse ayrı gruplara düşer ve `agreement_threshold` hiç
    /// dolmaz -- istek sessizce finalize olmaz.
    ///
    /// Colibrì CPU/CUDA/Metal arka uçlarını aynı anda destekler ve farklı
    /// donanımda kayan nokta toplama sırası değişir; greedy örnekleme bile
    /// bunu düzeltmez, çünkü sorun örneklemede değil toplamadadır. Bu yüzden
    /// çok-arka-uçlu bir motor uzlaşma yolunda tek başına yeterli değildir:
    /// `DeterminismProfile` ile birlikte kullanılmalıdır.
    #[must_use]
    pub const fn is_bitwise_reproducible(self) -> bool {
        match self {
            // Tek arka uç + sabit çekirdek: aynı ikili, aynı sonuç.
            ServeEngine::Vllm | ServeEngine::Sglang | ServeEngine::LlamaCpp => true,
            // Heterojen yürütme motorun amacı; tek başına garanti edilemez.
            ServeEngine::Colibri => false,
        }
    }
}

/// Uzlaşma için gereken belirlenimlilik profili.
///
/// Lubot uzlaşması bit-birebir eşitlik ister (`output_commitment` gruplaması),
/// dolayısıyla operatörün örnekleme ve yürütme ayarları serbest bırakılamaz.
/// Bu profil, bir köprünün uzlaşma yoluna katılabilmesi için karşılaması
/// gereken asgari koşulları taşır.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeterminismProfile {
    /// Greedy örnekleme (`temperature = 0`). Sıfırdan farklı sıcaklık
    /// örneklemeyi rastgeleleştirir; iki operatör aynı tohumla bile farklı
    /// token seçebilir.
    pub greedy: bool,
    /// Sabit örnekleme tohumu.
    pub seed: u64,
    /// Tek ve sabit bir yürütme arka ucu (CPU **veya** CUDA **veya** Metal --
    /// karışık değil). Kayan nokta toplama sırası arka uca göre değişir.
    pub pinned_backend: bool,
}

impl DeterminismProfile {
    /// Uzlaşma yolu için gereken profil.
    #[must_use]
    pub const fn for_consensus(seed: u64) -> Self {
        Self {
            greedy: true,
            seed,
            pinned_backend: true,
        }
    }

    /// Profil uzlaşma için yeterli mi?
    #[must_use]
    pub const fn is_consensus_safe(&self) -> bool {
        self.greedy && self.pinned_backend
    }
}

/// Köprü yapılandırması.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeConfig {
    /// Ağırlık kaynağı - orijinal ad korunur (atıf).
    pub weight_source: String,
    /// API'de sunulan ad - kademe adlandırması: `lubot-{kademe}-{sürüm}`.
    pub served_model_name: String,
    /// Bu köprünün sunduğu kademe.
    pub tier: ModelTier,
    pub engine: ServeEngine,
    pub port: u16,
    pub base_url: String,
    /// Bu köprü uzlaşma yoluna katılacaksa gereken belirlenimlilik profili.
    ///
    /// `None` = köprü yalnız yerel/deneysel kullanım içindir; uzlaşmaya
    /// sokulmamalıdır.
    pub determinism: Option<DeterminismProfile>,
}

impl Default for ServeConfig {
    fn default() -> Self {
        Self::for_tier(ModelTier::Light, "v0.1")
    }
}

impl ServeConfig {
    /// Kademe + sürümden yapılandırma kur (2026-08-13 adlandırma kararı).
    #[must_use]
    pub fn for_tier(tier: ModelTier, version: &str) -> Self {
        let weight_source = match tier {
            ModelTier::Light => "deepseek-ai/DeepSeek-V4-Flash-Base",
            ModelTier::Normal => "deepseek-ai/DeepSeek-V4-Pro-Base",
        };
        Self {
            weight_source: weight_source.to_string(),
            served_model_name: tier.served_model_name(version),
            tier,
            engine: ServeEngine::Vllm,
            port: 8000,
            base_url: "http://127.0.0.1:8000/v1".to_string(),
            determinism: None,
        }
    }
}

/// Atıf politikası denetimi: sunulan ad, üçüncü taraf model adını taşıyamaz
/// ("DeepSeek'in kodunu alıp Lubot diye satmıyoruz" - yalnız kendi katmanımız
/// Lubot adını taşır; taban `NOTICE.md` ve model kartında açıkça yazılır).
///
/// # Errors
///
/// `served_model_name` içinde "deepseek" veya çarpan etiketi
/// kalıbı (ör. "0.5x", "10x") geçiyorsa.
pub fn assert_served_name_is_ours(cfg: &ServeConfig) -> Result<(), String> {
    let name = cfg.served_model_name.to_lowercase();
    if name.contains("deepseek") {
        return Err(format!(
            "served_model_name üçüncü taraf adı taşıyamaz: {}",
            cfg.served_model_name
        ));
    }
    if looks_like_multiplier(&cfg.served_model_name) {
        return Err(format!(
            "served_model_name çarpan etiketi taşıyamaz: {}",
            cfg.served_model_name
        ));
    }
    Ok(())
}

/// Bu köprü uzlaşma yoluna sokulabilir mi?
///
/// Kural: motor tek başına bit-birebir üretilebilir değilse (çok arka uçlu),
/// uzlaşmaya ancak `is_consensus_safe` bir profille girebilir. Profil yoksa
/// fail-closed reddedilir -- sessizce kabul edip uzlaşmanın hiç dolmamasını
/// izlemek, hatayı canlılık sorunu gibi gösterir ve teşhisi zorlaştırır.
///
/// # Errors
///
/// Profil yoksa veya profil greedy/sabit-arka-uç koşullarını karşılamıyorsa.
pub fn assert_consensus_ready(cfg: &ServeConfig) -> Result<(), String> {
    match cfg.determinism {
        None => {
            if cfg.engine.is_bitwise_reproducible() {
                return Err(format!(
                    "{:?} bit-birebir üretilebilir olsa da uzlaşma için açık bir \
                     belirlenimlilik profili gerekir (greedy + sabit tohum)",
                    cfg.engine
                ));
            }
            Err(format!(
                "{:?} çok arka uçlu bir motordur; belirlenimlilik profili olmadan \
                 uzlaşmaya sokulamaz",
                cfg.engine
            ))
        }
        Some(p) if !p.is_consensus_safe() => Err(format!(
            "belirlenimlilik profili yetersiz: greedy={}, pinned_backend={}",
            p.greedy, p.pinned_backend
        )),
        Some(_) => Ok(()),
    }
}

/// Çarpan/kat etiketi kalıbı: `0.5x`, `2x`, `10x` gibi. Lubot kademeleri
/// yalnızca `light` / `normal` adlarını taşır.
#[must_use]
fn looks_like_multiplier(name: &str) -> bool {
    let lower = name.to_lowercase();
    let mut in_number = false;
    for c in lower.chars() {
        if c.is_ascii_digit() || c == '.' || c == ',' {
            in_number = true;
        } else if c == 'x' && in_number {
            return true;
        } else {
            in_number = false;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_light_tier() {
        let cfg = ServeConfig::default();
        assert_eq!(cfg.tier, ModelTier::Light);
        assert_eq!(cfg.served_model_name, "lubot-light-v0.1");
        assert!(assert_served_name_is_ours(&cfg).is_ok());
    }

    #[test]
    fn normal_tier_maps_to_pro_weights_but_our_name() {
        let cfg = ServeConfig::for_tier(ModelTier::Normal, "v0.1");
        assert_eq!(cfg.weight_source, "deepseek-ai/DeepSeek-V4-Pro-Base");
        assert_eq!(cfg.served_model_name, "lubot-normal-v0.1");
        assert!(assert_served_name_is_ours(&cfg).is_ok());
    }

    #[test]
    fn third_party_name_in_served_alias_is_rejected() {
        let cfg = ServeConfig {
            served_model_name: "lubot-deepseek-v1".to_string(),
            ..Default::default()
        };
        assert!(assert_served_name_is_ours(&cfg).is_err());
    }

    #[test]
    fn multiplier_labels_are_rejected() {
        for bad in ["lubot-0.5x", "lubot-10x-v1", "lubot-2x"] {
            let cfg = ServeConfig {
                served_model_name: bad.to_string(),
                ..Default::default()
            };
            assert!(
                assert_served_name_is_ours(&cfg).is_err(),
                "{bad} reddedilmeli"
            );
        }
    }

    #[test]
    fn colibri_tek_basina_uzlasmaya_giremez() {
        // Colibrì CPU/CUDA/Metal'i aynı anda destekler: bit-birebir eşitlik
        // motorun kendi garantisi değildir.
        assert!(!ServeEngine::Colibri.is_bitwise_reproducible());
        let cfg = ServeConfig {
            engine: ServeEngine::Colibri,
            determinism: None,
            ..Default::default()
        };
        let err = assert_consensus_ready(&cfg).expect_err("profilsiz kabul edilmemeliydi");
        assert!(err.contains("çok arka uçlu"), "{err}");
    }

    #[test]
    fn belirlenimlilik_profili_colibriyi_uzlasmaya_uygun_kilar() {
        let cfg = ServeConfig {
            engine: ServeEngine::Colibri,
            determinism: Some(DeterminismProfile::for_consensus(42)),
            ..Default::default()
        };
        assert!(assert_consensus_ready(&cfg).is_ok());
    }

    #[test]
    fn eksik_profil_reddedilir() {
        // Kapı boş (vacuous) değil: yetersiz profil de reddedilmeli.
        for bad in [
            DeterminismProfile {
                greedy: false,
                seed: 1,
                pinned_backend: true,
            },
            DeterminismProfile {
                greedy: true,
                seed: 1,
                pinned_backend: false,
            },
        ] {
            let cfg = ServeConfig {
                engine: ServeEngine::Colibri,
                determinism: Some(bad),
                ..Default::default()
            };
            assert!(
                assert_consensus_ready(&cfg).is_err(),
                "yetersiz profil reddedilmeliydi: {bad:?}"
            );
        }
    }

    #[test]
    fn varsayilan_kopru_uzlasmaya_hazir_degildir() {
        // Varsayılan yapılandırma yerel kullanım içindir; uzlaşmaya sokmak
        // açık bir karar olmalıdır.
        assert!(assert_consensus_ready(&ServeConfig::default()).is_err());
    }

    #[test]
    fn plain_tier_names_pass_multiplier_check() {
        let cfg = ServeConfig::for_tier(ModelTier::Light, "v0.1");
        assert!(assert_served_name_is_ours(&cfg).is_ok());
    }
}
