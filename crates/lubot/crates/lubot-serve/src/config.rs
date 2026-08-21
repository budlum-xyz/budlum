//! Serving yapılandırması ve atıf politikası denetimi.

use lubot_core::tier::ModelTier;

/// Çıkarım motoru (araştırma §1.4: a resident-batch engine ve a resident-graph engine gün-0 destekli).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeEngine {
    ResidentBatch,
    ResidentGraph,
    QuantizedLocal,
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
            ModelTier::Light => "example-org/base-checkpoint-light",
            ModelTier::Normal => "example-org/base-checkpoint-normal",
        };
        Self {
            weight_source: weight_source.to_string(),
            served_model_name: tier.served_model_name(version),
            tier,
            engine: ServeEngine::ResidentBatch,
            port: 8000,
            base_url: "http://127.0.0.1:8000/v1".to_string(),
        }
    }
}

/// Atıf politikası denetimi: sunulan ad, üçüncü taraf model adını taşıyamaz
/// ("the upstream vendor'in kodunu alıp Lubot diye satmıyoruz" - yalnız kendi katmanımız
/// Lubot adını taşır; taban `NOTICE.md` ve model kartında açıkça yazılır).
///
/// # Errors
///
/// `served_model_name` içinde "upstream" veya çarpan etiketi
/// kalıbı (ör. "0.5x", "10x") geçiyorsa.
pub fn assert_served_name_is_ours(cfg: &ServeConfig) -> Result<(), String> {
    let name = cfg.served_model_name.to_lowercase();
    if name.contains("upstream") {
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

/// Çarpan/kat etiketi kalıbı: `0.5x`, `2x`, `10x` gibi. Lubot kademeleri
/// yalnızca `light` / `normal` adlarını taşır.
#[must_use]
fn looks_like_multiplier(name: &str) -> bool {
    let lower = name.to_lowercase();
    let mut chars = lower.chars().peekable();
    let mut in_number = false;
    while let Some(c) = chars.next() {
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
        assert_eq!(cfg.weight_source, "example-org/base-checkpoint-normal");
        assert_eq!(cfg.served_model_name, "lubot-normal-v0.1");
        assert!(assert_served_name_is_ours(&cfg).is_ok());
    }

    #[test]
    fn third_party_name_in_served_alias_is_rejected() {
        let mut cfg = ServeConfig::default();
        cfg.served_model_name = "lubot-upstream-v1".to_string();
        assert!(assert_served_name_is_ours(&cfg).is_err());
    }

    #[test]
    fn multiplier_labels_are_rejected() {
        for bad in ["lubot-0.5x", "lubot-10x-v1", "lubot-2x"] {
            let mut cfg = ServeConfig::default();
            cfg.served_model_name = bad.to_string();
            assert!(assert_served_name_is_ours(&cfg).is_err(), "{bad} reddedilmeli");
        }
    }

    #[test]
    fn plain_tier_names_pass_multiplier_check() {
        let cfg = ServeConfig::for_tier(ModelTier::Light, "v0.1");
        assert!(assert_served_name_is_ours(&cfg).is_ok());
    }
}
