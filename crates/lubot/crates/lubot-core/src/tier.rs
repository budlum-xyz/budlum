//! Lubot model kademe adlandırması.
//!
//! Karar (2026-08-13): DeepSeek'in varyant adları (Flash/Pro) Lubot
//! katmanında kullanılmaz; kendi adlarımız geçerlidir:
//!
//! - `Light`  ← DeepSeek-V4-Flash(-Base) tabanlı
//! - `Normal` ← DeepSeek-V4-Pro(-Base) tabanlı
//!
//! Çarpan/kat kademe etiketleri (ör. "0.5x", "10x") Lubot'ta **yoktur**.
//! Ağırlık repo adları (üçüncü taraf) atıf gereği olduğu gibi korunur
//! (bkz. `NOTICE.md`); yalnız bizim katmanımız kendi adını taşır.

/// Lubot kademesi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModelTier {
    /// Flash tabanlı: günlük kullanım, düşük gecikme.
    Light,
    /// Pro tabanlı: en yüksek kapasite.
    Normal,
}

impl ModelTier {
    /// Kademenin adı (kimliklerde ve `served_model_name` içinde kullanılır).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ModelTier::Light => "light",
            ModelTier::Normal => "normal",
        }
    }

    /// Bu kademe için API'de sunulan model adı: `lubot-{kademe}-{sürüm}`.
    #[must_use]
    pub fn served_model_name(self, version: &str) -> String {
        format!("lubot-{}-{}", self.as_str(), version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn served_names_follow_tier_naming() {
        assert_eq!(
            ModelTier::Light.served_model_name("v0.1"),
            "lubot-light-v0.1"
        );
        assert_eq!(
            ModelTier::Normal.served_model_name("v0.1"),
            "lubot-normal-v0.1"
        );
    }

    #[test]
    fn tier_names_contain_no_multiplier_labels() {
        for t in [ModelTier::Light, ModelTier::Normal] {
            let s = t.as_str();
            assert!(!s.contains('x'));
            assert!(!s.contains("0.5"));
            assert!(!s.contains("10"));
        }
    }
}
