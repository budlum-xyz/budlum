//! AI inference layer model tier naming.
//!
//! The upstream variant names are not used in the AI inference layer; our
//! own names apply:
//!
//! - `Light`  is the smaller capacity class
//! - `Normal` is the larger capacity class
//!
//! Multiplier tier labels (such as "0.5x" or "10x") do **not** exist in the AI inference layer.
//! Third-party weight repository names are kept as they are because attribution
//! requires it; only our own layer carries our own name.

/// The AI inference layer tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModelTier {
    /// The smaller capacity class: everyday use, low latency.
    Light,
    /// The larger capacity class: the highest capacity.
    Normal,
}

impl ModelTier {
    /// The name of the tier (used in identifiers and in `served_model_name`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ModelTier::Light => "light",
            ModelTier::Normal => "normal",
        }
    }

    /// The model name served over the API for this tier:
    /// `ai_inference-{tier}-{version}`.
    #[must_use]
    pub fn served_model_name(self, version: &str) -> String {
        format!("ai_inference-{}-{}", self.as_str(), version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn served_names_follow_tier_naming() {
        assert_eq!(
            ModelTier::Light.served_model_name("v0.1"),
            "ai_inference-light-v0.1"
        );
        assert_eq!(
            ModelTier::Normal.served_model_name("v0.1"),
            "ai_inference-normal-v0.1"
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
