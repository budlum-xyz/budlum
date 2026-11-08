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

fn contains_multiplier_token(s: &str) -> bool {
    let mut in_number = false;
    for ch in s.chars() {
        let low = ch.to_ascii_lowercase();
        if low.is_ascii_digit() || (in_number && low == '.') {
            in_number = true;
        } else if low == 'x' && in_number {
            return true;
        } else {
            in_number = false;
        }
    }
    false
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

    /// Convenience: whether `version` is safe to embed in a served model identifier (no
    /// whitespace, control characters, or multiplier labels such as `0.5x` or
    /// `10x`).
    #[must_use]
    pub fn is_valid_version(version: &str) -> bool {
        !version.is_empty()
            && !version.chars().any(|c| c.is_whitespace() || c.is_control())
            && !contains_multiplier_token(version)
    }

    /// Convenience: validated form of [`Self::served_model_name`].
    ///
    /// # Errors
    ///
    /// Returns an error if `version` is empty, contains whitespace or control
    /// characters, or injects a multiplier label (`0.5x`, `10x`, ...).
    pub fn try_served_model_name(self, version: &str) -> Result<String, String> {
        if !Self::is_valid_version(version) {
            return Err(format!(
                "invalid or multiplier-bearing model version label: {version:?}"
            ));
        }
        Ok(format!("ai_inference-{}-{version}", self.as_str()))
    }

    /// The model name served over the API for this tier:
    /// `ai_inference-{tier}-{version}`.
    ///
    /// If `version` is empty (prefix query) or fails [`Self::is_valid_version`],
    /// the bare tier prefix `ai_inference-{tier}-` is returned so an injected
    /// multiplier or control sequence never enters the served identifier and
    /// downstream admission refuses the empty version suffix.
    #[must_use]
    pub fn served_model_name(self, version: &str) -> String {
        if Self::is_valid_version(version) {
            format!("ai_inference-{}-{version}", self.as_str())
        } else {
            format!("ai_inference-{}-", self.as_str())
        }
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

    #[test]
    fn served_model_name_blocks_multiplier_and_control_injection() {
        let prefix = ModelTier::Light.served_model_name("");
        assert_eq!(prefix, "ai_inference-light-");
        for bad in [
            "0.5x",
            "10x",
            "v1-2x",
            "v1-10.0X",
            "v1\nheader",
            "v1 bad",
        ] {
            assert!(
                ModelTier::Light.try_served_model_name(bad).is_err(),
                "{bad:?}"
            );
            assert_eq!(
                ModelTier::Light.served_model_name(bad),
                "ai_inference-light-",
                "{bad:?} must never be embedded into served_model_name"
            );
        }
    }
}
