//! Serving configuration and attribution policy checks.

use lubot_core::tier::ModelTier;

/// Inference engine (research section 1.4: vLLM and SGLang are day-zero supported).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeEngine {
    Vllm,
    Sglang,
    LlamaCpp,
    /// Colibri (Apache-2.0): a MoE engine that streams weights from disk.
    ///
    /// vLLM and SGLang require the whole model to be resident in VRAM, which
    /// forces the operator to own a data-center class GPU and contradicts the
    /// principle of `src/lubot/effort.rs`: "A Lubot operator answers
    /// with the machine it actually owns." Colibrì VRAM/RAM/NVMe'yi tek bir
    /// as a placement hierarchy, consumer hardware can be an
    /// operator too.
    ///
    /// It is spoken to as a separate process over an OpenAI-compatible endpoint; no code
    /// is copied and no crate dependency is added. Attribution goes into `NOTICE.md`.
    Colibri,
}

impl ServeEngine {
    /// Whether this engine is guaranteed to produce bit-identical output for the same
    /// edilebilir mi?
    ///
    /// **Why it matters:** `AiRegistry::try_finalize_with_proofs` groups results by
    /// `output_commitment: [u8; 32]`. If two operators differ by a single
    /// bit they fall into separate groups and `agreement_threshold` is never
    /// reached -- the request silently fails to finalize.
    ///
    /// Colibri supports the CPU/CUDA/Metal backends at the same time, and floating point
    /// summation order changes across hardware; even greedy sampling
    /// does not fix it, because the problem is in the summation, not the sampling. So
    /// a multi-backend engine is not sufficient on its own for the consensus path:
    /// it must be used together with a `DeterminismProfile`.
    #[must_use]
    pub const fn is_bitwise_reproducible(self) -> bool {
        match self {
            // A single backend plus fixed kernels: same binary, same result.
            ServeEngine::Vllm | ServeEngine::Sglang | ServeEngine::LlamaCpp => true,
            // Heterogeneous execution is the point of the engine; it cannot be guaranteed alone.
            ServeEngine::Colibri => false,
        }
    }
}

/// The determinism profile required for consensus.
///
/// Lubot consensus requires bit-identical equality (the `output_commitment` grouping),
/// so the operator's sampling and execution settings cannot be left free.
/// This profile carries the minimum conditions a bridge must meet to join the
/// consensus path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeterminismProfile {
    /// Greedy sampling (`temperature = 0`). A non-zero temperature randomizes
    /// sampling; two operators may pick different tokens even with the same
    /// seed.
    pub greedy: bool,
    /// A fixed sampling seed.
    pub seed: u64,
    /// A single fixed execution backend (CPU **or** CUDA **or** Metal --
    /// not mixed). Floating point summation order varies by backend.
    pub pinned_backend: bool,
}

impl DeterminismProfile {
    /// The profile required for the consensus path.
    #[must_use]
    pub const fn for_consensus(seed: u64) -> Self {
        Self {
            greedy: true,
            seed,
            pinned_backend: true,
        }
    }

    /// Whether the profile is sufficient for consensus.
    #[must_use]
    pub const fn is_consensus_safe(&self) -> bool {
        self.greedy && self.pinned_backend
    }
}

/// Bridge configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeConfig {
    /// The weight source - the original name is preserved (attribution).
    pub weight_source: String,
    /// The name served through the API - tier naming: `lubot-{tier}-{version}`.
    pub served_model_name: String,
    /// The tier this bridge serves.
    pub tier: ModelTier,
    pub engine: ServeEngine,
    pub port: u16,
    pub base_url: String,
    /// The determinism profile required if this bridge joins the consensus path.
    ///
    /// `None` means the bridge is for local/experimental use only and must not be put into
    /// consensus.
    pub determinism: Option<DeterminismProfile>,
}

impl Default for ServeConfig {
    fn default() -> Self {
        Self::for_tier(ModelTier::Light, "v0.1")
    }
}

impl ServeConfig {
    /// Build a configuration from tier + version (the 2026-08-13 naming decision).
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

/// Attribution policy check: the served name cannot carry a third-party model name
/// (we do not take a third-party model and sell it as Lubot - only our own layer
/// carries the Lubot name; the base is stated openly in `NOTICE.md` and the model card).
///
/// # Errors
///
/// If `served_model_name` contains a third-party name or a multiplier tag
/// pattern (for example "0.5x", "10x").
pub fn assert_served_name_is_ours(cfg: &ServeConfig) -> Result<(), String> {
    let name = cfg.served_model_name.to_lowercase();
    if name.contains("deepseek") {
        return Err(format!(
            "served_model_name cannot carry a third-party name: {}",
            cfg.served_model_name
        ));
    }
    if looks_like_multiplier(&cfg.served_model_name) {
        return Err(format!(
            "served_model_name cannot carry a multiplier tag: {}",
            cfg.served_model_name
        ));
    }
    Ok(())
}

/// Whether this bridge may be put into the consensus path.
///
/// Rule: if the engine is not bit-reproducible on its own (multi-backend),
/// it may enter consensus only with an `is_consensus_safe` profile. Without a profile
/// it is refused fail-closed -- silently accepting and then watching consensus never fill
/// makes the fault look like a liveness problem and hinders diagnosis.
///
/// # Errors
///
/// If there is no profile, or the profile does not meet the greedy/fixed-backend conditions.
pub fn assert_consensus_ready(cfg: &ServeConfig) -> Result<(), String> {
    match cfg.determinism {
        None => {
            if cfg.engine.is_bitwise_reproducible() {
                return Err(format!(
                    "{:?} may be bit-reproducible, but consensus requires an explicit \
                     determinism profile (greedy + fixed seed)",
                    cfg.engine
                ));
            }
            Err(format!(
                "{:?} is a multi-backend engine; without a determinism profile it \
                 cannot be put into consensus",
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

/// Multiplier tag pattern such as `0.5x`, `2x`, `10x`. Lubot tiers
/// carry only the names `light` / `normal`.
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
                "{bad} must be refused"
            );
        }
    }

    #[test]
    fn colibri_tek_basina_uzlasmaya_giremez() {
        // Colibri supports CPU/CUDA/Metal at the same time: bit-identical equality
        // is not a guarantee the engine itself makes.
        assert!(!ServeEngine::Colibri.is_bitwise_reproducible());
        let cfg = ServeConfig {
            engine: ServeEngine::Colibri,
            determinism: None,
            ..Default::default()
        };
        let err = assert_consensus_ready(&cfg).expect_err("profilsiz kabul edilmemeliydi");
        assert!(err.contains("multi-backend"), "{err}");
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
        // The gate is not vacuous: an insufficient profile must be refused too.
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
                "an insufficient profile should have been refused: {bad:?}"
            );
        }
    }

    #[test]
    fn varsayilan_kopru_uzlasmaya_hazir_degildir() {
        // The default configuration is for local use; putting it into consensus
        // must be an explicit decision.
        assert!(assert_consensus_ready(&ServeConfig::default()).is_err());
    }

    #[test]
    fn plain_tier_names_pass_multiplier_check() {
        let cfg = ServeConfig::for_tier(ModelTier::Light, "v0.1");
        assert!(assert_served_name_is_ours(&cfg).is_ok());
    }
}
