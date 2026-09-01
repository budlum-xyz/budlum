//! The training plan.
//!
//! The adapter dtype is pinned to BF16/FP16 through the type system: FP4
//! adapters carry a router-collapse risk (research section 1.5,
//! awesome-deepseek-v4). The example ranges: 1K-10K for LoRA, 100K+ for a full
//! SFT (from the same guide).

use ai_core::manifest::AdapterDtype;
use ai_core::model::{Hash32, ModelId};

/// The training method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuneMethod {
    Lora,
    FullSft,
}

/// The training plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunePlan {
    pub base: ModelId,
    pub method: TuneMethod,
    pub adapter_dtype: AdapterDtype,
    /// 1K-10K for LoRA; 100K+ for a full SFT.
    pub max_examples: u32,
    /// The content_id list of the training sets (registered in B.U.D.).
    pub dataset_hashes: Vec<Hash32>,
}

impl TunePlan {
    /// The default LoRA plan (the 2026-08-13 decision: LoRA SFT on
    /// V4-Flash-Base).
    #[must_use]
    pub fn lora(base: ModelId, max_examples: u32) -> Self {
        Self {
            base,
            method: TuneMethod::Lora,
            adapter_dtype: AdapterDtype::Bf16,
            max_examples,
            dataset_hashes: Vec::new(),
        }
    }

    /// The full SFT plan (only by a deliberate decision; it requires 100K+
    /// examples).
    #[must_use]
    pub fn full_sft(base: ModelId) -> Self {
        Self {
            base,
            method: TuneMethod::FullSft,
            adapter_dtype: AdapterDtype::Bf16,
            max_examples: 100_000,
            dataset_hashes: Vec::new(),
        }
    }

    /// The LoRA example range check: below 1K is not practical, and above 10K
    /// the signal weakens for LoRA. A full SFT expects 100K+.
    ///
    /// # Errors
    ///
    /// An explanatory message when it is out of range.
    pub fn assert_example_range(&self) -> Result<(), String> {
        match self.method {
            TuneMethod::Lora => {
                if !(1_000..=10_000).contains(&self.max_examples) {
                    return Err(format!(
                        "the LoRA example count has to be in the 1K-10K range (currently: {})",
                        self.max_examples
                    ));
                }
            }
            TuneMethod::FullSft => {
                if self.max_examples < 100_000 {
                    return Err(format!(
                        "a full SFT expects 100K+ examples (currently: {})",
                        self.max_examples
                    ));
                }
            }
        }
        Ok(())
    }

    /// Make it explicit that the plan cannot run without a dataset.
    #[must_use]
    pub fn has_datasets(&self) -> bool {
        !self.dataset_hashes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_lora_plan_uses_bf16() {
        let p = TunePlan::lora(ModelId([2; 32]), 2_000);
        assert_eq!(p.method, TuneMethod::Lora);
        assert_eq!(p.adapter_dtype, AdapterDtype::Bf16);
    }

    #[test]
    fn lora_range_is_enforced() {
        let too_small = TunePlan::lora(ModelId([2; 32]), 500);
        assert!(too_small.assert_example_range().is_err());

        let ok = TunePlan::lora(ModelId([2; 32]), 2_000);
        assert!(ok.assert_example_range().is_ok());
    }

    #[test]
    fn full_sft_floor_is_enforced() {
        let p = TunePlan::full_sft(ModelId([2; 32]));
        assert!(p.assert_example_range().is_ok());

        let mut too_small = p.clone();
        too_small.max_examples = 50_000;
        assert!(too_small.assert_example_range().is_err());
    }
}
