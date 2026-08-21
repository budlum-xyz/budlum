//! Eğitim planı.
//!
//! Adaptör dtype'ı tip sistemiyle BF16/FP16'a sabitlenir: FP4 adaptörler
//! router-collapse riski taşır (araştırma §1.5, awesome-upstream-base).
//! Örnek aralıkları: LoRA 1K-10K, tam SFT 100K+ (aynı rehber).

use lubot_core::manifest::AdapterDtype;
use lubot_core::model::{Hash32, ModelId};

/// Eğitim yöntemi.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuneMethod {
    Lora,
    FullSft,
}

/// Eğitim planı.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunePlan {
    pub base: ModelId,
    pub method: TuneMethod,
    pub adapter_dtype: AdapterDtype,
    /// LoRA için 1K-10K; tam SFT için 100K+.
    pub max_examples: u32,
    /// Eğitim setlerinin content_id listesi (B.U.D. kayıtlı).
    pub dataset_hashes: Vec<Hash32>,
}

impl TunePlan {
    /// Varsayılan LoRA planı (2026-08-13 kararı: LoRA SFT, V4-Flash-Base).
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

    /// Tam SFT planı (yalnız bilinçli kararla; 100K+ örnek gerektirir).
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

    /// LoRA örnek aralığı denetimi: 1K altı pratik değil, 10K üstü LoRA
    /// için sinyal zayıflar. Tam SFT'de 100K+ beklenir.
    ///
    /// # Errors
    ///
    /// Aralık dışındaysa açıklayıcı mesaj.
    pub fn assert_example_range(&self) -> Result<(), String> {
        match self.method {
            TuneMethod::Lora => {
                if !(1_000..=10_000).contains(&self.max_examples) {
                    return Err(format!(
                        "LoRA örnek sayısı 1K-10K aralığında olmalı (şu an: {})",
                        self.max_examples
                    ));
                }
            }
            TuneMethod::FullSft => {
                if self.max_examples < 100_000 {
                    return Err(format!(
                        "tam SFT 100K+ örnek bekler (şu an: {})",
                        self.max_examples
                    ));
                }
            }
        }
        Ok(())
    }

    /// Planın veri seti olmadan koşulamayacağı açık olsun.
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
