//! Bounded model-class whitelist for on-chain AI execution (v1).

use serde::{Deserialize, Serialize};

/// Maximum linear layer width (neurons) for v1 fixed-point MLP.
pub const MAX_MLP_WIDTH: usize = 64;
/// Maximum number of dense layers (including output).
pub const MAX_MLP_LAYERS: usize = 4;
/// Maximum total weight parameters (weights + biases).
pub const MAX_MLP_PARAMS: usize = 4096;

/// Which guest programs may be proven on L1 (whitelist).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AiExecutionModelClass {
    /// Integer fixed-point MLP, ReLU, bit-exact Goldilocks-friendly arithmetic.
    FixedPointMlpV1 = 1,
}

impl AiExecutionModelClass {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::FixedPointMlpV1),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FixedPointMlpV1 => "fixed_point_mlp_v1",
        }
    }
}

/// Default class for v1 registration.
pub const DEFAULT_EXECUTION_CLASS: AiExecutionModelClass = AiExecutionModelClass::FixedPointMlpV1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelClassLimits {
    pub max_width: usize,
    pub max_layers: usize,
    pub max_params: usize,
}

impl AiExecutionModelClass {
    pub fn limits(self) -> ModelClassLimits {
        match self {
            Self::FixedPointMlpV1 => ModelClassLimits {
                max_width: MAX_MLP_WIDTH,
                max_layers: MAX_MLP_LAYERS,
                max_params: MAX_MLP_PARAMS,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitelist_only_mlp_v1() {
        assert!(AiExecutionModelClass::from_u8(1).is_some());
        assert!(AiExecutionModelClass::from_u8(0).is_none());
        assert!(AiExecutionModelClass::from_u8(99).is_none());
        let lim = DEFAULT_EXECUTION_CLASS.limits();
        assert!(lim.max_params <= 4096);
    }
}
