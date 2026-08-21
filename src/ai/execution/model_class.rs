//! Bounded model-class whitelist for on-chain AI execution (v1).

use serde::{Deserialize, Serialize};

/// Maximum linear layer width (neurons) for v1 fixed-point MLP.
///
/// This is a per-dimension ceiling, not a shape that is always reachable:
/// guest memory binds first. A `[64, 1]` model fits comfortably, a `[64, 64]`
/// one does not. `FixedPointMlpSpec::validate` rejects the difference instead
/// of letting it surface as a truncated forward pass.
pub const MAX_MLP_WIDTH: usize = 64;
/// Maximum number of dense layers (including output).
pub const MAX_MLP_LAYERS: usize = 4;
/// Maximum total weight parameters (weights + biases).
///
/// Rarely the binding limit. The guest memory image (8 KiB) caps a square
/// hidden layer at roughly 28 neurons, well below the 4096-parameter budget,
/// so a spec can be within this constant and still be rejected.
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

    /// The class advertises a width; at least one shape at that width must be
    /// buildable, otherwise the constant is decoration.
    #[test]
    fn max_width_is_reachable_in_at_least_one_shape() {
        use crate::ai::execution::FixedPointMlpSpec;
        let spec = FixedPointMlpSpec {
            dims: vec![MAX_MLP_WIDTH as u16, 1],
            weights: vec![1; MAX_MLP_WIDTH],
            biases: vec![0],
        };
        assert!(
            spec.validate().is_ok(),
            "MAX_MLP_WIDTH must be usable in some valid model"
        );
    }

    /// And a shape that the parameter budget allows but guest memory does not
    /// must be rejected up front, not truncated at run time.
    #[test]
    fn memory_binds_before_the_parameter_budget() {
        use crate::ai::execution::FixedPointMlpSpec;
        let n = 32usize;
        let spec = FixedPointMlpSpec {
            dims: vec![n as u16, n as u16],
            weights: vec![1; n * n],
            biases: vec![0; n],
        };
        assert!(
            spec.weights.len() + spec.biases.len() <= MAX_MLP_PARAMS,
            "this shape is within the parameter budget"
        );
        let err = spec
            .validate()
            .expect_err("but guest memory cannot hold it");
        assert!(
            err.contains("guest memory"),
            "rejection must name the real limit, got: {err}"
        );
    }
}
