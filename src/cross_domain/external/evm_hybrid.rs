//! Deterministic planning for verifying Budlum's hybrid finality proof on an EVM.
//!
//! This module does not pretend that a gas estimate is a cryptographic proof.
//! It records the two facts that decide the reverse direction separately:
//!
//! * which verification precompiles the target chain actually exposes; and
//! * whether the BLS message point is bound to the signed root by a circuit or
//!   a native hash-to-curve operation.
//!
//! EIP-2537 accepts uncompressed points. It does not decompress Ethereum's
//! compressed sync-committee points and it does not perform the complete
//! hash-to-curve procedure. A plan that says "BLS precompile present" while
//! leaving the message point unbound is therefore rejected before a contract
//! can call it. The optimistic mode is explicit and carries a challenge
//! window; it is never reported as cryptographic finality.

use serde::{Deserialize, Serialize};

/// Final EIP-2537 allocation. The constants are part of the wire contract,
/// not an implementation detail: early drafts used different addresses.
pub const BLS_G1_ADD_ADDRESS: u64 = 0x0b;
pub const BLS_G1_MSM_ADDRESS: u64 = 0x0c;
pub const BLS_G2_ADD_ADDRESS: u64 = 0x0d;
pub const BLS_G2_MSM_ADDRESS: u64 = 0x0e;
pub const BLS_PAIRING_ADDRESS: u64 = 0x0f;
pub const BLS_MAP_FP_TO_G1_ADDRESS: u64 = 0x10;
pub const BLS_MAP_FP2_TO_G2_ADDRESS: u64 = 0x11;

/// EIP-8051's proposed ML-DSA allocations. EIP-8051 is not a deployed
/// mainnet guarantee, so the runtime probe remains mandatory.
pub const ML_DSA_FIPS_ADDRESS: u64 = 0x12;
pub const ML_DSA_ETH_ADDRESS: u64 = 0x13;

/// A runtime observation of one precompile address. An empty successful call
/// is not enough to identify an implementation (an EOA also succeeds), so a
/// caller must mark `recognised` only after the chain-specific probe has
/// checked the expected ABI and output shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrecompileObservation {
    pub address: u64,
    pub call_succeeded: bool,
    pub returned_expected_shape: bool,
}

impl PrecompileObservation {
    /// Whether this observation proves that the address is usable for the
    /// requested ABI. Both checks are needed: success with garbage is not a
    /// cryptographic capability.
    #[must_use]
    pub fn recognised(&self) -> bool {
        self.call_succeeded && self.returned_expected_shape
    }
}

/// Capabilities observed at deployment time. These booleans mean "the probe
/// passed", not merely "the address was empty".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmPrecompiles {
    pub bls_pairing: bool,
    pub ml_dsa_fips: bool,
    pub ml_dsa_eth: bool,
}

impl EvmPrecompiles {
    /// Builds the capability set from explicit ABI probes. Unknown addresses
    /// and duplicate observations are ignored rather than guessed.
    #[must_use]
    pub fn from_observations(observations: &[PrecompileObservation]) -> Self {
        let mut out = Self {
            bls_pairing: false,
            ml_dsa_fips: false,
            ml_dsa_eth: false,
        };
        for observation in observations {
            if !observation.recognised() {
                continue;
            }
            match observation.address {
                BLS_PAIRING_ADDRESS => out.bls_pairing = true,
                ML_DSA_FIPS_ADDRESS => out.ml_dsa_fips = true,
                ML_DSA_ETH_ADDRESS => out.ml_dsa_eth = true,
                _ => {}
            }
        }
        out
    }

    #[must_use]
    pub fn has_ml_dsa(&self) -> bool {
        self.ml_dsa_fips || self.ml_dsa_eth
    }

    /// Chooses the FIPS variant when available. Falling back to the ETH
    /// variant is a deliberate wire-format decision, not a compatibility
    /// guess: the two variants do not accept the same keys.
    #[must_use]
    pub fn ml_dsa_variant(&self) -> Option<MlDsaVariant> {
        if self.ml_dsa_fips {
            Some(MlDsaVariant::Fips204)
        } else if self.ml_dsa_eth {
            Some(MlDsaVariant::Eip8051Eth)
        } else {
            None
        }
    }
}

/// The two EIP-8051 key encodings. They are different algorithms at the
/// encoding boundary even though both are named ML-DSA in casual discussion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MlDsaVariant {
    Fips204,
    Eip8051Eth,
}

/// How the BLS message point was connected to the signed root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageBinding {
    /// A STARK/SNARK circuit checked expand-message, field decoding,
    /// hash-to-curve and point decompression before producing the uncompressed
    /// point supplied to EIP-2537.
    ZkCircuit,
    /// The target chain has a native operation whose specification covers the
    /// complete hash-to-curve suite used by this proof. EIP-2537's map-to-curve
    /// operations alone do not qualify.
    NativeHashToCurve,
    /// The caller merely supplied a point. This is never enough for full
    /// cryptographic mode.
    Unbound,
}

/// The exact mode the target EVM can offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvmVerificationMode {
    /// BLS and ML-DSA both verify now, and the BLS message point is bound.
    FullCryptographic,
    /// BLS verifies now; the post-quantum half is held behind a challenge
    /// window. This is not equivalent to the hybrid proof.
    ClassicalOnlyChallenge,
    /// ML-DSA verifies now; the BLS half is held behind a challenge window.
    PostQuantumOnlyChallenge,
    /// No native verifier is available. The claim remains pending until the
    /// challenge window closes.
    OptimisticChallenge,
}

/// Published gas assumptions. They are estimates, not consensus facts; a
/// deployment should replace them with its chain's schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmGasSchedule {
    /// EIP-2537 pairing cost. It is variable by input and client; this is the
    /// contract call budget rather than a claim about every target chain.
    pub bls_pairing_budget: u64,
    /// EIP-8051 published proposal cost for either ML-DSA variant.
    pub ml_dsa_verify: u64,
    pub transaction_base: u64,
    pub calldata_zero: u64,
    pub calldata_nonzero: u64,
}

impl Default for EvmGasSchedule {
    fn default() -> Self {
        Self {
            bls_pairing_budget: 400_000,
            ml_dsa_verify: 4_500,
            transaction_base: 21_000,
            calldata_zero: 4,
            calldata_nonzero: 16,
        }
    }
}

/// Proof material crossing into the EVM. The point lengths are explicit here
/// because accepting compressed bytes and forwarding them to EIP-2537 is a
/// format error, not a recoverable verification failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmHybridProof {
    pub chain_id: u64,
    pub height: u64,
    pub state_root: [u8; 32],
    pub g1_hashed_message: Vec<u8>,
    pub g2_aggregate_pubkey: Vec<u8>,
    pub g1_generator: Vec<u8>,
    pub g2_negated_signature: Vec<u8>,
    pub ml_dsa_public_key: Vec<u8>,
    pub ml_dsa_signature: Vec<u8>,
    /// The exact EIP-8051 encoding used by these bytes. FIPS-204 and the ETH
    /// variant are not interchangeable, even when their field sizes match.
    pub ml_dsa_variant: MlDsaVariant,
    pub message_binding: MessageBinding,
    /// Number of zero and non-zero bytes in the ABI payload. The planner does
    /// not guess ABI padding; the caller supplies the exact encoded counts.
    pub calldata_zero_bytes: u64,
    pub calldata_nonzero_bytes: u64,
}

/// Maximum individual ML-DSA field accepted by the planner. This is a
/// resource bound, not a claim that every parameter set has this size.
pub const MAX_ML_DSA_FIELD_BYTES: usize = 8 * 1024;

impl EvmHybridProof {
    /// Performs shape and resource checks before selecting a verification mode.
    pub fn validate_shape(&self) -> Result<(), EvmPlanError> {
        let points = [
            ("g1_hashed_message", self.g1_hashed_message.len(), 128usize),
            ("g1_generator", self.g1_generator.len(), 128usize),
            ("g2_aggregate_pubkey", self.g2_aggregate_pubkey.len(), 256usize),
            (
                "g2_negated_signature",
                self.g2_negated_signature.len(),
                256usize,
            ),
        ];
        for (name, actual, expected) in points {
            if actual != expected {
                return Err(EvmPlanError::WrongPointLength {
                    field: name,
                    expected,
                    actual,
                });
            }
        }
        for (field, length) in [
            ("ml_dsa_public_key", self.ml_dsa_public_key.len()),
            ("ml_dsa_signature", self.ml_dsa_signature.len()),
        ] {
            if length == 0 || length > MAX_ML_DSA_FIELD_BYTES {
                return Err(EvmPlanError::BadMlDsaLength { field, length });
            }
        }
        if self.g1_hashed_message.iter().all(|byte| *byte == 0)
            || self.g2_aggregate_pubkey.iter().all(|byte| *byte == 0)
            || self.g1_generator.iter().all(|byte| *byte == 0)
            || self.g2_negated_signature.iter().all(|byte| *byte == 0)
        {
            return Err(EvmPlanError::IdentityPoint);
        }
        Ok(())
    }

    /// The bytes charged by the caller's ABI encoding, excluding the fixed
    /// transaction base. Kept separate so a UI can show crypto gas and data
    /// gas rather than presenting one unexplained number.
    #[must_use]
    pub fn calldata_gas(&self, schedule: EvmGasSchedule) -> u64 {
        self.calldata_zero_bytes
            .saturating_mul(schedule.calldata_zero)
            .saturating_add(
                self.calldata_nonzero_bytes
                    .saturating_mul(schedule.calldata_nonzero),
            )
    }
}

/// Why no plan was produced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EvmPlanError {
    #[error("{field} has {actual} bytes; EIP-2537 requires {expected} uncompressed bytes")]
    WrongPointLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("{field} has {length} bytes, outside the ML-DSA resource bound")]
    BadMlDsaLength { field: &'static str, length: usize },
    #[error("an identity BLS point cannot carry a finality signature")]
    IdentityPoint,
    #[error("a full cryptographic plan needs a bound BLS message point")]
    UnboundMessagePoint,
    #[error("optimistic mode requires a non-zero challenge window")]
    MissingChallengeWindow,
    #[error("the chain id is zero")]
    ZeroChainId,
    #[error(
        "the proof declares ML-DSA variant {variant:?}, but the chain did not probe that verifier"
    )]
    MlDsaVariantUnavailable { variant: MlDsaVariant },
}

/// A selected verification plan, suitable for a deployment report or a
/// contract configuration transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmVerificationPlan {
    pub mode: EvmVerificationMode,
    pub ml_dsa_variant: Option<MlDsaVariant>,
    pub estimated_gas: u64,
    pub challenge_window: u64,
    pub cryptographic: bool,
}

impl EvmVerificationPlan {
    /// Returns whether this plan can be treated as immediate finality. The
    /// optimistic variants remain pending until the window is settled.
    #[must_use]
    fn is_immediate(&self) -> bool {
        self.cryptographic
    }
}

/// Selects the strongest honest mode available on a target EVM.
///
/// Shape is checked even for optimistic mode: accepting malformed material
/// into a pending queue is a denial-of-service footgun, not a security model.
/// Performs the runtime-probe-to-plan step in one call. Keeping the probe
/// conversion here prevents a caller from accidentally treating an address
/// list as a capability list without checking the ABI response.
pub fn plan_from_observations(
    observations: &[PrecompileObservation],
    proof: &EvmHybridProof,
    schedule: EvmGasSchedule,
    challenge_window: u64,
) -> Result<EvmVerificationPlan, EvmPlanError> {
    plan_verification(
        EvmPrecompiles::from_observations(observations),
        proof,
        schedule,
        challenge_window,
    )
}

pub fn plan_verification(
    capabilities: EvmPrecompiles,
    proof: &EvmHybridProof,
    schedule: EvmGasSchedule,
    challenge_window: u64,
) -> Result<EvmVerificationPlan, EvmPlanError> {
    if proof.chain_id == 0 {
        return Err(EvmPlanError::ZeroChainId);
    }
    proof.validate_shape()?;
    let bls = capabilities.bls_pairing;
    let pq = capabilities.has_ml_dsa();
    if pq {
        let variant_available = match proof.ml_dsa_variant {
            MlDsaVariant::Fips204 => capabilities.ml_dsa_fips,
            MlDsaVariant::Eip8051Eth => capabilities.ml_dsa_eth,
        };
        if !variant_available {
            return Err(EvmPlanError::MlDsaVariantUnavailable {
                variant: proof.ml_dsa_variant,
            });
        }
    }
    let bound = !matches!(proof.message_binding, MessageBinding::Unbound);
    let mode = match (bls, pq) {
        (true, true) if bound => EvmVerificationMode::FullCryptographic,
        (true, true) => return Err(EvmPlanError::UnboundMessagePoint),
        (true, false) => EvmVerificationMode::ClassicalOnlyChallenge,
        (false, true) => EvmVerificationMode::PostQuantumOnlyChallenge,
        (false, false) => EvmVerificationMode::OptimisticChallenge,
    };
    let cryptographic = matches!(mode, EvmVerificationMode::FullCryptographic);
    if !cryptographic && challenge_window == 0 {
        return Err(EvmPlanError::MissingChallengeWindow);
    }
    let crypto_gas = (if bls {
        schedule.bls_pairing_budget
    } else {
        0
    })
    .saturating_add(if pq { schedule.ml_dsa_verify } else { 0 });
    let estimated_gas = schedule
        .transaction_base
        .saturating_add(crypto_gas)
        .saturating_add(proof.calldata_gas(schedule));
    Ok(EvmVerificationPlan {
        mode,
        ml_dsa_variant: pq.then_some(proof.ml_dsa_variant),
        estimated_gas,
        challenge_window: if cryptographic { 0 } else { challenge_window },
        cryptographic,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(len: usize, byte: u8) -> Vec<u8> {
        vec![byte; len]
    }

    fn proof(binding: MessageBinding) -> EvmHybridProof {
        EvmHybridProof {
            chain_id: 1,
            height: 42,
            state_root: [7; 32],
            g1_hashed_message: point(128, 1),
            g2_aggregate_pubkey: point(256, 2),
            g1_generator: point(128, 3),
            g2_negated_signature: point(256, 4),
            ml_dsa_public_key: point(1_952, 5),
            ml_dsa_signature: point(3_293, 6),
            ml_dsa_variant: MlDsaVariant::Fips204,
            message_binding: binding,
            calldata_zero_bytes: 100,
            calldata_nonzero_bytes: 200,
        }
    }

    #[test]
    fn final_addresses_are_adjacent_not_overlapping() {
        assert_eq!(BLS_PAIRING_ADDRESS, 0x0f);
        assert_eq!(ML_DSA_FIPS_ADDRESS, 0x12);
        assert_eq!(ML_DSA_ETH_ADDRESS, 0x13);
        assert_ne!(BLS_PAIRING_ADDRESS, ML_DSA_FIPS_ADDRESS);
    }

    #[test]
    fn an_empty_successful_probe_is_not_a_capability() {
        let capabilities = EvmPrecompiles::from_observations(&[
            PrecompileObservation {
                address: BLS_PAIRING_ADDRESS,
                call_succeeded: true,
                returned_expected_shape: false,
            },
            PrecompileObservation {
                address: ML_DSA_FIPS_ADDRESS,
                call_succeeded: true,
                returned_expected_shape: true,
            },
        ]);
        assert!(!capabilities.bls_pairing);
        assert!(capabilities.has_ml_dsa());
    }

    #[test]
    fn both_precompiles_and_a_circuit_produce_immediate_crypto_mode() {
        let plan = plan_verification(
            EvmPrecompiles {
                bls_pairing: true,
                ml_dsa_fips: true,
                ml_dsa_eth: false,
            },
            &proof(MessageBinding::ZkCircuit),
            EvmGasSchedule::default(),
            100,
        )
        .expect("the complete path is available");
        assert_eq!(plan.mode, EvmVerificationMode::FullCryptographic);
        assert!(plan.is_immediate());
        assert_eq!(plan.challenge_window, 0);
        assert_eq!(plan.ml_dsa_variant, Some(MlDsaVariant::Fips204));
    }

    #[test]
    fn a_fips_proof_is_not_run_through_only_the_eth_variant() {
        let err = plan_verification(
            EvmPrecompiles {
                bls_pairing: true,
                ml_dsa_fips: false,
                ml_dsa_eth: true,
            },
            &proof(MessageBinding::ZkCircuit),
            EvmGasSchedule::default(),
            100,
        )
        .unwrap_err();
        assert_eq!(
            err,
            EvmPlanError::MlDsaVariantUnavailable {
                variant: MlDsaVariant::Fips204
            }
        );
    }

    #[test]
    fn unbound_points_are_not_accepted_as_full_hybrid_finality() {
        let err = plan_verification(
            EvmPrecompiles {
                bls_pairing: true,
                ml_dsa_fips: true,
                ml_dsa_eth: false,
            },
            &proof(MessageBinding::Unbound),
            EvmGasSchedule::default(),
            100,
        )
        .unwrap_err();
        assert_eq!(err, EvmPlanError::UnboundMessagePoint);
    }

    #[test]
    fn absent_pq_is_a_challenge_mode_not_a_silent_downgrade() {
        let plan = plan_verification(
            EvmPrecompiles {
                bls_pairing: true,
                ml_dsa_fips: false,
                ml_dsa_eth: false,
            },
            &proof(MessageBinding::ZkCircuit),
            EvmGasSchedule::default(),
            64,
        )
        .expect("the challenge window makes the downgrade explicit");
        assert_eq!(plan.mode, EvmVerificationMode::ClassicalOnlyChallenge);
        assert!(!plan.is_immediate());
        assert_eq!(plan.challenge_window, 64);
    }

    #[test]
    fn no_crypto_path_without_a_window_is_refused() {
        let err = plan_verification(
            EvmPrecompiles {
                bls_pairing: false,
                ml_dsa_fips: false,
                ml_dsa_eth: false,
            },
            &proof(MessageBinding::ZkCircuit),
            EvmGasSchedule::default(),
            0,
        )
        .unwrap_err();
        assert_eq!(err, EvmPlanError::MissingChallengeWindow);
    }

    #[test]
    fn compressed_points_are_rejected_before_gas_is_reported() {
        let mut short = proof(MessageBinding::ZkCircuit);
        short.g1_hashed_message.truncate(96);
        let err = plan_verification(
            EvmPrecompiles {
                bls_pairing: true,
                ml_dsa_fips: true,
                ml_dsa_eth: false,
            },
            &short,
            EvmGasSchedule::default(),
            100,
        )
        .unwrap_err();
        assert!(matches!(err, EvmPlanError::WrongPointLength { .. }));
    }
}
