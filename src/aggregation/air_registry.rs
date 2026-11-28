//! Phase 5 `AirRegistry`: binds canonical `AirId` digests to native Stage 2
//! (`verify_algebra`) constraint evaluators sharing the `BudZKVM` PCS.
//!
//! `BudAir` is always registered as a built-in entry (`AirRegistry::with_builtins`).
//! External AIRs using the exact same Goldilocks / Keccak / FRI PCS
//! configuration (such as [`ExternalFibAirEvaluator`]) register alongside it
//! and verify through `TransactionType::VerifyStark` + `Claim::Poly`.
//!
//! WIRING: `AirId`, `bud_air_id`, `agg_fold_air_id`, `external_fib_air_id`,
//! `AirVerifyError`, `VerifiedAlgebraResult`, `AirAlgebraEvaluator`,
//! `BudAirEvaluator`, `AggFoldAirEvaluator`, and `ExternalFibAirEvaluator`
//! form the public Phase 5 `AirRegistry` extension surface consumed by
//! `aggregation::chain::check_block_with_backend_and_airs`, external AIR
//! integrators, `src/aggregation/tests/phase5.rs`, and `benches/agg_phase5_pcs.rs`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use bincode::Options;
use bud_proof::chips::fib::verify_fibonacci_algebra;
use bud_proof::chips::fold::verify_agg_fold_algebra;
use bud_proof::plonky3_prover::verify_bud_air_algebra_u64;

use super::claim::{Claim, Ext, GOLDILOCKS_MODULUS};
use super::hash::{h, TAG_AIR_ID};
use super::programs::pcs_claim::{
    eval_value_of, poly_hash_of, BudAirAuxData, VerifyStarkTx, MAX_PCS_PUBLIC_VALUES,
};
use crate::domain::types::{DomainId, Hash32};

/// Maximum serialized size of `BudAirAuxData` inside `VerifyStarkTx::air_aux_data`.
pub const MAX_BUD_AIR_AUX_BYTES: u64 = 1024 * 1024;
/// Maximum `BudVM` instruction words accepted in `BudAirAuxData::program`.
const MAX_BUD_AIR_PROGRAM_WORDS: usize = 65_536;
/// Maximum opened extension elements allowed in a single opened trace row or quotient chunk.
const MAX_OPENED_VECTOR_LEN: usize = 4_096;
/// Maximum quotient chunks accepted in a single `VerifyStarkTx`.
const MAX_QUOTIENT_CHUNKS: usize = 256;

/// Canonical 32-byte identifier of a registered AIR inside [`AirRegistry`].
pub type AirId = Hash32;

/// Canonical [`AirId`] of the built-in `BudZKVM` (`BudAir`) evaluator.
#[must_use]
pub fn bud_air_id() -> AirId {
    h(&[TAG_AIR_ID, b"budlum.bud_air.v1"])
}

/// Canonical [`AirId`] of the built-in `AggFoldAir` evaluator.
#[must_use]
pub fn agg_fold_air_id() -> AirId {
    h(&[TAG_AIR_ID, b"budlum.agg_fold_air.v1"])
}

/// Canonical [`AirId`] of the reference external (non-`BudAir`) Fibonacci AIR.
#[must_use]
pub fn external_fib_air_id() -> AirId {
    h(&[TAG_AIR_ID, b"budlum.external_fib_air.v1"])
}

/// Why Stage 2 (`verify_algebra`) or `AirRegistry` verification refused a
/// `VerifyStark` statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AirVerifyError {
    /// `air_id` is not registered in [`AirRegistry`].
    UnknownAir(AirId),
    /// Attempting to register an already-present `air_id`.
    DuplicateAirId(AirId),
    /// `air_aux_data` could not be decoded or violated bounds.
    InvalidAuxData,
    /// A public value or opened limb is non-canonical (`>= GOLDILOCKS_MODULUS`).
    InvalidFieldElement,
    /// Stage 2 (`verify_algebra`) rejected the commitments, shape, or AIR constraints.
    AlgebraFailed(String),
    /// `tx.claim_refs` does not reference the re-derived `Claim::Poly` digest.
    MissingPolyClaimRef,
    /// The re-derived `Claim::Poly` digest is not proven by the block `ClaimFrame`.
    UnprovenPolyClaim,
}

impl std::fmt::Display for AirVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownAir(_) => write!(f, "verify_stark: AIR is not registered in AirRegistry"),
            Self::DuplicateAirId(_) => write!(f, "air_registry: duplicate AIR id"),
            Self::InvalidAuxData => write!(f, "verify_stark: invalid AIR auxiliary metadata"),
            Self::InvalidFieldElement => {
                write!(f, "verify_stark: non-canonical Goldilocks field element")
            }
            Self::AlgebraFailed(msg) => write!(f, "verify_stark: algebra check failed: {msg}"),
            Self::MissingPolyClaimRef => {
                write!(f, "verify_stark: tx.claim_refs omits expected Claim::Poly")
            }
            Self::UnprovenPolyClaim => {
                write!(f, "verify_stark: Claim::Poly is not proven in ClaimFrame")
            }
        }
    }
}

impl std::error::Error for AirVerifyError {}

/// Canonical outputs returned by an [`AirAlgebraEvaluator`] after re-deriving
/// `zeta` from commitments and public values and checking all AIR constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAlgebraResult {
    /// Canonical 256-bit polynomial-bundle commitment (`Claim::Poly.poly_hash`).
    pub poly_hash: Hash32,
    /// Re-derived out-of-domain point (`Claim::Poly.point == zeta`).
    pub zeta: Ext,
    /// Canonical opened-values digest (`Claim::Poly.value`).
    pub value: Ext,
}

/// Native Stage 2 (`verify_algebra`) evaluator bound to a single [`AirId`].
pub trait AirAlgebraEvaluator: Send + Sync {
    /// The unique [`AirId`] of this AIR.
    fn air_id(&self) -> AirId;

    /// Human-readable AIR name for diagnostics.
    fn name(&self) -> &'static str;

    /// Validates `stmt` without running FRI: checks shape, re-derives `zeta`
    /// from `stmt.commitments` and `stmt.public_values`, and verifies
    /// `constraints(zeta) / Z_H(zeta) == quotient(zeta)`.
    ///
    /// # Errors
    ///
    /// Returns [`AirVerifyError`] if inputs, auxiliary data, or constraints fail.
    fn verify_algebra_statement(
        &self,
        stmt: &VerifyStarkTx,
    ) -> Result<VerifiedAlgebraResult, AirVerifyError>;
}

fn validate_opened_slice(slice: &[[u64; 3]]) -> Result<(), AirVerifyError> {
    if slice.len() > MAX_OPENED_VECTOR_LEN {
        return Err(AirVerifyError::InvalidAuxData);
    }
    if slice
        .iter()
        .any(|limbs| limbs.iter().any(|&v| v >= GOLDILOCKS_MODULUS))
    {
        return Err(AirVerifyError::InvalidFieldElement);
    }
    Ok(())
}

/// Validates syntactic bounds and canonical Goldilocks field representation of
/// an on-chain [`VerifyStarkTx`] without allocating beyond the payload size.
///
/// Enforced both by every [`AirAlgebraEvaluator`] and directly by
/// `Executor::apply_transaction_checked` as defense in depth.
///
/// # Errors
///
/// Returns [`AirVerifyError`] if `degree_bits`, `air_aux_data`, opened vector
/// lengths, or any Goldilocks field limb is out of bounds.
pub fn validate_verify_stark_envelope(stmt: &VerifyStarkTx) -> Result<(), AirVerifyError> {
    if usize::from(stmt.degree_bits) > bud_proof::bud_stark::MAX_VERIFIER_DEGREE_BITS {
        return Err(AirVerifyError::InvalidAuxData);
    }
    if u64::try_from(stmt.air_aux_data.len()).unwrap_or(u64::MAX) > MAX_BUD_AIR_AUX_BYTES {
        return Err(AirVerifyError::InvalidAuxData);
    }
    if stmt.public_values.len() > MAX_PCS_PUBLIC_VALUES
        || stmt.public_values.iter().any(|&v| v >= GOLDILOCKS_MODULUS)
    {
        return Err(AirVerifyError::InvalidFieldElement);
    }
    let ov = &stmt.opened_values;
    validate_opened_slice(&ov.trace_local)?;
    if let Some(next) = &ov.trace_next {
        validate_opened_slice(next)?;
    }
    if let Some(aux_l) = &ov.aux_trace_local {
        validate_opened_slice(aux_l)?;
    }
    if let Some(aux_n) = &ov.aux_trace_next {
        validate_opened_slice(aux_n)?;
    }
    if let Some(pre_l) = &ov.preprocessed_local {
        validate_opened_slice(pre_l)?;
    }
    if let Some(pre_n) = &ov.preprocessed_next {
        validate_opened_slice(pre_n)?;
    }
    if ov.quotient_chunks.len() > MAX_QUOTIENT_CHUNKS {
        return Err(AirVerifyError::InvalidAuxData);
    }
    for chunk in &ov.quotient_chunks {
        validate_opened_slice(chunk)?;
    }
    if let Some(rand) = &ov.random {
        validate_opened_slice(rand)?;
    }
    Ok(())
}

fn validate_common_fields(stmt: &VerifyStarkTx) -> Result<(), AirVerifyError> {
    validate_verify_stark_envelope(stmt)
}

/// Decodes [`BudAirAuxData`] with byte and pre-allocation caps clamped strictly
/// to `bytes.len().min(MAX_BUD_AIR_AUX_BYTES)` so a short payload declaring a
/// huge `program` length cannot trigger oversized `Vec::with_capacity` allocation.
fn decode_bud_air_aux(bytes: &[u8]) -> Result<BudAirAuxData, AirVerifyError> {
    let raw_len = u64::try_from(bytes.len()).map_err(|_| AirVerifyError::InvalidAuxData)?;
    if bytes.is_empty() || raw_len > MAX_BUD_AIR_AUX_BYTES {
        return Err(AirVerifyError::InvalidAuxData);
    }
    let aux: BudAirAuxData = bincode::DefaultOptions::new()
        .with_limit(raw_len)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|_| AirVerifyError::InvalidAuxData)?;
    if aux.program.is_empty() || aux.program.len() > MAX_BUD_AIR_PROGRAM_WORDS {
        return Err(AirVerifyError::InvalidAuxData);
    }
    Ok(aux)
}

/// Built-in evaluator for the `BudZKVM` virtual machine AIR (`BudAir`).
pub struct BudAirEvaluator;

impl AirAlgebraEvaluator for BudAirEvaluator {
    fn air_id(&self) -> AirId {
        bud_air_id()
    }

    fn name(&self) -> &'static str {
        "BudAir"
    }

    fn verify_algebra_statement(
        &self,
        stmt: &VerifyStarkTx,
    ) -> Result<VerifiedAlgebraResult, AirVerifyError> {
        validate_common_fields(stmt)?;
        let aux = decode_bud_air_aux(&stmt.air_aux_data)?;
        let commitments = stmt.commitments.to_chip();
        let opened_values = stmt
            .opened_values
            .to_chip()
            .map_err(|_| AirVerifyError::InvalidFieldElement)?;
        let (zeta_limbs, shape, pre_commit) = verify_bud_air_algebra_u64(
            &aux.program,
            &aux.expected_inputs,
            &commitments,
            &opened_values,
            usize::from(stmt.degree_bits),
            &stmt.public_values,
        )
        .map_err(AirVerifyError::AlgebraFailed)?;
        let zeta = Ext::new(zeta_limbs).map_err(|_| AirVerifyError::InvalidFieldElement)?;
        let poly_hash = poly_hash_of(
            stmt.degree_bits,
            shape,
            &stmt.commitments,
            Some(&pre_commit),
        );
        let value = eval_value_of(&poly_hash, zeta, &stmt.opened_values)
            .map_err(|_| AirVerifyError::InvalidFieldElement)?;
        Ok(VerifiedAlgebraResult {
            poly_hash,
            zeta,
            value,
        })
    }
}

/// Built-in evaluator for the 23-column recursive fold AIR (`AggFoldAir`).
pub struct AggFoldAirEvaluator;

impl AirAlgebraEvaluator for AggFoldAirEvaluator {
    fn air_id(&self) -> AirId {
        agg_fold_air_id()
    }

    fn name(&self) -> &'static str {
        "AggFoldAir"
    }

    fn verify_algebra_statement(
        &self,
        stmt: &VerifyStarkTx,
    ) -> Result<VerifiedAlgebraResult, AirVerifyError> {
        validate_common_fields(stmt)?;
        if !stmt.air_aux_data.is_empty() {
            return Err(AirVerifyError::InvalidAuxData);
        }
        let commitments = stmt.commitments.to_chip();
        let opened_values = stmt
            .opened_values
            .to_chip()
            .map_err(|_| AirVerifyError::InvalidFieldElement)?;
        let (zeta_limbs, shape) = verify_agg_fold_algebra(
            &commitments,
            &opened_values,
            usize::from(stmt.degree_bits),
            &stmt.public_values,
        )
        .map_err(AirVerifyError::AlgebraFailed)?;
        let zeta = Ext::new(zeta_limbs).map_err(|_| AirVerifyError::InvalidFieldElement)?;
        let poly_hash = poly_hash_of(stmt.degree_bits, shape, &stmt.commitments, None);
        let value = eval_value_of(&poly_hash, zeta, &stmt.opened_values)
            .map_err(|_| AirVerifyError::InvalidFieldElement)?;
        Ok(VerifiedAlgebraResult {
            poly_hash,
            zeta,
            value,
        })
    }
}

/// Reference external (non-`BudZKVM`) AIR evaluator using the exact same
/// Goldilocks / Keccak / FRI PCS configuration (`FibonacciAir`).
pub struct ExternalFibAirEvaluator;

impl AirAlgebraEvaluator for ExternalFibAirEvaluator {
    fn air_id(&self) -> AirId {
        external_fib_air_id()
    }

    fn name(&self) -> &'static str {
        "ExternalFibAir"
    }

    fn verify_algebra_statement(
        &self,
        stmt: &VerifyStarkTx,
    ) -> Result<VerifiedAlgebraResult, AirVerifyError> {
        validate_common_fields(stmt)?;
        if !stmt.air_aux_data.is_empty() {
            return Err(AirVerifyError::InvalidAuxData);
        }
        let commitments = stmt.commitments.to_chip();
        let opened_values = stmt
            .opened_values
            .to_chip()
            .map_err(|_| AirVerifyError::InvalidFieldElement)?;
        let (zeta_limbs, shape) = verify_fibonacci_algebra(
            &commitments,
            &opened_values,
            usize::from(stmt.degree_bits),
            &stmt.public_values,
        )
        .map_err(AirVerifyError::AlgebraFailed)?;
        let zeta = Ext::new(zeta_limbs).map_err(|_| AirVerifyError::InvalidFieldElement)?;
        let poly_hash = poly_hash_of(stmt.degree_bits, shape, &stmt.commitments, None);
        let value = eval_value_of(&poly_hash, zeta, &stmt.opened_values)
            .map_err(|_| AirVerifyError::InvalidFieldElement)?;
        Ok(VerifiedAlgebraResult {
            poly_hash,
            zeta,
            value,
        })
    }
}

/// Registry binding canonical [`AirId`] digests to native Stage 2
/// (`verify_algebra`) constraint evaluators.
#[derive(Default)]
pub struct AirRegistry {
    evaluators: BTreeMap<AirId, Arc<dyn AirAlgebraEvaluator>>,
}

impl AirRegistry {
    /// Builds the default registry containing the built-in `BudAir` and
    /// `AggFoldAir` evaluators.
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut reg = Self::default();
        let _ = reg.register(Arc::new(BudAirEvaluator));
        let _ = reg.register(Arc::new(AggFoldAirEvaluator));
        reg
    }

    /// Registers an AIR evaluator under its canonical [`AirId`].
    ///
    /// # Errors
    ///
    /// Returns [`AirVerifyError::DuplicateAirId`] if an evaluator is already
    /// registered for that [`AirId`].
    pub fn register(
        &mut self,
        evaluator: Arc<dyn AirAlgebraEvaluator>,
    ) -> Result<(), AirVerifyError> {
        let id = evaluator.air_id();
        if self.evaluators.contains_key(&id) {
            return Err(AirVerifyError::DuplicateAirId(id));
        }
        self.evaluators.insert(id, evaluator);
        Ok(())
    }

    /// Looks up a registered AIR evaluator by [`AirId`].
    #[must_use]
    pub fn get(&self, id: &AirId) -> Option<&Arc<dyn AirAlgebraEvaluator>> {
        self.evaluators.get(id)
    }

    /// Verifies an on-chain [`VerifyStarkTx`] against `self`, re-deriving
    /// `zeta` locally, running `verify_algebra`, and asserting that the
    /// resulting `Claim::Poly { poly_hash, point: zeta, value }` is both
    /// referenced by `claim_refs` and present in `proven_claims`.
    ///
    /// # Errors
    ///
    /// Returns [`AirVerifyError`] if `stmt.air_id` is unregistered, algebra
    /// verification fails, `claim_refs` omits the expected `Claim::Poly`, or
    /// the claim is not proven in the block `ClaimFrame`.
    pub fn verify_stark_tx(
        &self,
        domain: DomainId,
        stmt: &VerifyStarkTx,
        claim_refs: &[Hash32],
        proven_claims: &BTreeSet<Hash32>,
    ) -> Result<Claim, AirVerifyError> {
        let evaluator = self
            .get(&stmt.air_id)
            .ok_or(AirVerifyError::UnknownAir(stmt.air_id))?;
        // Fail fast before running Stage 2 algebra or BudAir preprocessed setup
        // when the transaction has no referenced or proven Claim::Poly digest.
        if claim_refs.is_empty() {
            return Err(AirVerifyError::MissingPolyClaimRef);
        }
        if !claim_refs.iter().any(|r| proven_claims.contains(r)) {
            return Err(AirVerifyError::UnprovenPolyClaim);
        }
        let alg = evaluator.verify_algebra_statement(stmt)?;
        let expected_claim = Claim::Poly {
            poly_hash: alg.poly_hash,
            point: alg.zeta,
            value: alg.value,
        };
        let expected_digest = expected_claim.digest(domain);
        if !claim_refs.contains(&expected_digest) {
            return Err(AirVerifyError::MissingPolyClaimRef);
        }
        if !proven_claims.contains(&expected_digest) {
            return Err(AirVerifyError::UnprovenPolyClaim);
        }
        Ok(expected_claim)
    }
}
