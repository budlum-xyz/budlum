//! Phase 5 PCS opening objects, `VerifyStarkTx` payloads, and `Claim::Poly`
//! derivation (`ObjectKind::PcsOpening -> Claim::Poly`).
//!
//! A [`PcsOpeningObject`] carries the heavy FRI + Merkle opening proof off
//! chain inside the aggregation `ObjectPool`. Aggregators run Stage 1
//! ([`bud_proof::plonky3_prover::verify_chip_pcs_openings_u64`]) once, derive
//! a compact 81-byte `Claim::Poly { poly_hash, point, value }`, and fold it
//! into the block `MasterProof`. The on-chain [`VerifyStarkTx`] transaction
//! omits the FRI proof completely and only carries commitments, public values,
//! opened values, and references to the proven `Claim::Poly` digest(s) so the
//! chain runs Stage 2 (`verify_algebra`) and re-derives `zeta` locally.
//!
//! WIRING: `WireCommitments`, `WireOpenedValues`, `from_chip`, `from_chip_proof`,
//! `from_bud_envelope`, and `to_verify_stark_tx` are the Phase 5 prover/wallet
//! constructors for `ObjectKind::PcsOpening` envelopes and `TransactionType::VerifyStark`
//! payloads, exercised by `src/aggregation/tests/phase5.rs` and `benches/agg_phase5_pcs.rs`.

use std::io::{Read, Write};

use bincode::Options;
use bud_proof::adapter::{ExecutionPublicInputs, ProofEnvelope};
use bud_proof::bud_stark::{PcsOpeningShape, MAX_VERIFIER_DEGREE_BITS};
use bud_proof::plonky3_prover::{
    chip_commitment_from_bytes, chip_commitment_to_bytes, chip_ext_from_limbs, chip_ext_to_limbs,
    extract_bud_envelope_pcs, verify_chip_pcs_openings_u64, ChipCommitments, ChipOpenedValues,
    ChipPcsProof, ChipProof,
};
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use super::super::claim::{Claim, Ext, GOLDILOCKS_MODULUS};
use super::super::hash::{TAG_PCS_EVAL, TAG_PCS_POLY};
use super::super::object::ObjectError;
use crate::domain::types::Hash32;

/// Magic prefix of a canonical `PcsOpeningObject` wire envelope.
const PCS_OBJECT_MAGIC: [u8; 4] = *b"BDP5";
/// Wire format version of `PcsOpeningObject`.
const PCS_OBJECT_VERSION: u8 = 1;
/// Hard cap on decompressed bytes inside a `PcsOpeningObject` (zip-bomb guard).
const MAX_DECOMPRESSED_PCS_BYTES: usize = 4 * 1024 * 1024;
/// Upper bound on public values carried by one `PcsOpeningObject` or `VerifyStarkTx`.
pub const MAX_PCS_PUBLIC_VALUES: usize = 1024;

/// Canonical 32-byte polynomial commitments carried in [`PcsOpeningObject`]
/// and [`VerifyStarkTx`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireCommitments {
    /// Commitment to the main execution trace matrix.
    pub trace: Hash32,
    /// Optional commitment to the auxiliary (LogUp) trace matrix.
    pub aux_trace: Option<Hash32>,
    /// Commitment to the quotient chunk polynomials.
    pub quotient_chunks: Hash32,
    /// Optional randomization commitment (always `None` for non-ZK PCS).
    pub random: Option<Hash32>,
}

impl WireCommitments {
    /// Converts from a `bud-proof` [`ChipCommitments`] value.
    ///
    /// # Errors
    ///
    /// Returns [`ObjectError::Invalid`] if any commitment has a non-unit cap height.
    pub fn from_chip(commits: &ChipCommitments) -> Result<Self, ObjectError> {
        let trace = chip_commitment_to_bytes(&commits.trace).ok_or(ObjectError::Invalid)?;
        let aux_trace = match &commits.aux_trace {
            Some(c) => Some(chip_commitment_to_bytes(c).ok_or(ObjectError::Invalid)?),
            None => None,
        };
        let quotient_chunks =
            chip_commitment_to_bytes(&commits.quotient_chunks).ok_or(ObjectError::Invalid)?;
        let random = match &commits.random {
            Some(c) => Some(chip_commitment_to_bytes(c).ok_or(ObjectError::Invalid)?),
            None => None,
        };
        Ok(Self {
            trace,
            aux_trace,
            quotient_chunks,
            random,
        })
    }

    /// Converts into a `bud-proof` [`ChipCommitments`] value.
    #[must_use]
    pub fn to_chip(&self) -> ChipCommitments {
        ChipCommitments {
            trace: chip_commitment_from_bytes(self.trace),
            aux_trace: self.aux_trace.map(chip_commitment_from_bytes),
            quotient_chunks: chip_commitment_from_bytes(self.quotient_chunks),
            random: self.random.map(chip_commitment_from_bytes),
        }
    }
}

/// Canonical out-of-domain opened values carried in [`PcsOpeningObject`] and
/// [`VerifyStarkTx`], stored as 3 canonical Goldilocks limbs per cubic
/// extension element.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireOpenedValues {
    /// Main trace row opened at `zeta`.
    pub trace_local: Vec<[u64; 3]>,
    /// Optional main trace row opened at `zeta_next`.
    pub trace_next: Option<Vec<[u64; 3]>>,
    /// Optional auxiliary trace row opened at `zeta`.
    pub aux_trace_local: Option<Vec<[u64; 3]>>,
    /// Optional auxiliary trace row opened at `zeta_next`.
    pub aux_trace_next: Option<Vec<[u64; 3]>>,
    /// Optional preprocessed trace row opened at `zeta`.
    pub preprocessed_local: Option<Vec<[u64; 3]>>,
    /// Optional preprocessed trace row opened at `zeta_next`.
    pub preprocessed_next: Option<Vec<[u64; 3]>>,
    /// Quotient chunk evaluations opened at `zeta`.
    pub quotient_chunks: Vec<Vec<[u64; 3]>>,
    /// Optional randomization evaluations opened at `zeta`.
    pub random: Option<Vec<[u64; 3]>>,
}

fn vec_to_chip_ext(
    vals: &[[u64; 3]],
) -> Result<Vec<bud_proof::plonky3_prover::ChipExtensionField>, ObjectError> {
    let mut out = Vec::with_capacity(vals.len());
    for &limbs in vals {
        out.push(chip_ext_from_limbs(limbs).ok_or(ObjectError::Invalid)?);
    }
    Ok(out)
}

fn opt_vec_to_chip_ext(
    vals: Option<&Vec<[u64; 3]>>,
) -> Result<Option<Vec<bud_proof::plonky3_prover::ChipExtensionField>>, ObjectError> {
    match vals {
        Some(v) => Ok(Some(vec_to_chip_ext(v)?)),
        None => Ok(None),
    }
}

impl WireOpenedValues {
    /// Converts from a `bud-proof` [`ChipOpenedValues`] value.
    #[must_use]
    pub fn from_chip(ov: &ChipOpenedValues) -> Self {
        let map_slice = |s: &[bud_proof::plonky3_prover::ChipExtensionField]| -> Vec<[u64; 3]> {
            s.iter().map(|&e| chip_ext_to_limbs(e)).collect()
        };
        Self {
            trace_local: map_slice(&ov.trace_local),
            trace_next: ov.trace_next.as_deref().map(map_slice),
            aux_trace_local: ov.aux_trace_local.as_deref().map(map_slice),
            aux_trace_next: ov.aux_trace_next.as_deref().map(map_slice),
            preprocessed_local: ov.preprocessed_local.as_deref().map(map_slice),
            preprocessed_next: ov.preprocessed_next.as_deref().map(map_slice),
            quotient_chunks: ov.quotient_chunks.iter().map(|c| map_slice(c)).collect(),
            random: ov.random.as_deref().map(map_slice),
        }
    }

    /// Converts into a `bud-proof` [`ChipOpenedValues`] value, refusing any
    /// non-canonical Goldilocks limb (`>= GOLDILOCKS_MODULUS`).
    ///
    /// # Errors
    ///
    /// Returns [`ObjectError::Invalid`] if any limb is non-canonical.
    pub fn to_chip(&self) -> Result<ChipOpenedValues, ObjectError> {
        let mut quotient_chunks = Vec::with_capacity(self.quotient_chunks.len());
        for chunk in &self.quotient_chunks {
            quotient_chunks.push(vec_to_chip_ext(chunk)?);
        }
        Ok(ChipOpenedValues {
            trace_local: vec_to_chip_ext(&self.trace_local)?,
            trace_next: opt_vec_to_chip_ext(self.trace_next.as_ref())?,
            aux_trace_local: opt_vec_to_chip_ext(self.aux_trace_local.as_ref())?,
            aux_trace_next: opt_vec_to_chip_ext(self.aux_trace_next.as_ref())?,
            preprocessed_local: opt_vec_to_chip_ext(self.preprocessed_local.as_ref())?,
            preprocessed_next: opt_vec_to_chip_ext(self.preprocessed_next.as_ref())?,
            quotient_chunks,
            random: opt_vec_to_chip_ext(self.random.as_ref())?,
        })
    }
}

/// On-chain payload of `TransactionType::VerifyStark`.
///
/// Carries only the AIR identifier, instance public values, polynomial
/// commitments, and out-of-domain opened values. Zero FRI or Merkle opening
/// proof bytes enter the block; the corresponding `Claim::Poly` digest travels
/// in `tx.claim_refs` and is proven by the block `MasterProof`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyStarkTx {
    /// Canonical `AirRegistry` identifier selecting the native constraint evaluator.
    pub air_id: Hash32,
    /// Base-2 logarithm of the trace height.
    pub degree_bits: u8,
    /// Public values as canonical Goldilocks elements (`< GOLDILOCKS_MODULUS`).
    pub public_values: Vec<u64>,
    /// Optional AIR-specific verifier metadata (for `BudAir`: serialized
    /// [`BudAirAuxData`]).
    pub air_aux_data: Vec<u8>,
    /// Matrix commitments bound into the Fiat-Shamir transcript.
    pub commitments: WireCommitments,
    /// Out-of-domain opened values evaluated by `verify_algebra`.
    pub opened_values: WireOpenedValues,
}

/// Auxiliary verifier metadata carried in [`VerifyStarkTx::air_aux_data`] for
/// the built-in `BudAir` entry in `AirRegistry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudAirAuxData {
    /// `BudVM` program words verified against `MainnetActivation::default()`.
    pub program: Vec<u64>,
    /// Canonical `ExecutionPublicInputs` matching `VerifyStarkTx::public_values`.
    pub expected_inputs: ExecutionPublicInputs,
}

/// Off-chain heavy PCS opening object submitted via `ObjectKind::PcsOpening`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcsOpeningObject {
    /// Base-2 logarithm of the trace height.
    pub degree_bits: u8,
    /// Main execution trace column width.
    pub air_width: u32,
    /// Preprocessed matrix width (`0` if no preprocessed columns).
    pub preprocessed_width: u32,
    /// Preprocessed commitment root (present iff `preprocessed_width > 0`).
    pub preprocessed_commit: Option<Hash32>,
    /// Base-2 logarithm of the quotient chunk count.
    pub log_num_quotient_chunks: u8,
    /// Whether the AIR opens `trace_next` (and `aux_trace_next`) at `zeta_next`.
    pub main_next: bool,
    /// Whether the AIR opens `preprocessed_next` at `zeta_next`.
    pub pre_next: bool,
    /// Public instance inputs as canonical Goldilocks elements.
    pub public_values: Vec<u64>,
    /// Matrix commitments.
    pub commitments: WireCommitments,
    /// Out-of-domain opened values.
    pub opened_values: WireOpenedValues,
    /// Heavy FRI + Merkle opening proof (`postcard`-encoded `ChipPcsProof`).
    pub opening_proof_bytes: Vec<u8>,
}

impl PcsOpeningObject {
    /// Builds a [`PcsOpeningObject`] from a `ChipProof`, its validated
    /// [`PcsOpeningShape`], canonical `u64` public values, and optional
    /// preprocessed commitment.
    ///
    /// # Errors
    ///
    /// Returns [`ObjectError::Invalid`] if dimensions overflow, any field value
    /// is non-canonical, any commitment has a non-unit cap height, or
    /// serializing the opening proof fails.
    pub fn from_chip_proof(
        proof: &ChipProof,
        shape: PcsOpeningShape,
        public_values: &[u64],
        preprocessed_commit: Option<Hash32>,
    ) -> Result<Self, ObjectError> {
        let degree_bits = u8::try_from(proof.degree_bits).map_err(|_| ObjectError::Invalid)?;
        let air_width = u32::try_from(shape.air_width).map_err(|_| ObjectError::Invalid)?;
        let preprocessed_width =
            u32::try_from(shape.preprocessed_width).map_err(|_| ObjectError::Invalid)?;
        let log_num_quotient_chunks =
            u8::try_from(shape.log_num_quotient_chunks).map_err(|_| ObjectError::Invalid)?;
        if public_values.len() > MAX_PCS_PUBLIC_VALUES
            || public_values.iter().any(|&v| v >= GOLDILOCKS_MODULUS)
        {
            return Err(ObjectError::Invalid);
        }
        let commitments = WireCommitments::from_chip(&proof.commitments)?;
        let opened_values = WireOpenedValues::from_chip(&proof.opened_values);
        let opening_proof_bytes =
            postcard::to_allocvec(&proof.opening_proof).map_err(|_| ObjectError::Invalid)?;
        Ok(Self {
            degree_bits,
            air_width,
            preprocessed_width,
            preprocessed_commit,
            log_num_quotient_chunks,
            main_next: shape.main_next,
            pre_next: shape.pre_next,
            public_values: public_values.to_vec(),
            commitments,
            opened_values,
            opening_proof_bytes,
        })
    }

    /// Builds a [`PcsOpeningObject`] directly from a `BudAir` [`ProofEnvelope`],
    /// program words, and `ExecutionPublicInputs`.
    ///
    /// # Errors
    ///
    /// Returns [`ObjectError::Invalid`] if the envelope proof bytes cannot be
    /// decoded, have trailing bytes, or `BudAir` preprocessed setup fails.
    pub fn from_bud_envelope(
        envelope: &ProofEnvelope,
        program: &[u64],
        expected_inputs: &ExecutionPublicInputs,
    ) -> Result<Self, ObjectError> {
        let (proof, shape, pvs, pre_commit) =
            extract_bud_envelope_pcs(envelope, program, expected_inputs)
                .map_err(|_| ObjectError::Invalid)?;
        Self::from_chip_proof(&proof, shape, &pvs, Some(pre_commit))
    }

    /// Reconstructs the [`PcsOpeningShape`] declared by this object.
    ///
    /// # Errors
    ///
    /// Returns [`ObjectError::Invalid`] if any width fails platform conversion.
    pub fn shape(&self) -> Result<PcsOpeningShape, ObjectError> {
        Ok(PcsOpeningShape {
            air_width: usize::try_from(self.air_width).map_err(|_| ObjectError::Invalid)?,
            preprocessed_width: usize::try_from(self.preprocessed_width)
                .map_err(|_| ObjectError::Invalid)?,
            log_num_quotient_chunks: usize::from(self.log_num_quotient_chunks),
            main_next: self.main_next,
            pre_next: self.pre_next,
            has_aux_trace: self.commitments.aux_trace.is_some(),
        })
    }

    /// Produces the lightweight on-chain [`VerifyStarkTx`] corresponding to
    /// this PCS opening (stripping `opening_proof_bytes`).
    #[must_use]
    pub fn to_verify_stark_tx(&self, air_id: Hash32, air_aux_data: Vec<u8>) -> VerifyStarkTx {
        VerifyStarkTx {
            air_id,
            degree_bits: self.degree_bits,
            public_values: self.public_values.clone(),
            air_aux_data,
            commitments: self.commitments.clone(),
            opened_values: self.opened_values.clone(),
        }
    }

    /// Encodes into the bounded deflate-compressed `BDP5` wire container.
    ///
    /// # Errors
    ///
    /// Returns [`ObjectError::Invalid`] if serialization or compression fails.
    pub fn encode(&self) -> Result<Vec<u8>, ObjectError> {
        let raw = bincode::DefaultOptions::new()
            .with_limit(MAX_DECOMPRESSED_PCS_BYTES as u64)
            .serialize(self)
            .map_err(|_| ObjectError::Invalid)?;
        if raw.len() > MAX_DECOMPRESSED_PCS_BYTES {
            return Err(ObjectError::PayloadTooLarge(raw.len()));
        }
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&raw).map_err(|_| ObjectError::Invalid)?;
        let compressed = encoder.finish().map_err(|_| ObjectError::Invalid)?;
        let mut out = Vec::with_capacity(5 + compressed.len());
        out.extend_from_slice(&PCS_OBJECT_MAGIC);
        out.push(PCS_OBJECT_VERSION);
        out.extend_from_slice(&compressed);
        Ok(out)
    }

    /// Decodes a `BDP5` wire container with hard decompression and bincode
    /// bounds.
    ///
    /// # Errors
    ///
    /// Returns [`ObjectError::Invalid`] on bad magic, bad version, oversized
    /// inflation, trailing bytes, or malformed bincode.
    pub fn decode(bytes: &[u8]) -> Result<Self, ObjectError> {
        let (Some(magic), Some(&version), Some(payload)) =
            (bytes.get(..4), bytes.get(4), bytes.get(5..))
        else {
            return Err(ObjectError::Invalid);
        };
        if magic != PCS_OBJECT_MAGIC || version != PCS_OBJECT_VERSION {
            return Err(ObjectError::Invalid);
        }
        let mut decoder = DeflateDecoder::new(payload);
        let mut raw = Vec::new();
        let limit = (MAX_DECOMPRESSED_PCS_BYTES as u64).saturating_add(1);
        decoder
            .by_ref()
            .take(limit)
            .read_to_end(&mut raw)
            .map_err(|_| ObjectError::Invalid)?;
        if raw.len() > MAX_DECOMPRESSED_PCS_BYTES {
            return Err(ObjectError::Invalid);
        }
        let obj: Self = bincode::DefaultOptions::new()
            .with_limit(MAX_DECOMPRESSED_PCS_BYTES as u64)
            .reject_trailing_bytes()
            .deserialize(&raw)
            .map_err(|_| ObjectError::Invalid)?;
        if usize::from(obj.degree_bits) > MAX_VERIFIER_DEGREE_BITS
            || obj.public_values.len() > MAX_PCS_PUBLIC_VALUES
        {
            return Err(ObjectError::Invalid);
        }
        Ok(obj)
    }
}

/// Computes the canonical 256-bit polynomial-bundle commitment `poly_hash` for
/// `Claim::Poly`.
///
/// Binds every committed polynomial root (`trace`, optional `aux_trace`,
/// `quotient_chunks`, optional `random`, optional `preprocessed_commit`) along
/// with `degree_bits` and the exact [`PcsOpeningShape`] metadata.
#[must_use]
pub fn poly_hash_of(
    degree_bits: u8,
    shape: PcsOpeningShape,
    commitments: &WireCommitments,
    preprocessed_commit: Option<&Hash32>,
) -> Hash32 {
    let mut hasher = Keccak256::new();
    hasher.update(TAG_PCS_POLY);
    hasher.update([degree_bits]);
    hasher.update(
        u32::try_from(shape.air_width)
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    hasher.update(
        u32::try_from(shape.preprocessed_width)
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    hasher.update([u8::try_from(shape.log_num_quotient_chunks).unwrap_or(u8::MAX)]);
    let flags = u8::from(shape.main_next)
        | (u8::from(shape.pre_next) << 1)
        | (u8::from(shape.has_aux_trace) << 2);
    hasher.update([flags]);
    hasher.update(commitments.trace);
    match &commitments.aux_trace {
        Some(c) => {
            hasher.update([1u8]);
            hasher.update(c);
        }
        None => hasher.update([0u8]),
    }
    hasher.update(commitments.quotient_chunks);
    match &commitments.random {
        Some(c) => {
            hasher.update([1u8]);
            hasher.update(c);
        }
        None => hasher.update([0u8]),
    }
    match preprocessed_commit {
        Some(c) => {
            hasher.update([1u8]);
            hasher.update(c);
        }
        None => hasher.update([0u8]),
    }
    hasher.finalize().into()
}

fn update_ext_vec(hasher: &mut Keccak256, vec: &[[u64; 3]]) -> Result<(), ObjectError> {
    let len = u32::try_from(vec.len()).map_err(|_| ObjectError::Invalid)?;
    hasher.update(len.to_be_bytes());
    for limbs in vec {
        if limbs.iter().any(|&v| v >= GOLDILOCKS_MODULUS) {
            return Err(ObjectError::Invalid);
        }
        for &limb in limbs {
            hasher.update(limb.to_le_bytes());
        }
    }
    Ok(())
}

fn update_opt_ext_vec(
    hasher: &mut Keccak256,
    opt: Option<&Vec<[u64; 3]>>,
) -> Result<(), ObjectError> {
    match opt {
        Some(v) => {
            hasher.update([1u8]);
            update_ext_vec(hasher, v)
        }
        None => {
            hasher.update([0u8]);
            Ok(())
        }
    }
}

/// Computes the canonical [`Ext`] evaluation digest (`Claim::Poly.value`) over
/// `poly_hash`, `zeta`, and every opened polynomial value vector.
///
/// Every opened element is length-prefixed and checked for canonical Goldilocks
/// representation so altering any single opened limb changes `value`.
///
/// # Errors
///
/// Returns [`ObjectError::Invalid`] if any limb is non-canonical or a vector
/// length overflows `u32`.
pub fn eval_value_of(
    poly_hash: &Hash32,
    zeta: Ext,
    opened: &WireOpenedValues,
) -> Result<Ext, ObjectError> {
    let mut hasher = Keccak256::new();
    hasher.update(TAG_PCS_EVAL);
    hasher.update(poly_hash);
    for limb in zeta.limbs() {
        hasher.update(limb.to_le_bytes());
    }
    update_ext_vec(&mut hasher, &opened.trace_local)?;
    update_opt_ext_vec(&mut hasher, opened.trace_next.as_ref())?;
    update_opt_ext_vec(&mut hasher, opened.aux_trace_local.as_ref())?;
    update_opt_ext_vec(&mut hasher, opened.aux_trace_next.as_ref())?;
    update_opt_ext_vec(&mut hasher, opened.preprocessed_local.as_ref())?;
    update_opt_ext_vec(&mut hasher, opened.preprocessed_next.as_ref())?;
    let q_len = u32::try_from(opened.quotient_chunks.len()).map_err(|_| ObjectError::Invalid)?;
    hasher.update(q_len.to_be_bytes());
    for chunk in &opened.quotient_chunks {
        update_ext_vec(&mut hasher, chunk)?;
    }
    update_opt_ext_vec(&mut hasher, opened.random.as_ref())?;

    let digest: [u8; 32] = hasher.finalize().into();
    let l0 = u64::from_le_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]) % GOLDILOCKS_MODULUS;
    let l1 = u64::from_le_bytes([
        digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14],
        digest[15],
    ]) % GOLDILOCKS_MODULUS;
    let l2 = u64::from_le_bytes([
        digest[16], digest[17], digest[18], digest[19], digest[20], digest[21], digest[22],
        digest[23],
    ]) % GOLDILOCKS_MODULUS;
    Ext::new([l0, l1, l2]).map_err(|_| ObjectError::Invalid)
}

/// Stage 1 verifier for `ObjectKind::PcsOpening`: validates canonical limbs,
/// runs real FRI + Merkle PCS opening verification via
/// [`verify_chip_pcs_openings_u64`], and derives the canonical `Claim::Poly`.
///
/// # Errors
///
/// Returns [`ObjectError::Invalid`] if any field element is non-canonical, the
/// opening proof cannot be decoded without trailing bytes, or FRI opening
/// verification fails.
pub fn verify_pcs_opening(obj: &PcsOpeningObject) -> Result<Claim, ObjectError> {
    if obj.public_values.len() > MAX_PCS_PUBLIC_VALUES
        || obj.public_values.iter().any(|&v| v >= GOLDILOCKS_MODULUS)
    {
        return Err(ObjectError::Invalid);
    }
    let shape = obj.shape()?;
    let commitments = obj.commitments.to_chip();
    let opened_values = obj.opened_values.to_chip()?;
    let preprocessed_commit = obj.preprocessed_commit.map(chip_commitment_from_bytes);

    let (opening_proof, trailing): (ChipPcsProof, &[u8]) =
        postcard::take_from_bytes(&obj.opening_proof_bytes).map_err(|_| ObjectError::Invalid)?;
    if !trailing.is_empty() {
        return Err(ObjectError::Invalid);
    }

    let zeta_limbs = verify_chip_pcs_openings_u64(
        shape,
        &commitments,
        &opened_values,
        &opening_proof,
        usize::from(obj.degree_bits),
        &obj.public_values,
        preprocessed_commit.as_ref(),
    )
    .map_err(|_| ObjectError::Invalid)?;
    let point = Ext::new(zeta_limbs).map_err(|_| ObjectError::Invalid)?;
    let poly_hash = poly_hash_of(
        obj.degree_bits,
        shape,
        &obj.commitments,
        obj.preprocessed_commit.as_ref(),
    );
    let value = eval_value_of(&poly_hash, point, &obj.opened_values)?;
    Ok(Claim::Poly {
        poly_hash,
        point,
        value,
    })
}
