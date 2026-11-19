//! Zero-residual `Bat3` reconstruction: a bounded, integer-only synthesis
//! engine that re-expands a compressed blueprint back to its canonical bytes
//! and verifies the result against a declared commitment.
//!
//! WIRING: reached through `crate::bat3` (re-exported in `src/bat3/mod.rs`)
//! and called by `crate::explorer_evidence` to re-verify reconstructed state.

use crate::core::hash::hash_fields_bytes;
use serde::{Deserialize, Serialize};

/// Maximum number of reconstruction steps in one blueprint.
///
/// WIRING: enforced in [`Bat3Blueprint::from_steps`].
pub const MAX_BAT3_BLUEPRINT_STEPS: usize = 4096;

/// Maximum reconstructed output, capped at 1 MiB so a malicious blueprint
/// cannot force an unbounded allocation.
///
/// WIRING: enforced in [`Bat3Blueprint::from_steps`] and
/// [`reconstruct_and_verify`].
pub const MAX_BAT3_RECONSTRUCT_BYTES: usize = 1024 * 1024;

/// Why a `Bat3` reconstruction was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum Bat3ReconstructError {
    /// The blueprint carried too many steps.
    #[error("Bat3 blueprint carries too many steps")]
    TooManySteps,
    /// The blueprint's declared length exceeded the output ceiling.
    #[error("Bat3 blueprint output {declared} exceeds ceiling {ceiling}")]
    OutputExceedsCeiling { declared: u64, ceiling: usize },
    /// The reconstructed bytes did not match the declared commitment.
    #[error("Bat3 reconstruction commitment mismatch")]
    CommitmentMismatch,
}

/// One reconstruction primitive in a [`Bat3Blueprint`].
///
/// WIRING: assembled by producers and consumed by [`reconstruct_and_verify`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReconstructStep {
    /// Emit a literal byte segment verbatim.
    LiteralSegment(Vec<u8>),
    /// Repeat a pattern `repeat_count` times.
    RepeatPattern { pattern: Vec<u8>, repeat_count: u64 },
    /// Copy `length` bytes from `back_offset` bytes earlier in the output.
    BackReference { back_offset: u64, length: u64 },
    /// Generate a byte run from a seeded affine recurrence, masked per byte.
    AffineByteRun {
        seed: u8,
        stride: u8,
        mask_byte: u8,
        length: u64,
    },
}

/// A bounded `Bat3` reconstruction blueprint.
///
/// WIRING: constructed by producers and verified by [`reconstruct_and_verify`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bat3Blueprint {
    steps: Vec<ReconstructStep>,
    declared_len: u64,
    expected_commitment: [u8; 32],
}

impl Bat3Blueprint {
    /// Builds a blueprint from steps, validating the step count and the
    /// declared length ceiling before accepting it.
    ///
    /// # Errors
    ///
    /// Returns [`Bat3ReconstructError::TooManySteps`] or
    /// [`Bat3ReconstructError::OutputExceedsCeiling`].
    pub fn from_steps(steps: Vec<ReconstructStep>) -> Result<Self, Bat3ReconstructError> {
        if steps.len() > MAX_BAT3_BLUEPRINT_STEPS {
            return Err(Bat3ReconstructError::TooManySteps);
        }
        let declared_len = Self::declared_len(&steps);
        if declared_len > MAX_BAT3_RECONSTRUCT_BYTES as u64 {
            return Err(Bat3ReconstructError::OutputExceedsCeiling {
                declared: declared_len,
                ceiling: MAX_BAT3_RECONSTRUCT_BYTES,
            });
        }
        let expected_commitment = compute_reconstruct_commitment(&steps);
        Ok(Self {
            steps,
            declared_len,
            expected_commitment,
        })
    }

    /// The declared reconstructed length, in bytes.
    #[must_use]
    pub const fn output_len(&self) -> u64 {
        self.declared_len
    }

    /// The commitment the reconstructed bytes must match.
    #[must_use]
    pub const fn expected_commitment(&self) -> &[u8; 32] {
        &self.expected_commitment
    }

    /// The steps of this blueprint.
    #[must_use]
    pub fn steps(&self) -> &[ReconstructStep] {
        &self.steps
    }

    /// Computes the total declared output length without materializing it.
    ///
    /// WIRING: used by [`Self::from_steps`] for the ceiling check.
    fn declared_len(steps: &[ReconstructStep]) -> u64 {
        let mut total: u64 = 0;
        for step in steps {
            match step {
                ReconstructStep::LiteralSegment(bytes) => {
                    total = total.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
                }
                ReconstructStep::RepeatPattern {
                    pattern,
                    repeat_count,
                } => {
                    let per = u64::try_from(pattern.len()).unwrap_or(u64::MAX);
                    total = total.saturating_add(per.saturating_mul(*repeat_count));
                }
                ReconstructStep::BackReference { length, .. } => {
                    total = total.saturating_add(*length);
                }
                ReconstructStep::AffineByteRun { length, .. } => {
                    total = total.saturating_add(*length);
                }
            }
            if total > MAX_BAT3_RECONSTRUCT_BYTES as u64 {
                return u64::MAX;
            }
        }
        total
    }
}

/// Computes the domain-separated commitment over a step list.
///
/// WIRING: computed once at blueprint construction and re-derived on
/// verification, so a tampered step list is caught before any output is
/// allocated.
#[must_use]
pub fn compute_reconstruct_commitment(steps: &[ReconstructStep]) -> [u8; 32] {
    let mut acc: [u8; 32] = hash_fields_bytes(&[b"BDLM_BAT3_RECONSTRUCT_V1", &[]]);
    for step in steps {
        match step {
            ReconstructStep::LiteralSegment(bytes) => {
                acc = hash_fields_bytes(&[b"BDLM_BAT3_RECONSTRUCT_V1", &acc, &[0x01u8], bytes]);
            }
            ReconstructStep::RepeatPattern {
                pattern,
                repeat_count,
            } => {
                let rep_le = repeat_count.to_le_bytes();
                acc = hash_fields_bytes(&[
                    b"BDLM_BAT3_RECONSTRUCT_V1",
                    &acc,
                    &[0x02u8],
                    pattern,
                    &rep_le,
                ]);
            }
            ReconstructStep::BackReference {
                back_offset,
                length,
            } => {
                let off_le = back_offset.to_le_bytes();
                let len_le = length.to_le_bytes();
                acc = hash_fields_bytes(&[
                    b"BDLM_BAT3_RECONSTRUCT_V1",
                    &acc,
                    &[0x03u8],
                    &off_le,
                    &len_le,
                ]);
            }
            ReconstructStep::AffineByteRun {
                seed,
                stride,
                mask_byte,
                length,
            } => {
                let len_le = length.to_le_bytes();
                acc = hash_fields_bytes(&[
                    b"BDLM_BAT3_RECONSTRUCT_V1",
                    &acc,
                    &[0x04u8],
                    &[*seed, *stride, *mask_byte],
                    &len_le,
                ]);
            }
        }
    }
    acc
}

/// Re-expands a blueprint to its canonical bytes and verifies the commitment.
///
/// # Errors
///
/// Returns [`Bat3ReconstructError::OutputExceedsCeiling`] if the actual
/// output exceeds the ceiling, or [`Bat3ReconstructError::CommitmentMismatch`]
/// if the reconstructed bytes do not match the declared commitment.
pub fn reconstruct_and_verify(blueprint: &Bat3Blueprint) -> Result<Vec<u8>, Bat3ReconstructError> {
    let mut out: Vec<u8> = Vec::with_capacity(
        usize::try_from(blueprint.declared_len).unwrap_or(MAX_BAT3_RECONSTRUCT_BYTES),
    );
    for step in &blueprint.steps {
        match step {
            ReconstructStep::LiteralSegment(bytes) => {
                if out.len().saturating_add(bytes.len()) > MAX_BAT3_RECONSTRUCT_BYTES {
                    return Err(Bat3ReconstructError::OutputExceedsCeiling {
                        declared: blueprint.declared_len,
                        ceiling: MAX_BAT3_RECONSTRUCT_BYTES,
                    });
                }
                out.extend_from_slice(bytes);
            }
            ReconstructStep::RepeatPattern {
                pattern,
                repeat_count,
            } => {
                let total = u64::try_from(pattern.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(*repeat_count);
                if out
                    .len()
                    .saturating_add(usize::try_from(total).unwrap_or(MAX_BAT3_RECONSTRUCT_BYTES))
                    > MAX_BAT3_RECONSTRUCT_BYTES
                {
                    return Err(Bat3ReconstructError::OutputExceedsCeiling {
                        declared: blueprint.declared_len,
                        ceiling: MAX_BAT3_RECONSTRUCT_BYTES,
                    });
                }
                for _ in 0..*repeat_count {
                    out.extend_from_slice(pattern);
                }
            }
            ReconstructStep::BackReference {
                back_offset,
                length,
            } => {
                let start = out.len().checked_sub(*back_offset as usize);
                let Some(start) = start else {
                    return Err(Bat3ReconstructError::CommitmentMismatch);
                };
                let end = start
                    .checked_add(*length as usize)
                    .ok_or(Bat3ReconstructError::CommitmentMismatch)?;
                let Some(copied) = out.get(start..end).map(<[u8]>::to_vec) else {
                    return Err(Bat3ReconstructError::CommitmentMismatch);
                };
                out.extend_from_slice(&copied);
            }
            ReconstructStep::AffineByteRun {
                seed,
                stride,
                mask_byte,
                length,
            } => {
                if out.len().saturating_add(*length as usize) > MAX_BAT3_RECONSTRUCT_BYTES {
                    return Err(Bat3ReconstructError::OutputExceedsCeiling {
                        declared: blueprint.declared_len,
                        ceiling: MAX_BAT3_RECONSTRUCT_BYTES,
                    });
                }
                let mut state = u32::from(*seed);
                let stride_u = u32::from(*stride);
                for _ in 0..*length {
                    let b =
                        ((state.wrapping_mul(0x9E3779B1) ^ stride_u) ^ u32::from(*mask_byte)) as u8;
                    out.push(b);
                    state = state.wrapping_add(stride_u);
                }
            }
        }
    }
    if out.len() != usize::try_from(blueprint.declared_len).unwrap_or(MAX_BAT3_RECONSTRUCT_BYTES) {
        return Err(Bat3ReconstructError::CommitmentMismatch);
    }
    let out_hash = hash_fields_bytes(&[out.as_slice()]);
    let commitment = hash_fields_bytes(&[
        b"BDLM_BAT3_RECONSTRUCT_V1",
        &out_hash,
        &blueprint.declared_len.to_le_bytes(),
    ]);
    if commitment != blueprint.expected_commitment {
        return Err(Bat3ReconstructError::CommitmentMismatch);
    }
    Ok(out)
}
