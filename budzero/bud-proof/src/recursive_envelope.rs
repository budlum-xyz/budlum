//! Versioned recursion-proof envelope for the aggregation fold verifier.
//!
//! R-8 / CEO T-K.1: the version, recursion level, child verifier-key digest,
//! parameter set, domain, program, public input, and statement digest travel
//! with the proof. A verifier checks these fields against context it derives
//! independently; metadata supplied by the proof is never its own authority.

/// The proof-wire version. Bump when the recursive envelope or its statement
/// binding changes; older and future formats are refused.
pub const PROOF_FORMAT_VERSION: u32 = 3;

/// Hard upper bound checked before copying proof bytes out of the wire buffer.
/// WIRING: enforced by recursive envelope proof size admission.
pub const MAX_RECURSIVE_PROOF_BYTES: usize = 10 * 1024 * 1024;
/// Recursion is bounded even before the caller validates a concrete frame.
pub const MAX_RECURSION_LEVEL: u32 = 64;

const MAGIC: [u8; 4] = *b"BRPE";
const HEADER_BYTES: usize = 4 + 4 + 4 + 32 + 4 + 4 + 32 + 32 + 32 + 4 + 4;

/// A recursive proof together with the statement context its verifier must pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursiveProofEnvelope {
    /// Wire protocol version; must equal [`PROOF_FORMAT_VERSION`].
    pub proof_format_version: u32,
    /// Zero for a leaf proof; each recursive parent increases this by one.
    pub recursion_level: u32,
    /// Digest of the verifier key used for the child proof(s); zero only at level 0.
    pub child_verification_key_hash: [u8; 32],
    /// Consensus parameter-set identifier.
    pub parameter_set: u32,
    /// Claim domain to which the proof is bound.
    pub domain: u32,
    /// Allowlisted program whose execution is proved.
    pub program_hash: [u8; 32],
    /// Public input of the proved statement.
    pub public_input: [u8; 32],
    /// Digest of the full statement, including recursion metadata.
    pub statement_digest: [u8; 32],
    /// Number of fold operations committed by the proof.
    pub num_steps: u32,
    /// Serialized proof body.
    pub proof_bytes: Vec<u8>,
}

/// Verifier-owned context; unlike the envelope, it is derived from the
/// expected frame and active consensus parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecursiveProofContext {
    /// Level derived from the frame tree, not copied from the envelope.
    pub recursion_level: u32,
    /// Child verifier-key hash pinned by this verifier.
    pub child_verification_key_hash: [u8; 32],
    /// Active consensus parameter set.
    pub parameter_set: u32,
    /// Expected claim domain.
    pub domain: u32,
    /// Expected allowlisted program.
    pub program_hash: [u8; 32],
    /// Expected public input.
    pub public_input: [u8; 32],
    /// Recomputed statement digest.
    pub statement_digest: [u8; 32],
}

/// A malformed recursive proof envelope or mismatch against pinned verifier context.
#[derive(Debug, Clone, PartialEq, Eq)]
/// WIRING: returned by recursive envelope open/seal boundaries.
pub enum EnvelopeError {
    /// The wire version is not the one supported by this verifier.
    UnsupportedVersion(u32),
    /// The claimed level exceeds the protocol bound.
    InvalidRecursionLevel(u32),
    /// A leaf proof carried a child key when no child exists.
    UnexpectedChildVerificationKey,
    /// A recursive proof omitted its required child verifier-key digest.
    MissingChildVerificationKey,
    /// The proof body is empty.
    EmptyProof,
    /// The proof body exceeds the allocation bound.
    ProofTooLarge(usize),
    /// No fold operations were committed.
    InvalidStepCount,
    /// The envelope ended before all fixed or variable-width fields.
    Truncated,
    /// Bytes remain after the declared envelope body.
    TrailingBytes,
    /// The fixed magic prefix is not recognized.
    BadMagic,
    /// The claimed recursion level differs from the verifier-derived level.
    RecursionLevelMismatch { expected: u32, actual: u32 },
    /// The child verifier-key hash differs from the pinned key.
    ChildVerificationKeyMismatch,
    /// The parameter set differs from the active consensus parameter set.
    ParameterSetMismatch { expected: u32, actual: u32 },
    /// The claim domain differs from the expected domain.
    DomainMismatch { expected: u32, actual: u32 },
    /// The program hash is not the expected allowlisted program.
    ProgramHashMismatch,
    /// The public input differs from the expected statement.
    PublicInputMismatch,
    /// The full statement digest differs from the verifier-derived digest.
    StatementDigestMismatch,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported recursive proof version {version}")
            }
            Self::InvalidRecursionLevel(level) => {
                write!(f, "recursion level {level} is out of bounds")
            }
            Self::UnexpectedChildVerificationKey => {
                write!(f, "a leaf proof must not name a child verification key")
            }
            Self::MissingChildVerificationKey => {
                write!(f, "a recursive proof must name its child verification key")
            }
            Self::EmptyProof => write!(f, "recursive proof body is empty"),
            Self::ProofTooLarge(size) => {
                write!(f, "recursive proof body of {size} bytes exceeds the cap")
            }
            Self::InvalidStepCount => write!(f, "recursive proof has no fold steps"),
            Self::Truncated => write!(f, "recursive proof envelope is truncated"),
            Self::TrailingBytes => write!(f, "bytes follow the recursive proof envelope"),
            Self::BadMagic => write!(f, "recursive proof envelope magic is invalid"),
            Self::RecursionLevelMismatch { expected, actual } => write!(
                f,
                "recursion level {actual} does not match expected {expected}"
            ),
            Self::ChildVerificationKeyMismatch => {
                write!(f, "child verification-key digest does not match")
            }
            Self::ParameterSetMismatch { expected, actual } => write!(
                f,
                "parameter set {actual} does not match expected {expected}"
            ),
            Self::DomainMismatch { expected, actual } => {
                write!(f, "domain {actual} does not match expected {expected}")
            }
            Self::ProgramHashMismatch => {
                write!(f, "program hash does not match the expected program")
            }
            Self::PublicInputMismatch => {
                write!(f, "public input does not match the expected statement")
            }
            Self::StatementDigestMismatch => {
                write!(f, "statement digest does not match the expected statement")
            }
        }
    }
}

impl std::error::Error for EnvelopeError {}

impl RecursiveProofEnvelope {
    /// Validate the bounded wire shape and supported version.
    pub fn validate_shape(&self) -> Result<(), EnvelopeError> {
        if self.proof_format_version != PROOF_FORMAT_VERSION {
            return Err(EnvelopeError::UnsupportedVersion(self.proof_format_version));
        }
        if self.recursion_level > MAX_RECURSION_LEVEL {
            return Err(EnvelopeError::InvalidRecursionLevel(self.recursion_level));
        }
        match (
            self.recursion_level,
            self.child_verification_key_hash == [0; 32],
        ) {
            (0, false) => return Err(EnvelopeError::UnexpectedChildVerificationKey),
            (1.., true) => return Err(EnvelopeError::MissingChildVerificationKey),
            _ => {}
        }
        if self.proof_bytes.is_empty() {
            return Err(EnvelopeError::EmptyProof);
        }
        if self.proof_bytes.len() > MAX_RECURSIVE_PROOF_BYTES {
            return Err(EnvelopeError::ProofTooLarge(self.proof_bytes.len()));
        }
        if self.num_steps == 0 {
            return Err(EnvelopeError::InvalidStepCount);
        }
        Ok(())
    }

    /// Encode the envelope canonically in big-endian fixed-width metadata.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        self.validate_shape()?;
        let proof_len = u32::try_from(self.proof_bytes.len())
            .map_err(|_| EnvelopeError::ProofTooLarge(self.proof_bytes.len()))?;
        let mut out = Vec::with_capacity(HEADER_BYTES.saturating_add(self.proof_bytes.len()));
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&self.proof_format_version.to_be_bytes());
        out.extend_from_slice(&self.recursion_level.to_be_bytes());
        out.extend_from_slice(&self.child_verification_key_hash);
        out.extend_from_slice(&self.parameter_set.to_be_bytes());
        out.extend_from_slice(&self.domain.to_be_bytes());
        out.extend_from_slice(&self.program_hash);
        out.extend_from_slice(&self.public_input);
        out.extend_from_slice(&self.statement_digest);
        out.extend_from_slice(&self.num_steps.to_be_bytes());
        out.extend_from_slice(&proof_len.to_be_bytes());
        out.extend_from_slice(&self.proof_bytes);
        Ok(out)
    }

    /// Decode one complete envelope; reject truncation, trailing bytes and
    /// oversize payloads before copying the proof body.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() < HEADER_BYTES {
            return Err(EnvelopeError::Truncated);
        }
        if bytes.len() > HEADER_BYTES.saturating_add(MAX_RECURSIVE_PROOF_BYTES) {
            return Err(EnvelopeError::ProofTooLarge(
                bytes.len().saturating_sub(HEADER_BYTES),
            ));
        }
        let mut rest = bytes;
        if take::<4>(&mut rest)? != MAGIC {
            return Err(EnvelopeError::BadMagic);
        }
        let proof_format_version = u32::from_be_bytes(take::<4>(&mut rest)?);
        let recursion_level = u32::from_be_bytes(take::<4>(&mut rest)?);
        let child_verification_key_hash = take::<32>(&mut rest)?;
        let parameter_set = u32::from_be_bytes(take::<4>(&mut rest)?);
        let domain = u32::from_be_bytes(take::<4>(&mut rest)?);
        let program_hash = take::<32>(&mut rest)?;
        let public_input = take::<32>(&mut rest)?;
        let statement_digest = take::<32>(&mut rest)?;
        let num_steps = u32::from_be_bytes(take::<4>(&mut rest)?);
        let proof_len =
            usize::try_from(u32::from_be_bytes(take::<4>(&mut rest)?)).unwrap_or(usize::MAX);
        if proof_len > MAX_RECURSIVE_PROOF_BYTES {
            return Err(EnvelopeError::ProofTooLarge(proof_len));
        }
        if rest.len() < proof_len {
            return Err(EnvelopeError::Truncated);
        }
        if rest.len() > proof_len {
            return Err(EnvelopeError::TrailingBytes);
        }
        let envelope = Self {
            proof_format_version,
            recursion_level,
            child_verification_key_hash,
            parameter_set,
            domain,
            program_hash,
            public_input,
            statement_digest,
            num_steps,
            proof_bytes: rest.to_vec(),
        };
        envelope.validate_shape()?;
        Ok(envelope)
    }

    /// Compare every consensus-critical field to independently derived context.
    pub fn validate_for(&self, expected: &RecursiveProofContext) -> Result<(), EnvelopeError> {
        self.validate_shape()?;
        if self.recursion_level != expected.recursion_level {
            return Err(EnvelopeError::RecursionLevelMismatch {
                expected: expected.recursion_level,
                actual: self.recursion_level,
            });
        }
        if self.child_verification_key_hash != expected.child_verification_key_hash {
            return Err(EnvelopeError::ChildVerificationKeyMismatch);
        }
        if self.parameter_set != expected.parameter_set {
            return Err(EnvelopeError::ParameterSetMismatch {
                expected: expected.parameter_set,
                actual: self.parameter_set,
            });
        }
        if self.domain != expected.domain {
            return Err(EnvelopeError::DomainMismatch {
                expected: expected.domain,
                actual: self.domain,
            });
        }
        if self.program_hash != expected.program_hash {
            return Err(EnvelopeError::ProgramHashMismatch);
        }
        if self.public_input != expected.public_input {
            return Err(EnvelopeError::PublicInputMismatch);
        }
        if self.statement_digest != expected.statement_digest {
            return Err(EnvelopeError::StatementDigestMismatch);
        }
        Ok(())
    }
}

fn take<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], EnvelopeError> {
    let (head, tail) = input.split_at_checked(N).ok_or(EnvelopeError::Truncated)?;
    let out = <[u8; N]>::try_from(head).map_err(|_| EnvelopeError::Truncated)?;
    *input = tail;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (RecursiveProofEnvelope, RecursiveProofContext) {
        let context = RecursiveProofContext {
            recursion_level: 1,
            child_verification_key_hash: [0xA5; 32],
            parameter_set: 7,
            domain: 42,
            program_hash: [0x11; 32],
            public_input: [0x22; 32],
            statement_digest: [0x33; 32],
        };
        let envelope = RecursiveProofEnvelope {
            proof_format_version: PROOF_FORMAT_VERSION,
            recursion_level: context.recursion_level,
            child_verification_key_hash: context.child_verification_key_hash,
            parameter_set: context.parameter_set,
            domain: context.domain,
            program_hash: context.program_hash,
            public_input: context.public_input,
            statement_digest: context.statement_digest,
            num_steps: 3,
            proof_bytes: vec![0x5A; 17],
        };
        (envelope, context)
    }

    #[test]
    fn recursive_envelope_roundtrips_all_statement_context() {
        let (envelope, expected) = sample();
        let bytes = envelope.to_bytes().expect("encode");
        let decoded = RecursiveProofEnvelope::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, envelope);
        decoded.validate_for(&expected).expect("context matches");
    }

    #[test]
    fn level_one_proof_cannot_be_presented_as_level_zero() {
        let (envelope, mut expected) = sample();
        expected.recursion_level = 0;
        assert_eq!(
            envelope.validate_for(&expected),
            Err(EnvelopeError::RecursionLevelMismatch {
                expected: 0,
                actual: 1,
            })
        );
    }

    #[test]
    fn proof_under_another_child_verification_key_is_rejected() {
        let (envelope, mut expected) = sample();
        expected.child_verification_key_hash = [0xA6; 32];
        assert_eq!(
            envelope.validate_for(&expected),
            Err(EnvelopeError::ChildVerificationKeyMismatch)
        );
    }

    #[test]
    fn version_domain_parameter_and_statement_mismatches_are_fail_closed() {
        let (mut envelope, expected) = sample();
        envelope.proof_format_version = PROOF_FORMAT_VERSION - 1;
        assert_eq!(
            envelope.validate_for(&expected),
            Err(EnvelopeError::UnsupportedVersion(PROOF_FORMAT_VERSION - 1))
        );

        let (envelope, mut expected) = sample();
        expected.parameter_set += 1;
        assert!(matches!(
            envelope.validate_for(&expected),
            Err(EnvelopeError::ParameterSetMismatch { .. })
        ));
        expected.parameter_set -= 1;
        expected.domain += 1;
        assert!(matches!(
            envelope.validate_for(&expected),
            Err(EnvelopeError::DomainMismatch { .. })
        ));
        expected.domain -= 1;
        expected.statement_digest[0] ^= 1;
        assert_eq!(
            envelope.validate_for(&expected),
            Err(EnvelopeError::StatementDigestMismatch)
        );
    }

    #[test]
    fn decoder_rejects_truncated_and_trailing_bytes() {
        let (envelope, _) = sample();
        let mut bytes = envelope.to_bytes().expect("encode");
        bytes.pop();
        assert_eq!(
            RecursiveProofEnvelope::from_bytes(&bytes),
            Err(EnvelopeError::Truncated)
        );

        let mut bytes = envelope.to_bytes().expect("encode");
        bytes.push(0);
        assert_eq!(
            RecursiveProofEnvelope::from_bytes(&bytes),
            Err(EnvelopeError::TrailingBytes)
        );
    }

    #[test]
    fn wire_version_and_magic_are_fail_closed() {
        let (envelope, _) = sample();
        let mut bytes = envelope.to_bytes().expect("encode");
        bytes[4..8].copy_from_slice(&(PROOF_FORMAT_VERSION - 1).to_be_bytes());
        assert_eq!(
            RecursiveProofEnvelope::from_bytes(&bytes),
            Err(EnvelopeError::UnsupportedVersion(PROOF_FORMAT_VERSION - 1))
        );

        let mut bytes = envelope.to_bytes().expect("encode");
        bytes[0] ^= 1;
        assert_eq!(
            RecursiveProofEnvelope::from_bytes(&bytes),
            Err(EnvelopeError::BadMagic)
        );
    }

    #[test]
    fn verifier_context_checks_program_and_public_input_too() {
        let (envelope, mut expected) = sample();
        expected.program_hash[0] ^= 1;
        assert_eq!(
            envelope.validate_for(&expected),
            Err(EnvelopeError::ProgramHashMismatch)
        );
        expected.program_hash[0] ^= 1;
        expected.public_input[0] ^= 1;
        assert_eq!(
            envelope.validate_for(&expected),
            Err(EnvelopeError::PublicInputMismatch)
        );
    }

    #[test]
    fn shape_rejects_invalid_depth_missing_key_empty_body_and_zero_steps() {
        let (mut envelope, _) = sample();
        envelope.recursion_level = MAX_RECURSION_LEVEL + 1;
        assert_eq!(
            envelope.validate_shape(),
            Err(EnvelopeError::InvalidRecursionLevel(
                MAX_RECURSION_LEVEL + 1
            ))
        );

        let (mut envelope, _) = sample();
        envelope.child_verification_key_hash = [0; 32];
        assert_eq!(
            envelope.validate_shape(),
            Err(EnvelopeError::MissingChildVerificationKey)
        );

        let (mut envelope, _) = sample();
        envelope.recursion_level = 0;
        assert_eq!(
            envelope.validate_shape(),
            Err(EnvelopeError::UnexpectedChildVerificationKey)
        );

        let (mut envelope, _) = sample();
        envelope.proof_bytes.clear();
        assert_eq!(envelope.validate_shape(), Err(EnvelopeError::EmptyProof));

        let (mut envelope, _) = sample();
        envelope.num_steps = 0;
        assert_eq!(
            envelope.validate_shape(),
            Err(EnvelopeError::InvalidStepCount)
        );
    }

    #[test]
    fn parser_checks_declared_payload_cap_before_copying_proof_bytes() {
        let (envelope, _) = sample();
        let mut bytes = envelope.to_bytes().expect("encode");
        let len_at = HEADER_BYTES - 4;
        let over_limit = u32::try_from(MAX_RECURSIVE_PROOF_BYTES + 1).expect("fits u32");
        bytes[len_at..HEADER_BYTES].copy_from_slice(&over_limit.to_be_bytes());
        bytes.truncate(HEADER_BYTES);
        assert_eq!(
            RecursiveProofEnvelope::from_bytes(&bytes),
            Err(EnvelopeError::ProofTooLarge(MAX_RECURSIVE_PROOF_BYTES + 1))
        );
    }
}
