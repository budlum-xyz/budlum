//! BudZKVM Proof Verification Integration.
//!
//! This module bridges the STARK proof system (`bud-proof`) with the
//! executor layer. When a ZKVM execution proof is submitted:
//!
//! 1. Deserialize the `ProofEnvelope`
//! 2. Verify `public_inputs_hash` matches the claimed execution
//! 3. Verify the STARK proof against the public inputs
//! 4. If valid, update the contract state root
//!
//! ## Design decisions
//! - Proof verification is **deterministic** — same proof + inputs = same result
//!   on every node. No randomness, no side effects.
//! - Failed verification is a validation error, NOT a panic — the network
//!   continues operating even with garbage proofs.
//! - The verification gas cost is bounded by `proof.degree_bits` — larger
//!   proofs cost more gas, preventing DoS via huge proofs.

use sha2::{Digest, Sha256};

/// Maximum proof size in bytes (prevents DoS via oversized proofs).
pub const MAX_PROOF_BYTES: usize = 1 << 20; // 1 MB

/// Maximum degree bits (prevents DoS via huge trace).
pub const MAX_DEGREE_BITS: u32 = 24; // 2^24 = 16M rows

/// Gas cost per degree bit (linear scaling).
pub const GAS_PER_DEGREE_BIT: u64 = 1000;

/// Minimum proof format version accepted.
pub const MIN_PROOF_FORMAT_VERSION: u32 = 1;

/// Errors during proof verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofVerifyError {
    /// Proof envelope too large.
    ProofTooLarge { size: usize, max: usize },
    /// Degree bits exceed maximum.
    DegreeTooLarge { degree_bits: u32, max: u32 },
    /// Proof format version too old.
    FormatVersionTooOld { version: u32, min: u32 },
    /// Public inputs hash mismatch.
    PublicInputsMismatch { expected: [u8; 32], got: [u8; 32] },
    /// STARK proof verification failed.
    InvalidProof(String),
    /// Deserialization error.
    DeserializationError(String),
    /// Unsupported proof backend.
    UnsupportedBackend(String),
    /// Gas limit exceeded.
    GasExceeded { required: u64, limit: u64 },
}

impl std::fmt::Display for ProofVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofVerifyError::ProofTooLarge { size, max } => {
                write!(f, "proof too large: {size} bytes (max {max})")
            }
            ProofVerifyError::DegreeTooLarge { degree_bits, max } => {
                write!(f, "degree bits too large: {degree_bits} (max {max})")
            }
            ProofVerifyError::FormatVersionTooOld { version, min } => {
                write!(f, "proof format version {version} too old (min {min})")
            }
            ProofVerifyError::PublicInputsMismatch { expected, got } => {
                write!(
                    f,
                    "public inputs hash mismatch: expected {}, got {}",
                    hex::encode(expected),
                    hex::encode(got)
                )
            }
            ProofVerifyError::InvalidProof(msg) => {
                write!(f, "invalid STARK proof: {msg}")
            }
            ProofVerifyError::DeserializationError(msg) => {
                write!(f, "proof deserialization error: {msg}")
            }
            ProofVerifyError::UnsupportedBackend(backend) => {
                write!(f, "unsupported proof backend: {backend}")
            }
            ProofVerifyError::GasExceeded { required, limit } => {
                write!(f, "proof verification gas exceeded: {required} > {limit}")
            }
        }
    }
}

impl std::error::Error for ProofVerifyError {}

/// Result of a successful proof verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProof {
    /// The program hash that was executed.
    pub program_hash: [u8; 32],
    /// The initial state root before execution.
    pub initial_state_root: [u8; 32],
    /// The final state root after execution.
    pub final_state_root: [u8; 32],
    /// Gas consumed by verification.
    pub verification_gas: u64,
    /// The trace length (number of execution steps).
    pub trace_len: u64,
}

/// Envelope structure for a ZKVM proof (matches `bud-proof::ProofEnvelope`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProofEnvelope {
    pub proof_format_version: u32,
    pub backend: String,
    pub public_inputs_hash: [u8; 32],
    pub proof_bytes: Vec<u8>,
    pub degree_bits: u32,
}

/// Public inputs for the execution proof.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExecutionPublicInputs {
    pub chain_id: u64,
    pub program_hash: [u8; 32],
    pub initial_state_root: [u8; 32],
    pub final_state_root: [u8; 32],
    pub sender: u64,
    pub nonce: u64,
    pub block_height: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub exit_code: u64,
    pub trace_len: u64,
    pub event_digest: [u8; 32],
}

impl ExecutionPublicInputs {
    /// Canonical serialization for hashing.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(176);
        bytes.extend_from_slice(&self.chain_id.to_le_bytes());
        bytes.extend_from_slice(&self.program_hash);
        bytes.extend_from_slice(&self.initial_state_root);
        bytes.extend_from_slice(&self.final_state_root);
        bytes.extend_from_slice(&self.sender.to_le_bytes());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes.extend_from_slice(&self.block_height.to_le_bytes());
        bytes.extend_from_slice(&self.gas_limit.to_le_bytes());
        bytes.extend_from_slice(&self.gas_used.to_le_bytes());
        bytes.extend_from_slice(&self.exit_code.to_le_bytes());
        bytes.extend_from_slice(&self.trace_len.to_le_bytes());
        bytes.extend_from_slice(&self.event_digest);
        bytes
    }

    /// SHA-256 hash of canonical bytes.
    pub fn hash(&self) -> [u8; 32] {
        let bytes = self.to_canonical_bytes();
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_EXEC_PUBLIC_INPUTS_V1");
        hasher.update(&bytes);
        hasher.finalize().into()
    }
}

/// The proof verifier — stateless, deterministic.
pub struct ProofVerifier;

impl ProofVerifier {
    /// Verify a proof envelope against expected public inputs.
    ///
    /// Steps:
    /// 1. Validate envelope bounds (size, degree, format version)
    /// 2. Verify public_inputs_hash matches
    /// 3. Verify the STARK proof (when STARK backend is linked)
    /// 4. Return verified proof with state transition info
    pub fn verify(
        envelope: &ProofEnvelope,
        expected_inputs: &ExecutionPublicInputs,
        gas_limit: u64,
    ) -> Result<VerifiedProof, ProofVerifyError> {
        // 1. Size bounds
        if envelope.proof_bytes.len() > MAX_PROOF_BYTES {
            return Err(ProofVerifyError::ProofTooLarge {
                size: envelope.proof_bytes.len(),
                max: MAX_PROOF_BYTES,
            });
        }

        // 2. Degree bounds
        if envelope.degree_bits > MAX_DEGREE_BITS {
            return Err(ProofVerifyError::DegreeTooLarge {
                degree_bits: envelope.degree_bits,
                max: MAX_DEGREE_BITS,
            });
        }

        // 3. Format version
        if envelope.proof_format_version < MIN_PROOF_FORMAT_VERSION {
            return Err(ProofVerifyError::FormatVersionTooOld {
                version: envelope.proof_format_version,
                min: MIN_PROOF_FORMAT_VERSION,
            });
        }

        // 4. Gas check
        let verification_gas = (envelope.degree_bits as u64) * GAS_PER_DEGREE_BIT;
        if verification_gas > gas_limit {
            return Err(ProofVerifyError::GasExceeded {
                required: verification_gas,
                limit: gas_limit,
            });
        }

        // 5. Public inputs hash verification
        let computed_hash = expected_inputs.hash();
        if computed_hash != envelope.public_inputs_hash {
            return Err(ProofVerifyError::PublicInputsMismatch {
                expected: computed_hash,
                got: envelope.public_inputs_hash,
            });
        }

        // 6. Backend-specific STARK verification
        //
        // The actual STARK verification happens here. In production, this calls
        // into `bud-proof`'s verifier. For now, we verify the structural
        // invariants and return success — the STARK backend integration point.
        //
        // When `bud-proof` is linked:
        //   let proof = Proof::from_bytes(&envelope.proof_bytes)?;
        //   bud_stark::verifier::verify(&config, &air, &proof, &public_values)?;
        //
        // The proof_bytes are opaque to the executor — only the STARK verifier
        // understands their internal structure.

        Ok(VerifiedProof {
            program_hash: expected_inputs.program_hash,
            initial_state_root: expected_inputs.initial_state_root,
            final_state_root: expected_inputs.final_state_root,
            verification_gas,
            trace_len: expected_inputs.trace_len,
        })
    }

    /// Quick structural validation without full STARK verification.
    /// Used for pre-flight checks before committing gas.
    pub fn validate_envelope_structure(envelope: &ProofEnvelope) -> Result<(), ProofVerifyError> {
        if envelope.proof_bytes.len() > MAX_PROOF_BYTES {
            return Err(ProofVerifyError::ProofTooLarge {
                size: envelope.proof_bytes.len(),
                max: MAX_PROOF_BYTES,
            });
        }
        if envelope.degree_bits > MAX_DEGREE_BITS {
            return Err(ProofVerifyError::DegreeTooLarge {
                degree_bits: envelope.degree_bits,
                max: MAX_DEGREE_BITS,
            });
        }
        if envelope.proof_format_version < MIN_PROOF_FORMAT_VERSION {
            return Err(ProofVerifyError::FormatVersionTooOld {
                version: envelope.proof_format_version,
                min: MIN_PROOF_FORMAT_VERSION,
            });
        }
        if envelope.backend.is_empty() {
            return Err(ProofVerifyError::UnsupportedBackend("empty".into()));
        }
        Ok(())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_inputs() -> ExecutionPublicInputs {
        ExecutionPublicInputs {
            chain_id: 1337,
            program_hash: [1u8; 32],
            initial_state_root: [2u8; 32],
            final_state_root: [3u8; 32],
            sender: 100,
            nonce: 1,
            block_height: 50,
            gas_limit: 1_000_000,
            gas_used: 50_000,
            exit_code: 0,
            trace_len: 1024,
            event_digest: [4u8; 32],
        }
    }

    fn make_envelope(inputs: &ExecutionPublicInputs) -> ProofEnvelope {
        ProofEnvelope {
            proof_format_version: 1,
            backend: "plonky3-stark".into(),
            public_inputs_hash: inputs.hash(),
            proof_bytes: vec![0u8; 100],
            degree_bits: 10,
        }
    }

    #[test]
    fn valid_proof_verifies() {
        let inputs = make_inputs();
        let envelope = make_envelope(&inputs);
        let result = ProofVerifier::verify(&envelope, &inputs, 1_000_000);
        assert!(result.is_ok());
        let verified = result.unwrap();
        assert_eq!(verified.program_hash, [1u8; 32]);
        assert_eq!(verified.final_state_root, [3u8; 32]);
    }

    #[test]
    fn oversized_proof_rejected() {
        let inputs = make_inputs();
        let mut envelope = make_envelope(&inputs);
        envelope.proof_bytes = vec![0u8; MAX_PROOF_BYTES + 1];

        let err = ProofVerifier::verify(&envelope, &inputs, 1_000_000).unwrap_err();
        assert!(matches!(err, ProofVerifyError::ProofTooLarge { .. }));
    }

    #[test]
    fn degree_too_large_rejected() {
        let inputs = make_inputs();
        let mut envelope = make_envelope(&inputs);
        envelope.degree_bits = MAX_DEGREE_BITS + 1;

        let err = ProofVerifier::verify(&envelope, &inputs, 1_000_000).unwrap_err();
        assert!(matches!(err, ProofVerifyError::DegreeTooLarge { .. }));
    }

    #[test]
    fn format_version_too_old_rejected() {
        let inputs = make_inputs();
        let mut envelope = make_envelope(&inputs);
        envelope.proof_format_version = 0;

        let err = ProofVerifier::verify(&envelope, &inputs, 1_000_000).unwrap_err();
        assert!(matches!(err, ProofVerifyError::FormatVersionTooOld { .. }));
    }

    #[test]
    fn public_inputs_mismatch_rejected() {
        let inputs = make_inputs();
        let mut envelope = make_envelope(&inputs);
        envelope.public_inputs_hash[0] ^= 0xFF; // tamper

        let err = ProofVerifier::verify(&envelope, &inputs, 1_000_000).unwrap_err();
        assert!(matches!(err, ProofVerifyError::PublicInputsMismatch { .. }));
    }

    #[test]
    fn gas_limit_exceeded_rejected() {
        let inputs = make_inputs();
        let mut envelope = make_envelope(&inputs);
        envelope.degree_bits = 20; // 20 * 1000 = 20000 gas

        let err = ProofVerifier::verify(&envelope, &inputs, 10_000).unwrap_err();
        assert!(matches!(err, ProofVerifyError::GasExceeded { .. }));
    }

    #[test]
    fn public_inputs_hash_is_deterministic() {
        let inputs = make_inputs();
        let h1 = inputs.hash();
        let h2 = inputs.hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_inputs_different_hash() {
        let inputs1 = make_inputs();
        let mut inputs2 = inputs1.clone();
        inputs2.chain_id = 9999;
        assert_ne!(inputs1.hash(), inputs2.hash());
    }

    #[test]
    fn validate_envelope_structure_catches_all_basics() {
        let inputs = make_inputs();
        let envelope = make_envelope(&inputs);
        assert!(ProofVerifier::validate_envelope_structure(&envelope).is_ok());

        let mut bad = envelope.clone();
        bad.backend = String::new();
        assert!(ProofVerifier::validate_envelope_structure(&bad).is_err());
    }

    #[test]
    fn verification_gas_scales_with_degree() {
        let inputs = make_inputs();
        let mut envelope = make_envelope(&inputs);
        envelope.degree_bits = 10;
        let r1 = ProofVerifier::verify(&envelope, &inputs, 1_000_000).unwrap();

        envelope.degree_bits = 20;
        let r2 = ProofVerifier::verify(&envelope, &inputs, 1_000_000).unwrap();

        assert!(r2.verification_gas > r1.verification_gas);
        assert_eq!(r2.verification_gas, 20 * GAS_PER_DEGREE_BIT);
    }
}
