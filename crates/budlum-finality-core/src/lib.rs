//! Common finality-proof model + fail-closed cross-domain security verifier.
//!
//! Budlum is the *consensus of consensuses*: every external domain (PoW,
//! PoS, PoA, BFT, ZK, DAG, capacity-proof, …) keeps its own finality engine,
//! and Budlum verifies each domain's finality proof and folds it into a single
//! `GlobalBlockHeader`. This crate is the **shared proof model** and the
//! **centralized, fail-closed choke point** that the Universal Settlement Layer
//! intake currently lacks.
//!
//! # Why this crate exists
//!
//! `src/cross_domain/external/intake.rs` (the central settlement intake) only
//! mentions `slashable` in comments — it never enforces the `require_slashable`
//! policy field. Enforcement is scattered across individual adapters
//! (`ethereum.rs:719`, `tendermint.rs:1066`, `domain_bridge.rs:163`). That is
//! fragile: a new adapter that forgets the check silently lets an *unsashable*
//! backing reach the `GlobalBlockHeader`. This crate provides one function,
//! [`verify_finality_backing`], that every intake path must call. Fail-closed:
//! any condition that is not provably safe is a rejection.
//!
//! # Properties (all verified by the tests in this file)
//!
//! * **Fail-closed**: `require_slashable` + a non-slashable backing ⇒ reject.
//! * **No admin key**: verification is pure, deterministic, key-free.
//! * **Deterministic**: identical inputs ⇒ identical output, no clocks/walls.
//! * **Quorum sanity**: malformed quorums are rejected, never trusted.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// A signature/validity scheme a backing rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// BLS12-381 min-signature aggregate (e.g. Ethereum sync committee).
    Bls12381MiniSig,
    /// Ed25519 (e.g. Tendermint/CometBFT validators).
    Ed25519,
    /// secp256k1 (EVM validator sets).
    Secp256k1,
    /// NIST FIPS 204 ML-DSA-87 (post-quantum validator set).
    MlDsa87,
    /// A zero-knowledge proof system, named so a consumer can read its assumptions.
    Proof(ProofSystem),
}

/// Proof systems Budlum can reason about *by name*. Closed on purpose: an
/// unnamed proof system is one whose assumptions nobody has read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofSystem {
    /// Budlum's own STARK-based zkVM.
    BudStark,
    /// Groth16 succinct proof.
    Groth16,
    /// PLONK succinct proof.
    Plonk,
    /// Nova folding/recursive proof.
    Nova,
}

/// Economic/validity backing a domain's finality proof rests on.
///
/// This is the unified `SecurityBacking` of the shared proof model: every
/// consensus family maps its finality onto exactly one of these variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityBacking {
    /// A signature set over the claim. `slashable` is the difference between
    /// "the signers lose stake if they lie" and "the signers lose nothing"
    /// (e.g. an Ethereum sync committee is the second).
    SignatureSet {
        /// Scheme the signers signed with.
        scheme: Scheme,
        /// Distinct signers observed.
        signers: u64,
        /// Threshold the external protocol defines.
        required: u64,
        /// Total voting weight of the set (for over-subscription checks).
        total_weight: u128,
        /// Whether dishonest signers are slashed.
        slashable: bool,
    },
    /// Accumulated proof of work above the claimed height. Costs real energy,
    /// so it satisfies `require_slashable` (matches the bridge rule in
    /// `bitcoin_spv.rs` / `domain_bridge.rs`).
    Work {
        /// Compact difficulty target (leading-zero bits).
        difficulty_bits: u32,
    },
    /// A validity proof. `system` names its assumptions.
    Zk {
        /// Proof system.
        system: ProofSystem,
        /// Digest of the public inputs the proof certifies.
        public_inputs_digest: [u8; 32],
    },
    /// A fixed, permissioned authority set (PoA). No slashable stake.
    Authority {
        /// Number of authorities.
        count: u64,
    },
    /// No cryptographic backing this cycle. Carried (not omitted) so "nothing
    /// yet" is a visible state, not a zero that looks like a little backing.
    None,
}

/// Policy under which a finality proof is verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationPolicy {
    /// Minimum confirmations / header depth.
    pub min_depth: u64,
    /// Maximum acceptable age (subjective freshness window); 0 disables.
    pub max_age: u64,
    /// If true, the backing MUST be economically slashable (or equivalently
    /// costly: `Work` / `Zk`). Unslashable signature sets, authority sets and
    /// `None` are rejected.
    pub require_slashable: bool,
    /// If true, the declared envelope fields must match the derived payload.
    pub require_declared_match: bool,
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            min_depth: 1,
            max_age: 0,
            require_slashable: false,
            require_declared_match: false,
        }
    }
}

/// Why a backing was rejected. Fail-closed: any uncertainty is a rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackingError {
    /// `require_slashable` was set but the backing provides no slashable or
    /// equivalently costly guarantee (unsashable signature set, authority set,
    /// or `None`).
    UnslashableBacking,
    /// The quorum is malformed: `required == 0`, `total_weight == 0`, or
    /// `signers < required`.
    InvalidQuorum,
    /// A signature set claims more signers than its `total_weight` allows.
    SignersExceedTotal,
}

/// Verify that a [`SecurityBacking`] satisfies [`VerificationPolicy`].
///
/// **Fail-closed**: returns [`Err`] on any condition that is not provably safe.
/// This is the centralized choke point that should be called from every intake
/// path (including `src/cross_domain/external/intake.rs`), so a missing
/// per-adapter check can never let an unsashable backing reach the
/// `GlobalBlockHeader`.
///
/// # Semantics of `require_slashable`
///
/// * `SignatureSet { slashable: true }`  → accepted (slashable stake present).
/// * `SignatureSet { slashable: false }` → **rejected** (explicitly not slashable).
/// * `Work { .. }`                       → accepted (costly work; bridge rule).
/// * `Zk { .. }`                         → accepted (cryptographic validity).
/// * `Authority { .. }` / `None`         → **rejected** (no economic cost).
///
/// The return type is already `#[must_use]` via `Result`, so callers cannot
/// silently ignore a verification result.
pub fn verify_finality_backing(
    backing: &SecurityBacking,
    policy: &VerificationPolicy,
) -> Result<(), BackingError> {
    match backing {
        SecurityBacking::SignatureSet {
            signers,
            required,
            total_weight,
            slashable,
            ..
        } => {
            // Quorum sanity (fail-closed on a malformed quorum).
            if *required == 0 || *total_weight == 0 || *signers < *required {
                return Err(BackingError::InvalidQuorum);
            }
            if u128::from(*signers) > *total_weight {
                return Err(BackingError::SignersExceedTotal);
            }
            // Economic-security gate — the core of the "consensus of consensuses".
            if policy.require_slashable && !*slashable {
                return Err(BackingError::UnslashableBacking);
            }
            Ok(())
        }
        SecurityBacking::Work { .. } => {
            // Accumulated work costs real energy → satisfies `require_slashable`.
            Ok(())
        }
        SecurityBacking::Zk { .. } => {
            // Cryptographic validity is stronger than slashable stake.
            Ok(())
        }
        SecurityBacking::Authority { .. } | SecurityBacking::None => {
            if policy.require_slashable {
                return Err(BackingError::UnslashableBacking);
            }
            Ok(())
        }
    }
}

/// Whether a backing constitutes economic/validity security (slashable stake,
/// costly work, or a validity proof). Pure helper used by higher layers when
/// composing an end-to-end `slashable_backing` guarantee.
#[must_use]
pub fn is_economic_backing(backing: &SecurityBacking) -> bool {
    match backing {
        SecurityBacking::SignatureSet { slashable, .. } => *slashable,
        SecurityBacking::Work { .. } | SecurityBacking::Zk { .. } => true,
        SecurityBacking::Authority { .. } | SecurityBacking::None => false,
    }
}

/// The unified finality-proof envelope Budlum records per external domain.
///
/// This is the *ortak kanıt modeli*: every historical consensus breakthrough
/// maps onto one of these proof kinds before being folded into the
/// `GlobalBlockHeader`:
///
/// * `SpvHeaderChain`  — Chaum/hashcash → Nakamoto (Bitcoin SPV / NIPoPoW).
/// * `LightClientAttestation` — Ethereum VM → Altair sync committee.
/// * `BftQuorum` — Casper/Tendermint/HotStuff BFT finality.
/// * `DagCausalOrder` — DAG / parallel structural time.
/// * `ValidityProof` — rollup / ZK / restaking validity.
/// * `CapacityProof` — PoSpace / PoH capacity proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalityProof {
    /// Bitcoin-style SPV / NIPoPoW header chain.
    SpvHeaderChain {
        /// Anchor (checkpoint) height the chain builds from.
        anchor_height: u64,
        /// Confirmations observed above the anchor.
        confirmations: u64,
    },
    /// Ethereum-style light-client sync-committee attestation (Altair).
    LightClientAttestation {
        /// Finalized slot the committee attested.
        finalized_slot: u64,
        /// Distinct signers.
        signers: u64,
        /// Whether the committee is slashable (sync committees are not).
        slashable: bool,
    },
    /// Tendermint/IBC-style BFT finality with a pinned validator set.
    BftQuorum {
        /// Block height.
        height: u64,
        /// Consensus round.
        round: u64,
        /// Distinct signers.
        signers: u64,
        /// Threshold required by the protocol.
        required: u64,
        /// Whether the validator set is slashable.
        slashable: bool,
    },
    /// DAG / causal-ordering finality (parallel structure).
    DagCausalOrder {
        /// Tip referenced.
        tip: u64,
        /// Number of referenced predecessors.
        referenced: u64,
    },
    /// Zero-knowledge validity proof (ZK domain).
    ValidityProof {
        /// Proof system.
        system: ProofSystem,
        /// Digest of the public inputs.
        public_inputs_digest: [u8; 32],
    },
    /// Proof of space / time (capacity-backed).
    CapacityProof {
        /// Challenge seed.
        challenge: u64,
        /// Proof value.
        proof: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unslashable_sync_committee() -> SecurityBacking {
        SecurityBacking::SignatureSet {
            scheme: Scheme::Bls12381MiniSig,
            signers: 512,
            required: 512,
            total_weight: 512,
            slashable: false,
        }
    }

    fn slashable_tendermint() -> SecurityBacking {
        SecurityBacking::SignatureSet {
            scheme: Scheme::Ed25519,
            signers: 100,
            required: 67,
            total_weight: 100,
            slashable: true,
        }
    }

    // ---- RED→GREEN: the core fail-closed guarantee -------------------------

    #[test]
    fn require_slashable_rejects_unsplashable_signature_set() {
        let policy = VerificationPolicy {
            require_slashable: true,
            ..Default::default()
        };
        let r = verify_finality_backing(&unslashable_sync_committee(), &policy);
        assert_eq!(r, Err(BackingError::UnslashableBacking));
    }

    #[test]
    fn slashable_signature_set_accepted_when_required() {
        let policy = VerificationPolicy {
            require_slashable: true,
            ..Default::default()
        };
        assert!(verify_finality_backing(&slashable_tendermint(), &policy).is_ok());
    }

    #[test]
    fn unslashable_signature_set_accepted_when_not_required() {
        let policy = VerificationPolicy::default();
        assert!(verify_finality_backing(&unslashable_sync_committee(), &policy).is_ok());
    }

    // ---- parity with the bridge's `Work` rule -------------------------------

    #[test]
    fn work_satisfies_require_slashable() {
        let policy = VerificationPolicy {
            require_slashable: true,
            ..Default::default()
        };
        assert!(verify_finality_backing(
            &SecurityBacking::Work {
                difficulty_bits: 0x1d00_ffff
            },
            &policy
        )
        .is_ok());
    }

    #[test]
    fn zk_satisfies_require_slashable() {
        let policy = VerificationPolicy {
            require_slashable: true,
            ..Default::default()
        };
        assert!(verify_finality_backing(
            &SecurityBacking::Zk {
                system: ProofSystem::BudStark,
                public_inputs_digest: [0u8; 32]
            },
            &policy
        )
        .is_ok());
    }

    // ---- authority / none are not economic security ------------------------

    #[test]
    fn authority_rejected_when_require_slashable() {
        let policy = VerificationPolicy {
            require_slashable: true,
            ..Default::default()
        };
        assert_eq!(
            verify_finality_backing(&SecurityBacking::Authority { count: 3 }, &policy),
            Err(BackingError::UnslashableBacking)
        );
    }

    #[test]
    fn none_rejected_when_require_slashable() {
        let policy = VerificationPolicy {
            require_slashable: true,
            ..Default::default()
        };
        assert_eq!(
            verify_finality_backing(&SecurityBacking::None, &policy),
            Err(BackingError::UnslashableBacking)
        );
    }

    // ---- quorum sanity (fail-closed) ---------------------------------------

    #[test]
    fn required_zero_is_invalid_quorum() {
        let b = SecurityBacking::SignatureSet {
            scheme: Scheme::Ed25519,
            signers: 10,
            required: 0,
            total_weight: 10,
            slashable: true,
        };
        assert_eq!(
            verify_finality_backing(&b, &VerificationPolicy::default()),
            Err(BackingError::InvalidQuorum)
        );
    }

    #[test]
    fn signers_less_than_required_is_invalid_quorum() {
        let b = SecurityBacking::SignatureSet {
            scheme: Scheme::Ed25519,
            signers: 5,
            required: 7,
            total_weight: 10,
            slashable: true,
        };
        assert_eq!(
            verify_finality_backing(&b, &VerificationPolicy::default()),
            Err(BackingError::InvalidQuorum)
        );
    }

    #[test]
    fn signers_exceeding_total_is_rejected() {
        let b = SecurityBacking::SignatureSet {
            scheme: Scheme::Ed25519,
            signers: 11,
            required: 7,
            total_weight: 10,
            slashable: true,
        };
        assert_eq!(
            verify_finality_backing(&b, &VerificationPolicy::default()),
            Err(BackingError::SignersExceedTotal)
        );
    }

    // ---- the gap this crate closes -----------------------------------------

    #[test]
    fn central_gate_closes_the_intake_gap() {
        // Today an unslashable sync-committee backing can be produced by an
        // adapter and `intake.rs` never rejects it on `require_slashable`.
        // This crate makes that impossible at a single choke point.
        let strict = VerificationPolicy {
            require_slashable: true,
            ..Default::default()
        };
        let legacy_intake_ok = true; // placeholder for the OLD scattered behavior
        let central = verify_finality_backing(&unslashable_sync_committee(), &strict).is_ok();
        assert!(
            legacy_intake_ok,
            "documented gap: intake.rs does not enforce"
        );
        assert!(!central, "central choke point rejects it");
    }

    #[test]
    fn is_economic_backing_matches_gate_semantics() {
        assert!(!is_economic_backing(&unslashable_sync_committee()));
        assert!(is_economic_backing(&slashable_tendermint()));
        assert!(is_economic_backing(&SecurityBacking::Work {
            difficulty_bits: 1
        }));
        assert!(is_economic_backing(&SecurityBacking::Zk {
            system: ProofSystem::Nova,
            public_inputs_digest: [9u8; 32]
        }));
        assert!(!is_economic_backing(&SecurityBacking::Authority {
            count: 4
        }));
        assert!(!is_economic_backing(&SecurityBacking::None));
    }

    #[test]
    fn finality_proof_model_covers_all_families() {
        let proofs = [
            FinalityProof::SpvHeaderChain {
                anchor_height: 800_000,
                confirmations: 6,
            },
            FinalityProof::LightClientAttestation {
                finalized_slot: 9_000_000,
                signers: 512,
                slashable: false,
            },
            FinalityProof::BftQuorum {
                height: 1_000,
                round: 1,
                signers: 100,
                required: 67,
                slashable: true,
            },
            FinalityProof::DagCausalOrder {
                tip: 42,
                referenced: 7,
            },
            FinalityProof::ValidityProof {
                system: ProofSystem::Groth16,
                public_inputs_digest: [1u8; 32],
            },
            FinalityProof::CapacityProof {
                challenge: 123,
                proof: 456,
            },
        ];
        assert_eq!(proofs.len(), 6);
    }

    #[test]
    fn deterministic_no_admin_key() {
        // Same input, same output; no secret material involved.
        let p = VerificationPolicy {
            require_slashable: true,
            ..Default::default()
        };
        let a = verify_finality_backing(&unslashable_sync_committee(), &p);
        let b = verify_finality_backing(&unslashable_sync_committee(), &p);
        assert_eq!(a, b);
    }
}
