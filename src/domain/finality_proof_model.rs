//! The shape of a finality proof: which commitment fields it binds, how its
//! signers are weighted, what the verifier had to trust first, and what "deep
//! enough" means for its family.
//!
//! # Why this exists
//!
//! `FinalityProof` is an enum and `DomainFinalityAdapter` is a trait, so a proof
//! can be verified. What the type system does not carry is **what a given
//! proof actually commits to**. That fact was written out by hand inside every
//! adapter, and the adapters disagree in substance: a Bitcoin SPV header binds a
//! transaction root and no state root, a ZK claim binds a state root and no
//! transaction root, and a BLS certificate binds a height and a block hash and
//! nothing else. A reader had to open each adapter to learn the difference, and
//! a caller had no way to ask.
//!
//! The claim "consensus of consensuses" is a claim about *composition*: proofs
//! from different families meet in one `GlobalBlockHeader`. Composition is only
//! auditable if the bound field set of each family is stated in one place
//! rather than inferred from each adapter's control flow. This module is the
//! vocabulary for that statement; the table itself is
//! [`FinalityProof::shape`](crate::domain::finality_adapter::FinalityProof::shape),
//! beside the enum it describes.
//!
//! # What it is not
//!
//! It is not a second verifier. Nothing here re-checks a signature, and the
//! shape is not trusted: an adapter that ignores its own shape still verifies
//! the way it always did. The value is that the table is written once, is
//! testable against every variant, and is the statement settlement checks
//! itself against before it anchors a root (see
//! `settlement::domains::verify_commitment_finality_observed`).
//!
//! # Stability
//!
//! `binds` is a `u32` bitset, not a struct of booleans, so a new bound can be
//! added without moving the value. The constants are append-only: a proof whose
//! shape changes from one release to the next is a proof whose meaning changed.

/// The proof binds `DomainCommitment::domain_height`.
pub const BINDS_HEIGHT: u32 = 1 << 0;
/// The proof binds `DomainCommitment::parent_domain_block_hash`.
pub const BINDS_PARENT_HASH: u32 = 1 << 1;
/// The proof binds `DomainCommitment::domain_block_hash`.
pub const BINDS_BLOCK_HASH: u32 = 1 << 2;
/// The proof binds `DomainCommitment::state_root`.
pub const BINDS_STATE_ROOT: u32 = 1 << 3;
/// The proof binds `DomainCommitment::tx_root`.
pub const BINDS_TX_ROOT: u32 = 1 << 4;
/// The proof binds `DomainCommitment::event_root`.
pub const BINDS_EVENT_ROOT: u32 = 1 << 5;
/// The proof binds `DomainCommitment::timestamp_ms`.
pub const BINDS_TIMESTAMP: u32 = 1 << 6;

/// How the signers of a quorum proof are weighted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuorumClass {
    /// Chainwork, not signers: the heaviest valid chain wins.
    WorkWeighted,
    /// Stake: the signed stake must exceed the threshold.
    StakeWeighted,
    /// One authority one vote, with no stake concept.
    AuthorityWeighted,
    /// Validity proof or envelope carrying its own verified statement (no signer quorum).
    ProofCarrying,
}

/// What a verifier had to accept before the proof could be checked at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustAnchor {
    /// The domain's registered `validator_set_hash`.
    RegisteredSet,
    /// The domain's declared `genesis_state_root`.
    GenesisStateRoot,
    /// A checkpoint the caller already trusts (a header window's first header).
    TrustedCheckpoint,
    /// The proof carries its own claim registry entry; no external anchor.
    ProofCarrying,
}

/// What "deep enough" means for the family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepthClass {
    /// A number of descendant headers.
    Confirmations,
    /// One block is final; depth is a liveness question, not a safety one.
    SingleBlock,
    /// A proof that is delayed by construction (a STARK behind its claim).
    ProofDelay,
}

/// What one proof family covers, stated once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalityProofShape {
    /// A bitset of the `BINDS_*` constants.
    pub binds: u32,
    pub quorum: QuorumClass,
    pub trust_anchor: TrustAnchor,
    pub depth: DepthClass,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::finality::{FinalityCert, ValidatorEntry, ValidatorSetSnapshot};
    use crate::core::address::Address;
    use crate::domain::types::Hash32;
    use crate::domain::FinalityProof;

    const ZERO: Hash32 = [0u8; 32];

    fn cert(height: u64) -> FinalityCert {
        FinalityCert {
            epoch: 1,
            checkpoint_height: height,
            checkpoint_hash: hex::encode([1u8; 32]),
            chain_id: 1,
            agg_sig_bls: Vec::new(),
            bitmap: Vec::new(),
            set_hash: hex::encode([2u8; 32]),
            seat_table_version: 0,
        }
    }

    fn snapshot() -> ValidatorSetSnapshot {
        ValidatorSetSnapshot {
            epoch: 1,
            validators: vec![ValidatorEntry {
                address: Address::from([3u8; 32]),
                stake: 1,
                bls_public_key: Vec::new(),
                pop_signature: Vec::new(),
                pq_public_key: Vec::new(),
            }],
            set_hash: hex::encode([2u8; 32]),
            total_stake: 1,
        }
    }

    const EVERY_FIELD: u32 = BINDS_HEIGHT
        | BINDS_PARENT_HASH
        | BINDS_BLOCK_HASH
        | BINDS_STATE_ROOT
        | BINDS_TX_ROOT
        | BINDS_EVENT_ROOT
        | BINDS_TIMESTAMP;

    /// Every variant's shape must agree with the message its adapter verifies.
    #[test]
    fn every_variant_declares_the_fields_its_adapter_binds() {
        let cases: Vec<(FinalityProof, u32)> = vec![
            (
                FinalityProof::PoS {
                    cert: cert(9),
                    validator_snapshot: snapshot(),
                },
                BINDS_HEIGHT | BINDS_BLOCK_HASH,
            ),
            (
                FinalityProof::PoA {
                    authorities: vec![Address::from([3u8; 32])],
                    signatures: Vec::new(),
                },
                EVERY_FIELD,
            ),
            (
                FinalityProof::Bft {
                    round: 1,
                    commit_hash: ZERO,
                    cert: cert(9),
                    validator_snapshot: snapshot(),
                },
                BINDS_HEIGHT | BINDS_BLOCK_HASH,
            ),
            (
                FinalityProof::Zk {
                    domain_id: 1,
                    target_height: 2,
                    final_state_root: ZERO,
                },
                BINDS_HEIGHT | BINDS_STATE_ROOT,
            ),
            (
                FinalityProof::Dag {
                    round: 1,
                    anchor: ZERO,
                    parent_anchor: ZERO,
                    authorities: vec![Address::from([3u8; 32])],
                    signatures: Vec::new(),
                },
                EVERY_FIELD,
            ),
            (
                FinalityProof::Poh {
                    chain: Vec::new(),
                    authorities: vec![Address::from([3u8; 32])],
                    signatures: Vec::new(),
                },
                EVERY_FIELD,
            ),
            (
                FinalityProof::Pospace {
                    prover: Address::from([3u8; 32]),
                    plot_id: ZERO,
                    quality_bits: 1,
                    prover_signature: Vec::new(),
                    authorities: vec![Address::from([3u8; 32])],
                    signatures: Vec::new(),
                },
                EVERY_FIELD,
            ),
            (
                FinalityProof::PoWHeaderChain {
                    headers: Vec::new(),
                },
                EVERY_FIELD,
            ),
            (
                FinalityProof::BitcoinSpv {
                    headers: Vec::new(),
                },
                BINDS_HEIGHT
                    | BINDS_PARENT_HASH
                    | BINDS_BLOCK_HASH
                    | BINDS_TX_ROOT
                    | BINDS_TIMESTAMP,
            ),
            (
                FinalityProof::DagPq {
                    round: 1,
                    anchor: ZERO,
                    parent_anchor: ZERO,
                    authorities: Vec::new(),
                    signatures: Vec::new(),
                },
                EVERY_FIELD,
            ),
            (
                FinalityProof::PohPq {
                    chain: Vec::new(),
                    authorities: Vec::new(),
                    signatures: Vec::new(),
                },
                EVERY_FIELD,
            ),
            (
                FinalityProof::PospacePq {
                    prover: Address::from([3u8; 32]),
                    plot_id: ZERO,
                    quality_bits: 1,
                    prover_signature: Vec::new(),
                    authorities: Vec::new(),
                    signatures: Vec::new(),
                },
                EVERY_FIELD,
            ),
            (FinalityProof::Raw(Vec::new()), 0),
        ];
        for (proof, expected) in cases {
            assert_eq!(proof.shape().binds, expected, "{proof:?}");
        }
    }

    /// The two work-weighted families are the only ones that need a checkpoint
    /// the caller already trusts rather than a set the domain registered.
    #[test]
    fn work_weighted_families_anchor_on_a_checkpoint() {
        for proof in [
            FinalityProof::PoWHeaderChain {
                headers: Vec::new(),
            },
            FinalityProof::BitcoinSpv {
                headers: Vec::new(),
            },
        ] {
            let shape = proof.shape();
            assert_eq!(shape.quorum, QuorumClass::WorkWeighted);
            assert_eq!(shape.trust_anchor, TrustAnchor::TrustedCheckpoint);
            assert_eq!(shape.depth, DepthClass::Confirmations);
        }
    }

    /// A shape with no bounds reports no fields, not a panic.
    #[test]
    fn raw_shape_binds_nothing() {
        let shape = FinalityProof::Raw(Vec::new()).shape();
        assert_eq!(shape.binds, 0);
        assert_eq!(shape.quorum, QuorumClass::ProofCarrying);
        assert_eq!(shape.trust_anchor, TrustAnchor::ProofCarrying);
        assert_eq!(shape.depth, DepthClass::ProofDelay);
    }
}
