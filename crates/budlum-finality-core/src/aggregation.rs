//! Consensus-of-consensuses aggregation.
//!
//! How per-domain finality proofs compose into a single, slashable, end-to-end
//! final `GlobalBlockHeader`. This mirrors the composition in
//! `src/settlement/universal_finality.rs` (`end_to_end_slashable`): a cross-domain
//! value route is only as safe as its weakest link, so the global header is
//! fail-closed - empty or partial sets are NOT a consensus of consensuses.

use crate::{is_economic_backing, SecurityBacking};

/// The consensus families Budlum settles. Closed set so an unknown family can
/// never silently enter a global header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainKind {
    /// Proof of work (Nakamoto).
    Pow,
    /// Proof of stake.
    Pos,
    /// Proof of authority.
    Poa,
    /// Byzantine fault tolerant (Tendermint/HotStuff/Casper).
    Bft,
    /// Zero-knowledge validity.
    Zk,
    /// Directed acyclic graph / parallel structure.
    Dag,
    /// Storage attestation.
    StorageAttestation,
    /// AI inference attestation.
    AiInference,
}

/// One domain's verified finality contribution to the global header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainFinality {
    /// Which consensus family produced this finality.
    pub family: DomainKind,
    /// Backing observed for this domain.
    pub backing: SecurityBacking,
    /// Whether the domain has reached finality under its own rule.
    pub finalized: bool,
}

/// A `GlobalBlockHeader` records one finality proof per domain and folds them
/// into a single consensus-of-consensuses claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalBlockHeader {
    /// Per-domain finality contributions.
    pub domains: Vec<DomainFinality>,
}

impl GlobalBlockHeader {
    /// Build a header from the contributing domains.
    #[must_use]
    pub fn new(domains: Vec<DomainFinality>) -> Self {
        Self { domains }
    }

    /// Every contributing domain has reached finality. This is the bare
    /// "consensus of consensuses": each family's finality is verified and
    /// recorded. Fail-closed: an empty header is not a consensus.
    #[must_use]
    pub fn is_consensus_of_consensuses(&self) -> bool {
        !self.domains.is_empty() && self.domains.iter().all(|d| d.finalized)
    }

    /// End-to-end slashable: every domain is finalized **and** economically
    /// backed. This is the predicate that gates cross-domain value routing.
    /// Fail-closed: an empty or partially-backed set is not slashable.
    #[must_use]
    pub fn is_end_to_end_slashable(&self) -> bool {
        !self.domains.is_empty()
            && self
                .domains
                .iter()
                .all(|d| d.finalized && is_economic_backing(&d.backing))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecurityBacking;

    fn pow_source() -> DomainFinality {
        DomainFinality {
            family: DomainKind::Pow,
            backing: SecurityBacking::Work {
                difficulty_bits: 0x1d00_ffff,
            },
            finalized: true,
        }
    }
    fn pos_hub(slashable: bool) -> DomainFinality {
        DomainFinality {
            family: DomainKind::Pos,
            backing: SecurityBacking::SignatureSet {
                scheme: crate::Scheme::Ed25519,
                signers: 100,
                required: 67,
                total_weight: 100,
                slashable,
            },
            finalized: true,
        }
    }
    fn bft_target() -> DomainFinality {
        DomainFinality {
            family: DomainKind::Bft,
            backing: SecurityBacking::SignatureSet {
                scheme: crate::Scheme::Ed25519,
                signers: 100,
                required: 67,
                total_weight: 100,
                slashable: true,
            },
            finalized: true,
        }
    }

    #[test]
    fn full_slashable_chain_is_consensus_of_consensuses() {
        let h = GlobalBlockHeader::new(vec![pow_source(), pos_hub(true), bft_target()]);
        assert!(h.is_consensus_of_consensuses());
        assert!(h.is_end_to_end_slashable());
    }

    #[test]
    fn unslashable_hub_breaks_end_to_end_but_not_finality() {
        let h = GlobalBlockHeader::new(vec![pow_source(), pos_hub(false), bft_target()]);
        // All finalized -> still a consensus of consensuses.
        assert!(h.is_consensus_of_consensuses());
        // But the hub is not economically backed -> not slashable for value.
        assert!(!h.is_end_to_end_slashable());
    }

    #[test]
    fn non_finalized_domain_breaks_both() {
        let mut hub = pos_hub(true);
        hub.finalized = false;
        let h = GlobalBlockHeader::new(vec![pow_source(), hub, bft_target()]);
        assert!(!h.is_consensus_of_consensuses());
        assert!(!h.is_end_to_end_slashable());
    }

    #[test]
    fn empty_header_is_fail_closed() {
        let h = GlobalBlockHeader::new(vec![]);
        assert!(!h.is_consensus_of_consensuses());
        assert!(!h.is_end_to_end_slashable());
    }

    #[test]
    fn zk_domain_counts_as_economic_backing() {
        let zk = DomainFinality {
            family: DomainKind::Zk,
            backing: SecurityBacking::Zk {
                system: crate::ProofSystem::BudStark,
                public_inputs_digest: [0u8; 32],
            },
            finalized: true,
        };
        let h = GlobalBlockHeader::new(vec![zk, bft_target()]);
        assert!(h.is_end_to_end_slashable());
    }
}
