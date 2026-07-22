//! Task 11.8 — per-domain fork-choice and lifecycle primitives.
//!
//! This module is deliberately pure: it resolves candidate heads without
//! mutating chain state or performing network/RPC calls. Consensus engines can
//! wire these helpers later while the deterministic rules are already pinned by
//! unit tests.

use crate::core::address::Address;
use crate::domain::{ConsensusKind, DomainId, Hash32};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainFinalityStatus {
    Probabilistic,
    Justified,
    Finalized,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForkChoiceReason {
    PowMostWork,
    PosLatestMessageDriven,
    BftQuorumCertificate,
    PoaRoundRobinAuthority,
    SingleCandidate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForkChoiceError {
    NoCandidates,
    MixedDomainCandidates,
    MissingCumulativeWork,
    MissingVoteWeight,
    MissingQuorumCertificate,
    MissingAuthorityQuorum,
    ConflictingFinality,
    UnsupportedConsensusKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkCandidate {
    pub domain_id: DomainId,
    pub head_hash: Hash32,
    pub parent_hash: Hash32,
    pub height: u64,
    pub cumulative_work: Option<u128>,
    pub vote_weight: Option<u128>,
    pub justified_checkpoint: Option<Hash32>,
    pub finalized_checkpoint: Option<Hash32>,
    pub proposer: Option<Address>,
    pub qc_present: bool,
    pub authority_quorum: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedHead {
    pub domain_id: DomainId,
    pub head_hash: Hash32,
    pub height: u64,
    pub finality: DomainFinalityStatus,
    pub reason: ForkChoiceReason,
}

pub trait ConsensusDomainForkChoice {
    fn fork_choice(&self, candidates: &[ForkCandidate]) -> Result<ResolvedHead, ForkChoiceError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainForkChoice {
    pub domain_id: DomainId,
    pub kind: ConsensusKind,
}

impl ConsensusDomainForkChoice for DomainForkChoice {
    fn fork_choice(&self, candidates: &[ForkCandidate]) -> Result<ResolvedHead, ForkChoiceError> {
        ensure_single_domain(self.domain_id, candidates)?;
        if candidates.len() == 1 {
            return Ok(resolve_single(candidates[0].clone()));
        }
        match &self.kind {
            ConsensusKind::PoW => resolve_pow(candidates),
            ConsensusKind::PoS => resolve_pos(candidates),
            ConsensusKind::Bft => resolve_bft(candidates),
            ConsensusKind::PoA => resolve_poa(candidates),
            _ => Err(ForkChoiceError::UnsupportedConsensusKind),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainLifecycleStatus {
    Proposed,
    Active,
    Paused,
    Draining,
    Retired,
}

impl DomainLifecycleStatus {
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Proposed, Self::Active)
                | (Self::Active, Self::Paused)
                | (Self::Paused, Self::Active)
                | (Self::Active, Self::Draining)
                | (Self::Paused, Self::Draining)
                | (Self::Draining, Self::Retired)
        )
    }
}

fn ensure_single_domain(
    expected_domain: DomainId,
    candidates: &[ForkCandidate],
) -> Result<(), ForkChoiceError> {
    if candidates.is_empty() {
        return Err(ForkChoiceError::NoCandidates);
    }
    if candidates.iter().any(|c| c.domain_id != expected_domain) {
        return Err(ForkChoiceError::MixedDomainCandidates);
    }
    Ok(())
}

fn resolve_single(candidate: ForkCandidate) -> ResolvedHead {
    ResolvedHead {
        domain_id: candidate.domain_id,
        head_hash: candidate.head_hash,
        height: candidate.height,
        finality: if candidate.finalized_checkpoint.is_some() {
            DomainFinalityStatus::Finalized
        } else if candidate.justified_checkpoint.is_some() {
            DomainFinalityStatus::Justified
        } else {
            DomainFinalityStatus::Probabilistic
        },
        reason: ForkChoiceReason::SingleCandidate,
    }
}

fn resolve_pow(candidates: &[ForkCandidate]) -> Result<ResolvedHead, ForkChoiceError> {
    let best = candidates
        .iter()
        .map(|c| c.cumulative_work.map(|work| (c, work)))
        .collect::<Option<Vec<_>>>()
        .ok_or(ForkChoiceError::MissingCumulativeWork)?
        .into_iter()
        .max_by(|(a, aw), (b, bw)| {
            aw.cmp(bw)
                .then(a.height.cmp(&b.height))
                .then(b.head_hash.cmp(&a.head_hash))
        })
        .map(|(c, _)| c)
        .ok_or(ForkChoiceError::NoCandidates)?;
    Ok(ResolvedHead {
        domain_id: best.domain_id,
        head_hash: best.head_hash,
        height: best.height,
        finality: DomainFinalityStatus::Probabilistic,
        reason: ForkChoiceReason::PowMostWork,
    })
}

fn resolve_pos(candidates: &[ForkCandidate]) -> Result<ResolvedHead, ForkChoiceError> {
    let best = candidates
        .iter()
        .map(|c| c.vote_weight.map(|weight| (c, weight)))
        .collect::<Option<Vec<_>>>()
        .ok_or(ForkChoiceError::MissingVoteWeight)?
        .into_iter()
        .max_by(|(a, aw), (b, bw)| {
            aw.cmp(bw)
                .then(a.height.cmp(&b.height))
                .then(b.head_hash.cmp(&a.head_hash))
        })
        .map(|(c, _)| c)
        .ok_or(ForkChoiceError::NoCandidates)?;
    Ok(ResolvedHead {
        domain_id: best.domain_id,
        head_hash: best.head_hash,
        height: best.height,
        finality: if best.finalized_checkpoint.is_some() {
            DomainFinalityStatus::Finalized
        } else {
            DomainFinalityStatus::Justified
        },
        reason: ForkChoiceReason::PosLatestMessageDriven,
    })
}

fn resolve_bft(candidates: &[ForkCandidate]) -> Result<ResolvedHead, ForkChoiceError> {
    let with_qc: Vec<&ForkCandidate> = candidates.iter().filter(|c| c.qc_present).collect();
    if with_qc.is_empty() {
        return Err(ForkChoiceError::MissingQuorumCertificate);
    }
    let best = with_qc
        .into_iter()
        .max_by(|a, b| a.height.cmp(&b.height).then(b.head_hash.cmp(&a.head_hash)))
        .ok_or(ForkChoiceError::NoCandidates)?;
    let same_height_conflicts = candidates
        .iter()
        .filter(|c| c.qc_present && c.height == best.height && c.head_hash != best.head_hash)
        .count();
    if same_height_conflicts > 0 {
        return Err(ForkChoiceError::ConflictingFinality);
    }
    Ok(ResolvedHead {
        domain_id: best.domain_id,
        head_hash: best.head_hash,
        height: best.height,
        finality: DomainFinalityStatus::Finalized,
        reason: ForkChoiceReason::BftQuorumCertificate,
    })
}

fn resolve_poa(candidates: &[ForkCandidate]) -> Result<ResolvedHead, ForkChoiceError> {
    let best = candidates
        .iter()
        .filter(|c| c.authority_quorum)
        .max_by(|a, b| a.height.cmp(&b.height).then(b.head_hash.cmp(&a.head_hash)))
        .ok_or(ForkChoiceError::MissingAuthorityQuorum)?;
    Ok(ResolvedHead {
        domain_id: best.domain_id,
        head_hash: best.head_hash,
        height: best.height,
        finality: DomainFinalityStatus::Finalized,
        reason: ForkChoiceReason::PoaRoundRobinAuthority,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> Hash32 {
        [byte; 32]
    }

    fn candidate(domain_id: DomainId, height: u64, byte: u8) -> ForkCandidate {
        ForkCandidate {
            domain_id,
            head_hash: hash(byte),
            parent_hash: hash(byte.saturating_sub(1)),
            height,
            cumulative_work: None,
            vote_weight: None,
            justified_checkpoint: None,
            finalized_checkpoint: None,
            proposer: Some(Address::from([byte; 32])),
            qc_present: false,
            authority_quorum: false,
        }
    }

    #[test]
    fn pow_picks_highest_cumulative_work() {
        let resolver = DomainForkChoice {
            domain_id: 1,
            kind: ConsensusKind::PoW,
        };
        let mut weak = candidate(1, 10, 0x10);
        weak.cumulative_work = Some(100);
        let mut strong = candidate(1, 9, 0x20);
        strong.cumulative_work = Some(200);
        let head = resolver.fork_choice(&[weak, strong.clone()]).unwrap();
        assert_eq!(head.head_hash, strong.head_hash);
        assert_eq!(head.reason, ForkChoiceReason::PowMostWork);
    }

    #[test]
    fn pos_picks_highest_vote_weight() {
        let resolver = DomainForkChoice {
            domain_id: 2,
            kind: ConsensusKind::PoS,
        };
        let mut a = candidate(2, 10, 0x11);
        a.vote_weight = Some(10);
        let mut b = candidate(2, 9, 0x22);
        b.vote_weight = Some(20);
        b.finalized_checkpoint = Some(hash(0xAA));
        let head = resolver.fork_choice(&[a, b.clone()]).unwrap();
        assert_eq!(head.head_hash, b.head_hash);
        assert_eq!(head.finality, DomainFinalityStatus::Finalized);
    }

    #[test]
    fn bft_conflicting_qc_is_rejected() {
        let resolver = DomainForkChoice {
            domain_id: 3,
            kind: ConsensusKind::Bft,
        };
        let mut a = candidate(3, 10, 0x31);
        a.qc_present = true;
        let mut b = candidate(3, 10, 0x32);
        b.qc_present = true;
        assert_eq!(
            resolver.fork_choice(&[a, b]).unwrap_err(),
            ForkChoiceError::ConflictingFinality
        );
    }

    #[test]
    fn poa_requires_authority_quorum() {
        let resolver = DomainForkChoice {
            domain_id: 4,
            kind: ConsensusKind::PoA,
        };
        let a = candidate(4, 10, 0x41);
        assert_eq!(
            resolver.fork_choice(&[a]).unwrap().reason,
            ForkChoiceReason::SingleCandidate
        );
        let mut b = candidate(4, 11, 0x42);
        b.authority_quorum = true;
        let head = resolver
            .fork_choice(&[candidate(4, 10, 0x41), b.clone()])
            .unwrap();
        assert_eq!(head.head_hash, b.head_hash);
        assert_eq!(head.reason, ForkChoiceReason::PoaRoundRobinAuthority);
    }

    #[test]
    fn lifecycle_transitions_are_explicit() {
        assert!(DomainLifecycleStatus::Proposed.can_transition_to(DomainLifecycleStatus::Active));
        assert!(DomainLifecycleStatus::Active.can_transition_to(DomainLifecycleStatus::Paused));
        assert!(DomainLifecycleStatus::Paused.can_transition_to(DomainLifecycleStatus::Draining));
        assert!(DomainLifecycleStatus::Draining.can_transition_to(DomainLifecycleStatus::Retired));
        assert!(!DomainLifecycleStatus::Retired.can_transition_to(DomainLifecycleStatus::Active));
        assert!(!DomainLifecycleStatus::Proposed.can_transition_to(DomainLifecycleStatus::Retired));
    }

    #[test]
    fn mixed_domain_candidates_rejected() {
        let resolver = DomainForkChoice {
            domain_id: 1,
            kind: ConsensusKind::PoW,
        };
        let mut a = candidate(1, 1, 1);
        a.cumulative_work = Some(1);
        let mut b = candidate(2, 1, 2);
        b.cumulative_work = Some(2);
        assert_eq!(
            resolver.fork_choice(&[a, b]).unwrap_err(),
            ForkChoiceError::MixedDomainCandidates
        );
    }
}
