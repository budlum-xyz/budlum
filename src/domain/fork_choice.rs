//! Per-domain fork-choice and lifecycle primitives.
//!
//! This module is deliberately pure: it resolves candidate heads without
//! Mutating chain state or performing network/RPC calls. Consensus engines can
//! Wire these helpers later while the deterministic rules are already pinned by
//! Unit tests.

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
    ZkVerifiedState,
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
    /// Performs the requested operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
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
        let mut head = match &self.kind {
            ConsensusKind::PoW | ConsensusKind::Pospace => resolve_pow(candidates)?,
            ConsensusKind::PoS => resolve_pos(candidates)?,
            ConsensusKind::Bft | ConsensusKind::Dag | ConsensusKind::Poh => {
                resolve_bft(candidates)?
            }
            ConsensusKind::PoA => resolve_poa(candidates)?,
            ConsensusKind::Zk => resolve_zk(candidates)?,
            ConsensusKind::StorageAttestation(_)
            | ConsensusKind::AiInference
            | ConsensusKind::Custom(_) => return Err(ForkChoiceError::UnsupportedConsensusKind),
        };
        if candidates.len() == 1
            && !matches!(
                self.kind,
                ConsensusKind::Bft
                    | ConsensusKind::Dag
                    | ConsensusKind::Poh
                    | ConsensusKind::PoA
                    | ConsensusKind::Zk
            )
        {
            head.reason = ForkChoiceReason::SingleCandidate;
        }
        Ok(head)
    }
}

/// Freeze state produced when conflicting finalized commitments are observed
/// for the same domain.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum DomainForkFreezeStatus {
    Active,
    Frozen {
        conflicting_height: u64,
        head_a: Hash32,
        head_b: Hash32,
    },
}

/// In-block evidence required to unfreeze a domain frozen by conflicting
/// finalized commitments. Out-of-block claims (`verified_in_block == false`)
/// or zero digests are unconditionally refused.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct InBlockForkResolutionProof {
    block_height: u64,
    winning_head_hash: Hash32,
    quorum_proof_digest: Hash32,
    verified_in_block: bool,
}

#[cfg(test)]
impl DomainForkChoice {
    fn first_conflict_pair(candidates: &[ForkCandidate]) -> Option<(u64, Hash32, Hash32)> {
        let mut seen = std::collections::BTreeMap::<u64, Hash32>::new();
        for c in candidates {
            if let Some(prev) = seen.insert(c.height, c.head_hash) {
                if prev != c.head_hash {
                    return Some((c.height, prev, c.head_hash));
                }
            }
        }
        let mut seen_cp: Option<(u64, Hash32)> = None;
        for c in candidates {
            if let Some(cp) = c.finalized_checkpoint {
                match seen_cp {
                    None => seen_cp = Some((c.height, cp)),
                    Some((h, prev_cp)) if prev_cp != cp => {
                        return Some((h.min(c.height), prev_cp, cp));
                    }
                    Some(_) => {}
                }
            }
        }
        None
    }

    fn evaluate_with_freeze(
        &self,
        candidates: &[ForkCandidate],
    ) -> Result<(DomainForkFreezeStatus, ResolvedHead), (ForkChoiceError, DomainForkFreezeStatus)>
    {
        match self.fork_choice(candidates) {
            Ok(head) => Ok((DomainForkFreezeStatus::Active, head)),
            Err(ForkChoiceError::ConflictingFinality) => {
                let (conflicting_height, head_a, head_b) =
                    Self::first_conflict_pair(candidates).unwrap_or((0, [0u8; 32], [0u8; 32]));
                Err((
                    ForkChoiceError::ConflictingFinality,
                    DomainForkFreezeStatus::Frozen {
                        conflicting_height,
                        head_a,
                        head_b,
                    },
                ))
            }
            Err(err) => Err((err, DomainForkFreezeStatus::Active)),
        }
    }

    fn unfreeze_with_in_block_proof(
        &self,
        current: &DomainForkFreezeStatus,
        winning_candidate: &ForkCandidate,
        proof: &InBlockForkResolutionProof,
    ) -> Result<(DomainForkFreezeStatus, ResolvedHead), ForkChoiceError> {
        let DomainForkFreezeStatus::Frozen {
            conflicting_height, ..
        } = current
        else {
            return Err(ForkChoiceError::NoCandidates);
        };
        if !proof.verified_in_block
            || proof.quorum_proof_digest == [0u8; 32]
            || proof.block_height == 0
            || proof.winning_head_hash != winning_candidate.head_hash
            || winning_candidate.height < *conflicting_height
        {
            return Err(ForkChoiceError::ConflictingFinality);
        }
        let resolved = self.fork_choice(std::slice::from_ref(winning_candidate))?;
        if resolved.finality != DomainFinalityStatus::Finalized {
            return Err(ForkChoiceError::ConflictingFinality);
        }
        Ok((DomainForkFreezeStatus::Active, resolved))
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
    #[must_use]
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

fn resolve_pow(candidates: &[ForkCandidate]) -> Result<ResolvedHead, ForkChoiceError> {
    let best = candidates
        .iter()
        .map(|c| c.cumulative_work.filter(|w| *w > 0).map(|work| (c, work)))
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

fn has_same_height_conflict<'a>(candidates: impl Iterator<Item = &'a ForkCandidate>) -> bool {
    let mut seen = std::collections::BTreeMap::<u64, Hash32>::new();
    for candidate in candidates {
        if let Some(prev_hash) = seen.insert(candidate.height, candidate.head_hash) {
            if prev_hash != candidate.head_hash {
                return true;
            }
        }
    }
    false
}

fn has_conflicting_finalized_checkpoints(candidates: &[ForkCandidate]) -> bool {
    let mut seen: Option<Hash32> = None;
    for cp in candidates.iter().filter_map(|c| c.finalized_checkpoint) {
        match seen {
            None => seen = Some(cp),
            Some(prev) if prev != cp => return true,
            Some(_) => {}
        }
    }
    false
}

fn resolve_pos(candidates: &[ForkCandidate]) -> Result<ResolvedHead, ForkChoiceError> {
    if has_conflicting_finalized_checkpoints(candidates) {
        return Err(ForkChoiceError::ConflictingFinality);
    }
    let best = candidates
        .iter()
        .map(|c| c.vote_weight.filter(|w| *w > 0).map(|weight| (c, weight)))
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
    // Check every height in the candidate set - not only the highest - so a
    // double-QC equivocation at height H cannot be masked by a single higher
    // candidate at height H + 1.
    if has_same_height_conflict(with_qc.iter().copied()) {
        return Err(ForkChoiceError::ConflictingFinality);
    }
    let best = with_qc
        .into_iter()
        .max_by(|a, b| a.height.cmp(&b.height).then(b.head_hash.cmp(&a.head_hash)))
        .ok_or(ForkChoiceError::NoCandidates)?;
    Ok(ResolvedHead {
        domain_id: best.domain_id,
        head_hash: best.head_hash,
        height: best.height,
        finality: DomainFinalityStatus::Finalized,
        reason: ForkChoiceReason::BftQuorumCertificate,
    })
}

fn resolve_poa(candidates: &[ForkCandidate]) -> Result<ResolvedHead, ForkChoiceError> {
    let with_quorum: Vec<&ForkCandidate> =
        candidates.iter().filter(|c| c.authority_quorum).collect();
    if with_quorum.is_empty() {
        return Err(ForkChoiceError::MissingAuthorityQuorum);
    }
    if has_same_height_conflict(with_quorum.iter().copied()) {
        return Err(ForkChoiceError::ConflictingFinality);
    }
    let best = with_quorum
        .into_iter()
        .max_by(|a, b| a.height.cmp(&b.height).then(b.head_hash.cmp(&a.head_hash)))
        .ok_or(ForkChoiceError::NoCandidates)?;
    Ok(ResolvedHead {
        domain_id: best.domain_id,
        head_hash: best.head_hash,
        height: best.height,
        finality: DomainFinalityStatus::Finalized,
        reason: ForkChoiceReason::PoaRoundRobinAuthority,
    })
}

fn resolve_zk(candidates: &[ForkCandidate]) -> Result<ResolvedHead, ForkChoiceError> {
    let verified: Vec<&ForkCandidate> = candidates
        .iter()
        .filter(|c| c.qc_present && c.finalized_checkpoint.is_some())
        .collect();
    if verified.is_empty() {
        return Err(ForkChoiceError::MissingQuorumCertificate);
    }
    if has_same_height_conflict(verified.iter().copied()) {
        return Err(ForkChoiceError::ConflictingFinality);
    }
    let best = verified
        .into_iter()
        .max_by(|a, b| a.height.cmp(&b.height).then(b.head_hash.cmp(&a.head_hash)))
        .ok_or(ForkChoiceError::NoCandidates)?;
    Ok(ResolvedHead {
        domain_id: best.domain_id,
        head_hash: best.head_hash,
        height: best.height,
        finality: DomainFinalityStatus::Finalized,
        reason: ForkChoiceReason::ZkVerifiedState,
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
            resolver.fork_choice(&[a]).unwrap_err(),
            ForkChoiceError::MissingAuthorityQuorum
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
    fn poa_conflicting_quorum_at_one_height_is_rejected() {
        let resolver = DomainForkChoice {
            domain_id: 4,
            kind: ConsensusKind::PoA,
        };
        let mut a = candidate(4, 10, 0x41);
        a.authority_quorum = true;
        let mut b = candidate(4, 10, 0x42);
        b.authority_quorum = true;
        assert_eq!(
            resolver.fork_choice(&[a, b]).unwrap_err(),
            ForkChoiceError::ConflictingFinality
        );
    }

    #[test]
    fn bft_single_candidate_without_qc_is_rejected() {
        let resolver = DomainForkChoice {
            domain_id: 3,
            kind: ConsensusKind::Bft,
        };
        assert_eq!(
            resolver.fork_choice(&[candidate(3, 10, 0x31)]).unwrap_err(),
            ForkChoiceError::MissingQuorumCertificate
        );
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

    #[test]
    fn single_candidate_cannot_bypass_work_or_vote_weight() {
        let pow = DomainForkChoice {
            domain_id: 1,
            kind: ConsensusKind::PoW,
        };
        let mut lone_pow = candidate(1, 10, 0x51);
        lone_pow.finalized_checkpoint = Some(hash(0xFF));
        assert_eq!(
            pow.fork_choice(std::slice::from_ref(&lone_pow))
                .unwrap_err(),
            ForkChoiceError::MissingCumulativeWork
        );
        lone_pow.cumulative_work = Some(0);
        assert_eq!(
            pow.fork_choice(std::slice::from_ref(&lone_pow))
                .unwrap_err(),
            ForkChoiceError::MissingCumulativeWork
        );
        lone_pow.cumulative_work = Some(42);
        let resolved_pow = pow.fork_choice(&[lone_pow]).unwrap();
        assert_eq!(resolved_pow.finality, DomainFinalityStatus::Probabilistic);
        assert_eq!(resolved_pow.reason, ForkChoiceReason::SingleCandidate);

        let pos = DomainForkChoice {
            domain_id: 2,
            kind: ConsensusKind::PoS,
        };
        let mut lone_pos = candidate(2, 10, 0x61);
        assert_eq!(
            pos.fork_choice(std::slice::from_ref(&lone_pos))
                .unwrap_err(),
            ForkChoiceError::MissingVoteWeight
        );
        lone_pos.vote_weight = Some(0);
        assert_eq!(
            pos.fork_choice(std::slice::from_ref(&lone_pos))
                .unwrap_err(),
            ForkChoiceError::MissingVoteWeight
        );
        lone_pos.vote_weight = Some(100);
        let resolved_pos = pos.fork_choice(&[lone_pos]).unwrap();
        assert_eq!(resolved_pos.reason, ForkChoiceReason::SingleCandidate);
    }

    #[test]
    fn fork_choice_detects_sub_tip_equivocation_and_resolves_dag_poh_pospace_zk() {
        let base = |h: u64, byte: u8| ForkCandidate {
            domain_id: 7,
            head_hash: [byte; 32],
            parent_hash: [0x01; 32],
            height: h,
            cumulative_work: Some(u128::from(h) * 10),
            vote_weight: Some(u128::from(h) * 100),
            justified_checkpoint: Some([0xAA; 32]),
            finalized_checkpoint: Some([0xBB; 32]),
            proposer: None,
            qc_present: true,
            authority_quorum: true,
        };

        // Sub-tip double-QC at h=10 masked by single h=11 candidate must fail closed.
        let bft = DomainForkChoice {
            domain_id: 7,
            kind: ConsensusKind::Bft,
        };
        assert_eq!(
            bft.fork_choice(&[base(10, 0x11), base(10, 0x22), base(11, 0x33)]),
            Err(ForkChoiceError::ConflictingFinality)
        );

        // Conflicting PoS finalized checkpoints must fail closed.
        let pos = DomainForkChoice {
            domain_id: 7,
            kind: ConsensusKind::PoS,
        };
        let mut pos_b = base(11, 0x44);
        pos_b.finalized_checkpoint = Some([0xCC; 32]);
        assert_eq!(
            pos.fork_choice(&[base(10, 0x11), pos_b]),
            Err(ForkChoiceError::ConflictingFinality)
        );

        // Sub-tip double authority quorum at h=10 under PoA must also fail closed.
        let poa = DomainForkChoice {
            domain_id: 7,
            kind: ConsensusKind::PoA,
        };
        assert_eq!(
            poa.fork_choice(&[base(10, 0x11), base(10, 0x22), base(12, 0x55)]),
            Err(ForkChoiceError::ConflictingFinality)
        );

        // Zk resolves cleanly and refuses same-height conflicting verified claims.
        let zk = DomainForkChoice {
            domain_id: 7,
            kind: ConsensusKind::Zk,
        };
        let head = zk
            .fork_choice(&[base(10, 0x11), base(12, 0x22)])
            .expect("resolve zk");
        assert_eq!(head.height, 12);
        assert_eq!(head.head_hash, [0x22; 32]);
        assert_eq!(head.reason, ForkChoiceReason::ZkVerifiedState);
        assert_eq!(
            zk.fork_choice(&[base(10, 0x11), base(10, 0x99), base(12, 0x22)]),
            Err(ForkChoiceError::ConflictingFinality)
        );
    }

    #[test]
    fn conflicting_finalized_commitments_freeze_domain_and_only_in_block_proof_unfreezes() {
        let bft = DomainForkChoice {
            domain_id: 9,
            kind: ConsensusKind::Bft,
        };
        let branch_a = ForkCandidate {
            domain_id: 9,
            head_hash: [0x11; 32],
            parent_hash: [0x01; 32],
            height: 42,
            cumulative_work: None,
            vote_weight: Some(1_000),
            justified_checkpoint: Some([0x11; 32]),
            finalized_checkpoint: Some([0x11; 32]),
            proposer: None,
            qc_present: true,
            authority_quorum: true,
        };
        let branch_b = ForkCandidate {
            head_hash: [0x22; 32],
            justified_checkpoint: Some([0x22; 32]),
            finalized_checkpoint: Some([0x22; 32]),
            ..branch_a.clone()
        };

        // 1. Conflicting finalized commitments freeze the domain.
        let (err, frozen) = bft
            .evaluate_with_freeze(&[branch_a.clone(), branch_b])
            .expect_err("conflicting finalized commitments must freeze domain");
        assert_eq!(err, ForkChoiceError::ConflictingFinality);
        assert_eq!(
            frozen,
            DomainForkFreezeStatus::Frozen {
                conflicting_height: 42,
                head_a: [0x11; 32],
                head_b: [0x22; 32],
            }
        );

        // 2. Out-of-block claim cannot unfreeze.
        let off_chain_proof = InBlockForkResolutionProof {
            block_height: 100,
            winning_head_hash: branch_a.head_hash,
            quorum_proof_digest: [0xAB; 32],
            verified_in_block: false,
        };
        assert_eq!(
            bft.unfreeze_with_in_block_proof(&frozen, &branch_a, &off_chain_proof),
            Err(ForkChoiceError::ConflictingFinality)
        );

        // 3. Zero-digest proof cannot unfreeze even if marked in-block.
        let zero_proof = InBlockForkResolutionProof {
            verified_in_block: true,
            quorum_proof_digest: [0u8; 32],
            ..off_chain_proof.clone()
        };
        assert_eq!(
            bft.unfreeze_with_in_block_proof(&frozen, &branch_a, &zero_proof),
            Err(ForkChoiceError::ConflictingFinality)
        );

        // 4. Valid in-block proof over the winning finalized branch unfreezes the domain.
        let in_block_proof = InBlockForkResolutionProof {
            block_height: 101,
            winning_head_hash: branch_a.head_hash,
            quorum_proof_digest: [0xCD; 32],
            verified_in_block: true,
        };
        let (next_state, resolved) = bft
            .unfreeze_with_in_block_proof(&frozen, &branch_a, &in_block_proof)
            .expect("valid in-block proof must unfreeze domain");
        assert_eq!(next_state, DomainForkFreezeStatus::Active);
        assert_eq!(resolved.head_hash, [0x11; 32]);
        assert_eq!(resolved.height, 42);
        assert_eq!(resolved.finality, DomainFinalityStatus::Finalized);
    }
}

/// Measured behavior of the ZK fork-choice arm ("finality comes from proof").
///
/// `ConsensusKind::Zk` maps to `CryptographicValidity`
/// (`src/settlement/universal_finality.rs`), meaning it must select a verified
/// finality claim rather than vote weight or cumulative work. The tests below
/// lock this behavior as measurement: without a QC and finalized checkpoint it
/// refuses to resolve, two conflicting verified candidates at the same height
/// refuse to resolve, and large `cumulative_work`/`vote_weight` never sway it.
#[cfg(test)]
mod zk_fork_choice_gate_tests {
    use super::*;

    fn candidate(domain_id: DomainId, height: u64, byte: u8) -> ForkCandidate {
        ForkCandidate {
            domain_id,
            head_hash: [byte; 32],
            parent_hash: [0x01; 32],
            height,
            cumulative_work: None,
            vote_weight: None,
            justified_checkpoint: None,
            finalized_checkpoint: None,
            proposer: None,
            qc_present: false,
            authority_quorum: false,
        }
    }

    fn zk(domain_id: DomainId) -> DomainForkChoice {
        DomainForkChoice {
            domain_id,
            kind: ConsensusKind::Zk,
        }
    }

    #[test]
    fn zk_arm_refuses_without_verified_finality_claim() {
        // Neither candidate has a QC or finalized checkpoint: must refuse.
        let res = zk(9).fork_choice(&[candidate(9, 10, 0x11), candidate(9, 12, 0x22)]);
        assert_eq!(res, Err(ForkChoiceError::MissingQuorumCertificate));
    }

    #[test]
    fn zk_arm_refuses_when_qc_present_without_finalized_checkpoint() {
        // `qc_present` alone is insufficient: finalized_checkpoint must also be bound.
        let mut with_qc = candidate(9, 12, 0x22);
        with_qc.qc_present = true;
        assert_eq!(
            zk(9).fork_choice(&[with_qc]),
            Err(ForkChoiceError::MissingQuorumCertificate)
        );
    }

    #[test]
    fn zk_arm_refuses_conflicting_finality_at_same_height() {
        let mut a = candidate(9, 12, 0x22);
        a.qc_present = true;
        a.finalized_checkpoint = Some([0xBB; 32]);
        let mut b = candidate(9, 12, 0x33);
        b.qc_present = true;
        b.finalized_checkpoint = Some([0xCC; 32]);
        assert_eq!(
            zk(9).fork_choice(&[a, b]),
            Err(ForkChoiceError::ConflictingFinality)
        );
    }

    #[test]
    fn zk_arm_ignores_cumulative_work_and_vote_weight() {
        // Huge `cumulative_work`/`vote_weight` without a finality claim:
        // ZK arm never falls back to PoW/PoS rules and refuses.
        let mut heavy = candidate(9, 99, 0x44);
        heavy.cumulative_work = Some(u128::MAX);
        heavy.vote_weight = Some(u128::MAX);
        assert_eq!(
            zk(9).fork_choice(&[heavy]),
            Err(ForkChoiceError::MissingQuorumCertificate)
        );

        // Between two verified candidates selection follows height; the higher
        // verified candidate wins regardless of lower vote_weight.
        let mut low = candidate(9, 10, 0x55);
        low.qc_present = true;
        low.finalized_checkpoint = Some([0xBB; 32]);
        low.vote_weight = Some(u128::MAX);
        let mut high = candidate(9, 11, 0x66);
        high.qc_present = true;
        high.finalized_checkpoint = Some([0xBB; 32]);
        let head = zk(9).fork_choice(&[low, high]).expect("must resolve");
        assert_eq!(head.height, 11);
        assert_eq!(head.head_hash, [0x66; 32]);
    }
}
