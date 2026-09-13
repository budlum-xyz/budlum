//! Multi-prover quorum rounds on the consensus intake: the production home
//! of the `quorum` module's rules.
//!
//! # Why the intake needs rounds at all
//!
//! `IntakeState::submit_evidence` answers one question: is this evidence a
//! valid proof under the domain's declared rules. For a *proven* domain that
//! is the whole story. For a *vote-based* domain it is not - the adapter
//! checks the signatures, but which finalised header the prover chose to
//! carry is the prover's choice, and provers can disagree. The `quorum`
//! module states the resolution rules; this module gives them the thing they
//! were missing: a place where several provers' answers about the same
//! external height actually accumulate.
//!
//! # The shape of a round
//!
//! A round is keyed by `(domain, height)`. Provers submit their evidence
//! through [`QuorumRounds::submit`]; each submission is verified by the
//! domain's adapter exactly as a single submission would be, and the result
//! is folded into the round as an [`Answer`]:
//!
//! - verification succeeded -> `Answer::Claim(state_root)` - the claim is
//!   the root, because that is the thing Budlum would commit to;
//! - the adapter refused for a reason about the claim -> a
//!   `ConsensusRefusal` with the mapped [`RefusalKind`];
//! - the adapter could not answer for a reason about itself
//!   (`Unavailable`, `Crypto` with no verifier installed) ->
//!   `Answer::Infrastructure`, which never counts as a participant.
//!
//! The round decides through [`decide`] under the domain's stored
//! [`QuorumPolicy`]. Nothing is committed until the round returns
//! `AgreedClaim`; an `AgreedRefusal` closes the round negatively (the
//! external evidence is bad - that is an answer); `Dispute` freezes the
//! round for the challenge game and marks the domain faulted, because two
//! bonded provers carrying different finalised headers at the same height
//! is exactly the situation the fault state exists to describe.
//!
//! # What a round refuses
//!
//! - a second answer from the same prover in the same round: one bond, one
//!   voice - resubmission would let a single operator manufacture agreement;
//! - answers after the round decided: a decided round is a fact, and facts
//!   do not take late votes;
//! - more answers than `max_participants`: the policy's bound is the
//!   memory bound.
//!
//! # Determinism
//!
//! Rounds are `BTreeMap`-keyed and answers are folded in submission order,
//! which is block order once this sits behind the chain actor. Two nodes
//! that saw the same submissions in the same order hold the same rounds;
//! the round state is part of [`super::intake::IntakeState`]'s serialized
//! form and therefore inside `state_digest`.

use crate::core::address::Address;
use crate::cross_domain::external::quorum::{
    decide, group_answers, lead_is_unassailable, Answer, AnswerGroup, QuorumOutcome, QuorumPolicy,
};
use crate::cross_domain::external::selftest::RefusalKind;
use crate::cross_domain::external::spec::{
    AdapterError, DomainKey, FinalityAttestation, RawConsensusEvidence,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One prover's recorded participation in one round: who answered, what the
/// fold saw, and the digest of the evidence they carried. The digest stays
/// so a later challenge can name the exact bytes a slashing is about. When
/// the answer is a claim, the attestation the adapter produced travels with
/// the entry: the round's product must be readable from the round itself,
/// not reconstructed from a registry that may have moved on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoundEntry {
    pub prover: Address,
    pub answer: Answer,
    pub evidence_digest: [u8; 32],
    pub attestation: Option<Box<FinalityAttestation>>,
}

/// The lifecycle of one `(domain, height)` round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoundState {
    /// Answers are still being collected.
    Open,
    /// Enough provers agreed on one claim; the attestation is the round's
    /// product and the height is committable.
    AgreedClaim {
        claim: [u8; 32],
        count: usize,
        /// The attestation of the first prover inside the winning group, in
        /// arrival order. Every member of the group derived the same root;
        /// the first arrival is the deterministic representative.
        attestation: Box<FinalityAttestation>,
    },
    /// Enough provers refused the same way. Negative knowledge, kept: the
    /// evidence for this height is bad under the declared rules.
    AgreedRefusal { kind: RefusalKind, count: usize },
    /// Valid participants disagreed and no group reached the threshold. The
    /// round freezes here; resolution belongs to the challenge game
    /// (`slash_external_prover`), not to more votes.
    Disputed,
}

/// One quorum round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumRound {
    pub domain: DomainKey,
    pub height: u64,
    pub state: RoundState,
    pub entries: Vec<RoundEntry>,
    /// Height of the local chain when the round opened, for staleness
    /// sweeping: a round nobody finished is not kept forever.
    pub opened_at: u64,
}

impl QuorumRound {
    /// The answers as the quorum module wants them.
    fn answers(&self) -> Vec<Answer> {
        self.entries.iter().map(|e| e.answer).collect()
    }

    /// Whether this prover already answered. One bond, one voice.
    fn has_answered(&self, prover: &Address) -> bool {
        self.entries.iter().any(|e| e.prover == *prover)
    }

    /// The round as a watcher sees it: the current groups, how many
    /// answers were infrastructure failures (never participants), whether
    /// the leading group can still be caught, and whether the snapshot
    /// already constitutes a decision under the policy. This is the read
    /// the RPC surface serves to a submitter whose evidence returned
    /// "round pending".
    #[must_use]
    pub fn progress(&self, policy: &QuorumPolicy) -> RoundProgress {
        let answers = self.answers();
        let (standings, infrastructure_failures) = group_answers(&answers);
        let remaining = policy.max_participants.saturating_sub(self.entries.len());
        RoundProgress {
            lead_unassailable: lead_is_unassailable(&answers, policy, remaining),
            decided: decide(&answers, policy).decided(),
            remaining_seats: remaining,
            infrastructure_failures,
            standings,
        }
    }
}

/// A watcher's snapshot of one round, produced by [`QuorumRound::progress`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoundProgress {
    /// Whether the leading group can no longer be caught or tied by the
    /// seats that remain. `true` means the outcome is already inevitable.
    pub lead_unassailable: bool,
    /// Whether this snapshot is a decision the policy would act on.
    pub decided: bool,
    /// Seats the policy still admits.
    pub remaining_seats: usize,
    /// Answers that never counted as participants.
    pub infrastructure_failures: usize,
    /// The groups, largest first, exactly as the quorum rules group them.
    pub standings: Vec<AnswerGroup>,
}

/// What went wrong at the round boundary. Distinct from the intake's own
/// error: a refusal here means the answer never entered a round.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RoundError {
    #[error("no external domain is registered under this key")]
    UnknownDomain,
    #[error("this domain has no quorum policy; single-submission is its path")]
    NoQuorumPolicy,
    #[error("prover already answered in this round; one bond, one voice")]
    DuplicateAnswer,
    #[error("round is already decided: {state}")]
    RoundClosed { state: String },
    #[error("round is full: the policy admits {max} participants")]
    RoundFull { max: usize },
}

/// The quorum layer of the intake: policies per domain, live rounds, and the
/// fold from adapter results to answers. Owned by `IntakeState`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumRounds {
    /// The quorum policy each vote-based domain runs under. Registered
    /// domains without an entry here use the single-submission path; a
    /// proven domain never needs one (a proof does not become truer when
    /// several people carry it).
    #[serde(with = "crate::core::map_keys")]
    pub policies: BTreeMap<DomainKey, QuorumPolicy>,
    /// Live and recently decided rounds, keyed by domain and external
    /// height. Kept decided until swept so the RPC surface can show what a
    /// round concluded and why.
    #[serde(with = "crate::core::map_keys")]
    pub rounds: BTreeMap<RoundKey, QuorumRound>,
}

/// The key of one round: which domain, which external height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RoundKey {
    pub domain: DomainKey,
    pub height: u64,
}

/// JSON map key: `"<domain hex>:<height>"`.
impl crate::core::map_keys::MapKey for RoundKey {
    fn to_key_string(&self) -> String {
        format!("{}:{}", hex::encode(self.domain.0), self.height)
    }
    fn from_key_string(s: &str) -> Result<Self, String> {
        let [domain, height] = crate::core::map_keys::parts::<2>(s)?;
        Ok(Self {
            domain: DomainKey(crate::core::map_keys::parse_hex32(domain)?),
            height: crate::core::map_keys::parse_uint(height, "height")?,
        })
    }
}

/// How many local blocks a decided or stale round is kept before sweeping.
/// Undecided rounds older than this are also swept: a round that never
/// gathered a quorum is itself information, but unbounded retention is a
/// memory promise nobody made.
pub const ROUND_RETENTION_BLOCKS: u64 = 10_000;

impl QuorumRounds {
    /// Installs (or replaces) the quorum policy of one domain. Policy
    /// installation is a consensus action for the same reason registration
    /// is: two nodes disagreeing about the threshold decide differently.
    pub fn set_policy(&mut self, domain: DomainKey, policy: QuorumPolicy) {
        self.policies.insert(domain, policy);
    }

    /// The policy of a domain, if it runs quorum rounds.
    #[must_use]
    pub fn policy_of(&self, domain: &DomainKey) -> Option<&QuorumPolicy> {
        self.policies.get(domain)
    }

    /// Folds one adapter result into the round for `(domain, height)`,
    /// creating the round if it is new, and re-decides the round.
    ///
    /// `verified` is the adapter's verdict on this prover's evidence,
    /// produced by the caller (the intake, which owns adapter construction).
    /// This function never verifies anything itself: it is the bookkeeping
    /// between verdicts and outcomes, and keeping crypto out of it is what
    /// makes its determinism reviewable.
    ///
    /// # Errors
    ///
    /// [`RoundError`] when the answer cannot enter the round. An error here
    /// leaves the round untouched.
    pub fn submit(
        &mut self,
        domain: DomainKey,
        evidence: &RawConsensusEvidence,
        verified: &Result<FinalityAttestation, AdapterError>,
        local_height: u64,
    ) -> Result<RoundState, RoundError> {
        let Some(policy) = self.policies.get(&domain).copied() else {
            return Err(RoundError::NoQuorumPolicy);
        };
        let height = evidence.declared_height;
        let round = self
            .rounds
            .entry(RoundKey { domain, height })
            .or_insert_with(|| QuorumRound {
                domain,
                height,
                state: RoundState::Open,
                entries: Vec::new(),
                opened_at: local_height,
            });
        if !matches!(round.state, RoundState::Open) {
            return Err(RoundError::RoundClosed {
                state: state_name(&round.state).to_string(),
            });
        }
        if round.has_answered(&evidence.submitter) {
            return Err(RoundError::DuplicateAnswer);
        }
        if round.entries.len() >= policy.max_participants {
            return Err(RoundError::RoundFull {
                max: policy.max_participants,
            });
        }

        let (answer, attestation) = match verified {
            Ok(attestation) => (
                Answer::Claim(attestation.state_root),
                Some(Box::new(attestation.clone())),
            ),
            Err(err) => (answer_of_error(err), None),
        };
        round.entries.push(RoundEntry {
            prover: evidence.submitter,
            answer,
            evidence_digest: evidence.digest(),
            attestation,
        });

        let outcome = decide(&round.answers(), &policy);
        round.state = match outcome {
            QuorumOutcome::AgreedClaim { claim, count } => {
                // The representative attestation: the first entry in arrival
                // order whose claim matches the winner. Arrival order is
                // block order behind the chain actor, so every node picks
                // the same representative.
                match find_attestation(&round.entries, claim) {
                    Some(att) => RoundState::AgreedClaim {
                        claim,
                        count,
                        attestation: att,
                    },
                    // A winning claim with no stored attestation cannot
                    // happen - a claim only enters with one - but "cannot
                    // happen" is not a reason to abort. The round stays
                    // open, which is the refusal that loses nothing.
                    None => RoundState::Open,
                }
            }
            QuorumOutcome::AgreedRefusal { kind, count } => {
                RoundState::AgreedRefusal { kind, count }
            }
            QuorumOutcome::Dispute { ref groups } => {
                // `decide` sees a snapshot; the round sees time. Two cases:
                //
                // - two or more groups already AT the threshold: a tie, and
                //   more votes cannot un-reach a threshold - permanent, so
                //   the round freezes for the challenge game now;
                // - no group at the threshold yet: only a dispute if no
                //   group can still get there with the seats that remain -
                //   otherwise the round stays open and waits, because
                //   waiting costs nothing and a frozen round costs a
                //   challenge game.
                let at_threshold = groups
                    .iter()
                    .filter(|g| g.count >= policy.agreement_threshold)
                    .count();
                let remaining = policy.max_participants.saturating_sub(round.entries.len());
                let best = groups.iter().map(|g| g.count).max().unwrap_or(0);
                if at_threshold >= 2 {
                    RoundState::Disputed
                } else if remaining > 0
                    && best.saturating_add(remaining) >= policy.agreement_threshold
                {
                    RoundState::Open
                } else {
                    RoundState::Disputed
                }
            }
            QuorumOutcome::LowParticipants { .. } | QuorumOutcome::NoValidParticipants { .. } => {
                RoundState::Open
            }
        };
        Ok(round.state.clone())
    }

    /// Sweeps rounds older than [`ROUND_RETENTION_BLOCKS`]. Called from the
    /// same block-commit hook that drives the registry clock.
    pub fn sweep(&mut self, local_height: u64) {
        self.rounds.retain(|_, round| {
            local_height.saturating_sub(round.opened_at) <= ROUND_RETENTION_BLOCKS
        });
    }

    /// The round for `(domain, height)`, for the RPC surface.
    #[must_use]
    pub fn round_of(&self, domain: &DomainKey, height: u64) -> Option<&QuorumRound> {
        self.rounds.get(&RoundKey {
            domain: *domain,
            height,
        })
    }

    /// Every live or retained round of one domain, oldest external height
    /// first, for the RPC surface.
    #[must_use]
    pub fn rounds_of(&self, domain: &DomainKey) -> Vec<&QuorumRound> {
        self.rounds
            .iter()
            .filter(|(k, _)| k.domain == *domain)
            .map(|(_, r)| r)
            .collect()
    }
}

/// Maps an adapter error to the answer kind the quorum counts. The split the
/// quorum module insists on: a refusal about the *claim* participates, a
/// failure about the *prover or transport* does not.
fn answer_of_error(err: &AdapterError) -> Answer {
    match err {
        // The adapter could not answer for a reason about itself. Counting
        // this as a participant would make "everybody is down" converge on
        // "everybody agrees", the failure mode the quorum docs name as the
        // worst one.
        AdapterError::Unavailable { .. } => Answer::Infrastructure,
        other => Answer::ConsensusRefusal(RefusalKind::of(other)),
    }
}

/// The first entry (arrival order) that carried the winning claim, with its
/// attestation. Arrival order is block order behind the chain actor, so the
/// representative is the same on every node.
fn find_attestation(entries: &[RoundEntry], claim: [u8; 32]) -> Option<Box<FinalityAttestation>> {
    entries
        .iter()
        .find(|e| matches!(e.answer, Answer::Claim(c) if c == claim))
        .and_then(|e| e.attestation.clone())
}

fn state_name(state: &RoundState) -> &'static str {
    match state {
        RoundState::Open => "open",
        RoundState::AgreedClaim { .. } => "agreed-claim",
        RoundState::AgreedRefusal { .. } => "agreed-refusal",
        RoundState::Disputed => "disputed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::external::quorum::{DisputeBehavior, LowParticipantsBehavior};
    use crate::cross_domain::external::spec::{AdapterId, SecurityBacking, TimeUnit};

    fn addr(b: u8) -> Address {
        Address([b; 32])
    }

    fn key() -> DomainKey {
        DomainKey::from_parts(&AdapterId::from_name("test"), "testnet")
    }

    fn policy(threshold: usize) -> QuorumPolicy {
        QuorumPolicy {
            agreement_threshold: threshold,
            max_participants: 8,
            dispute: DisputeBehavior::ReturnError,
            low_participants: LowParticipantsBehavior::ReturnError,
        }
    }

    fn evidence(submitter: u8, height: u64) -> RawConsensusEvidence {
        RawConsensusEvidence {
            adapter: AdapterId::from_name("test"),
            evidence_version: 1,
            network: "testnet".to_string(),
            payload: vec![submitter],
            declared_height: height,
            declared_root: [submitter; 32],
            submitter: addr(submitter),
        }
    }

    fn attestation(root: [u8; 32], height: u64) -> FinalityAttestation {
        FinalityAttestation {
            adapter: AdapterId::from_name("test"),
            domain: key(),
            height,
            state_root: root,
            finalized_at: height,
            time_unit: TimeUnit::Height,
            security: SecurityBacking::None,
            evidence_digest: [9; 32],
            adapter_version: 1,
            evidence_version: 1,
        }
    }

    #[test]
    fn a_domain_without_a_policy_refuses_rounds_by_name() {
        let mut rounds = QuorumRounds::default();
        let verdict: Result<FinalityAttestation, AdapterError> = Ok(attestation([1; 32], 5));
        let err = rounds
            .submit(key(), &evidence(1, 5), &verdict, 100)
            .unwrap_err();
        assert_eq!(err, RoundError::NoQuorumPolicy);
    }

    #[test]
    fn agreement_at_the_threshold_closes_the_round_with_the_claim() {
        let mut rounds = QuorumRounds::default();
        rounds.set_policy(key(), policy(2));
        let verdict = Ok(attestation([7; 32], 5));
        let first = rounds
            .submit(key(), &evidence(1, 5), &verdict, 100)
            .expect("first answer enters");
        assert!(
            matches!(first, RoundState::Open),
            "one of two is not quorum"
        );
        let second = rounds
            .submit(key(), &evidence(2, 5), &verdict, 100)
            .expect("second answer enters");
        match second {
            RoundState::AgreedClaim { claim, count, .. } => {
                assert_eq!(claim, [7; 32]);
                assert_eq!(count, 2);
            }
            other => panic!("expected agreement, got {other:?}"),
        }
    }

    #[test]
    fn one_prover_cannot_vote_twice() {
        let mut rounds = QuorumRounds::default();
        rounds.set_policy(key(), policy(2));
        let verdict = Ok(attestation([7; 32], 5));
        rounds
            .submit(key(), &evidence(1, 5), &verdict, 100)
            .expect("first");
        let err = rounds
            .submit(key(), &evidence(1, 5), &verdict, 100)
            .unwrap_err();
        assert_eq!(err, RoundError::DuplicateAnswer);
    }

    #[test]
    fn a_decided_round_takes_no_late_votes() {
        let mut rounds = QuorumRounds::default();
        rounds.set_policy(key(), policy(2));
        let verdict = Ok(attestation([7; 32], 5));
        rounds
            .submit(key(), &evidence(1, 5), &verdict, 100)
            .unwrap();
        rounds
            .submit(key(), &evidence(2, 5), &verdict, 100)
            .unwrap();
        let err = rounds
            .submit(key(), &evidence(3, 5), &verdict, 100)
            .unwrap_err();
        assert!(matches!(err, RoundError::RoundClosed { .. }));
    }

    #[test]
    fn an_assailable_lead_keeps_the_round_open() {
        let mut rounds = QuorumRounds::default();
        rounds.set_policy(
            key(),
            QuorumPolicy {
                agreement_threshold: 3,
                max_participants: 8,
                dispute: DisputeBehavior::ReturnError,
                low_participants: LowParticipantsBehavior::ReturnError,
            },
        );
        let a = Ok(attestation([1; 32], 5));
        let b = Ok(attestation([2; 32], 5));
        rounds.submit(key(), &evidence(1, 5), &a, 100).unwrap();
        rounds.submit(key(), &evidence(2, 5), &a, 100).unwrap();
        rounds.submit(key(), &evidence(3, 5), &b, 100).unwrap();
        // 2 vs 1 under threshold 3: nobody reached quorum and the round is
        // not full, so it stays open rather than declaring anything.
        let state = rounds.round_of(&key(), 5).unwrap().state.clone();
        assert!(matches!(state, RoundState::Open));
    }

    #[test]
    fn a_full_round_that_split_is_a_dispute_not_a_choice() {
        let mut rounds = QuorumRounds::default();
        rounds.set_policy(
            key(),
            QuorumPolicy {
                agreement_threshold: 3,
                max_participants: 4,
                dispute: DisputeBehavior::ReturnError,
                low_participants: LowParticipantsBehavior::ReturnError,
            },
        );
        let a = Ok(attestation([1; 32], 5));
        let b = Ok(attestation([2; 32], 5));
        rounds.submit(key(), &evidence(1, 5), &a, 100).unwrap();
        rounds.submit(key(), &evidence(2, 5), &a, 100).unwrap();
        rounds.submit(key(), &evidence(3, 5), &b, 100).unwrap();
        // 2 vs 1 with one seat left: group `a` can still reach 3, so the
        // round waits.
        let mid = rounds.round_of(&key(), 5).unwrap().state.clone();
        assert!(matches!(mid, RoundState::Open), "one seat can still decide");
        rounds.submit(key(), &evidence(4, 5), &b, 100).unwrap();
        // 2 vs 2, no seats left, threshold 3: nobody can reach it. That is
        // a dispute, and picking a side would be a choice the evidence did
        // not support.
        let state = rounds.round_of(&key(), 5).unwrap().state.clone();
        assert!(
            matches!(state, RoundState::Disputed),
            "expected dispute, got {state:?}"
        );
    }

    #[test]
    fn matching_refusals_close_the_round_as_negative_knowledge() {
        let mut rounds = QuorumRounds::default();
        rounds.set_policy(key(), policy(2));
        let refusal: Result<FinalityAttestation, AdapterError> = Err(AdapterError::ConsensusRule {
            rule: "bad".to_string(),
        });
        rounds
            .submit(key(), &evidence(1, 5), &refusal, 100)
            .unwrap();
        let state = rounds
            .submit(key(), &evidence(2, 5), &refusal, 100)
            .unwrap();
        match state {
            RoundState::AgreedRefusal { kind, count } => {
                assert_eq!(kind, RefusalKind::ConsensusRule);
                assert_eq!(count, 2);
            }
            other => panic!("expected agreed refusal, got {other:?}"),
        }
    }

    #[test]
    fn infrastructure_failures_never_count_as_participants() {
        let mut rounds = QuorumRounds::default();
        rounds.set_policy(key(), policy(1));
        let down: Result<FinalityAttestation, AdapterError> = Err(AdapterError::Unavailable {
            reason: "no verifier installed".to_string(),
        });
        let state = rounds.submit(key(), &evidence(1, 5), &down, 100).unwrap();
        // Threshold 1, one answer - but it was infrastructure, so the round
        // must NOT decide. "Everybody is down" must never read as agreement.
        assert!(matches!(state, RoundState::Open));
    }

    #[test]
    fn the_policy_bound_is_the_memory_bound() {
        let mut rounds = QuorumRounds::default();
        rounds.set_policy(
            key(),
            QuorumPolicy {
                agreement_threshold: 99,
                max_participants: 2,
                dispute: DisputeBehavior::ReturnError,
                low_participants: LowParticipantsBehavior::ReturnError,
            },
        );
        let a = Ok(attestation([1; 32], 5));
        let b = Ok(attestation([2; 32], 5));
        let c = Ok(attestation([3; 32], 5));
        rounds.submit(key(), &evidence(1, 5), &a, 100).unwrap();
        rounds.submit(key(), &evidence(2, 5), &b, 100).unwrap();
        let err = rounds.submit(key(), &evidence(3, 5), &c, 100).unwrap_err();
        assert_eq!(err, RoundError::RoundFull { max: 2 });
    }

    #[test]
    fn sweeping_removes_only_rounds_past_retention() {
        let mut rounds = QuorumRounds::default();
        rounds.set_policy(key(), policy(2));
        let verdict = Ok(attestation([7; 32], 5));
        rounds
            .submit(key(), &evidence(1, 5), &verdict, 100)
            .unwrap();
        rounds
            .submit(key(), &evidence(2, 9), &verdict, 200)
            .unwrap();
        rounds.sweep(100 + ROUND_RETENTION_BLOCKS + 1);
        assert!(rounds.round_of(&key(), 5).is_none(), "old round swept");
        assert!(rounds.round_of(&key(), 9).is_some(), "young round kept");
    }

    #[test]
    fn progress_reports_standings_and_inevitability_honestly() {
        let mut rounds = QuorumRounds::default();
        let pol = QuorumPolicy {
            agreement_threshold: 2,
            max_participants: 3,
            dispute: DisputeBehavior::ReturnError,
            low_participants: LowParticipantsBehavior::ReturnError,
        };
        rounds.set_policy(key(), pol);
        let a = Ok(attestation([1; 32], 5));
        rounds.submit(key(), &evidence(1, 5), &a, 100).unwrap();
        let round = rounds.round_of(&key(), 5).expect("round").clone();
        let progress = round.progress(&pol);
        assert!(!progress.decided, "one of two is not a decision");
        assert!(
            !progress.lead_unassailable,
            "one answer with two seats left can still be rivalled"
        );
        assert_eq!(progress.remaining_seats, 2);
        assert_eq!(progress.standings.len(), 1);
        assert_eq!(progress.standings[0].count, 1);

        rounds.submit(key(), &evidence(2, 5), &a, 100).unwrap();
        let round = rounds.round_of(&key(), 5).expect("round").clone();
        let progress = round.progress(&pol);
        assert!(progress.decided, "two matching answers at threshold 2");
        // Leader holds 2; the one remaining seat could at best form a rival
        // of 1, which falls strictly short. The outcome is inevitable.
        assert!(progress.lead_unassailable);
        assert_eq!(progress.remaining_seats, 1);
    }

    #[test]
    fn progress_counts_infrastructure_failures_apart_from_participants() {
        let mut rounds = QuorumRounds::default();
        let pol = QuorumPolicy {
            agreement_threshold: 2,
            max_participants: 4,
            dispute: DisputeBehavior::ReturnError,
            low_participants: LowParticipantsBehavior::ReturnError,
        };
        rounds.set_policy(key(), pol);
        let down: Result<FinalityAttestation, AdapterError> = Err(AdapterError::Unavailable {
            reason: "verifier missing".to_string(),
        });
        rounds.submit(key(), &evidence(1, 5), &down, 100).unwrap();
        let round = rounds.round_of(&key(), 5).expect("round").clone();
        let progress = round.progress(&pol);
        assert_eq!(progress.infrastructure_failures, 1);
        assert!(progress.standings.is_empty(), "a timeout is not a standing");
        assert!(!progress.decided);
    }

    #[test]
    fn rounds_of_lists_a_domains_rounds_in_height_order() {
        let mut rounds = QuorumRounds::default();
        rounds.set_policy(key(), policy(2));
        let verdict = Ok(attestation([7; 32], 0));
        rounds
            .submit(key(), &evidence(1, 9), &verdict, 100)
            .unwrap();
        rounds
            .submit(key(), &evidence(1, 5), &verdict, 100)
            .unwrap();
        let listed: Vec<u64> = rounds.rounds_of(&key()).iter().map(|r| r.height).collect();
        assert_eq!(listed, vec![5, 9], "BTreeMap order is height order");
    }
}
