//! Cross-prover agreement: when several provers carry the same external state
//! and disagree, what the chain does about it.
//!
//! # The gap this closes
//!
//! An adapter answers "is this evidence a valid proof under the declared
//! rules". It does not answer "is this what the external chain actually did".
//! For a proven domain those are the same question. For a vote-based domain
//! they are not: the adapter checks the signatures, but *which* header the
//! prover chose to carry is the prover's choice, and two provers can carry two
//! different finalised headers from the same chain at the same height - after
//! a reorg, during a fork, or because one of them is lying.
//!
//! So several provers are asked, their answers are grouped, and a winner
//! emerges only if enough of them agree. Nothing here trusts a single prover.
//!
//! # The four rules that are easy to get wrong
//!
//! **1. An infrastructure failure is not an answer.** If three provers time
//! out and one says "height 100, root 0xaa", that is not a 3-to-1 agreement
//! and it is not a 1-to-0 agreement either. Timeouts are excluded from the
//! participant count entirely. Counting them would mean "everybody is down"
//! eventually reads as "everybody agrees", which is the single worst failure
//! mode a quorum layer can have.
//!
//! **2. "Not enough participants" is not "participants disagree".** Both are
//! failures, but they mean different things and are reported separately: one
//! says the question was not asked widely enough, the other says it was asked
//! and the answers diverged. Collapsing them into one state hides which
//! problem the domain has.
//!
//! **3. A tie at the threshold is a dispute, not a coin flip.** Two groups of
//! three with a threshold of three is not agreement; picking either one is a
//! choice the chain did not earn. Ties are reported as disputes with both
//! groups named.
//!
//! **4. A preference can never promote an infrastructure error.** "Prefer a
//! non-empty answer" is a sensible tie-breaker between two real answers. It
//! must never be able to turn a transport failure into one. Every preference
//! in this module operates only over groups that already count as valid
//! participants.
//!
//! # Where this came from
//!
//! The grouping/threshold/dispute structure and the infrastructure-versus-
//! consensus distinction are a well-established pattern for cross-checking
//! independent sources of the same fact; the design here is our own
//! implementation of that pattern against this chain's types, not a
//! transcription of anybody's code.

use crate::cross_domain::external::selftest::RefusalKind;
use serde::{Deserialize, Serialize};

/// What one prover actually answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Answer {
    /// A claim about the external state, identified by the canonical hash of
    /// what was claimed. Grouping is on this hash, never on the prover's
    /// identity: two provers agreeing is meaningful, two provers being the
    /// same operator is not something this layer can or should detect.
    Claim([u8; 32]),
    /// The prover read the evidence and refused it for a reason about the
    /// *claim*: bad proof, consensus rule, wrong version. This counts as a
    /// participant, because it is an answer about the external state - several
    /// provers independently refusing the same way is agreement about a
    /// refusal.
    ConsensusRefusal(RefusalKind),
    /// The prover could not answer for a reason about itself or the transport:
    /// timeout, unreachable node, no verifier installed, out of memory. This
    /// does NOT count as a participant.
    Infrastructure,
}

impl Answer {
    /// Whether this answer counts toward the participant total.
    #[must_use]
    pub fn counts(&self) -> bool {
        !matches!(self, Self::Infrastructure)
    }

    /// A stable label, for grouping and for error messages. Stable across runs
    /// and independent of `Debug` formatting, because it is used as a map key.
    #[must_use]
    pub fn group_key(&self) -> String {
        match self {
            Self::Claim(hash) => format!("claim:{}", hex32(hash)),
            Self::ConsensusRefusal(kind) => format!("refusal:{}", kind.as_str()),
            Self::Infrastructure => "infrastructure".to_string(),
        }
    }
}

/// One group of identical answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnswerGroup {
    pub key: String,
    pub count: usize,
    /// The answer itself, kept so a winner can be turned back into a value.
    pub answer: Answer,
}

/// How to resolve a disagreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisputeBehavior {
    /// Refuse. The caller gets an error naming both groups.
    ReturnError,
    /// Take the most common valid group. Useful where a wrong answer is
    /// recoverable and an unavailable one is not - never for a state root that
    /// will be committed to.
    AcceptMostCommon,
}

/// How to resolve "we did not ask widely enough".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LowParticipantsBehavior {
    /// Refuse. The default, and the right answer for anything committed to.
    ReturnError,
    /// Take whatever the (too few) participants agreed on.
    AcceptMostCommon,
}

/// The quorum configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumPolicy {
    /// How many participants must give the same answer.
    pub agreement_threshold: usize,
    /// How many answers are collected at most. Bounded so a caller cannot ask
    /// the chain to hold an unbounded number of responses in memory.
    pub max_participants: usize,
    pub dispute: DisputeBehavior,
    pub low_participants: LowParticipantsBehavior,
}

impl QuorumPolicy {
    /// The policy for anything that will be committed to: refuse on dispute,
    /// refuse when too few answered, no preferences.
    #[must_use]
    pub fn strict(agreement_threshold: usize, max_participants: usize) -> Self {
        Self {
            agreement_threshold,
            max_participants,
            dispute: DisputeBehavior::ReturnError,
            low_participants: LowParticipantsBehavior::ReturnError,
        }
    }
}

/// What the quorum decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuorumOutcome {
    /// Enough participants made the same claim.
    AgreedClaim { claim: [u8; 32], count: usize },
    /// Enough participants refused in the same way. A refusal is a result: it
    /// means the external evidence is bad, which is different from "we could
    /// not tell".
    AgreedRefusal { kind: RefusalKind, count: usize },
    /// Valid participants disagreed and no group reached the threshold.
    Dispute { groups: Vec<AnswerGroup> },
    /// Too few valid participants to decide anything. Distinct from `Dispute`:
    /// the question was not asked widely enough, not answered differently.
    LowParticipants { valid: usize, required: usize },
    /// Nobody answered at all, or everybody failed at the infrastructure
    /// level. Not a `LowParticipants` with zero - a separate state, because
    /// "the provers are all down" is an operational alarm and "we asked two
    /// and needed three" is a configuration problem.
    NoValidParticipants { infrastructure_failures: usize },
}

impl QuorumOutcome {
    /// Whether this outcome is a decision the caller can act on.
    #[must_use]
    pub fn decided(&self) -> bool {
        matches!(self, Self::AgreedClaim { .. } | Self::AgreedRefusal { .. })
    }
}

/// Groups the answers. Infrastructure answers are counted but excluded from
/// the valid groups - they are reported in the outcome so an operator can see
/// them, but they never form a group that can win.
#[must_use]
pub fn group_answers(answers: &[Answer]) -> (Vec<AnswerGroup>, usize) {
    let mut keys: Vec<String> = Vec::new();
    let mut groups: Vec<AnswerGroup> = Vec::new();
    let mut infrastructure = 0usize;

    for answer in answers {
        if matches!(answer, Answer::Infrastructure) {
            infrastructure = infrastructure.saturating_add(1);
            continue;
        }
        let key = answer.group_key();
        match keys.iter().position(|k| *k == key) {
            Some(at) => {
                if let Some(group) = groups.get_mut(at) {
                    group.count = group.count.saturating_add(1);
                }
            }
            None => {
                keys.push(key.clone());
                groups.push(AnswerGroup {
                    key,
                    count: 1,
                    answer: *answer,
                });
            }
        }
    }
    // Deterministic order: largest group first, then by key. Without this the
    // "most common" choice would depend on the order provers happened to
    // answer in, which is not a fact about the world.
    groups.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    (groups, infrastructure)
}

/// Decides.
///
/// The order of the checks matters and is the substance of this module:
/// infrastructure exclusion first, then low-participants, then threshold, then
/// ties, then the dispute policy. Reordering them changes what "agreement"
/// means.
#[must_use]
pub fn decide(answers: &[Answer], policy: &QuorumPolicy) -> QuorumOutcome {
    let (groups, infrastructure) = group_answers(answers);
    let valid: usize = groups.iter().map(|g| g.count).sum();

    if valid == 0 {
        return QuorumOutcome::NoValidParticipants {
            infrastructure_failures: infrastructure,
        };
    }

    // Not enough participants is its own state, checked before any winner is
    // looked for: a single answer from a single prover must not be able to
    // reach the "agreement" branch just because the threshold is 1 and only
    // one prover answered.
    if valid < policy.agreement_threshold {
        return match policy.low_participants {
            LowParticipantsBehavior::ReturnError => QuorumOutcome::LowParticipants {
                valid,
                required: policy.agreement_threshold,
            },
            LowParticipantsBehavior::AcceptMostCommon => winner_of(&groups),
        };
    }

    // Threshold winners. Only groups that reached the threshold are
    // candidates; a group of one cannot win because a group of five exists.
    let winners: Vec<&AnswerGroup> = groups
        .iter()
        .filter(|g| g.count >= policy.agreement_threshold)
        .collect();

    match winners.len() {
        0 => match policy.dispute {
            DisputeBehavior::ReturnError => QuorumOutcome::Dispute { groups },
            DisputeBehavior::AcceptMostCommon => winner_of(&groups),
        },
        1 => match winners.first() {
            // `first` rather than `[0]`: the length was just checked, but an
            // index that is merely *probably* in range is an abort waiting for
            // an edit, and the gate that says so is right.
            Some(only) => outcome_of(only),
            None => QuorumOutcome::Dispute { groups },
        },
        _ => {
            // Two or more groups at the threshold. That is a tie, and a tie is
            // a dispute: picking one would be a choice the evidence did not
            // support. Named explicitly rather than resolved by sort order.
            let tied: Vec<AnswerGroup> = winners.into_iter().cloned().collect();
            QuorumOutcome::Dispute { groups: tied }
        }
    }
}

/// Turns a group into an outcome.
#[must_use]
fn outcome_of(group: &AnswerGroup) -> QuorumOutcome {
    match group.answer {
        Answer::Claim(claim) => QuorumOutcome::AgreedClaim {
            claim,
            count: group.count,
        },
        Answer::ConsensusRefusal(kind) => QuorumOutcome::AgreedRefusal {
            kind,
            count: group.count,
        },
        // Unreachable: infrastructure answers never form a group. Kept as a
        // refusal-shaped outcome rather than a panic, because a quorum layer
        // that can panic is a quorum layer a prover can take down.
        Answer::Infrastructure => QuorumOutcome::NoValidParticipants {
            infrastructure_failures: group.count,
        },
    }
}

/// The most common group. Only called when a policy explicitly allows it.
#[must_use]
fn winner_of(groups: &[AnswerGroup]) -> QuorumOutcome {
    match groups.first() {
        Some(group) => outcome_of(group),
        None => QuorumOutcome::NoValidParticipants {
            infrastructure_failures: 0,
        },
    }
}

/// Whether the leading group can still be overtaken by the participants that
/// have not answered yet.
///
/// This is the short-circuit: if the leader's count already exceeds the
/// threshold and the remaining participants could not bring any other group up
/// to it, waiting for them cannot change the answer. Asking anyway is latency
/// with no information in it.
///
/// `remaining` is how many participants have been asked but not yet answered.
#[must_use]
pub fn lead_is_unassailable(answers: &[Answer], policy: &QuorumPolicy, remaining: usize) -> bool {
    let (groups, _) = group_answers(answers);
    let Some(leader) = groups.first() else {
        return false;
    };
    if leader.count < policy.agreement_threshold {
        return false;
    }
    // The best any rival can reach is its current count plus every remaining
    // participant. If that still falls short of the leader, the leader holds.
    //
    // When there is no second group yet the answer is `remaining`, not zero:
    // every participant still out could answer with the SAME new claim and
    // form one rival group from nothing. Counting that as zero would report an
    // unassailable lead whenever only one claim had arrived so far, which is
    // exactly the case where waiting is most informative.
    let best_rival = match groups.get(1) {
        Some(second) => second.count.saturating_add(remaining),
        None => remaining,
    };
    // A tie is a dispute, so the rival must fall strictly short - reaching the
    // leader's count would produce a tie, which is not a win.
    best_rival < leader.count
}

/// Lowercase hex, local so this module's group keys do not depend on another
/// module's formatting.
#[must_use]
fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(b: u8) -> Answer {
        Answer::Claim([b; 32])
    }

    fn policy(threshold: usize) -> QuorumPolicy {
        QuorumPolicy::strict(threshold, 16)
    }

    #[test]
    fn an_infrastructure_failure_is_never_an_answer() {
        // Three timeouts and one claim is NOT 3-to-1 agreement, and it is not
        // 1-to-0 either. This is the worst failure mode a quorum layer can
        // have: "everybody is down" reading as "everybody agrees".
        let answers = [
            Answer::Infrastructure,
            Answer::Infrastructure,
            Answer::Infrastructure,
            claim(0xaa),
        ];
        let outcome = decide(&answers, &policy(3));
        assert_eq!(
            outcome,
            QuorumOutcome::LowParticipants {
                valid: 1,
                required: 3
            },
            "timeouts were counted as participants"
        );
    }

    #[test]
    fn all_infrastructure_failures_are_their_own_alarm() {
        let answers = [Answer::Infrastructure; 4];
        let outcome = decide(&answers, &policy(2));
        assert_eq!(
            outcome,
            QuorumOutcome::NoValidParticipants {
                infrastructure_failures: 4
            },
            "an operational outage must not read as a configuration problem"
        );
    }

    #[test]
    fn nobody_answering_is_not_the_same_as_too_few_answering() {
        let none = decide(&[], &policy(2));
        assert!(matches!(
            none,
            QuorumOutcome::NoValidParticipants { .. }
        ));
        let few = decide(&[claim(1)], &policy(2));
        assert!(matches!(few, QuorumOutcome::LowParticipants { valid: 1, required: 2 }));
    }

    #[test]
    fn a_threshold_is_reached_by_identical_claims_only() {
        let answers = [claim(0xaa), claim(0xaa), claim(0xaa), claim(0xbb)];
        let outcome = decide(&answers, &policy(3));
        assert_eq!(
            outcome,
            QuorumOutcome::AgreedClaim {
                claim: [0xaa; 32],
                count: 3
            }
        );
    }

    #[test]
    fn a_tie_at_the_threshold_is_a_dispute_not_a_coin_flip() {
        // Three and three with a threshold of three. Picking either would be a
        // choice the evidence did not support.
        let answers = [claim(0xaa), claim(0xaa), claim(0xaa), claim(0xbb), claim(0xbb), claim(0xbb)];
        let outcome = decide(&answers, &policy(3));
        match outcome {
            QuorumOutcome::Dispute { groups } => {
                assert_eq!(groups.len(), 2, "both tied groups must be named");
                assert!(groups.iter().all(|g| g.count == 3));
            }
            other => panic!("a tie at the threshold must be a dispute, got {other:?}"),
        }
    }

    #[test]
    fn an_agreed_refusal_is_a_result_not_an_absence_of_one() {
        // Three provers independently refusing the same way is agreement about
        // the evidence being bad - which is different from "we could not tell".
        let answers = [
            Answer::ConsensusRefusal(RefusalKind::Crypto),
            Answer::ConsensusRefusal(RefusalKind::Crypto),
            Answer::ConsensusRefusal(RefusalKind::Crypto),
        ];
        let outcome = decide(&answers, &policy(3));
        assert_eq!(
            outcome,
            QuorumOutcome::AgreedRefusal {
                kind: RefusalKind::Crypto,
                count: 3
            }
        );
    }

    #[test]
    fn two_different_refusals_do_not_agree() {
        let answers = [
            Answer::ConsensusRefusal(RefusalKind::Crypto),
            Answer::ConsensusRefusal(RefusalKind::Malformed),
            claim(0xaa),
        ];
        let outcome = decide(&answers, &policy(2));
        assert!(
            matches!(outcome, QuorumOutcome::Dispute { .. }),
            "three different answers must not produce a winner: {outcome:?}"
        );
    }

    #[test]
    fn accept_most_common_still_refuses_when_nothing_was_valid() {
        // The permissive policy must not turn an outage into an answer.
        let mut permissive = policy(2);
        permissive.low_participants = LowParticipantsBehavior::AcceptMostCommon;
        permissive.dispute = DisputeBehavior::AcceptMostCommon;
        let outcome = decide(&[Answer::Infrastructure; 5], &permissive);
        assert!(
            matches!(outcome, QuorumOutcome::NoValidParticipants { .. }),
            "a preference promoted an infrastructure failure: {outcome:?}"
        );
    }

    #[test]
    fn grouping_is_deterministic_regardless_of_arrival_order() {
        // Without a stable order, "most common" would depend on which prover
        // answered first - not a fact about the world.
        let a = [claim(0xaa), claim(0xbb), claim(0xaa)];
        let b = [claim(0xbb), claim(0xaa), claim(0xaa)];
        let (ga, _) = group_answers(&a);
        let (gb, _) = group_answers(&b);
        assert_eq!(ga, gb, "grouping depends on arrival order");
        assert_eq!(ga.first().map(|g| g.count), Some(2));
    }

    #[test]
    fn an_unassailable_lead_does_not_wait() {
        let answers = [claim(0xaa), claim(0xaa), claim(0xaa)];
        // Two provers still out; the best a rival can reach is 2, the leader
        // has 3. Waiting cannot change the answer.
        assert!(lead_is_unassailable(&answers, &policy(3), 2));
        // Four still out: a rival could reach 4 and win, so waiting matters.
        assert!(!lead_is_unassailable(&answers, &policy(3), 4));
        // Exactly enough to TIE is not unassailable, because a tie is a dispute
        // and a dispute is not a win.
        assert!(
            !lead_is_unassailable(&answers, &policy(3), 3),
            "reaching the leader's count is a tie, and a tie is not a win"
        );
    }

    #[test]
    fn a_lead_below_the_threshold_is_never_unassailable() {
        let answers = [claim(0xaa)];
        assert!(!lead_is_unassailable(&answers, &policy(3), 0));
        assert!(lead_is_unassailable(&[claim(0xaa); 3], &policy(3), 0));
    }

    #[test]
    fn group_keys_are_stable_and_do_not_depend_on_debug_formatting() {
        let a = claim(0xab).group_key();
        let b = claim(0xab).group_key();
        assert_eq!(a, b);
        assert!(a.starts_with("claim:"));
        assert_ne!(a, claim(0xac).group_key());
        assert_eq!(
            Answer::ConsensusRefusal(RefusalKind::Crypto).group_key(),
            "refusal:crypto"
        );
        assert_eq!(Answer::Infrastructure.group_key(), "infrastructure");
    }
}
