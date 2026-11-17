//! Votes that arrived before this node had a round to count them in.
//!
//! A finality vote is published once and can never be retransmitted: the
//! payload is signed over its own content, so a retry is byte-identical, and
//! gossipsub answers byte-identical with `Duplicate` and does not send it
//! again. That makes every delivery a single shot, and this node used to spend
//! that single shot on nothing whenever the vote landed before the aggregator
//! round it belongs to was open - the vote was refused with
//! `No active finality aggregator` (or, for a precommit, with `Cannot
//! precommit before prevote quorum`) and dropped. Neither side can recover:
//! the author cannot re-publish, and the receiver has nothing left to ask for.
//!
//! Measured on the devnet (`Devnet Multi-Node Smoke`, job `124634428303`): the
//! mesh is a star - every follower dials node1 and no two followers are
//! connected - so a vote reaches a follower only if node1 relays it. At
//! checkpoint height 8 the four prevotes reached node1 while the followers'
//! rounds were still closed; each follower ignored the vote it received, the
//! relayed copies never came back, no follower ever reached a prevote quorum,
//! no follower could precommit, node1 never reached a precommit quorum, and
//! finality stayed at 6 for the rest of the run. The same tree had passed the
//! same job an hour earlier, which is what a race looks like from the outside.
//!
//! So the vote is held instead of dropped. A bounded queue keeps the votes for
//! rounds this node has not opened yet, and the vote beat replays them the
//! moment its aggregator holds that epoch and height. A held vote is not
//! counted early: it still goes through the same `handle_prevote` /
//! `handle_precommit` checks, so nothing is admitted that the round would have
//! refused. The bound is what keeps a peer from making this node remember
//! votes forever - past the cap the oldest is dropped, and a vote that is
//! still relevant will be republished by nobody, which is exactly the failure
//! this module removes for the common case (one or two open rounds).

use std::collections::VecDeque;

use crate::chain::finality::{Precommit, Prevote};

/// Votes held for rounds this node has not opened, at most.
///
/// Two votes per validator per round and a handful of rounds in flight is
/// single digits; the cap is set far above that so a stall does not lose the
/// vote that would have ended it, and far below anything a peer can grow.
const DEFERRED_VOTE_CAP: usize = 128;

/// Maximum deferred slots one validator identity may occupy at once across
/// upcoming rounds (prevote + precommit across the 8-checkpoint early-vote horizon).
const MAX_DEFERRED_PER_VOTER: usize = 16;

/// A vote held for a round that is not open here yet.
#[derive(Clone, Debug)]
pub(crate) enum DeferredVote {
    Prevote(Prevote),
    Precommit(Precommit),
}

impl DeferredVote {
    fn voter_id(&self) -> crate::core::address::Address {
        match self {
            Self::Prevote(v) => v.voter_id,
            Self::Precommit(v) => v.voter_id,
        }
    }

    const fn is_precommit(&self) -> bool {
        matches!(self, Self::Precommit(_))
    }

    fn checkpoint_hash(&self) -> &str {
        match self {
            Self::Prevote(v) => &v.checkpoint_hash,
            Self::Precommit(v) => &v.checkpoint_hash,
        }
    }
}

/// Bounded, height-keyed store of votes that arrived too early.
#[derive(Debug, Default)]
pub(crate) struct DeferredVotes {
    inner: VecDeque<(u64, u64, DeferredVote)>,
}

impl DeferredVotes {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Hold `vote` for `epoch`/`height`, deduplicating per
    /// `(round, checkpoint_hash, voter, kind)`, bounding each voter's share,
    /// and dropping the oldest overall when full.
    pub(crate) fn push(&mut self, epoch: u64, height: u64, vote: DeferredVote) {
        let voter = vote.voter_id();
        let is_precommit = vote.is_precommit();
        let checkpoint_hash = vote.checkpoint_hash();
        if self.inner.iter().any(|(e, h, existing)| {
            *e == epoch
                && *h == height
                && existing.voter_id() == voter
                && existing.is_precommit() == is_precommit
                && existing.checkpoint_hash() == checkpoint_hash
        }) {
            return;
        }
        let voter_slots = self
            .inner
            .iter()
            .filter(|(_, _, existing)| existing.voter_id() == voter)
            .count();
        if voter_slots >= MAX_DEFERRED_PER_VOTER {
            if let Some(pos) = self
                .inner
                .iter()
                .position(|(_, _, existing)| existing.voter_id() == voter)
            {
                let _ = self.inner.remove(pos);
            }
        } else if self.inner.len() >= DEFERRED_VOTE_CAP {
            self.inner.pop_front();
        }
        self.inner.push_back((epoch, height, vote));
    }

    /// Drop every vote at or below a finalized height, since finalized rounds
    /// cannot reopen or reorg.
    pub(crate) fn prune_through(&mut self, finalized_height: u64) {
        if finalized_height == 0 {
            return;
        }
        self.inner.retain(|(_, h, _)| *h > finalized_height);
    }

    /// Take every vote held for the exact `(epoch, height, checkpoint_hash)`
    /// round, oldest first.
    ///
    /// Votes naming a different hash at the same height stay queued so a node
    /// temporarily holding a minority fork preserves canonical votes across its
    /// subsequent reorg.
    pub(crate) fn take_for_round(
        &mut self,
        epoch: u64,
        height: u64,
        checkpoint_hash: &str,
    ) -> Vec<DeferredVote> {
        let mut taken = Vec::new();
        let mut kept = VecDeque::with_capacity(self.inner.len());
        while let Some((vote_epoch, vote_height, vote)) = self.inner.pop_front() {
            if vote_epoch == epoch
                && vote_height == height
                && vote.checkpoint_hash() == checkpoint_hash
            {
                taken.push(vote);
            } else {
                kept.push_back((vote_epoch, vote_height, vote));
            }
        }
        self.inner = kept;
        taken
    }

    /// Take every vote held for `epoch` and `height` regardless of hash.
    #[cfg(test)]
    pub(crate) fn take_for(&mut self, epoch: u64, height: u64) -> Vec<DeferredVote> {
        let mut taken = Vec::new();
        let mut kept = VecDeque::with_capacity(self.inner.len());
        while let Some((vote_epoch, vote_height, vote)) = self.inner.pop_front() {
            if vote_epoch == epoch && vote_height == height {
                taken.push(vote);
            } else {
                kept.push_back((vote_epoch, vote_height, vote));
            }
        }
        self.inner = kept;
        taken
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::Address;

    fn prevote(height: u64, salt: u8) -> Prevote {
        Prevote {
            epoch: 0,
            checkpoint_height: height,
            checkpoint_hash: format!("{salt:02x}").repeat(32),
            chain_id: 45262,
            voter_id: Address::from([salt; 32]),
            sig_bls: Vec::new(),
            auth_sig: Vec::new(),
        }
    }

    fn precommit(height: u64, salt: u8) -> Precommit {
        Precommit {
            epoch: 0,
            checkpoint_height: height,
            checkpoint_hash: format!("{salt:02x}").repeat(32),
            chain_id: 45262,
            voter_id: Address::from([salt; 32]),
            sig_bls: Vec::new(),
            auth_sig: Vec::new(),
            pq_sig: Vec::new(),
        }
    }

    /// The defect: a vote that arrived while the round was closed used to be
    /// dropped, and the author cannot send it again.
    #[test]
    fn a_vote_that_arrived_early_is_handed_back_when_its_round_opens() {
        let mut held = DeferredVotes::new();
        held.push(0, 8, DeferredVote::Prevote(prevote(8, 1)));
        held.push(0, 8, DeferredVote::Prevote(prevote(8, 2)));
        held.push(0, 6, DeferredVote::Precommit(precommit(6, 3)));

        let for_height_eight = held.take_for(0, 8);
        assert_eq!(for_height_eight.len(), 2, "both early votes come back");
        assert!(
            held.take_for(0, 8).is_empty(),
            "a taken vote is not replayed twice"
        );
        assert_eq!(
            held.take_for(0, 6).len(),
            1,
            "another round's vote was still held"
        );
        assert!(
            held.take_for(0, 6).is_empty(),
            "and is not replayed twice either"
        );
    }

    #[test]
    fn another_epoch_is_a_different_round() {
        let mut held = DeferredVotes::new();
        held.push(1, 8, DeferredVote::Prevote(prevote(8, 1)));
        assert!(held.take_for(0, 8).is_empty(), "epoch 1 is not epoch 0");
        assert_eq!(held.take_for(1, 8).len(), 1);
    }

    #[test]
    fn the_store_is_bounded_and_drops_the_oldest() {
        let mut held = DeferredVotes::new();
        for index in 0..(DEFERRED_VOTE_CAP + 8) {
            let salt = u8::try_from(index % 251).unwrap_or(1);
            held.push(0, 1, DeferredVote::Prevote(prevote(1, salt)));
        }
        let kept = held.take_for(0, 1);
        assert_eq!(kept.len(), DEFERRED_VOTE_CAP);
        match kept.first() {
            Some(DeferredVote::Prevote(vote)) => assert_eq!(
                vote.voter_id,
                Address::from([8u8; 32]),
                "the oldest eight were dropped"
            ),
            other => panic!("unexpected first deferred vote: {other:?}"),
        }
    }

    #[test]
    fn one_voter_cannot_evict_other_validators_early_votes() {
        let mut held = DeferredVotes::new();
        held.push(0, 8, DeferredVote::Prevote(prevote(8, 1)));
        held.push(0, 8, DeferredVote::Prevote(prevote(8, 2)));
        for round in 10..100 {
            held.push(0, round, DeferredVote::Prevote(prevote(round, 99)));
            held.push(0, round, DeferredVote::Precommit(precommit(round, 99)));
        }
        let honest = held.take_for(0, 8);
        assert_eq!(
            honest.len(),
            2,
            "a single voter flooding rounds must only evict its own slots"
        );
    }

    #[test]
    fn canonical_hash_votes_survive_minority_fork_round_and_prune_on_finality() {
        let mut held = DeferredVotes::new();
        let canonical_hash = "ca".repeat(32);
        let fork_hash = "f0".repeat(32);
        let mut canonical_pv = prevote(50, 1);
        canonical_pv.epoch = 1;
        canonical_pv.checkpoint_hash = canonical_hash.clone();
        let mut canonical_pc = precommit(50, 2);
        canonical_pc.epoch = 1;
        canonical_pc.checkpoint_hash = canonical_hash.clone();
        let mut fork_pv = prevote(50, 3);
        fork_pv.epoch = 1;
        fork_pv.checkpoint_hash = fork_hash.clone();

        held.push(1, 50, DeferredVote::Prevote(canonical_pv));
        held.push(1, 50, DeferredVote::Precommit(canonical_pc));
        held.push(1, 50, DeferredVote::Prevote(fork_pv));

        // While the node holds the minority fork round, only the fork vote is
        // drained; canonical votes stay buffered for post-reorg replay.
        assert_eq!(held.take_for_round(1, 50, &fork_hash).len(), 1);
        let replayed = held.take_for_round(1, 50, &canonical_hash);
        assert_eq!(replayed.len(), 2);

        // Once height 50 finalizes, stale votes at or below 50 are pruned while
        // future rounds stay intact.
        let mut stale = prevote(50, 4);
        stale.epoch = 1;
        stale.checkpoint_hash = fork_hash;
        let mut future = prevote(55, 5);
        future.epoch = 1;
        held.push(1, 50, DeferredVote::Prevote(stale));
        held.push(1, 55, DeferredVote::Prevote(future.clone()));
        held.prune_through(50);
        assert!(held.take_for(1, 50).is_empty());
        assert_eq!(held.take_for_round(1, 55, &future.checkpoint_hash).len(), 1);
    }
}
