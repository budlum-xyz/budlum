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
const DEFERRED_VOTE_CAP: usize = 64;

/// A vote held for a round that is not open here yet.
#[derive(Clone, Debug)]
pub(crate) enum DeferredVote {
    Prevote(Prevote),
    Precommit(Precommit),
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

    /// Hold `vote` for `epoch`/`height`, dropping the oldest when full.
    pub(crate) fn push(&mut self, epoch: u64, height: u64, vote: DeferredVote) {
        if self.inner.len() >= DEFERRED_VOTE_CAP {
            self.inner.pop_front();
        }
        self.inner.push_back((epoch, height, vote));
    }

    /// Take every vote held for exactly this round, oldest first.
    ///
    /// Votes for any other round stay: they may still be replayed when their
    /// own round opens, and they are bounded by the cap.
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
}
