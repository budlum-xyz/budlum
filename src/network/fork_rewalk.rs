//! Bounds the locator re-walk that a fork signal triggers.
//!
//! A sync batch that does not join this chain is a fork signal: the sender may
//! simply be on a branch that won the slot, so the follower answers by walking
//! its locator again and asking someone for the blocks from the common
//! ancestor. That walk used to be issued inside the same event-loop iteration
//! as the refusal, with no spacing at all. On the devnet a follower that could
//! not name a common ancestor sat in a loop of roughly two hundred header
//! requests in thirty milliseconds, and the peer's own sync rate limiter
//! answered the flood by refusing to serve the follower at all
//! (`Rejected sync request from banned/rate-limited peer`, and then a
//! `ResponseOmission` on the sender's side). The follower's round stayed open
//! for 119 seconds and it fell forty blocks behind - the amplification, not
//! the fork, is what broke the follower.
//!
//! The gate keeps the first re-walk immediate and then widens the window
//! between attempts, so a fork heals at once while a peer that cannot help is
//! asked at most once per window. Nothing here is a permanent ban: a joined
//! batch clears the counter, and the next block announcement asks again.

/// First window between two locator walks, in seconds.
const FORK_REWALK_BASE_SECS: u64 = 1;

/// Widest window between two locator walks, in seconds.
const FORK_REWALK_MAX_SECS: u64 = 8;

/// Doublings before the window stops growing.
const FORK_REWALK_MAX_SHIFT: u32 = 3;

/// Spacing between consecutive locator re-walks after a fork signal.
#[derive(Debug, Default)]
pub(crate) struct ForkRewalkGate {
    /// Consecutive re-walks since the last joined batch.
    streak: u32,
    /// When the last re-walk was actually sent, in whole seconds since the
    /// epoch; `None` when nothing has been sent since the last progress.
    last_walk: Option<u64>,
}

impl ForkRewalkGate {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Seconds that must pass between the previous re-walk and the next one.
    pub(crate) fn backoff_secs(&self) -> u64 {
        let shift = self.streak.min(FORK_REWALK_MAX_SHIFT);
        (FORK_REWALK_BASE_SECS << shift).min(FORK_REWALK_MAX_SECS)
    }

    /// Whether a fork signal at `now` (seconds since the epoch) may walk the
    /// locator now.
    ///
    /// A refusal does not change the gate: the caller leaves the round closed
    /// and the next block announcement asks again, instead of retrying inside
    /// the same iteration.
    pub(crate) fn may_walk(&self, now: u64) -> bool {
        match self.last_walk {
            None => true,
            Some(last) => now.saturating_sub(last) >= self.backoff_secs(),
        }
    }

    /// Record a re-walk that was actually sent. The following ones wait longer.
    pub(crate) fn record_walk(&mut self, now: u64) {
        self.streak = self.streak.saturating_add(1);
        self.last_walk = Some(now);
    }

    /// A batch joined this chain: the sync peer is useful, so the next fork
    /// signal is answered immediately again.
    pub(crate) fn record_progress(&mut self) {
        self.streak = 0;
        self.last_walk = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_fork_signal_walks_at_once() {
        let gate = ForkRewalkGate::new();
        assert!(gate.may_walk(1_000));
    }

    /// The defect: a refusal used to re-request inside the same iteration, so a
    /// follower that could not name an ancestor re-walked hundreds of times per
    /// second until the peer rate-limited it. One walk per second at the start.
    #[test]
    fn a_second_fork_signal_in_the_same_second_waits() {
        let mut gate = ForkRewalkGate::new();
        assert!(gate.may_walk(1_000));
        gate.record_walk(1_000);
        assert!(!gate.may_walk(1_000), "the same second must not re-walk");
        assert!(!gate.may_walk(1_001), "the widened window is honoured");
        assert!(gate.may_walk(1_002), "then it may walk again");
        assert!(!gate.may_walk(0), "a clock that moved backwards waits too");
    }

    #[test]
    fn a_repeating_fork_widens_the_window_up_to_the_cap() {
        let mut gate = ForkRewalkGate::new();
        gate.record_walk(1_000);
        assert_eq!(gate.backoff_secs(), 2);
        gate.record_walk(1_002);
        assert_eq!(gate.backoff_secs(), 4);
        gate.record_walk(1_006);
        assert_eq!(gate.backoff_secs(), 8);
        gate.record_walk(1_014);
        assert_eq!(gate.backoff_secs(), FORK_REWALK_MAX_SECS);
        assert!(!gate.may_walk(1_021));
        assert!(gate.may_walk(1_022));
    }

    #[test]
    fn a_joined_batch_clears_the_backoff() {
        let mut gate = ForkRewalkGate::new();
        gate.record_walk(1_000);
        gate.record_walk(1_002);
        assert_eq!(gate.backoff_secs(), 4);
        gate.record_progress();
        assert_eq!(gate.backoff_secs(), FORK_REWALK_BASE_SECS);
        assert!(
            gate.may_walk(1_002),
            "progress makes the next walk immediate"
        );
    }
}
