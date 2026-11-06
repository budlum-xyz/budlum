//! The bounds a compatibility gateway puts on node-local state (section 8.11.2
//! rule 3: "filters and subscriptions: a bounded number of filters, a timeout,
//! and a per-peer quota").
//!
//! # Why a filter is a cost this node pays for a stranger
//!
//! A filter is a promise: "ask me again and I will tell you what changed since
//! you last asked". Keeping that promise costs memory on this node and work on
//! every new block, and the stranger who opened it paid nothing. Without an
//! expiry and a cap, one client opens filters in a loop until the node is
//! holding a set that no legitimate client would ever use - the same shape as
//! the unbounded subscription fan-out that [`crate::rpc::server`] already caps
//! at [`crate::rpc::server`]'s feed pool.
//!
//! # Three bounds, each doing one job
//!
//! * **A count per peer.** One client may not hold the whole budget, however
//!   many connections it opens. A peer is identified the way the existing
//!   per-IP limiter identifies one.
//! * **An expiry in blocks, not in wall time.** A filter expires when the chain
//!   has moved on, so every node reaches the same answer at the same height and
//!   the expiry is reproducible in a test rather than dependent on how fast a
//!   machine is. Section 8.11.2 says "timeout"; blocks are this chain's clock.
//! * **A total budget.** The per-peer cap multiplied by the number of peers is
//!   still unbounded, so the node holds a total as well, and refuses past it
//!   with the code Ethereum clients retry on.
//!
//! A filter that has expired is answered with `null` for its id on the next
//! `eth_getFilterChanges`, which is what a client already handles: it installs
//! a new one. Silently returning an empty list would tell the client that
//! nothing happened, which is a lie the client cannot detect.

use std::collections::BTreeMap;

/// Filters one peer may hold at once.
///
/// A wallet watching an application needs a handful. Sixteen is comfortably
/// above that, and low enough that the per-peer cap is never the reason a
/// legitimate client fails.
pub const MAX_FILTERS_PER_PEER: usize = 16;

/// Blocks a filter survives without being polled.
///
/// Ethereum's own guidance is that a filter dies after roughly five minutes of
/// inactivity. At this chain's target block time the number of blocks in five
/// minutes is the honest translation, and expressing it in blocks keeps the
/// expiry a function of chain state rather than of a wall clock.
pub const MAX_FILTER_TTL_BLOCKS: u64 = 300;

/// Filters the node holds in total, across every peer.
///
/// WIRING: `FilterBudget::install` compares against this; the operator status
/// page reports it beside the count it bounds.
///
/// The per-peer cap does not bound the sum, and the sum is the memory. 4096 is
/// the same order as the subscription feed pool, so the two node-local budgets
/// a client can grow are comparable.
pub const MAX_FILTERS_TOTAL: usize = 4096;

/// Why a filter install was refused.
///
/// WIRING: the gateway's `eth_newFilter` handler answers with [`Self::code`]
/// and [`Self::message`] when [`FilterBudget::install`] refuses; the handler
/// lands with the transport, and the refusal is the one shape a client already
/// retries on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterRefused {
    /// This peer already holds [`MAX_FILTERS_PER_PEER`].
    PerPeer,
    /// The node already holds [`MAX_FILTERS_TOTAL`].
    Node,
}

impl FilterRefused {
    /// The JSON-RPC error code (the Ethereum "limit exceeded" code a client
    /// already backs off on).
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::PerPeer | Self::Node => -32005,
        }
    }

    /// The message, saying which bound was reached.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::PerPeer => "filter limit reached for this peer; uninstall one first",
            Self::Node => "filter limit reached on this node; retry later",
        }
    }
}

/// One installed filter.
///
/// WIRING: `eth_getFilterChanges` reads [`Self::polled_at`] through
/// [`FilterBudget::poll`], which is the only place the expiry is decided; the
/// struct is public because the handler returns its fields beside the changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstalledFilter {
    /// The height the filter was installed at.
    pub installed_at: u64,
    /// The height it was last polled at.
    pub polled_at: u64,
}

impl InstalledFilter {
    /// Whether the filter has outlived its ttl at `height`.
    #[must_use]
    pub const fn is_expired(&self, height: u64) -> bool {
        height.saturating_sub(self.polled_at) > MAX_FILTER_TTL_BLOCKS
    }
}

/// The node's filter bookkeeping: one bounded map, keyed by filter id, with the
/// owning peer beside each entry.
///
/// The map is ordered by id rather than hashed, so a test, a log and an
/// operator's inspection all see the same order and the sweep below visits
/// entries deterministically. Ids are assigned by the caller, which owns the
/// nonce, and this type never invents one: an id that a client saw must be the
/// id the node stored.
#[derive(Debug, Clone, Default)]
pub struct FilterBudget {
    filters: BTreeMap<u64, (String, InstalledFilter)>,
    per_peer: BTreeMap<String, usize>,
}

impl FilterBudget {
    /// An empty budget.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many filters the node holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.filters.len()
    }

    /// Whether the node holds no filter.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }

    /// How many filters `peer` holds.
    #[must_use]
    pub fn held_by(&self, peer: &str) -> usize {
        self.per_peer.get(peer).copied().unwrap_or(0)
    }

    /// Install a filter for `peer` at `height`.
    ///
    /// # Errors
    ///
    /// [`FilterRefused`] when the peer's cap or the node's cap is reached, and
    /// the reason is part of the return value so the caller can say which.
    pub fn install(
        &mut self,
        id: u64,
        peer: &str,
        height: u64,
    ) -> Result<InstalledFilter, FilterRefused> {
        if self.held_by(peer) >= MAX_FILTERS_PER_PEER {
            return Err(FilterRefused::PerPeer);
        }
        if self.filters.len() >= MAX_FILTERS_TOTAL {
            return Err(FilterRefused::Node);
        }
        // Re-installing an id that is already held replaces it. An id collision
        // is the caller's bug, and replacing keeps the map's accounting right
        // instead of double-counting one filter.
        if let Some((old_peer, _)) = self.filters.remove(&id) {
            self.decrement(&old_peer);
        }
        let filter = InstalledFilter {
            installed_at: height,
            polled_at: height,
        };
        self.filters.insert(id, (peer.to_owned(), filter));
        *self.per_peer.entry(peer.to_owned()).or_insert(0) += 1;
        Ok(filter)
    }

    /// Poll a filter at `height`, refreshing its ttl.
    ///
    /// Returns `None` when the id is unknown or has expired, which the caller
    /// answers as "no such filter" so the client installs a new one. An expired
    /// filter is removed here rather than at the sweep, because a poll is the
    /// only moment the node learns that this client is still interested in it.
    pub fn poll(&mut self, id: u64, height: u64) -> Option<InstalledFilter> {
        let filter = *self.filters.get(&id).map(|(_, f)| f)?;
        if filter.is_expired(height) {
            self.uninstall(id);
            return None;
        }
        if let Some((_, f)) = self.filters.get_mut(&id) {
            f.polled_at = height;
            return Some(*f);
        }
        None
    }

    /// Remove a filter, and report whether it was there.
    pub fn uninstall(&mut self, id: u64) -> bool {
        match self.filters.remove(&id) {
            Some((peer, _)) => {
                self.decrement(&peer);
                true
            }
            None => false,
        }
    }

    /// Drop every expired filter at `height`, and return how many went.
    ///
    /// A node calls this on each new block. It is separate from [`Self::poll`]
    /// because a client that never polls again holds memory until the sweep
    /// finds it, and a client that never polls again is exactly the one the
    /// bound exists for.
    pub fn sweep(&mut self, height: u64) -> usize {
        let expired: Vec<u64> = self
            .filters
            .iter()
            .filter(|(_, (_, f))| f.is_expired(height))
            .map(|(id, _)| *id)
            .collect();
        for id in &expired {
            self.uninstall(*id);
        }
        expired.len()
    }

    fn decrement(&mut self, peer: &str) {
        if let Some(n) = self.per_peer.get_mut(peer) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.per_peer.remove(peer);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_cannot_hold_more_than_its_share() {
        let mut budget = FilterBudget::new();
        for id in 0..u64::try_from(MAX_FILTERS_PER_PEER).unwrap() {
            budget
                .install(id, "peer-a", 0)
                .expect("within the per-peer cap");
        }
        assert_eq!(budget.held_by("peer-a"), MAX_FILTERS_PER_PEER);
        assert_eq!(
            budget.install(999, "peer-a", 0),
            Err(FilterRefused::PerPeer)
        );
        // Another peer is unaffected by peer-a's cap: the bound is per peer.
        budget.install(1000, "peer-b", 0).expect("peer-b is empty");
        assert_eq!(budget.held_by("peer-b"), 1);
    }

    #[test]
    fn the_node_has_a_total_budget_and_says_which_bound_it_hit() {
        assert_eq!(FilterRefused::PerPeer.code(), -32005);
        assert_eq!(FilterRefused::Node.code(), -32005);
        assert_ne!(FilterRefused::PerPeer.message(), FilterRefused::Node.message());
        let mut budget = FilterBudget::new();
        // Fill through a single peer's cap only, then the node cap with many
        // peers: the total is reached without any one peer exceeding its own.
        let peers = MAX_FILTERS_TOTAL / MAX_FILTERS_PER_PEER + 1;
        let mut id = 0u64;
        'outer: for p in 0..peers {
            let peer = format!("peer-{p}");
            for _ in 0..MAX_FILTERS_PER_PEER {
                match budget.install(id, &peer, 0) {
                    Ok(_) => id += 1,
                    Err(e) => {
                        assert_eq!(e, FilterRefused::Node, "the node cap was hit first");
                        break 'outer;
                    }
                }
            }
        }
        assert_eq!(budget.len(), MAX_FILTERS_TOTAL);
    }

    #[test]
    fn a_filter_expires_by_chain_height_not_by_wall_clock() {
        let mut budget = FilterBudget::new();
        budget.install(7, "peer-a", 100).expect("install");
        assert!(budget.poll(7, 100 + MAX_FILTER_TTL_BLOCKS).is_some());
        // Polling refreshed the ttl: the boundary is inclusive of exactly the
        // ttl, so a filter polled at every block never expires.
        assert!(budget.poll(7, 100 + 2 * MAX_FILTER_TTL_BLOCKS).is_some());
        // Now let it go quiet.
        assert_eq!(budget.poll(7, 100 + 3 * MAX_FILTER_TTL_BLOCKS + 1), None);
        assert!(budget.is_empty(), "an expired filter is removed, not kept");
    }

    #[test]
    fn the_sweep_removes_what_no_one_polls_and_keeps_what_is_live() {
        let mut budget = FilterBudget::new();
        budget.install(1, "peer-a", 0).expect("install");
        budget.install(2, "peer-b", 0).expect("install");
        // Peer b polls at the halfway mark; peer a never comes back.
        let half = MAX_FILTER_TTL_BLOCKS / 2;
        assert!(budget.poll(2, half).is_some());
        let gone = budget.sweep(MAX_FILTER_TTL_BLOCKS + 1);
        assert_eq!(gone, 1, "only the silent filter expired");
        assert!(budget.poll(2, MAX_FILTER_TTL_BLOCKS + 1).is_some());
        assert!(budget.poll(1, MAX_FILTER_TTL_BLOCKS + 1).is_none());
        // The per-peer count follows the removal, or the cap becomes a leak.
        assert_eq!(budget.held_by("peer-a"), 0);
    }

    #[test]
    fn uninstalling_an_unknown_filter_is_reported_rather_than_ignored() {
        let mut budget = FilterBudget::new();
        assert!(!budget.uninstall(42));
        budget.install(42, "peer-a", 0).expect("install");
        assert!(budget.uninstall(42));
        assert!(!budget.uninstall(42), "the second uninstall is a no-op");
    }
}
