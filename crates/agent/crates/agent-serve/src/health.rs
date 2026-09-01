//! Health counters - dependency-free and atomic.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::bridge::StartupRefusal;

/// The runtime counters.
#[derive(Debug, Default)]
pub struct Health {
    requests: AtomicU64,
    rejected_closed_loop: AtomicU64,
    hash_failures: AtomicU64,
    refused_startups: AtomicU64,
}

/// A snapshot, for an RPC or CLI summary. It follows the spirit of budlum's
/// `AgentMetricsSnapshot` but stays independent of the chain layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HealthSnapshot {
    pub requests: u64,
    pub rejected_closed_loop: u64,
    pub hash_failures: u64,
    /// Bridges that refused to start, over the life of this process.
    ///
    /// Counted because a supervisor that restarts a failing bridge turns a
    /// permanent misconfiguration into a quiet loop: each attempt refuses
    /// correctly, nothing is served, and the only evidence is in the logs
    /// nobody reads. A number an operator can poll makes the loop visible.
    pub refused_startups: u64,
}

impl Health {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_request(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Counted when a source outside the closed circuit is refused.
    pub fn record_rejected_closed_loop(&self) {
        self.rejected_closed_loop.fetch_add(1, Ordering::Relaxed);
    }

    /// Counted when hash verification fires fail-closed.
    pub fn record_hash_failure(&self) {
        self.hash_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Counted when a bridge refuses to start.
    ///
    /// Takes the refusal rather than being a bare increment, so the counter
    /// cannot be raised by a caller that has not actually been refused.
    pub fn record_refused_startup(&self, _why: &StartupRefusal) {
        self.refused_startups.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn snapshot(&self) -> HealthSnapshot {
        HealthSnapshot {
            requests: self.requests.load(Ordering::Relaxed),
            rejected_closed_loop: self.rejected_closed_loop.load(Ordering::Relaxed),
            hash_failures: self.hash_failures.load(Ordering::Relaxed),
            refused_startups: self.refused_startups.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate() {
        let h = Health::new();
        h.record_request();
        h.record_request();
        h.record_rejected_closed_loop();
        h.record_hash_failure();

        let s = h.snapshot();
        assert_eq!(s.requests, 2);
        assert_eq!(s.rejected_closed_loop, 1);
        assert_eq!(s.hash_failures, 1);
    }
}
