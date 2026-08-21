//! Sağlık sayaçları (bağımlılıksız; atomik).

use std::sync::atomic::{AtomicU64, Ordering};

/// Çalışma zamanı sayaçları.
#[derive(Debug, Default)]
pub struct Health {
    requests: AtomicU64,
    rejected_closed_loop: AtomicU64,
    hash_failures: AtomicU64,
}

/// Anlık görüntü (RPC/CLI özeti için; budlum `LubotMetricsSnapshot`
/// ruhunda ama zincir katmanından bağımsız).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HealthSnapshot {
    pub requests: u64,
    pub rejected_closed_loop: u64,
    pub hash_failures: u64,
}

impl Health {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_request(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Kapalı-devre dışı kaynak reddedildiğinde say.
    pub fn record_rejected_closed_loop(&self) {
        self.rejected_closed_loop.fetch_add(1, Ordering::Relaxed);
    }

    /// Hash doğrulaması fail-closed tetiklendiğinde say.
    pub fn record_hash_failure(&self) {
        self.hash_failures.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn snapshot(&self) -> HealthSnapshot {
        HealthSnapshot {
            requests: self.requests.load(Ordering::Relaxed),
            rejected_closed_loop: self.rejected_closed_loop.load(Ordering::Relaxed),
            hash_failures: self.hash_failures.load(Ordering::Relaxed),
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
