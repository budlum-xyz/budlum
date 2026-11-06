//! Bounded filter table for the Ethereum compatibility gateway (WP-28, 2/N).
//!
//! Section 8.11.2 names the filter methods and the WP-28 card asks for a
//! bounded number of filters, an idle timeout and a per-peer quota. The table
//! below is that bound. It holds no chain state and no log data: it holds one
//! small record per admitted filter on this node.
//!
//! Log delivery still needs the EVM execution environment (WP-27). Until that
//! package merges, every read of a filter answers `-32004` and names the
//! Budlum door. An empty change list would be a plausible but false answer, so
//! no change list is invented here. The bound is real today: a client cannot
//! open an unbounded number of filters while it waits for that environment.
//!
//! The peer key comes from the connection extension the HTTP listener sets.
//! When the extension is absent, every caller shares one anonymous bucket.
//! That is fail-closed: the quota can only become tighter, never looser.
//!
//! The limits are TESTNET-DEFAULT values. Governance changes them after the
//! measurements of WP-35. Nothing here claims a measurement.

use std::collections::BTreeMap;
use std::net::SocketAddr;

/// The node-wide ceiling on admitted filters.
pub const MAX_FILTERS_TOTAL: usize = 128;

/// The ceiling for one peer. One wallet needs a handful of filters.
pub const MAX_FILTERS_PER_PEER: usize = 8;

/// A filter with no read for this many seconds is dropped.
pub const FILTER_IDLE_TTL_SECS: u64 = 300;

/// The ceiling on the serialized filter object one record holds.
pub const MAX_FILTER_SPEC_BYTES: usize = 16 * 1024;

/// The bucket used when a connection carries no socket address.
pub const ANONYMOUS_PEER: &str = "anonymous";

/// The two filter shapes Section 8.11.2 names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterKind {
    /// `eth_newFilter`: log criteria.
    Log,
    /// `eth_newBlockFilter`: new block heads.
    Block,
}

/// Why a filter call failed. Each variant carries one JSON-RPC code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterError {
    /// The filter object is larger than the record ceiling.
    SpecTooLarge,
    /// This peer already holds the allowed number of filters.
    PeerQuotaReached,
    /// The node holds the allowed number of filters.
    PoolFull,
    /// The id is not a hex quantity or names no live filter.
    UnknownFilter,
    /// The filter expired. Its slot is released by this call.
    Expired,
    /// Another peer owns this filter id.
    ForeignFilter,
    /// The id counter cannot advance.
    IdOverflow,
    /// Log data needs the execution environment of WP-27.
    ExecutionEnvironmentUnavailable,
}

impl FilterError {
    /// The JSON-RPC code for this failure.
    pub fn code(self) -> i32 {
        match self {
            Self::SpecTooLarge | Self::UnknownFilter | Self::Expired => -32602,
            Self::ForeignFilter => -32603,
            Self::ExecutionEnvironmentUnavailable => -32004,
            Self::PeerQuotaReached | Self::PoolFull | Self::IdOverflow => -32005,
        }
    }

    /// One line for a client log. Short sentences, one meaning per line.
    pub fn message(self) -> &'static str {
        match self {
            Self::SpecTooLarge => "filter object exceeds the record limit",
            Self::PeerQuotaReached => "per-peer filter quota reached; uninstall a filter",
            Self::PoolFull => "node filter limit reached; retry later",
            Self::UnknownFilter => "unknown filter id",
            Self::Expired => "filter expired; its slot is now free",
            Self::ForeignFilter => "filter id belongs to another peer",
            Self::IdOverflow => "filter id counter is exhausted",
            Self::ExecutionEnvironmentUnavailable => {
                "log data needs the EVM execution environment (WP-27)"
            }
        }
    }

    /// A stable machine-readable reason for the error data.
    pub fn reason(self) -> &'static str {
        match self {
            Self::SpecTooLarge => "spec_too_large",
            Self::PeerQuotaReached => "peer_quota_reached",
            Self::PoolFull => "pool_full",
            Self::UnknownFilter => "unknown_filter",
            Self::Expired => "expired",
            Self::ForeignFilter => "foreign_filter",
            Self::IdOverflow => "id_overflow",
            Self::ExecutionEnvironmentUnavailable => "no_execution_environment",
        }
    }

    /// The Budlum door that answers the same question, when one exists.
    pub fn door(self) -> Option<&'static str> {
        match self {
            Self::ExecutionEnvironmentUnavailable => Some("bud_subscribe"),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct FilterEntry {
    peer: String,
    kind: FilterKind,
    spec: String,
    touched_at: u64,
}

/// A bounded, expiring, per-peer filter table.
#[derive(Debug, Default)]
pub struct FilterPool {
    next_id: u64,
    entries: BTreeMap<u64, FilterEntry>,
}

impl FilterPool {
    /// An empty pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of live records.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the pool holds no records.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The number of live records owned by one peer.
    pub fn peer_len(&self, peer: &str) -> usize {
        self.entries.values().filter(|entry| entry.peer == peer).count()
    }

    /// Drop records that saw no read inside the idle timeout. Returns the
    /// number dropped, so a caller can see the sweep worked.
    pub fn expire(&mut self, now: u64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| now.saturating_sub(entry.touched_at) < FILTER_IDLE_TTL_SECS);
        before - self.entries.len()
    }

    /// Admit one filter and return its hex quantity id.
    ///
    /// A call sweeps first, so an expired record never holds a slot against a
    /// new one. All three bounds are checked before any record is written.
    pub fn create(
        &mut self,
        peer: &str,
        kind: FilterKind,
        spec: &str,
        now: u64,
    ) -> Result<String, FilterError> {
        self.expire(now);
        if spec.len() > MAX_FILTER_SPEC_BYTES {
            return Err(FilterError::SpecTooLarge);
        }
        if self.peer_len(peer) >= MAX_FILTERS_PER_PEER {
            return Err(FilterError::PeerQuotaReached);
        }
        if self.entries.len() >= MAX_FILTERS_TOTAL {
            return Err(FilterError::PoolFull);
        }
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or(FilterError::IdOverflow)?;
        self.entries.insert(
            id,
            FilterEntry {
                peer: peer.to_string(),
                kind,
                spec: spec.to_string(),
                touched_at: now,
            },
        );
        Ok(format!("0x{id:x}"))
    }

    /// Resolve a filter id for one peer, or name the reason it cannot be used.
    fn resolve(&mut self, peer: &str, id: &str, now: u64) -> Result<u64, FilterError> {
        let key = id
            .strip_prefix("0x")
            .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            .ok_or(FilterError::UnknownFilter)?;
        let Some(entry) = self.entries.get(&key) else {
            return Err(FilterError::UnknownFilter);
        };
        if now.saturating_sub(entry.touched_at) >= FILTER_IDLE_TTL_SECS {
            self.entries.remove(&key);
            return Err(FilterError::Expired);
        }
        if entry.peer != peer {
            return Err(FilterError::ForeignFilter);
        }
        Ok(key)
    }

    /// Read the changes of a filter.
    ///
    /// This validates ownership and freshness, then refuses. No log data is
    /// invented before WP-27. The slot stays bounded while the client waits.
    pub fn changes(
        &mut self,
        peer: &str,
        id: &str,
        now: u64,
    ) -> Result<Vec<serde_json::Value>, FilterError> {
        let key = self.resolve(peer, id, now)?;
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.touched_at = now;
        }
        Err(FilterError::ExecutionEnvironmentUnavailable)
    }

    /// Drop one filter. Returns whether a live record was removed.
    pub fn uninstall(&mut self, peer: &str, id: &str, now: u64) -> Result<bool, FilterError> {
        let key = self.resolve(peer, id, now)?;
        Ok(self.entries.remove(&key).is_some())
    }

    /// The kind of a live filter. Used by tests, not by the handlers.
    #[cfg(test)]
    fn kind(&self, id: &str) -> Option<FilterKind> {
        let key = id
            .strip_prefix("0x")
            .and_then(|hex| u64::from_str_radix(hex, 16).ok())?;
        self.entries.get(&key).map(|entry| entry.kind)
    }
}

/// Whole seconds since the Unix epoch. Zero when the clock is unavailable, so
/// the pool still expires records instead of holding them forever.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|span| span.as_secs())
        .unwrap_or(0)
}

/// The quota key for one connection. The IP is enough: a new port on the same
/// host must not create a new quota bucket.
pub fn peer_of(ext: &jsonrpsee::Extensions) -> String {
    ext.get::<SocketAddr>()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| ANONYMOUS_PEER.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn many_peers(count: usize, now: u64) -> (FilterPool, Vec<String>) {
        let mut pool = FilterPool::new();
        let mut ids = Vec::new();
        let mut peer_index = 0usize;
        while ids.len() < count {
            let peer = format!("peer-{peer_index}");
            peer_index += 1;
            for _ in 0..MAX_FILTERS_PER_PEER {
                if ids.len() == count {
                    break;
                }
                let id = pool
                    .create(&peer, FilterKind::Log, "{}", now)
                    .expect("a slot below the ceiling is free");
                ids.push(id);
            }
        }
        (pool, ids)
    }

    #[test]
    fn eth_filters_are_bounded() {
        let (mut pool, ids) = many_peers(MAX_FILTERS_TOTAL, 1_000);
        assert_eq!(pool.len(), MAX_FILTERS_TOTAL);
        assert_eq!(ids.len(), MAX_FILTERS_TOTAL);
        assert_eq!(
            pool.create("another-peer", FilterKind::Log, "{}", 1_000),
            Err(FilterError::PoolFull)
        );
        assert_eq!(pool.len(), MAX_FILTERS_TOTAL);
    }

    #[test]
    fn eth_filter_per_peer_quota_is_enforced() {
        let mut pool = FilterPool::new();
        for _ in 0..MAX_FILTERS_PER_PEER {
            pool.create("one-peer", FilterKind::Log, "{}", 10)
                .expect("the quota is not reached yet");
        }
        assert_eq!(pool.peer_len("one-peer"), MAX_FILTERS_PER_PEER);
        assert_eq!(
            pool.create("one-peer", FilterKind::Block, "{}", 10),
            Err(FilterError::PeerQuotaReached)
        );
        assert_eq!(
            pool.create("other-peer", FilterKind::Block, "{}", 10),
            Ok("0x8".to_string())
        );
    }

    #[test]
    fn eth_filter_ttl_expires_and_releases_the_slot() {
        let mut pool = FilterPool::new();
        let id = pool
            .create("peer", FilterKind::Log, "{}", 100)
            .expect("an empty pool has a slot");
        let late = 100 + FILTER_IDLE_TTL_SECS;
        assert_eq!(
            pool.changes("peer", &id, late),
            Err(FilterError::Expired)
        );
        assert!(pool.is_empty(), "an expired record must not hold a slot");
        assert_eq!(pool.expire(late + 1), 0);
    }

    #[test]
    fn eth_filter_is_bound_to_its_peer() {
        let mut pool = FilterPool::new();
        let id = pool
            .create("owner", FilterKind::Log, "{}", 5)
            .expect("an empty pool has a slot");
        assert_eq!(pool.uninstall("other", &id, 5), Err(FilterError::ForeignFilter));
        assert_eq!(pool.len(), 1, "a refused uninstall keeps the record");
        assert_eq!(pool.kind(&id), Some(FilterKind::Log));
    }

    #[test]
    fn eth_uninstall_releases_the_slot() {
        let mut pool = FilterPool::new();
        let id = pool
            .create("owner", FilterKind::Block, "{}", 5)
            .expect("an empty pool has a slot");
        assert_eq!(pool.uninstall("owner", &id, 6), Ok(true));
        assert!(pool.is_empty());
        assert_eq!(pool.uninstall("owner", &id, 6), Err(FilterError::UnknownFilter));
        assert_eq!(
            pool.create("owner", FilterKind::Block, "{}", 6),
            Ok("0x1".to_string()),
            "ids never repeat"
        );
    }

    #[test]
    fn eth_oversize_filter_is_refused() {
        let mut pool = FilterPool::new();
        let big = "a".repeat(MAX_FILTER_SPEC_BYTES + 1);
        assert_eq!(
            pool.create("owner", FilterKind::Log, &big, 1),
            Err(FilterError::SpecTooLarge)
        );
        assert!(pool.is_empty());
    }

    #[test]
    fn eth_filter_changes_do_not_invent_evm_logs() {
        let mut pool = FilterPool::new();
        let id = pool
            .create("owner", FilterKind::Log, "{}", 1)
            .expect("an empty pool has a slot");
        assert_eq!(
            pool.changes("owner", &id, 2),
            Err(FilterError::ExecutionEnvironmentUnavailable)
        );
        assert_eq!(pool.changes("owner", "0xdead", 2), Err(FilterError::UnknownFilter));
        assert_eq!(pool.len(), 1, "a refusal does not drop the filter");
    }

    #[test]
    fn eth_filter_ids_are_unique_and_hex() {
        let mut pool = FilterPool::new();
        let first = pool
            .create("owner", FilterKind::Log, "{}", 1)
            .expect("an empty pool has a slot");
        let second = pool
            .create("owner", FilterKind::Block, "{}", 1)
            .expect("the quota allows a second filter");
        assert_ne!(first, second);
        assert!(first.starts_with("0x") && second.starts_with("0x"));
        assert_eq!(pool.kind(&second), Some(FilterKind::Block));
    }
}
