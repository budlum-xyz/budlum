//! Bounded Ethereum filter and subscription table (`Section 8.11.2`, `WP-28` item 3).
//!
//! Enforces three independent DoS bounds:
//! 1. Node-wide maximum active filters (`max_filters`),
//! 2. Per-peer filter quota (`max_filters_per_peer`),
//! 3. Idle expiration timeout (`filter_ttl_ms`), swept lazily before every allocation,
//! plus bounded block-range span (`max_log_block_range`) and result cap (`max_log_results`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::types::{parse_eth_address, parse_eth_word32, BlockSelector, EthLogEntry};

/// Default global filter cap across all connected peers.
pub const DEFAULT_MAX_FILTERS: usize = 1_024;
/// Default maximum concurrent filters owned by a single peer key.
pub const DEFAULT_MAX_FILTERS_PER_PEER: usize = 32;
/// Default idle TTL of a filter in milliseconds (`5` minutes).
pub const DEFAULT_FILTER_TTL_MS: u64 = 300_000;
/// Default maximum block span queried by `eth_getLogs` in one request.
pub const DEFAULT_MAX_LOG_BLOCK_RANGE: u64 = 2_000;
/// Default maximum log entries returned by one `eth_getLogs` / `eth_getFilterLogs` call.
pub const DEFAULT_MAX_LOG_RESULTS: usize = 10_000;
/// Default global active WebSocket subscription cap.
pub const DEFAULT_MAX_SUBSCRIPTIONS: usize = 512;

/// Single-value or array-of-values JSON-RPC filter field (`address` and topic entries).
///
/// Convenience: serde representation of flexible EIP-1474 log filter fields.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

/// Raw JSON-RPC filter object accepted by `eth_getLogs`, `eth_newFilter`, and `eth_subscribe("logs")`.
///
/// Convenience: serde input model for Ethereum log filters.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RawEthFilter {
    pub from_block: Option<String>,
    pub to_block: Option<String>,
    pub block_hash: Option<String>,
    pub address: Option<OneOrMany<String>>,
    pub topics: Option<Vec<Option<OneOrMany<String>>>>,
}

/// Validated, canonicalized log filter predicate.
///
/// Convenience: evaluated against [`EthLogEntry`] items in `eth_getLogs` and `logs` feeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedLogFilter {
    pub from_block: BlockSelector,
    pub to_block: BlockSelector,
    pub block_hash: Option<[u8; 32]>,
    pub addresses: Vec<[u8; 20]>,
    pub topics: [Option<Vec<[u8; 32]>>; 4],
}

impl ParsedLogFilter {
    /// Validate and parse a [`RawEthFilter`] (enforcing EIP-234 rule: `blockHash` cannot
    /// be combined with `fromBlock` or `toBlock`, and at most 4 topic positions).
    ///
    /// Convenience: shared by `eth_getLogs`, `eth_newFilter`, and `eth_subscribe`.
    pub fn from_raw(raw: &RawEthFilter) -> Result<Self, String> {
        if raw.block_hash.is_some() && (raw.from_block.is_some() || raw.to_block.is_some()) {
            return Err("EIP-234 forbids combining blockHash with fromBlock/toBlock".into());
        }
        let block_hash = match &raw.block_hash {
            Some(h) => Some(parse_eth_word32(h, false)?),
            None => None,
        };
        let from_block = BlockSelector::parse_opt(raw.from_block.as_deref())?;
        let to_block = BlockSelector::parse_opt(raw.to_block.as_deref())?;

        let mut addresses = Vec::new();
        match &raw.address {
            None => {}
            Some(OneOrMany::One(a)) => addresses.push(parse_eth_address(a)?),
            Some(OneOrMany::Many(list)) => {
                if list.len() > 128 {
                    return Err("filter address list exceeds 128 entries".into());
                }
                for a in list {
                    addresses.push(parse_eth_address(a)?);
                }
            }
        }

        let mut topics: [Option<Vec<[u8; 32]>>; 4] = [None, None, None, None];
        if let Some(raw_topics) = &raw.topics {
            if raw_topics.len() > 4 {
                return Err("EVM log filter cannot specify more than 4 topic positions".into());
            }
            for (idx, item) in raw_topics.iter().enumerate() {
                let parsed_pos = match item {
                    None => None,
                    Some(OneOrMany::One(t)) => Some(vec![parse_eth_word32(t, false)?]),
                    Some(OneOrMany::Many(alts)) => {
                        if alts.len() > 64 {
                            return Err("topic OR-list exceeds 64 alternatives".into());
                        }
                        let mut v = Vec::with_capacity(alts.len());
                        for t in alts {
                            v.push(parse_eth_word32(t, false)?);
                        }
                        Some(v)
                    }
                };
                if let Some(slot) = topics.get_mut(idx) {
                    *slot = parsed_pos;
                }
            }
        }

        Ok(Self {
            from_block,
            to_block,
            block_hash,
            addresses,
            topics,
        })
    }

    /// Test whether `log` satisfies the address and topic predicates of this filter.
    ///
    /// Convenience: used by historical log scans and live WebSocket `logs` feeds.
    #[must_use]
    pub fn matches_log(&self, log: &EthLogEntry) -> bool {
        if let Some(bh) = self.block_hash {
            if log.block_hash != bh {
                return false;
            }
        }
        if !self.addresses.is_empty() && !self.addresses.contains(&log.address) {
            return false;
        }
        for (pos, constraint) in self.topics.iter().enumerate() {
            if let Some(allowed) = constraint {
                if allowed.is_empty() {
                    continue;
                }
                let Some(actual) = log.topics.get(pos) else {
                    return false;
                };
                if !allowed.contains(actual) {
                    return false;
                }
            }
        }
        true
    }
}

/// Kind of installed stateful filter.
#[derive(Debug, Clone)]
pub enum EthFilterKind {
    Logs(ParsedLogFilter),
    Blocks,
}

#[derive(Debug, Clone)]
struct FilterRecord {
    owner_peer: String,
    kind: EthFilterKind,
    last_polled_block: u64,
    last_polled_ms: u64,
}

/// Refusal reasons from [`BoundedEthFilters`].
///
/// Convenience: mapped onto deterministic JSON-RPC `-32005` limit errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterError {
    GlobalCapReached(usize),
    PeerQuotaReached { peer: String, max: usize },
    NotFound(u128),
    InvalidFilter(String),
}

impl std::fmt::Display for FilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GlobalCapReached(max) => write!(f, "global filter limit ({max}) reached"),
            Self::PeerQuotaReached { peer, max } => {
                write!(f, "per-peer filter quota ({max}) reached for {peer}")
            }
            Self::NotFound(id) => write!(f, "filter 0x{id:x} not found or expired"),
            Self::InvalidFilter(msg) => f.write_str(msg),
        }
    }
}

/// Bounded node-local filter manager with lazy TTL eviction and per-peer quotas.
///
/// Convenience: embedded in `EthCompatState` and tested directly by `eth_filters_are_bounded`.
#[derive(Debug)]
pub struct BoundedEthFilters {
    max_filters: usize,
    max_per_peer: usize,
    ttl_ms: u64,
    next_id: u128,
    entries: BTreeMap<u128, FilterRecord>,
}

impl Default for BoundedEthFilters {
    fn default() -> Self {
        Self::new(
            DEFAULT_MAX_FILTERS,
            DEFAULT_MAX_FILTERS_PER_PEER,
            DEFAULT_FILTER_TTL_MS,
        )
    }
}

impl BoundedEthFilters {
    /// Construct a bounded filter registry with explicit limits.
    ///
    /// Convenience: configured from `[compat.ethereum]` in `NodeConfig`.
    #[must_use]
    pub fn new(max_filters: usize, max_per_peer: usize, ttl_ms: u64) -> Self {
        Self {
            max_filters: max_filters.max(1),
            max_per_peer: max_per_peer.max(1),
            ttl_ms: ttl_ms.max(1_000),
            next_id: 1,
            entries: BTreeMap::new(),
        }
    }

    /// Evict all filters idle for longer than `ttl_ms` at monotonic timestamp `now_ms`.
    ///
    /// Convenience: invoked before allocations and exposed for deterministic TTL tests.
    pub fn evict_expired(&mut self, now_ms: u64) -> usize {
        let ttl = self.ttl_ms;
        let before = self.entries.len();
        self.entries
            .retain(|_, rec| now_ms.saturating_sub(rec.last_polled_ms) <= ttl);
        before.saturating_sub(self.entries.len())
    }

    /// Number of currently active filters.
    ///
    /// Convenience: exposed for metrics and unit tests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no filters are active.
    ///
    /// Convenience: pairs with [`Self::len`].
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn check_capacity_without_mutating(&self, peer: &str, now_ms: u64) -> Result<(), FilterError> {
        let ttl = self.ttl_ms;
        let live_total = self
            .entries
            .values()
            .filter(|rec| now_ms.saturating_sub(rec.last_polled_ms) <= ttl)
            .count();
        if live_total >= self.max_filters {
            return Err(FilterError::GlobalCapReached(self.max_filters));
        }
        let live_peer = self
            .entries
            .values()
            .filter(|rec| {
                now_ms.saturating_sub(rec.last_polled_ms) <= ttl && rec.owner_peer == peer
            })
            .count();
        if live_peer >= self.max_per_peer {
            return Err(FilterError::PeerQuotaReached {
                peer: peer.to_string(),
                max: self.max_per_peer,
            });
        }
        Ok(())
    }

    /// Install a log filter owned by `peer` starting from `head_block`.
    ///
    /// Convenience: backs `eth_newFilter`.
    pub fn install_log_filter(
        &mut self,
        peer: &str,
        raw: &RawEthFilter,
        head_block: u64,
        now_ms: u64,
    ) -> Result<u128, FilterError> {
        let parsed = ParsedLogFilter::from_raw(raw).map_err(FilterError::InvalidFilter)?;
        self.check_capacity_without_mutating(peer, now_ms)?;
        self.evict_expired(now_ms);
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.entries.insert(
            id,
            FilterRecord {
                owner_peer: peer.to_string(),
                kind: EthFilterKind::Logs(parsed),
                last_polled_block: head_block,
                last_polled_ms: now_ms,
            },
        );
        Ok(id)
    }

    /// Install a block-header filter owned by `peer` starting from `head_block`.
    ///
    /// Convenience: backs `eth_newBlockFilter`.
    pub fn install_block_filter(
        &mut self,
        peer: &str,
        head_block: u64,
        now_ms: u64,
    ) -> Result<u128, FilterError> {
        self.check_capacity_without_mutating(peer, now_ms)?;
        self.evict_expired(now_ms);
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.entries.insert(
            id,
            FilterRecord {
                owner_peer: peer.to_string(),
                kind: EthFilterKind::Blocks,
                last_polled_block: head_block,
                last_polled_ms: now_ms,
            },
        );
        Ok(id)
    }

    /// Advance a filter's watermark to `new_head_block` and return `(kind, previous_watermark)`.
    ///
    /// Convenience: backs `eth_getFilterChanges`.
    pub fn poll_filter(
        &mut self,
        peer: &str,
        id: u128,
        new_head_block: u64,
        now_ms: u64,
    ) -> Result<(EthFilterKind, u64), FilterError> {
        let ttl = self.ttl_ms;
        let out = match self.entries.get(&id) {
            Some(rec)
                if rec.owner_peer == peer
                    && now_ms.saturating_sub(rec.last_polled_ms) <= ttl =>
            {
                (rec.kind.clone(), rec.last_polled_block)
            }
            _ => return Err(FilterError::NotFound(id)),
        };
        self.evict_expired(now_ms);
        if let Some(rec) = self.entries.get_mut(&id) {
            rec.last_polled_block = new_head_block;
            rec.last_polled_ms = now_ms;
        }
        Ok(out)
    }

    /// Read a log filter's predicate without advancing its block watermark (refreshes TTL).
    ///
    /// Convenience: backs `eth_getFilterLogs`.
    pub fn inspect_log_filter(
        &mut self,
        peer: &str,
        id: u128,
        now_ms: u64,
    ) -> Result<ParsedLogFilter, FilterError> {
        let ttl = self.ttl_ms;
        let found = match self.entries.get(&id) {
            Some(rec)
                if rec.owner_peer == peer
                    && now_ms.saturating_sub(rec.last_polled_ms) <= ttl =>
            {
                match &rec.kind {
                    EthFilterKind::Logs(f) => Some(f.clone()),
                    EthFilterKind::Blocks => None,
                }
            }
            _ => return Err(FilterError::NotFound(id)),
        };
        let Some(parsed) = found else {
            return Err(FilterError::InvalidFilter(
                "eth_getFilterLogs requires a log filter, not a block filter".into(),
            ));
        };
        self.evict_expired(now_ms);
        if let Some(rec) = self.entries.get_mut(&id) {
            rec.last_polled_ms = now_ms;
        }
        Ok(parsed)
    }

    /// Remove filter `id`, returning `true` if it existed and was still live.
    ///
    /// Convenience: backs `eth_uninstallFilter`.
    pub fn uninstall(&mut self, peer: &str, id: u128, now_ms: u64) -> bool {
        self.evict_expired(now_ms);
        if !self
            .entries
            .get(&id)
            .is_some_and(|record| record.owner_peer == peer)
        {
            return false;
        }
        self.entries.remove(&id).is_some()
    }
}
