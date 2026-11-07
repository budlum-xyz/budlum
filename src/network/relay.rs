//! Circuit-relay reservation admission, AutoNAT reachability, and DCUtR upgrade tracking (WP-15).
//!
//! Directive Section 7.11 bounds every relay reservation by global capacity and per-subnet cap,
//! tracks AutoNAT reachability (`Unknown = 0`, `Public = 1`, `Private = 2`), and upgrades
//! relayed circuits to direct connections via DCUtR hole-punching.
//! Convenience: public NAT traversal state machines and relay admission book shared by node and metrics.

use crate::core::chain_config::RelayConfig;
use crate::network::peer_manager::SubnetKey;
use libp2p::PeerId;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

static METRIC_RELAY_RESERVATIONS: AtomicI64 = AtomicI64::new(0);
static METRIC_RELAY_CIRCUITS: AtomicI64 = AtomicI64::new(0);
static METRIC_NAT_STATUS: AtomicI64 = AtomicI64::new(0);
static METRIC_DCUTR_SUCCESS_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Snapshot of process-wide NAT and relay metrics folded into Prometheus scrapes.
#[must_use]
pub fn snapshot_metrics() -> (i64, i64, i64, u64) {
    (
        METRIC_RELAY_RESERVATIONS.load(Ordering::Relaxed),
        METRIC_RELAY_CIRCUITS.load(Ordering::Relaxed),
        METRIC_NAT_STATUS.load(Ordering::Relaxed),
        METRIC_DCUTR_SUCCESS_TOTAL.load(Ordering::Relaxed),
    )
}

/// AutoNAT reachability state reported in `budlum_nat_status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatReachability {
    /// Not enough dial-back probes have completed yet.
    Unknown = 0,
    /// Dial-back probes succeeded: node is publicly reachable.
    Public = 1,
    /// Dial-back probes failed: node is behind a private NAT and requests a relay reservation.
    Private = 2,
}

/// Deterministic AutoNAT dial-back confidence tracker (Section 7.11).
#[derive(Debug, Clone)]
pub struct AutonatTracker {
    successes: u32,
    failures: u32,
    confidence_threshold: u32,
    status: NatReachability,
}

impl AutonatTracker {
    /// Create a tracker requiring `confidence_threshold` consecutive verdicts to lock status.
    #[must_use]
    pub fn new(confidence_threshold: u32) -> Self {
        let threshold = confidence_threshold.max(1);
        METRIC_NAT_STATUS.store(NatReachability::Unknown as i64, Ordering::Relaxed);
        Self {
            successes: 0,
            failures: 0,
            confidence_threshold: threshold,
            status: NatReachability::Unknown,
        }
    }

    /// Record the outcome of one dial-back probe from an external peer.
    pub fn record_dial_back(&mut self, reachable: bool) -> NatReachability {
        if reachable {
            self.successes = self.successes.saturating_add(1);
            self.failures = 0;
            if self.successes >= self.confidence_threshold {
                self.status = NatReachability::Public;
            }
        } else {
            self.failures = self.failures.saturating_add(1);
            self.successes = 0;
            if self.failures >= self.confidence_threshold {
                self.status = NatReachability::Private;
            }
        }
        METRIC_NAT_STATUS.store(self.status as i64, Ordering::Relaxed);
        self.status
    }

    /// Current reachability verdict.
    #[must_use]
    pub const fn status(&self) -> NatReachability {
        self.status
    }

    /// Whether the node should acquire a relay reservation (`Private` NAT).
    #[must_use]
    pub const fn needs_relay_reservation(&self) -> bool {
        matches!(self.status, NatReachability::Private)
    }
}

/// Reason a relay reservation or circuit request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayDenyReason {
    /// Circuit relay service is disabled on this node.
    RelayDisabled,
    /// Global reservation table is full.
    MaxReservationsReached,
    /// Calling peer's `/24` or `/48` subnet already holds its maximum reservations.
    SubnetQuotaExceeded,
    /// Active relayed circuit table is full.
    MaxCircuitsReached,
    /// Destination peer holds no active reservation on this relay.
    TargetNotReserved,
    /// Relayed circuit byte ceiling exceeded.
    CircuitByteLimitExceeded,
}

/// Bounded circuit-relay reservation and active-circuit admission book (Section 7.11).
#[derive(Debug, Clone)]
pub struct RelayReservationBook {
    config: RelayConfig,
    reservations: BTreeMap<PeerId, SubnetKey>,
    subnet_counts: BTreeMap<SubnetKey, u32>,
    circuits: BTreeMap<(PeerId, PeerId), u64>,
    direct_peers: BTreeSet<(PeerId, PeerId)>,
}

impl RelayReservationBook {
    /// Construct a new book from `config`.
    #[must_use]
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            reservations: BTreeMap::new(),
            subnet_counts: BTreeMap::new(),
            circuits: BTreeMap::new(),
            direct_peers: BTreeSet::new(),
        }
    }

    fn sync_gauges(&self) {
        METRIC_RELAY_RESERVATIONS.store(
            i64::try_from(self.reservations.len()).unwrap_or(i64::MAX),
            Ordering::Relaxed,
        );
        METRIC_RELAY_CIRCUITS.store(
            i64::try_from(self.circuits.len()).unwrap_or(i64::MAX),
            Ordering::Relaxed,
        );
    }

    /// Request or refresh a relay slot reservation for `peer` arriving from `ip`.
    ///
    /// # Errors
    ///
    /// Returns [`RelayDenyReason`] if relay service is disabled or global/subnet caps bind.
    pub fn reserve(&mut self, peer: PeerId, ip: IpAddr) -> Result<(), RelayDenyReason> {
        if !self.config.enable_circuit_relay {
            return Err(RelayDenyReason::RelayDisabled);
        }
        let subnet = SubnetKey::from_ip(ip);
        if self.reservations.contains_key(&peer) {
            return Ok(());
        }
        if self.reservations.len() >= self.config.max_reservations as usize {
            return Err(RelayDenyReason::MaxReservationsReached);
        }
        let used = self.subnet_counts.get(&subnet).copied().unwrap_or(0);
        if used >= self.config.max_reservations_per_subnet {
            return Err(RelayDenyReason::SubnetQuotaExceeded);
        }
        self.reservations.insert(peer, subnet);
        self.subnet_counts.insert(subnet, used + 1);
        self.sync_gauges();
        Ok(())
    }

    /// Open a bounded relayed circuit from `src` to reserved `dst`.
    ///
    /// # Errors
    ///
    /// Returns [`RelayDenyReason`] if `dst` has no reservation or `max_circuits` is full.
    pub fn open_circuit(&mut self, src: PeerId, dst: PeerId) -> Result<(), RelayDenyReason> {
        if !self.config.enable_circuit_relay {
            return Err(RelayDenyReason::RelayDisabled);
        }
        if !self.reservations.contains_key(&dst) {
            return Err(RelayDenyReason::TargetNotReserved);
        }
        if !self.circuits.contains_key(&(src, dst))
            && self.circuits.len() >= self.config.max_circuits as usize
        {
            return Err(RelayDenyReason::MaxCircuitsReached);
        }
        self.circuits.entry((src, dst)).or_insert(0);
        self.sync_gauges();
        Ok(())
    }

    /// Charge `bytes` against an open relayed circuit `(src, dst)`.
    ///
    /// # Errors
    ///
    /// Returns [`RelayDenyReason::CircuitByteLimitExceeded`] and closes the circuit if over budget.
    pub fn charge_circuit_bytes(&mut self, src: PeerId, dst: PeerId, bytes: u64) -> Result<(), RelayDenyReason> {
        let Some(used) = self.circuits.get_mut(&(src, dst)) else {
            return Err(RelayDenyReason::TargetNotReserved);
        };
        let next = used.saturating_add(bytes);
        if next > self.config.max_circuit_bytes {
            self.circuits.remove(&(src, dst));
            self.sync_gauges();
            return Err(RelayDenyReason::CircuitByteLimitExceeded);
        }
        *used = next;
        Ok(())
    }

    /// Upgrade an active relayed circuit `(src, dst)` to a direct connection via DCUtR,
    /// releasing the relayed circuit slot and incrementing `budlum_dcutr_success_total`.
    pub fn upgrade_via_dcutr(&mut self, src: PeerId, dst: PeerId) -> bool {
        if self.circuits.remove(&(src, dst)).is_some() {
            let pair = if src <= dst { (src, dst) } else { (dst, src) };
            self.direct_peers.insert(pair);
            METRIC_DCUTR_SUCCESS_TOTAL.fetch_add(1, Ordering::Relaxed);
            self.sync_gauges();
            true
        } else {
            false
        }
    }

    /// Whether `a` and `b` completed a DCUtR upgrade to a direct connection.
    #[must_use]
    pub fn has_direct_connection(&self, a: PeerId, b: PeerId) -> bool {
        let pair = if a <= b { (a, b) } else { (b, a) };
        self.direct_peers.contains(&pair)
    }

    /// Active reservation count.
    #[must_use]
    pub fn reservation_count(&self) -> usize {
        self.reservations.len()
    }

    /// Active relayed circuit count.
    #[must_use]
    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn relay_reservation_limits_hold() {
        let cfg = RelayConfig {
            enable_circuit_relay: true,
            max_reservations: 3,
            max_reservations_per_subnet: 2,
            max_circuits: 2,
            max_circuit_bytes: 1024,
            max_circuit_duration_secs: 60,
        };
        let mut book = RelayReservationBook::new(cfg);
        let sub_a1 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let sub_a2 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
        let sub_a3 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3));
        let sub_b1 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 1, 0, 0, 0, 1));
        let sub_c1 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 2, 1, 0, 0, 0, 1));

        assert_eq!(book.reserve(PeerId::random(), sub_a1), Ok(()));
        assert_eq!(book.reserve(PeerId::random(), sub_a2), Ok(()));
        // Third peer in same /24 refused by per-subnet cap.
        assert_eq!(
            book.reserve(PeerId::random(), sub_a3),
            Err(RelayDenyReason::SubnetQuotaExceeded)
        );
        // Third global slot from distinct /48 succeeds; fourth hits global ceiling.
        assert_eq!(book.reserve(PeerId::random(), sub_b1), Ok(()));
        assert_eq!(
            book.reserve(PeerId::random(), sub_c1),
            Err(RelayDenyReason::MaxReservationsReached)
        );
        assert_eq!(book.reservation_count(), 3);
    }

    #[test]
    fn autonat_reports_private_behind_nat() {
        let mut tracker = AutonatTracker::new(3);
        assert_eq!(tracker.status(), NatReachability::Unknown);
        assert!(!tracker.needs_relay_reservation());

        assert_eq!(tracker.record_dial_back(false), NatReachability::Unknown);
        assert_eq!(tracker.record_dial_back(false), NatReachability::Unknown);
        assert_eq!(tracker.record_dial_back(false), NatReachability::Private);
        assert!(tracker.needs_relay_reservation());
    }

    #[test]
    fn dcutr_upgrade_in_simulated_nat() {
        let mut nat_a = AutonatTracker::new(2);
        let mut nat_b = AutonatTracker::new(2);
        for _ in 0..2 {
            nat_a.record_dial_back(false);
            nat_b.record_dial_back(false);
        }
        assert!(nat_a.needs_relay_reservation() && nat_b.needs_relay_reservation());

        let cfg = RelayConfig {
            enable_circuit_relay: true,
            ..RelayConfig::default()
        };
        let mut relay = RelayReservationBook::new(cfg);
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        relay
            .reserve(peer_b, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)))
            .expect("peer B reserves relay slot");
        relay
            .open_circuit(peer_a, peer_b)
            .expect("peer A dials peer B over relay");
        assert_eq!(relay.circuit_count(), 1);
        relay
            .charge_circuit_bytes(peer_a, peer_b, 512)
            .expect("DCUtR sync frame within relay circuit budget");

        assert!(relay.upgrade_via_dcutr(peer_a, peer_b));
        assert_eq!(relay.circuit_count(), 0);
        assert!(relay.has_direct_connection(peer_a, peer_b));
    }
}
