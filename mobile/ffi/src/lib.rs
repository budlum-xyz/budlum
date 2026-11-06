//! UniFFI bindings of the Budlum mobile validator core (WP-11 job 2).
//!
//! One object, [`MobileNode`], wraps [`MobileCore`] behind a mutex so the
//! Android service and the iOS background task can share it across threads.
//! Every value crosses the boundary as a UniFFI record or enum; byte strings
//! travel as `Vec<u8>` and are length-checked here, never trusted.
//!
//! Events reach the host through [`NodeListener`], which Kotlin and Swift
//! implement. A listener is always called after the core lock is released,
//! so it may call back into the node.
//!
//! Duties the core produces (share releases, resume requests) wait in an
//! outbox until the network layer of the core submits them on the duty lane
//! (WP-11 job 4). [`MobileNode::pending_duties`] reports how many wait; none
//! is dropped.
//!
//! The only `unsafe` in this crate is the FFI scaffolding that
//! `uniffi::setup_scaffolding!` generates. S-5 binds the node core to
//! `#![forbid(unsafe_code)]`; the mobile core keeps it, this crate cannot.

uniffi::setup_scaffolding!();

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use budlum_mobile_core::{
    Connection, CoreError, CoreStatus, DutyTx, LastAudit, MobileCore, NetworkPolicy, Policy,
    PowerPolicy, RelayOffer, ValidatorClass, FREE_SPACE_FLOOR_BYTES, QUOTA_DEFAULT_BYTES,
    QUOTA_MAX_BYTES, QUOTA_MIN_BYTES,
};
use budlum_types::class::AuditWindow;

/// The class a phone registers as (section 7.2). A phone is never `Full`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PhoneClass {
    /// Android: 24 h audit window, suspended after 72 h without a passed audit.
    Mobile,
    /// iOS: 48 h audit window, suspended after 7 days, quota at most 8 GiB.
    MobileOpportunistic,
}

impl PhoneClass {
    const fn class(self) -> ValidatorClass {
        match self {
            Self::Mobile => ValidatorClass::Mobile,
            Self::MobileOpportunistic => ValidatorClass::MobileOpportunistic,
        }
    }
}

/// How long a validator has to answer a custody audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AuditSpan {
    /// A number of epochs (the Full class).
    Epochs {
        /// Epochs.
        epochs: u64,
    },
    /// A number of hours (both phone classes).
    Hours {
        /// Hours.
        hours: u64,
    },
}

/// The consensus parameters of a phone class and the core's storage limits,
/// read from `budlum-types` and the core so the apps keep no copy of the
/// section 7.2 table (K-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct ClassParameters {
    /// Epochs per presence window.
    pub presence_window_epochs: u64,
    /// Hours unseen before suspension. Suspension is not a slash (V-4).
    pub suspension_hours: u64,
    /// The custody audit answer window.
    pub audit_window: AuditSpan,
    /// The class quota ceiling, or none when only the user range applies.
    pub max_custody_quota_bytes: Option<u64>,
    /// The smallest quota a user may choose.
    pub quota_min_bytes: u64,
    /// The largest quota a user may choose.
    pub quota_max_bytes: u64,
    /// The quota of a new node.
    pub quota_default_bytes: u64,
    /// Free space the core keeps on the device by releasing shares.
    pub free_space_floor_bytes: u64,
}

/// The parameters of `class`.
#[uniffi::export]
pub fn class_parameters(class: PhoneClass) -> ClassParameters {
    let class = class.class();
    ClassParameters {
        presence_window_epochs: class.presence_window_epochs(),
        suspension_hours: class.suspension_hours(),
        audit_window: match class.audit_window() {
            AuditWindow::Epochs(epochs) => AuditSpan::Epochs { epochs },
            AuditWindow::Hours(hours) => AuditSpan::Hours { hours },
        },
        max_custody_quota_bytes: class.max_custody_quota_bytes(),
        quota_min_bytes: QUOTA_MIN_BYTES,
        quota_max_bytes: QUOTA_MAX_BYTES,
        quota_default_bytes: QUOTA_DEFAULT_BYTES,
        free_space_floor_bytes: FREE_SPACE_FLOOR_BYTES,
    }
}

/// A relay the phone reaches the network through (section 7.9.3).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Relay {
    /// libp2p multiaddress of the relay.
    pub multiaddr: String,
    /// Offered relay capacity.
    pub capacity_kbps: u64,
}

impl From<Relay> for RelayOffer {
    fn from(relay: Relay) -> Self {
        Self {
            multiaddr: relay.multiaddr,
            capacity_kbps: relay.capacity_kbps,
        }
    }
}

impl From<RelayOffer> for Relay {
    fn from(offer: RelayOffer) -> Self {
        Self {
            multiaddr: offer.multiaddr,
            capacity_kbps: offer.capacity_kbps,
        }
    }
}

/// Which networks the node may use (section 7.9.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum NetworkUse {
    /// Wi-Fi or another unmetered network only. The default.
    UnmeteredOnly,
    /// Metered networks too, up to a daily cap.
    Metered {
        /// Daily cap on metered traffic.
        daily_cap_mb: u32,
    },
}

/// When the node may run (section 7.9.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PowerUse {
    /// While charging, or on battery above 50 percent. The default.
    ChargingOrBatteryAbove50,
    /// Only while charging.
    ChargingOnly,
}

/// The user's policy. `thermal_pause` cannot be turned off; the core
/// refuses a policy that tries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct NodePolicy {
    /// Network use.
    pub network: NetworkUse,
    /// Power use.
    pub power: PowerUse,
    /// Pause when the device is hot. Always true.
    pub thermal_pause: bool,
    /// Custody quota: 1 GiB to 64 GiB, at most 8 GiB for an iOS validator.
    pub quota_bytes: u64,
    /// Serve stored symbols to readers.
    pub serve_symbols: bool,
}

impl From<NodePolicy> for Policy {
    fn from(policy: NodePolicy) -> Self {
        Self {
            network: match policy.network {
                NetworkUse::UnmeteredOnly => NetworkPolicy::UnmeteredOnly,
                NetworkUse::Metered { daily_cap_mb } => NetworkPolicy::Metered { daily_cap_mb },
            },
            power: match policy.power {
                PowerUse::ChargingOrBatteryAbove50 => PowerPolicy::ChargingOrBatteryAbove50,
                PowerUse::ChargingOnly => PowerPolicy::ChargingOnly,
            },
            thermal_pause: policy.thermal_pause,
            quota_bytes: policy.quota_bytes,
            serve_symbols: policy.serve_symbols,
        }
    }
}

impl From<Policy> for NodePolicy {
    fn from(policy: Policy) -> Self {
        Self {
            network: match policy.network {
                NetworkPolicy::UnmeteredOnly => NetworkUse::UnmeteredOnly,
                NetworkPolicy::Metered { daily_cap_mb } => NetworkUse::Metered { daily_cap_mb },
            },
            power: match policy.power {
                PowerPolicy::ChargingOrBatteryAbove50 => PowerUse::ChargingOrBatteryAbove50,
                PowerPolicy::ChargingOnly => PowerUse::ChargingOnly,
            },
            thermal_pause: policy.thermal_pause,
            quota_bytes: policy.quota_bytes,
            serve_symbols: policy.serve_symbols,
        }
    }
}

/// The last custody audit outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AuditState {
    /// No audit answered yet.
    Unaudited,
    /// The last audit was answered with a valid proof.
    Passed,
    /// The last audit was missed.
    Missed,
}

impl From<LastAudit> for AuditState {
    fn from(audit: LastAudit) -> Self {
        match audit {
            LastAudit::None => Self::Unaudited,
            LastAudit::Passed => Self::Passed,
            LastAudit::Missed => Self::Missed,
        }
    }
}

/// The panel snapshot (section 7.9.5).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct NodeStatus {
    /// Whether the duty loop runs.
    pub running: bool,
    /// Bytes of shares stored.
    pub stored_bytes: u64,
    /// The current quota.
    pub quota_bytes: u64,
    /// The last audit outcome.
    pub last_audit: AuditState,
    /// The relay in use, or none when the node has no connection.
    pub relay: Option<Relay>,
    /// Duties waiting for the network.
    pub pending_duties: u32,
}

/// Why shares were released. Neither is a penalty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ReleaseReason {
    /// Free space fell below the 2 GB floor.
    FreeSpaceFloor,
    /// The user lowered the quota below the bytes stored.
    QuotaLowered,
    /// The user left.
    Leave,
}

/// What the node tells the host.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum NodeEvent {
    /// The duty loop started.
    Started,
    /// The duty loop stopped. Shares stay until the user leaves.
    Stopped,
    /// A new policy is in force.
    PolicyChanged {
        /// The policy as the core applied it.
        policy: NodePolicy,
    },
    /// Shares were released and their release waits in the outbox.
    SharesReleased {
        /// How many shares.
        count: u32,
        /// Why.
        reason: ReleaseReason,
    },
    /// The relay dropped and the node moved to the next one.
    RelaySwitched {
        /// The relay now in use, or none when no relay is left.
        relay: Option<Relay>,
    },
}

/// Implemented by the host (Kotlin, Swift) to receive [`NodeEvent`]s.
#[uniffi::export(foreign)]
pub trait NodeListener: Send + Sync {
    /// Called once per event, outside the core lock.
    fn on_event(&self, event: NodeEvent);
}

/// A refusal from the core, with its stable machine code.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
pub enum MobileError {
    /// The core refused the call; nothing changed.
    Refused {
        /// Stable machine code, for example `mobile_quota_above_class_cap`.
        code: String,
        /// Human-readable reason.
        message: String,
    },
}

impl MobileError {
    fn refused(code: &str, message: &str) -> Self {
        Self::Refused {
            code: code.to_owned(),
            message: message.to_owned(),
        }
    }
}

impl fmt::Display for MobileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused { code, message } => write!(f, "{code}: {message}"),
        }
    }
}

impl std::error::Error for MobileError {}

impl From<CoreError> for MobileError {
    fn from(error: CoreError) -> Self {
        Self::Refused {
            code: error.code.to_owned(),
            message: error.message,
        }
    }
}

/// A poisoned lock still holds consistent data here: every core method
/// either completes or refuses before mutating, so the guard is recovered
/// rather than turned into a panic across the FFI boundary.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn saturating_count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn released_shares(duties: &[DutyTx]) -> usize {
    duties
        .iter()
        .map(|duty| match duty {
            DutyTx::ReleaseShares { shares } => shares.len(),
            _ => 0,
        })
        .sum()
}

/// The mobile validator, as the apps see it.
#[derive(uniffi::Object)]
pub struct MobileNode {
    core: Mutex<MobileCore>,
    outbox: Mutex<Vec<DutyTx>>,
    listener: Mutex<Option<Arc<dyn NodeListener>>>,
}

impl MobileNode {
    fn emit(&self, event: NodeEvent) {
        let listener = lock(&self.listener).clone();
        if let Some(listener) = listener {
            listener.on_event(event);
        }
    }

    /// Queue duties for the network and return the shares they release. A
    /// release of no shares carries nothing and is not queued.
    fn queue(&self, duties: Vec<DutyTx>) -> usize {
        let duties: Vec<DutyTx> = duties
            .into_iter()
            .filter(|duty| !matches!(duty, DutyTx::ReleaseShares { shares } if shares.is_empty()))
            .collect();
        let released = released_shares(&duties);
        lock(&self.outbox).extend(duties);
        released
    }
}

#[uniffi::export]
impl MobileNode {
    /// A stopped node with the default policy.
    ///
    /// `owner` is the 32-byte stake owner address held by the wallet;
    /// `available_bytes` is the free space the host measured.
    ///
    /// # Errors
    ///
    /// [`MobileError::Refused`] with `mobile_owner_length` when `owner` is not
    /// 32 bytes.
    #[uniffi::constructor]
    pub fn new(
        owner: Vec<u8>,
        class: PhoneClass,
        relays: Vec<Relay>,
        available_bytes: u64,
    ) -> Result<Arc<Self>, MobileError> {
        let owner: [u8; 32] = owner.try_into().map_err(|_| {
            MobileError::refused("mobile_owner_length", "the owner address is 32 bytes")
        })?;
        let relays = relays.into_iter().map(RelayOffer::from).collect();
        let core = MobileCore::new(owner, class.class(), relays, available_bytes);
        Ok(Arc::new(Self {
            core: Mutex::new(core),
            outbox: Mutex::new(Vec::new()),
            listener: Mutex::new(None),
        }))
    }

    /// Register the host's event listener, replacing any earlier one.
    pub fn set_listener(&self, listener: Arc<dyn NodeListener>) {
        *lock(&self.listener) = Some(listener);
    }

    /// Start the duty loop.
    pub fn start(&self) {
        lock(&self.core).start();
        self.emit(NodeEvent::Started);
    }

    /// Stop the duty loop. Shares stay on the device.
    pub fn stop(&self) {
        lock(&self.core).stop();
        self.emit(NodeEvent::Stopped);
    }

    /// The panel snapshot.
    pub fn status(&self) -> NodeStatus {
        let CoreStatus {
            running,
            stored_bytes,
            quota_bytes,
            last_audit,
            connection,
        } = lock(&self.core).status();
        let relay = match connection {
            Connection::Down => None,
            Connection::Relay(offer) => Some(Relay::from(offer)),
        };
        NodeStatus {
            running,
            stored_bytes,
            quota_bytes,
            last_audit: last_audit.into(),
            relay,
            pending_duties: self.pending_duties(),
        }
    }

    /// The policy in force.
    pub fn policy(&self) -> NodePolicy {
        lock(&self.core).policy().into()
    }

    /// Replace the policy. A quota below the bytes stored releases the
    /// largest shares; their release waits in the outbox.
    ///
    /// # Errors
    ///
    /// [`MobileError::Refused`] when the thermal pause is off, the quota is
    /// outside 1 GiB to 64 GiB, or above the class cap; the old policy stays.
    pub fn set_policy(&self, policy: NodePolicy) -> Result<(), MobileError> {
        let (applied, duties) = {
            let mut core = lock(&self.core);
            core.set_policy(policy.into())?;
            (core.policy(), core.drain_duties())
        };
        let count = saturating_count(self.queue(duties));
        self.emit(NodeEvent::PolicyChanged {
            policy: applied.into(),
        });
        if count > 0 {
            self.emit(NodeEvent::SharesReleased {
                count,
                reason: ReleaseReason::QuotaLowered,
            });
        }
        Ok(())
    }

    /// Report the free space the host measured. Below the 2 GB floor the core
    /// releases the largest shares; the count released is returned.
    pub fn report_free_space(&self, available_bytes: u64) -> u32 {
        let duties = {
            let mut core = lock(&self.core);
            core.set_available_bytes(available_bytes);
            core.drain_duties()
        };
        let count = saturating_count(self.queue(duties));
        if count > 0 {
            self.emit(NodeEvent::SharesReleased {
                count,
                reason: ReleaseReason::FreeSpaceFloor,
            });
        }
        count
    }

    /// The relay connection dropped: move to the next relay.
    pub fn on_relay_drop(&self) -> Option<Relay> {
        let relay = lock(&self.core).on_relay_drop().map(Relay::from);
        self.emit(NodeEvent::RelaySwitched {
            relay: relay.clone(),
        });
        relay
    }

    /// Queue a resume request after a suspension (section 7.8: it takes
    /// effect one epoch after inclusion).
    pub fn resume(&self) {
        let duty = lock(&self.core).resume();
        self.queue(vec![duty]);
    }

    /// Leave: release every share and stop. Not a penalty. Returns the count
    /// of shares released; unbonding is the wallet's transaction.
    pub fn leave(&self) -> u32 {
        let duty = lock(&self.core).leave();
        let count = saturating_count(self.queue(vec![duty]));
        self.emit(NodeEvent::SharesReleased {
            count,
            reason: ReleaseReason::Leave,
        });
        self.emit(NodeEvent::Stopped);
        count
    }

    /// Duties waiting for the network.
    pub fn pending_duties(&self) -> u32 {
        saturating_count(lock(&self.outbox).len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    #[derive(Default)]
    struct Recorder(Mutex<Vec<NodeEvent>>);

    impl NodeListener for Recorder {
        fn on_event(&self, event: NodeEvent) {
            lock(&self.0).push(event);
        }
    }

    fn node(class: PhoneClass) -> Arc<MobileNode> {
        let relays = vec![
            Relay {
                multiaddr: "/ip4/192.0.2.1/tcp/4001".to_owned(),
                capacity_kbps: 1_000,
            },
            Relay {
                multiaddr: "/ip4/192.0.2.2/tcp/4001".to_owned(),
                capacity_kbps: 1_000,
            },
        ];
        MobileNode::new(vec![7; 32], class, relays, 64 * GIB).expect("node")
    }

    #[test]
    fn mobile_ffi_refuses_an_owner_that_is_not_32_bytes() {
        for owner in [Vec::new(), vec![7; 31], vec![7; 33]] {
            let refused = MobileNode::new(owner, PhoneClass::Mobile, Vec::new(), 64 * GIB);
            match refused {
                Err(MobileError::Refused { code, .. }) => assert_eq!(code, "mobile_owner_length"),
                Ok(_) => panic!("a malformed owner was accepted"),
            }
        }
    }

    #[test]
    fn mobile_ffi_policy_round_trips_and_keeps_the_thermal_pause() {
        let node = node(PhoneClass::Mobile);
        let mut policy = node.policy();
        assert_eq!(policy.network, NetworkUse::UnmeteredOnly);
        assert!(policy.thermal_pause);

        policy.network = NetworkUse::Metered { daily_cap_mb: 200 };
        policy.power = PowerUse::ChargingOnly;
        policy.quota_bytes = 16 * GIB;
        node.set_policy(policy).expect("policy");
        assert_eq!(node.policy(), policy);

        let mut hot = policy;
        hot.thermal_pause = false;
        match node.set_policy(hot) {
            Err(MobileError::Refused { code, .. }) => {
                assert_eq!(code, "mobile_thermal_pause_locked");
            }
            Ok(()) => panic!("the thermal pause was turned off"),
        }
        assert_eq!(node.policy(), policy);
    }

    #[test]
    fn mobile_ffi_caps_an_ios_quota_at_8_gib() {
        let node = node(PhoneClass::MobileOpportunistic);
        let mut policy = node.policy();
        policy.quota_bytes = 8 * GIB + 1;
        match node.set_policy(policy) {
            Err(MobileError::Refused { code, .. }) => {
                assert_eq!(code, "mobile_quota_above_class_cap");
            }
            Ok(()) => panic!("an iOS quota above 8 GiB was accepted"),
        }
        policy.quota_bytes = 8 * GIB;
        node.set_policy(policy).expect("8 GiB");
    }

    #[test]
    fn mobile_ffi_reports_events_and_status() {
        let node = node(PhoneClass::Mobile);
        let recorder = Arc::new(Recorder::default());
        node.set_listener(recorder.clone());

        node.start();
        assert!(node.status().running);
        let next = node.on_relay_drop();
        assert_eq!(
            next.as_ref().map(|relay| relay.multiaddr.as_str()),
            Some("/ip4/192.0.2.2/tcp/4001")
        );
        assert_eq!(node.status().relay, next);
        node.resume();
        assert_eq!(node.pending_duties(), 1);
        assert_eq!(node.status().pending_duties, 1);
        node.stop();

        let events = lock(&recorder.0).clone();
        assert_eq!(
            events,
            vec![
                NodeEvent::Started,
                NodeEvent::RelaySwitched { relay: next },
                NodeEvent::Stopped,
            ]
        );
    }

    #[test]
    fn mobile_ffi_leave_stops_without_queueing_an_empty_release() {
        let node = node(PhoneClass::Mobile);
        let recorder = Arc::new(Recorder::default());
        node.set_listener(recorder.clone());
        node.start();
        assert_eq!(node.leave(), 0);
        assert!(!node.status().running);
        assert_eq!(node.pending_duties(), 0);
        let events = lock(&recorder.0).clone();
        assert_eq!(
            events.get(1..),
            Some(
                &[
                    NodeEvent::SharesReleased {
                        count: 0,
                        reason: ReleaseReason::Leave,
                    },
                    NodeEvent::Stopped,
                ][..]
            )
        );
    }

    #[test]
    fn mobile_ffi_class_parameters_are_the_section_7_2_table() {
        let android = class_parameters(PhoneClass::Mobile);
        assert_eq!(android.presence_window_epochs, 4);
        assert_eq!(android.suspension_hours, 72);
        assert_eq!(android.audit_window, AuditSpan::Hours { hours: 24 });
        assert_eq!(android.max_custody_quota_bytes, None);
        assert_eq!(android.quota_default_bytes, 4 * GIB);

        let ios = class_parameters(PhoneClass::MobileOpportunistic);
        assert_eq!(ios.presence_window_epochs, 4);
        assert_eq!(ios.suspension_hours, 168);
        assert_eq!(ios.audit_window, AuditSpan::Hours { hours: 48 });
        assert_eq!(ios.max_custody_quota_bytes, Some(8 * GIB));
        assert_eq!((ios.quota_min_bytes, ios.quota_max_bytes), (GIB, 64 * GIB));
        assert_eq!(ios.free_space_floor_bytes, 2_000_000_000);
    }

    #[test]
    fn mobile_ffi_free_space_above_the_floor_releases_nothing() {
        let node = node(PhoneClass::Mobile);
        assert_eq!(node.report_free_space(32 * GIB), 0);
        assert_eq!(node.pending_duties(), 0);
    }
}
