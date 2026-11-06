//! Duty engine: the production path of the mobile core (section 7.9.1).

use crate::custody::{Audit, CustodyProofBatch};
use crate::error::CoreError;
use crate::handover::{fetch_from_holders, Holder, ShareSource};
use crate::policy::Policy;
use crate::presence::{network_hint_ipv4, PresenceSignal, ResumeValidator, ValidatorClass};
use crate::quota::below_floor;
use crate::relay::{RelayOffer, RelayPool};
use crate::store::{AssignedShare, ShareId, ShareStore};

/// Testnet chain id (section 1.5).
pub const TESTNET_CHAIN_ID: u64 = 45_261;

/// A duty-lane transaction this core wants the host to submit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DutyTx {
    /// Confirm the signer's shares of an object.
    CustodyAck {
        /// Object key.
        object: [u8; 32],
        /// Local share id that was accepted.
        share: ShareId,
    },
    /// Answer open audits.
    CustodyProofBatch(CustodyProofBatch),
    /// Presence for one window.
    Presence(PresenceSignal),
    /// Restore a suspended validator one epoch later.
    Resume(ResumeValidator),
    /// Drop shares and lower the quota. Not a penalty.
    ReleaseShares {
        /// Released shares.
        shares: Vec<ShareId>,
    },
}

/// Last audit this core answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastAudit {
    /// No audit yet.
    None,
    /// Proof verified against the stored root.
    Passed,
    /// The core had no matching share.
    Missed,
}

/// Connection state the status panel shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Connection {
    /// No relay bound.
    Down,
    /// Bound to this relay.
    Relay(RelayOffer),
}

/// Snapshot for the persistent notification (section 7.9.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreStatus {
    /// Whether the duty loop is running.
    pub running: bool,
    /// Bytes currently stored.
    pub stored_bytes: u64,
    /// Current quota.
    pub quota_bytes: u64,
    /// Last audit result.
    pub last_audit: LastAudit,
    /// Connection.
    pub connection: Connection,
}

/// The mobile validator core.
#[derive(Debug)]
pub struct MobileCore {
    policy: Policy,
    store: ShareStore,
    relays: RelayPool,
    available_bytes: u64,
    running: bool,
    last_audit: LastAudit,
    owner: [u8; 32],
    class: ValidatorClass,
    chain_id: u64,
    pending: Vec<DutyTx>,
}

impl MobileCore {
    /// A stopped core with the default policy and the given owner and relays.
    #[must_use]
    pub fn new(
        owner: [u8; 32],
        class: ValidatorClass,
        relays: Vec<RelayOffer>,
        available_bytes: u64,
    ) -> Self {
        Self {
            policy: Policy::default(),
            store: ShareStore::new(),
            relays: RelayPool::new(relays),
            available_bytes,
            running: false,
            last_audit: LastAudit::None,
            owner,
            class,
            chain_id: TESTNET_CHAIN_ID,
            pending: Vec::new(),
        }
    }

    /// Start the duty loop.
    pub fn start(&mut self) {
        self.running = true;
    }

    /// Stop the duty loop. Shares stay on disk until [`Self::leave`].
    pub fn stop(&mut self) {
        self.running = false;
    }

    /// Panel snapshot.
    #[must_use]
    pub fn status(&self) -> CoreStatus {
        CoreStatus {
            running: self.running,
            stored_bytes: self.store.stored_bytes(),
            quota_bytes: self.policy.quota_bytes,
            last_audit: self.last_audit,
            connection: self
                .relays
                .current()
                .cloned()
                .map_or(Connection::Down, Connection::Relay),
        }
    }

    /// Replace the policy. Thermal pause cannot be cleared.
    ///
    /// # Errors
    ///
    /// [`CoreError`] when the quota is out of range.
    pub fn set_policy(&mut self, policy: Policy) -> Result<(), CoreError> {
        if !policy.thermal_pause {
            return Err(CoreError::new(
                "mobile_thermal_pause_locked",
                "the thermal pause cannot be disabled",
            ));
        }
        let mut next = Policy::default();
        next.set_quota(policy.quota_bytes)?;
        next.network = policy.network;
        next.power = policy.power;
        next.serve_symbols = policy.serve_symbols;
        self.policy = next;
        Ok(())
    }

    /// Accept an assigned share and return the `CustodyAck` duty.
    ///
    /// # Errors
    ///
    /// [`CoreError`] when the quota would be exceeded, the floor is already
    /// breached and leave is required, or the leaf does not match.
    pub fn accept_share(&mut self, assigned: AssignedShare) -> Result<DutyTx, CoreError> {
        if let Some(tx) = self.release_for_floor() {
            self.pending.push(tx);
        }
        if below_floor(self.available_bytes) {
            return Err(CoreError::new(
                "mobile_free_space_floor",
                "free space is below 2 GB; the core released shares and will not accept more",
            ));
        }
        let incoming = assigned.symbol.len() as u64;
        let record = self.store.accept(assigned, self.policy.quota_bytes)?;
        self.available_bytes = self.available_bytes.saturating_sub(incoming);
        Ok(DutyTx::CustodyAck {
            object: record.object,
            share: record.id,
        })
    }

    /// Answer an audit. The proof is checked against the stored symbol root
    /// before it leaves the core.
    ///
    /// # Errors
    ///
    /// [`CoreError`] when the share is missing or the proof does not verify.
    pub fn answer_audit(&mut self, audit: Audit) -> Result<DutyTx, CoreError> {
        match self.store.answer(&audit) {
            Ok(proof) => {
                if let Some(share) = self.store.matching_audit(&audit) {
                    proof
                        .verify(&audit, &share.proof_context())
                        .map_err(|_| {
                            CoreError::new(
                                "mobile_audit_self_check",
                                "a proof this core built did not verify",
                            )
                        })?;
                }
                self.last_audit = LastAudit::Passed;
                Ok(DutyTx::CustodyProofBatch(CustodyProofBatch {
                    proofs: vec![proof],
                }))
            }
            Err(err) => {
                self.last_audit = LastAudit::Missed;
                Err(err)
            }
        }
    }

    /// Presence signal for `window`, signed by `sign`.
    pub fn presence_signal<F>(&self, window: u64, ipv4: [u8; 4], sign: F) -> DutyTx
    where
        F: FnOnce(&[u8; 32]) -> Vec<u8>,
    {
        let signal = PresenceSignal::sign(
            self.owner,
            self.chain_id,
            window,
            self.class,
            network_hint_ipv4(ipv4),
            sign,
        );
        DutyTx::Presence(signal)
    }

    /// `ResumeValidator` for this owner.
    #[must_use]
    pub fn resume(&self) -> DutyTx {
        DutyTx::Resume(ResumeValidator { owner: self.owner })
    }

    /// Leave: release every share and stop. Not a penalty.
    pub fn leave(&mut self) -> DutyTx {
        let mut shares = Vec::new();
        while let Some(id) = self.store.largest_id() {
            if let Some(n) = self.store.release(id) {
                self.available_bytes = self.available_bytes.saturating_add(n);
                shares.push(id);
            } else {
                break;
            }
        }
        self.running = false;
        DutyTx::ReleaseShares { shares }
    }

    /// Switch relay after a drop.
    pub fn on_relay_drop(&mut self) -> Option<RelayOffer> {
        self.relays.on_drop().cloned()
    }

    /// Fetch a symbol, failing over after two seconds of silence.
    ///
    /// # Errors
    ///
    /// [`CoreError`] when every holder is silent.
    pub fn fetch_symbol<S: ShareSource>(
        &self,
        holders: &[Holder],
        source: &S,
    ) -> Result<Vec<u8>, CoreError> {
        fetch_from_holders(holders, source)
    }

    /// Release largest shares until free space is at least 2 GB, and lower
    /// the quota to the bytes that remain. Returns the duty if anything was
    /// released.
    pub fn release_for_floor(&mut self) -> Option<DutyTx> {
        if !below_floor(self.available_bytes) {
            return None;
        }
        let mut released = Vec::new();
        while below_floor(self.available_bytes) {
            let Some(id) = self.store.largest_id() else {
                break;
            };
            match self.store.release(id) {
                Some(n) => {
                    self.available_bytes = self.available_bytes.saturating_add(n);
                    released.push(id);
                }
                None => break,
            }
        }
        self.policy.quota_bytes = self.store.stored_bytes().max(1);
        if released.is_empty() {
            None
        } else {
            Some(DutyTx::ReleaseShares { shares: released })
        }
    }

    /// Duties produced as a side effect (floor releases) since the last drain.
    /// The host submits them on the duty lane.
    pub fn drain_duties(&mut self) -> Vec<DutyTx> {
        core::mem::take(&mut self.pending)
    }

    /// Inject host-measured free space. Tests and the Android host call this.
    pub fn set_available_bytes(&mut self, available_bytes: u64) {
        self.available_bytes = available_bytes;
    }

    /// Current free space as the core sees it.
    #[must_use]
    pub fn available_bytes(&self) -> u64 {
        self.available_bytes
    }

    /// Current policy.
    #[must_use]
    pub fn policy(&self) -> Policy {
        self.policy
    }
}
