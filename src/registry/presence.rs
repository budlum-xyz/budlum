//! Validator presence protocol, non-slashing suspension, and single-pairing BLS
//! aggregate verification (Section 7.8, Section 6.21.3, Section 11.7).
//! exposed for budlum-mobile-core, consensus block proposer, and handover coordinator.
//!
//! Offline validators are suspended (`Suspended`), never slashed (invariant V-4).
//! Equivocating across distinct [`PresenceClass`] tags in the
//! same presence window is a provable double-sign slashed at 1% of stake.

use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::chain::finality::{sign_bls, verify_bls_sig};
use crate::core::address::Address;

/// Gossip topic for validator presence signals (Section 7.8 item 3).
pub const PRESENCE_GOSSIP_TOPIC: &str = "/budlum/presence/1";

/// Domain separation tag for validator presence digests (`BDLM_PRESENCE_V1`).
pub(crate) const PRESENCE_DOMAIN_TAG: &[u8] = b"BDLM_PRESENCE_V1";

/// Full-class presence window length in epochs (Section 7.8 item 1).
pub const FULL_PRESENCE_WINDOW_EPOCHS: u64 = 1;

/// Mobile-class presence window length in epochs (Section 7.8 item 1: 4 epochs).
pub const MOBILE_PRESENCE_WINDOW_EPOCHS: u64 = 4;

/// Offline hours before a Full validator is suspended (Section 7.2: 1 day).
pub const FULL_SUSPENSION_HOURS: u64 = 24;

/// Offline hours before an Android Mobile validator is suspended (Section 7.2: 72 hours).
pub const MOBILE_SUSPENSION_HOURS: u64 = 72;

/// Offline hours before an iOS opportunistic Mobile validator is suspended (Section 7.2: 7 days).
pub const IOS_OPPORTUNISTIC_SUSPENSION_HOURS: u64 = 168;

/// Stake slash ratio in parts-per-million for a presence double-sign (1% = 10,000 PPM).
pub const PRESENCE_DOUBLE_SIGN_SLASH_PPM: u64 = 10_000;

/// Peer-score penalty applied when a peer relays duplicate presence signals in the same window.
pub const DUPLICATE_SIGNAL_PEER_PENALTY: i32 = -25;

/// Epochs after `ResumeValidator` before a suspended validator becomes active again.
pub const RESUME_ACTIVATION_DELAY_EPOCHS: u64 = 1;

/// Maximum deduplicated presence signals retained in [`PresenceGossipInbox`].
pub const MAX_PRESENCE_INBOX_ENTRIES: usize = 65_536;

/// The one validator-class definition shared by the node and phone (K-4).
/// The alias keeps existing node call sites source-compatible.
pub use budlum_types::ValidatorClass as PresenceClass;
const _: &[u8] = PRESENCE_DOMAIN_TAG;

/// Convert an offline duration in hours to a ceiling epoch count (Section 6.21.3):
/// `ceil(hours * 3600 / (slot_secs * epoch_len_blocks))`.
/// Convenience: exposed for validator class and governance parameter checks.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn hours_to_epochs(
    hours: u64,
    slot_secs: u64,
    epoch_len_blocks: u64,
) -> Result<u64, PresenceError> {
    let denom = u128::from(slot_secs).saturating_mul(u128::from(epoch_len_blocks));
    if denom == 0 {
        return Err(PresenceError::ZeroEpochDuration);
    }
    let total_secs = u128::from(hours).saturating_mul(3_600);
    let ceil_epochs = total_secs
        .saturating_add(denom.saturating_sub(1))
        .checked_div(denom)
        .ok_or(PresenceError::ZeroEpochDuration)?;
    u64::try_from(ceil_epochs).map_err(|_| PresenceError::EpochOverflow)
}

/// Canonical 32-byte signing digest for a presence window (Section 7.8 item 2).
///
/// All four fields, including the domain tag, are length-prefixed under G-5.
/// The shared definition is the same function the mobile core signs.
#[must_use]
pub fn presence_signing_digest(chain_id: u64, window: u64, class: PresenceClass) -> [u8; 32] {
    budlum_types::presence::presence_message(chain_id, window, class)
}

pub use budlum_types::presence::PresenceSignal;

/// Sign the shared presence message with the node's BLS implementation.
/// The signal layout and digest remain defined by `budlum-types`; only the
/// chain-specific BLS primitive stays here.
#[must_use]
pub fn sign_presence_signal(
    validator: Address,
    chain_id: u64,
    window: u64,
    class: PresenceClass,
    network_hint: [u8; 32],
    secret_key: &Scalar,
) -> PresenceSignal {
    PresenceSignal::sign(validator, chain_id, window, class, network_hint, |digest| {
        sign_bls(secret_key, digest)
    })
}

fn verify_presence_signal(
    signal: &PresenceSignal,
    bls_public_key: &[u8],
    chain_id: u64,
) -> Result<(), PresenceError> {
    let digest = presence_signing_digest(chain_id, signal.window, signal.class);
    verify_bls_sig(bls_public_key, &digest, &signal.sig_bls)
        .map_err(PresenceError::InvalidSignature)
}

/// Provable equivocation when a validator signs two different [`PresenceClass`] values
/// in the same `window` (Section 7.8 item 8; 1% stake slash).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceDoubleSignEvidence {
    pub first: PresenceSignal,
    pub second: PresenceSignal,
}

/// Outcome of ingesting a gossip `PresenceSignal` on `/budlum/presence/1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GossipIngestOutcome {
    Accepted,
    /// Duplicate signal in the same `(validator, window)` dropped with peer penalty.
    DroppedDuplicate {
        peer_score_delta: i32,
    },
    /// Conflicting class signed in the same `(validator, window)`: slashable double-sign.
    DoubleSignDetected(Box<PresenceDoubleSignEvidence>),
}

/// Per-window gossip deduplicator and double-sign detector for `/budlum/presence/1`.
#[derive(Debug, Clone, Default)]
pub struct PresenceGossipInbox {
    seen: BTreeMap<(Address, u64), PresenceSignal>,
}

impl PresenceGossipInbox {
    /// Validate and ingest a `PresenceSignal` against `bls_public_key`.
    /// Convenience: exposed for `/budlum/presence/1` gossip handler.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn ingest(
        &mut self,
        signal: PresenceSignal,
        bls_public_key: &[u8],
        chain_id: u64,
    ) -> Result<GossipIngestOutcome, PresenceError> {
        if signal.validator == Address::zero() {
            return Err(PresenceError::InvalidSignature(
                "zero validator address".to_owned(),
            ));
        }
        verify_presence_signal(&signal, bls_public_key, chain_id)?;
        let key = (signal.validator, signal.window);
        if let Some(existing) = self.seen.get(&key) {
            if existing.class != signal.class {
                return Ok(GossipIngestOutcome::DoubleSignDetected(Box::new(
                    PresenceDoubleSignEvidence {
                        first: existing.clone(),
                        second: signal,
                    },
                )));
            }
            return Ok(GossipIngestOutcome::DroppedDuplicate {
                peer_score_delta: DUPLICATE_SIGNAL_PEER_PENALTY,
            });
        }
        while self.seen.len() >= MAX_PRESENCE_INBOX_ENTRIES {
            let Some(oldest_key) = self
                .seen
                .iter()
                .min_by_key(|((_, w), _)| *w)
                .map(|(k, _)| *k)
            else {
                break;
            };
            self.seen.remove(&oldest_key);
        }
        self.seen.insert(key, signal);
        Ok(GossipIngestOutcome::Accepted)
    }

    /// Drain accepted signals for `(window, class)` to build a block [`PresenceAggregate`].
    /// Convenience: exposed for block proposer aggregate assembly.
    #[must_use]
    pub fn signals_for_window(&self, window: u64, class: PresenceClass) -> Vec<PresenceSignal> {
        self.seen
            .values()
            .filter(|s| s.window == window && s.class == class)
            .cloned()
            .collect()
    }
}

/// Block-embedded aggregate presence proof verified with a single BLS pairing (Section 7.8 item 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceAggregate {
    pub window: u64,
    pub class: PresenceClass,
    /// Little-endian bitset over the ordered validator directory for `class`.
    pub bitmap: Vec<u8>,
    /// 48-byte compressed G1 sum of all signers indicated by `bitmap`.
    pub aggregate_sig: Vec<u8>,
}

impl PresenceAggregate {
    /// Aggregate verified signals for `(window, class)` over an ordered `roster` of `(Address, bls_pk)`.
    /// Convenience: exposed for block proposer aggregate builder.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn build(
        window: u64,
        class: PresenceClass,
        roster: &[(Address, Vec<u8>)],
        signals: &[PresenceSignal],
        chain_id: u64,
    ) -> Result<Self, PresenceError> {
        if roster.is_empty() {
            return Err(PresenceError::EmptyAggregate);
        }
        let mut seen_roster = BTreeSet::new();
        for (addr, _) in roster {
            if *addr == Address::zero() {
                return Err(PresenceError::InvalidSignature(
                    "zero validator address in roster".to_owned(),
                ));
            }
            if !seen_roster.insert(*addr) {
                return Err(PresenceError::DuplicateRosterValidator);
            }
        }
        let mut by_addr: BTreeMap<Address, &PresenceSignal> = BTreeMap::new();
        for sig in signals {
            if sig.window == window && sig.class == class {
                by_addr.insert(sig.validator, sig);
            }
        }

        let bitmap_len = roster.len().saturating_add(7) / 8;
        let mut bitmap = vec![0u8; bitmap_len];
        let mut sum_sig = G1Projective::identity();
        let mut count = 0usize;

        for (idx, (addr, pk)) in roster.iter().enumerate() {
            let Some(sig) = by_addr.get(addr) else {
                continue;
            };
            verify_presence_signal(sig, pk, chain_id)?;
            let g1 = decode_g1(&sig.sig_bls)?;
            sum_sig += G1Projective::from(g1);
            let byte_idx = idx / 8;
            let bit_idx = idx % 8;
            if let Some(slot) = bitmap.get_mut(byte_idx) {
                *slot |= 1u8 << bit_idx;
            }
            count = count.saturating_add(1);
        }

        if count == 0 {
            return Err(PresenceError::EmptyAggregate);
        }
        let agg_sig = G1Affine::from(sum_sig);
        if bool::from(agg_sig.is_identity()) {
            return Err(PresenceError::InvalidSignature(
                "aggregate signature is identity".to_owned(),
            ));
        }

        Ok(Self {
            window,
            class,
            bitmap,
            aggregate_sig: agg_sig.to_compressed().to_vec(),
        })
    }

    /// Verify the aggregate in ONE BLS pairing check by summing the G2 public keys
    /// selected by `bitmap` and checking `verify_bls_sig(agg_pk, digest, aggregate_sig)`.
    /// Returns the verified present validator addresses.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn verify_single_pairing(
        &self,
        roster: &[(Address, Vec<u8>)],
        chain_id: u64,
    ) -> Result<Vec<Address>, PresenceError> {
        let max_bytes = roster.len().saturating_add(7) / 8;
        if self.bitmap.len() != max_bytes {
            return Err(PresenceError::InvalidBitmapLength);
        }
        // Reject trailing bits past `roster.len()`.
        let rem = roster.len() % 8;
        if rem != 0 {
            if let Some(last) = self.bitmap.last() {
                let trailing_mask = !((1u8 << rem).wrapping_sub(1));
                if (*last & trailing_mask) != 0 {
                    return Err(PresenceError::InvalidBitmapTrailingBits);
                }
            }
        }

        // Reject duplicate or zero addresses across the roster so rogue keys
        // cannot cancel each other or double-count signers.
        let mut seen_roster = BTreeSet::new();
        for (addr, _) in roster {
            if *addr == Address::zero() {
                return Err(PresenceError::InvalidSignature(
                    "zero validator address in roster".to_owned(),
                ));
            }
            if !seen_roster.insert(*addr) {
                return Err(PresenceError::DuplicateRosterValidator);
            }
        }

        // Reject identity or non-subgroup aggregate signatures before pairing.
        let _ = decode_g1(&self.aggregate_sig)?;

        let mut sum_pk = G2Projective::identity();
        let mut present = Vec::new();
        for (idx, (addr, pk_bytes)) in roster.iter().enumerate() {
            let byte_idx = idx / 8;
            let bit_idx = idx % 8;
            let is_set = self
                .bitmap
                .get(byte_idx)
                .is_some_and(|b| (*b >> bit_idx) & 1 == 1);
            if !is_set {
                continue;
            }
            let pk = decode_g2(pk_bytes)?;
            sum_pk += G2Projective::from(pk);
            present.push(*addr);
        }

        if present.is_empty() {
            return Err(PresenceError::EmptyAggregate);
        }

        let agg_pk = G2Affine::from(sum_pk);
        if bool::from(agg_pk.is_identity()) {
            return Err(PresenceError::InvalidSignature(
                "aggregate public key is identity".to_owned(),
            ));
        }
        let agg_pk_bytes = agg_pk.to_compressed();
        let digest = presence_signing_digest(chain_id, self.window, self.class);
        verify_bls_sig(&agg_pk_bytes, &digest, &self.aggregate_sig)
            .map_err(PresenceError::InvalidSignature)?;
        Ok(present)
    }
}

/// Chain-state validator record tracked by [`PresenceTracker`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorPresenceState {
    pub class: PresenceClass,
    #[serde(default)]
    pub bls_public_key: Vec<u8>,
    pub stake_atoms: u64,
    pub last_seen_epoch: u64,
    pub last_seen_window: Option<u64>,
    pub seen_windows_in_period: u64,
    pub suspended: bool,
    pub resume_effective_epoch: Option<u64>,
    pub slashed_double_sign: bool,
}

/// On-chain presence state machine enforcing non-slashing suspension (V-4),
/// `ResumeValidator` 1-epoch delay, 1% double-sign slash, and reward multipliers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceTracker {
    pub slot_secs: u64,
    pub epoch_len_blocks: u64,
    validators: BTreeMap<Address, ValidatorPresenceState>,
}

impl PresenceTracker {
    #[must_use]
    pub fn new(slot_secs: u64, epoch_len_blocks: u64) -> Self {
        Self {
            slot_secs,
            epoch_len_blocks,
            validators: BTreeMap::new(),
        }
    }

    /// Convenience: exposed for validator registration hook.
    ///
    /// Ignores the zero address and preserves any existing validator record so
    /// re-registration cannot wipe double-sign slash, suspension, or key state.
    pub fn register_validator(
        &mut self,
        validator: Address,
        class: PresenceClass,
        stake_atoms: u64,
        registered_epoch: u64,
    ) {
        if validator == Address::zero() {
            return;
        }
        self.validators
            .entry(validator)
            .or_insert(ValidatorPresenceState {
                class,
                bls_public_key: Vec::new(),
                stake_atoms,
                last_seen_epoch: registered_epoch,
                last_seen_window: None,
                seen_windows_in_period: 0,
                suspended: false,
                resume_effective_epoch: None,
                slashed_double_sign: false,
            });
    }

    /// Bind the registered BLS public key a validator signs presence signals with,
    /// so equivocation slashing checks against local consensus key material and
    /// never against a caller-supplied key travelling with the evidence.
    /// Convenience: exposed for validator key registration and consensus hooks.
    pub fn register_validator_bls_key(&mut self, validator: &Address, bls_public_key: &[u8]) {
        if decode_g2(bls_public_key).is_err() {
            return;
        }
        if let Some(st) = self.validators.get_mut(validator) {
            st.bls_public_key = bls_public_key.to_vec();
        }
    }

    /// Convenience: exposed for RPC and consensus eligibility queries.
    #[must_use]
    pub fn state_of(&self, validator: &Address) -> Option<&ValidatorPresenceState> {
        self.validators.get(validator)
    }

    /// Record verified block [`PresenceAggregate`] signers at `current_epoch`.
    /// Convenience: exposed for block execution presence aggregate hook.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn apply_aggregate(
        &mut self,
        aggregate: &PresenceAggregate,
        roster: &[(Address, Vec<u8>)],
        chain_id: u64,
        current_epoch: u64,
    ) -> Result<Vec<Address>, PresenceError> {
        let expected_window =
            budlum_types::presence::window_of_epoch(current_epoch, aggregate.class);
        if aggregate.window != expected_window {
            return Err(PresenceError::StaleAggregate);
        }
        let present = aggregate.verify_single_pairing(roster, chain_id)?;
        let roster_keys: BTreeMap<Address, &[u8]> = roster
            .iter()
            .map(|(addr, pk)| (*addr, pk.as_slice()))
            .collect();
        // Validate every selected signer's roster key against its registered BLS
        // key before mutating any state so a refusal leaves state untouched.
        for addr in &present {
            if let Some(st) = self.validators.get(addr) {
                if !st.bls_public_key.is_empty()
                    && roster_keys.get(addr).copied() != Some(st.bls_public_key.as_slice())
                {
                    return Err(PresenceError::InvalidSignature(
                        "aggregate roster BLS key does not match registered validator key"
                            .to_owned(),
                    ));
                }
            }
        }
        for addr in &present {
            if let Some(st) = self.validators.get_mut(addr) {
                if !st.suspended
                    && !st.slashed_double_sign
                    && st.class == aggregate.class
                    && st
                        .last_seen_window
                        .is_none_or(|prev| prev < aggregate.window)
                {
                    st.last_seen_window = Some(aggregate.window);
                    st.last_seen_epoch = current_epoch;
                    st.seen_windows_in_period = st.seen_windows_in_period.saturating_add(1);
                }
            }
        }
        Ok(present)
    }

    /// Full-class finalized `SeatParticipation` also counts as presence (Section 7.8 item 5).
    /// Convenience: exposed for finalized checkpoint participation hook.
    pub fn record_full_seat_participation(&mut self, validator: &Address, current_epoch: u64) {
        if let Some(st) = self.validators.get_mut(validator) {
            if !st.suspended
                && !st.slashed_double_sign
                && st.class == PresenceClass::Full
                && st.last_seen_epoch < current_epoch
            {
                st.last_seen_epoch = current_epoch;
                if st.last_seen_window != Some(current_epoch) {
                    st.last_seen_window = Some(current_epoch);
                    st.seen_windows_in_period = st.seen_windows_in_period.saturating_add(1);
                }
            }
        }
    }

    /// Synchronize consecutive epoch-miss tracking from [`crate::registry::LivenessTracker`]
    /// into non-slashing suspension notices (V-4).
    /// Convenience: exposed for epoch-close suspension transition.
    pub fn sync_liveness_suspensions<F>(
        &mut self,
        liveness: &mut crate::registry::liveness::LivenessTracker,
        epoch: u64,
        expected: &[Address],
        participated: F,
        threshold: u64,
    ) -> Vec<crate::registry::liveness::SuspensionNotice>
    where
        F: FnMut(&Address) -> bool,
    {
        let notices = liveness.record_suspension_epoch(epoch, expected, participated, threshold);
        for notice in &notices {
            if let Some(st) = self.validators.get_mut(&notice.validator) {
                st.suspended = true;
            }
        }
        notices
    }

    /// Advance to `current_epoch`: activate pending `ResumeValidator` requests whose
    /// 1-epoch delay has elapsed, and suspend validators exceeding their offline threshold.
    /// Stake is NEVER reduced by suspension (invariant V-4).
    /// Convenience: exposed for epoch boundary transition.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn advance_epoch(
        &mut self,
        current_epoch: u64,
    ) -> Result<BTreeSet<Address>, PresenceError> {
        let mut newly_suspended = BTreeSet::new();
        let slot_secs = self.slot_secs;
        let epoch_len = self.epoch_len_blocks;

        for (addr, st) in &mut self.validators {
            if st.slashed_double_sign {
                st.suspended = true;
                st.resume_effective_epoch = None;
                continue;
            }
            if let Some(activate_at) = st.resume_effective_epoch {
                if current_epoch >= activate_at {
                    st.suspended = false;
                    st.resume_effective_epoch = None;
                    st.last_seen_epoch = current_epoch;
                }
            }
            if st.suspended {
                continue;
            }
            let threshold_epochs =
                hours_to_epochs(st.class.suspension_hours(), slot_secs, epoch_len)?;
            let absent_epochs = current_epoch.saturating_sub(st.last_seen_epoch);
            if absent_epochs >= threshold_epochs {
                st.suspended = true;
                newly_suspended.insert(*addr);
            }
        }
        Ok(newly_suspended)
    }

    /// Submit `ResumeValidator` (Section 7.8 item 7): reactivates after 1 full epoch.
    /// Convenience: exposed for `ResumeValidator` transaction execution.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn apply_resume_validator(
        &mut self,
        validator: &Address,
        current_epoch: u64,
    ) -> Result<u64, PresenceError> {
        let st = self
            .validators
            .get_mut(validator)
            .ok_or(PresenceError::UnknownValidator)?;
        if st.slashed_double_sign {
            return Err(PresenceError::ValidatorSlashed);
        }
        if !st.suspended {
            return Err(PresenceError::ValidatorNotSuspended);
        }
        let effective = current_epoch
            .checked_add(RESUME_ACTIVATION_DELAY_EPOCHS)
            .ok_or(PresenceError::EpochOverflow)?;
        let chosen = st
            .resume_effective_epoch
            .map_or(effective, |prev| prev.min(effective));
        st.resume_effective_epoch = Some(chosen);
        Ok(chosen)
    }

    /// Verify and apply a 1% stake slash for signing two different [`PresenceClass`]
    /// tags in the same presence window (Section 7.8 item 8, Section 11.7).
    /// Convenience: exposed for equivocation evidence processing.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn slash_double_sign(
        &mut self,
        evidence: &PresenceDoubleSignEvidence,
        bls_public_key: &[u8],
        chain_id: u64,
    ) -> Result<u64, PresenceError> {
        if evidence.first.validator != evidence.second.validator
            || evidence.first.window != evidence.second.window
            || evidence.first.class == evidence.second.class
        {
            return Err(PresenceError::InvalidDoubleSignEvidence);
        }
        // Always authenticate double-sign evidence against the accused
        // validator's registered BLS key, never a caller-chosen key.
        let registered_key = {
            let st = self
                .validators
                .get(&evidence.first.validator)
                .ok_or(PresenceError::UnknownValidator)?;
            if st.bls_public_key.is_empty() || st.bls_public_key.as_slice() != bls_public_key {
                return Err(PresenceError::InvalidSignature(
                    "evidence BLS key does not match registered validator key".to_string(),
                ));
            }
            st.bls_public_key.clone()
        };
        verify_presence_signal(&evidence.first, &registered_key, chain_id)?;
        verify_presence_signal(&evidence.second, &registered_key, chain_id)?;

        let st = self
            .validators
            .get_mut(&evidence.first.validator)
            .ok_or(PresenceError::UnknownValidator)?;
        if st.slashed_double_sign {
            st.suspended = true;
            st.resume_effective_epoch = None;
            return Ok(0);
        }
        let slash_atoms = u64::try_from(
            u128::from(st.stake_atoms).saturating_mul(u128::from(PRESENCE_DOUBLE_SIGN_SLASH_PPM))
                / 1_000_000,
        )
        .unwrap_or(u64::MAX);
        st.stake_atoms = st.stake_atoms.saturating_sub(slash_atoms);
        st.slashed_double_sign = true;
        st.suspended = true;
        st.resume_effective_epoch = None;
        Ok(slash_atoms)
    }

    /// Reward multiplier in parts-per-million (`[0, 1_000_000]`) equal to the
    /// fraction of expected windows observed during the reward period (Section 7.8 item 9).
    /// Convenience: exposed for epoch custody reward distribution.
    #[must_use]
    pub fn reward_multiplier_ppm(&self, validator: &Address, expected_windows: u64) -> u32 {
        if expected_windows == 0 {
            return 0;
        }
        let Some(st) = self.validators.get(validator) else {
            return 0;
        };
        let capped = st.seen_windows_in_period.min(expected_windows);
        let ppm = u128::from(capped).saturating_mul(1_000_000) / u128::from(expected_windows);
        u32::try_from(ppm).unwrap_or(1_000_000)
    }

    /// Reset observed window counters at the end of a reward period.
    /// Convenience: exposed for reward period rollover.
    pub fn reset_period_counters(&mut self) {
        for st in self.validators.values_mut() {
            st.seen_windows_in_period = 0;
        }
    }
}

fn decode_g1(bytes: &[u8]) -> Result<G1Affine, PresenceError> {
    let raw: [u8; 48] = bytes
        .try_into()
        .map_err(|_| PresenceError::InvalidSignature("invalid G1 length".to_owned()))?;
    let pt = G1Affine::from_compressed_unchecked(&raw)
        .into_option()
        .ok_or_else(|| PresenceError::InvalidSignature("invalid G1 encoding".to_owned()))?;
    let torsion_free: bool = pt.is_torsion_free().into();
    if !bool::from(pt.is_on_curve()) || !torsion_free || bool::from(pt.is_identity()) {
        return Err(PresenceError::InvalidSignature(
            "G1 point outside prime subgroup".to_owned(),
        ));
    }
    Ok(pt)
}

fn decode_g2(bytes: &[u8]) -> Result<G2Affine, PresenceError> {
    let raw: [u8; 96] = bytes
        .try_into()
        .map_err(|_| PresenceError::InvalidSignature("invalid G2 length".to_owned()))?;
    let pt = G2Affine::from_compressed_unchecked(&raw)
        .into_option()
        .ok_or_else(|| PresenceError::InvalidSignature("invalid G2 encoding".to_owned()))?;
    let torsion_free: bool = pt.is_torsion_free().into();
    if !bool::from(pt.is_on_curve()) || !torsion_free || bool::from(pt.is_identity()) {
        return Err(PresenceError::InvalidSignature(
            "G2 point outside prime subgroup".to_owned(),
        ));
    }
    Ok(pt)
}

/// Errors raised by the presence protocol and suspension state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresenceError {
    ZeroEpochDuration,
    EpochOverflow,
    EmptyAggregate,
    StaleAggregate,
    InvalidBitmapLength,
    InvalidBitmapTrailingBits,
    InvalidSignature(String),
    InvalidDoubleSignEvidence,
    DuplicateRosterValidator,
    UnknownValidator,
    ValidatorNotSuspended,
    ValidatorSlashed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::liveness::LivenessTracker;

    const CHAIN_ID: u64 = 45_261;

    fn keypair_for(idx: u64) -> (Address, Scalar, Vec<u8>) {
        let sk = Scalar::from(idx + 1);
        let pk = G2Affine::from(G2Projective::generator() * sk)
            .to_compressed()
            .to_vec();
        let mut raw = [0u8; 32];
        raw[..8].copy_from_slice(&(idx + 1).to_le_bytes());
        (Address::from(raw), sk, pk)
    }

    #[test]
    fn node_presence_digest_matches_the_shared_mobile_vector() {
        let digest = include_bytes!("../../tests/vectors/presence/v1/digest.bin");
        assert_eq!(
            &presence_signing_digest(45_261, 11, PresenceClass::Mobile),
            digest
        );
        assert_ne!(
            presence_signing_digest(45_261, 11, PresenceClass::Mobile),
            presence_signing_digest(45_261, 11, PresenceClass::Full)
        );
    }

    #[test]
    fn presence_window_hours_convert_to_epochs() {
        // Testnet: 3-second slots, 50-block epochs => 150 seconds (2.5 min) per epoch.
        // 1 day (24h) = 86,400s => 576 epochs.
        assert_eq!(hours_to_epochs(24, 3, 50).unwrap(), 576);
        // 72h => 1,728 epochs.
        assert_eq!(hours_to_epochs(72, 3, 50).unwrap(), 1_728);
        // 168h (7 days) => 4,032 epochs.
        assert_eq!(hours_to_epochs(168, 3, 50).unwrap(), 4_032);
        // Non-divisible duration rounds UP (ceiling).
        assert_eq!(hours_to_epochs(1, 7, 100).unwrap(), 6);
    }

    #[test]
    fn presence_aggregate_verifies() {
        // Done criterion: verify 1,000 simulated Mobile validators in ONE single BLS aggregate!
        let count = 1_000usize;
        let mut roster = Vec::with_capacity(count);
        let mut signals = Vec::with_capacity(count);
        for i in 0..count {
            let (addr, sk, pk) = keypair_for(i as u64);
            roster.push((addr, pk));
            if i % 2 == 0 {
                signals.push(sign_presence_signal(
                    addr,
                    CHAIN_ID,
                    9,
                    PresenceClass::Mobile,
                    [0xAA; 32],
                    &sk,
                ));
            }
        }

        let agg = PresenceAggregate::build(9, PresenceClass::Mobile, &roster, &signals, CHAIN_ID)
            .unwrap();
        let present = agg.verify_single_pairing(&roster, CHAIN_ID).unwrap();
        assert_eq!(present.len(), 500);

        // Forging an extra bitmap bit for an absent validator MUST fail single-pairing verification.
        let mut forged = agg.clone();
        forged.bitmap[0] |= 0b0000_0010; // index 1 did not sign
        assert!(forged.verify_single_pairing(&roster, CHAIN_ID).is_err());
    }

    #[test]
    fn absent_validator_is_suspended_not_slashed() {
        let mut tracker = PresenceTracker::new(3, 50); // 150s/epoch
        let (mobile, _, _) = keypair_for(1);
        let initial_stake = 10_000_000_000u64;
        tracker.register_validator(mobile, PresenceClass::Mobile, initial_stake, 0);

        // Before 1,728 epochs (72h), validator remains active.
        assert!(tracker.advance_epoch(1_727).unwrap().is_empty());
        assert!(!tracker.state_of(&mobile).unwrap().suspended);

        // At epoch 1,728, validator is suspended with ZERO stake cut (V-4).
        let suspended = tracker.advance_epoch(1_728).unwrap();
        assert!(suspended.contains(&mobile));
        let st = tracker.state_of(&mobile).unwrap();
        assert!(st.suspended);
        assert_eq!(st.stake_atoms, initial_stake);
    }

    #[test]
    fn resume_restores_after_one_epoch() {
        let mut tracker = PresenceTracker::new(3, 50);
        let (full, _, _) = keypair_for(2);
        tracker.register_validator(full, PresenceClass::Full, 50_000, 0);

        tracker.advance_epoch(576).unwrap();
        assert!(tracker.state_of(&full).unwrap().suspended);

        let activate_at = tracker.apply_resume_validator(&full, 600).unwrap();
        assert_eq!(activate_at, 601);

        // Same epoch 600: still suspended.
        tracker.advance_epoch(600).unwrap();
        assert!(tracker.state_of(&full).unwrap().suspended);

        // Epoch 601: restored!
        tracker.advance_epoch(601).unwrap();
        assert!(!tracker.state_of(&full).unwrap().suspended);
    }

    #[test]
    fn presence_double_sign_is_slashed_one_percent() {
        let mut tracker = PresenceTracker::new(3, 50);
        let (val, sk, pk) = keypair_for(3);
        let (_attacker, attacker_sk, attacker_pk) = keypair_for(4);
        tracker.register_validator(val, PresenceClass::Mobile, 100_000, 0);
        tracker.register_validator_bls_key(&val, &pk);

        // An attacker signing equivocating signals under their own BLS key
        // naming `val` MUST NOT slash `val`.
        let forged_ev = PresenceDoubleSignEvidence {
            first: sign_presence_signal(
                val,
                CHAIN_ID,
                42,
                PresenceClass::Mobile,
                [1; 32],
                &attacker_sk,
            ),
            second: sign_presence_signal(
                val,
                CHAIN_ID,
                42,
                PresenceClass::Full,
                [1; 32],
                &attacker_sk,
            ),
        };
        assert!(matches!(
            tracker.slash_double_sign(&forged_ev, &attacker_pk, CHAIN_ID),
            Err(PresenceError::InvalidSignature(_))
        ));
        assert_eq!(tracker.state_of(&val).unwrap().stake_atoms, 100_000);
        assert!(!tracker.state_of(&val).unwrap().slashed_double_sign);

        let mut inbox = PresenceGossipInbox::default();
        let sig_mobile =
            sign_presence_signal(val, CHAIN_ID, 42, PresenceClass::Mobile, [1; 32], &sk);
        let sig_dup = sign_presence_signal(val, CHAIN_ID, 42, PresenceClass::Mobile, [2; 32], &sk);
        let sig_full = sign_presence_signal(val, CHAIN_ID, 42, PresenceClass::Full, [1; 32], &sk);

        assert_eq!(
            inbox.ingest(sig_mobile, &pk, CHAIN_ID).unwrap(),
            GossipIngestOutcome::Accepted
        );
        assert_eq!(
            inbox.ingest(sig_dup, &pk, CHAIN_ID).unwrap(),
            GossipIngestOutcome::DroppedDuplicate {
                peer_score_delta: DUPLICATE_SIGNAL_PEER_PENALTY
            }
        );
        let outcome = inbox.ingest(sig_full, &pk, CHAIN_ID).unwrap();
        let GossipIngestOutcome::DoubleSignDetected(ev) = outcome else {
            panic!("expected double-sign evidence");
        };

        let slashed = tracker.slash_double_sign(&ev, &pk, CHAIN_ID).unwrap();
        assert_eq!(slashed, 1_000); // exact 1% of 100,000
        assert_eq!(tracker.state_of(&val).unwrap().stake_atoms, 99_000);
        assert!(tracker.state_of(&val).unwrap().suspended);
    }

    #[test]
    fn liveness_report_no_longer_slashes() {
        let mut liveness = LivenessTracker::new();
        let v = Address::from([7u8; 32]);
        assert!(liveness
            .record_suspension_epoch(1, &[v], |_| false, 3)
            .is_empty());
        assert!(liveness
            .record_suspension_epoch(2, &[v], |_| false, 3)
            .is_empty());
        let notices = liveness.record_suspension_epoch(3, &[v], |_| false, 3);
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].validator, v);
        assert_eq!(notices[0].missed_epochs, 3);
        assert_eq!(notices[0].stake_slashed_atoms, 0);
    }

    #[test]
    fn wave3_presence_rejects_resume_and_epoch_unsuspension_for_slashed_double_signer() {
        // Case A: double-sign slash followed by apply_resume_validator MUST fail.
        let mut tracker = PresenceTracker::new(3, 50);
        let (val, sk, pk) = keypair_for(10);
        tracker.register_validator(val, PresenceClass::Mobile, 100_000, 0);
        tracker.register_validator_bls_key(&val, &pk);

        let ev = PresenceDoubleSignEvidence {
            first: sign_presence_signal(val, CHAIN_ID, 7, PresenceClass::Mobile, [1; 32], &sk),
            second: sign_presence_signal(val, CHAIN_ID, 7, PresenceClass::Full, [2; 32], &sk),
        };
        assert_eq!(
            tracker.slash_double_sign(&ev, &pk, CHAIN_ID).unwrap(),
            1_000
        );
        assert!(
            tracker.apply_resume_validator(&val, 10).is_err(),
            "equivocation-slashed validator must not be allowed to schedule resume"
        );
        tracker.advance_epoch(11).unwrap();
        assert!(
            tracker.state_of(&val).unwrap().suspended,
            "slashed validator must remain suspended across epoch rollover"
        );

        // Case B: pre-scheduled resume before double-sign slash MUST be cleared
        // on slash so advance_epoch cannot auto-reactivate the slashed validator.
        let mut tracker2 = PresenceTracker::new(3, 50);
        let (val2, sk2, pk2) = keypair_for(11);
        tracker2.register_validator(val2, PresenceClass::Full, 100_000, 0);
        tracker2.register_validator_bls_key(&val2, &pk2);
        tracker2.advance_epoch(576).unwrap();
        assert!(tracker2.state_of(&val2).unwrap().suspended);
        assert_eq!(tracker2.apply_resume_validator(&val2, 600).unwrap(), 601);

        let ev2 = PresenceDoubleSignEvidence {
            first: sign_presence_signal(val2, CHAIN_ID, 8, PresenceClass::Mobile, [3; 32], &sk2),
            second: sign_presence_signal(val2, CHAIN_ID, 8, PresenceClass::Full, [4; 32], &sk2),
        };
        assert_eq!(
            tracker2.slash_double_sign(&ev2, &pk2, CHAIN_ID).unwrap(),
            1_000
        );
        tracker2.advance_epoch(601).unwrap();
        assert!(
            tracker2.state_of(&val2).unwrap().suspended,
            "pre-existing resume_effective_epoch must not un-suspend a slashed double-signer"
        );
    }

    #[test]
    fn wave3_presence_rejects_duplicate_roster_identity_sum_unregistered_key_and_suspended_rewards()
    {
        let (v1, sk1, pk1) = keypair_for(20);
        let (v2, _sk2, _pk2) = keypair_for(21);
        let (_attacker, attacker_sk, attacker_pk) = keypair_for(22);

        // 1. Duplicate address in roster MUST be rejected by verify_single_pairing.
        let sig1 = sign_presence_signal(v1, CHAIN_ID, 0, PresenceClass::Full, [1; 32], &sk1);
        let dup_roster = vec![(v1, pk1.clone()), (v1, pk1.clone())];
        let dup_agg = PresenceAggregate {
            window: 0,
            class: PresenceClass::Full,
            bitmap: vec![0b0000_0001],
            aggregate_sig: sig1.sig_bls.clone(),
        };
        assert!(
            dup_agg
                .verify_single_pairing(&dup_roster, CHAIN_ID)
                .is_err(),
            "duplicate validator address in roster must be rejected"
        );

        // 2. Rogue-key cancellation (pk + (-pk) == identity) MUST be rejected.
        let neg_pk1 = G2Affine::from(-G2Projective::from(decode_g2(&pk1).unwrap()))
            .to_compressed()
            .to_vec();
        let rogue_roster = vec![(v1, pk1.clone()), (v2, neg_pk1)];
        let id_sig = G1Affine::identity().to_compressed().to_vec();
        let rogue_agg = PresenceAggregate {
            window: 0,
            class: PresenceClass::Full,
            bitmap: vec![0b0000_0011],
            aggregate_sig: id_sig,
        };
        assert!(
            rogue_agg
                .verify_single_pairing(&rogue_roster, CHAIN_ID)
                .is_err(),
            "identity aggregate public key / signature must be rejected"
        );

        // 3. apply_aggregate MUST bind roster key to registered st.bls_public_key.
        let mut tracker = PresenceTracker::new(3, 50);
        tracker.register_validator(v1, PresenceClass::Full, 100_000, 0);
        tracker.register_validator_bls_key(&v1, &pk1);
        let forged_sig =
            sign_presence_signal(v1, CHAIN_ID, 0, PresenceClass::Full, [2; 32], &attacker_sk);
        let forged_roster = vec![(v1, attacker_pk)];
        let forged_agg = PresenceAggregate::build(
            0,
            PresenceClass::Full,
            &forged_roster,
            &[forged_sig],
            CHAIN_ID,
        )
        .unwrap();
        assert!(
            tracker
                .apply_aggregate(&forged_agg, &forged_roster, CHAIN_ID, 0)
                .is_err(),
            "apply_aggregate must reject roster key mismatching registered BLS key"
        );

        // 4. Suspended validator must NOT accrue custody reward windows via
        //    apply_aggregate or record_full_seat_participation.
        tracker.advance_epoch(576).unwrap();
        assert!(tracker.state_of(&v1).unwrap().suspended);
        let honest_roster = vec![(v1, pk1)];
        let sig_576 = sign_presence_signal(v1, CHAIN_ID, 576, PresenceClass::Full, [3; 32], &sk1);
        let agg_576 = PresenceAggregate::build(
            576,
            PresenceClass::Full,
            &honest_roster,
            &[sig_576],
            CHAIN_ID,
        )
        .unwrap();
        let _ = tracker.apply_aggregate(&agg_576, &honest_roster, CHAIN_ID, 576);
        tracker.record_full_seat_participation(&v1, 577);
        assert_eq!(
            tracker.state_of(&v1).unwrap().seen_windows_in_period,
            0,
            "suspended validator must not earn custody presence windows"
        );
        assert_eq!(tracker.reward_multiplier_ppm(&v1, 10), 0);
    }

    #[test]
    fn wave3_presence_rejects_zero_address_and_overwrite_of_slashed_validator_on_reregister() {
        let mut tracker = PresenceTracker::new(3, 50);
        tracker.register_validator(Address::zero(), PresenceClass::Full, 50_000, 0);
        assert!(
            tracker.state_of(&Address::zero()).is_none(),
            "zero address must not be registered in PresenceTracker"
        );

        let (val, sk, pk) = keypair_for(30);
        tracker.register_validator(val, PresenceClass::Mobile, 100_000, 0);
        tracker.register_validator_bls_key(&val, &pk);
        let ev = PresenceDoubleSignEvidence {
            first: sign_presence_signal(val, CHAIN_ID, 12, PresenceClass::Mobile, [1; 32], &sk),
            second: sign_presence_signal(val, CHAIN_ID, 12, PresenceClass::Full, [2; 32], &sk),
        };
        assert_eq!(
            tracker.slash_double_sign(&ev, &pk, CHAIN_ID).unwrap(),
            1_000
        );

        // Re-registering an existing validator must NOT wipe its slash/suspension record.
        tracker.register_validator(val, PresenceClass::Mobile, 100_000, 50);
        let st = tracker.state_of(&val).unwrap();
        assert!(
            st.slashed_double_sign,
            "slash flag must survive re-register"
        );
        assert!(st.suspended, "suspension must survive re-register");
        assert_eq!(st.stake_atoms, 99_000, "slashed stake must not be restored");
        assert_eq!(
            st.bls_public_key, pk,
            "registered BLS key must not be wiped"
        );
    }

    #[test]
    fn wave3_presence_rejects_u64_max_zero_delay_resume_and_bounds_gossip_inbox() {
        let mut tracker = PresenceTracker::new(3, 50);
        let (val, sk, pk) = keypair_for(40);
        tracker.register_validator(val, PresenceClass::Full, 50_000, 0);
        tracker.advance_epoch(576).unwrap();

        // u64::MAX must fail with EpochOverflow instead of 0-epoch same-epoch activation.
        assert_eq!(
            tracker.apply_resume_validator(&val, u64::MAX),
            Err(PresenceError::EpochOverflow)
        );
        // Repeated apply_resume_validator must not postpone an earlier scheduled resume.
        assert_eq!(tracker.apply_resume_validator(&val, 600).unwrap(), 601);
        assert_eq!(tracker.apply_resume_validator(&val, 700).unwrap(), 601);

        // PresenceGossipInbox must reject zero validator address.
        let mut inbox = PresenceGossipInbox::default();
        let zero_sig = sign_presence_signal(
            Address::zero(),
            CHAIN_ID,
            1,
            PresenceClass::Mobile,
            [9; 32],
            &sk,
        );
        assert!(
            inbox.ingest(zero_sig, &pk, CHAIN_ID).is_err(),
            "zero validator address must be rejected by PresenceGossipInbox"
        );

        // PresenceGossipInbox must stay bounded at <= 65_536 entries under flood.
        let template = sign_presence_signal(val, CHAIN_ID, 0, PresenceClass::Mobile, [5; 32], &sk);
        for w in 0..65_536u64 {
            let mut s = template.clone();
            s.window = w;
            inbox.seen.insert((val, w), s);
        }
        let fresh =
            sign_presence_signal(val, CHAIN_ID, 70_000, PresenceClass::Mobile, [6; 32], &sk);
        assert_eq!(
            inbox.ingest(fresh, &pk, CHAIN_ID).unwrap(),
            GossipIngestOutcome::Accepted
        );
        assert!(
            inbox.seen.len() <= 65_536,
            "PresenceGossipInbox::seen must not grow past its cap (got {})",
            inbox.seen.len()
        );
    }
}
