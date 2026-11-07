//! Validator presence protocol, non-slashing suspension, and single-pairing BLS
//! aggregate verification (Section 7.8, Section 6.21.3, Section 11.7; ).
//! exposed for budlum-mobile-core, consensus block proposer, and handover coordinator.
//!
//! Offline validators are suspended (`Suspended`), never slashed (invariant V-4,
//! closing ). Equivocating across distinct [`PresenceClass`] tags in the
//! same presence window is a provable double-sign slashed at 1% of stake.

use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};

use crate::chain::finality::{sign_bls, verify_bls_sig};
use crate::core::address::Address;

/// Gossip topic for validator presence signals (Section 7.8 item 3).
pub const PRESENCE_GOSSIP_TOPIC: &str = "/budlum/presence/1";

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

/// Presence class tag carried in `PresenceSignal` and signed under `BDLM_PRESENCE_V1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum PresenceClass {
    /// Dedicated Full validator (1-epoch window, 24h suspension threshold).
    Full = 0x00,
    /// Android Mobile validator (4-epoch window, 72h suspension threshold).
    Mobile = 0x01,
    /// iOS opportunistic Mobile validator (4-epoch window, 168h suspension threshold).
    IosOpportunistic = 0x02,
}

impl PresenceClass {
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    /// Convenience: exposed for mobile and full task engines querying window cadence.
    #[must_use]
    pub const fn window_epochs(self) -> u64 {
        match self {
            Self::Full => FULL_PRESENCE_WINDOW_EPOCHS,
            Self::Mobile | Self::IosOpportunistic => MOBILE_PRESENCE_WINDOW_EPOCHS,
        }
    }

    #[must_use]
    pub const fn suspension_hours(self) -> u64 {
        match self {
            Self::Full => FULL_SUSPENSION_HOURS,
            Self::Mobile => MOBILE_SUSPENSION_HOURS,
            Self::IosOpportunistic => IOS_OPPORTUNISTIC_SUSPENSION_HOURS,
        }
    }
}

/// Convert an offline duration in hours to a ceiling epoch count (Section 6.21.3):
/// `ceil(hours * 3600 / (slot_secs * epoch_len_blocks))`.
/// Convenience: exposed for validator class and governance parameter checks.
#[must_use]
pub fn hours_to_epochs(hours: u64, slot_secs: u64, epoch_len_blocks: u64) -> Result<u64, PresenceError> {
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

/// Canonical 32-byte signing digest for a presence window (Section 7.8 item 2):
/// `SHA3-256("BDLM_PRESENCE_V1" || chain_id_le8 || window_le8 || class_u8)`.
#[must_use]
pub fn presence_signing_digest(chain_id: u64, window: u64, class: PresenceClass) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_PRESENCE_V1");
    h.update(chain_id.to_le_bytes());
    h.update(window.to_le_bytes());
    h.update([class.to_byte()]);
    h.finalize().into()
}

/// Individual gossip presence message on `/budlum/presence/1` (Section 7.8 item 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceSignal {
    pub validator: Address,
    pub window: u64,
    pub class: PresenceClass,
    /// Hash of the validator's IPv4 /24 or IPv6 /48 prefix.
    pub network_hint: [u8; 32],
    /// 48-byte compressed BLS12-381 G1 signature over [`presence_signing_digest`].
    pub sig_bls: Vec<u8>,
}

impl PresenceSignal {
    /// Sign a presence signal for `(chain_id, window, class)` using `secret_key`.
    /// Convenience: exposed for full and mobile validator presence signers.
    #[must_use]
    pub fn sign(
        validator: Address,
        chain_id: u64,
        window: u64,
        class: PresenceClass,
        network_hint: [u8; 32],
        secret_key: &Scalar,
    ) -> Self {
        let digest = presence_signing_digest(chain_id, window, class);
        let sig_bls = sign_bls(secret_key, &digest);
        Self {
            validator,
            window,
            class,
            network_hint,
            sig_bls,
        }
    }

    /// Verify this presence signal against the validator's 96-byte BLS public key.
    pub fn verify(&self, bls_public_key: &[u8], chain_id: u64) -> Result<(), PresenceError> {
        let digest = presence_signing_digest(chain_id, self.window, self.class);
        verify_bls_sig(bls_public_key, &digest, &self.sig_bls)
            .map_err(PresenceError::InvalidSignature)
    }
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
    DroppedDuplicate { peer_score_delta: i32 },
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
    pub fn ingest(
        &mut self,
        signal: PresenceSignal,
        bls_public_key: &[u8],
        chain_id: u64,
    ) -> Result<GossipIngestOutcome, PresenceError> {
        signal.verify(bls_public_key, chain_id)?;
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
            sig.verify(pk, chain_id)?;
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

        Ok(Self {
            window,
            class,
            bitmap,
            aggregate_sig: G1Affine::from(sum_sig).to_compressed().to_vec(),
        })
    }

    /// Verify the aggregate in ONE BLS pairing check by summing the G2 public keys
    /// selected by `bitmap` and checking `verify_bls_sig(agg_pk, digest, aggregate_sig)`.
    /// Returns the verified present validator addresses.
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

        let mut sum_pk = G2Projective::identity();
        let mut present = Vec::new();
        for (idx, (addr, pk_bytes)) in roster.iter().enumerate() {
            let byte_idx = idx / 8;
            let bit_idx = idx % 8;
            let is_set = self
                .bitmap
                .get(byte_idx)
                .map(|b| (*b >> bit_idx) & 1 == 1)
                .unwrap_or(false);
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

        let agg_pk_bytes = G2Affine::from(sum_pk).to_compressed();
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
    pub fn register_validator(
        &mut self,
        validator: Address,
        class: PresenceClass,
        stake_atoms: u64,
        registered_epoch: u64,
    ) {
        self.validators.insert(
            validator,
            ValidatorPresenceState {
                class,
                stake_atoms,
                last_seen_epoch: registered_epoch,
                last_seen_window: None,
                seen_windows_in_period: 0,
                suspended: false,
                resume_effective_epoch: None,
                slashed_double_sign: false,
            },
        );
    }

    /// Convenience: exposed for RPC and consensus eligibility queries.
    #[must_use]
    pub fn state_of(&self, validator: &Address) -> Option<&ValidatorPresenceState> {
        self.validators.get(validator)
    }

    /// Record verified block [`PresenceAggregate`] signers at `current_epoch`.
    /// Convenience: exposed for block execution presence aggregate hook.
    pub fn apply_aggregate(
        &mut self,
        aggregate: &PresenceAggregate,
        roster: &[(Address, Vec<u8>)],
        chain_id: u64,
        current_epoch: u64,
    ) -> Result<Vec<Address>, PresenceError> {
        let present = aggregate.verify_single_pairing(roster, chain_id)?;
        for addr in &present {
            if let Some(st) = self.validators.get_mut(addr) {
                if st.class == aggregate.class && st.last_seen_window != Some(aggregate.window) {
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
            if st.class == PresenceClass::Full && st.last_seen_epoch < current_epoch {
                st.last_seen_epoch = current_epoch;
                if st.last_seen_window != Some(current_epoch) {
                    st.last_seen_window = Some(current_epoch);
                    st.seen_windows_in_period = st.seen_windows_in_period.saturating_add(1);
                }
            }
        }
    }

    /// Synchronize consecutive epoch-miss tracking from [`crate::registry::LivenessTracker`]
    /// into non-slashing suspension notices (V-4, ).
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
    pub fn advance_epoch(&mut self, current_epoch: u64) -> Result<BTreeSet<Address>, PresenceError> {
        let mut newly_suspended = BTreeSet::new();
        let slot_secs = self.slot_secs;
        let epoch_len = self.epoch_len_blocks;

        for (addr, st) in &mut self.validators {
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
    pub fn apply_resume_validator(
        &mut self,
        validator: &Address,
        current_epoch: u64,
    ) -> Result<u64, PresenceError> {
        let st = self
            .validators
            .get_mut(validator)
            .ok_or(PresenceError::UnknownValidator)?;
        if !st.suspended {
            return Err(PresenceError::ValidatorNotSuspended);
        }
        let effective = current_epoch.saturating_add(RESUME_ACTIVATION_DELAY_EPOCHS);
        st.resume_effective_epoch = Some(effective);
        Ok(effective)
    }

    /// Verify and apply a 1% stake slash for signing two different [`PresenceClass`]
    /// tags in the same presence window (Section 7.8 item 8, Section 11.7).
    /// Convenience: exposed for equivocation evidence processing.
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
        evidence.first.verify(bls_public_key, chain_id)?;
        evidence.second.verify(bls_public_key, chain_id)?;

        let st = self
            .validators
            .get_mut(&evidence.first.validator)
            .ok_or(PresenceError::UnknownValidator)?;
        if st.slashed_double_sign {
            return Ok(0);
        }
        let slash_atoms = u64::try_from(
            u128::from(st.stake_atoms)
                .saturating_mul(u128::from(PRESENCE_DOUBLE_SIGN_SLASH_PPM))
                / 1_000_000,
        )
        .unwrap_or(u64::MAX);
        st.stake_atoms = st.stake_atoms.saturating_sub(slash_atoms);
        st.slashed_double_sign = true;
        st.suspended = true;
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
    InvalidBitmapLength,
    InvalidBitmapTrailingBits,
    InvalidSignature(String),
    InvalidDoubleSignEvidence,
    UnknownValidator,
    ValidatorNotSuspended,
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
                signals.push(PresenceSignal::sign(
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
        tracker.register_validator(val, PresenceClass::Mobile, 100_000, 0);

        let mut inbox = PresenceGossipInbox::default();
        let sig_mobile = PresenceSignal::sign(val, CHAIN_ID, 42, PresenceClass::Mobile, [1; 32], &sk);
        let sig_dup = PresenceSignal::sign(val, CHAIN_ID, 42, PresenceClass::Mobile, [2; 32], &sk);
        let sig_full = PresenceSignal::sign(val, CHAIN_ID, 42, PresenceClass::Full, [1; 32], &sk);

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
        assert!(liveness.record_suspension_epoch(1, &[v], |_| false, 3).is_empty());
        assert!(liveness.record_suspension_epoch(2, &[v], |_| false, 3).is_empty());
        let notices = liveness.record_suspension_epoch(3, &[v], |_| false, 3);
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].validator, v);
        assert_eq!(notices[0].missed_epochs, 3);
        assert_eq!(notices[0].stake_slashed_atoms, 0);
    }
}
