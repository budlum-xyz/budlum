//! Instant Task Handover (AGD, Section 7.6), 40-block finality stall disaster
//! recovery mode (Section 7.7), and multi-validator churn simulation.
//! exposed for consensus proposer rotation, checkpoint seat handover, storage
//! task schedulers, and the standalone rehearsal harness. The node's live
//! recovery metric and PoS round path use `validators::handover`; this
//! coordinator remains a separate drill model, not a second chain-state
//! authority.
//!
//! # Risk R-03 (Section 7.7 item 5)
//!
//! When more than one third of active seats vanish simultaneously, BFT finality
//! halts while available-chain block production continues. After
//! [`FINALITY_STALL_RECOVERY_BLOCKS`] (40 blocks = 8 checkpoint intervals), the
//! node raises `budlum_finality_stalled = 1` and enters recovery mode. Once one
//! full epoch elapses in recovery mode, the next epoch's committee is derived
//! from available-chain [`PresenceTracker`] records. During a network partition
//! lasting longer than one epoch, both sides of the partition could derive
//! fork-local recovery committees (Ethereum inactivity-leak risk class, R-03).

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::core::address::Address;
use crate::core::metrics::Metrics;
use crate::registry::presence::{PresenceAggregate, PresenceClass, PresenceTracker};
use crate::storage::bud3::custody::reassign_unacked_share;
use crate::storage::bud3::fountain::{SegmentDecoder, SegmentEncoder, Symbol};
use crate::storage::bud3::limits::Profile;
use crate::storage::bud3::meter::Meter;
use crate::storage::bud3::placement::Share;
use crate::storage::bud3::repair::{handover_expired_repair_duty, ScheduledRepairDuty};

/// Consecutive finalized `SeatParticipation` absences triggering seat handover (Section 7.6 row 2).
pub const SEAT_ABSENCE_HANDOVER_CHECKPOINTS: u64 = 2;

/// Client custody-share read timeout in milliseconds before switching holder (Section 7.6 row 3).
pub const CUSTODY_READ_TIMEOUT_MS: u64 = 2_000;

/// Checkpoint interval in blocks on testnet (5 blocks = 15 seconds).
pub const CHECKPOINT_INTERVAL_BLOCKS: u64 = 5;

/// Blocks without finality before entering disaster recovery mode (Section 7.7: 8 checkpoints = 40 blocks).
pub const FINALITY_STALL_RECOVERY_BLOCKS: u64 = 40;

/// Maximum per-validator seat share cap (`floor(S / 4)`, 25%).
pub const MAX_VALIDATOR_SEAT_FRACTION_DENOM: usize = 4;

/// Every duty governed by Section 7.6 Instant Task Handover (AGD).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HandoverDutyKind {
    BlockProposal,
    FinalitySeat,
    CustodyRead,
    CustodyDurability,
    NewShareAssignment,
    RepairTask,
    UploadGateway,
    CircuitRelay,
    PresenceAggregation,
}

/// Disaster recovery mode state machine (Section 7.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryMode {
    Normal,
    Recovery {
        entered_at_height: u64,
        entered_at_epoch: u64,
    },
}

/// Coordinator executing all nine Section 7.6 Instant Task Handover rules and
/// Section 7.7 finality-stall disaster recovery without human or governance votes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoverCoordinator {
    pub finalized_height: u64,
    pub latest_height: u64,
    pub current_epoch: u64,
    pub recovery_mode: RecoveryMode,
    consecutive_seat_misses: BTreeMap<Address, u64>,
    pending_presence_aggregates: Vec<PresenceAggregate>,
}

impl Default for HandoverCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl HandoverCoordinator {
    #[must_use]
    pub fn new() -> Self {
        Self {
            finalized_height: 0,
            latest_height: 0,
            current_epoch: 0,
            recovery_mode: RecoveryMode::Normal,
            consecutive_seat_misses: BTreeMap::new(),
            pending_presence_aggregates: Vec::new(),
        }
    }

    /// Value of the `budlum_finality_stalled` gauge (`1` in recovery mode, `0` otherwise).
    /// Convenience: exposed for Prometheus exporter and stall assertions.
    #[must_use]
    pub const fn budlum_finality_stalled(&self) -> u8 {
        match self.recovery_mode {
            RecoveryMode::Normal => 0,
            RecoveryMode::Recovery { .. } => 1,
        }
    }

    /// Write `budlum_finality_stalled` to the node [`Metrics`] registry.
    /// Convenience: exposed for block commit metrics hook.
    pub fn sync_metrics(&self, metrics: &Metrics) {
        metrics
            .finality_stalled
            .set(i64::from(self.budlum_finality_stalled()));
    }

    /// Row 1 (Block proposal): deterministic round-robin leader handover when a
    /// slot leader misses its turn (max delay: 1 round = 3 seconds).
    /// Convenience: exposed for PoS round leader selection.
    #[must_use]
    pub fn proposer_for_round(proposers: &[Address], height: u64, round: u64) -> Option<Address> {
        if proposers.is_empty() {
            return None;
        }
        let idx = usize::try_from(height.saturating_add(round) % (proposers.len() as u64)).ok()?;
        proposers.get(idx).copied()
    }

    /// Row 2 (Finality seat): track finalized checkpoint participation; after 2
    /// consecutive absences, replace the seat holder with the first active standby.
    /// Convenience: exposed for finalized checkpoint seat table update.
    pub fn record_checkpoint_participation(
        &mut self,
        active_holders: &mut Vec<Address>,
        participated: &BTreeSet<Address>,
        standby_queue: &[Address],
    ) -> Vec<(Address, Address)> {
        let mut handovers = Vec::new();
        let active_snapshot: BTreeSet<Address> = active_holders.iter().copied().collect();
        let mut used_standbys = BTreeSet::new();

        for slot in active_holders.iter_mut() {
            if participated.contains(slot) {
                self.consecutive_seat_misses.remove(slot);
                continue;
            }
            let misses = self.consecutive_seat_misses.entry(*slot).or_insert(0);
            *misses = misses.saturating_add(1);
            if *misses >= SEAT_ABSENCE_HANDOVER_CHECKPOINTS {
                if let Some(replacement) = standby_queue
                    .iter()
                    .copied()
                    .find(|cand| !active_snapshot.contains(cand) && !used_standbys.contains(cand))
                {
                    let departed = *slot;
                    *slot = replacement;
                    self.consecutive_seat_misses.remove(&departed);
                    used_standbys.insert(replacement);
                    handovers.push((departed, replacement));
                }
            }
        }
        handovers
    }

    /// Row 3 (Custody share read): switch immediately to the next holder once a
    /// holder exceeds [`CUSTODY_READ_TIMEOUT_MS`] (2,000 ms).
    /// Convenience: exposed for client-side symbol retrieval failover.
    #[must_use]
    pub fn select_read_holder_after_timeout(
        holders: &[[u8; 32]],
        timed_out: &BTreeSet<[u8; 32]>,
        elapsed_ms: u64,
    ) -> Option<[u8; 32]> {
        if elapsed_ms < CUSTODY_READ_TIMEOUT_MS {
            return holders.first().copied();
        }
        holders.iter().copied().find(|h| !timed_out.contains(h))
    }

    /// Row 4 (Custody durability): identify shares held by suspended validators so
    /// lazy repair writes replacement symbols to a fresh candidate.
    /// Convenience: exposed for maintenance durability sweep.
    #[must_use]
    pub fn shares_needing_durability_handover(
        shares: &[Share],
        presence: &PresenceTracker,
    ) -> Vec<Share> {
        shares
            .iter()
            .filter(|sh| {
                let addr = Address::from(sh.validator);
                presence.state_of(&addr).is_some_and(|st| st.suspended)
            })
            .copied()
            .collect()
    }

    /// Row 5 (New custody share assignment): hand over an unacknowledged share
    /// after [`SHARE_ASSIGNMENT_ACK_DEADLINE_EPOCHS`] (3 epochs).
    /// Convenience: exposed for epoch custody assignment audit.
    #[must_use]
    pub fn handover_unacked_share(
        share: &Share,
        assigned_epoch: u64,
        acked: bool,
        current_epoch: u64,
        ordered_candidates: &[[u8; 32]],
    ) -> Option<Share> {
        reassign_unacked_share(
            share,
            assigned_epoch,
            acked,
            current_epoch,
            ordered_candidates,
        )
    }

    /// Row 6 (Repair task): hand over an unstarted repair duty after
    /// [`REPAIR_TASK_HANDOVER_BLOCKS`] (20 blocks).
    /// Convenience: exposed for block-level repair task scheduler.
    #[must_use]
    pub fn handover_repair_duty(
        duty: &ScheduledRepairDuty,
        current_height: u64,
        ordered_full_candidates: &[[u8; 32]],
    ) -> Option<ScheduledRepairDuty> {
        handover_expired_repair_duty(duty, current_height, ordered_full_candidates)
    }

    /// Row 7 (Upload gateway): immediate client failover to the next responsive gateway.
    /// Convenience: exposed for upload client gateway failover.
    #[must_use]
    pub fn select_next_upload_gateway(
        gateways: &[Address],
        failed: &BTreeSet<Address>,
    ) -> Option<Address> {
        gateways.iter().copied().find(|g| !failed.contains(g))
    }

    /// Row 8 (Circuit relay): immediate mobile validator failover to the next relay offer.
    /// Convenience: exposed for mobile libp2p relay manager.
    #[must_use]
    pub fn select_next_relay_offer(
        relay_offers: &[Address],
        dropped: &BTreeSet<Address>,
    ) -> Option<Address> {
        relay_offers.iter().copied().find(|r| !dropped.contains(r))
    }

    /// Row 9 (Presence aggregation): if the proposer of block `h` omits a
    /// [`PresenceAggregate`], retain it so the proposer of block `h + 1` includes it.
    /// Convenience: exposed for block proposer presence queue.
    pub fn on_presence_window_ready(&mut self, aggregate: PresenceAggregate, proposer_included: bool) -> Vec<PresenceAggregate> {
        self.pending_presence_aggregates.push(aggregate);
        if proposer_included {
            std::mem::take(&mut self.pending_presence_aggregates)
        } else {
            Vec::new()
        }
    }

    /// Flush all queued [`PresenceAggregate`]s into the next block (`h + 1`).
    /// Convenience: exposed for fallback block proposer assembly.
    pub fn flush_pending_presence_aggregates(&mut self) -> Vec<PresenceAggregate> {
        std::mem::take(&mut self.pending_presence_aggregates)
    }

    /// Observe a new available-chain block at `(height, epoch)` and update
    /// finality-stall disaster recovery state (Section 7.7).
    /// Convenience: exposed for block import recovery monitor.
    pub fn observe_block(&mut self, height: u64, epoch: u64, new_finalized_height: Option<u64>) {
        self.observe_block_at_interval(
            height,
            epoch,
            new_finalized_height,
            CHECKPOINT_INTERVAL_BLOCKS,
        );
    }

    /// Interval-aware form for rehearsals on networks whose checkpoint period
    /// differs from testnet. Eight missed checkpoints trigger recovery.
    /// Convenience: exposed for chain-specific recovery drills.
    pub fn observe_block_at_interval(
        &mut self,
        height: u64,
        epoch: u64,
        new_finalized_height: Option<u64>,
        checkpoint_interval: u64,
    ) {
        self.latest_height = height;
        self.current_epoch = epoch;
        let stall_blocks = 8u64.saturating_mul(checkpoint_interval.max(1));
        if let Some(fin) = new_finalized_height {
            if fin > self.finalized_height {
                self.finalized_height = fin;
            }
            if height.saturating_sub(self.finalized_height) < stall_blocks {
                self.recovery_mode = RecoveryMode::Normal;
                return;
            }
        }
        if matches!(self.recovery_mode, RecoveryMode::Normal)
            && height.saturating_sub(self.finalized_height) >= stall_blocks
        {
            self.recovery_mode = RecoveryMode::Recovery {
                entered_at_height: height,
                entered_at_epoch: epoch,
            };
        }
    }

    /// True once a full epoch has elapsed inside disaster recovery mode so the
    /// next epoch's committee can be derived from available-chain presence (Section 7.7 item 4).
    /// Convenience: exposed for epoch boundary committee builder.
    #[must_use]
    pub const fn can_recompute_recovery_committee(&self, next_epoch: u64) -> bool {
        match self.recovery_mode {
            RecoveryMode::Normal => false,
            RecoveryMode::Recovery {
                entered_at_epoch, ..
            } => next_epoch.saturating_sub(entered_at_epoch) >= 1,
        }
    }

    /// Derive the recovery committee eligible Full validators from available-chain
    /// [`PresenceTracker`] records once one full recovery epoch has passed (Section 7.7 item 4).
    /// Convenience: exposed for disaster recovery committee election.
    #[must_use]
    pub fn compute_recovery_committee(
        &self,
        next_epoch: u64,
        candidates: &[Address],
        presence: &PresenceTracker,
        recent_horizon_epochs: u64,
    ) -> Option<Vec<Address>> {
        if !self.can_recompute_recovery_committee(next_epoch) {
            return None;
        }
        let eligible: Vec<Address> = candidates
            .iter()
            .copied()
            .filter(|addr| {
                presence.state_of(addr).is_some_and(|st| {
                    st.class == PresenceClass::Full
                        && !st.suspended
                        && next_epoch.saturating_sub(st.last_seen_epoch) <= recent_horizon_epochs
                })
            })
            .collect();
        if eligible.is_empty() {
            None
        } else {
            Some(eligible)
        }
    }
}

/// Summary metrics emitted by [`ChurnSimulator::run_blocks`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChurnRunSummary {
    pub blocks_produced: u64,
    pub checkpoints_finalized: u64,
    pub max_finality_gap_checkpoints: u64,
    pub objects_intact: usize,
    pub objects_total: usize,
    pub entered_recovery_mode: bool,
}

#[derive(Debug, Clone)]
struct SimulatedObject {
    original: Vec<u8>,
    profile: Profile,
    holder_symbols: BTreeMap<Address, Vec<Symbol>>,
}

/// In-process N-Full + M-Mobile churn simulator with packet loss, latency,
/// abrupt validator departures/returns, seat handover, and B.U.D. 3.0 object durability.
#[derive(Debug, Clone)]
pub struct ChurnSimulator {
    pub coordinator: HandoverCoordinator,
    pub presence: PresenceTracker,
    pub full_validators: Vec<Address>,
    pub standby_full: Vec<Address>,
    pub mobile_validators: Vec<Address>,
    pub online: BTreeSet<Address>,
    pub packet_drop_ppm: u32,
    pub epoch_len_blocks: u64,
    objects: Vec<SimulatedObject>,
}

impl ChurnSimulator {
    /// Build a simulated network with `n_full` active Full seat holders,
    /// `n_standby` standby Full validators, and `m_mobile` Mobile validators.
    /// Convenience: exposed for `tests/churn` and rehearsal simulations.
    #[must_use]
    pub fn new(n_full: usize, n_standby: usize, m_mobile: usize, epoch_len_blocks: u64) -> Self {
        let mut presence = PresenceTracker::new(3, epoch_len_blocks.max(1));
        let mut full_validators = Vec::with_capacity(n_full);
        let mut standby_full = Vec::with_capacity(n_standby);
        let mut mobile_validators = Vec::with_capacity(m_mobile);
        let mut online = BTreeSet::new();

        for i in 0..n_full {
            let addr = tagged_addr(0x10, i as u64);
            presence.register_validator(addr, PresenceClass::Full, 100_000, 0);
            full_validators.push(addr);
            online.insert(addr);
        }
        for i in 0..n_standby {
            let addr = tagged_addr(0x20, i as u64);
            presence.register_validator(addr, PresenceClass::Full, 100_000, 0);
            standby_full.push(addr);
            online.insert(addr);
        }
        for i in 0..m_mobile {
            let addr = tagged_addr(0x30, i as u64);
            presence.register_validator(addr, PresenceClass::Mobile, 10_000, 0);
            mobile_validators.push(addr);
            online.insert(addr);
        }

        Self {
            coordinator: HandoverCoordinator::new(),
            presence,
            full_validators,
            standby_full,
            mobile_validators,
            online,
            packet_drop_ppm: 0,
            epoch_len_blocks: epoch_len_blocks.max(1),
            objects: Vec::new(),
        }
    }

    /// Store a RaptorQ-coded B.U.D. 3.0 object distributed across Full and Mobile holders
    /// so churn runs verify zero object loss (`objects_intact == objects_total`).
    /// Convenience: exposed for churn durability scenarios.
    pub fn store_coded_object(&mut self, payload: &[u8]) -> Result<(), String> {
        let profile = Profile {
            id: 0,
            qr_version: 40,
            symbol_size: 256,
            fps: 10,
            k_max: 64,
        };
        let enc = SegmentEncoder::new(0, payload, &profile).map_err(|e| format!("{e:?}"))?;
        let mut all_syms = enc.source_symbols();
        let repair = enc
            .repair_symbols(0, enc.k().saturating_mul(2).max(8))
            .map_err(|e| format!("{e:?}"))?;
        all_syms.extend(repair);

        let mut holders: Vec<Address> = self.full_validators.clone();
        holders.extend(self.standby_full.iter().copied());
        holders.extend(self.mobile_validators.iter().take(8).copied());
        if holders.is_empty() {
            return Err("no holders in simulator".to_owned());
        }

        let mut holder_symbols: BTreeMap<Address, Vec<Symbol>> = BTreeMap::new();
        for (idx, sym) in all_syms.into_iter().enumerate() {
            if let Some(h) = holders.get(idx % holders.len()) {
                holder_symbols.entry(*h).or_default().push(sym);
            }
        }
        self.objects.push(SimulatedObject {
            original: payload.to_vec(),
            profile,
            holder_symbols,
        });
        Ok(())
    }

    /// Stop `validators` abruptly (simulating crash or sudden disconnect).
    /// Convenience: exposed for churn fault injection.
    pub fn set_offline(&mut self, validators: &[Address]) {
        for v in validators {
            self.online.remove(v);
        }
    }

    /// Return `validators` online.
    /// Convenience: exposed for churn recovery injection.
    pub fn set_online(&mut self, validators: &[Address]) {
        for v in validators {
            self.online.insert(*v);
        }
    }

    /// Run `num_blocks` blocks, executing checkpoint quorum checks (`floor(2*S/3) + 1`
    /// over Full seats ONLY; Mobile count never enters finality quorum), Instant Seat
    /// Handover, 40-block disaster recovery mode, and coded object reconstruction checks.
    /// Convenience: exposed for churn test scenarios.
    pub fn run_blocks(&mut self, num_blocks: u64) -> ChurnRunSummary {
        let mut checkpoints_finalized = 0u64;
        let mut max_gap_blocks = 0u64;
        let mut entered_recovery_mode = false;
        let start_height = self.coordinator.latest_height.saturating_add(1);
        let end_height = self.coordinator.latest_height.saturating_add(num_blocks);

        for h in start_height..=end_height {
            let epoch = h / self.epoch_len_blocks;
            for v in &self.full_validators {
                if self.online.contains(v) {
                    self.presence.record_full_seat_participation(v, epoch);
                }
            }
            for v in &self.standby_full {
                if self.online.contains(v) {
                    self.presence.record_full_seat_participation(v, epoch);
                }
            }

            let mut new_fin = None;
            if h % CHECKPOINT_INTERVAL_BLOCKS == 0 && !self.full_validators.is_empty() {
                let seats = self.full_validators.len();
                let quorum = (seats.saturating_mul(2) / 3).saturating_add(1);
                let participated: BTreeSet<Address> = self
                    .full_validators
                    .iter()
                    .copied()
                    .enumerate()
                    .filter(|(idx, v)| {
                        self.online.contains(v) && !dropped_packet(h, *idx as u64, self.packet_drop_ppm)
                    })
                    .map(|(_, v)| v)
                    .collect();

                if participated.len() >= quorum {
                    new_fin = Some(h);
                    checkpoints_finalized = checkpoints_finalized.saturating_add(1);
                    let standby = self.standby_full.clone();
                    let _ = self.coordinator.record_checkpoint_participation(
                        &mut self.full_validators,
                        &participated,
                        &standby,
                    );
                }
            }

            self.coordinator.observe_block(h, epoch, new_fin);
            if matches!(self.coordinator.recovery_mode, RecoveryMode::Recovery { .. }) {
                entered_recovery_mode = true;
                let mut pool = self.full_validators.clone();
                pool.extend(self.standby_full.iter().copied());
                pool.sort();
                pool.dedup();
                if let Some(recovered) =
                    self.coordinator
                        .compute_recovery_committee(epoch.saturating_add(1), &pool, &self.presence, 2)
                {
                    self.full_validators = recovered;
                }
            }

            let gap = h.saturating_sub(self.coordinator.finalized_height);
            if gap > max_gap_blocks {
                max_gap_blocks = gap;
            }
        }

        let objects_intact = self.count_reconstructible_objects();
        ChurnRunSummary {
            blocks_produced: num_blocks,
            checkpoints_finalized,
            max_finality_gap_checkpoints: max_gap_blocks / CHECKPOINT_INTERVAL_BLOCKS,
            objects_intact,
            objects_total: self.objects.len(),
            entered_recovery_mode,
        }
    }

    fn count_reconstructible_objects(&self) -> usize {
        let mut intact = 0usize;
        for obj in &self.objects {
            let Ok(mut dec) = SegmentDecoder::new(0, obj.original.len() as u64, &obj.profile) else {
                continue;
            };
            let mut meter = Meter::new(1 << 20, 1 << 20);
            for (holder, syms) in &obj.holder_symbols {
                if !self.online.contains(holder) {
                    continue;
                }
                for sym in syms {
                    if dec.is_done() {
                        break;
                    }
                    let _ = dec.push(sym, &mut meter);
                }
            }
            if dec.into_bytes().as_deref() == Some(obj.original.as_slice()) {
                intact = intact.saturating_add(1);
            }
        }
        intact
    }
}

fn tagged_addr(tag: u8, idx: u64) -> Address {
    let mut raw = [0u8; 32];
    if let Some(first) = raw.first_mut() {
        *first = tag;
    }
    if let Some(slice) = raw.get_mut(1..9) {
        slice.copy_from_slice(&idx.to_le_bytes());
    }
    Address::from(raw)
}

fn dropped_packet(height: u64, idx: u64, drop_ppm: u32) -> bool {
    if drop_ppm == 0 {
        return false;
    }
    let mix = height
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(idx.wrapping_mul(0xBF58_476D_1CE4_E5B9));
    (mix % 1_000_000) < u64::from(drop_ppm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::bud3::placement::Class;

    #[test]
    fn proposer_round_handover() {
        let proposers = vec![
            Address::from([1u8; 32]),
            Address::from([2u8; 32]),
            Address::from([3u8; 32]),
        ];
        let r0 = HandoverCoordinator::proposer_for_round(&proposers, 10, 0).unwrap();
        let r1 = HandoverCoordinator::proposer_for_round(&proposers, 10, 1).unwrap();
        assert_ne!(r0, r1);
        assert_eq!(r0, proposers[1]);
        assert_eq!(r1, proposers[2]);
    }

    #[test]
    fn repair_task_handover_after_20_blocks() {
        let duty = ScheduledRepairDuty {
            object: [0xAB; 32],
            segment: 0,
            assignee: [1u8; 32],
            assigned_height: 100,
            started: false,
        };
        let candidates = [[1u8; 32], [2u8; 32], [3u8; 32]];
        // At +19 blocks: still owned by original assignee.
        assert!(HandoverCoordinator::handover_repair_duty(&duty, 119, &candidates).is_none());
        // At +20 blocks: handed over to next Full candidate `[2u8; 32]`.
        let reassigned =
            HandoverCoordinator::handover_repair_duty(&duty, 120, &candidates).unwrap();
        assert_eq!(reassigned.assignee, [2u8; 32]);
        assert_eq!(reassigned.assigned_height, 120);
    }

    #[test]
    fn custody_assignment_handover_after_3_epochs() {
        let share = Share {
            validator: [10u8; 32],
            class: Class::Mobile,
            first_esi: 4,
            symbols: 2,
        };
        let candidates = [[10u8; 32], [11u8; 32]];
        assert!(
            HandoverCoordinator::handover_unacked_share(&share, 5, false, 7, &candidates).is_none()
        );
        let next =
            HandoverCoordinator::handover_unacked_share(&share, 5, false, 8, &candidates).unwrap();
        assert_eq!(next.validator, [11u8; 32]);
        assert_eq!(next.first_esi, 4);
    }

    #[test]
    fn presence_aggregate_fallback_next_block() {
        let mut coord = HandoverCoordinator::new();
        let agg = PresenceAggregate {
            window: 7,
            class: PresenceClass::Mobile,
            bitmap: vec![0b0000_0001],
            aggregate_sig: vec![0x11; 48],
        };
        // Block `h` proposer omits the aggregate -> retained in queue.
        assert!(coord.on_presence_window_ready(agg.clone(), false).is_empty());
        // Block `h + 1` proposer flushes and includes it -> 1-block max delay.
        let flushed = coord.flush_pending_presence_aggregates();
        assert_eq!(flushed, vec![agg]);
    }

    #[test]
    fn ten_percent_full_departure_keeps_finality() {
        let mut sim = ChurnSimulator::new(10, 3, 200, 10);
        sim.store_coded_object(&b"resilient object under 10% full departure".repeat(40))
            .unwrap();
        // 10% of Full validators (1 of 10) depart abruptly.
        let departed = [sim.full_validators[0]];
        sim.set_offline(&departed);

        let summary = sim.run_blocks(30);
        assert_eq!(summary.checkpoints_finalized, 6);
        assert!(summary.max_finality_gap_checkpoints <= 2);
        assert_eq!(summary.objects_intact, summary.objects_total);
        assert!(!summary.entered_recovery_mode);
    }

    #[test]
    fn all_mobile_departure_does_not_touch_finality() {
        let mut baseline = ChurnSimulator::new(8, 2, 500, 10);
        let base_summary = baseline.run_blocks(25);

        let mut churned = ChurnSimulator::new(8, 2, 500, 10);
        churned
            .store_coded_object(&b"object survives 100% mobile departure via full shares".repeat(32))
            .unwrap();
        // Stop ALL 500 Mobile validators simultaneously!
        let all_mobile = churned.mobile_validators.clone();
        churned.set_offline(&all_mobile);

        let summary = churned.run_blocks(25);
        assert_eq!(summary.checkpoints_finalized, base_summary.checkpoints_finalized);
        assert_eq!(
            summary.max_finality_gap_checkpoints,
            base_summary.max_finality_gap_checkpoints
        );
        assert_eq!(summary.objects_intact, 1);
    }

    #[test]
    fn finality_stall_enters_recovery_mode() {
        let mut sim = ChurnSimulator::new(9, 0, 50, 10);
        // Take 4 of 9 (> 1/3) Full validators offline so finality stalls!
        let offline: Vec<Address> = sim.full_validators[..4].to_vec();
        sim.set_offline(&offline);

        // Run 40 blocks (8 checkpoints): enters disaster recovery mode and sets gauge to 1!
        let stalled = sim.run_blocks(40);
        assert!(stalled.entered_recovery_mode);
        assert_eq!(sim.coordinator.budlum_finality_stalled(), 1);
        let metrics = Metrics::new().unwrap();
        sim.coordinator.sync_metrics(&metrics);
        assert_eq!(metrics.finality_stalled.get(), 1);

        // Run 25 more blocks (> 1 full recovery epoch): available-chain presence derives
        // the 5 surviving Full validators as the recovery committee and finality resumes!
        let recovered = sim.run_blocks(25);
        assert!(recovered.checkpoints_finalized > 0);
        assert_eq!(sim.coordinator.budlum_finality_stalled(), 0);
    }
}
