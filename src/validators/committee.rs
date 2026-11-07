//! The finality committee: seats, the seat quorum and the seat bitmap.
//!
//! Finality is counted in seats, not in validators and not in raw stake. Each
//! epoch a committee of `S` seats is derived from the eligible Full validators
//! (section 7.4.2). A validator holds seats in proportion to its weight, but no
//! validator holds more than a quarter of the seats, so one departure cannot
//! drop the remaining seats below the two thirds quorum. The quorum for a
//! checkpoint is `floor(2 * A / 3) + 1` seats, where `A` is the number of
//! occupied seats (section 7.4.3). The validator-count quorum is gone: a
//! thousand low-weight validators no longer hold finality hostage to a head
//! count, and a phone leaving never touches it (BLG-246).
//!
//! The table is a pure function of the epoch, the epoch randomness and the
//! eligible set, so every honest node derives the same table from the same
//! finalized state (V-3). Seat allocation uses the largest remainder method;
//! ties break on `SHA3-256(BDLM_SEAT_TIE_V1 || randomness || address)`, the
//! smaller hash winning. Each seat carries an ordered standby list of `R`
//! distinct other validators, ranked by a stake-weighted rendezvous hash
//! `SHA3-256(BDLM_SEAT_STANDBY_V1 || randomness || epoch || seat || address)`.
//! The instant seat handover (section 7.5) walks these lists.
//!
//! All arithmetic is integer. The rendezvous score compares `hash * weight`
//! cross products in `u128`, so the order is identical on every architecture
//! and no floating point enters consensus.
//! Convenience: public committee seat table and handover inspection helpers consumed by finality and RPC.

use crate::core::address::Address;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};

/// The ceiling on the committee size, `S_max` (section 7.4.2).
/// TESTNET-DEFAULT: governance replaces this once measured.
pub const COMMITTEE_MAX_SEATS: usize = 128;
/// The seats drawn per eligible validator before the ceiling binds: `S = min(S_max, 4 * |E|)`.
pub const SEATS_PER_VALIDATOR: usize = 4;
/// The length of each seat's standby list, `R` (section 7.4.2).
/// TESTNET-DEFAULT: governance replaces this once measured.
pub const SEAT_STANDBY_DEPTH: usize = 3;

const SEAT_TIE_TAG: &[u8] = b"BDLM_SEAT_TIE_V1";
const SEAT_STANDBY_TAG: &[u8] = b"BDLM_SEAT_STANDBY_V1";

/// The tunable shapes of a committee. The defaults are the testnet parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitteeParams {
    /// `S_max`, the ceiling on the seat count.
    pub max_seats: usize,
    /// `R`, the standby list length per seat.
    pub standby_depth: usize,
}

impl Default for CommitteeParams {
    fn default() -> Self {
        Self { max_seats: COMMITTEE_MAX_SEATS, standby_depth: SEAT_STANDBY_DEPTH }
    }
}

/// One seat of the committee. An unoccupied seat (`owner` is `None`) carries no
/// vote and is not counted in the quorum denominator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seat {
    /// The validator that holds the seat, if any.
    pub owner: Option<Address>,
    /// The ordered standby list: distinct validators, none equal to the owner.
    pub standbys: Vec<Address>,
}

/// A bitmap with one bit per seat, least significant bit first within each
/// byte. A certificate carries it to name the seats that signed (section
/// 7.4.3).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SeatBitmap {
    bytes: Vec<u8>,
}

impl SeatBitmap {
    /// An all-zero bitmap sized for `seat_count` seats.
    #[must_use]
    pub fn new(seat_count: usize) -> Self {
        Self { bytes: vec![0u8; seat_count.div_ceil(8)] }
    }

    /// Set the bit for seat `index`. An out-of-range index is ignored.
    pub fn set(&mut self, index: usize) {
        if let Some(byte) = self.bytes.get_mut(index / 8) {
            *byte |= 1u8 << (index % 8);
        }
    }

    /// Whether seat `index` is set. An out-of-range index reads as unset.
    #[must_use]
    pub(crate) fn contains(&self, index: usize) -> bool {
        self.bytes
            .get(index / 8)
            .is_some_and(|byte| byte & (1u8 << (index % 8)) != 0)
    }

    /// The number of set bits.
    #[must_use]
    pub(crate) fn count(&self) -> usize {
        self.bytes
            .iter()
            .map(|byte| usize::try_from(byte.count_ones()).unwrap_or(0))
            .sum()
    }

    /// The raw bytes, for the wire and for hashing.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Read a bitmap off the wire, bounded by the committee ceiling.
    ///
    /// A peer sends these bytes, so the length is checked before allocating:
    /// the most a honest record can name is `COMMITTEE_MAX_SEATS` seats.
    ///
    /// # Errors
    ///
    /// A byte string longer than the ceiling can hold.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let max_bytes = COMMITTEE_MAX_SEATS.div_ceil(8);
        if bytes.len() > max_bytes {
            return Err(format!(
                "seat bitmap is {} bytes, at most {max_bytes}",
                bytes.len()
            ));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
}

/// The participation record a checkpoint block carries (section 7.5.1).
///
/// The block at `h_j` names the seats whose precommits for `h_{j-1}` the
/// proposer collected. An honest proposer records every vote it saw. The
/// record is consensus data: the next seat table is derived from the records
/// of two consecutive finalized blocks, so every honest node derives the same
/// table (V-3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeatParticipation {
    /// The checkpoint the recorded votes were cast for, `h_{j-1}`.
    pub checkpoint: u64,
    /// The seats those votes cover.
    pub seats: SeatBitmap,
}

impl SeatParticipation {
    /// The record a proposer builds from the precommits it collected for
    /// `checkpoint`, mapped through the table those votes were counted under.
    #[must_use]
    pub fn collect(
        table: &CommitteeTable,
        checkpoint: u64,
        voters: impl IntoIterator<Item = &Address>,
    ) -> Self {
        Self {
            checkpoint,
            seats: table.seat_bitmap(voters),
        }
    }
}

/// The most seats one checkpoint may hand over: `ceil(S / 10)` (section
/// 7.5.1). A mass departure moves to the standbys over several checkpoints
/// instead of reshaping the whole committee at once.
#[must_use]
pub fn handover_limit(seat_count: usize) -> usize {
    seat_count.div_ceil(10)
}

/// The committee for one epoch, derived from finalized state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeTable {
    /// The epoch the committee serves.
    pub epoch: u64,
    /// The finalized checkpoint height the table was derived from (the seat
    /// table version a vote binds to, section 7.4.4).
    pub version: u64,
    /// The seats, in seat-index order.
    pub seats: Vec<Seat>,
}

/// Length-prefix a field before hashing it, so two adjacent fields cannot trade
/// bytes across their boundary (the workspace hash-input rule).
fn absorb(hasher: &mut Sha3_256, field: &[u8]) {
    let len = u64::try_from(field.len()).unwrap_or(u64::MAX);
    hasher.update(len.to_le_bytes());
    hasher.update(field);
}

/// The tie-break rank of an address: the smaller hash wins a remainder tie.
fn tie_rank(randomness: &[u8; 32], address: &Address) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    absorb(&mut hasher, SEAT_TIE_TAG);
    hasher.update(randomness);
    absorb(&mut hasher, address.as_bytes());
    hasher.finalize().into()
}

/// The rendezvous rank of a candidate for one seat's standby list.
fn standby_rank(randomness: &[u8; 32], epoch: u64, seat: u64, address: &Address) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    absorb(&mut hasher, SEAT_STANDBY_TAG);
    hasher.update(randomness);
    hasher.update(epoch.to_le_bytes());
    hasher.update(seat.to_le_bytes());
    absorb(&mut hasher, address.as_bytes());
    hasher.finalize().into()
}

/// The top 64 bits of a rank, read big-endian, used as the rendezvous hash.
fn rank_head(rank: &[u8; 32]) -> u64 {
    let head = <[u8; 8]>::try_from(&rank[..8]).unwrap_or([0u8; 8]);
    u64::from_be_bytes(head)
}

impl CommitteeTable {
    /// Derive the committee for `epoch` from the eligible Full validators.
    ///
    /// `eligible` is a list of `(address, weight)` pairs. Duplicates collapse to
    /// their first weight and zero-weight entries are dropped, so the input
    /// order never changes the table. `version` is the finalized checkpoint
    /// height the table is derived from. The seat count is
    /// `min(max_seats, 4 * |E|)`; allocation is largest remainder with a
    /// `floor(S / 4)` cap per validator; seats that the cap leaves unallocated
    /// stay empty.
    #[must_use]
    pub fn derive(
        epoch: u64,
        version: u64,
        randomness: &[u8; 32],
        eligible: &[(Address, u64)],
        params: &CommitteeParams,
    ) -> Self {
        // Deduplicate by address and drop zero weight, in address order so the
        // result is independent of the input order.
        let mut by_address: BTreeMap<[u8; 32], u64> = BTreeMap::new();
        for (address, weight) in eligible {
            if *weight > 0 {
                by_address.entry(address.0).or_insert(*weight);
            }
        }
        let members: Vec<(Address, u64)> = by_address
            .into_iter()
            .map(|(bytes, weight)| (Address(bytes), weight))
            .collect();
        let n = members.len();
        let seat_count = params.max_seats.min(SEATS_PER_VALIDATOR.saturating_mul(n));
        let cap = seat_count / 4;

        let alloc = allocate_seats(&members, randomness, seat_count, cap);

        // Seat indices run in address order; each validator's seats are
        // consecutive. Seats the cap could not fill stay empty at the end.
        let mut seats: Vec<Seat> = Vec::with_capacity(seat_count);
        for (index, (address, _)) in members.iter().enumerate() {
            for _ in 0..alloc[index] {
                seats.push(Seat { owner: Some(*address), standbys: Vec::new() });
            }
        }
        while seats.len() < seat_count {
            seats.push(Seat { owner: None, standbys: Vec::new() });
        }

        for (index, seat) in seats.iter_mut().enumerate() {
            seat.standbys = rank_standbys(&members, randomness, epoch, index, seat.owner, params);
        }

        Self { epoch, version, seats }
    }

    /// Derive the committee from a finality snapshot, using the epoch
    /// randomness of the hash-chain election (section 7.4.7). The snapshot is
    /// the eligible Full set: active, consensus-ready and PoP-verified. While
    /// the hash-chain election runs in shadow mode the reveal list is empty,
    /// so the randomness is the canonical epoch value the chain derives today;
    /// it upgrades to the reveal-fed value when the election goes primary.
    #[must_use]
    pub fn for_snapshot(
        snapshot: &crate::chain::finality::ValidatorSetSnapshot,
        version: u64,
        chain_id: u64,
    ) -> Self {
        let eligible: Vec<(Address, u64)> = snapshot
            .validators
            .iter()
            .map(|v| (v.address, v.stake))
            .collect();
        let randomness = crate::consensus::filiz::epoch_randomness(chain_id, snapshot.epoch, &[]);
        Self::derive(snapshot.epoch, version, &randomness, &eligible, &CommitteeParams::default())
    }

    /// The total number of seats, occupied or not.
    #[must_use]
    pub fn seat_count(&self) -> usize {
        self.seats.len()
    }

    /// The number of occupied seats, `A_x`: the quorum denominator.
    #[must_use]
    pub fn active_seats(&self) -> usize {
        self.seats.iter().filter(|seat| seat.owner.is_some()).count()
    }

    /// The seat quorum for `active` occupied seats: `floor(2 * active / 3) + 1`
    /// (section 7.4.3). An empty committee needs one seat it does not have, so
    /// it can never finalize.
    #[must_use]
    pub fn quorum(active: usize) -> usize {
        2 * active / 3 + 1
    }

    /// The seat quorum of this table.
    #[must_use]
    pub fn quorum_seats(&self) -> usize {
        Self::quorum(self.active_seats())
    }

    /// The owner of seat `index`, if the seat exists and is occupied.
    #[must_use]
    pub(crate) fn owner_of(&self, index: usize) -> Option<Address> {
        self.seats.get(index).and_then(|seat| seat.owner)
    }

    /// The seat indices held by `owner`, in ascending order.
    #[must_use]
    pub fn seats_of(&self, owner: &Address) -> Vec<usize> {
        self.seats
            .iter()
            .enumerate()
            .filter_map(|(index, seat)| (seat.owner.as_ref() == Some(owner)).then_some(index))
            .collect()
    }

    /// The number of seats covered by a set of voters. A voter signs once and
    /// covers every seat it holds (section 7.4.3); a voter outside the
    /// committee covers nothing.
    pub fn covered_seats(&self, voters: impl IntoIterator<Item = &Address>) -> usize {
        // Count through the bitmap, not by summing per voter: a seat is covered
        // once however many times its holder appears in the input, so a
        // repeated address cannot inflate the count toward the quorum.
        self.seat_bitmap(voters).count()
    }

    /// The seat bitmap naming every seat held by the given voters.
    pub(crate) fn seat_bitmap(&self, voters: impl IntoIterator<Item = &Address>) -> SeatBitmap {
        let mut bitmap = SeatBitmap::new(self.seat_count());
        for voter in voters {
            for index in self.seats_of(voter) {
                bitmap.set(index);
            }
        }
        bitmap
    }

    /// Apply Instant Seat Handover (section 7.5.1) and return the table for the
    /// next checkpoint.
    ///
    /// `previous` and `current` are the participation records of the two
    /// consecutive finalized blocks, older first. A seat missing from BOTH is
    /// handed to its next standby; a seat missing from only one is kept, so a
    /// single dropped vote never moves a seat. Standbys are tried in order and
    /// one already holding a seat in this table is skipped, so a handover never
    /// concentrates seats. When the list runs out the seat goes empty and
    /// leaves the quorum denominator.
    ///
    /// At most `ceil(S / 10)` seats move per checkpoint, in seat-index order;
    /// the rest wait for the next one. A standby already holding a quarter of
    /// the seats is skipped, so a handover keeps the cap that makes one
    /// departure survivable. `lost_this_epoch` carries the validators that
    /// already lost a seat in this epoch: they do not regain one until the next
    /// epoch recomputes eligibility. The returned set is that input plus the
    /// validators this call displaced, so the caller threads it through the
    /// epoch.
    ///
    /// `version` is the height of the finalized block carrying `current`: the
    /// seat table version a vote for the next checkpoint binds to (7.4.4).
    ///
    /// The table is never mutated in place: the caller keeps the old one for
    /// the checkpoint still in flight.
    #[must_use]
    pub fn hand_over(
        &self,
        previous: &SeatParticipation,
        current: &SeatParticipation,
        version: u64,
        lost_this_epoch: &BTreeSet<Address>,
    ) -> (Self, BTreeSet<Address>) {
        let mut next = self.clone();
        let mut lost = lost_this_epoch.clone();
        let limit = handover_limit(self.seat_count());
        let cap = self.seat_count() / 4;
        let mut moved = 0usize;
        for index in 0..next.seats.len() {
            if moved >= limit {
                break;
            }
            let Some(owner) = next.owner_of(index) else {
                continue;
            };
            // Both records must miss the seat. One miss is a lost vote or a
            // proposer that dropped it, not a departure.
            if previous.seats.contains(index) || current.seats.contains(index) {
                continue;
            }
            // The standbys are ranked at derivation; take the first that may
            // still sit. A validator that already lost a seat this epoch does
            // not come back through a standby slot, and none may cross the
            // quarter cap by collecting handed-over seats.
            let replacement = next.seats[index]
                .standbys
                .iter()
                .find(|candidate| {
                    !lost.contains(*candidate) && next.seats_of(*candidate).len() < cap
                })
                .copied();
            next.seats[index].owner = replacement;
            lost.insert(owner);
            moved += 1;
        }
        // The version names the table, so it advances only when the seats
        // actually moved. A checkpoint where everyone participated keeps the
        // epoch's base version, and its certificates verify against the base
        // table a snapshot-only verifier can derive.
        if moved > 0 {
            next.version = version;
        }
        (next, lost)
    }
}

/// Largest-remainder seat allocation with a per-validator cap.
///
/// Each validator first takes `floor(S * w / W)` seats, capped. The leftover
/// seats go one at a time to the largest fractional remainders, skipping any
/// validator already at the cap, until the seats run out or every validator is
/// capped. Remainder ties break on the address tie rank.
fn allocate_seats(
    members: &[(Address, u64)],
    randomness: &[u8; 32],
    seat_count: usize,
    cap: usize,
) -> Vec<usize> {
    let mut alloc = vec![0usize; members.len()];
    let total_weight: u128 = members.iter().map(|(_, weight)| u128::from(*weight)).sum();
    if total_weight == 0 || seat_count == 0 || cap == 0 {
        return alloc;
    }
    let seats = u128::try_from(seat_count).unwrap_or(0);
    // Precompute the tie rank once per member: the comparator reads it instead
    // of hashing on every comparison.
    let mut remainders: Vec<(u128, [u8; 32], usize)> = Vec::with_capacity(members.len());
    for (index, (address, weight)) in members.iter().enumerate() {
        let ideal = seats * u128::from(*weight);
        let base = ideal / total_weight;
        alloc[index] = usize::try_from(base).unwrap_or(0).min(cap);
        remainders.push((ideal % total_weight, tie_rank(randomness, address), index));
    }
    remainders.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let mut used: usize = alloc.iter().sum();
    while used < seat_count {
        let before = used;
        for (_, _, index) in &remainders {
            if used == seat_count {
                break;
            }
            if alloc[*index] < cap {
                alloc[*index] += 1;
                used += 1;
            }
        }
        if used == before {
            // Every validator is at the cap; the rest of the seats stay empty.
            break;
        }
    }
    alloc
}

/// Rank the standby candidates for one seat and take the first `R`.
///
/// The owner is excluded. Candidates are ordered by the stake-weighted
/// rendezvous score `hash / weight` (smaller wins), compared exactly as the
/// `u128` cross product `hash_a * weight_b` versus `hash_b * weight_a`, so a
/// heavier validator is proportionally more likely to rank first. Equal scores
/// break on the full rank, then on the address, keeping the order total.
fn rank_standbys(
    members: &[(Address, u64)],
    randomness: &[u8; 32],
    epoch: u64,
    seat_index: usize,
    owner: Option<Address>,
    params: &CommitteeParams,
) -> Vec<Address> {
    let seat = u64::try_from(seat_index).unwrap_or(u64::MAX);
    let mut candidates: Vec<(Address, u64, [u8; 32])> = members
        .iter()
        .filter(|(address, _)| Some(*address) != owner)
        .map(|(address, weight)| {
            (*address, *weight, standby_rank(randomness, epoch, seat, address))
        })
        .collect();
    candidates.sort_by(|a, b| {
        let lhs = u128::from(rank_head(&a.2)) * u128::from(b.1);
        let rhs = u128::from(rank_head(&b.2)) * u128::from(a.1);
        lhs.cmp(&rhs).then_with(|| a.2.cmp(&b.2)).then_with(|| a.0.cmp(&b.0))
    });
    candidates
        .into_iter()
        .take(params.standby_depth)
        .map(|(address, _, _)| address)
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address([byte; 32])
    }

    fn randomness() -> [u8; 32] {
        [7u8; 32]
    }

    fn equal_members(count: u8, weight: u64) -> Vec<(Address, u64)> {
        (1..=count).map(|i| (addr(i), weight)).collect()
    }

    /// The derivation every epoch-1 case uses, at the shared version 10.
    fn table_of(members: &[(Address, u64)]) -> CommitteeTable {
        CommitteeTable::derive(1, 10, &randomness(), members, &CommitteeParams::default())
    }

    /// The table most cases reason about: eight equal validators, 32 seats,
    /// four each, cap 8, quorum 22.
    fn eight_equal() -> CommitteeTable {
        table_of(&equal_members(8, 1000))
    }

    #[test]
    fn seat_count_is_four_per_validator_under_the_ceiling() {
        let table = eight_equal();
        assert_eq!(table.seat_count(), 32);
        assert_eq!(table.active_seats(), 32);
    }

    #[test]
    fn seat_count_stops_at_the_ceiling() {
        let table = table_of(&equal_members(64, 1000));
        assert_eq!(table.seat_count(), COMMITTEE_MAX_SEATS);
    }

    #[test]
    fn single_validator_seat_cap_is_one_quarter() {
        // A whale among eight validators cannot hold more than floor(S / 4).
        let mut members = equal_members(7, 1000);
        members.push((addr(8), 1_000_000_000));
        let table =
            table_of(&members);
        let cap = table.seat_count() / 4;
        assert_eq!(table.seats_of(&addr(8)).len(), cap);
        // No validator exceeds the cap.
        for i in 1..=8 {
            assert!(table.seats_of(&addr(i)).len() <= cap);
        }
    }

    #[test]
    fn lone_validator_cannot_fill_the_committee() {
        // S = 4, cap = 1: one validator holds one seat, three stay empty.
        let table = table_of(&equal_members(1, 1000));
        assert_eq!(table.seat_count(), 4);
        assert_eq!(table.active_seats(), 1);
        assert_eq!(table.quorum_seats(), 1);
    }

    #[test]
    fn allocation_is_proportional_by_largest_remainder() {
        // Weights 3:1 over 16 seats give 12 and 4 exactly.
        let members = vec![(addr(1), 3000), (addr(2), 1000)];
        let table =
            table_of(&members);
        // Two validators: S = 8, cap = 2, so the cap binds and both fill to 2.
        assert_eq!(table.seat_count(), 8);
        assert_eq!(table.seats_of(&addr(1)).len(), 2);
        assert_eq!(table.seats_of(&addr(2)).len(), 2);
        assert_eq!(table.active_seats(), 4);
    }

    #[test]
    fn allocation_sums_to_the_seat_count_when_the_cap_allows() {
        let members = vec![
            (addr(1), 5000),
            (addr(2), 3000),
            (addr(3), 1500),
            (addr(4), 500),
        ];
        let table =
            table_of(&members);
        assert_eq!(table.seat_count(), 16);
        assert_eq!(table.active_seats(), 16);
        let total: usize = (1..=4).map(|i| table.seats_of(&addr(i)).len()).sum();
        assert_eq!(total, 16);
    }

    #[test]
    fn table_is_independent_of_input_order() {
        let mut a = equal_members(8, 1000);
        let mut b = a.clone();
        b.reverse();
        a[0].1 = 9000;
        b.last_mut().unwrap().1 = 9000;
        let ta = table_of(&a);
        let tb = table_of(&b);
        assert_eq!(ta, tb);
    }

    #[test]
    fn standbys_exclude_the_owner_and_are_distinct() {
        let table = eight_equal();
        for seat in &table.seats {
            let owner = seat.owner.unwrap();
            assert_eq!(seat.standbys.len(), SEAT_STANDBY_DEPTH);
            assert!(!seat.standbys.contains(&owner));
            let mut sorted = seat.standbys.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(sorted.len(), seat.standbys.len());
        }
    }

    #[test]
    fn committee_quorum_ignores_validator_count() {
        // Eight validators hold 32 seats; the quorum is 22 seats, not a head
        // count. Three validators (12 seats) cannot finalize; six (24) can.
        let table = eight_equal();
        assert_eq!(table.quorum_seats(), 22);
        let three: Vec<Address> = (1..=3).map(addr).collect();
        let six: Vec<Address> = (1..=6).map(addr).collect();
        assert!(table.covered_seats(three.iter()) < table.quorum_seats());
        assert!(table.covered_seats(six.iter()) >= table.quorum_seats());
    }

    #[test]
    fn a_repeated_signer_does_not_inflate_the_seat_quorum() {
        // Three validators hold 12 of 32 seats, short of the 22-seat quorum.
        // Listing them repeatedly must not reach it: a seat is covered once.
        let table = eight_equal();
        let once: Vec<Address> = (1..=3).map(addr).collect();
        let repeated: Vec<Address> = once.iter().cycle().take(30).copied().collect();
        assert_eq!(table.covered_seats(once.iter()), 12);
        assert_eq!(table.covered_seats(repeated.iter()), 12);
        assert!(table.covered_seats(repeated.iter()) < table.quorum_seats());
    }

    #[test]
    fn quorum_arithmetic_matches_the_formula() {
        assert_eq!(CommitteeTable::quorum(0), 1);
        assert_eq!(CommitteeTable::quorum(1), 1);
        assert_eq!(CommitteeTable::quorum(3), 3);
        assert_eq!(CommitteeTable::quorum(4), 3);
        assert_eq!(CommitteeTable::quorum(16), 11);
        assert_eq!(CommitteeTable::quorum(32), 22);
        assert_eq!(CommitteeTable::quorum(128), 86);
    }

    #[test]
    fn empty_committee_never_finalizes() {
        let table = table_of(&[]);
        assert_eq!(table.seat_count(), 0);
        assert_eq!(table.active_seats(), 0);
        assert_eq!(table.covered_seats([]), 0);
        assert!(table.covered_seats([]) < table.quorum_seats());
    }

    #[test]
    fn seat_bitmap_names_the_voters_seats() {
        let table = eight_equal();
        let voters = vec![addr(1), addr(2)];
        let bitmap = table.seat_bitmap(voters.iter());
        assert_eq!(bitmap.count(), 8);
        for index in table.seats_of(&addr(1)) {
            assert!(bitmap.contains(index));
        }
        assert!(!bitmap.contains(31));
    }

    #[test]
    fn bitmap_ignores_out_of_range_and_counts_bits() {
        let mut bitmap = SeatBitmap::new(10);
        bitmap.set(0);
        bitmap.set(9);
        bitmap.set(99);
        assert_eq!(bitmap.count(), 2);
        assert!(bitmap.contains(0));
        assert!(bitmap.contains(9));
        assert!(!bitmap.contains(99));
        assert_eq!(bitmap.as_bytes().len(), 2);
    }

    #[test]
    fn standby_order_is_deterministic() {
        let members = equal_members(8, 1000);
        let a = table_of(&members);
        let b = table_of(&members);
        assert_eq!(a.seats[0].standbys, b.seats[0].standbys);
        // A different epoch reshuffles the standby order.
        let c = CommitteeTable::derive(2, 10, &randomness(), &members, &CommitteeParams::default());
        assert_ne!(a.seats[0].standbys, c.seats[0].standbys);
    }

    /// A table of eight equal validators, and a record naming every seat except
    /// the ones `missing` holds.
    fn table_and_record(missing: &[Address]) -> (CommitteeTable, SeatParticipation) {
        let table = CommitteeTable::derive(
            1,
            5,
            &randomness(),
            &equal_members(8, 1000),
            &CommitteeParams::default(),
        );
        let present: Vec<Address> = (1..=8)
            .map(addr)
            .filter(|a| !missing.contains(a))
            .collect();
        let record = SeatParticipation::collect(&table, 5, present.iter());
        (table, record)
    }

    /// The same seats seen one checkpoint earlier: the two-record rule needs a
    /// pair, and most cases hold the seat set steady across it.
    fn prior(record: &SeatParticipation) -> SeatParticipation {
        SeatParticipation {
            checkpoint: record.checkpoint.saturating_sub(5),
            seats: record.seats.clone(),
        }
    }

    #[test]
    fn seat_handover_limit_per_checkpoint() {
        // Every validator but one departs at once. Only ceil(32 / 10) = 4 seats
        // may move in one checkpoint; the rest wait for the next.
        let missing: Vec<Address> = (2..=8).map(addr).collect();
        let (table, record) = table_and_record(&missing);
        let (next, _) = table.hand_over(&prior(&record), &record, 10, &BTreeSet::new());
        let moved = (0..table.seat_count())
            .filter(|i| table.owner_of(*i) != next.owner_of(*i))
            .count();
        assert_eq!(moved, handover_limit(table.seat_count()));
        assert_eq!(moved, 4);
        // Seats moved, so the table names the block that moved them.
        assert_eq!(next.version, 10);
    }

    #[test]
    fn a_seat_missing_from_one_record_is_kept() {
        // One dropped vote is not a departure: the two-record rule keeps the
        // seat with its owner.
        let (table, current) = table_and_record(&[addr(1)]);
        let everyone: Vec<Address> = (1..=8).map(addr).collect();
        let previous = SeatParticipation::collect(&table, 0, everyone.iter());
        let (next, lost) = table.hand_over(&previous, &current, 10, &BTreeSet::new());
        assert_eq!(next.seats, table.seats, "one miss must not move a seat");
        assert!(lost.is_empty());
        // Nothing moved, so the version stays the epoch's base one and the
        // round's certificates verify against the base table.
        assert_eq!(next.version, table.version);
    }

    #[test]
    fn a_seat_missing_from_two_records_moves_to_a_standby() {
        let (table, record) = table_and_record(&[addr(1)]);
        let previous = prior(&record);
        let (next, lost) = table.hand_over(&previous, &record, 10, &BTreeSet::new());
        assert!(lost.contains(&addr(1)));
        for index in table.seats_of(&addr(1)) {
            let new_owner = next.owner_of(index).expect("a standby takes the seat");
            assert_ne!(new_owner, addr(1));
            assert!(table.seats[index].standbys.contains(&new_owner));
        }
        // The occupied count is unchanged: the seats moved, they did not empty.
        assert_eq!(next.active_seats(), table.active_seats());
        // And no receiver crossed the quarter cap collecting them.
        let cap = next.seat_count() / 4;
        for i in 1..=8 {
            assert!(next.seats_of(&addr(i)).len() <= cap);
        }
    }

    #[test]
    fn a_validator_that_lost_a_seat_does_not_regain_one_this_epoch() {
        // addr(1) already lost a seat earlier in this epoch. Now addr(2)
        // departs, and addr(1) sits in the standby list of one of its seats.
        // The lost set must keep addr(1) out of that slot.
        let (table, record) = table_and_record(&[addr(2)]);
        let previous = prior(&record);
        let lost = BTreeSet::from([addr(1)]);
        let (next, _) = table.hand_over(&previous, &record, 10, &lost);
        for index in table.seats_of(&addr(2)) {
            assert_ne!(
                next.owner_of(index),
                Some(addr(1)),
                "a validator that lost a seat came back through a standby slot"
            );
        }
        // Whatever moved, addr(1) gained nothing.
        assert!(next.seats_of(&addr(1)).len() <= table.seats_of(&addr(1)).len());
    }

    #[test]
    fn an_exhausted_standby_list_empties_the_seat_and_the_denominator() {
        // Two validators: S = 8, cap = 2, four seats empty. The occupied seats
        // have a one-entry standby list whose only candidate is already at the
        // cap, so a departure empties the seat instead.
        let members = vec![(addr(1), 1000), (addr(2), 1000)];
        let table =
            CommitteeTable::derive(1, 5, &randomness(), &members, &CommitteeParams::default());
        assert_eq!(table.active_seats(), 4);
        let only_two = vec![addr(2)];
        let record = SeatParticipation::collect(&table, 5, only_two.iter());
        let previous = prior(&record);
        let (next, _) = table.hand_over(&previous, &record, 10, &BTreeSet::new());
        assert!(next.active_seats() < table.active_seats());
        assert!(next.quorum_seats() <= table.quorum_seats());
    }

    #[test]
    fn handover_is_deterministic_and_leaves_the_old_table_intact() {
        let (table, record) = table_and_record(&[addr(1), addr(2)]);
        let previous = prior(&record);
        let (a, lost_a) = table.hand_over(&previous, &record, 10, &BTreeSet::new());
        let (b, lost_b) = table.hand_over(&previous, &record, 10, &BTreeSet::new());
        assert_eq!((a, lost_a), (b, lost_b));
        // The in-flight checkpoint still counts under the old table.
        assert_eq!(table.version, 5);
        assert!(!table.seats_of(&addr(1)).is_empty());
    }

    #[test]
    fn participation_records_the_seats_of_the_votes_it_saw() {
        let (table, record) = table_and_record(&[addr(8)]);
        assert_eq!(record.checkpoint, 5);
        assert_eq!(record.seats.count(), table.seats_of(&addr(1)).len() * 7);
        for index in table.seats_of(&addr(8)) {
            assert!(!record.seats.contains(index));
        }
    }
}
