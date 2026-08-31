//! Disk staging: bandwidth-weighted striping across the devices an operator
//! owns.
//!
//! [`crate::residency`] decides *which tier* a weight lives on; this module
//! decides *how the disk tier is read back*. A routed expert staged to disk is
//! a coalesced read. When the operator owns more than one storage device, that
//! read can be split across them, one contiguous chunk per device, and the
//! only way the split is a win instead of a wait is when each device is asked
//! for a share proportional to what it measured. A slow device asked for an
//! equal third of every stripe turns three parallel reads into one slow read:
//! the join waits for the slowest leg.
//!
//! The split therefore follows measured bandwidth, and the measure is a probe
//! the operator runs at startup - the same probe that decides which device
//! holds a shard also decides how much of one it reads. Splitting by a guessed
//! `1 / device_count` is the bug this module exists to refuse: a guessed split
//! is right only for matched devices, and wrong exactly when it costs the
//! most.
//!
//! # Invariants
//!
//! * Chunk sizes sum to exactly the requested length and their offsets are
//!   contiguous. A gap or an overlap is silent corruption, not a slow read.
//! * Equal measured bandwidths produce an equal split.
//! * A device that measures nothing receives nothing, and a plan with no
//!   usable device is refused rather than guessed.
//! * The first device owns offset zero, so the first chunk keeps landing on
//!   the replica the router picked and first-chunk load keeps spreading.
//!
//! Everything here is a pure function of a length and a set of measured
//! weights, so it is testable without disks, threads, or file descriptors.

/// One storage device an operator stages weights on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageDevice {
    /// Stable identity of the device, content-addressed by the operator.
    pub id: [u8; 32],
    /// Sequential read bandwidth the probe measured, in KiB/s.
    pub bandwidth_kib_s: u64,
}

/// Why no stripe plan was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StripeError {
    /// A zero-length read has nothing to stripe.
    NothingToStripe,
    /// No device was given.
    NoDevice,
    /// Every device measured zero bandwidth; a plan over them would be a guess.
    NoUsableDevice,
    /// The sum of the measured weights overflowed.
    WeightOverflow,
}

impl std::fmt::Display for StripeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NothingToStripe => write!(f, "staging: nothing to stripe"),
            Self::NoDevice => write!(f, "staging: no device to stripe across"),
            Self::NoUsableDevice => write!(f, "staging: no device measured usable bandwidth"),
            Self::WeightOverflow => write!(f, "staging: measured weights overflow"),
        }
    }
}

impl std::error::Error for StripeError {}

/// One contiguous byte range assigned to one device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StripeChunk {
    /// The device that reads this range.
    pub device: [u8; 32],
    /// Byte offset of the range within the whole read.
    pub offset: u64,
    /// Length of the range.
    pub len: u64,
}

/// Split a read of `len` bytes across `devices` in proportion to measured
/// bandwidth.
///
/// `devices` order matters: the first entry owns offset zero. A device that
/// measured zero bandwidth receives nothing (but the plan is refused only when
/// *every* device measured zero, because then there is nothing to weight by).
/// The last device in the order absorbs the rounding remainder so the chunks
/// always sum to `len` exactly.
///
/// # Errors
///
/// [`StripeError::NothingToStripe`], [`StripeError::NoDevice`],
/// [`StripeError::NoUsableDevice`], or [`StripeError::WeightOverflow`] as
/// described on the variants.
pub fn stripe_plan(len: u64, devices: &[StorageDevice]) -> Result<Vec<StripeChunk>, StripeError> {
    if len == 0 {
        return Err(StripeError::NothingToStripe);
    }
    if devices.is_empty() {
        return Err(StripeError::NoDevice);
    }

    let mut total_weight: u64 = 0;
    for dev in devices {
        total_weight = total_weight
            .checked_add(dev.bandwidth_kib_s)
            .ok_or(StripeError::WeightOverflow)?;
    }
    if total_weight == 0 {
        return Err(StripeError::NoUsableDevice);
    }

    let mut chunks = Vec::with_capacity(devices.len());
    let mut offset: u64 = 0;
    let mut remaining: u64 = len;

    for (i, dev) in devices.iter().enumerate() {
        let share = if i + 1 == devices.len() {
            // The last device absorbs the rounding remainder, guaranteeing the
            // sum is exactly `len`.
            remaining
        } else {
            // floor(len * w / total). Computed in u128 so the multiply cannot
            // wrap; the result is at most `len` and always fits in u64.
            let share = (u128::from(len) * u128::from(dev.bandwidth_kib_s))
                / u128::from(total_weight);
            u64::try_from(share).map_err(|_| StripeError::WeightOverflow)?
        };
        chunks.push(StripeChunk {
            device: dev.id,
            offset,
            len: share,
        });
        offset = offset.saturating_add(share);
        remaining = remaining.saturating_sub(share);
    }

    Ok(chunks)
}

/// A startup measurement of one device, taken before any placement decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceProbe {
    /// The device the probe measured.
    pub device: StorageDevice,
    /// The bandwidth the probe actually measured, in KiB/s.
    pub measured_kib_s: u64,
}

impl DeviceProbe {
    /// A device whose probe came back empty is not a usable staging device.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        self.measured_kib_s > 0
    }

    /// The weight a stripe plan should use for this device: the measured
    /// bandwidth, so a device the probe weighted down also receives a
    /// proportionally small share of every stripe.
    #[must_use]
    pub const fn weight_kib_s(&self) -> u64 {
        self.measured_kib_s
    }
}

#[cfg(test)]
mod staging_tests {
    use super::*;

    fn dev(id: u8, bw: u64) -> StorageDevice {
        StorageDevice {
            id: [id; 32],
            bandwidth_kib_s: bw,
        }
    }

    fn total(chunks: &[StripeChunk]) -> u64 {
        chunks.iter().map(|c| c.len).sum()
    }

    #[test]
    fn equal_weights_split_evenly() {
        let plan = stripe_plan(1000, &[dev(1, 100), dev(2, 100)]).unwrap();
        assert_eq!(total(&plan), 1000);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].len, 500);
        assert_eq!(plan[1].len, 500);
    }

    #[test]
    fn a_slow_leg_gets_a_proportionally_small_share() {
        // Two fast devices and one measured 25x slower: the slow leg must get
        // a share proportional to its bandwidth, far below an equal third.
        let len = 1_000_000;
        let plan = stripe_plan(len, &[dev(1, 100), dev(2, 100), dev(3, 4)]).unwrap();
        let slow = plan.iter().find(|c| c.device == [3u8; 32]).unwrap();
        let fast = plan.iter().find(|c| c.device == [1u8; 32]).unwrap();
        let equal_third = len / 3;
        assert!(slow.len < equal_third / 2, "slow leg {} must be under half an equal third {}", slow.len, equal_third / 2);
        assert!(fast.len > equal_third * 13 / 10, "fast leg {} must exceed 1.3x an equal third", fast.len);
        assert_eq!(total(&plan), len);
    }

    #[test]
    fn chunks_sum_exactly_and_are_contiguous_for_every_rotation() {
        let devices = [dev(1, 100), dev(2, 50), dev(3, 25)];
        let len = 19_000_000;
        for rotation in 0..devices.len() {
            let mut rotated = devices;
            rotated.rotate_left(rotation);
            let plan = stripe_plan(len, &rotated).unwrap();
            assert_eq!(total(&plan), len, "rotation {rotation} must sum to len");
            let mut cursor: u64 = 0;
            for (i, c) in plan.iter().enumerate() {
                assert_eq!(c.offset, cursor, "rotation {rotation} chunk {i} offset gap");
                assert!(c.len <= len, "rotation {rotation} chunk {i} longer than the read");
                cursor += c.len;
            }
            assert_eq!(cursor, len, "rotation {rotation} must end exactly at len");
        }
    }

    #[test]
    fn the_first_chunk_lands_on_the_first_device() {
        let plan = stripe_plan(5000, &[dev(9, 100), dev(8, 100)]).unwrap();
        assert_eq!(plan[0].offset, 0);
        assert_eq!(plan[0].device, [9u8; 32]);
    }

    #[test]
    fn a_lopsided_weighting_never_goes_negative_or_beyond_the_read() {
        let len = 300;
        let plan = stripe_plan(len, &[dev(1, 1), dev(2, 1), dev(3, 254)]).unwrap();
        assert_eq!(total(&plan), len);
        for c in &plan {
            assert!(c.len <= len);
        }
        // The two tiny legs each get about 1 byte; the fast device the rest.
        let fast = plan.iter().find(|c| c.device == [3u8; 32]).unwrap();
        assert_eq!(fast.len, len - 2);
    }

    #[test]
    fn a_device_that_measured_nothing_receives_nothing() {
        let plan = stripe_plan(1000, &[dev(1, 0), dev(2, 100)]).unwrap();
        let dead = plan.iter().find(|c| c.device == [1u8; 32]).unwrap();
        assert_eq!(dead.len, 0);
        assert_eq!(total(&plan), 1000);
    }

    #[test]
    fn all_zero_bandwidth_is_refused_not_guessed() {
        assert_eq!(
            stripe_plan(1000, &[dev(1, 0), dev(2, 0)]).unwrap_err(),
            StripeError::NoUsableDevice
        );
    }

    #[test]
    fn zero_length_no_device_are_refused() {
        assert_eq!(stripe_plan(0, &[dev(1, 100)]).unwrap_err(), StripeError::NothingToStripe);
        assert_eq!(stripe_plan(100, &[]).unwrap_err(), StripeError::NoDevice);
    }

    #[test]
    fn the_plan_is_deterministic() {
        let devices = [dev(1, 100), dev(2, 50), dev(3, 25)];
        let a = stripe_plan(123_456, &devices).unwrap();
        let b = stripe_plan(123_456, &devices).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn an_unusable_probe_is_not_usable() {
        let good = DeviceProbe { device: dev(1, 100), measured_kib_s: 6400 };
        let bad = DeviceProbe { device: dev(2, 100), measured_kib_s: 0 };
        assert!(good.is_usable());
        assert!(!bad.is_usable());
        assert_eq!(good.weight_kib_s(), 6400);
    }
}
