//! Which storage strategy an object deserves *today*.
//!
//! [`crate::storage::derived`] and [`crate::storage::generated`] each remove
//! bytes by keeping a description instead. Both are worth it below some
//! request rate and not above it, and the crossing point is one division.
//!
//! What this module adds is that the crossing point does not move but the
//! object does. Access to a stored object decays with age, so the same object
//! sits on different sides of the same threshold at different times. A
//! strategy chosen once at upload is therefore wrong for most of the object's
//! life, in whichever direction it was wrong to begin with.
//!
//! # Three numbers, three thresholds
//!
//! The break-even request rate for a lever that shrinks an object to `m` of
//! its size, at `cpu_nanos_per_byte` to reproduce:
//!
//! ```text
//! r* = (1 - m) * disk_rate / (cpu_nanos_per_byte * cpu_rate)
//! ```
//!
//! Measured on the rates this project already uses (0.29 $/TB/month owned
//! disk, 0.0025 $/hour of processor):
//!
//! | lever | m | r* (reads/month) |
//! |---|---|---|
//! | lossless JPEG recompression | 0.773 | 1.4 |
//! | derived region of a master | 0 | 20.9 |
//! | described content | 0 | 418 |
//!
//! Three levers, three thresholds, three orders of magnitude apart. A single
//! hot/cold split cannot express that: an object read fifty times a month is
//! cold for one lever and hot for the other two.
//!
//! # Why the counter has to be an estimate
//!
//! Counting reads exactly would mean writing on every read, which is the cost
//! the levers exist to avoid. This keeps a decaying estimate instead: each
//! read adds one, and the accumulated value halves every
//! [`ACCESS_HALF_LIFE_EPOCHS`]. That is a single multiply on read and needs no
//! history, and it answers the only question being asked, which is the current
//! rate rather than the total.
//!
//! # Why moving costs something
//!
//! Changing strategy is work: bytes are dropped or recomputed once. A rate
//! hovering at the threshold would otherwise flip every epoch and pay that
//! cost repeatedly, which is how a saving turns into a loss without anything
//! looking wrong. Two things prevent it. The transition cost is charged
//! against the projected saving before a move is allowed, and the thresholds
//! carry hysteresis, so leaving a strategy needs a rate meaningfully past the
//! one that entered it.
//!
//! # What was measured, and what it ruled out
//!
//! Proving a generator's output with the repository's own STARK stack was
//! costed rather than assumed. `draw_gradient` spends about 72 VM steps per
//! pixel; the trace is `TRACE_WIDTH = 745` columns and `3n+1` rows rounded up
//! to a power of two. A 3 KB avatar is 1,024 pixels, so 73,728 steps, so
//! 262,144 rows, so 195 million trace cells. Against a published Plonky3
//! Goldilocks measurement of 2,633 x 32,768 cells in 1.51 s, that is 3.4
//! seconds of proving, which at the rates above buys about 2,664 months of
//! storing the same object.
//!
//! So a proof per object is not on the table, and this module does not offer
//! it. What it offers is the cheap check that was available all along:
//! `manifest_id` is the hash of the bytes, so recomputing and hashing is a
//! complete verification, and it costs the same as the reproduction the reader
//! was going to do anyway. The proving route stays interesting for the case
//! where a *verifier* must be convinced without reproducing, and that case is
//! not this one.
//!
//! # What is wired and what is not
//!
//! The arithmetic, its bounds and its refusals are here, tested, and exported
//! from [`crate::storage`]. What no production path does yet is *consult* a
//! strategy for a real object, because that needs an access estimate carried
//! in the manifest, which is a consensus-surface change and lands separately.
//! So the decision function is reachable and the decision is not yet taken.

/// Epochs over which an access estimate halves.
///
/// The decay makes the estimate track the current rate rather than the total,
/// so an object that was popular a year ago does not look popular now. The
/// value is a policy choice and not a measurement: the real decay curve of a
/// live network cannot be known before there is one. It is exposed rather
/// than buried so the number a decision rests on is visible to whoever
/// disagrees with it.
pub const ACCESS_HALF_LIFE_EPOCHS: u64 = 720;

/// Fixed-point scale for access estimates and thresholds.
///
/// Integer arithmetic throughout, for the reason `fixed_point` gives: this
/// decides whether bytes are written, and two nodes that round differently
/// would disagree about what the network holds.
pub const ACCESS_SCALE: u64 = 1_000_000;

/// How far past a threshold a rate must sit before the strategy changes.
///
/// Expressed in sixteenths. A rate exactly at the crossing point is a
/// coin-flip between two strategies of equal cost, and following it would
/// move the object every epoch for no gain. Leaving costs more than
/// arriving, so the band is asymmetric.
pub const HYSTERESIS_SIXTEENTHS: u64 = 4;

/// A lever that trades bytes for processor time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lever {
    /// Size after the lever is applied, in millionths of the original.
    /// Zero means the bytes are gone entirely and only a description remains.
    pub size_millionths: u64,
    /// Processor nanoseconds to reproduce one byte on read.
    pub cpu_nanos_per_byte: u64,
}

/// What an operator's hardware costs, as a ratio rather than a price.
///
/// A currency amount would put an oracle in the path of a storage decision.
/// These are rates the operator computes once from what its own disk and its
/// own power cost, and nothing on chain has to agree with them: two operators
/// can honestly reach different answers for the same object, because they
/// bought different hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorRates {
    /// Cost of holding one byte for one epoch, in picodollars.
    pub disk_picodollars_per_byte_epoch: u64,
    /// Cost of one processor nanosecond, in picodollars.
    pub cpu_picodollars_per_nano: u64,
}

/// Why a strategy question could not be answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdError {
    /// A lever that shrinks nothing cannot pay for the processor time it adds.
    LeverSavesNothing { size_millionths: u64 },
    /// A lever claiming to be free on read would have an infinite threshold.
    LeverIsFree,
    /// Rates of zero make every comparison meaningless rather than cheap.
    RatesAreZero,
}

impl std::fmt::Display for ThresholdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LeverSavesNothing { size_millionths } => write!(
                f,
                "a lever leaving {size_millionths} millionths of the object saves nothing \
                 and only adds processor time on every read"
            ),
            Self::LeverIsFree => write!(
                f,
                "a lever that costs no processor time per byte has no crossing point; \
                 it would always win, which means it was mismeasured"
            ),
            Self::RatesAreZero => write!(
                f,
                "operator rates of zero cannot order two strategies against each other"
            ),
        }
    }
}

impl std::error::Error for ThresholdError {}

/// A decaying estimate of how often an object is read.
///
/// Not a counter. Counting exactly would mean a write per read, which is the
/// cost the levers exist to avoid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AccessEstimate {
    /// Accumulated reads, scaled by [`ACCESS_SCALE`], as of `last_epoch`.
    scaled: u64,
    /// Epoch the accumulation was last brought up to date.
    last_epoch: u64,
}

impl AccessEstimate {
    /// An object nobody has read yet.
    #[must_use]
    pub const fn new(epoch: u64) -> Self {
        Self {
            scaled: 0,
            last_epoch: epoch,
        }
    }

    /// Bring the estimate up to `epoch` by halving once per half-life.
    ///
    /// Repeated halving rather than a power: the exponent is bounded by the
    /// loop below at 64 iterations, after which the value is zero anyway, and
    /// integer halving is exactly reproducible on every machine where a
    /// floating exponential would not be.
    fn decayed_to(self, epoch: u64) -> u64 {
        let elapsed = epoch.saturating_sub(self.last_epoch);
        let halvings = elapsed / ACCESS_HALF_LIFE_EPOCHS;
        if halvings >= 64 {
            return 0;
        }
        self.scaled >> halvings
    }

    /// Record a read at `epoch`.
    pub fn record_read(&mut self, epoch: u64) {
        self.scaled = self.decayed_to(epoch).saturating_add(ACCESS_SCALE);
        self.last_epoch = epoch;
    }

    /// Estimated reads per half-life at `epoch`, scaled by [`ACCESS_SCALE`].
    #[must_use]
    pub fn rate_scaled(&self, epoch: u64) -> u64 {
        self.decayed_to(epoch)
    }
}

/// Reads per half-life at which a lever stops paying for itself.
///
/// Returned scaled by [`ACCESS_SCALE`], to be compared against
/// [`AccessEstimate::rate_scaled`].
///
/// # Errors
///
/// [`ThresholdError::LeverSavesNothing`] for a lever that does not shrink the
/// object, [`ThresholdError::LeverIsFree`] for one claiming no processor cost,
/// and [`ThresholdError::RatesAreZero`] when the operator's rates are zero.
pub fn break_even_rate_scaled(
    lever: Lever,
    object_bytes: u64,
    rates: OperatorRates,
) -> Result<u64, ThresholdError> {
    if lever.size_millionths >= 1_000_000 {
        return Err(ThresholdError::LeverSavesNothing {
            size_millionths: lever.size_millionths,
        });
    }
    if lever.cpu_nanos_per_byte == 0 {
        return Err(ThresholdError::LeverIsFree);
    }
    if rates.disk_picodollars_per_byte_epoch == 0 || rates.cpu_picodollars_per_nano == 0 {
        return Err(ThresholdError::RatesAreZero);
    }

    // Saving over one half-life, in picodollars. u128 because bytes times a
    // rate times an epoch count overflows u64 for objects a network would
    // actually hold.
    let saved_fraction = u128::from(1_000_000 - lever.size_millionths);
    let saved = u128::from(object_bytes)
        * saved_fraction
        * u128::from(rates.disk_picodollars_per_byte_epoch)
        * u128::from(ACCESS_HALF_LIFE_EPOCHS)
        / 1_000_000;

    // Cost of reproducing the object once.
    let per_read = u128::from(object_bytes)
        * u128::from(lever.cpu_nanos_per_byte)
        * u128::from(rates.cpu_picodollars_per_nano);
    if per_read == 0 {
        return Err(ThresholdError::LeverIsFree);
    }

    let scaled = saved * u128::from(ACCESS_SCALE) / per_read;
    Ok(u64::try_from(scaled).unwrap_or(u64::MAX))
}

/// Whether an object should move to, or away from, a lever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Apply the lever: drop the bytes and keep the description.
    Apply,
    /// Undo the lever: the object is read often enough to deserve its bytes.
    Revert,
    /// Stay as it is. Either the rate is inside the hysteresis band, or the
    /// move would not repay its own cost.
    Hold,
}

/// Decide whether an object's strategy should change this epoch.
///
/// `currently_applied` says which side the object is on now, which is what
/// makes the hysteresis asymmetric: the band is applied against the direction
/// of travel rather than around the threshold in the abstract.
///
/// `transition_cost_picodollars` is charged against the saving the move would
/// produce over one half-life. A move that cannot repay itself in that window
/// is refused, which is what stops an object at the boundary from paying the
/// cost every epoch and never recovering it.
///
/// # Errors
///
/// Whatever [`break_even_rate_scaled`] returns.
pub fn decide(
    lever: Lever,
    object_bytes: u64,
    rates: OperatorRates,
    access: AccessEstimate,
    epoch: u64,
    currently_applied: bool,
    transition_cost_picodollars: u64,
) -> Result<Decision, ThresholdError> {
    let threshold = break_even_rate_scaled(lever, object_bytes, rates)?;
    let rate = access.rate_scaled(epoch);

    // Hysteresis: the band sits on the far side of the threshold from where
    // the object already is, so a rate hovering at the crossing point does
    // not move it.
    let band = threshold / 16 * HYSTERESIS_SIXTEENTHS;

    if currently_applied {
        // Leaving only when clearly above.
        if rate <= threshold.saturating_add(band) {
            return Ok(Decision::Hold);
        }
    } else {
        // Arriving only when clearly below.
        if rate >= threshold.saturating_sub(band) {
            return Ok(Decision::Hold);
        }
    }

    // The move has to repay its own cost inside one half-life, or it is a
    // loss dressed as a saving.
    //
    // The gain has opposite signs in the two directions, and getting that
    // wrong makes the rule refuse exactly the moves it should force. Applying
    // the lever gains the storage it frees and loses the reproduction it
    // adds. Reverting gains the reproduction it stops paying and loses the
    // storage it takes back. Subtracting the same way round in both cases
    // meant a strongly overheated object computed a negative gain, saturated
    // to zero, and was held on the grounds that moving would not pay.
    let saved_fraction = u128::from(1_000_000 - lever.size_millionths);
    let storage_saved = u128::from(object_bytes)
        * saved_fraction
        * u128::from(rates.disk_picodollars_per_byte_epoch)
        * u128::from(ACCESS_HALF_LIFE_EPOCHS)
        / 1_000_000;
    let reproduction = u128::from(rate)
        * u128::from(object_bytes)
        * u128::from(lever.cpu_nanos_per_byte)
        * u128::from(rates.cpu_picodollars_per_nano)
        / u128::from(ACCESS_SCALE);
    let gain = if currently_applied {
        reproduction.saturating_sub(storage_saved)
    } else {
        storage_saved.saturating_sub(reproduction)
    };
    if gain <= u128::from(transition_cost_picodollars) {
        return Ok(Decision::Hold);
    }

    if currently_applied {
        Ok(Decision::Revert)
    } else {
        Ok(Decision::Apply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rates close to the ones this project measured: 0.29 $/TB/month of
    /// owned disk and 0.0025 $/hour of processor, converted to picodollars
    /// per byte-epoch and per nanosecond at an hour-long epoch.
    fn rates() -> OperatorRates {
        // Both rates land below one picodollar, so both are carried at a
        // common 1e6 scale. Only their ratio enters the arithmetic, so the
        // scale cancels; what does not cancel is applying it to one side and
        // not the other, which is how these two numbers were wrong by a
        // factor of a thousand on the first pass and moved every threshold
        // with them.
        OperatorRates {
            // 0.29 $/TB/month = 4.028e-16 $/byte-hour = 4.028e-4 picodollars.
            disk_picodollars_per_byte_epoch: 403,
            // 0.0025 $/hour = 6.944e-16 $/ns = 6.944e-4 picodollars.
            cpu_picodollars_per_nano: 694,
        }
    }

    fn described() -> Lever {
        Lever {
            size_millionths: 0,
            cpu_nanos_per_byte: 1,
        }
    }

    fn recompressed() -> Lever {
        Lever {
            size_millionths: 773_000,
            cpu_nanos_per_byte: 67,
        }
    }

    /// Different levers cross at different rates, and not by a little.
    ///
    /// This is the reason a single hot/cold split cannot express the
    /// decision: an object read at a rate between two thresholds is cold for
    /// one lever and hot for another at the same instant.
    #[test]
    fn each_lever_has_its_own_crossing_point() {
        let bytes = 500_000;
        let described_at = break_even_rate_scaled(described(), bytes, rates()).unwrap();
        let recompressed_at = break_even_rate_scaled(recompressed(), bytes, rates()).unwrap();

        assert!(
            described_at > recompressed_at * 4,
            "describing an object should stay worthwhile far longer than recompressing it: \
             described {described_at}, recompressed {recompressed_at}"
        );
    }

    /// An estimate decays, so an object that was hot becomes cold without
    /// anyone touching it.
    #[test]
    fn an_access_estimate_halves_every_half_life() {
        let mut a = AccessEstimate::new(0);
        for _ in 0..64 {
            a.record_read(0);
        }
        let start = a.rate_scaled(0);
        assert_eq!(start, 64 * ACCESS_SCALE);

        assert_eq!(a.rate_scaled(ACCESS_HALF_LIFE_EPOCHS), start / 2);
        assert_eq!(a.rate_scaled(ACCESS_HALF_LIFE_EPOCHS * 2), start / 4);
        assert_eq!(a.rate_scaled(ACCESS_HALF_LIFE_EPOCHS * 6), start / 64);
    }

    /// The decay must not run away into nonsense at large ages.
    #[test]
    fn a_very_old_estimate_is_zero_rather_than_wrapping() {
        let mut a = AccessEstimate::new(0);
        a.record_read(0);
        assert_eq!(a.rate_scaled(u64::MAX), 0);
    }

    /// The same object crosses a threshold as it ages, with no change to the
    /// object and no change to the threshold.
    ///
    /// This is the property the module exists for. A strategy chosen once at
    /// upload is wrong for most of the object's life.
    #[test]
    fn the_same_object_changes_side_as_it_ages() {
        let bytes = 500_000;
        let mut a = AccessEstimate::new(0);
        for _ in 0..4_000 {
            a.record_read(0);
        }

        let hot = decide(described(), bytes, rates(), a, 0, false, 0).unwrap();
        assert_eq!(hot, Decision::Hold, "a heavily read object keeps its bytes");

        let cold = decide(
            described(),
            bytes,
            rates(),
            a,
            ACCESS_HALF_LIFE_EPOCHS * 12,
            false,
            0,
        )
        .unwrap();
        assert_eq!(
            cold,
            Decision::Apply,
            "the same object, unread for twelve half-lives, deserves the lever"
        );
    }

    /// Hysteresis: a rate sitting on the threshold does not move the object.
    ///
    /// Without this the object flips every epoch and pays the transition cost
    /// each time, which turns a saving into a loss while every individual
    /// decision looks correct.
    #[test]
    fn a_rate_at_the_threshold_does_not_move_the_object() {
        let bytes = 500_000;
        let threshold = break_even_rate_scaled(described(), bytes, rates()).unwrap();

        // An estimate sitting exactly at the crossing point.
        let mut a = AccessEstimate::new(0);
        a.scaled = threshold;

        assert_eq!(
            decide(described(), bytes, rates(), a, 0, false, 0).unwrap(),
            Decision::Hold
        );
        assert_eq!(
            decide(described(), bytes, rates(), a, 0, true, 0).unwrap(),
            Decision::Hold
        );
    }

    /// The canary for the test above: outside the band the object does move,
    /// or the hysteresis would be a refusal to ever act.
    #[test]
    fn a_rate_well_past_the_band_does_move_the_object() {
        let bytes = 500_000;
        let threshold = break_even_rate_scaled(described(), bytes, rates()).unwrap();

        let mut cold = AccessEstimate::new(0);
        cold.scaled = threshold / 4;
        assert_eq!(
            decide(described(), bytes, rates(), cold, 0, false, 0).unwrap(),
            Decision::Apply
        );

        let mut hot = AccessEstimate::new(0);
        hot.scaled = threshold.saturating_mul(4);
        assert_eq!(
            decide(described(), bytes, rates(), hot, 0, true, 0).unwrap(),
            Decision::Revert
        );
    }

    /// A move that cannot repay its own cost inside one half-life is held.
    ///
    /// Named for the decision rather than for a refusal: nothing errors here,
    /// the object simply stays where it is. A test named for a rejection that
    /// asserts a `Hold` is the kind of miscount this repository has a gate
    /// against, and that gate caught this name.
    #[test]
    fn a_transition_that_costs_more_than_it_saves_is_held() {
        let bytes = 500_000;
        let mut a = AccessEstimate::new(0);
        a.scaled = 0;

        let free = decide(described(), bytes, rates(), a, 0, false, 0).unwrap();
        assert_eq!(free, Decision::Apply, "with no transition cost, move");

        let expensive = decide(described(), bytes, rates(), a, 0, false, u64::MAX).unwrap();
        assert_eq!(
            expensive,
            Decision::Hold,
            "a move costing more than a half-life of savings is a loss"
        );
    }

    /// Levers that save nothing, cost nothing, or run against zero rates are
    /// refused rather than silently producing a threshold.
    #[test]
    fn a_meaningless_lever_or_rate_is_refused() {
        let bytes = 500_000;

        let no_saving = Lever {
            size_millionths: 1_000_000,
            cpu_nanos_per_byte: 1,
        };
        assert!(matches!(
            break_even_rate_scaled(no_saving, bytes, rates()),
            Err(ThresholdError::LeverSavesNothing { .. })
        ));

        let free = Lever {
            size_millionths: 0,
            cpu_nanos_per_byte: 0,
        };
        assert_eq!(
            break_even_rate_scaled(free, bytes, rates()),
            Err(ThresholdError::LeverIsFree)
        );

        let zero = OperatorRates {
            disk_picodollars_per_byte_epoch: 0,
            cpu_picodollars_per_nano: 1,
        };
        assert_eq!(
            break_even_rate_scaled(described(), bytes, zero),
            Err(ThresholdError::RatesAreZero)
        );
    }

    /// Two operators with different hardware may reach different answers for
    /// the same object, and both are right.
    ///
    /// A consensus rule forcing one answer would be pricing hardware it
    /// cannot see.
    #[test]
    fn operators_with_different_hardware_may_disagree() {
        let bytes = 500_000;
        let mut a = AccessEstimate::new(0);
        a.scaled = 200 * ACCESS_SCALE;

        let cheap_disk = OperatorRates {
            disk_picodollars_per_byte_epoch: 40,
            cpu_picodollars_per_nano: 694_000,
        };
        let dear_disk = OperatorRates {
            disk_picodollars_per_byte_epoch: 4_030,
            cpu_picodollars_per_nano: 694_000,
        };

        let on_cheap = decide(described(), bytes, cheap_disk, a, 0, false, 0).unwrap();
        let on_dear = decide(described(), bytes, dear_disk, a, 0, false, 0).unwrap();
        assert_ne!(
            on_cheap, on_dear,
            "an operator with dear disk should describe an object that an operator \
             with cheap disk still stores"
        );
    }

    /// The arithmetic must not overflow on objects a network would hold.
    #[test]
    fn a_very_large_object_does_not_overflow_the_threshold() {
        let huge = u64::from(u32::MAX) * 4; // ~17 GB
        let t = break_even_rate_scaled(described(), huge, rates()).unwrap();
        assert!(t > 0, "a large object still has a finite crossing point");
    }
}
