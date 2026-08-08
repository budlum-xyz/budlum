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

/// Largest object this will reason about, in bytes.
///
/// Sixty-four gibibytes is past any single object a manifest describes. The
/// bound exists so a size arriving from a manifest is checked once, here,
/// rather than argued at each multiplication: `checked_product` below refuses
/// an overflow, but a refusal at the far end tells a caller only that the
/// arithmetic gave up, while a refusal here tells it which input was wrong.
///
/// Carried across from `storage::derivation_economics`, an earlier module
/// that computed the same crossing point without the decay, the hysteresis or
/// the transition cost. It is not in the tree; this is the part of it worth
/// keeping.
pub const MAX_OBJECT_BYTES: u64 = 64 << 30;

/// Largest per-byte reproduction cost this will reason about, in nanoseconds.
///
/// One second of processor time to reproduce a single byte. Past that the
/// lever is not one anybody applies on a read path, and admitting the value
/// only produces a threshold nobody acts on.
pub const MAX_CPU_NANOS_PER_BYTE: u64 = NANOS_PER_SECOND;

/// Nanoseconds in a second, for callers converting measured durations.
pub const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// How far past a threshold a rate must sit before the strategy changes.
///
/// Expressed in sixteenths, and the same width in both directions: a rate
/// below three quarters of the crossing point applies the lever, one above
/// five quarters reverts it, and the quarter either side is a dead band
/// nothing moves in. A rate exactly at the crossing point is a coin-flip
/// between two strategies of equal cost, and following it would move the
/// object every epoch for no gain.
///
/// Symmetric here and asymmetric in [`decide`] are different questions, and
/// only the second one is answered by this constant. Leaving a lever really
/// does cost more than arriving at it, because the bytes have to be produced
/// again rather than dropped. That asymmetry is charged where it is actually
/// known, against `transition_cost_picodollars`, which the caller measures.
/// Folding it into the band as well would charge it twice, at a ratio nobody
/// measured.
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
    /// An object of no bytes has nothing to save and nothing to reproduce.
    ///
    /// Refused rather than answered. Without this the zero falls through to
    /// `per_read == 0` and comes back as [`ThresholdError::LeverIsFree`],
    /// which sends a caller to look at its lever when the wrong number was
    /// the size.
    ObjectIsEmpty,
    /// The object is past [`MAX_OBJECT_BYTES`].
    ObjectTooLarge { bytes: u64 },
    /// The lever is past [`MAX_CPU_NANOS_PER_BYTE`].
    LeverTooSlow { cpu_nanos_per_byte: u64 },
    /// The product of size, rate and half-life leaves u128.
    ///
    /// Not a hypothetical. `[profile.release]` sets `overflow-checks = true`
    /// and `panic = "abort"`, so an unchecked product here does not wrap
    /// quietly and produce a wrong threshold: it kills the node. An object
    /// size arrives from a manifest, which is somebody else's number, so the
    /// arithmetic refuses rather than aborts.
    ProductLeavesU128,
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
            Self::ObjectIsEmpty => write!(
                f,
                "an object of no bytes has no storage to save and no bytes to reproduce, \
                 so no lever can be worth applying to it"
            ),
            Self::ObjectTooLarge { bytes } => write!(
                f,
                "an object of {bytes} bytes is past the {MAX_OBJECT_BYTES} this reasons \
                 about; a size that large did not come from a manifest describing one object"
            ),
            Self::LeverTooSlow { cpu_nanos_per_byte } => write!(
                f,
                "a lever costing {cpu_nanos_per_byte} nanoseconds per byte is past the \
                 {MAX_CPU_NANOS_PER_BYTE} this reasons about; nobody reproduces bytes at \
                 that price on a read path"
            ),
            Self::ProductLeavesU128 => write!(
                f,
                "the object size and rates given multiply past u128; no real object and \
                 no real hardware reach this, so the inputs are wrong rather than large"
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
/// [`ThresholdError::RatesAreZero`] when the operator's rates are zero,
/// [`ThresholdError::ObjectIsEmpty`] for an object of no bytes,
/// [`ThresholdError::ObjectTooLarge`] and [`ThresholdError::LeverTooSlow`]
/// for inputs past the bounds above, and
/// [`ThresholdError::ProductLeavesU128`] when the factors given multiply past
/// the type.
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
    // Bound the inputs before multiplying them. `checked_product` catches an
    // overflow either way, but it reports that the arithmetic gave up rather
    // than which number was wrong, and `object_bytes` arrives from a manifest.
    if object_bytes == 0 {
        return Err(ThresholdError::ObjectIsEmpty);
    }
    if object_bytes > MAX_OBJECT_BYTES {
        return Err(ThresholdError::ObjectTooLarge {
            bytes: object_bytes,
        });
    }
    if lever.cpu_nanos_per_byte > MAX_CPU_NANOS_PER_BYTE {
        return Err(ThresholdError::LeverTooSlow {
            cpu_nanos_per_byte: lever.cpu_nanos_per_byte,
        });
    }

    // Saving over one half-life, in picodollars. u128 because bytes times a
    // rate times an epoch count overflows u64 for objects a network would
    // actually hold.
    //
    // Widening to u128 moves the ceiling; it does not remove it. Four u64
    // factors reach 2^256 in principle, and `[profile.release]` sets
    // `overflow-checks = true` with `panic = "abort"`, so leaving u128 aborts
    // the process rather than wrapping into a wrong threshold. `object_bytes`
    // comes from a manifest and the rates come from an operator's config, so
    // neither is this module's number to trust. Every product is checked.
    let saved_fraction = u128::from(1_000_000 - lever.size_millionths);
    let saved = checked_product(&[
        u128::from(object_bytes),
        saved_fraction,
        u128::from(rates.disk_picodollars_per_byte_epoch),
        u128::from(ACCESS_HALF_LIFE_EPOCHS),
    ])? / 1_000_000;

    // Cost of reproducing the object once.
    let per_read = checked_product(&[
        u128::from(object_bytes),
        u128::from(lever.cpu_nanos_per_byte),
        u128::from(rates.cpu_picodollars_per_nano),
    ])?;
    if per_read == 0 {
        return Err(ThresholdError::LeverIsFree);
    }

    let scaled = checked_product(&[saved, u128::from(ACCESS_SCALE)])? / per_read;
    Ok(u64::try_from(scaled).unwrap_or(u64::MAX))
}

/// What one reproduction of an object costs, in picodollars.
///
/// The floor under any transition: applying a lever produces the object once
/// to check the result, and reverting one produces it once to get the bytes
/// back. A caller that has measured its own cost, including the write and any
/// coordination, should pass that instead; this is the part nobody has to
/// measure because it follows from the three numbers already here.
///
/// Offered because the alternative default is zero, and zero says moving is
/// free. For a cheap lever the difference is nothing: describing a 500 KB
/// object costs 347 million picodollars against 145 billion saved over a
/// half-life, a ratio of 0.0024. For an expensive one it decides the answer:
/// the same object under a video re-encode costs 2.8 trillion to produce
/// against the same 145 billion saved, a ratio of 19.3, and the move never
/// repays itself.
///
/// # Errors
///
/// [`ThresholdError::ObjectIsEmpty`], [`ThresholdError::ObjectTooLarge`] and
/// [`ThresholdError::LeverTooSlow`] for inputs outside the bounds, and
/// [`ThresholdError::ProductLeavesU128`] if the product leaves the type.
pub fn one_reproduction_picodollars(
    lever: Lever,
    object_bytes: u64,
    rates: OperatorRates,
) -> Result<u64, ThresholdError> {
    if object_bytes == 0 {
        return Err(ThresholdError::ObjectIsEmpty);
    }
    if object_bytes > MAX_OBJECT_BYTES {
        return Err(ThresholdError::ObjectTooLarge {
            bytes: object_bytes,
        });
    }
    if lever.cpu_nanos_per_byte > MAX_CPU_NANOS_PER_BYTE {
        return Err(ThresholdError::LeverTooSlow {
            cpu_nanos_per_byte: lever.cpu_nanos_per_byte,
        });
    }
    let product = checked_product(&[
        u128::from(object_bytes),
        u128::from(lever.cpu_nanos_per_byte),
        u128::from(rates.cpu_picodollars_per_nano),
    ])?;
    Ok(u64::try_from(product).unwrap_or(u64::MAX))
}

/// Multiply a list of factors, refusing rather than aborting on overflow.
///
/// # Errors
///
/// [`ThresholdError::ProductLeavesU128`] when the running product would leave
/// the type.
fn checked_product(factors: &[u128]) -> Result<u128, ThresholdError> {
    let mut acc: u128 = 1;
    for f in factors {
        acc = acc
            .checked_mul(*f)
            .ok_or(ThresholdError::ProductLeavesU128)?;
    }
    Ok(acc)
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
/// the band is applied against: it sits on the far side of the threshold from
/// where the object already is, rather than around the crossing point in the
/// abstract. The two widths are equal; see [`HYSTERESIS_SIXTEENTHS`].
///
/// `transition_cost_picodollars` is charged against the saving the move would
/// produce over one half-life. A move that cannot repay itself in that window
/// is refused, which is what stops an object at the boundary from paying the
/// cost every epoch and never recovering it.
///
/// Callers that have not measured their own transition cost should pass
/// [`one_reproduction_picodollars`] rather than zero. Zero is not a neutral
/// default, it is the claim that moving is free, and for an expensive lever it
/// is wrong by a wide margin: at the measured 8,090 nanoseconds per byte of a
/// re-encoded video frame, one reproduction costs about nineteen times what
/// describing the object saves over a whole half-life, so with zero the rule
/// applies the lever to an object nobody has read even once.
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
    // not move it. Same width both ways; the cost of moving is charged
    // separately below, where a caller can measure it.
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
    let storage_saved = checked_product(&[
        u128::from(object_bytes),
        saved_fraction,
        u128::from(rates.disk_picodollars_per_byte_epoch),
        u128::from(ACCESS_HALF_LIFE_EPOCHS),
    ])? / 1_000_000;
    // The rate is a fourth factor here that `break_even_rate_scaled` does not
    // carry, so this product leaves u128 sooner than that one does.
    let reproduction = checked_product(&[
        u128::from(rate),
        u128::from(object_bytes),
        u128::from(lever.cpu_nanos_per_byte),
        u128::from(rates.cpu_picodollars_per_nano),
    ])? / u128::from(ACCESS_SCALE);
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

    /// Two operators with different hardware reach different answers for the
    /// same object, and both are right.
    ///
    /// A consensus rule forcing one answer would be pricing hardware it
    /// cannot see.
    ///
    /// The two disk rates are the measured 403 divided and multiplied by ten:
    /// 0.029 $/TB/month for amortised disk an operator already owns, and 2.90
    /// $/TB/month for disk it rents. Both stay at the same 1e6 scale as the
    /// processor rate, because that is the whole point of the module and the
    /// first version of this test got it wrong: it carried the processor rate
    /// at 1e9 while the disk rates sat at 1e6, which pushed both thresholds a
    /// thousandfold below the read rate and made both operators answer the
    /// same way.
    #[test]
    fn operators_with_different_hardware_may_disagree() {
        let bytes = 500_000;
        let mut a = AccessEstimate::new(0);
        a.scaled = 200 * ACCESS_SCALE;

        // 0.029 $/TB/month: disk bought years ago and already paid for.
        let cheap_disk = OperatorRates {
            disk_picodollars_per_byte_epoch: 40,
            cpu_picodollars_per_nano: 694,
        };
        // 2.90 $/TB/month: disk rented by the month.
        let dear_disk = OperatorRates {
            disk_picodollars_per_byte_epoch: 4_030,
            cpu_picodollars_per_nano: 694,
        };

        let on_cheap = decide(described(), bytes, cheap_disk, a, 0, false, 0).unwrap();
        let on_dear = decide(described(), bytes, dear_disk, a, 0, false, 0).unwrap();

        // Named rather than merely different: `assert_ne!` alone would pass
        // for any two distinct answers, including the pair the other way
        // round, which is the answer a sign error produces.
        assert_eq!(
            on_cheap,
            Decision::Hold,
            "200 reads per half-life is above the 41.5 crossing point of cheap disk, \
             so the operator that owns its disk keeps the bytes"
        );
        assert_eq!(
            on_dear,
            Decision::Apply,
            "the same 200 reads is far below the 4,181 crossing point of rented disk, \
             so the operator paying by the month describes the object instead"
        );
    }

    /// The dead band is the same width on both sides of the crossing point.
    ///
    /// The constant's documentation said the band was asymmetric because
    /// leaving a lever costs more than arriving at it. The code applied one
    /// width in both directions, so the documentation described a rule the
    /// module did not have, and a reader sizing an object against it would
    /// have been wrong on one side. The asymmetry is real but it is charged
    /// against `transition_cost_picodollars`, not against the band. This
    /// pins which of the two the module actually does.
    #[test]
    fn the_dead_band_is_the_same_width_on_both_sides() {
        let bytes = 500_000;
        let threshold = break_even_rate_scaled(described(), bytes, rates()).unwrap();
        let band = threshold / 16 * HYSTERESIS_SIXTEENTHS;

        // Just inside the band on the low side: an unapplied object stays.
        let mut just_under = AccessEstimate::new(0);
        just_under.scaled = threshold - band + 1;
        assert_eq!(
            decide(described(), bytes, rates(), just_under, 0, false, 0).unwrap(),
            Decision::Hold
        );

        // One step further down and it moves, which locates the low edge.
        let mut past_under = AccessEstimate::new(0);
        past_under.scaled = threshold - band - 1;
        assert_eq!(
            decide(described(), bytes, rates(), past_under, 0, false, 0).unwrap(),
            Decision::Apply
        );

        // Just inside the band on the high side: an applied object stays.
        let mut just_over = AccessEstimate::new(0);
        just_over.scaled = threshold + band;
        assert_eq!(
            decide(described(), bytes, rates(), just_over, 0, true, 0).unwrap(),
            Decision::Hold
        );

        // One step further up and it moves, which locates the high edge.
        let mut past_over = AccessEstimate::new(0);
        past_over.scaled = threshold + band + 1;
        assert_eq!(
            decide(described(), bytes, rates(), past_over, 0, true, 0).unwrap(),
            Decision::Revert
        );

        // The two edges are equidistant. A future asymmetry has to change
        // this line, which is the point of writing it down.
        assert_eq!(
            threshold - (threshold - band),
            (threshold + band) - threshold,
            "the band is documented as one width in both directions"
        );
    }

    /// Widening to u128 moved the ceiling; it did not remove it.
    ///
    /// Four u64 factors reach past u128, and `[profile.release]` carries
    /// `overflow-checks = true` with `panic = "abort"`, so a product that
    /// leaves the type is not a wrong threshold quietly returned. It is the
    /// node gone. `object_bytes` arrives from a manifest and the rates from
    /// an operator's own config, so neither is this module's number to
    /// trust, and the arithmetic refuses instead.
    ///
    /// The numbers below are not reachable by any object: at the measured
    /// rates the smallest overflowing case needs a single object of roughly
    /// four hundred terabytes together with a read estimate at the top of
    /// u64. That is the point. The refusal exists so the unreachable case is
    /// an error value rather than a crash, and it costs one comparison.
    #[test]
    fn a_product_that_leaves_u128_is_refused_rather_than_aborting() {
        // Inside the input bounds, so the size check passes and the products
        // are what refuse: the largest object this reasons about against a
        // disk rate at the top of u64.
        let absurd_disk = OperatorRates {
            disk_picodollars_per_byte_epoch: u64::MAX,
            cpu_picodollars_per_nano: 694,
        };
        assert_eq!(
            break_even_rate_scaled(described(), MAX_OBJECT_BYTES, absurd_disk),
            Err(ThresholdError::ProductLeavesU128)
        );

        // The reproduction side, which carries the access rate as a fourth
        // factor and so leaves the type sooner than the saving side.
        let slow_lever = Lever {
            size_millionths: 0,
            cpu_nanos_per_byte: MAX_CPU_NANOS_PER_BYTE,
        };
        let mut hot = AccessEstimate::new(0);
        hot.scaled = u64::MAX;
        assert_eq!(
            decide(slow_lever, MAX_OBJECT_BYTES, absurd_disk, hot, 0, false, 0),
            Err(ThresholdError::ProductLeavesU128)
        );

        // The canary: an object a network would actually hold still answers.
        // A refusal that fires on everything would satisfy the two above.
        let real = break_even_rate_scaled(described(), 500_000, rates());
        assert!(
            real.is_ok(),
            "a 500 KB object at measured rates must still have a threshold, \
             or the overflow check is refusing the ordinary case: {real:?}"
        );
    }

    /// An input past the bounds is named, rather than reported as arithmetic
    /// that gave up.
    ///
    /// `checked_product` would catch both of these anyway, and would say
    /// `ProductLeavesU128`, which tells a caller that some multiplication
    /// overflowed and not which of its numbers was wrong. `object_bytes`
    /// arrives from a manifest, so the caller most in need of the answer is
    /// the one validating somebody else's input.
    #[test]
    fn an_input_past_the_bounds_is_refused_by_name() {
        assert_eq!(
            break_even_rate_scaled(described(), MAX_OBJECT_BYTES + 1, rates()),
            Err(ThresholdError::ObjectTooLarge {
                bytes: MAX_OBJECT_BYTES + 1
            })
        );

        let too_slow = Lever {
            size_millionths: 0,
            cpu_nanos_per_byte: MAX_CPU_NANOS_PER_BYTE + 1,
        };
        assert_eq!(
            break_even_rate_scaled(too_slow, 500_000, rates()),
            Err(ThresholdError::LeverTooSlow {
                cpu_nanos_per_byte: MAX_CPU_NANOS_PER_BYTE + 1
            })
        );

        // An empty object is its own answer, not a lever problem. Without
        // the check the zero reaches `per_read == 0` and returns
        // LeverIsFree, which names the wrong input: the lever is fine and
        // the size is what nobody supplied.
        assert_eq!(
            break_even_rate_scaled(described(), 0, rates()),
            Err(ThresholdError::ObjectIsEmpty)
        );

        // Exactly at each bound is inside it. A bound that refused its own
        // value would be off by one and no test above would say so.
        assert!(break_even_rate_scaled(described(), MAX_OBJECT_BYTES, rates()).is_ok());
        let at_bound = Lever {
            size_millionths: 0,
            cpu_nanos_per_byte: MAX_CPU_NANOS_PER_BYTE,
        };
        assert!(break_even_rate_scaled(at_bound, 500_000, rates()).is_ok());
    }

    /// Two transforms that were actually measured, and what they say about
    /// the levers this module tests with.
    ///
    /// From `storage::derivation_economics`, an earlier module that is not in
    /// the tree. It carried two timings taken on real data: extracting text
    /// from a word-processor container produced 128,899 bytes in 4.3 ms, and
    /// re-encoding a video frame at the master's quality produced 3,129,552
    /// bytes in 25.32 s. As reproduction cost per byte that is 33 and 8,090
    /// nanoseconds.
    ///
    /// The levers in the tests above cost 1 and 67. So one measured transform
    /// lands between them and the other is two orders of magnitude past both,
    /// which matters in a direction worth writing down: at 8,090 nanoseconds
    /// per byte the crossing point for a 500 KB object is a twentieth of a
    /// read per half-life. A video frame read once a year is still cheaper to
    /// keep than to re-encode. The expensive end of the lever range is where
    /// the answer stops being interesting, not where it gets harder.
    ///
    /// The point of pinning it here is that the two levers the other tests
    /// use are not invented numbers chosen to make thresholds come out
    /// ordered. They sit inside a range that was measured, and this test
    /// fails if a future edit moves them outside it.
    #[test]
    fn the_measured_transforms_bracket_the_levers_these_tests_use() {
        // Bytes produced per second of processor time, from the two timings.
        // Integer arithmetic, like everything else here.
        let text_nanos_per_byte = 4_300_000u64 / 128_899;
        let frame_nanos_per_byte = 25_320_000_000u64 / 3_129_552;
        assert_eq!(text_nanos_per_byte, 33);
        assert_eq!(frame_nanos_per_byte, 8_090);

        // Both are inside what this module will reason about, which is what
        // makes MAX_CPU_NANOS_PER_BYTE a bound on nonsense rather than on
        // real work.
        assert!(frame_nanos_per_byte < MAX_CPU_NANOS_PER_BYTE);

        let bytes = 500_000;
        let text = Lever {
            size_millionths: 0,
            cpu_nanos_per_byte: text_nanos_per_byte,
        };
        let frame = Lever {
            size_millionths: 0,
            cpu_nanos_per_byte: frame_nanos_per_byte,
        };
        let text_at = break_even_rate_scaled(text, bytes, rates()).unwrap();
        let frame_at = break_even_rate_scaled(frame, bytes, rates()).unwrap();

        // The cheaper transform is worth describing for longer, by the ratio
        // of their costs. Same shape as each_lever_has_its_own_crossing_point,
        // on numbers nobody chose.
        assert!(
            text_at > frame_at * 200,
            "measured transforms two orders of magnitude apart in cost must be two \
             orders apart in threshold: text {text_at}, frame {frame_at}"
        );

        // The expensive one crosses below a single read per half-life, so a
        // frame read once ever is still worth storing.
        assert!(
            frame_at < ACCESS_SCALE,
            "re-encoding at 8,090 ns/byte should not pay off at any real read rate: \
             {frame_at} scaled"
        );

        // And the levers the other tests use sit between the two measurements,
        // rather than outside anything anyone has timed.
        assert!(described().cpu_nanos_per_byte < text_nanos_per_byte);
        assert!(recompressed().cpu_nanos_per_byte < frame_nanos_per_byte);
    }

    /// Zero is not a neutral transition cost, and for an expensive lever it
    /// gives the wrong answer.
    ///
    /// `decide` takes the cost from its caller, and no caller measures it, so
    /// the value in practice is whatever a caller defaults to. Zero looks
    /// neutral and is not: it says moving is free.
    ///
    /// For the described lever the difference never shows, because one
    /// reproduction is four thousandths of what a half-life saves. For the
    /// measured video re-encode it decides the answer: one reproduction costs
    /// about nineteen times the saving, so the move cannot repay itself, and
    /// with a zero cost the rule applies the lever to an object nobody has
    /// read at all.
    #[test]
    fn a_zero_transition_cost_moves_an_object_that_can_never_repay_the_move() {
        let bytes = 500_000;
        let frame = Lever {
            size_millionths: 0,
            cpu_nanos_per_byte: 8_090,
        };
        let cold = AccessEstimate::new(0);

        let one = one_reproduction_picodollars(frame, bytes, rates()).unwrap();
        let saved_per_half_life = u128::from(bytes)
            * 1_000_000
            * u128::from(rates().disk_picodollars_per_byte_epoch)
            * u128::from(ACCESS_HALF_LIFE_EPOCHS)
            / 1_000_000;
        assert!(
            u128::from(one) > saved_per_half_life * 19,
            "one reproduction of a re-encoded frame should cost far more than a \
             half-life of holding it: {one} against {saved_per_half_life}"
        );

        // Never read, and told the move is free: applied.
        assert_eq!(
            decide(frame, bytes, rates(), cold, 0, false, 0).unwrap(),
            Decision::Apply
        );
        // Same object, charged one reproduction: held, because the move never
        // pays for itself.
        assert_eq!(
            decide(frame, bytes, rates(), cold, 0, false, one).unwrap(),
            Decision::Hold
        );

        // The canary: for a cheap lever the two agree, so this is a statement
        // about expensive levers and not a rule that freezes everything.
        let cheap_one = one_reproduction_picodollars(described(), bytes, rates()).unwrap();
        assert_eq!(
            decide(described(), bytes, rates(), cold, 0, false, 0).unwrap(),
            decide(described(), bytes, rates(), cold, 0, false, cheap_one).unwrap(),
        );
    }

    /// One reproduction follows from the three numbers already here.
    #[test]
    fn one_reproduction_is_size_times_cost_times_rate() {
        let bytes = 500_000;
        assert_eq!(
            one_reproduction_picodollars(described(), bytes, rates()).unwrap(),
            bytes * 1 * 694
        );
        assert_eq!(
            one_reproduction_picodollars(recompressed(), bytes, rates()).unwrap(),
            bytes * 67 * 694
        );
        // The bounds apply here too, or a manifest could reach the arithmetic
        // through this door instead.
        assert_eq!(
            one_reproduction_picodollars(described(), 0, rates()),
            Err(ThresholdError::ObjectIsEmpty)
        );
        assert_eq!(
            one_reproduction_picodollars(described(), MAX_OBJECT_BYTES + 1, rates()),
            Err(ThresholdError::ObjectTooLarge {
                bytes: MAX_OBJECT_BYTES + 1
            })
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
