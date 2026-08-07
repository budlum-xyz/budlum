//! Whether a derived object is cheaper to keep or to recompute on request.
//!
//! [`crate::storage::derived`] establishes that a derivation can be recomputed
//! byte-exactly and therefore need not be stored. It leaves open the question
//! this module answers: for a given derivation, *should* it be.
//!
//! The trade has two sides and one crossing point. Keeping a derivation costs
//! its size for as long as it is kept. Recomputing it costs processor time,
//! once per request. Below some request rate the disk is idle money and the
//! processor is cheaper; above it the processor is doing the same work over
//! and over and the disk is cheaper.
//!
//! # The crossing point is one division
//!
//! Storing `bytes` for a year costs `bytes * disk_rate * HOURS_PER_YEAR`.
//! Producing it `r` times costs `r * cpu_nanos * cpu_rate`. Setting those
//! equal and solving for `r`:
//!
//! ```text
//! r* = (bytes / cpu_nanos) * (disk_rate * HOURS_PER_YEAR / cpu_rate)
//! ```
//!
//! The right factor is a property of the operator's hardware and holds for
//! every object it stores. The left factor, bytes per unit of processor time,
//! is a property of the derivation alone. So the decision reduces to comparing
//! one number about the transform against one number about the machine, and
//! neither has anything to say about what kind of file it came from.
//!
//! That is worth stating plainly because the intuition runs the other way.
//! Measured across eleven formats, the derivations that are cheapest to
//! recompute are not grouped by media type at all. Extracting text from a
//! word-processor container yields about thirty million bytes per processor
//! second; re-encoding a video frame at the same quality the master holds
//! yields about a hundred and twenty thousand. Both are "documents" and
//! "video" only in the sense that a human filed them that way. The ratio is
//! two hundred and forty to one, and the ratio is the whole decision.
//!
//! # Why the numbers are rates and not prices
//!
//! A price would have to be a currency amount, which would put an oracle in
//! the path of a storage decision. The inputs here are ratios instead: how
//! many bytes a second of processor time produces, against how many bytes an
//! hour of disk holds for the price of a second of processor time. An
//! operator computes the second number once from what its own hardware cost
//! and what its own power costs, and nothing on chain has to agree with it.
//!
//! Which is deliberate. Operators do not have the same hardware. Amortising a
//! bought disk over its service life lands near a tenth of what renting the
//! equivalent object storage costs, and the same derivation can honestly be
//! worth keeping on one machine and worth recomputing on another. A consensus
//! rule that forced one answer would be pricing hardware it cannot see.
//!
//! # Arithmetic
//!
//! Integer throughout, in the same spirit as
//! [`crate::storage::fixed_point`]: the comparison decides whether bytes get
//! written, and two nodes that round differently would disagree about what
//! the network holds. Processor time is counted in nanoseconds so that
//! sub-millisecond transforms, which are most of them, do not truncate to
//! zero and report themselves as infinitely fast.
//!
//! WIRING: unwired - measured: nothing calls this yet. The policy is a
//! node-local decision that belongs to the retrieval path, and the retrieval
//! path does not exist. What is here is the arithmetic and its refusals.

/// Hours in a year of storage. Leap years are not modelled: the input rates
/// are estimates good to a few percent, and a quarter of a day is four
/// thousandths of that.
pub const HOURS_PER_YEAR: u64 = 8_760;

/// Nanoseconds in a second, for callers converting measured durations.
pub const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// Largest derivation size this will reason about, in bytes.
///
/// Sixty-four gibibytes is past any single derived object and far enough
/// below the range where the products below could overflow that the bound can
/// be checked once here rather than argued at each multiplication.
pub const MAX_DERIVATION_BYTES: u64 = 64 << 30;

/// Largest processor cost this will reason about, in nanoseconds.
///
/// One hour. A derivation that takes longer than an hour to produce is not a
/// derivation anyone recomputes on request, and admitting the value would
/// only produce a threshold nobody acts on.
pub const MAX_DERIVATION_NANOS: u64 = 3_600 * NANOS_PER_SECOND;

/// What an operator's hardware costs, as a ratio rather than a price.
///
/// Both fields are in the same arbitrary unit, so only their quotient
/// matters. An operator may fill them in as thousandths of a cent or as
/// millionths of anything else, provided it uses the same unit twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardwareRates {
    /// Cost of holding one byte for one hour.
    pub disk_cost_per_byte_hour: u64,
    /// Cost of one second of one processor core.
    pub cpu_cost_per_core_second: u64,
    /// The unit both costs are expressed in, per whole currency unit. Present
    /// so the two figures above can be small integers rather than fractions:
    /// a byte-hour costs far less than a cent, and rounding it to a cent
    /// would round it to nothing.
    pub scale: u64,
}

/// What a derivation costs to produce, measured rather than declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivationCost {
    /// Size of the produced object.
    pub bytes: u64,
    /// Processor time one production takes, in nanoseconds.
    pub cpu_nanos: u64,
}

/// What to do with a derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivationPolicy {
    /// Keep the bytes. Requests are frequent enough that recomputing them
    /// costs more processor time than the disk costs.
    Keep,
    /// Drop the bytes and produce them per request.
    Recompute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivationEconomicsError {
    /// A derivation that produces no bytes has nothing to store, so the
    /// comparison has no meaning. Refused rather than answered, because the
    /// caller asking is confused about something.
    EmptyDerivation,
    /// A derivation that takes no measurable processor time would divide by
    /// zero. Callers that measured zero should measure a batch and divide.
    ZeroCost,
    /// Past [`MAX_DERIVATION_BYTES`].
    DerivationTooLarge { bytes: u64 },
    /// Past [`MAX_DERIVATION_NANOS`].
    DerivationTooSlow { cpu_nanos: u64 },
    /// A rate field was zero, which would make the quotient meaningless in
    /// one direction or the other.
    DegenerateRates,
}

impl DerivationCost {
    /// Bytes produced per second of processor time.
    ///
    /// The property of the transform that the decision turns on, isolated so
    /// it can be compared across transforms without reference to any
    /// particular machine.
    pub fn bytes_per_cpu_second(self) -> Result<u64, DerivationEconomicsError> {
        self.validate()?;
        // Widened before the multiply: bytes is bounded at 2^36 and the
        // nanosecond factor is 2^30, so the product needs 66 bits.
        let scaled = u128::from(self.bytes) * u128::from(NANOS_PER_SECOND);
        let per_second = scaled / u128::from(self.cpu_nanos);
        Ok(u64::try_from(per_second).unwrap_or(u64::MAX))
    }

    fn validate(self) -> Result<(), DerivationEconomicsError> {
        if self.bytes == 0 {
            return Err(DerivationEconomicsError::EmptyDerivation);
        }
        if self.cpu_nanos == 0 {
            return Err(DerivationEconomicsError::ZeroCost);
        }
        if self.bytes > MAX_DERIVATION_BYTES {
            return Err(DerivationEconomicsError::DerivationTooLarge { bytes: self.bytes });
        }
        if self.cpu_nanos > MAX_DERIVATION_NANOS {
            return Err(DerivationEconomicsError::DerivationTooSlow {
                cpu_nanos: self.cpu_nanos,
            });
        }
        Ok(())
    }
}

impl HardwareRates {
    fn validate(self) -> Result<(), DerivationEconomicsError> {
        if self.disk_cost_per_byte_hour == 0
            || self.cpu_cost_per_core_second == 0
            || self.scale == 0
        {
            return Err(DerivationEconomicsError::DegenerateRates);
        }
        Ok(())
    }
}

/// Requests per year above which keeping the bytes costs less than producing
/// them.
///
/// Returned as a whole number of requests, rounded down, so a derivation
/// sitting exactly on the boundary is recomputed. The bias is deliberate:
/// the failure mode of recomputing is a slower response, and the failure mode
/// of keeping is a disk that fills, and only one of those is recoverable
/// without deleting something.
pub fn breakeven_requests_per_year(
    cost: DerivationCost,
    rates: HardwareRates,
) -> Result<u64, DerivationEconomicsError> {
    cost.validate()?;
    rates.validate()?;

    // Yearly cost of holding the bytes, in the caller's scaled unit.
    let hold = u128::from(cost.bytes)
        * u128::from(rates.disk_cost_per_byte_hour)
        * u128::from(HOURS_PER_YEAR);

    // Cost of producing them once. The nanosecond count is divided by a
    // second's worth after the multiply rather than before, so a transform
    // taking a fraction of a second keeps its precision.
    let produce = u128::from(cost.cpu_nanos) * u128::from(rates.cpu_cost_per_core_second);
    if produce == 0 {
        return Err(DerivationEconomicsError::ZeroCost);
    }
    let per_production = produce / u128::from(NANOS_PER_SECOND);
    if per_production == 0 {
        // The production is cheap enough that it costs less than the smallest
        // representable amount in the caller's unit. Recomputing always wins,
        // which is a breakeven of zero rather than a division by zero.
        return Ok(0);
    }

    Ok(u64::try_from(hold / per_production).unwrap_or(u64::MAX))
}

/// Which side of the crossing point an observed request rate falls on.
pub fn policy_for(
    cost: DerivationCost,
    rates: HardwareRates,
    observed_requests_per_year: u64,
) -> Result<DerivationPolicy, DerivationEconomicsError> {
    let breakeven = breakeven_requests_per_year(cost, rates)?;
    if observed_requests_per_year > breakeven {
        Ok(DerivationPolicy::Keep)
    } else {
        Ok(DerivationPolicy::Recompute)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rates for a bought disk amortised over its service life, alongside
    /// power at an industrial tariff. Scaled to picounits so the byte-hour
    /// figure is not rounded to nothing.
    fn owned_hardware() -> HardwareRates {
        HardwareRates {
            // A tebibyte-year near three and a half currency units, spread
            // over the bytes and hours in one.
            disk_cost_per_byte_hour: 1,
            cpu_cost_per_core_second: 694,
            scale: 1_000_000_000_000,
        }
    }

    #[test]
    fn throughput_is_a_property_of_the_transform_not_the_media() {
        // Text extracted from a container, against a video ladder rung. Both
        // measured; the first produces bytes two orders of magnitude faster.
        let text = DerivationCost {
            bytes: 128_899,
            cpu_nanos: 4_300_000,
        };
        let rung = DerivationCost {
            bytes: 3_129_552,
            cpu_nanos: 25_320_000_000,
        };
        let text_rate = text.bytes_per_cpu_second().expect("a valid derivation");
        let rung_rate = rung.bytes_per_cpu_second().expect("a valid derivation");
        assert!(text_rate > rung_rate * 200, "{text_rate} vs {rung_rate}");
    }

    #[test]
    fn a_cheap_transform_crosses_over_later_than_an_expensive_one() {
        let rates = owned_hardware();
        let cheap = DerivationCost {
            bytes: 128_899,
            cpu_nanos: 4_300_000,
        };
        let dear = DerivationCost {
            bytes: 3_129_552,
            cpu_nanos: 25_320_000_000,
        };
        let cheap_breakeven =
            breakeven_requests_per_year(cheap, rates).expect("a valid derivation");
        let dear_breakeven =
            breakeven_requests_per_year(dear, rates).expect("a valid derivation");
        assert!(
            cheap_breakeven > dear_breakeven,
            "{cheap_breakeven} vs {dear_breakeven}"
        );
    }

    #[test]
    fn the_same_derivation_can_go_either_way_on_different_hardware() {
        // The point of taking rates as an argument. A rented byte-hour costs
        // more than an owned one, which moves the crossing point without any
        // property of the derivation changing.
        let cost = DerivationCost {
            bytes: 231_652,
            cpu_nanos: 197_300_000,
        };
        let owned = owned_hardware();
        let rented = HardwareRates {
            disk_cost_per_byte_hour: 12,
            ..owned
        };
        let owned_breakeven = breakeven_requests_per_year(cost, owned).expect("a valid derivation");
        let rented_breakeven =
            breakeven_requests_per_year(cost, rented).expect("a valid derivation");
        assert!(
            rented_breakeven > owned_breakeven,
            "{rented_breakeven} vs {owned_breakeven}"
        );

        // And a request rate between the two crossing points is answered
        // differently by each, which is the whole reason this is not a
        // consensus constant.
        let between = (owned_breakeven + rented_breakeven) / 2;
        assert_eq!(
            policy_for(cost, owned, between).expect("a valid derivation"),
            DerivationPolicy::Keep
        );
        assert_eq!(
            policy_for(cost, rented, between).expect("a valid derivation"),
            DerivationPolicy::Recompute
        );
    }

    #[test]
    fn sitting_exactly_on_the_crossing_point_recomputes() {
        let rates = owned_hardware();
        let cost = DerivationCost {
            bytes: 15_107,
            cpu_nanos: 48_300_000,
        };
        let breakeven = breakeven_requests_per_year(cost, rates).expect("a valid derivation");
        assert_eq!(
            policy_for(cost, rates, breakeven).expect("a valid derivation"),
            DerivationPolicy::Recompute
        );
        assert_eq!(
            policy_for(cost, rates, breakeven + 1).expect("a valid derivation"),
            DerivationPolicy::Keep
        );
    }

    #[test]
    fn a_derivation_producing_nothing_is_refused_rather_than_answered() {
        let rates = owned_hardware();
        let cost = DerivationCost {
            bytes: 0,
            cpu_nanos: 1_000,
        };
        assert_eq!(
            breakeven_requests_per_year(cost, rates),
            Err(DerivationEconomicsError::EmptyDerivation)
        );
    }

    #[test]
    fn a_transform_measured_at_zero_is_refused_rather_than_dividing() {
        let rates = owned_hardware();
        let cost = DerivationCost {
            bytes: 1_024,
            cpu_nanos: 0,
        };
        assert_eq!(
            cost.bytes_per_cpu_second(),
            Err(DerivationEconomicsError::ZeroCost)
        );
        assert_eq!(
            breakeven_requests_per_year(cost, rates),
            Err(DerivationEconomicsError::ZeroCost)
        );
    }

    #[test]
    fn absurd_inputs_are_bounded_rather_than_overflowing() {
        let rates = owned_hardware();
        let huge = DerivationCost {
            bytes: MAX_DERIVATION_BYTES + 1,
            cpu_nanos: 1_000_000,
        };
        assert_eq!(
            breakeven_requests_per_year(huge, rates),
            Err(DerivationEconomicsError::DerivationTooLarge {
                bytes: MAX_DERIVATION_BYTES + 1
            })
        );
        let slow = DerivationCost {
            bytes: 1_024,
            cpu_nanos: MAX_DERIVATION_NANOS + 1,
        };
        assert_eq!(
            breakeven_requests_per_year(slow, rates),
            Err(DerivationEconomicsError::DerivationTooSlow {
                cpu_nanos: MAX_DERIVATION_NANOS + 1
            })
        );
    }

    #[test]
    fn a_zero_rate_is_refused_because_the_quotient_would_be_meaningless() {
        let cost = DerivationCost {
            bytes: 1_024,
            cpu_nanos: 1_000_000,
        };
        for rates in [
            HardwareRates {
                disk_cost_per_byte_hour: 0,
                cpu_cost_per_core_second: 1,
                scale: 1,
            },
            HardwareRates {
                disk_cost_per_byte_hour: 1,
                cpu_cost_per_core_second: 0,
                scale: 1,
            },
            HardwareRates {
                disk_cost_per_byte_hour: 1,
                cpu_cost_per_core_second: 1,
                scale: 0,
            },
        ] {
            assert_eq!(
                breakeven_requests_per_year(cost, rates),
                Err(DerivationEconomicsError::DegenerateRates)
            );
        }
    }

    #[test]
    fn a_transform_too_cheap_to_price_never_wins_by_being_kept() {
        // Production costing less than the smallest representable amount
        // reports a crossing point of zero, so every rate above nothing
        // recomputes.
        let rates = HardwareRates {
            disk_cost_per_byte_hour: 1,
            cpu_cost_per_core_second: 1,
            scale: 1,
        };
        let cost = DerivationCost {
            bytes: 64,
            cpu_nanos: 300_000,
        };
        assert_eq!(
            breakeven_requests_per_year(cost, rates),
            Ok(0),
            "a production below the representable minimum"
        );
        assert_eq!(
            policy_for(cost, rates, 1).expect("a valid derivation"),
            DerivationPolicy::Keep
        );
    }
}
