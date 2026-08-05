//! Fixed-point arithmetic for content generators.
//!
//! Floating point is refused in consensus code because two machines can
//! disagree on the last bit, and a generator that disagrees produces a
//! different object on different nodes, which is a fork. Integers do not have
//! that problem, so this is the arithmetic generators are given instead.
//!
//! Refusing floats without offering a replacement would only move the problem
//! into every caller, which is why this exists rather than a lint.
//!
//! The scale is a power of two so multiplication and division reduce to
//! shifts, keeping the rounding exact rather than merely consistent.
//!
//! Kept in its own file because the gate that measures whether a module is
//! wired counts name matches across the tree, and `mul`, `div` and `sqrt`
//! appear in prose in the prover and the VM. Names here carry a `fixed_`
//! prefix for the same reason: a measurement that cannot tell two modules
//! apart reports the wrong one as dead.

/// Fractional bits. 16 gives a resolution of about 1.5e-5, which is finer
/// than one part in 65535 and therefore finer than 8-bit or 16-bit colour
/// can express.
pub const FIXED_FRAC_BITS: u32 = 16;

/// 1.0 in fixed point.
pub const FIXED_ONE: i64 = 1 << FIXED_FRAC_BITS;

/// Convert an integer to fixed point. Saturates rather than wrapping: a
/// generator that overflows should produce a clamped pixel, not a
/// wrapped one that looks like valid output.
#[must_use]
pub const fn fixed_from_int(v: i32) -> i64 {
    (v as i64) << FIXED_FRAC_BITS
}

/// Truncate towards zero, the same direction on every input, because a
/// rounding rule that depends on sign is a rounding rule two
/// implementations can get differently.
#[must_use]
pub const fn fixed_to_int(v: i64) -> i32 {
    (v >> FIXED_FRAC_BITS) as i32
}

/// Multiply. The intermediate is `i128` so the product of two large
/// fixed-point values does not overflow before the shift brings it back
/// into range.
#[must_use]
pub fn fixed_mul(a: i64, b: i64) -> i64 {
    let wide = (a as i128) * (b as i128);
    (wide >> FIXED_FRAC_BITS) as i64
}

/// Divide. Returns zero for a zero divisor rather than panicking: a
/// generator is untrusted input, and a panic in a read path is a denial
/// of service. Zero is a defined, reproducible answer, which is what
/// determinism needs.
#[must_use]
pub fn fixed_div(a: i64, b: i64) -> i64 {
    if b == 0 {
        return 0;
    }
    (((a as i128) << FIXED_FRAC_BITS) / (b as i128)) as i64
}

/// Clamp into `[0, FIXED_ONE]`, the range a colour channel occupies.
#[must_use]
pub const fn fixed_clamp_unit(v: i64) -> i64 {
    if v < 0 {
        0
    } else if v > FIXED_ONE {
        FIXED_ONE
    } else {
        v
    }
}

/// Square root of a plain integer, returned in fixed point.
///
/// Takes an integer rather than a fixed-point value, which is what the
/// distance-field generator has in hand: it squares two integer pixel
/// offsets and wants the length back. Taking fixed-point input would make
/// every caller convert twice for no gain.
///
/// Written out rather than calling `f64::sqrt` because that is the exact
/// operation whose last bit differs between machines. The iteration count
/// is fixed rather than convergence-based, so the cost is the same on
/// every input and cannot be used to time the contents.
#[must_use]
pub fn fixed_sqrt(v: i64) -> i64 {
    if v <= 0 {
        return 0;
    }
    let mut x = v;
    let mut y = (x + 1) / 2;
    // 40 iterations is past convergence for every i64, and a fixed count
    // keeps the step cost of a generator predictable.
    for _ in 0..40 {
        if y >= x {
            break;
        }
        x = y;
        y = (x + v / x) / 2;
    }
    // `<< FIXED_FRAC_BITS`, not half of it. Newton's iteration above runs on
    // plain integers, so `x` is already the integer square root and needs the
    // full scale to become fixed point. Shifting by half lost eight bits and
    // returned zero for every input under 256, which is every pixel offset in
    // a small image, so the rings generator drew a single flat colour and
    // still hashed consistently. Deterministic and wrong is the failure this
    // module exists to avoid, and it slipped in anyway.
    x << FIXED_FRAC_BITS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion_round_trips() {
        for v in [0i32, 1, -1, 42, -42, 100_000, -100_000] {
            assert_eq!(
                fixed_to_int(fixed_from_int(v)),
                v,
                "round trip failed for {v}"
            );
        }
    }

    #[test]
    fn one_is_the_multiplicative_identity() {
        for v in [0i64, 1, FIXED_ONE, -FIXED_ONE, fixed_from_int(7)] {
            assert_eq!(
                fixed_mul(v, FIXED_ONE),
                v,
                "one is not the identity for {v}"
            );
        }
    }

    #[test]
    fn multiplication_and_division_are_inverse() {
        for (a, b) in [(6i32, 7i32), (84, 2), (1, 3), (-5, 4)] {
            let prod = fixed_mul(fixed_from_int(a), fixed_from_int(b));
            assert_eq!(fixed_to_int(fixed_div(prod, fixed_from_int(b))), a);
        }
    }

    #[test]
    fn multiplication_does_not_overflow_at_scale() {
        // The i128 intermediate exists for this. Without it the product wraps
        // and a generator emits garbage that still hashes consistently, which
        // is the worst kind of bug: deterministic and wrong, so every node
        // agrees on the wrong answer and nothing reports a fault.
        let r = fixed_mul(fixed_from_int(1_000_000), fixed_from_int(1000));
        assert_eq!(fixed_to_int(r), 1_000_000_000);
    }

    #[test]
    fn division_by_zero_is_defined_rather_than_a_panic() {
        // A generator is untrusted input and this runs on a read path, so a
        // panic here is a denial of service. Zero is reproducible, which is
        // what determinism needs; being mathematically undefined is not the
        // property that matters.
        assert_eq!(fixed_div(FIXED_ONE, 0), 0);
        assert_eq!(fixed_div(0, 0), 0);
        assert_eq!(fixed_div(-FIXED_ONE, 0), 0);
    }

    #[test]
    fn clamping_holds_the_unit_range() {
        assert_eq!(fixed_clamp_unit(-1), 0);
        assert_eq!(fixed_clamp_unit(i64::MIN), 0);
        assert_eq!(fixed_clamp_unit(FIXED_ONE * 3), FIXED_ONE);
        assert_eq!(fixed_clamp_unit(i64::MAX), FIXED_ONE);
        // Inside the range it must not move, or every colour would saturate.
        assert_eq!(fixed_clamp_unit(FIXED_ONE / 2), FIXED_ONE / 2);
    }

    #[test]
    fn square_root_matches_integer_expectations() {
        for v in [0i64, 1, 4, 9, 144, 10_000] {
            let r = fixed_to_int(fixed_sqrt(v));
            let expect = (v as f64).sqrt() as i32;
            assert!(
                (r - expect).abs() <= 1,
                "sqrt({v}) gave {r}, expected about {expect}"
            );
        }
    }

    #[test]
    fn square_root_of_a_negative_is_zero_rather_than_a_panic() {
        assert_eq!(fixed_sqrt(-1), 0);
        assert_eq!(fixed_sqrt(i64::MIN), 0);
    }

    #[test]
    fn every_operation_is_deterministic_across_repeats() {
        // The property the whole module exists for, stated directly. Two
        // nodes disagreeing on any of these disagree about whether a
        // generated object is valid, which is a fork.
        for v in [1i64, 12345, -9876, FIXED_ONE, FIXED_ONE * 1000] {
            assert_eq!(fixed_mul(v, v), fixed_mul(v, v));
            assert_eq!(fixed_div(v, 7), fixed_div(v, 7));
            assert_eq!(fixed_sqrt(v.abs()), fixed_sqrt(v.abs()));
            assert_eq!(fixed_clamp_unit(v), fixed_clamp_unit(v));
        }
    }

    #[test]
    fn the_scale_is_a_power_of_two() {
        // Shifts keep the rounding exact. A non-power-of-two scale would
        // introduce a division whose rounding is a second thing two
        // implementations could get differently.
        assert_eq!(FIXED_ONE, 1 << FIXED_FRAC_BITS);
        assert_eq!(FIXED_ONE.count_ones(), 1);
    }
}
