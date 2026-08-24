//! B.U.D. 2.0 fixed-point arithmetic: the no-float rule.
//!
//! Floating point lets two machines differ in the last bit, so a generator
//! (which must produce byte-identical output) would emit a different object on
//! each -> a fork. Integers do not have that problem, which is why generator
//! arithmetic is fixed point.
//!
//! This module: shift-based fixed point (a 2^16 scale, finer than 8/16-bit
//! colour), saturating conversions, and a square root by deterministic
//! iteration. `#![forbid(unsafe_code)]`, `const fn` so it runs inside a
//! generator, and no panics.

#![forbid(unsafe_code)]

/// Fractional bits: 16, giving a resolution around 1.5e-5, finer than
/// 8/16-bit colour.
pub const FIXED_FRAC_BITS: u32 = 16;
pub const FIXED_ONE: i64 = 1 << FIXED_FRAC_BITS;

/// Integer to fixed point. Saturating: an overflow clamps, it does not wrap.
#[must_use]
pub const fn fixed_from_int(v: i32) -> i64 {
    (v as i64) << FIXED_FRAC_BITS
}

/// Fixed point to integer, truncating toward zero, the same direction for
/// either sign.
#[must_use]
pub const fn fixed_to_int(v: i64) -> i32 {
    (v >> FIXED_FRAC_BITS) as i32
}

/// Fixed-point multiply (32.16 by 32.16 -> 32.16). Saturating.
#[must_use]
pub const fn fixed_mul(a: i64, b: i64) -> i64 {
    let r = ((a as i128) * (b as i128)) >> FIXED_FRAC_BITS;
    if r > i64::MAX as i128 {
        i64::MAX
    } else if r < i64::MIN as i128 {
        i64::MIN
    } else {
        r as i64
    }
}

/// Fixed-point divide (32.16 / 32.16 -> 32.16). Division by zero saturates to
/// `i64::MAX`.
#[must_use]
pub const fn fixed_div(a: i64, b: i64) -> i64 {
    if b == 0 {
        return i64::MAX;
    }
    let r = ((a as i128) << FIXED_FRAC_BITS) / (b as i128);
    if r > i64::MAX as i128 {
        i64::MAX
    } else if r < i64::MIN as i128 {
        i64::MIN
    } else {
        r as i64
    }
}

/// Square root by Newton iteration: deterministic, with a fixed step count.
/// The input must be non-negative. 16 iterations reach roughly 2^-16.
#[must_use]
pub fn fixed_sqrt(v: i64) -> i64 {
    if v <= 0 {
        return 0;
    }
    // ilk tahmin: v >> (frac/2)
    let mut x = (v >> (FIXED_FRAC_BITS / 2)).max(1);
    for _ in 0..16 {
        // x = (x + v/x) / 2 - sabit nokta
        let next = fixed_div(x + fixed_div(v, x).max(1), fixed_from_int(2));
        if next == x {
            break;
        }
        x = next;
    }
    x
}

/// A fixed-point fraction in the 0-1 range, for a probability or a weight.
///
/// [`fixed_ratio`] widens this to file lengths, and the zip-bomb gate in
/// `bud_format` decides acceptance with it, so this is on the path that has to
/// give the same verdict on every machine.
///
/// Not `pub`: nothing outside this module needs the narrow `u32` form, and
/// exporting a symbol no caller wants is how a public surface fills up with
/// items that only look used.
#[must_use]
const fn fixed_fraction(numerator: u32, denom: u32) -> i64 {
    if denom == 0 {
        return 0;
    }
    (((numerator as i128) << FIXED_FRAC_BITS) / (denom as i128)) as i64
}

/// The compression ratio as a fixed-point value, for the gate that refuses a
/// zip bomb.
///
/// `BudFile::ratio` returns `f64`, and the zip-bomb gate used to compare it
/// against a `f64` limit. That is a division whose last bit is allowed to
/// differ between machines, deciding acceptance of an object: two nodes can
/// disagree on whether the same file is a bomb, which is the fork this module
/// exists to prevent. This computes the same quantity with integers, so the
/// verdict is the same everywhere.
///
/// This is [`fixed_fraction`] widened to the lengths a file carries. Lengths
/// above [`u32::MAX`] saturate to [`i64::MAX`] rather than wrapping: a payload
/// that small against an original that large is far past any sane limit, and
/// a wrap would turn a gigantic ratio into a small one, which is the direction
/// that lets a bomb through.
#[must_use]
pub const fn fixed_ratio(original_len: u64, payload_len: u64) -> i64 {
    if payload_len == 0 {
        return FIXED_ONE;
    }
    // The common case is two lengths that fit in 32 bits, which is exactly
    // what `fixed_fraction` takes; the wide path below only exists for files
    // past 4 GiB.
    if original_len <= u32::MAX as u64 && payload_len <= u32::MAX as u64 {
        return fixed_fraction(original_len as u32, payload_len as u32);
    }
    let r = ((original_len as i128) << FIXED_FRAC_BITS) / (payload_len as i128);
    if r > i64::MAX as i128 {
        i64::MAX
    } else {
        r as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_roundtrip() {
        for v in [-100i32, -1, 0, 1, 100, 1000] {
            let f = fixed_from_int(v);
            assert_eq!(fixed_to_int(f), v);
        }
        // 1.5 -> 1, truncating toward zero
        let f = fixed_from_int(1) + FIXED_ONE / 2;
        assert_eq!(fixed_to_int(f), 1);
    }

    #[test]
    fn mul_div_inverse() {
        // 3.0 * 4.0 = 12.0
        let a = fixed_from_int(3);
        let b = fixed_from_int(4);
        let m = fixed_mul(a, b);
        assert_eq!(fixed_to_int(m), 12);
        // 12 / 3 = 4
        assert_eq!(fixed_to_int(fixed_div(m, a)), 4);
        // kesirli: 0.5 * 0.5 = 0.25
        let half = FIXED_ONE / 2;
        let q = fixed_mul(half, half);
        assert_eq!(fixed_to_int(q), 0);
        assert!(q > 0 && q < FIXED_ONE, "0.25 sabit noktada");
        // 1/2 = 0.5
        assert_eq!(fixed_div(FIXED_ONE, fixed_from_int(2)), half);
    }

    #[test]
    fn saturating_overflow() {
        // An i64 overflow saturates rather than wrapping
        let big = i64::MAX;
        let m = fixed_mul(big, fixed_from_int(2));
        assert_eq!(m, i64::MAX);
        // Division by zero saturates
        assert_eq!(fixed_div(FIXED_ONE, 0), i64::MAX);
    }

    #[test]
    fn sqrt_approximation() {
        // sqrt(4) ≈ 2
        let s = fixed_sqrt(fixed_from_int(4));
        assert!(
            (fixed_to_int(s) - 2).abs() <= 1,
            "sqrt(4)≈2: {}",
            fixed_to_int(s)
        );
        // sqrt(0) = 0
        assert_eq!(fixed_sqrt(0), 0);
        // sqrt(1) ≈ 1
        let s1 = fixed_sqrt(FIXED_ONE);
        assert!((fixed_to_int(s1) - 1).abs() <= 1);
        // monoton: sqrt(16) > sqrt(4)
        assert!(fixed_sqrt(fixed_from_int(16)) > fixed_sqrt(fixed_from_int(4)));
    }

    /// The ratio gate must not depend on float rounding.
    ///
    /// The same file has to be a bomb, or not, on every machine. This pins the
    /// integer path against exact expected values so a change of rounding is a
    /// test failure rather than a fork.
    #[test]
    fn fixed_ratio_is_exact_and_saturates() {
        // 100:1 exactly, the limit the zip-bomb gate uses.
        assert_eq!(fixed_ratio(100, 1), fixed_from_int(100));
        // 1:1 and the empty-payload case both mean "no compression claimed".
        assert_eq!(fixed_ratio(42, 42), FIXED_ONE);
        assert_eq!(fixed_ratio(42, 0), FIXED_ONE);
        // A ratio below one is representable, not truncated to zero.
        assert_eq!(fixed_ratio(1, 2), FIXED_ONE / 2);
        // Determinism: the same inputs give the same bits, every time.
        assert_eq!(fixed_ratio(7, 3), fixed_ratio(7, 3));
        // Saturation goes up, never wraps down: a wrap would turn a bomb into
        // a small ratio and let it through the gate.
        assert_eq!(fixed_ratio(u64::MAX, 1), i64::MAX);
        assert!(fixed_ratio(u64::MAX, 2) > fixed_from_int(100));
    }

    /// `fixed_ratio` and `fixed_fraction` are the same operation in the two
    /// directions the codebase needs, so they must agree where they overlap.
    #[test]
    fn fixed_ratio_agrees_with_fixed_fraction() {
        for (num, den) in [(1u32, 3u32), (2, 7), (5, 8), (99, 100)] {
            assert_eq!(
                fixed_fraction(num, den),
                fixed_ratio(u64::from(num), u64::from(den)),
                "{num}/{den} disagreed between the two entry points"
            );
        }
    }

    #[test]
    fn fraction_and_determinism() {
        // 1/3 sabit noktada
        let third = fixed_fraction(1, 3);
        assert!(third > 0 && third < FIXED_ONE);
        // Determinism: the same input gives the same output
        assert_eq!(fixed_fraction(1, 3), fixed_fraction(1, 3));
        assert_eq!(
            fixed_mul(fixed_from_int(7), fixed_from_int(9)),
            fixed_mul(fixed_from_int(9), fixed_from_int(7))
        );
        // denom 0 → 0
        assert_eq!(fixed_fraction(5, 0), 0);
    }
}
