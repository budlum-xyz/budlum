//! B.U.D. 2.0 - Sabit Nokta Aritmetiği (no-float ilkesi; budlum fixed_point.rs deseni) (2026-08-16)
//!
//! Ana repo ilkesi: kayan nokta, iki makinenin son bitten farklılaşmasına yol açabilir →
//! üretici (deterministik üretim) farklı nesne üretir → FORK. Tamsayılar bu sorunu
//! yaşamaz; bu yüzden üreticilerin aritmetiği sabit noktadır.
//!
//! Bu modül: shift-tabanlı sabit nokta (2^16 ölçek - 8/16-bit renkten ince),
//! doyuran (saturating) dönüşümler, karekök (yaklaşık - deterministik yineleme).
//! `#![forbid(unsafe_code)]`, `const fn` (üreticide çalışır), panik'siz.

#![forbid(unsafe_code)]

/// Kesirli bit sayısı: 16 → çözünürlük ~1.5e-5 (8/16-bit renkten ince).
pub const FIXED_FRAC_BITS: u32 = 16;
pub const FIXED_ONE: i64 = 1 << FIXED_FRAC_BITS;

/// Tamsayıdan sabit noktaya (doyuran - taşma sarmaz, kıskanır).
#[must_use]
pub const fn fixed_from_int(v: i32) -> i64 {
    (v as i64) << FIXED_FRAC_BITS
}

/// Sabit noktadan tamsayıya (sıfıra doğru keser - işaretten bağımsız aynı yön).
#[must_use]
pub const fn fixed_to_int(v: i64) -> i32 {
    (v >> FIXED_FRAC_BITS) as i32
}

/// Sabit nokta çarpma (32.16 × 32.16 → 32.16). Doyuran.
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

/// Sabit nokta bölme (32.16 / 32.16 → 32.16). Sıfır bölme → i64::MAX (doyur).
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

/// Karekök (Newton yinelemesi - deterministik, sabit adım). Girdi ≥ 0.
/// 16 yineleme yeterli (yaklaşık 2^-16 hassasiyet).
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

/// 0-1 aralığında sabit nokta (fraksiyon) - olasılık/ağırlık için.
#[must_use]
pub const fn fixed_fraction(numerator: u32, denom: u32) -> i64 {
    if denom == 0 {
        return 0;
    }
    (((numerator as i128) << FIXED_FRAC_BITS) / (denom as i128)) as i64
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
        // 1.5 → 1 (sıfıra doğru keser)
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
        // i64 taşması doyurur (sarmaz)
        let big = i64::MAX;
        let m = fixed_mul(big, fixed_from_int(2));
        assert_eq!(m, i64::MAX);
        // sıfır bölme → doyur
        assert_eq!(fixed_div(FIXED_ONE, 0), i64::MAX);
    }

    #[test]
    fn sqrt_approximation() {
        // sqrt(4) ≈ 2
        let s = fixed_sqrt(fixed_from_int(4));
        assert!((fixed_to_int(s) - 2).abs() <= 1, "sqrt(4)≈2: {}", fixed_to_int(s));
        // sqrt(0) = 0
        assert_eq!(fixed_sqrt(0), 0);
        // sqrt(1) ≈ 1
        let s1 = fixed_sqrt(FIXED_ONE);
        assert!((fixed_to_int(s1) - 1).abs() <= 1);
        // monoton: sqrt(16) > sqrt(4)
        assert!(fixed_sqrt(fixed_from_int(16)) > fixed_sqrt(fixed_from_int(4)));
    }

    #[test]
    fn fraction_and_determinism() {
        // 1/3 sabit noktada
        let third = fixed_fraction(1, 3);
        assert!(third > 0 && third < FIXED_ONE);
        // determinizm: aynı girdi aynı çıktı
        assert_eq!(fixed_fraction(1, 3), fixed_fraction(1, 3));
        assert_eq!(fixed_mul(fixed_from_int(7), fixed_from_int(9)), fixed_mul(fixed_from_int(9), fixed_from_int(7)));
        // denom 0 → 0
        assert_eq!(fixed_fraction(5, 0), 0);
    }
}
