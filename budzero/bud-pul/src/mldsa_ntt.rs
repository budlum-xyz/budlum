//! The ML-DSA number theoretic transform over q = 8380417.
//!
//! This is the plain Rust definition of FIPS 204 algorithms 41 and 42 that the NTT chip must
//! reproduce row by row. It is the oracle for the chip's equality test: whatever the AIR proves
//! has to equal these functions, and these functions are checked here against the schoolbook
//! product in `Z_q[X] / (X^256 + 1)` instead of against themselves.

/// The ML-DSA modulus.
pub const Q: u64 = 8_380_417;

/// The degree of the ring polynomials.
pub const N: usize = 256;

/// A primitive 512th root of unity modulo `Q` (FIPS 204, section 7.5).
/// exposed for: the proof/VM crate's test-and-tooling surface — production readers land with the prover wiring wave.
pub const ZETA: u64 = 1_753;

/// `256^-1 mod Q`, the scaling of the inverse transform.
/// exposed for: the proof/VM crate's test-and-tooling surface — production readers land with the prover wiring wave.
pub const N_INV: u64 = 8_347_681;

fn pow_mod(mut base: u64, mut exp: u64) -> u64 {
    let mut acc = 1u64;
    base %= Q;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = acc * base % Q;
        }
        base = base * base % Q;
        exp >>= 1;
    }
    acc
}

fn bit_reverse_8(mut value: usize) -> usize {
    let mut out = 0usize;
    for _ in 0..8 {
        out = (out << 1) | (value & 1);
        value >>= 1;
    }
    out
}

/// `zetas[k] = ZETA^BitRev8(k) mod Q`, the twiddle table of the transform.
#[must_use]
/// exposed for: the proof/VM crate's test-and-tooling surface — production readers land with the prover wiring wave.
pub fn zetas() -> [u64; N] {
    let mut table = [0u64; N];
    for (k, slot) in table.iter_mut().enumerate() {
        *slot = pow_mod(ZETA, bit_reverse_8(k) as u64);
    }
    table
}

/// The forward transform (FIPS 204 algorithm 41). Inputs are reduced modulo `Q` first.
#[must_use]
/// exposed for: the proof/VM crate's test-and-tooling surface — production readers land with the prover wiring wave.
pub fn ntt(input: &[u64; N]) -> [u64; N] {
    let zetas = zetas();
    let mut w = input.map(|c| c % Q);
    let mut m = 0usize;
    let mut len = 128usize;
    while len >= 1 {
        let mut start = 0usize;
        while start < N {
            m += 1;
            let z = zetas[m];
            for j in start..start + len {
                let t = z * w[j + len] % Q;
                w[j + len] = (w[j] + Q - t) % Q;
                w[j] = (w[j] + t) % Q;
            }
            start += 2 * len;
        }
        len /= 2;
    }
    w
}

/// The inverse transform (FIPS 204 algorithm 42), including the final scaling by `256^-1`.
#[must_use]
/// exposed for: the proof/VM crate's test-and-tooling surface — production readers land with the prover wiring wave.
pub fn inverse_ntt(input: &[u64; N]) -> [u64; N] {
    let zetas = zetas();
    let mut w = input.map(|c| c % Q);
    let mut m = N;
    let mut len = 1usize;
    while len < N {
        let mut start = 0usize;
        while start < N {
            m -= 1;
            let z = (Q - zetas[m]) % Q;
            for j in start..start + len {
                let t = w[j];
                w[j] = (t + w[j + len]) % Q;
                w[j + len] = (t + Q - w[j + len]) % Q * z % Q;
            }
            start += 2 * len;
        }
        len *= 2;
    }
    w.map(|c| c * N_INV % Q)
}

/// The product in `Z_q[X] / (X^256 + 1)` through the transform: pointwise in the NTT domain.
#[must_use]
/// exposed for: the proof/VM crate's test-and-tooling surface — production readers land with the prover wiring wave.
pub fn multiply(a: &[u64; N], b: &[u64; N]) -> [u64; N] {
    let (na, nb) = (ntt(a), ntt(b));
    let mut product = [0u64; N];
    for i in 0..N {
        product[i] = na[i] * nb[i] % Q;
    }
    inverse_ntt(&product)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(seed: u64) -> [u64; N] {
        let mut state = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let mut out = [0u64; N];
        for slot in &mut out {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *slot = (state >> 33) % Q;
        }
        out
    }

    /// The schoolbook product modulo `X^256 + 1`: `X^256 = -1`.
    fn negacyclic(a: &[u64; N], b: &[u64; N]) -> [u64; N] {
        let mut out = [0u64; N];
        for (i, &ai) in a.iter().enumerate() {
            for (j, &bj) in b.iter().enumerate() {
                let term = ai * bj % Q;
                let k = i + j;
                if k < N {
                    out[k] = (out[k] + term) % Q;
                } else {
                    out[k - N] = (out[k - N] + Q - term) % Q;
                }
            }
        }
        out
    }

    #[test]
    fn the_constants_are_what_the_standard_says() {
        assert_eq!(pow_mod(ZETA, 512), 1);
        assert_eq!(pow_mod(ZETA, 256), Q - 1);
        assert_eq!(N_INV * 256 % Q, 1);
        assert_eq!(zetas()[0], 1);
        assert_eq!(zetas()[1], pow_mod(ZETA, 128));
    }

    #[test]
    fn the_inverse_undoes_the_transform() {
        for seed in 0..4 {
            let a = sample(seed);
            assert_eq!(inverse_ntt(&ntt(&a)), a);
        }
    }

    #[test]
    fn the_transform_product_equals_the_schoolbook_product() {
        for seed in 0..3 {
            let a = sample(seed);
            let b = sample(seed + 100);
            assert_eq!(multiply(&a, &b), negacyclic(&a, &b));
        }
    }
}
