//! Parameter sets. The 2026-09-19 user decision is "dual-budget": the
//! construction is written once against [`BpqsParams`], with one canonical
//! parameter row shipped per security level. Everything here is a constant;
//! nothing is config at runtime.
//!
//! Winternitz arithmetic, recorded so an auditor does not have to re-derive:
//! with `w = 16` (nibbles) and digest size `N` bytes,
//! `LEN1 = 8N / 4 = 2N` message digits, and the checksum needs
//! `LEN2 = floor(log16(LEN1 * 15)) + 1` digits. `LEN = LEN1 + LEN2`.
//! The runtime double-check that the literal constants equal the formula
//! lives in this module's tests.

/// Everything a parameter row fixes.
pub trait BpqsParams:
    'static + Sized + Clone + Copy + core::fmt::Debug + PartialEq + Eq + core::hash::Hash
{
    /// Digest length in bytes (same for message, chain elements, node values).
    const N: usize;
    /// Winternitz chain base: 16 (nibble chains).
    const WIN: u32;
    /// Message digits (`2 * N` at `w = 16`).
    const LEN1: usize;
    /// Checksum digits (`floor(log16(LEN1 * 15)) + 1`).
    const LEN2: usize;
    /// Total chain count per epoch key (`LEN1 + LEN2`).
    const LEN: usize;
    /// Epoch Merkle tree height; number of leaves is `1 << T_LOG2`.
    const T_LOG2: usize;
    /// Few-time ceiling per epoch. 2026-09-19 decision: 4. 2026-09-22
    /// decision (bar-1 record, SECURITY-ARGUMENT.md section 6): 1 - the
    /// few-time domination hunt at q=4 was priced ~2^23 classical
    /// (checksum-exact), tens of orders below the level-5 line, so the
    /// in-family posture moved to one-time. The quadratic-shape caveat
    /// stays with the verifier: quota is a ceremony-log rule, not a
    /// property the wire can prove.
    const Q_MAX: u32 = 1;
    /// Human name, for test vectors and error strings.
    const NAME: &'static str;
}

/// Canonical set: NIST level-5 budget. Signature
/// `4 (epoch) + 16 (randomizer) + 67 * 32 (chains) + 16 * 32 (path)` ≈ 2.7 KB.
///
/// LEN1 = 2·32 = 64; LEN2 = floor(log16(64·15)) + 1 = floor(2.47) + 1 = 3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ParamsL5;

impl BpqsParams for ParamsL5 {
    const N: usize = 32;
    const WIN: u32 = 16;
    const LEN1: usize = 64;
    const LEN2: usize = 3;
    const LEN: usize = 67;
    const T_LOG2: usize = 16;
    const NAME: &'static str = "bpqs-l5-research";
}

/// Carried set: NIST level-3 budget (2026-09-19 "dual-budget" decision:
/// written once, transportable).
///
/// LEN1 = 2·24 = 48; LEN2 = floor(log16(48·15)) + 1 = floor(2.37) + 1 = 3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ParamsL3;

impl BpqsParams for ParamsL3 {
    const N: usize = 24;
    const WIN: u32 = 16;
    const LEN1: usize = 48;
    const LEN2: usize = 3;
    const LEN: usize = 51;
    const T_LOG2: usize = 16;
    const NAME: &'static str = "bpqs-l3-research";
}

/// Small-tree set for the test battery: identical Winternitz shape, same
/// chain math, but the epoch tree is 16 leaves instead of 65536 so unit
/// tests do not spend minutes minting one committee key. Not a parameter
/// row: `doc(hidden)`, never referenced by the public signing API, and the
/// acceptance-bar review notes its presence is test-only.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ParamsTestFast;

impl BpqsParams for ParamsTestFast {
    const N: usize = 32;
    const WIN: u32 = 16;
    const LEN1: usize = 64;
    const LEN2: usize = 3;
    const LEN: usize = 67;
    const T_LOG2: usize = 4;
    const NAME: &'static str = "bpqs-fast-test-only";
}

#[cfg(test)]
mod params_tests {
    use super::*;

    fn formula_len1<P: BpqsParams>() -> usize {
        2 * P::N
    }

    fn formula_len2<P: BpqsParams>() -> usize {
        let mut value = formula_len1::<P>() as u64 * (P::WIN as u64 - 1);
        let mut digits = 1usize;
        while value >= P::WIN as u64 {
            value /= P::WIN as u64;
            digits += 1;
        }
        digits
    }

    #[test]
    fn l5_chain_count_is_67() {
        assert_eq!(ParamsL5::LEN, 67, "LEN1=64 LEN2=3 at N=32");
    }

    #[test]
    fn l3_chain_count_is_51() {
        assert_eq!(ParamsL3::LEN, 51, "LEN1=48 LEN2=3 at N=24");
    }

    #[test]
    fn literal_constants_match_the_winternitz_formula() {
        assert_eq!(ParamsL5::LEN1, formula_len1::<ParamsL5>());
        assert_eq!(ParamsL5::LEN2, formula_len2::<ParamsL5>());
        assert_eq!(ParamsL5::LEN, formula_len1::<ParamsL5>() + ParamsL5::LEN2);
        assert_eq!(ParamsL3::LEN1, formula_len1::<ParamsL3>());
        assert_eq!(ParamsL3::LEN2, formula_len2::<ParamsL3>());
        assert_eq!(ParamsL3::LEN, formula_len1::<ParamsL3>() + ParamsL3::LEN2);
        assert_eq!(ParamsTestFast::LEN, 67);
    }
}
