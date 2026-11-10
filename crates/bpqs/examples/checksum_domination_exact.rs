//! Exact checksum-side enumeration for the Budlum-BPQS domination hunt.
//!
//! Companion to crates/bpqs/SECURITY-ARGUMENT.md section 6. The security
//! argument prices the few-time hunt with the three checksum digits treated
//! as uniform ("first-order estimate"). This program computes the checksum
//! side EXACTLY, so the only un-priced term left in the first-order
//! decomposition is the message-into-checksum cross-correlation (the
//! reviewer's formal refinement, question 1 of
//! docs/BPQS_INDEPENDENT_REVIEW_CALL.md).
//!
//! Ground truth used here (must match crates/bpqs/src/params.rs):
//!  - LEN = 67 for any w = 16 row; 64 message digits + 3 checksum digits.
//!  - checksum T = sum_{j=1..64} (15 - m_j); since 15 - m_j is uniform on
//!    0..15 whenever m_j is, T is the sum of 64 iid uniform 0..15 digits.
//!  - checksum digit ranks: (T % 16, (T div 16) % 16, T div 256) - T < 1024
//!    for the any-w row, so rank 2 lives in 0..3 with probability 1.
//!
//! Everything is exact: a std-only arbitrary-precision unsigned integer
//! (`Big`, values reach about 2^2300 for q = 8) carries the counts, and every
//! probability is a numerator/denominator pair of `Big`s compared by
//! cross-multiplication. Floats appear ONLY to print the display digits, and
//! are derived from the exact pair (top 64 bits of each side).
//!
//! This is the Rust port of the former tools/bpqs_checksum_domination_exact.py;
//! the stdout is byte-identical to that script's, pinned in
//! `checksum_domination_exact.expected.txt`.
//!
//! Run:   cargo run --release --example checksum_domination_exact
//! Check: cargo run --release --example checksum_domination_exact -- --check
//!        (exit 1 if stdout differs from the committed expected output)
//! Test:  cargo test --release --example checksum_domination_exact

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt::Write as _;

// ---------------------------------------------------------------------------
// Minimal arbitrary-precision unsigned integer (little-endian u32 limbs,
// always trimmed: no high zero limbs, zero is the empty vector).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
struct Big(Vec<u32>);

impl Big {
    fn zero() -> Big {
        Big(Vec::new())
    }

    fn from_u64(v: u64) -> Big {
        let mut b = Big(vec![v as u32, (v >> 32) as u32]);
        b.trim();
        b
    }

    fn trim(&mut self) {
        while self.0.last() == Some(&0) {
            self.0.pop();
        }
    }

    fn is_zero(&self) -> bool {
        self.0.is_empty()
    }

    fn add(&self, o: &Big) -> Big {
        let (a, b) = if self.0.len() >= o.0.len() {
            (&self.0, &o.0)
        } else {
            (&o.0, &self.0)
        };
        let mut out = Vec::with_capacity(a.len() + 1);
        let mut carry = 0u64;
        for (i, &limb) in a.iter().enumerate() {
            let s = limb as u64 + b.get(i).copied().unwrap_or(0) as u64 + carry;
            out.push(s as u32);
            carry = s >> 32;
        }
        if carry != 0 {
            out.push(carry as u32);
        }
        Big(out)
    }

    fn mul(&self, o: &Big) -> Big {
        if self.is_zero() || o.is_zero() {
            return Big::zero();
        }
        let mut out = vec![0u32; self.0.len() + o.0.len()];
        for (i, &x) in self.0.iter().enumerate() {
            let mut carry = 0u64;
            for (j, &y) in o.0.iter().enumerate() {
                let t = x as u64 * y as u64 + out[i + j] as u64 + carry;
                out[i + j] = t as u32;
                carry = t >> 32;
            }
            out[i + o.0.len()] = carry as u32;
        }
        let mut b = Big(out);
        b.trim();
        b
    }

    fn pow(&self, e: u32) -> Big {
        let mut r = Big::from_u64(1);
        for _ in 0..e {
            r = r.mul(self);
        }
        r
    }

    fn bit_len(&self) -> u64 {
        match self.0.last() {
            None => 0,
            Some(&top) => (self.0.len() as u64 - 1) * 32 + (32 - top.leading_zeros() as u64),
        }
    }

    fn trailing_zeros(&self) -> u64 {
        let mut n = 0;
        for &l in &self.0 {
            if l == 0 {
                n += 32;
            } else {
                return n + l.trailing_zeros() as u64;
            }
        }
        n
    }

    fn shr(&self, bits: u64) -> Big {
        let (limbs, sh) = ((bits / 32) as usize, (bits % 32) as u32);
        if limbs >= self.0.len() {
            return Big::zero();
        }
        let src = &self.0[limbs..];
        let mut out = Vec::with_capacity(src.len());
        for i in 0..src.len() {
            let lo = src[i] >> sh;
            let hi = if sh > 0 {
                src.get(i + 1).map_or(0, |&n| n << (32 - sh))
            } else {
                0
            };
            out.push(lo | hi);
        }
        let mut b = Big(out);
        b.trim();
        b
    }

    /// Low 64 bits.
    fn low_u64(&self) -> u64 {
        let lo = self.0.first().copied().unwrap_or(0) as u64;
        let hi = self.0.get(1).copied().unwrap_or(0) as u64;
        lo | (hi << 32)
    }

    /// Top (up to) 64 bits and the number of bits dropped below them.
    fn top64(&self) -> (u64, i64) {
        let bl = self.bit_len();
        if bl <= 64 {
            (self.low_u64(), 0)
        } else {
            (self.shr(bl - 64).low_u64(), (bl - 64) as i64)
        }
    }

    fn cmp(&self, o: &Big) -> Ordering {
        self.0
            .len()
            .cmp(&o.0.len())
            .then_with(|| self.0.iter().rev().cmp(o.0.iter().rev()))
    }
}

/// Exact rational num/den (not reduced; equality is cross-multiplication).
#[derive(Clone, Debug)]
struct Frac {
    num: Big,
    den: Big,
}

impl Frac {
    fn new(num: Big, den: Big) -> Frac {
        Frac { num, den }
    }

    fn eq_exact(&self, o: &Frac) -> bool {
        self.num.mul(&o.den).cmp(&o.num.mul(&self.den)) == Ordering::Equal
    }

    /// Display-only conversion; relative error about 2^-52 from the top 64
    /// bits of each side.
    fn to_f64(&self) -> f64 {
        if self.num.is_zero() {
            return 0.0;
        }
        let (mn, sn) = self.num.top64();
        let (md, sd) = self.den.top64();
        (mn as f64 / md as f64) * 2f64.powi((sn - sd) as i32)
    }
}

fn fmt(x: &Frac, ndigits: usize) -> String {
    format!("{:.*}", ndigits, x.to_f64())
}

fn log2(x: &Frac) -> f64 {
    x.to_f64().log2()
}

// ---------------------------------------------------------------------------
// The enumeration.
// ---------------------------------------------------------------------------

const W: usize = 16;
const MSG_DIGITS: usize = 64;
const T_MAX: usize = (W - 1) * MSG_DIGITS + 1; // 961 bins, T in 0..960

/// Exact distribution of T = sum of MSG_DIGITS iid Uniform(0..W-1).
fn checksum_dist() -> (Vec<Big>, Big) {
    let mut counts = vec![Big::from_u64(1)]; // count per partial sum
    for _ in 0..MSG_DIGITS {
        let mut nxt = vec![Big::zero(); counts.len() + (W - 1)];
        for (s, c) in counts.iter().enumerate() {
            for v in 0..W {
                nxt[s + v] = nxt[s + v].add(c);
            }
        }
        counts = nxt;
    }
    let total = counts.iter().fold(Big::zero(), |a, c| a.add(c));
    assert!(total == Big::from_u64(W as u64).pow(MSG_DIGITS as u32) && counts.len() == T_MAX);
    (counts, total)
}

fn digits_of(t: usize) -> [usize; 3] {
    [t % W, (t / W) % W, t / (W * W)]
}

/// Marginal of one digit rank as raw counts (probability = count / total).
fn marginal(counts: &[Big], rank: usize) -> Vec<Big> {
    let mut raw = vec![Big::zero(); W];
    for (t, c) in counts.iter().enumerate() {
        let d = digits_of(t)[rank];
        raw[d] = raw[d].add(c);
    }
    raw
}

/// E[min of q iid draws of the digit] = sum_{v>=1} P(D >= v)^q, as an exact
/// fraction over total^q.
fn e_min(marg: &[Big], total: &Big, q: u32) -> Frac {
    let mut num = Big::zero();
    for v in 1..W {
        let tail = marg[v..].iter().fold(Big::zero(), |a, c| a.add(c));
        num = num.add(&tail.pow(q));
    }
    Frac::new(num, total.pow(q))
}

/// Exact P(C <= H digitwise) for two iid checksum vectors (q = 1).
fn domination_prob_pair(counts: &[Big], total: &Big) -> Frac {
    let mut num = Big::zero();
    for (t_c, c_c) in counts.iter().enumerate() {
        let dc = digits_of(t_c);
        for (t_h, c_h) in counts.iter().enumerate() {
            let dh = digits_of(t_h);
            if (0..3).all(|r| dc[r] <= dh[r]) {
                num = num.add(&c_c.mul(c_h));
            }
        }
    }
    Frac::new(num, total.mul(total))
}

/// P(candidate checksum digitwise <= min of q_h honest draws, each).
///
/// min_{i<=q} digit_r >= v  <=>  all q draws have digit_r >= v; joint over
/// the 3 ranks requires the honest joint distribution of the digit VECTOR,
/// not just marginals. Honest joint: buckets of T by digit vector. Exact
/// value is sum_d c_d * reach_d^q / total^(q+1).
fn domination_prob_pair_q(counts: &[Big], total: &Big, q_h: u32) -> Frac {
    let mut bucket: BTreeMap<[usize; 3], Big> = BTreeMap::new();
    for (t, c) in counts.iter().enumerate() {
        let d = digits_of(t);
        let e = bucket.entry(d).or_insert_with(Big::zero);
        *e = e.add(c);
    }
    let mut num = Big::zero();
    for (d, c) in &bucket {
        // reach(d): mass of honest vectors >= d componentwise
        let reach = bucket
            .iter()
            .filter(|(e, _)| (0..3).all(|r| e[r] >= d[r]))
            .fold(Big::zero(), |a, (_, c)| a.add(c));
        num = num.add(&c.mul(&reach.pow(q_h)));
    }
    Frac::new(num, total.pow(q_h + 1))
}

fn render() -> String {
    let mut o = String::new();
    let (counts, total) = checksum_dist();
    let margs: Vec<Vec<Big>> = (0..3).map(|r| marginal(&counts, r)).collect();
    let unif: Vec<Big> = vec![Big::from_u64(1); W];
    let unif_total = Big::from_u64(W as u64);
    let msg_term_p = Frac::new(Big::from_u64(17), Big::from_u64(32)); // (8.5/16) per digit

    let _ = writeln!(
        o,
        "== exact checksum digit marginals (rank: values with nonzero mass) =="
    );
    for (r, m) in margs.iter().enumerate() {
        let nz: Vec<String> = m
            .iter()
            .enumerate()
            .filter(|(_, c)| !c.is_zero())
            .map(|(v, c)| format!("{v}: '{}'", fmt(&Frac::new(c.clone(), total.clone()), 6)))
            .collect();
        let _ = writeln!(o, "  rank {r}: {{{}}}", nz.join(", "));
        // m_v / total == 1 / 16  <=>  16 * m_v == total, for every v
        let is_unif = m.iter().all(|c| {
            Frac::new(c.clone(), total.clone())
                .eq_exact(&Frac::new(Big::from_u64(1), unif_total.clone()))
        });
        let _ = writeln!(
            o,
            "  rank {r}: matches uniform exactly? {}",
            if is_unif { "True" } else { "False" }
        );
    }

    let _ = writeln!(
        o,
        "\n== E[min of q iid draws] per checksum rank (uniform compare) =="
    );
    for q in [1u32, 2, 4, 8] {
        let vals: Vec<String> = (0..3)
            .map(|r| format!("'{}'", fmt(&e_min(&margs[r], &total, q), 4)))
            .collect();
        let vals_u = fmt(&e_min(&unif, &unif_total, q), 4);
        let _ = writeln!(o, "  q={q}: ranks [{}]  uniform {vals_u}", vals.join(", "));
    }

    let _ = writeln!(o, "\n== checksum-side joint domination term ==");
    let p1 = domination_prob_pair(&counts, &total);
    let p1u = Frac::new(msg_term_p.num.pow(3), msg_term_p.den.pow(3)); // uniform first-order value
                                                                       // Python printed the bit-length difference of the REDUCED fraction. The
                                                                       // denominator total^2 is a power of two here, so reducing is exactly
                                                                       // stripping min(tz(num), tz(den)) common factors of two.
    let strip = p1.num.trailing_zeros().min(p1.den.trailing_zeros());
    let bl_diff = p1.num.shr(strip).bit_len() as i64 - p1.den.shr(strip).bit_len() as i64;
    let _ = writeln!(
        o,
        "  exact  P(C<=H over 3 ranks), q=1: {}  bit-length difference {}",
        fmt(&p1, 6),
        bl_diff
    );
    let _ = writeln!(o, "  uniform first-order (17/32)^3:   {}", fmt(&p1u, 6));
    for q in [1u32, 2, 4, 8] {
        let p = domination_prob_pair_q(&counts, &total, q);
        let _ = writeln!(
            o,
            "  q_honest={q}: exact P(C <= min over honest q, joint ranks) = {}  log2 = {:.3}",
            fmt(&p, 6),
            log2(&p)
        );
    }

    let _ = writeln!(o, "\n== refined q=1 first-order work factor ==");
    let msg_term = Frac::new(
        msg_term_p.num.pow(MSG_DIGITS as u32),
        msg_term_p.den.pow(MSG_DIGITS as u32),
    );
    let refined = Frac::new(msg_term.num.mul(&p1.num), msg_term.den.mul(&p1.den));
    let uniform_fs = Frac::new(msg_term.num.mul(&p1u.num), msg_term.den.mul(&p1u.den));
    let _ = writeln!(
        o,
        "  msg-position term (17/32)^64: log2 = {:.3}",
        log2(&msg_term)
    );
    let _ = writeln!(o, "  exact checksum term:          log2 = {:.3}", log2(&p1));
    let _ = writeln!(
        o,
        "  refined total:                log2 = {:.3}   (first-order-uniform was {:.3})",
        log2(&refined),
        log2(&uniform_fs)
    );

    let _ = writeln!(o, "\n== rank-2 support check ==");
    let hi = counts
        .iter()
        .enumerate()
        .filter(|(t, c)| digits_of(*t)[2] >= 4 && !c.is_zero())
        .count();
    let _ = writeln!(
        o,
        "  T values with rank2 digit >= 4 and positive mass: {hi} (expect 0)"
    );
    o
}

const EXPECTED: &str = include_str!("checksum_domination_exact.expected.txt");

fn main() {
    let out = render();
    if std::env::args().any(|a| a == "--check") {
        if out == EXPECTED {
            println!("checksum_domination_exact: output matches the pinned expected text");
        } else {
            eprintln!("checksum_domination_exact: OUTPUT DIFFERS from checksum_domination_exact.expected.txt");
            eprintln!("{out}");
            std::process::exit(1);
        }
    } else {
        print!("{out}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_equals_pinned_python_output() {
        assert_eq!(render(), EXPECTED);
    }

    #[test]
    fn big_matches_u128() {
        let xs: [u64; 6] = [
            0,
            1,
            0xffff_ffff,
            0x1_0000_0000,
            u64::MAX,
            0x1234_5678_9abc_def0,
        ];
        for &a in &xs {
            for &b in &xs {
                let (ba, bb) = (Big::from_u64(a), Big::from_u64(b));
                let sum = a as u128 + b as u128;
                let prod = a as u128 * b as u128;
                let to128 = |x: &Big| {
                    x.0.iter()
                        .rev()
                        .fold(0u128, |acc, &l| (acc << 32) | l as u128)
                };
                assert_eq!(to128(&ba.add(&bb)), sum);
                assert_eq!(to128(&ba.mul(&bb)), prod);
                assert_eq!(ba.cmp(&bb), a.cmp(&b));
            }
        }
    }

    #[test]
    fn big_pow_shift_bits() {
        let p = Big::from_u64(16).pow(64); // 2^256
        assert_eq!(p.bit_len(), 257);
        assert_eq!(p.trailing_zeros(), 256);
        assert_eq!(p.shr(256), Big::from_u64(1));
        assert_eq!(p.shr(257), Big::zero());
        assert_eq!(Big::from_u64(3).pow(41).low_u64(), 3u64.pow(41));
    }

    #[test]
    fn frac_cross_multiplication_and_display() {
        let half = Frac::new(Big::from_u64(17), Big::from_u64(34));
        assert!(half.eq_exact(&Frac::new(Big::from_u64(1), Big::from_u64(2))));
        assert_eq!(fmt(&half, 3), "0.500");
        let tiny = Frac::new(Big::from_u64(1), Big::from_u64(2).pow(300));
        assert_eq!(log2(&tiny), -300.0);
    }
}
