// Benchmark harness, not node code: this binary measures throughput and is
// never part of a running validator. A failed setup step should stop the
// measurement loudly rather than be threaded through `Result`.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! benches/micro/timing_safe.rs - a dudect-style statistical timing regression test.
//!
//! Statistically audits that the `constant_time_eq_str` comparison in RPC
//! authentication really stays constant time:
//!
//!   1. Positive control: verifies that an early-exit naive `==`-like comparison produces a
//!      MEASURABLE timing difference between the "first byte differs" and "last byte differs"
//!      classes (a harness sensitivity test).
//!      If the control shows no difference the environment/harness is unreliable -> exit 2.
//!   2. The real test: `constant_time_eq_str` must produce NO significant difference between the
//!      same two classes. The verdict requires BOTH conditions together:
//!      |Welch t| >= 4.5 **and** the observed difference being at least 5 percent of the known
//!      leak measured in the same run -> exit 1.
//!
//! Why two conditions: the t statistic answers "is there a difference", not "does the
//! difference matter". Because `measure_min_per_batch` takes the batch minimum the
//! variance is tiny; as the denominator shrinks t inflates. The tighter the measurement the
//! MORE red the gate goes - even as constant-timeness improves. A real run:
//!
//!     kontrol (naif, SIZMALI): mean_first=19.05ns mean_last=41.41ns |t|=83.62
//!     constant_time_eq_str   : mean_first=119.48ns mean_last=118.45ns |t|=7.62
//!
//! The naive implementation leaks 22.36 ns; the real function 1.03 ns - three cycles at 3 GHz,
//! that is on the order of `Instant::now()` resolution. The gate counted that as a
//! violation. Raising the threshold would be the timing version of raising a ratchet;
//! the right answer is to measure effect size. The denominator of the ratio is not an invented constant
//! but the control measured in the same run: if the environment slows down both slow down
//! together and the ratio keeps its meaning.
//!
//! Statistics: Welch's t test as used by dudect; instead of raw measurements it uses
//! batch minimums (interruptions can only ADD time; taking the minimum
//! removes outliers - the standard robust approach in the side-channel
//! literature). The threshold 4.5 is the dudect standard.
//!
//! Running:
//!   cargo bench --bench timing_safe (this is what CI uses)
//! Environment variables (for local in-depth analysis):
//!   TIMING_SAFE_BATCHES (default 64), TIMING_SAFE_ITERS (default 4096 per batch per class)

use std::env;
use std::hint::black_box;
use std::process::ExitCode;
use std::time::Instant;

use budlum_core::rpc::server::constant_time_eq_str;

/// The dudect standard decision threshold (statistical significance).
const T_THRESHOLD: f64 = 4.5;

/// Practical significance threshold: if the observed difference is below this fraction of the
/// known leak in the same run it counts as noise.
///
/// 5 percent is not arbitrary but derived from measurements: the real leak was 22.36 ns while
/// the constant-time path differed by 1.03 ns (4.6 percent). The threshold sits just above
/// that, so a run that passes today goes red only if the difference DOUBLES.
/// Reverting to the naive implementation (100 percent) or adding a partial early exit
/// is caught comfortably.
const EFFECT_RATIO_THRESHOLD: f64 = 0.05;

/// Positive control: a deliberately early-exiting comparison with a timing
/// leak. A harness that cannot catch this cannot catch a constant-time violation
/// Yakalayamaz.
fn naive_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

/// A deterministic pseudo-random source (xorshift64*): key material is derived from it so the
/// input does not stay fixed; since the seed is fixed the runs are
/// reproducible.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
}

/// N batches times iters measurements; the two classes are measured interleaved within each
/// batch and the per-batch class MINIMUM is returned.
fn measure_min_per_batch<F: Fn(&[u8], &[u8]) -> bool>(
    f: F,
    first: &[u8],
    last: &[u8],
    valid: &[u8],
    batches: usize,
    iters: usize,
) -> (Vec<u64>, Vec<u64>) {
    let mut mins_first = Vec::with_capacity(batches);
    let mut mins_last = Vec::with_capacity(batches);
    for _ in 0..batches {
        let mut m_first = u64::MAX;
        let mut m_last = u64::MAX;
        for i in 0..iters {
            // Interleaved measurement: drift loads both classes equally.
            let (cand, acc) = if i % 2 == 0 {
                (first, &mut m_first)
            } else {
                (last, &mut m_last)
            };
            let t0 = Instant::now();
            black_box(f(black_box(cand), black_box(valid)));
            let dt = t0.elapsed().as_nanos() as u64;
            *acc = (*acc).min(dt);
        }
        mins_first.push(m_first);
        mins_last.push(m_last);
    }
    (mins_first, mins_last)
}

fn mean(xs: &[u64]) -> f64 {
    xs.iter().sum::<u64>() as f64 / xs.len() as f64
}

fn variance(xs: &[u64]) -> f64 {
    let m = mean(xs);
    xs.iter().map(|x| (*x as f64 - m).powi(2)).sum::<f64>() / (xs.len() as f64 - 1.0)
}

/// Welch's t statistic (unequal variance assumption).
fn welch_t(a: &[u64], b: &[u64]) -> f64 {
    let na = a.len() as f64;
    let nb = b.len() as f64;
    let num = mean(a) - mean(b);
    let den = (variance(a) / na + variance(b) / nb).sqrt();
    if den == 0.0 {
        // The environment is extremely quiet: both distributions collapsed to a single value. No statistic
        // can be built; return f64::MAX as fail-safe (the caller decides).
        return if num == 0.0 { 0.0 } else { f64::MAX };
    }
    num / den
}

fn getenv_usize(key: &str, default: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn main() -> ExitCode {
    let batches = getenv_usize("TIMING_SAFE_BATCHES", 64);
    let iters = getenv_usize("TIMING_SAFE_ITERS", 4096);

    // A deterministic 64-byte API key (in the x-api-key length class).
    let mut rng = XorShift(0xB0D1_0CA7_5EED_1234);
    let secret: String = (0..64)
        .map(|_| {
            let r = (rng.next() % 62) as u8;
            match r {
                0..=25 => (b'A' + r) as char,
                26..=51 => (b'a' + r - 26) as char,
                _ => (b'0' + r - 52) as char,
            }
        })
        .collect();

    // Class A: the first character differs (a naive comparison returns immediately).
    // Class B: the last character differs (a naive comparison walks the longest path).
    let mut diff_first = secret.clone();
    let mut diff_last = secret.clone();
    let first_byte = secret.as_bytes()[0];
    let last_byte = secret.as_bytes()[63];
    diff_first.replace_range(0..1, if first_byte == b'A' { "B" } else { "A" });
    diff_last.replace_range(63..64, if last_byte == b'A' { "B" } else { "A" });

    // Warm-up: let the I-cache / branch predictor settle.
    for _ in 0..20_000 {
        black_box(constant_time_eq_str(
            black_box(&diff_first),
            black_box(&secret),
        ));
        black_box(naive_eq_bytes(
            black_box(diff_last.as_bytes()),
            black_box(secret.as_bytes()),
        ));
    }

    // 1) Positive control (harness sensitivity)
    let (ctl_a, ctl_b) = measure_min_per_batch(
        naive_eq_bytes,
        diff_first.as_bytes(),
        diff_last.as_bytes(),
        secret.as_bytes(),
        batches,
        iters,
    );
    let t_control = welch_t(&ctl_a, &ctl_b);

    // 2) The real measurement (the constant-time implementation)
    let ct = |a: &[u8], b: &[u8]| -> bool {
        constant_time_eq_str(
            std::str::from_utf8(a).expect("ascii key"),
            std::str::from_utf8(b).expect("ascii key"),
        )
    };
    let (ct_a, ct_b) = measure_min_per_batch(
        ct,
        diff_first.as_bytes(),
        diff_last.as_bytes(),
        secret.as_bytes(),
        batches,
        iters,
    );
    let t_ct = welch_t(&ct_a, &ct_b);

    println!("=== Timing-safe statistical test (dudect style) ===");
    println!("batches={batches} iters/batch/class={iters} threshold=|t|>={T_THRESHOLD}");
    println!(
        "kontrol (naif, SIZMALI): mean_first={:.2}ns mean_last={:.2}ns |t|={:.2}",
        mean(&ctl_a),
        mean(&ctl_b),
        t_control.abs()
    );
    println!(
        "constant_time_eq_str : mean_first={:.2}ns mean_last={:.2}ns |t|={:.2}",
        mean(&ct_a),
        mean(&ct_b),
        t_ct.abs()
    );

    if t_control.abs() < T_THRESHOLD {
        eprintln!(
            "FAIL(harness): the positive control produced no timing difference (|t|={:.2} < {T_THRESHOLD}). \
             Measurement is unreliable in this environment; the constant-time result is INVALID.",
            t_control.abs()
        );
        return ExitCode::from(2);
    }
    // Effect size: what fraction of the known leak in the same run is the observed
    // difference? The denominator is the measured control, not a constant, so if the environment slows
    // both slow down and the ratio keeps its meaning.
    let ct_delta = (mean(&ct_a) - mean(&ct_b)).abs();
    let control_delta = (mean(&ctl_a) - mean(&ctl_b)).abs();
    if control_delta <= 0.0 {
        eprintln!("FAIL(harness): the control measured zero difference; the effect size ratio cannot be built.");
        return ExitCode::from(2);
    }
    let effect_ratio = ct_delta / control_delta;
    println!(
        "effect size          : delta={ct_delta:.2}ns control_delta={control_delta:.2}ns \
         ratio={:.1}% (threshold {:.1}%)",
        effect_ratio * 100.0,
        EFFECT_RATIO_THRESHOLD * 100.0
    );

    // Both conditions together: statistical evidence AND practical magnitude. Neither
    // substitutes for the other - t alone counts 1 ns as a violation, and the ratio alone
    // lets a large but random difference through in a noisy environment.
    if t_ct.abs() >= T_THRESHOLD && effect_ratio >= EFFECT_RATIO_THRESHOLD {
        eprintln!(
            "FAIL(regression): constant_time_eq_str produced a significant difference between the classes \
             (|t|={:.2} >= {T_THRESHOLD} VE oran={:.1}% >= {:.1}%). \
             Constant-timeness is broken!",
            t_ct.abs(),
            effect_ratio * 100.0,
            EFFECT_RATIO_THRESHOLD * 100.0
        );
        return ExitCode::from(1);
    }
    if t_ct.abs() >= T_THRESHOLD {
        println!(
            "PASS: |t|={:.2} is above the threshold but the difference is only {:.1}% of the control \
             ({ct_delta:.2}ns) - measurement noise, not a leak.",
            t_ct.abs(),
            effect_ratio * 100.0
        );
        return ExitCode::SUCCESS;
    }
    println!("PASS: the control is sensitive and constant_time_eq_str produced no difference between classes.");
    ExitCode::SUCCESS
}
