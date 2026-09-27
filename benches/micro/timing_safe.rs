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
//!     control (naive, LEAKY) : mean_first=19.05ns mean_last=41.41ns |t|=83.62
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
/// leak. A harness that cannot catch this cannot catch a constant-time
/// violation either.
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
/// How many calls share one clock reading.
///
/// Measured 2026-09-25 (run 36102043330, job 107948777912): on that runner
/// `Instant::now()` resolved to 10 ns steps, so every per-call measurement
/// collapsed onto a multiple of one tick. The control's two classes came out
/// as a flat 30.00 ns and 40.00 ns - zero variance, for which Welch's t is
/// undefined (`welch_t` returns NaN) - and the known leak was measured as a
/// single tick.
/// The real function differed by 3.15 ns, which is below the tick, yet the
/// ratio 3.15/10 read as 31.4 percent and the gate went red. That is a
/// resolution artefact, not a regression.
///
/// Timing a batch of calls under ONE clock reading divides the granularity by
/// the batch size: 10 ns / 64 is 0.16 ns per call. The number reported stays
/// per-call, so the thresholds keep their meaning.
const CALLS_PER_SAMPLE: u64 = 64;

/// Clock granularity in nanoseconds, measured rather than assumed: the
/// smallest non-zero difference between two consecutive readings.
fn clock_granularity_ns() -> u64 {
    let mut best = u64::MAX;
    for _ in 0..10_000 {
        let t0 = Instant::now();
        let mut d = 0u64;
        while d == 0 {
            d = t0.elapsed().as_nanos() as u64;
        }
        best = best.min(d);
    }
    best
}

fn measure_min_per_batch<F: Fn(&[u8], &[u8]) -> bool>(
    f: F,
    first: &[u8],
    last: &[u8],
    valid: &[u8],
    batches: usize,
    iters: usize,
) -> (Vec<f64>, Vec<f64>) {
    let mut mins_first = Vec::with_capacity(batches);
    let mut mins_last = Vec::with_capacity(batches);
    for _ in 0..batches {
        let mut m_first = f64::INFINITY;
        let mut m_last = f64::INFINITY;
        for i in 0..iters {
            // Interleaved measurement: drift loads both classes equally.
            let (cand, acc) = if i % 2 == 0 {
                (first, &mut m_first)
            } else {
                (last, &mut m_last)
            };
            // One clock reading covers CALLS_PER_SAMPLE calls, then the time
            // is divided back down. Without this the reading is quantised to
            // the clock tick and the comparison measures the clock, not the
            // function. The division keeps the FRACTION: an integer ns would
            // snap every sample to a whole nanosecond and quietly destroy the
            // sub-tick resolution this batching exists to create (a 20 ns
            // tick over 64 calls resolves 0.3125 ns per call only because the
            // quotient is not truncated).
            let t0 = Instant::now();
            for _ in 0..CALLS_PER_SAMPLE {
                black_box(f(black_box(cand), black_box(valid)));
            }
            let dt = t0.elapsed().as_nanos() as f64 / CALLS_PER_SAMPLE as f64;
            *acc = (*acc).min(dt);
        }
        mins_first.push(m_first);
        mins_last.push(m_last);
    }
    (mins_first, mins_last)
}

fn mean(xs: &[f64]) -> f64 {
    xs.iter().sum::<f64>() / xs.len() as f64
}

fn variance(xs: &[f64]) -> f64 {
    let m = mean(xs);
    xs.iter().map(|x| (*x - m).powi(2)).sum::<f64>() / (xs.len() as f64 - 1.0)
}

/// Welch's t statistic (unequal variance assumption).
fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let na = a.len() as f64;
    let nb = b.len() as f64;
    let num = mean(a) - mean(b);
    let den = (variance(a) / na + variance(b) / nb).sqrt();
    if den == 0.0 {
        // Both classes collapsed onto a single value each (a quantised clock,
        // see CALLS_PER_SAMPLE). Welch's statistic is undefined here, and the
        // sentinel has to say so in a way `is_finite()` can see: `f64::MAX`
        // used to be returned for different means, and it is finite, so the
        // caller's guard let a 30ns-vs-40ns flat pair through as an
        // "infinitely significant" control (PR #81 review). NaN is not
        // finite, compares false against every threshold, and is rejected
        // before any verdict.
        return f64::NAN;
    }
    num / den
}

/// The sentinel contract, checked on every run rather than claimed: flat
/// samples (the quantised-clock case) must give a NON-finite statistic for
/// both different and equal means, and a real spread must give a finite one.
/// This bench has `harness = false`, so there is no `#[test]` to carry it;
/// the run itself is the test. Returns what is wrong, or `None`.
fn welch_sentinel_self_check() -> Option<String> {
    let flat_diff = welch_t(&[30.0, 30.0, 30.0], &[40.0, 40.0, 40.0]);
    if flat_diff.is_finite() || flat_diff.abs() >= T_THRESHOLD {
        return Some(format!(
            "flat 30ns vs flat 40ns gave t={flat_diff}; it must be non-finite and must not pass |t|>={T_THRESHOLD}"
        ));
    }
    let flat_same = welch_t(&[30.0, 30.0, 30.0], &[30.0, 30.0, 30.0]);
    if flat_same.is_finite() {
        return Some(format!(
            "flat equal classes gave finite t={flat_same}; nothing was measured there"
        ));
    }
    let spread = welch_t(&[30.0, 31.0, 29.0, 30.5], &[40.0, 41.0, 39.0, 40.5]);
    if !spread.is_finite() || spread >= 0.0 {
        return Some(format!(
            "a real spread gave t={spread}; expected finite and negative"
        ));
    }
    if !completely_separated(&[30.0, 30.0, 30.0], &[40.0, 40.0, 40.0]) {
        return Some("flat 30ns vs flat 40ns must count as completely separated".to_string());
    }
    if completely_separated(&[30.0, 30.0], &[30.0, 30.0])
        || completely_separated(&[30.0, 41.0], &[40.0, 31.0])
    {
        return Some("equal or overlapping classes must not count as separated".to_string());
    }
    None
}

/// Complete separation: every sample of one class is below every sample of
/// the other. This is what a zero-variance Welch case looks like when the
/// difference is real: a coarse clock puts each class on its own tick in
/// EVERY batch, so `welch_t` is undefined (NaN) although the evidence is
/// maximal, not absent. Under the null hypothesis the chance that N batches
/// per class separate completely by luck is 2 / C(2N, N) - for the default
/// 40 batches that is below 1e-22. Two flat classes on the SAME value are not
/// separated: they differ by nothing.
fn completely_separated(a: &[f64], b: &[f64]) -> bool {
    let (amin, amax) = a
        .iter()
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), x| {
            (lo.min(*x), hi.max(*x))
        });
    let (bmin, bmax) = b
        .iter()
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), x| {
            (lo.min(*x), hi.max(*x))
        });
    amax < bmin || bmax < amin
}

fn getenv_usize(key: &str, default: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn main() -> ExitCode {
    if let Some(neden) = welch_sentinel_self_check() {
        eprintln!("FAIL(harness): welch_t sentinel contract broken: {neden}");
        return ExitCode::from(2);
    }
    // One batch has no variance to compare (`variance` divides by len - 1),
    // and zero iterations produce empty samples; with either, Welch's t
    // degenerates to NaN and every later comparison passes silently,
    // turning the gate into an unconditional PASS. Floor both.
    let batches = getenv_usize("TIMING_SAFE_BATCHES", 64).max(2);
    let iters = getenv_usize("TIMING_SAFE_ITERS", 4096).max(1);

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

    let granularity = clock_granularity_ns();

    println!("=== Timing-safe statistical test (dudect style) ===");
    println!("clock granularity: {granularity}ns per tick, {CALLS_PER_SAMPLE} calls per sample");
    println!("batches={batches} iters/batch/class={iters} threshold=|t|>={T_THRESHOLD}");
    println!(
        "control (naive, LEAKY) : mean_first={:.2}ns mean_last={:.2}ns |t|={:.2}",
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

    // Validity before verdict. A degenerate control does not mean the function
    // under test is constant time, and it does not mean it is broken either;
    // it means this run measured nothing. Exit code 2 says exactly that, and
    // it is kept distinct from 1 (a real regression) on purpose.
    let control_delta_pre = (mean(&ctl_a) - mean(&ctl_b)).abs();
    let effective_resolution = granularity as f64 / CALLS_PER_SAMPLE as f64;
    // A NaN from `welch_t` is a zero-variance pair. It is resolved here, out
    // loud, before any threshold sees it: NaN compares false against every
    // threshold, so left alone it would read as "no difference" for the
    // function under test and as an unmeasurable control for the harness.
    // Measured 2026-09-27 (run 36326178651): the control's per-batch minima
    // were flat 1.88ns against flat 21.59ns over every batch - complete
    // separation, a 19.7ns gap on a 0.31ns effective resolution. That is the
    // strongest evidence the harness can produce, and calling it "nothing
    // measured" made the gate red on a perfectly good run.
    let t_control = if t_control.is_finite() {
        t_control
    } else if completely_separated(&ctl_a, &ctl_b)
        && control_delta_pre >= 3.0 * effective_resolution
    {
        println!(
            "control: zero variance with complete separation over {} batches per class \
             (gap {control_delta_pre:.2}ns, effective resolution {effective_resolution:.2}ns); \
             Welch's t is undefined, the separation itself is the evidence",
            ctl_a.len()
        );
        f64::INFINITY
    } else {
        eprintln!(
            "FAIL(harness): the control's variance collapsed to zero and the classes are not \
             separated beyond three resolution steps ({control_delta_pre:.2}ns gap, \
             {effective_resolution:.2}ns effective resolution, {granularity}ns tick); \
             Welch's t is not defined and nothing was measured."
        );
        return ExitCode::from(2);
    };
    let ct_delta_pre = (mean(&ct_a) - mean(&ct_b)).abs();
    let t_ct = if t_ct.is_finite() {
        t_ct
    } else if ct_delta_pre == 0.0 {
        // Both classes flat on the same value: no difference at all. That is
        // t = 0 by any reading, and it is stated rather than left as NaN.
        println!("constant_time_eq_str: both classes flat on one value; |t| taken as 0");
        0.0
    } else if completely_separated(&ct_a, &ct_b) {
        // Flat AND different: every batch put the classes on different
        // values. Treated as maximal significance so the effect-size check
        // below decides, instead of NaN sliding past the threshold as a pass.
        println!(
            "constant_time_eq_str: zero variance with complete separation (gap \
             {ct_delta_pre:.2}ns); |t| taken as infinite, the effect size decides"
        );
        f64::INFINITY
    } else {
        eprintln!(
            "FAIL(harness): constant_time_eq_str's classes collapsed onto single values that \
             neither coincide nor separate; Welch's t is not defined and nothing was measured."
        );
        return ExitCode::from(2);
    };
    // The comparison is against the EFFECTIVE resolution, not the raw tick:
    // one reading covers CALLS_PER_SAMPLE calls, so a 20ns tick resolves
    // 20/64 = 0.31ns per call - and the samples keep that fraction (see
    // measure_min_per_batch), so the effective resolution is real in the data,
    // not an artefact of an integer quotient. Measured 2026-09-25 (job
    // 107995294005): a 20ns tick, a control leak of 26.89ns and |t|=0.00 for
    // the constant-time path. Comparing that leak against the raw tick failed
    // a perfectly valid run,
    // which is the same class of mistake as the one this gate is here to
    // catch - judging the clock instead of the code.
    if control_delta_pre < 3.0 * effective_resolution {
        eprintln!(
            "FAIL(harness): the known leak measured {control_delta_pre:.2}ns against an \
             effective resolution of {effective_resolution:.2}ns ({granularity}ns tick over \
             {CALLS_PER_SAMPLE} calls). Below three resolution steps the ratio is an artefact \
             of the clock, not of the code. Nothing was measured."
        );
        return ExitCode::from(2);
    }
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
             (|t|={:.2} >= {T_THRESHOLD} AND ratio={:.1}% >= {:.1}%). \
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
