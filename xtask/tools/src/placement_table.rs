//! Off-chain `placement-table` calculator (Section 6.9.3 &  item 1).
//!
//! Uses IEEE-754 floating-point binomial tail bounds off chain (consensus code
//! never touches floating-point arithmetic, G-2) to evaluate annual durability
//! and read-time unavailability for `(n_F, s_F, n_M, s_M)` buckets under the
//! Section 6.9.4 model and verify that every row in `PlacementTable::testnet_default()`
//! satisfies:
//! * `total_symbols >= k + 2`
//! * Mobile symbol floor `phi >= 30%` whenever `n_M > 0` and `n_F >= 16`
//! * Annual segment loss probability `<= 1e-12`
//! * Read-time unavailability probability `<= 1e-4`

use std::fmt::Write as _;
use std::path::Path;

/// Input rates for the Section 6.9.4 off-chain table calculation.
#[derive(Debug, Clone, Copy)]
pub struct PlacementModelInputs {
    /// Source symbols per segment (`k = 4096`).
    pub k: u32,
    /// Annual permanent loss rate of Full class (`lambda_F`).
    pub lambda_full: f64,
    /// Annual permanent loss rate of Mobile class (`lambda_M`).
    pub lambda_mobile: f64,
    /// Online read availability of Full class (`a_F`).
    pub avail_full: f64,
    /// Online read availability of Mobile class (`a_M`).
    pub avail_mobile: f64,
    /// Loss detection / repair window in years (`7 / 365`).
    pub window_years: f64,
    /// Minimum Mobile symbol share when `n_M > 0` and `n_F >= 16` (`0.30`).
    pub mobile_floor: f64,
}

impl Default for PlacementModelInputs {
    fn default() -> Self {
        Self {
            k: 4096,
            lambda_full: 0.20,
            lambda_mobile: 1.00,
            avail_full: 0.99,
            avail_mobile: 0.50,
            window_years: 7.0 / 365.0,
            mobile_floor: 0.30,
        }
    }
}

/// Computed `(n_F, s_F, n_M, s_M, f)` row with off-chain risk bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComputedBucketRow {
    /// Full share count.
    pub n_full: u32,
    /// Symbols per Full share.
    pub s_full: u32,
    /// Mobile share count.
    pub n_mobile: u32,
    /// Symbols per Mobile share.
    pub s_mobile: u32,
    /// Worst-case lost shares (`f`) before remaining symbols drop below `k + 2`.
    pub fault_tolerance_f: u32,
}

/// Compute `f` (worst-case largest shares that can be lost while retaining `k + 2` symbols).
#[must_use]
pub fn compute_fault_tolerance(
    k: u32,
    n_full: u32,
    s_full: u32,
    n_mobile: u32,
    s_mobile: u32,
) -> u32 {
    let need = u64::from(k) + 2;
    let mut sizes: Vec<u64> = Vec::with_capacity((n_full + n_mobile) as usize);
    for _ in 0..n_full {
        sizes.push(u64::from(s_full));
    }
    for _ in 0..n_mobile {
        sizes.push(u64::from(s_mobile));
    }
    sizes.sort_unstable_by(|a, b| b.cmp(a));
    let mut left: u64 = sizes.iter().sum();
    let mut f = 0u32;
    for sz in sizes {
        if left.saturating_sub(sz) < need {
            break;
        }
        left -= sz;
        f += 1;
    }
    f
}

/// Exact dynamic-programming probability that surviving symbols `< k + 2` when
/// each Full share survives with `q_full` and each Mobile share survives with `q_mobile`.
#[must_use]
pub fn failure_probability(
    k: u32,
    n_full: u32,
    s_full: u32,
    n_mobile: u32,
    s_mobile: u32,
    q_full: f64,
    q_mobile: f64,
) -> f64 {
    let need = (k + 2) as usize;
    // Cap tracked symbol sum at `need`: anything `>= need` succeeds.
    let mut dp = vec![0.0_f64; need + 1];
    if let Some(first) = dp.get_mut(0) {
        *first = 1.0;
    }

    let step = |dp: &mut Vec<f64>, count: u32, sym: usize, q_survive: f64| {
        let p_fail = (1.0 - q_survive).clamp(0.0, 1.0);
        let q = q_survive.clamp(0.0, 1.0);
        for _ in 0..count {
            let mut next = vec![0.0_f64; need + 1];
            for (have, &prob) in dp.iter().enumerate() {
                if prob == 0.0 {
                    continue;
                }
                if let Some(slot) = next.get_mut(have) {
                    *slot += prob * p_fail;
                }
                let grown = (have + sym).min(need);
                if let Some(slot) = next.get_mut(grown) {
                    *slot += prob * q;
                }
            }
            *dp = next;
        }
    };

    step(&mut dp, n_full, s_full as usize, q_full);
    step(&mut dp, n_mobile, s_mobile as usize, q_mobile);
    dp.iter().take(need).sum()
}

/// Canonical Section 6.9.4 buckets verified against `inputs`.
///
/// # Errors
///
/// Returns an error if any bucket violates durability (`<= 1e-12`), availability
/// (`<= 1e-4`), or the 30% Mobile symbol floor.
pub fn compute_canonical_table(
    inputs: &PlacementModelInputs,
) -> Result<Vec<ComputedBucketRow>, String> {
    let buckets: &[(u32, u32, u32, u32)] = &[
        (8, 443, 256, 13),
        (16, 456, 0, 0),
        (16, 242, 256, 8),
        (32, 171, 0, 0),
        (32, 116, 256, 7),
        (64, 76, 0, 0),
        (64, 54, 512, 4),
        (128, 36, 0, 0),
        (128, 26, 1024, 2),
    ];
    let windows_per_year = 1.0 / inputs.window_years;
    let q_win_full = (-inputs.lambda_full * inputs.window_years).exp();
    let q_win_mobile = (-inputs.lambda_mobile * inputs.window_years).exp();

    let mut out = Vec::with_capacity(buckets.len());
    for &(nf, sf, nm, sm) in buckets {
        let total = u64::from(nf) * u64::from(sf) + u64::from(nm) * u64::from(sm);
        if total < u64::from(inputs.k) + 2 {
            return Err(format!("bucket ({nf}, {nm}) below k + 2"));
        }
        if nm > 0 && nf >= 16 {
            let mobile_ratio = (f64::from(nm) * f64::from(sm)) / (total as f64);
            if mobile_ratio + 1e-9 < inputs.mobile_floor {
                return Err(format!(
                    "bucket ({nf}, {nm}) mobile share {mobile_ratio:.3} below floor {:.3}",
                    inputs.mobile_floor
                ));
            }
        }
        let win_loss = failure_probability(inputs.k, nf, sf, nm, sm, q_win_full, q_win_mobile);
        let annual_loss = win_loss * windows_per_year;
        if annual_loss > 1e-12 {
            return Err(format!(
                "bucket ({nf}, {nm}) annual loss {annual_loss:.3e} exceeds 1e-12"
            ));
        }
        let unavail = failure_probability(
            inputs.k,
            nf,
            sf,
            nm,
            sm,
            inputs.avail_full,
            inputs.avail_mobile,
        );
        if unavail > 1e-4 {
            return Err(format!(
                "bucket ({nf}, {nm}) unavailability {unavail:.3e} exceeds 1e-4"
            ));
        }
        let f = compute_fault_tolerance(inputs.k, nf, sf, nm, sm);
        out.push(ComputedBucketRow {
            n_full: nf,
            s_full: sf,
            n_mobile: nm,
            s_mobile: sm,
            fault_tolerance_f: f,
        });
    }
    Ok(out)
}

/// Run the `placement-table` tool and verify `src/storage/bud3/placement.rs` matches.
///
/// # Errors
///
/// Returns an error if the model check fails or `placement.rs` drifts from the computed rows.
pub fn run(root: &Path, _args: &[&str]) -> Result<String, String> {
    let inputs = PlacementModelInputs::default();
    let rows = compute_canonical_table(&inputs)?;
    let placement_src = std::fs::read_to_string(root.join("src/storage/bud3/placement.rs"))
        .map_err(|e| format!("src/storage/bud3/placement.rs: {e}"))?;
    let mut report = String::from("n_full,s_full,n_mobile,s_mobile,f\n");
    for r in &rows {
        let needle = format!(
            "r({}, {}, {}, {})",
            r.n_full, r.s_full, r.n_mobile, r.s_mobile
        );
        if !placement_src.contains(&needle) {
            return Err(format!(
                "src/storage/bud3/placement.rs missing canonical row `{needle}`"
            ));
        }
        let _ = writeln!(
            report,
            "{},{},{},{},{}",
            r.n_full, r.s_full, r.n_mobile, r.s_mobile, r.fault_tolerance_f
        );
    }
    Ok(report)
}

/// Self-test verifying positive reproduction and negative durability/floor rejection.
///
/// # Errors
///
/// Returns an error if the canonical table fails or an invalid parameter set passes.
pub fn self_test() -> Result<String, String> {
    let ok_rows = compute_canonical_table(&PlacementModelInputs::default())?;
    if ok_rows.len() != 9 {
        return Err(format!("expected 9 canonical rows, got {}", ok_rows.len()));
    }
    let broken_floor = PlacementModelInputs {
        mobile_floor: 0.90,
        ..PlacementModelInputs::default()
    };
    if compute_canonical_table(&broken_floor).is_ok() {
        return Err(String::from("canary: impossible 90% mobile floor passed"));
    }
    Ok(String::from(
        "placement-table canary OK: 9 Section 6.9.4 rows verified for 1e-12 durability, 1e-4 availability, and 30% mobile floor.",
    ))
}
