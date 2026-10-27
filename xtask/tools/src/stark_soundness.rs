//! `stark-soundness`: how many bits of security the `BudZero` STARK configuration gives.
//!
//! The tool reads the FRI parameters out of `build_config` in
//! `budzero/bud-proof/src/plonky3_prover.rs` and computes three numbers:
//!
//! 1. **Assumed** security, the `ethSTARK` reading. It leans on the random-words
//!    conjecture for Reed-Solomon proximity (list size 1, decoding up to capacity).
//! 2. **Provable** security, with no assumption. It uses the unique-decoding and the
//!    Johnson-bound (list-decoding) regimes of the FRI analysis, the best proximity
//!    parameter `m` found by search, and nothing conjectured.
//! 3. **Quantum reading** of the provable composite. A quantum adversary searches the
//!    Fiat-Shamir challenges with Grover. Every search-type term (a challenge that
//!    can be re-sampled, grinding bits included) therefore counts half its bits. The
//!    collision term of the Merkle hash counts `n/3` bits (Brassard-Hoyer-Tapp)
//!    instead of `n/2`.
//!
//! # Why these formulas
//!
//! The arithmetic is a port of Plonky3's own `p3-security` crate (0.7.0, the version
//! the prover is pinned to), which mirrors the Ethereum Foundation `soundcalc`
//! calculator [S-17] and the papers below. The port is dependency-free on purpose
//! (this crate has no dependencies). Every term is `-log2(error)`, higher is better,
//! and the composite is the minimum over terms (the round-by-round convention used by
//! `soundcalc`), capped by the collision resistance of the commitment hash.
//!
//! Terms, for a field of `|F|` elements (the extension field), trace length `k`,
//! blowup rate `rho = 2^-log_blowup`, domain size `n = k / rho`:
//!
//! * AIR composition: `L * constraints / |F|`.
//! * DEEP-ALI: `L * max(deg * (k + c - 1) + (k - 1), (chunks + 1) * k + c - 1) / |F|`
//!   with `c` the number of opening points and `chunks` the quotient split.
//! * `LogUp`: `N * (W + 2) / |F|` with `N` the number of interactions times `k`
//!   and `W` the widest message.
//! * Batching of committed columns into one low-degree test (Johnson regime):
//!   `2 (m + 1/2)^5 n / (3 rho^(3/2)) * (columns - 1) / |F|`.
//! * FRI commit phase, unique decoding: `(arity - 1) (n + 1) / |F|`, plus the
//!   commit-phase grinding bits.
//! * FRI commit phase, list decoding (BCHKS25 Theorem 1.5):
//!   `((2 (m + 1/2)^5 + 3 (m + 1/2) gamma rho) n / (3 rho^(3/2)) + (m + 1/2) / sqrt(rho)) (arity - 1) / |F|`.
//! * FRI query phase: `alpha^queries`, plus the query grinding bits, with
//!   `alpha = (1 + rho_plus) / 2` (unique decoding) or `alpha = (1 + 1/(2m)) sqrt(rho)`
//!   (list decoding, `L = (m + 1/2) / sqrt(rho)`).
//! * Conjectured query phase (random words): `queries * -log2(rho + eta)` with
//!   `eta = log2(e/rho) rho / log2|F|`, plus the query grinding bits.
//! * Merkle hash collision: `output_bits / 2`.
//!
//! Sources: `ethSTARK` (eprint 2021/582); Proximity Gaps for Reed-Solomon Codes
//! (2020/654); On the Security of STARKs with FRI (2024/1553); On the Distribution of
//! the Distances of Random Words (2025/2010); BCHKS25 improved list-decoding proximity
//! gaps (2025/2055); Haboeck, multivariate lookups based on logarithmic derivatives
//! (2022/1530). The quantum reading is the QROM result for Fiat-Shamir of
//! Kilian/Micali style arguments, Chiesa, Manohar and Spooner, "Succinct Arguments in
//! the Quantum Random Oracle Model" (2019/834) [S-27]: the soundness loss is quadratic
//! in the number of oracle queries and the collision term is cubic.
//!
//! # What is measured and what is bounded
//!
//! The FRI parameters, the extension degree, the maximum trace length and the trace
//! widths are read from the source. The AIR constraint count, constraint degree and
//! `LogUp` shape are not derived symbolically here; they are stated below as upper
//! bounds read by hand from `plonky3_air.rs`. Raising a bound can only lower the
//! reported bits, so a bound that is too high is the safe direction.

use crate::report::Report;
use std::fmt::Write as _;
use std::path::Path;

/// Where the parameters live.
pub const PROVER_REL: &str = "budzero/bud-proof/src/plonky3_prover.rs";
const ADAPTER_REL: &str = "budzero/bud-proof/src/adapter.rs";
const AIR_REL: &str = "budzero/bud-proof/src/plonky3_air.rs";
/// The generated section of the measurements document.
pub const DOC_REL: &str = "docs/pq/MEASUREMENTS.md";

const BEGIN: &str = "<!-- stark-soundness:begin -->";
const END: &str = "<!-- stark-soundness:end -->";

/// The bit target of.
pub const TARGET_BITS: f64 = 128.0;
/// Upper bound for the proximity parameter searched in the list-decoding regime
/// (the `soundcalc` and `p3-security` cap).
const LIST_M_CAP: u32 = 1000;
/// Output size of the Merkle hash (Keccak-256).
const HASH_OUTPUT_BITS: f64 = 256.0;

/// Upper bound on the number of AIR constraints (hand-read from `plonky3_air.rs`:
/// 252 assertion sites, some inside loops over bit decompositions of at most 64 bits).
const AIR_CONSTRAINTS_BOUND: u32 = 4096;
/// Upper bound on the AIR constraint degree (the Poseidon S-box is `x^7`, times one
/// selector, with a margin of one).
const AIR_DEGREE_BOUND: u32 = 9;
/// Opening points per column: the current row and the next row.
const AIR_COMBO: u32 = 2;
/// Upper bound on the `LogUp` interactions per row, summed over the register, memory and
/// program buses.
const LOGUP_INTERACTIONS_BOUND: u32 = 16;
/// Widest `LogUp` message: the program tuple has eight fields.
const LOGUP_WIDTH_BOUND: u32 = 8;
/// Extension degrees `p3-goldilocks` provides: binomial 2, cubic trinomial 3, binomial 5.
pub const AVAILABLE_DEGREES: [u32; 3] = [2, 3, 5];

/// The FRI knobs of `p3_fri::FriParameters` that decide soundness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fri {
    /// `log2(1 / rho)`.
    pub log_blowup: u32,
    /// `log2` of the folding factor.
    pub max_log_arity: u32,
    /// `log2` of the final polynomial length.
    pub log_final_poly_len: u32,
    /// Number of queries.
    pub num_queries: u32,
    /// Grinding bits on the folding challenges.
    pub commit_pow_bits: u32,
    /// Grinding bits on the query indices.
    pub query_pow_bits: u32,
}

/// Everything the formulas need.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Setup {
    /// The FRI parameters.
    pub fri: Fri,
    /// Degree of the challenge field over Goldilocks.
    pub ext_degree: u32,
    /// `log2` of the longest trace.
    pub log_trace: u32,
    /// Committed columns batched into the low-degree test.
    pub batched_columns: u32,
}

/// `-log2(error)` per named term.
#[derive(Clone, Debug, PartialEq)]
pub struct Reading {
    /// Name of the reading.
    pub name: String,
    /// The terms, in order.
    pub terms: Vec<(String, f64)>,
    /// The regime that produced it, `unique`, `list m=..` or `conjectured`.
    pub regime: String,
}

impl Reading {
    /// The minimum over the terms.
    #[must_use]
    pub fn bits(&self) -> f64 {
        self.terms.iter().map(|t| t.1).fold(f64::INFINITY, f64::min)
    }

    /// The name of the term that binds.
    #[must_use]
    pub fn binding(&self) -> &str {
        let mut best: Option<&(String, f64)> = None;
        for t in &self.terms {
            if best.is_none_or(|b| t.1 < b.1) {
                best = Some(t);
            }
        }
        best.map_or("none", |t| t.0.as_str())
    }
}

/// The three values asks for, plus the conjectured quantum reading.
#[derive(Clone, Debug, PartialEq)]
pub struct Verdict {
    /// Ethstark reading, assumption-based.
    pub assumed: Reading,
    /// Provable reading, assumption-free.
    pub provable: Reading,
    /// Quantum reading of the provable composite.
    pub quantum: Reading,
    /// Quantum reading of the assumed composite.
    pub quantum_assumed: Reading,
}

fn f(x: u32) -> f64 {
    f64::from(x)
}

fn pow2(x: u32) -> f64 {
    2f64.powi(i32::try_from(x).unwrap_or(i32::MAX))
}

fn rho(fri: &Fri) -> f64 {
    1.0 / pow2(fri.log_blowup)
}

/// `log2(p)` for the Goldilocks prime `2^64 - 2^32 + 1`, without a lossy integer cast.
fn log2_goldilocks() -> f64 {
    64.0 + (-(2f64.powi(-32)) + 2f64.powi(-64)).ln_1p() / std::f64::consts::LN_2
}

/// `log2` of the size of the challenge field.
fn field_bits(setup: &Setup) -> f64 {
    f(setup.ext_degree) * log2_goldilocks()
}

fn lde_log(setup: &Setup) -> u32 {
    setup.log_trace + setup.fri.log_blowup
}

fn constraint_chunks() -> f64 {
    f(AIR_DEGREE_BOUND
        .saturating_sub(1)
        .max(1)
        .next_power_of_two())
}

fn ali_bits(setup: &Setup, list: f64) -> f64 {
    (field_bits(setup) - list.log2() - f(AIR_CONSTRAINTS_BOUND).log2()).max(0.0)
}

fn deep_bits(setup: &Setup, list: f64) -> f64 {
    let k = pow2(setup.log_trace);
    let deg = f(AIR_DEGREE_BOUND.max(1));
    let combo = f(AIR_COMBO);
    let ethstark = deg * (k + combo - 1.0) + (k - 1.0);
    let chunked = (constraint_chunks() + 1.0) * k + combo - 1.0;
    let factor = ethstark.max(chunked).max(1.0);
    (field_bits(setup) - list.log2() - factor.log2()).max(0.0)
}

fn logup_bits(setup: &Setup) -> f64 {
    let n_log = f(setup.log_trace) + f(LOGUP_INTERACTIONS_BOUND).log2();
    (field_bits(setup) - n_log - (f(LOGUP_WIDTH_BOUND) + 2.0).log2()).max(0.0)
}

/// FRI commit-phase error in the unique-decoding regime. `None` when no fold occurs.
fn commit_unique(setup: &Setup) -> Option<f64> {
    let fm1 = pow2(setup.fri.max_log_arity) - 1.0;
    if fm1 <= 0.0 || setup.fri.max_log_arity == 0 {
        return None;
    }
    let layers =
        lde_log(setup).saturating_sub(setup.fri.log_final_poly_len) / setup.fri.max_log_arity;
    if layers == 0 {
        return None;
    }
    let n = pow2(lde_log(setup));
    let bits = field_bits(setup) - (fm1 * (n + 1.0)).log2() + f(setup.fri.commit_pow_bits);
    Some(bits.max(0.0))
}

fn alpha_list(fri: &Fri, m: u32) -> f64 {
    (1.0 + 0.5 / f(m)) * rho(fri).sqrt()
}

fn list_size(fri: &Fri, m: u32) -> f64 {
    (f(m) + 0.5) / rho(fri).sqrt()
}

/// FRI commit-phase error in the list-decoding regime at proximity parameter `m`.
fn commit_list(setup: &Setup, m: u32) -> Option<f64> {
    let fri = &setup.fri;
    let r = rho(fri);
    let sqrt_rho = r.sqrt();
    let m_half = f(m) + 0.5;
    let gamma = 1.0 - alpha_list(fri, m);
    if gamma <= 0.0 {
        return Some(0.0);
    }
    let fm1 = pow2(fri.max_log_arity) - 1.0;
    if fm1 <= 0.0 || fri.max_log_arity == 0 {
        return None;
    }
    let n = pow2(lde_log(setup));
    let numerator = (2.0 * m_half.powi(5) + 3.0 * m_half * gamma * r) * n;
    let eps_linear = numerator / (3.0 * r * sqrt_rho) + m_half / sqrt_rho;
    let eps_round = eps_linear * fm1;
    let field = field_bits(setup);
    let bits_linear = field - eps_round.max(1.0).log2() + f(fri.commit_pow_bits);
    let bits_n_over_q =
        field - pow2(fri.max_log_arity).log2() - (n + 1.0).log2() - (2.0 * f(m) + 1.0).log2()
            + 0.5 * r.log2()
            + f(fri.commit_pow_bits);
    Some(bits_linear.min(bits_n_over_q).max(0.0))
}

fn query_bits(alpha: f64, fri: &Fri) -> f64 {
    if !alpha.is_finite() || alpha <= 0.0 || alpha >= 1.0 {
        return 0.0;
    }
    f(fri.query_pow_bits) - f(fri.num_queries) * alpha.log2()
}

/// Batching of the committed columns into one low-degree test, list-decoding regime.
fn batch_list(setup: &Setup, m: u32) -> Option<f64> {
    if setup.batched_columns < 2 {
        return None;
    }
    let fri = &setup.fri;
    let m_half = f(m) + 0.5;
    let log_n = f(lde_log(setup));
    let constant = (2.0 * m_half.powi(5) / 3.0).log2();
    let log_rho_neg = 1.5 * f(fri.log_blowup);
    let error = log_n + constant + log_rho_neg;
    Some((field_bits(setup) - (error + (f(setup.batched_columns) - 1.0).log2())).max(0.0))
}

/// Batching, unique-decoding regime.
fn batch_unique(setup: &Setup) -> Option<f64> {
    if setup.batched_columns < 2 {
        return None;
    }
    let error = f(setup.log_trace) + f(setup.fri.log_blowup);
    Some((field_bits(setup) - (error + (f(setup.batched_columns) - 1.0).log2())).max(0.0))
}

fn collision_bits() -> f64 {
    HASH_OUTPUT_BITS / 2.0
}

fn push_opt(terms: &mut Vec<(String, f64)>, name: &str, bits: Option<f64>) {
    if let Some(b) = bits {
        terms.push((name.to_string(), b));
    }
}

/// The provable reading in the unique-decoding regime.
fn provable_unique(setup: &Setup) -> Reading {
    let fri = &setup.fri;
    let mut terms: Vec<(String, f64)> = Vec::new();
    terms.push(("air-composition".into(), ali_bits(setup, 1.0)));
    terms.push(("deep-ali".into(), deep_bits(setup, 1.0)));
    let k = pow2(setup.log_trace);
    let n = pow2(lde_log(setup));
    let rho_plus = (k + f(AIR_COMBO)) / n;
    let alpha = (1.0 + rho_plus) * 0.5;
    let ldt_ok = k + f(AIR_COMBO) < alpha * n;
    let query = if ldt_ok { query_bits(alpha, fri) } else { 0.0 };
    terms.push(("fri-query".into(), query));
    push_opt(&mut terms, "fri-commit", commit_unique(setup));
    push_opt(&mut terms, "batching", batch_unique(setup));
    terms.push(("logup".into(), logup_bits(setup)));
    terms.push(("merkle-collision".into(), collision_bits()));
    Reading {
        name: "provable".into(),
        terms,
        regime: "unique decoding".into(),
    }
}

/// The provable reading in the list-decoding regime at proximity parameter `m`.
fn provable_list_at(setup: &Setup, m: u32) -> Reading {
    let fri = &setup.fri;
    let l = list_size(fri, m);
    let alpha = alpha_list(fri, m);
    let gamma = 1.0 - alpha;
    let k = pow2(setup.log_trace);
    let n = pow2(lde_log(setup));
    let ldt_ok = alpha < 1.0 && gamma > 0.0 && k + f(AIR_COMBO) < (1.0 - gamma) * n;
    let mut terms: Vec<(String, f64)> = Vec::new();
    terms.push(("air-composition".into(), ali_bits(setup, l)));
    terms.push(("deep-ali".into(), deep_bits(setup, l)));
    terms.push((
        "fri-query".into(),
        if ldt_ok { query_bits(alpha, fri) } else { 0.0 },
    ));
    push_opt(
        &mut terms,
        "fri-commit",
        if ldt_ok {
            commit_list(setup, m)
        } else {
            Some(0.0)
        },
    );
    push_opt(&mut terms, "batching", batch_list(setup, m));
    terms.push(("logup".into(), logup_bits(setup)));
    terms.push(("merkle-collision".into(), collision_bits()));
    Reading {
        name: "provable".into(),
        terms,
        regime: format!("list decoding, m = {m}"),
    }
}

/// The proximity parameters the search tries. The `n * eta^2` precondition of the
/// `ethSTARK` analysis bounds `m` from above; at trace lengths of `2^10` and more the
/// cap of 1000 is the tighter one.
fn list_m_range(setup: &Setup) -> std::ops::RangeInclusive<u32> {
    let h = pow2(setup.log_trace);
    let upper = (1.0 / (2.0 * (((h + 2.0) / h).sqrt() - 1.0))).ceil();
    let mut hi = 2;
    while hi < LIST_M_CAP && f(hi + 1) <= upper {
        hi += 1;
    }
    3..=hi
}

/// The provable reading: the better of unique decoding and the best list-decoding `m`.
#[must_use]
pub fn provable(setup: &Setup) -> Reading {
    let mut best = provable_unique(setup);
    for m in list_m_range(setup) {
        let candidate = provable_list_at(setup, m);
        if candidate.bits() > best.bits() {
            best = candidate;
        }
    }
    best
}

/// The assumed (conjectured, `ethSTARK`) reading.
#[must_use]
pub fn assumed(setup: &Setup) -> Reading {
    let fri = &setup.fri;
    let r = rho(fri);
    let field = field_bits(setup);
    let eta = ((std::f64::consts::LOG2_E + f(fri.log_blowup)) * r) / field;
    let effective = r + eta;
    let query = if effective > 0.0 && effective < 1.0 {
        f(fri.num_queries) * -effective.log2() + f(fri.query_pow_bits)
    } else {
        f(fri.query_pow_bits)
    };
    let mut terms: Vec<(String, f64)> = Vec::new();
    terms.push(("air-composition".into(), ali_bits(setup, 1.0)));
    terms.push(("deep-ali".into(), deep_bits(setup, 1.0)));
    terms.push(("fri-query".into(), query));
    push_opt(&mut terms, "fri-commit", commit_unique(setup));
    terms.push(("logup".into(), logup_bits(setup)));
    terms.push(("merkle-collision".into(), collision_bits()));
    Reading {
        name: "assumed".into(),
        terms,
        regime: "conjectured (random words)".into(),
    }
}

/// The `ethSTARK` query formula, `queries * log_blowup + grinding`, for reference.
#[must_use]
pub fn legacy_ethstark_query_bits(fri: &Fri) -> f64 {
    f(fri.num_queries) * f(fri.log_blowup) + f(fri.query_pow_bits)
}

/// The quantum reading of a classical composite: search terms count half, the hash
/// collision term counts `n / 3`.
#[must_use]
pub fn quantum(classical: &Reading, name: &str) -> Reading {
    let terms = classical
        .terms
        .iter()
        .map(|(label, bits)| {
            if label == "merkle-collision" {
                (label.clone(), HASH_OUTPUT_BITS / 3.0)
            } else {
                (label.clone(), bits / 2.0)
            }
        })
        .collect();
    Reading {
        name: name.into(),
        terms,
        regime: classical.regime.clone(),
    }
}

/// All readings for one configuration.
#[must_use]
pub fn verdict(setup: &Setup) -> Verdict {
    let assumed = assumed(setup);
    let provable = provable(setup);
    Verdict {
        quantum: quantum(&provable, "quantum (provable)"),
        quantum_assumed: quantum(&assumed, "quantum (assumed)"),
        assumed,
        provable,
    }
}

/// The smallest query count that makes the provable reading reach `target`, for a
/// given extension degree and the other parameters of `setup`.
#[must_use]
pub fn minimal_queries(setup: &Setup, degree: u32, target: f64) -> Option<u32> {
    let mut trial = Setup {
        ext_degree: degree,
        ..*setup
    };
    for q in 1..=400 {
        trial.fri.num_queries = q;
        if provable(&trial).bits() >= target {
            return Some(q);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Reading the parameters out of the source.
// ---------------------------------------------------------------------------

fn strip_line_comments(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        out.push_str(line.split("//").next().unwrap_or(""));
        out.push('\n');
    }
    out
}

fn field_value(body: &str, name: &str) -> Result<u32, String> {
    for line in body.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(name) {
            if let Some(rest) = rest.trim_start().strip_prefix(':') {
                let digits: String = rest
                    .trim()
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect();
                return digits
                    .parse::<u32>()
                    .map_err(|e| format!("`{name}` in build_config is not a plain integer: {e}"));
            }
        }
    }
    Err(format!(
        "`{name}` is not set in the FriParameters literal of build_config"
    ))
}

/// Read the FRI parameters out of `build_config`.
///
/// # Errors
///
/// When the literal is missing or a field is not a plain integer.
pub fn parse_fri(prover_src: &str) -> Result<Fri, String> {
    let code = strip_line_comments(prover_src);
    let start = code
        .find("p3_fri::FriParameters {")
        .ok_or("build_config has no `p3_fri::FriParameters` literal")?;
    let tail = &code[start..];
    let end = tail
        .find("};")
        .ok_or("the FriParameters literal is not closed")?;
    let body = &tail[..end];
    Ok(Fri {
        log_blowup: field_value(body, "log_blowup")?,
        max_log_arity: field_value(body, "max_log_arity")?,
        log_final_poly_len: field_value(body, "log_final_poly_len")?,
        num_queries: field_value(body, "num_queries")?,
        commit_pow_bits: field_value(body, "commit_proof_of_work_bits")?,
        query_pow_bits: field_value(body, "query_proof_of_work_bits")?,
    })
}

/// Read the degree of the challenge field.
///
/// # Errors
///
/// When the alias is missing or names an extension this tool does not know.
pub fn parse_ext_degree(prover_src: &str) -> Result<u32, String> {
    let code = strip_line_comments(prover_src);
    let line = code
        .lines()
        .find(|l| l.trim_start().starts_with("type MyExtensionField"))
        .ok_or("plonky3_prover.rs has no `MyExtensionField` alias")?;
    if line.contains("CubicTrinomialExtensionField") {
        return Ok(3);
    }
    let after = line
        .split("BinomialExtensionField<Goldilocks,")
        .nth(1)
        .ok_or("MyExtensionField is neither a binomial nor a cubic Goldilocks extension")?;
    let digits: String = after
        .trim()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits
        .parse::<u32>()
        .map_err(|e| format!("the extension degree is not an integer: {e}"))
}

fn const_value(src: &str, name: &str) -> Result<u64, String> {
    let marker = format!("const {name}: usize =");
    let rest = src
        .split(&marker)
        .nth(1)
        .ok_or_else(|| format!("no `{name}` constant"))?;
    let expr = rest.split(';').next().unwrap_or("").trim();
    if let Some(shift) = expr.strip_prefix("1 << ") {
        let s: u32 = shift
            .trim()
            .parse()
            .map_err(|e| format!("`{name}` shift is not an integer: {e}"))?;
        return 1u64
            .checked_shl(s)
            .ok_or_else(|| format!("`{name}` overflows"));
    }
    expr.replace('_', "")
        .parse::<u64>()
        .map_err(|e| format!("`{name}` is not a plain integer: {e}"))
}

fn log2_exact(value: u64) -> Result<u32, String> {
    if value.is_power_of_two() {
        Ok(value.trailing_zeros())
    } else {
        Err(format!("{value} is not a power of two"))
    }
}

/// The setup of the tree under `root`.
///
/// # Errors
///
/// When a source file is missing or cannot be parsed.
pub fn read_setup(root: &Path) -> Result<Setup, String> {
    let read = |rel: &str| {
        std::fs::read_to_string(root.join(rel)).map_err(|e| format!("{rel} could not be read: {e}"))
    };
    let prover = read(PROVER_REL)?;
    let adapter = read(ADAPTER_REL)?;
    let air = read(AIR_REL)?;
    let max_trace = const_value(&adapter, "MAX_TRACE_LEN")?;
    let main = const_value(&air, "TRACE_WIDTH")?;
    let pre = const_value(&air, "PREPROCESSED_WIDTH")?;
    let ext_degree = parse_ext_degree(&prover)?;
    // Main trace, preprocessed trace, three accumulator columns in the extension
    // field and the quotient chunks (each an extension element, so `degree` base
    // columns).
    let batched =
        main + pre + u64::from(3 * ext_degree) + (constraint_chunks_u64() * u64::from(ext_degree));
    Ok(Setup {
        fri: parse_fri(&prover)?,
        ext_degree,
        log_trace: log2_exact(max_trace)?,
        batched_columns: u32::try_from(batched).map_err(|e| format!("column count: {e}"))?,
    })
}

fn constraint_chunks_u64() -> u64 {
    u64::from(
        AIR_DEGREE_BOUND
            .saturating_sub(1)
            .max(1)
            .next_power_of_two(),
    )
}

// ---------------------------------------------------------------------------
// Rendering.
// ---------------------------------------------------------------------------

fn terms_table(readings: &[&Reading]) -> String {
    let mut labels: Vec<String> = Vec::new();
    for r in readings {
        for (l, _) in &r.terms {
            if !labels.contains(l) {
                labels.push(l.clone());
            }
        }
    }
    let mut out = String::from("| Term |");
    for r in readings {
        let _ = write!(out, " {} |", r.name);
    }
    out.push_str("\n|---|");
    for _ in readings {
        out.push_str("---|");
    }
    out.push('\n');
    for l in &labels {
        let _ = write!(out, "| {l} |");
        for r in readings {
            match r.terms.iter().find(|t| &t.0 == l) {
                Some((_, b)) => {
                    let _ = write!(out, " {b:.1} |");
                }
                None => out.push_str(" n/a |"),
            }
        }
        out.push('\n');
    }
    out
}

/// The table of parameters read from the source.
fn render_parameters(setup: &Setup) -> String {
    let fri = &setup.fri;
    let mut s = String::new();
    s.push_str("### Parameters read from the source\n\n| Parameter | Value |\n|---|---|\n");
    let _ = writeln!(s, "| `log_blowup` | {} |", fri.log_blowup);
    let _ = writeln!(s, "| `max_log_arity` | {} |", fri.max_log_arity);
    let _ = writeln!(s, "| `log_final_poly_len` | {} |", fri.log_final_poly_len);
    let _ = writeln!(s, "| `num_queries` | {} |", fri.num_queries);
    let _ = writeln!(
        s,
        "| `commit_proof_of_work_bits` | {} |",
        fri.commit_pow_bits
    );
    let _ = writeln!(s, "| `query_proof_of_work_bits` | {} |", fri.query_pow_bits);
    let _ = writeln!(
        s,
        "| extension degree over Goldilocks | {} |",
        setup.ext_degree
    );
    let _ = writeln!(s, "| challenge field size | 2^{:.1} |", field_bits(setup));
    let _ = writeln!(
        s,
        "| longest trace (`MAX_TRACE_LEN`) | 2^{} |",
        setup.log_trace
    );
    let _ = writeln!(s, "| batched columns | {} |", setup.batched_columns);
    s.push_str("| Merkle hash | Keccak-256 (256 bit output) |\n\n");
    s
}

/// The generated section, without the markers.
#[must_use]
pub fn render_section(setup: &Setup) -> String {
    let v = verdict(setup);
    let fri = &setup.fri;
    let mut s = String::new();
    s.push_str("## STARK soundness\n\n");
    s.push_str(
        "Generated by `cargo run --manifest-path xtask/tools/Cargo.toml -- stark-soundness --write`. \
`--check` fails when this section no longer matches `build_config`. The formulas and \
sources are in the header of `xtask/tools/src/stark_soundness.rs`.\n\n",
    );
    s.push_str(&render_parameters(setup));
    s.push_str("### Result\n\n| Reading | Bits | Binding term | Regime |\n|---|---|---|---|\n");
    for (label, r) in [
        ("Assumed (ethSTARK, conjectured)", &v.assumed),
        ("Provable (no assumption)", &v.provable),
        ("Quantum reading of the provable value", &v.quantum),
    ] {
        let _ = writeln!(
            s,
            "| {label} | {:.1} | {} | {} |",
            r.bits(),
            r.binding(),
            r.regime
        );
    }
    let _ = writeln!(
        s,
        "\nQuantum reading of the assumed value: {:.1} bits (binding term: {}).",
        v.quantum_assumed.bits(),
        v.quantum_assumed.binding()
    );
    let _ = writeln!(
        s,
        "The legacy ethSTARK query formula `queries * log_blowup + grinding` alone gives {:.0} bits; it is shown \
because the comment in `config.rs` quotes it, and it ignores every other term.",
        legacy_ethstark_query_bits(fri)
    );
    let _ = writeln!(
        s,
        "Thetarget is {TARGET_BITS:.0} bits provable: {}.\n",
        if v.provable.bits() >= TARGET_BITS {
            "met"
        } else {
            "not met"
        }
    );
    s.push_str("### Per-term bits\n\n");
    s.push_str(&terms_table(&[&v.assumed, &v.provable, &v.quantum]));
    s.push_str("\n### Smallest query count that reaches the target\n\n");
    s.push_str("Other parameters as above, extension degree varied over the degrees `p3-goldilocks` provides.\n\n");
    s.push_str("| Extension degree | Field bits | Queries for 128 bit provable |\n|---|---|---|\n");
    for degree in AVAILABLE_DEGREES {
        let probe = Setup {
            ext_degree: degree,
            ..*setup
        };
        let q = minimal_queries(setup, degree, TARGET_BITS)
            .map_or_else(|| "not reachable".to_string(), |q| q.to_string());
        let _ = writeln!(s, "| {degree} | {:.0} | {q} |", field_bits(&probe));
    }
    s.push_str("\n### Bounds that are stated, not derived\n\n");
    let _ = writeln!(
        s,
        "AIR constraints at most {AIR_CONSTRAINTS_BOUND}, constraint degree at most {AIR_DEGREE_BOUND}, \
{AIR_COMBO} opening points per column, `LogUp` interactions per row at most {LOGUP_INTERACTIONS_BOUND} with messages at most \
{LOGUP_WIDTH_BOUND} wide. They come from reading `plonky3_air.rs` by hand and are set above the observed values; a higher bound can \
only lower the reported bits.\n"
    );
    s.push_str(
        "The quantum reading halves every search-type term (Fiat-Shamir challenges, grinding included) and \
takes the Merkle collision term as `256 / 3` bits (Brassard-Hoyer-Tapp). It follows the quadratic loss of \
Fiat-Shamir in the quantum random oracle model (Chiesa, Manohar, Spooner, eprint 2019/834) and is a reading \
of that bound, not a separate proof.\n",
    );
    s
}

fn wrap(section: &str) -> String {
    format!("{BEGIN}\n{section}{END}\n")
}

/// Insert or replace the generated block in `existing`.
#[must_use]
pub fn splice(existing: &str, section: &str) -> String {
    let block = wrap(section);
    if let (Some(b), Some(e)) = (existing.find(BEGIN), existing.find(END)) {
        if b < e {
            let after = e + END.len();
            let after = if existing[after..].starts_with('\n') {
                after + 1
            } else {
                after
            };
            return format!("{}{}{}", &existing[..b], block, &existing[after..]);
        }
    }
    if existing.trim().is_empty() {
        return format!(
            "# Post-quantum measurements\n\nThe tables below are produced by repository tools and are regenerated, not edited by hand.\n\n{block}"
        );
    }
    let mut out = existing.to_string();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push('\n');
    out.push_str(&block);
    out
}

/// The generated block of `doc`, markers included, if present.
fn current_block(doc: &str) -> Option<&str> {
    let b = doc.find(BEGIN)?;
    let e = doc.find(END)? + END.len();
    (b < e).then(|| &doc[b..e])
}

fn usage() -> Report {
    Report::fail_with(
        "usage: stark-soundness [--write | --check | --search | --self-test]\n".to_string(),
        2,
    )
}

/// The canary: a known configuration must give a known verdict.
///
/// # Errors
///
/// When the model disagrees with a value that can be checked by hand.
pub fn self_test() -> Result<String, String> {
    let weak = Setup {
        fri: Fri {
            log_blowup: 1,
            max_log_arity: 1,
            log_final_poly_len: 0,
            num_queries: 1,
            commit_pow_bits: 0,
            query_pow_bits: 0,
        },
        ext_degree: 2,
        log_trace: 10,
        batched_columns: 10,
    };
    let weak_bits = provable(&weak).bits();
    if weak_bits > 5.0 {
        return Err(format!(
            "one query at rate 1/2 must be weak, got {weak_bits:.1} bits"
        ));
    }
    let strong = Setup {
        fri: Fri {
            log_blowup: 3,
            max_log_arity: 2,
            log_final_poly_len: 0,
            num_queries: 100,
            commit_pow_bits: 16,
            query_pow_bits: 16,
        },
        ext_degree: 5,
        log_trace: 20,
        batched_columns: 900,
    };
    let strong_bits = provable(&strong).bits();
    if strong_bits < TARGET_BITS {
        return Err(format!(
            "100 queries over a degree 5 extension must reach the target, got {strong_bits:.1} bits"
        ));
    }
    let hand = legacy_ethstark_query_bits(&strong.fri);
    if (hand - 316.0).abs() > 1e-9 {
        return Err(format!("the legacy formula gave {hand}, expected 316"));
    }
    let q = quantum(&provable(&strong), "q");
    if q.bits() >= provable(&strong).bits() {
        return Err("the quantum reading must be lower than the classical one".to_string());
    }
    Ok(format!(
        "stark-soundness self-test ok: weak {weak_bits:.1} bits, strong {strong_bits:.1} bits"
    ))
}

/// Run the tool with its command line arguments.
#[must_use]
pub fn cli(args: &[&str], root: &Path) -> Report {
    let mode = match args {
        [] => "print",
        ["--write"] => "write",
        ["--check"] => "check",
        ["--search"] => "search",
        ["--self-test"] => "self-test",
        _ => return usage(),
    };
    if mode == "self-test" {
        return match self_test() {
            Ok(msg) => Report::ok(format!("{msg}\n")),
            Err(e) => Report::fail_with(format!("{e}\n"), 1),
        };
    }
    let setup = match read_setup(root) {
        Ok(s) => s,
        Err(e) => return Report::fail_with(format!("{e}\n"), 1),
    };
    let section = render_section(&setup);
    let doc_path = root.join(DOC_REL);
    match mode {
        "write" => {
            let existing = std::fs::read_to_string(&doc_path).unwrap_or_default();
            if let Some(dir) = doc_path.parent() {
                if let Err(e) = std::fs::create_dir_all(dir) {
                    return Report::fail_with(
                        format!("{} could not be created: {e}\n", dir.display()),
                        1,
                    );
                }
            }
            match std::fs::write(&doc_path, splice(&existing, &section)) {
                Ok(()) => Report::ok(format!("wrote the stark-soundness section of {DOC_REL}\n")),
                Err(e) => Report::fail_with(format!("{DOC_REL} could not be written: {e}\n"), 1),
            }
        }
        "check" => {
            let Ok(doc) = std::fs::read_to_string(&doc_path) else {
                return Report::fail_with(format!("missing {DOC_REL}\n"), 1);
            };
            let bits = provable(&setup).bits();
            if bits < TARGET_BITS {
                return Report::fail_with(
                    format!(
                        "the provable reading is {bits:.1} bits, below thetarget of {TARGET_BITS:.0}\n"
                    ),
                    1,
                );
            }
            if current_block(&doc) == Some(wrap(&section).trim_end_matches('\n')) {
                Report::ok(format!(
                    "stark-soundness section is current, provable reading {bits:.1} bits\n"
                ))
            } else {
                Report::fail_with(
                    format!(
                        "the stark-soundness section of {DOC_REL} does not match {PROVER_REL}; \
run `cargo run --manifest-path xtask/tools/Cargo.toml -- stark-soundness --write`\n"
                    ),
                    1,
                )
            }
        }
        "search" => {
            let mut out = String::new();
            for degree in AVAILABLE_DEGREES {
                let q = minimal_queries(&setup, degree, TARGET_BITS);
                let _ = writeln!(
                    out,
                    "degree {degree}: minimal queries for {TARGET_BITS:.0} bit provable = {q:?}"
                );
            }
            Report::ok(out)
        }
        _ => Report::ok(section),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = "type MyExtensionField = BinomialExtensionField<Goldilocks, 2>;\n\
fn build_config() {\n\
    let fri_params = p3_fri::FriParameters {\n\
        log_blowup: 3,\n\
        max_log_arity: 2,\n\
        log_final_poly_len: 0,\n\
        num_queries: 100,\n\
        commit_proof_of_work_bits: 16, // grind\n\
        query_proof_of_work_bits: 16,\n\
        mmcs: challenge_mmcs,\n\
    };\n\
}\n";

    #[test]
    fn the_canary_passes() {
        assert!(self_test().is_ok());
    }

    #[test]
    fn parameters_are_read_out_of_the_literal() {
        let fri = parse_fri(SRC).expect("fri");
        assert_eq!(fri.log_blowup, 3);
        assert_eq!(fri.num_queries, 100);
        assert_eq!(fri.commit_pow_bits, 16);
        assert_eq!(parse_ext_degree(SRC).expect("degree"), 2);
    }

    #[test]
    fn a_cubic_alias_is_degree_three() {
        let src = "type MyExtensionField = CubicTrinomialExtensionField<Goldilocks>;\n";
        assert_eq!(parse_ext_degree(src).expect("degree"), 3);
    }

    #[test]
    fn a_missing_field_is_an_error_not_a_default() {
        assert!(parse_fri("let fri_params = p3_fri::FriParameters { log_blowup: 3, };").is_err());
    }

    #[test]
    fn the_legacy_formula_is_the_quoted_316() {
        let fri = parse_fri(SRC).expect("fri");
        assert!((legacy_ethstark_query_bits(&fri) - 316.0).abs() < 1e-9);
    }

    #[test]
    fn more_queries_never_lower_the_provable_reading() {
        let mut setup = Setup {
            fri: parse_fri(SRC).expect("fri"),
            ext_degree: 5,
            log_trace: 20,
            batched_columns: 900,
        };
        let mut last = 0.0;
        for q in [10, 20, 40, 80] {
            setup.fri.num_queries = q;
            let bits = provable(&setup).bits();
            assert!(bits >= last, "{q} queries gave {bits}, below {last}");
            last = bits;
        }
    }

    #[test]
    fn the_quantum_reading_is_below_the_classical_one() {
        let setup = Setup {
            fri: parse_fri(SRC).expect("fri"),
            ext_degree: 5,
            log_trace: 20,
            batched_columns: 900,
        };
        let v = verdict(&setup);
        assert!(v.quantum.bits() < v.provable.bits());
        assert!(v.quantum_assumed.bits() < v.assumed.bits());
    }

    #[test]
    fn a_larger_field_never_lowers_the_provable_reading() {
        let fri = parse_fri(SRC).expect("fri");
        let at = |degree| {
            provable(&Setup {
                fri,
                ext_degree: degree,
                log_trace: 20,
                batched_columns: 900,
            })
            .bits()
        };
        assert!(at(3) >= at(2));
        assert!(at(5) >= at(3));
    }

    #[test]
    fn splice_replaces_only_the_generated_block() {
        let first = splice("# Doc\n\nhand written\n", "one\n");
        assert!(first.contains("hand written"));
        let second = splice(&first, "two\n");
        assert!(second.contains("two") && !second.contains("one\n"));
        assert!(second.contains("hand written"));
        assert_eq!(second.matches(BEGIN).count(), 1);
    }
}
