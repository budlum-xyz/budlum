//! A storage decision compares two rates. Only their ratio matters, so any
//! common scale cancels, and that is exactly what makes the scale dangerous:
//! applying it to one rate and not the other changes every threshold by the
//! scale factor and changes nothing that looks wrong.
//!
//! Ported from `scripts/check-threshold-rates-share-one-scale.sh`.
//!
//! # The failure this closes
//!
//! `living_threshold.rs` carries a disk rate and a processor rate, both below
//! one picodollar, both therefore multiplied by 1e6 to survive integer
//! arithmetic. The first version multiplied the processor rate by 1e9 instead,
//! and the described-content threshold read 0.4 reads per half-life where the
//! measurement says 418. Every test still passed, because the tests compared
//! thresholds against each other and both sides moved together. It was caught
//! by recomputing the same arithmetic outside Rust, not by the suite.
//!
//! # What is checked
//!
//! * The module states, in its own comment, what each rate means in physical
//!   units.
//! * The rates are pinned to the measured values (0.29 $/TB/month and
//!   0.0025 $/hour, both at the same 1e6 scale: 403 and 694).
//! * A test asserts the ordering of two thresholds that differ by a known
//!   factor.
//! * No floating point anywhere in the module.
//! * The arithmetic widens to u128 before multiplying, and the widened
//!   products are checked.
//! * Every rate pair in the module sits on one scale, not just the pinned
//!   one: a pair whose sides are more than a hundredfold apart is a scale
//!   error.
//! * The hysteresis band's documentation matches what the band does, and a
//!   test pins the band width and the decay.

use std::path::Path;

/// Python `\s`.
fn skip_py_ws(s: &str) -> &str {
    let mut idx = 0usize;
    for (i, c) in s.char_indices() {
        if matches!(c, ' ' | '\t' | '\n' | '\r' | '\u{000c}' | '\u{000b}') {
            idx = i + c.len_utf8();
        } else {
            break;
        }
    }
    &s[idx..]
}

/// Does the character before `idx` exist and is it a word character?
fn word_before(s: &str, idx: usize) -> bool {
    s[..idx]
        .chars()
        .next_back()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Does the character at `idx` exist and is it a word character?
fn word_at(s: &str, idx: usize) -> bool {
    s[idx..]
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// `\b(f32|f64)\b` on one line.
fn has_float_type(line: &str) -> bool {
    for needle in ["f32", "f64"] {
        let mut from = 0usize;
        while let Some(pos) = line[from..].find(needle) {
            let abs = from + pos;
            if !word_before(line, abs) && !word_at(line, abs + needle.len()) {
                return true;
            }
            from = abs + 1;
        }
    }
    false
}

/// Does the text hold `key<digit>` where the character after the digit is not
/// a digit or underscore? Mirrors `grep -qE 'key<digit>[^0-9_]'`.
fn has_pinned_literal(text: &str, key: &str) -> bool {
    text.lines().any(|line| {
        if let Some(pos) = line.find(key) {
            let rest = &line[pos + key.len()..];
            !rest.is_empty()
                && !rest
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_digit() || c == '_')
        } else {
            false
        }
    })
}

/// The value after `key` on a line: digits and underscores until the first
/// other character, underscores removed. Mirrors the awk extraction.
fn extract_rate(line: &str, key: &str) -> Option<u64> {
    let after = line.rsplit_once(key)?.1;
    let after = skip_py_ws(after);
    let digits: String = after
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '_')
        .collect();
    if digits.is_empty() {
        return None;
    }
    digits.replace('_', "").parse().ok()
}

/// The lines from the first line containing `start` through the line equal to
/// `end` (or the end of the text), mirroring `sed -n '/start/,/^end$/p'`.
fn sed_range(src: &str, start: &str, end: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let mut s = None;
    let mut e = None;
    for (i, line) in lines.iter().enumerate() {
        if s.is_none() && line.contains(start) {
            s = Some(i);
        }
        if s.is_some() && *line == end {
            e = Some(i);
            break;
        }
    }
    let Some(s) = s else {
        return String::new();
    };
    let e = e.unwrap_or(lines.len().saturating_sub(1));
    lines[s..=e].join("\n")
}

/// Rate pairs whose sides are more than a hundredfold apart.
fn off_scale_pairs(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut disk_line: Option<usize> = None;
    let mut disk_val = 0u64;
    for (i, line) in src.lines().enumerate() {
        if let Some(val) = extract_rate(line, "disk_picodollars_per_byte_epoch:") {
            disk_line = Some(i);
            disk_val = val;
            continue;
        }
        if let Some(val) = extract_rate(line, "cpu_picodollars_per_nano:") {
            if disk_line == Some(i - 1) && disk_val > 0 && val > 0 {
                let (hi, lo) = if disk_val > val {
                    (disk_val, val)
                } else {
                    (val, disk_val)
                };
                if hi > lo.saturating_mul(100) {
                    out.push(format!(
                        "line {}: disk {} against processor {}",
                        i + 1,
                        disk_val,
                        val
                    ));
                }
            }
            disk_line = None;
        }
    }
    out
}

/// # Errors
///
fn check_units(src: &str) -> Result<(), String> {
    // Both rates must be named with a physical unit in a comment.
    if !src.contains("TB/month") {
        return Err(String::from(
            "FAIL: the disk rate is not stated in physical units; an integer \
             whose unit is implicit cannot be rechecked",
        ));
    }
    if !src.contains("$/hour") {
        return Err(String::from(
            "FAIL: the processor rate is not stated in physical units",
        ));
    }
    Ok(())
}

fn check_pins(src: &str) -> Result<(), String> {
    // The pinned integers, both at the same 1e6 scale.
    if !has_pinned_literal(src, "disk_picodollars_per_byte_epoch: 403") {
        return Err(String::from(
            "FAIL: the disk rate is not the measured 403 (0.29 $/TB/month at 1e6 scale)",
        ));
    }
    if !has_pinned_literal(src, "cpu_picodollars_per_nano: 694") {
        return Err(String::from(
            "FAIL: the processor rate is not the measured 694 (0.0025 $/hour at 1e6 scale). \
             A rate at a different scale from the disk rate moves every threshold by that \
             factor and breaks no test, because the tests compare thresholds against each \
             other",
        ));
    }
    Ok(())
}

fn check_ordering(src: &str) -> Result<(), String> {
    // A test must order two thresholds that are known to differ.
    if !src.contains("fn each_lever_has_its_own_crossing_point") {
        return Err(String::from(
            "FAIL: no test orders two levers' thresholds against each other",
        ));
    }
    let body = sed_range(src, "fn each_lever_has_its_own_crossing_point", "    }");
    if !body.contains("assert!") {
        return Err(String::from(
            "FAIL: the crossing-point test asserts nothing",
        ));
    }
    Ok(())
}

fn check_floats(src: &str) -> Result<(), String> {
    use std::fmt::Write as _;
    // Floating point is a fork waiting to happen.
    let floats: Vec<String> = src
        .lines()
        .enumerate()
        .filter(|(_, line)| has_float_type(line) && !line.trim_start().starts_with("//"))
        .map(|(i, line)| format!("{}:{line}", i + 1))
        .collect();
    if !floats.is_empty() {
        let mut msg = String::from(
            "FAIL: floating point in a module that decides whether bytes are written:\n",
        );
        for f in &floats {
            let _ = writeln!(msg, "  {f}");
        }
        return Err(msg);
    }
    Ok(())
}

fn check_arithmetic(src: &str) -> Result<(), String> {
    // The products must widen before multiplying, and the widened products
    // must still be checked.
    if !src.contains("u128::from") {
        return Err(String::from(
            "FAIL: the arithmetic does not widen to u128; bytes times a rate times an \
             epoch count overflows u64 for objects a network would actually hold",
        ));
    }
    if !src.contains("checked_mul") {
        return Err(String::from(
            "FAIL: the u128 products are unchecked. Four u64 factors leave u128, and \
             this crate aborts on overflow in release rather than wrapping, so an object \
             size from a manifest can end the process. Refuse the product instead",
        ));
    }
    if !src.contains("fn a_product_that_leaves_u128_is_refused_rather_than_aborting") {
        return Err(String::from(
            "FAIL: no test shows a product past u128 returning an error rather than \
             aborting",
        ));
    }
    Ok(())
}

fn check_rate_pairs(src: &str) -> Result<(), String> {
    use std::fmt::Write as _;
    // Every rate pair, not only the pinned one, must share a scale.
    let pairs = off_scale_pairs(src);
    if !pairs.is_empty() {
        let mut msg = String::from(
            "FAIL: a rate pair spans more than a hundredfold, which is a scale error \
             rather than a hardware difference; rented disk is about ten times owned \
             disk:\n",
        );
        for p in &pairs {
            let _ = writeln!(msg, "  {p}");
        }
        return Err(msg);
    }
    Ok(())
}

fn check_hysteresis(src: &str) -> Result<(), String> {
    // The hysteresis band's documentation must match what the band does.
    let hyst_doc = sed_range(
        src,
        "How far past a threshold a rate must sit",
        "HYSTERESIS_SIXTEENTHS: u64",
    );
    if hyst_doc.is_empty() {
        return Err(String::from(
            "FAIL: the hysteresis constant has no documentation",
        ));
    }
    let hyst_lower = hyst_doc.to_lowercase();
    if hyst_lower.contains("band is asymmetric") && !hyst_lower.contains("same width") {
        return Err(String::from(
            "FAIL: the hysteresis constant calls its band asymmetric. `decide` \
             computes one width and applies it in both directions, so a reader sizing \
             an object against that sentence is wrong on one side. The asymmetry \
             belongs to the transition cost",
        ));
    }
    if !src.contains("fn the_dead_band_is_the_same_width_on_both_sides") {
        return Err(String::from(
            "FAIL: no test pins the width of the dead band on each side of the \
             crossing point, so the constant's documentation and the code can drift \
             apart again",
        ));
    }
    Ok(())
}

/// # Errors
///
/// A rate without a physical unit, a wrongly scaled rate, a missing or empty
/// ordering test, floating point, narrow or unchecked arithmetic, an
/// off-scale rate pair, a misdocumented band, or a missing test.
pub fn run(root: &Path) -> Result<String, String> {
    let target = root.join("src/storage/living_threshold.rs");
    let src = std::fs::read_to_string(&target).map_err(|_| {
        "FAIL: living-threshold module missing at src/storage/living_threshold.rs".to_string()
    })?;

    check_units(&src)?;
    check_pins(&src)?;
    check_ordering(&src)?;
    check_floats(&src)?;
    check_arithmetic(&src)?;
    check_rate_pairs(&src)?;
    check_hysteresis(&src)?;

    // A decaying estimate that cannot decay is a counter with extra steps.
    if !src.contains("fn an_access_estimate_halves_every_half_life") {
        return Err(String::from(
            "FAIL: no test shows the access estimate actually decaying",
        ));
    }

    // The disagreement test must name the two answers it expects.
    if !src.contains("fn operators_with_different_hardware_may_disagree") {
        return Err(String::from(
            "FAIL: no test shows two operators reaching different answers for one \
             object",
        ));
    }
    let disagree = sed_range(
        &src,
        "fn operators_with_different_hardware_may_disagree",
        "    }",
    );
    if !disagree.contains("Decision::Hold") {
        return Err(String::from(
            "FAIL: the disagreement test does not name Hold as one of the two answers; \
             asserting only that the answers differ passes for the pair the other way \
             round, which is what a sign error produces",
        ));
    }
    if !disagree.contains("Decision::Apply") {
        return Err(String::from(
            "FAIL: the disagreement test does not name Apply as one of the two answers",
        ));
    }

    Ok(String::from(
        "Threshold rates OK: both rates carry a physical unit and one shared scale, \
         their thresholds are ordered by a test, the estimate is shown to decay, the \
         arithmetic widens, and there is no floating point.",
    ))
}

// ---------------------------------------------------------------------------
// Self-test: the fifteen canaries of the shell version.
// ---------------------------------------------------------------------------

const GOOD: &str = r"fn rates() -> OperatorRates {
    OperatorRates {
        // 0.29 $/TB/month at 1e6 scale.
        disk_picodollars_per_byte_epoch: 403,
        // 0.0025 $/hour at 1e6 scale.
        cpu_picodollars_per_nano: 694,
    }
}

fn widen() -> u128 {
    u128::from(1u64)
}

fn checked_product(factors: &[u128]) -> Result<u128, ThresholdError> {
    acc.checked_mul(*f).ok_or(ThresholdError::ProductLeavesU128)
}

#[test]
fn a_product_that_leaves_u128_is_refused_rather_than_aborting() {
    assert_eq!(r, Err(ThresholdError::ProductLeavesU128));
}

#[test]
fn each_lever_has_its_own_crossing_point() {
    assert!(described_at > recompressed_at * 4);
}

#[test]
fn an_access_estimate_halves_every_half_life() {
    assert_eq!(a.rate_scaled(HL), start / 2);
}

/// How far past a threshold a rate must sit before the strategy changes.
///
/// Expressed in sixteenths, and the same width in both directions.
pub const HYSTERESIS_SIXTEENTHS: u64 = 4;

#[test]
fn the_dead_band_is_the_same_width_on_both_sides() {
    assert_eq!(threshold - (threshold - band), (threshold + band) - threshold);
}

#[test]
fn operators_with_different_hardware_may_disagree() {
    let cheap_disk = OperatorRates {
        disk_picodollars_per_byte_epoch: 40,
        cpu_picodollars_per_nano: 694,
    };
    let dear_disk = OperatorRates {
        disk_picodollars_per_byte_epoch: 4_030,
        cpu_picodollars_per_nano: 694,
    };
    assert_eq!(on_cheap, Decision::Hold);
    assert_eq!(on_dear, Decision::Apply);
}
";

fn expect_module(src: Option<&str>, label: &str, expect_ok: bool) -> Result<(), String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!(
        "budlum-gates-threshold-{}-{nanos}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(dir.join("src/storage"));
    if let Some(src) = src {
        std::fs::write(dir.join("src/storage/living_threshold.rs"), src)
            .map_err(|e| e.to_string())?;
    }

    let result = run(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    if expect_ok {
        result.map(|_| ()).map_err(|e| format!("{label}: {e}"))
    } else {
        match result {
            Err(_) => Ok(()),
            Ok(_) => Err(format!("{label}: gate passed when it must fail")),
        }
    }
}

/// # Errors
///
/// The canaries that did not behave.
pub fn self_test() -> Result<String, String> {
    // The correct module must pass, or every canary below proves nothing.
    expect_module(Some(GOOD), "a correct module was rejected", true)?;

    // The exact bug this gate exists for: one rate at a different scale.
    // `sed s///` rewrites the pattern on every line it occurs, so all three
    // `694,` literals move to 694_000, leaving the pinned form gone.
    let scale = GOOD.replace(
        "cpu_picodollars_per_nano: 694,",
        "cpu_picodollars_per_nano: 694_000,",
    );
    expect_module(Some(&scale), "a processor rate a thousand times off", false)?;

    // A rate with no unit stated.
    let nounit = GOOD.replace("// 0.29 $/TB/month at 1e6 scale.\n", "");
    expect_module(Some(&nounit), "a disk rate with no physical unit", false)?;

    // No test ordering two thresholds.
    let noorder = GOOD.replacen(
        "fn each_lever_has_its_own_crossing_point",
        "fn unrelated",
        1,
    );
    expect_module(Some(&noorder), "no threshold-ordering test", false)?;

    // An ordering test that asserts nothing.
    let noassert = GOOD.replace(
        "    assert!(described_at > recompressed_at * 4);",
        "    let _ = described_at;",
    );
    expect_module(Some(&noassert), "an ordering test asserting nothing", false)?;

    // Floating point.
    let floaty = format!("{GOOD}\nfn drift(x: f64) -> f64 {{ x * 0.5 }}\n");
    expect_module(Some(&floaty), "floating point", false)?;

    // No widening.
    let narrow = GOOD.replace("    u128::from(1u64)", "    1");
    expect_module(Some(&narrow), "arithmetic that never widens", false)?;

    // No decay test.
    let nodecay = GOOD.replacen(
        "fn an_access_estimate_halves_every_half_life",
        "fn something",
        1,
    );
    expect_module(Some(&nodecay), "a module with no decay test", false)?;

    // The bug the pinned check missed: a second rate pair off by a thousand.
    let secondscale = second_rate_pair_off(GOOD);
    expect_module(
        Some(&secondscale),
        "an unpinned rate pair a thousand times off",
        false,
    )?;

    // A disagreement test that only asserts the answers differ.
    let nameless = GOOD
        .replace(
            "    assert_eq!(on_cheap, Decision::Hold);",
            "    assert_ne!(on_cheap, on_dear);",
        )
        .replace("    assert_eq!(on_dear, Decision::Apply);\n", "");
    expect_module(
        Some(&nameless),
        "a disagreement test naming neither answer",
        false,
    )?;

    // No disagreement test at all.
    let noagree = GOOD.replacen(
        "fn operators_with_different_hardware_may_disagree",
        "fn elsewhere",
        1,
    );
    expect_module(Some(&noagree), "a module with no disagreement test", false)?;

    // The band called asymmetric while the code applies one width both ways.
    let asym = GOOD.replace(
        "Expressed in sixteenths, and the same width in both directions.",
        "Expressed in sixteenths. Leaving costs more, so the band is asymmetric.",
    );
    expect_module(
        Some(&asym),
        "a band documented as asymmetric that is not",
        false,
    )?;

    // No test pinning the band width.
    let noband = GOOD.replacen(
        "fn the_dead_band_is_the_same_width_on_both_sides",
        "fn unpinned",
        1,
    );
    expect_module(Some(&noband), "a module with no dead-band test", false)?;

    // Widened but unchecked products.
    let unchecked = GOOD.replace(
        "    acc.checked_mul(*f).ok_or(ThresholdError::ProductLeavesU128)",
        "    acc * f",
    );
    expect_module(Some(&unchecked), "unchecked u128 products", false)?;

    // No test for the refusal.
    let noovf = GOOD.replacen(
        "fn a_product_that_leaves_u128_is_refused_rather_than_aborting",
        "fn other",
        1,
    );
    expect_module(
        Some(&noovf),
        "a module with no overflow-refusal test",
        false,
    )?;

    // Missing module.
    expect_module(None, "a missing module", false)?;

    Ok(String::from(
        "threshold-rate gate self-test OK: a wrongly scaled pinned rate, a wrongly \
         scaled unpinned rate, a rate with no unit, a missing or empty ordering test, \
         a disagreement test that names neither answer, a missing disagreement test, \
         a band documented as asymmetric that is not, a missing dead-band test, \
         floating point, narrow arithmetic, unchecked u128 products, a missing \
         overflow-refusal test, a missing decay test and an absent module are all \
         rejected; a correct module passes.",
    ))
}

/// The line after `disk_picodollars_per_byte_epoch: 40,` gets its processor
/// rate multiplied by a thousand, mirroring the shell canary's
/// `/disk...: 40,/{n;s/cpu...: 694,/cpu...: 694_000,/;}`.
fn second_rate_pair_off(good: &str) -> String {
    let mut out = String::new();
    let mut pending_disk_40 = false;
    for line in good.lines() {
        if pending_disk_40 && line.contains("cpu_picodollars_per_nano: 694,") {
            out.push_str(&line.replace(
                "cpu_picodollars_per_nano: 694,",
                "cpu_picodollars_per_nano: 694_000,",
            ));
            pending_disk_40 = false;
            out.push('\n');
            continue;
        }
        pending_disk_40 = line.contains("disk_picodollars_per_byte_epoch: 40,");
        out.push_str(line);
        out.push('\n');
    }
    out
}
