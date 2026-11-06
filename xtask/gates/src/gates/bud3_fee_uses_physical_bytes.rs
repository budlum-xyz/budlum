//! The storage fee is priced in physical bytes.
//!
//! Section 11.5 of the directive prices storage as
//! `ceil(physical_bytes x lifetime_days x P_s / (2^30 x 365))`. The input is
//! the **physical** byte count of the stored object: not the content length the
//! uploader started from, and not the symbol count the fountain produced. The
//! distinction is the whole point of the rule. A codec that shrinks a 40 MiB
//! upload to a 4 MiB object changes what the network stores, and pricing the
//! upload would charge for bytes nobody holds; pricing the symbols would charge
//! the same object differently after every placement and repair.
//!
//! The gate holds four properties of `src/storage/bud3/fees.rs`:
//!
//! 1. `storage_fee` reads `physical_bytes` and nothing that stands in for it.
//! 2. The formula keeps the three constants Section 11.5 quotes it against
//!    (`P_s`, the GiB, the 365 days), so a re-derivation cannot quietly drop a
//!    denominator and turn a yearly price into a daily one.
//! 3. The fee rounds up and is floored at 0.001 BUD, and the gateway's fifth is
//!    taken by flooring *its* share rather than the endowment's.
//! 4. The six tests the package card names are live.
//!
//! # What it cannot see
//!
//! This is a shape check. A caller that passes `content.len()` into
//! `storage_fee` as `physical_bytes` compiles and passes here; what stops that
//! is the executor taking the byte count from the object it stored. Keeping the
//! two numbers different names, which this gate does, is what makes the mistake
//! visible at the call site.

use std::fmt::Write as _;
use std::path::Path;

/// The module under test.
const FEES: &str = "src/storage/bud3/fees.rs";

/// The tests the WP-25 card names for the fee and the split.
const REQUIRED_TESTS: &[&str] = &[
    "storage_fee_formula_matches_section_11_5",
    "gateway_share_is_five_percent",
    "endowment_pays_only_passed_audits",
    "missed_audit_share_returns_to_pool",
    "decentralization_bytes_paid_by_pool",
    "storage_rewards_conserve_supply",
];

/// The text from `fn name(` to the closing brace at or above its indent.
///
/// A line-based scan rather than a parser: the region is used to look for
/// tokens, and a nested block that closes one level deeper does not end it.
fn region(code: &str, name: &str) -> Option<String> {
    let needle = format!("fn {name}(");
    let lines: Vec<&str> = code.lines().collect();
    let start = lines.iter().position(|l| l.contains(&needle))?;
    let indent = lines[start].len() - lines[start].trim_start().len();
    let mut out = String::new();
    for line in &lines[start..] {
        out.push_str(line);
        out.push('\n');
        if line.trim() == "}" && line.len() - line.trim_start().len() <= indent {
            return Some(out);
        }
    }
    Some(out)
}

/// Check the fee module.
///
/// # Errors
///
/// Returns every violated property, one per line.
pub fn run(root: &Path) -> Result<String, String> {
    let path = root.join(FEES);
    let src = std::fs::read_to_string(&path).map_err(|e| {
        format!(
            "the storage fee module could not be read ({}): {e}",
            path.display()
        )
    })?;
    let code = crate::gates::rust_literals::scrub(&src);
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    checked += 1;
    let fee = region(&code, "storage_fee");
    if fee.is_none() {
        problems.push(format!(
            "`storage_fee` is missing from {FEES}; Section 11.5's formula has no home."
        ));
    }
    if let Some(fee) = fee.as_deref() {
        checked += 1;
        if !fee.contains("physical_bytes") {
            problems.push(
                "`storage_fee` does not read `physical_bytes`. The price is on the \
                 bytes the network stores, not on the upload it started from."
                    .to_string(),
            );
        }

        checked += 1;
        for stand_in in ["symbol_bytes", "content_len", "payload"] {
            if fee.contains(stand_in) {
                problems.push(format!(
                    "`storage_fee` reads `{stand_in}`. The fee is priced in physical \
                     bytes; a symbol count prices the same object differently after \
                     every repair, and a content length prices bytes nobody holds."
                ));
            }
        }

        checked += 1;
        if !fee.contains("div_ceil") {
            problems.push(
                "`storage_fee` does not round up. A fee that rounds down is storage \
                 the network stores for free, and a fraction of a base unit is still \
                 a charge."
                    .to_string(),
            );
        }

        checked += 1;
        for constant in ["PRICE_PER_GIB_YEAR", "GIB_BYTES", "BILLING_DAYS"] {
            if !fee.contains(constant) {
                problems.push(format!(
                    "`storage_fee` does not use `{constant}`. Section 11.5 quotes the \
                     price per GiB per year; a formula that drops one of the three \
                     denominators silently changes the unit."
                ));
            }
        }
    }

    checked += 1;
    if !code.contains("MIN_STORAGE_FEE: u64 = BUD / 1_000") {
        problems.push(
            "`MIN_STORAGE_FEE` is not derived from the base unit as 0.001 BUD. Written \
             as a loose literal it stops matching the unit the day the unit changes."
                .to_string(),
        );
    }

    checked += 1;
    if !code.contains("GATEWAY_SHARE_PPM: u64 = 50_000") {
        problems.push(
            "`GATEWAY_SHARE_PPM` is not 50 000 ppm (five percent, Section 11.5 item 6)."
                .to_string(),
        );
    }

    checked += 1;
    match region(&code, "split_fee").as_deref() {
        None => problems.push("`split_fee` is missing; the fee has no split.".to_string()),
        Some(split) => {
            if !split.contains("saturating_sub(gateway)") {
                problems.push(
                    "`split_fee` does not give the endowment the remainder \
                     (`fee - gateway`). Flooring the endowment hands the gateway a \
                     rounding bonus on every fee that does not divide."
                        .to_string(),
                );
            }
        }
    }

    checked += 1;
    for &name in REQUIRED_TESTS {
        if !crate::gates::rust_literals::has_live_test(&src, name) {
            problems.push(format!(
                "required test `{name}` is missing from {FEES} or is not a live `#[test]`."
            ));
        }
    }

    if !problems.is_empty() {
        let mut msg = String::new();
        for problem in problems {
            writeln!(msg, "FAIL: {problem}").expect("writing to a String cannot fail");
        }
        return Err(msg);
    }
    Ok(format!("bud3 fee gate OK: {checked} checks, storage is priced in physical bytes"))
}

/// The fixture the canaries are run against.
fn fixture(fee_input: &str, rounding: &str, split: &str) -> String {
    let mut text = String::from(
        "const BUD: u64 = crate::tokenomics::BUD_UNIT;\n\
         pub const MIN_STORAGE_FEE: u64 = BUD / 1_000;\n\
         pub const GATEWAY_SHARE_PPM: u64 = 50_000;\n\
         pub const PRICE_PER_GIB_YEAR: u64 = BUD;\n\
         pub const GIB_BYTES: u64 = 1 << 30;\n\
         pub const BILLING_DAYS: u64 = 365;\n",
    );
    writeln!(
        text,
        "pub fn storage_fee(physical_bytes: u64, lifetime_days: u64) -> u64 {{\n    \
         let numerator = {fee_input}.saturating_mul(lifetime_days);\n    \
         let denominator = GIB_BYTES.saturating_mul(BILLING_DAYS);\n    \
         numerator.{rounding}(denominator).saturating_mul(PRICE_PER_GIB_YEAR)\n}}"
    )
    .expect("writing to a String cannot fail");
    writeln!(
        text,
        "pub fn split_fee(fee: u64) -> u64 {{\n    let gateway = fee / 20;\n    {split}\n}}"
    )
    .expect("writing to a String cannot fail");
    for &name in REQUIRED_TESTS {
        writeln!(text, "#[test]\nfn {name}() {{}}").expect("writing to a String cannot fail");
    }
    text
}

/// # Errors
///
/// Returns a finding when a defect fixture passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-fee")?;
    let _ = std::fs::create_dir_all(dir.join("src/storage/bud3"));
    let target = dir.join(FEES);

    let good = fixture("physical_bytes", "div_ceil", "fee.saturating_sub(gateway)");
    std::fs::write(&target, &good).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a fee module that prices physical bytes was refused",
        ));
    }

    // The content length took the place of the physical bytes.
    let wrong_input = fixture("content_len", "div_ceil", "fee.saturating_sub(gateway)");
    std::fs::write(&target, &wrong_input).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: the fee was priced by content length and passed",
        ));
    }

    // The fee rounds down.
    let rounds_down = fixture("physical_bytes", "saturating_div", "fee.saturating_sub(gateway)");
    std::fs::write(&target, &rounds_down).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a fee that rounds down passed the gate",
        ));
    }

    // The gateway takes the rounding.
    let gateway_first = fixture("physical_bytes", "div_ceil", "gateway.saturating_sub(fee)");
    std::fs::write(&target, &gateway_first).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a split that floors the endowment passed the gate",
        ));
    }

    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "bud3 fee canary OK (physical bytes PASS, content length, rounding down and \
         gateway-first splits FAIL).",
    ))
}
