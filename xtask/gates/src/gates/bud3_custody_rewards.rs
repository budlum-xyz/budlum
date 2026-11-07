//! Custody rewards follow symbol bytes, presence and the audit result.
//!
//! Section 11.4 item 5 and Section 11.5 items 4 and 5 pay the holders of an
//! object's symbols out of the storage endowment. Three rules decide who is
//! paid and how much, and each of them is a line of code somebody can delete
//! without a test failing on the deletion itself:
//!
//! 1. The weight is `symbol_bytes x presence_multiplier`. A validator that was
//!    seen in half the epoch's presence windows earns half as much per byte.
//! 2. A share that missed an audit is paid nothing for that window. Section
//!    11.7 is explicit that the answer to a missed audit is no reward and no
//!    slash, so the money cannot simply move to a neighbour either.
//! 3. What the endowment could not pay - a missed audit's part and the
//!    rounding dust - goes to the network security pool. It is not burned and
//!    not left in the ledger.
//!
//! The gate checks the shape of all three in `src/storage/bud3/fees.rs`, that
//! the epoch slice floors rather than rounds up, that the Mobile floor's extra
//! bytes are priced by a constant that exists, and that the four tests the
//! package card names are live.
//!
//! # What it cannot see
//!
//! A gate on text cannot prove the arithmetic. What it can do is refuse the
//! edit that makes the arithmetic meaningless: paying a share whose
//! `passed_audit` is false, or dropping `presence_ppm` from the weight, or
//! leaving the undistributed part unnamed so that a later reader has to guess
//! where it went. The tests beside the module hold the numbers.

use std::fmt::Write as _;
use std::path::Path;

/// The module under test.
const FEES: &str = "src/storage/bud3/fees.rs";

/// The tests the WP-25 card names for custody rewards.
const REQUIRED_TESTS: &[&str] = &[
    "endowment_pays_only_passed_audits",
    "missed_audit_share_returns_to_pool",
    "storage_rewards_conserve_supply",
    "decentralization_bytes_paid_by_pool",
];

/// The text from `fn name(` to the closing brace at or above its indent.
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

/// Check the custody reward rules.
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
    if !code.contains("pub passed_audit: bool") {
        problems.push(
            "`CustodyShare` has no `passed_audit` field. Without it there is nothing \
             to decide a missed audit by, and Section 11.7's no-reward rule has no \
             input."
                .to_string(),
        );
    }

    checked += 1;
    match region(&code, "custody_payout").as_deref() {
        None => problems.push(
            "`custody_payout` is missing; the endowment has no way to pay a share.".to_string(),
        ),
        Some(payout) => {
            for token in ["passed_audit", "presence_ppm", "symbol_bytes"] {
                if !payout.contains(token) {
                    problems.push(format!(
                        "`custody_payout` does not read `{token}`. A payout that skips it \
                         pays a share it could not check, an absent validator as much as \
                         a present one, or a one-byte share as much as a whole segment."
                    ));
                }
            }
            if !payout.contains("to_pool") {
                problems.push(
                    "`custody_payout` does not name the undistributed part. Section 11.5 \
                     item 5 sends what the endowment could not pay to the network \
                     security pool; a payout with no remainder field loses it."
                        .to_string(),
                );
            }
        }
    }

    checked += 1;
    match region(&code, "endowment_epoch_slice").as_deref() {
        None => problems.push(
            "`endowment_epoch_slice` is missing; the endowment releases nothing.".to_string(),
        ),
        Some(slice) => {
            if !slice.contains("SECONDS_PER_DAY") {
                problems.push(
                    "`endowment_epoch_slice` does not convert the lifetime to seconds. \
                     Section 11.5 releases `share x epoch / lifetime`, and a lifetime in \
                     days against an epoch in seconds is off by 86 400."
                        .to_string(),
                );
            }
            if slice.contains("div_ceil") {
                problems.push(
                    "`endowment_epoch_slice` rounds up. The releases would exceed the \
                     share the object paid for, and the last epoch would pay money the \
                     endowment never received."
                        .to_string(),
                );
            }
        }
    }

    checked += 1;
    match region(&code, "settle_epoch").as_deref() {
        None => problems
            .push("`settle_epoch` is missing; the ledger never pays anybody.".to_string()),
        Some(settle) => {
            if !settle.contains("to_pool") {
                problems.push(
                    "`StorageLedger::settle_epoch` does not move the undistributed part \
                     into the pool, so the ledger's balances stop adding up to what it \
                     charged."
                        .to_string(),
                );
            }
        }
    }

    checked += 1;
    match region(&code, "decentralization_extra_bytes").as_deref() {
        None => problems.push(
            "`decentralization_extra_bytes` is missing; the Mobile floor has no price."
                .to_string(),
        ),
        Some(extra) => {
            if !extra.contains("MOBILE_SHARE_FLOOR_PPM") {
                problems.push(
                    "`decentralization_extra_bytes` does not use `MOBILE_SHARE_FLOOR_PPM`. \
                     The floor is Section 6.9's 30 percent of the symbols; a literal \
                     hidden in the body cannot be reviewed against it."
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
    Ok(format!(
        "bud3 custody rewards gate OK: {checked} checks, audits and presence decide the payout"
    ))
}

/// The fixture the canaries are run against.
fn fixture(weight: &str, remainder: &str, slice_rounding: &str) -> String {
    let mut text = String::from(
        "pub const SECONDS_PER_DAY: u64 = 24 * 60 * 60;\n\
         pub const MOBILE_SHARE_FLOOR_PPM: u64 = 300_000;\n\
         pub struct CustodyShare {\n    pub symbol_bytes: u64,\n    \
         pub presence_ppm: u32,\n    pub passed_audit: bool,\n}\n\
         pub struct CustodyPayout {\n    pub paid: Vec<u64>,\n    pub to_pool: u64,\n}\n",
    );
    writeln!(
        text,
        "pub fn custody_payout(payout: u64, shares: &[CustodyShare]) -> CustodyPayout {{\n    \
         let _ = shares.iter().filter(|s| s.{weight});\n    \
         CustodyPayout {{ paid: Vec::new(), {remainder} }}\n}}"
    )
    .expect("writing to a String cannot fail");
    writeln!(
        text,
        "pub fn endowment_epoch_slice(share: u64, epoch_secs: u64, days: u64) -> u64 {{\n    \
         let life = days.saturating_mul(SECONDS_PER_DAY);\n    \
         share.saturating_mul(epoch_secs).{slice_rounding}(life)\n}}"
    )
    .expect("writing to a String cannot fail");
    writeln!(
        text,
        "pub fn settlement(ledger: &mut u64, to_pool: u64) {{\n    \
         *ledger = ledger.saturating_add(to_pool);\n}}"
    )
    .expect("writing to a String cannot fail");
    writeln!(
        text,
        "pub fn decentralization_extra_bytes(total: u64) -> u64 {{\n    \
         total.saturating_mul(MOBILE_SHARE_FLOOR_PPM)\n}}"
    )
    .expect("writing to a String cannot fail");
    for &name in REQUIRED_TESTS {
        writeln!(text, "#[test]\nfn {name}() {{}}").expect("writing to a String cannot fail");
    }
    text
}

/// The fixture plus the `settle_epoch` shape the gate looks for.
fn with_settle_epoch(mut text: String, moves_to_pool: bool) -> String {
    let body = if moves_to_pool {
        "fn settle_epoch(&mut self, payout: CustodyPayout) {\n    \
         let to_pool = payout.to_pool;\n    self.pool = self.pool.saturating_add(to_pool);\n}"
    } else {
        "fn settle_epoch(&mut self, payout: CustodyPayout) {\n    let _ = payout;\n}"
    };
    text.push_str(body);
    text.push('\n');
    text
}

/// # Errors
///
/// Returns a finding when a defect fixture passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-custody")?;
    let _ = std::fs::create_dir_all(dir.join("src/storage/bud3"));
    let target = dir.join(FEES);

    let good = with_settle_epoch(
        fixture(
            "passed_audit && s.presence_ppm > 0 && s.symbol_bytes > 0",
            "to_pool: 0",
            "saturating_div",
        ),
        true,
    );
    std::fs::write(&target, &good).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a payout that follows audits and presence was refused",
        ));
    }

    // The audit result is ignored: every share is paid for that window.
    let ignores_audit = with_settle_epoch(
        fixture("presence_ppm > 0 && s.symbol_bytes > 0", "to_pool: 0", "saturating_div"),
        true,
    );
    std::fs::write(&target, &ignores_audit).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a payout that ignored the audit result passed the gate",
        ));
    }

    // The undistributed part has no name and goes nowhere.
    let loses_remainder = with_settle_epoch(
        fixture(
            "passed_audit && s.presence_ppm > 0 && s.symbol_bytes > 0",
            "left_over: 0",
            "saturating_div",
        ),
        false,
    );
    std::fs::write(&target, &loses_remainder).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a payout with no remainder and no pool move passed the gate",
        ));
    }

    // The epoch slice rounds up and pays more than the object bought.
    let rounds_up = with_settle_epoch(
        fixture(
            "passed_audit && s.presence_ppm > 0 && s.symbol_bytes > 0",
            "to_pool: 0",
            "div_ceil",
        ),
        true,
    );
    std::fs::write(&target, &rounds_up).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: an endowment slice that rounds up passed the gate",
        ));
    }

    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "bud3 custody canary OK (audit and presence PASS; ignoring the audit, losing the \
         remainder and rounding the slice up FAIL).",
    ))
}
