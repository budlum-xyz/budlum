//! A transfer fee that cannot see the amount is not a fee on the transfer.
//!
//! Ported from `scripts/check-value-transfers-are-priced-by-value.sh`.
//!
//! # The failure this closes
//!
//! `validate_transaction_with_context` required exactly one thing of a fee:
//! `if tx.fee < self.base_fee { reject }`. `tx.amount` appeared twice in that
//! function, in the overflow guard and in the balance check, and nowhere in
//! pricing. Someone moving one base unit and someone moving a quadrillion
//! paid the same.
//!
//! # What is checked
//!
//! 1. `RegistryParams` carries the three proportional rates as distinct
//!    fields; `bridge_fee_ppm` is not merged into `bridge_relayer_fee_ppm`.
//! 2. Every rate is validated below 100%.
//! 3. The fee actually consults the amount.
//! 4. The combination is the floor plus the cut (user decision 2026-09-01:
//!    base + rate; the rate is protocol revenue bound at the instruction),
//!    never `max`.
//! 5. Rounding is up (`div_ceil`), and the arithmetic widens to `u128`.
//! 6. The rates are governance-tunable in both places that decide it: the
//!    whitelist in governance.rs and the match in account.rs.
//! 7. The named regressions exist as real `#[test]` functions.

use std::fmt::Write as _;
use std::path::Path;

/// The three proportional rates.
const RATES: [&str; 3] = ["transfer_fee_ppm", "swap_fee_ppm", "bridge_fee_ppm"];

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

/// Blank line comments (`//` to end of line).
fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let Some(pos) = line.find("//") else {
            out.push_str(line);
            continue;
        };
        out.push_str(&line[..pos]);
        for c in line[pos..].chars() {
            out.push(if c == '\n' { '\n' } else { ' ' });
        }
    }
    out
}

/// Brace-matched body of the item whose header is `pub fn NAME\s*\(`.
fn body_of<'a>(src: &'a str, name: &str) -> Option<&'a str> {
    body_of_with_header(src, &format!("pub fn {name}"))
}

/// Brace-matched body of the item whose header is `fn NAME\s*\(` (no `pub`).
fn body_of_plain<'a>(src: &'a str, name: &str) -> Option<&'a str> {
    body_of_with_header(src, &format!("fn {name}"))
}

fn body_of_with_header<'a>(src: &'a str, header: &str) -> Option<&'a str> {
    let mut from = 0usize;
    while let Some(pos) = src[from..].find(header) {
        let abs = from + pos;
        let rest = &src[abs + header.len()..];
        if !skip_py_ws(rest).starts_with('(') {
            from = abs + 1;
            continue;
        }
        let open_rel = src[abs + header.len()..].find('{')?;
        let i = abs + header.len() + open_rel;
        let mut depth = 0usize;
        for (off, c) in src[i..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&src[i..i + off + c.len_utf8()]);
                    }
                }
                _ => {}
            }
        }
        return None;
    }
    None
}

/// `pub RATE\s*:\s*u64`.
fn has_pub_rate_field(code: &str, rate: &str) -> bool {
    let needle = format!("pub {rate}");
    let mut from = 0usize;
    while let Some(pos) = code[from..].find(&needle) {
        let abs = from + pos;
        let mut rest = &code[abs + needle.len()..];
        rest = skip_py_ws(rest);
        if let Some(after_colon) = rest.strip_prefix(':') {
            if skip_py_ws(after_colon).starts_with("u64") {
                return true;
            }
        }
        from = abs + 1;
    }
    false
}

/// `base_fee\s*(?:\.saturating_add|\+)`.
fn adds_floor(code: &str) -> bool {
    let mut from = 0usize;
    while let Some(pos) = code[from..].find("base_fee") {
        let abs = from + pos;
        let rest = skip_py_ws(&code[abs + "base_fee".len()..]);
        if rest.starts_with(".saturating_add") || rest.starts_with('+') {
            return true;
        }
        from = abs + 1;
    }
    false
}

/// `#[test]\s*(?:#\[[^\]]*\]\s*)*fn\s+TEST\s*\(` in the raw source.
fn has_test_fn(src: &str, test: &str) -> bool {
    let mut from = 0usize;
    while let Some(pos) = src[from..].find("#[test]") {
        let abs = from + pos;
        let mut rest = &src[abs + "#[test]".len()..];
        rest = skip_py_ws(rest);
        // Optional attributes: `#[...]` groups.
        while rest.starts_with("#[") {
            let Some(close) = rest.find(']') else {
                break;
            };
            rest = skip_py_ws(&rest[close + 1..]);
        }
        let Some(after_fn) = rest.strip_prefix("fn") else {
            from = abs + 1;
            continue;
        };
        if after_fn.len() == skip_py_ws(after_fn).len() {
            from = abs + 1;
            continue; // `\s+` after `fn` is required
        }
        let after_fn = skip_py_ws(after_fn);
        let Some(tail) = after_fn.strip_prefix(test) else {
            from = abs + 1;
            continue;
        };
        if skip_py_ws(tail).starts_with('(') {
            return true;
        }
        from = abs + 1;
    }
    false
}

fn check_rate_fields(params_code: &str, problems: &mut Vec<String>, checked: &mut usize) {
    // The three rates exist and are separate fields.
    for rate in RATES {
        *checked += 1;
        if !has_pub_rate_field(params_code, rate) {
            problems.push(format!(
                "`RegistryParams` has no `{rate}`. A proportional cut that cannot \
                 be expressed as a parameter ends up as a literal at whichever \
                 call site lands first."
            ));
        }
    }

    *checked += 1;
    if params_code.contains("bridge_relayer_fee_ppm") && !params_code.contains("bridge_fee_ppm") {
        problems.push(String::from(
            "`bridge_fee_ppm` is gone while `bridge_relayer_fee_ppm` remains. Those \
             are different things: one is the protocol's cut on an outbound \
             transfer, the other is compensation paid to a relayer out of an \
             arriving asset. Merging them redirects revenue.",
        ));
    }
}

fn check_validate_bounds(params_code: &str, problems: &mut Vec<String>, checked: &mut usize) {
    // Each rate is bounded below 100%.
    if let Some(validate) = body_of(params_code, "validate") {
        for rate in RATES {
            *checked += 1;
            if !validate.contains(rate) {
                problems.push(format!(
                    "`validate` does not bound `{rate}`. A cut at or above 100% \
                     debits the sender everything and credits the recipient nothing."
                ));
            }
        }
    } else {
        problems.push(String::from(
            "cannot find `RegistryParams::validate` to check the rate bounds.",
        ));
    }
}

fn check_fee_shape(params_code: &str, problems: &mut Vec<String>, checked: &mut usize) {
    // The fee reads the amount, combines with max, and rounds up.
    let prop = body_of(params_code, "proportional_fee");
    let req = body_of(params_code, "required_transfer_fee");

    *checked += 1;
    if let Some(body) = prop {
        *checked += 1;
        if !body.contains("amount") {
            problems.push(String::from(
                "`proportional_fee` never mentions `amount`. A fee that ignores the \
                 value moved is exactly the bug this gate exists to prevent.",
            ));
        }
        *checked += 1;
        if !body.contains("div_ceil") {
            problems.push(String::from(
                "`proportional_fee` does not round up. Integer division sends any \
                 charge below one base unit to zero, so the smallest transfers ride \
                 free and splitting a large one becomes profitable. A genuinely \
                 free transfer is written as a zero rate.",
            ));
        }
        *checked += 1;
        if !body.contains("u128") {
            problems.push(String::from(
                "`proportional_fee` does not widen to `u128`. `amount * rate` leaves \
                 `u64` well inside the range of amounts this function exists to \
                 price.",
            ));
        }
    } else {
        problems.push(String::from(
            "no `proportional_fee` in RegistryParams; the fee has no single home \
             and each call site will spell the arithmetic its own way.",
        ));
    }

    *checked += 1;
    if let Some(body) = req {
        *checked += 1;
        if !adds_floor(body) {
            problems.push(String::from(
                "`required_transfer_fee` does not add the floor to the \
                 proportional cut. The decided model (user decision 2026-09-01) \
                 bills base + rate: the rate is protocol revenue bound at the \
                 instruction level, so it rides on top of the floor.",
            ));
        }
        *checked += 1;
        if body.contains(".max(") {
            problems.push(String::from(
                "`required_transfer_fee` maxes the floor against the cut. The \
                 decided model bills both: a max would let any large transfer \
                 skip the floor entirely.",
            ));
        }
    } else {
        problems.push(String::from(
            "no `required_transfer_fee`; nothing combines the floor with the cut.",
        ));
    }
}

fn check_validation_path(account_code: &str, problems: &mut Vec<String>, checked: &mut usize) {
    // The validation path must actually apply it.
    *checked += 1;
    if let Some(body) = body_of(account_code, "validate_transaction_with_context") {
        if !body.contains("required_transfer_fee") {
            problems.push(String::from(
                "`validate_transaction_with_context` does not call \
                 `required_transfer_fee`. The rate exists and nothing enforces it, \
                 which reads as a working proportional fee to anyone grepping for \
                 one.",
            ));
        }
    } else {
        problems.push(String::from(
            "cannot find `validate_transaction_with_context`. If it was renamed, \
             update this gate in the same commit so the fee check stays watched.",
        ));
    }
}

fn check_governance(
    gov_code: &str,
    account_code: &str,
    problems: &mut Vec<String>,
    checked: &mut usize,
) {
    // Governance can move the rates, in both places that decide it.
    // `apply_registry_parameter_update` is a private method, so its header
    // has no `pub`.
    let apply_fn = body_of_plain(account_code, "apply_registry_parameter_update");
    for rate in RATES {
        *checked += 1;
        if !gov_code.contains(&format!("\"{rate}\"")) {
            problems.push(format!(
                "`{rate}` is not on the governance whitelist. An economic rate that \
                 can only change by shipping a binary is not a parameter."
            ));
        }
        *checked += 1;
        if let Some(body) = apply_fn {
            if !body.contains(&format!("\"{rate}\"")) {
                problems.push(format!(
                    "`{rate}` is whitelisted but `apply_registry_parameter_update` has \
                     no arm for it. Governance would accept the proposal and then fail \
                     to apply it with `unknown registry parameter`. Two matches decide \
                     this, and both have to know the key."
                ));
            }
        } else {
            problems.push(String::from(
                "cannot find `apply_registry_parameter_update`; if it moved, update \
                 this gate in the same commit so the second half of the whitelist \
                 stays watched.",
            ));
        }
    }
}

fn check_tests(params_src: &str, problems: &mut Vec<String>, checked: &mut usize) {
    // The regressions must exist as real tests.
    *checked += 1;
    for test in TEST_NAMES {
        if !has_test_fn(params_src, test) {
            problems.push(format!(
                "required regression test `{test}` is missing or is not a `#[test]`."
            ));
        }
    }
}

/// # Errors
///
/// Missing sources, a rate that cannot be expressed, bounded or applied, a
/// fee that ignores the amount or truncates, or a missing regression test.
pub fn run(root: &Path) -> Result<String, String> {
    let params = root.join("src/registry/params.rs");
    let account = root.join("src/core/account.rs");
    let governance = root.join("src/core/governance.rs");

    for path in [&params, &account, &governance] {
        if !path.is_file() {
            return Err(format!(
                "FAIL: expected source file missing: {}",
                path.display()
            ));
        }
    }

    let params_src = std::fs::read_to_string(&params).unwrap_or_default();
    let params_code = strip_comments(&params_src);
    let account_code = strip_comments(&std::fs::read_to_string(&account).unwrap_or_default());
    let gov_code = strip_comments(&std::fs::read_to_string(&governance).unwrap_or_default());

    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    check_rate_fields(&params_code, &mut problems, &mut checked);
    check_validate_bounds(&params_code, &mut problems, &mut checked);
    check_fee_shape(&params_code, &mut problems, &mut checked);
    check_validation_path(&account_code, &mut problems, &mut checked);
    check_governance(&gov_code, &account_code, &mut problems, &mut checked);
    check_tests(&params_src, &mut problems, &mut checked);

    if checked == 0 {
        return Err(String::from("FAIL: gate checked nothing"));
    }

    if !problems.is_empty() {
        let mut msg = String::new();
        for p in &problems {
            let _ = writeln!(msg, "FAIL: {p}");
        }
        return Err(msg);
    }

    Ok(format!(
        "value pricing gate OK: {checked} checks, transfers are priced by value"
    ))
}

// ---------------------------------------------------------------------------
// Self-test: the ten canaries of the shell version.
// ---------------------------------------------------------------------------

const FIELDS: &str = "    pub transfer_fee_ppm: u64,\n\
    pub swap_fee_ppm: u64,\n\
    pub bridge_fee_ppm: u64,\n\
    pub bridge_relayer_fee_ppm: u64,\n";
const FIELDS_MERGED: &str = "    pub transfer_fee_ppm: u64,\n\
    pub swap_fee_ppm: u64,\n\
    pub bridge_relayer_fee_ppm: u64,\n";
const VALIDATE_GOOD: &str = "    pub fn validate(&self) -> Result<(), String> {\n\
        for (n, r) in [(\"transfer_fee_ppm\", self.transfer_fee_ppm),\n\
                       (\"swap_fee_ppm\", self.swap_fee_ppm),\n\
                       (\"bridge_fee_ppm\", self.bridge_fee_ppm)] {\n\
            if r >= PPM_DENOMINATOR { return Err(n.into()); }\n\
        }\n\
        Ok(())\n\
    }\n";
const VALIDATE_UNBOUNDED: &str = "    pub fn validate(&self) -> Result<(), String> {\n\
        Ok(())\n\
    }\n";
const PROP_GOOD: &str = "    pub fn proportional_fee(&self, amount: u64, rate_ppm: u64) -> u64 {\n\
        let scaled = u128::from(amount).saturating_mul(u128::from(rate_ppm));\n\
        u64::try_from(scaled.div_ceil(u128::from(PPM_DENOMINATOR))).unwrap_or(u64::MAX)\n\
    }\n";
const PROP_IGNORES: &str = "    pub fn proportional_fee(&self, _a: u64, rate_ppm: u64) -> u64 {\n\
        let scaled = u128::from(rate_ppm);\n\
        u64::try_from(scaled.div_ceil(u128::from(PPM_DENOMINATOR))).unwrap_or(u64::MAX)\n\
    }\n";
const PROP_TRUNCATES: &str =
    "    pub fn proportional_fee(&self, amount: u64, rate_ppm: u64) -> u64 {\n\
        let scaled = u128::from(amount).saturating_mul(u128::from(rate_ppm));\n\
        u64::try_from(scaled / u128::from(PPM_DENOMINATOR)).unwrap_or(u64::MAX)\n\
    }\n";
const REQ_GOOD: &str =
    "    pub fn required_transfer_fee(&self, amount: u64, base_fee: u64) -> u64 {\n\
        base_fee.saturating_add(self.proportional_fee(amount, self.transfer_fee_ppm))\n\
    }\n";
const REQ_MAXES: &str =
    "    pub fn required_transfer_fee(&self, amount: u64, base_fee: u64) -> u64 {\n\
        base_fee.max(self.proportional_fee(amount, self.transfer_fee_ppm))\n\
    }\n";
const TEST_NAMES: [&str; 7] = [
    "a_larger_transfer_requires_a_larger_fee",
    "the_default_rate_leaves_the_flat_fee_untouched",
    "splitting_a_transfer_does_not_reduce_the_total_fee",
    "a_priced_transfer_is_never_free_through_rounding",
    "an_enormous_transfer_saturates_rather_than_wrapping",
    "a_proportional_rate_at_or_above_one_hundred_percent_is_refused",
    "the_three_proportional_rates_are_independent",
];

/// Write one fixture tree and check the gate's verdict.
fn check_fixture(mode: &str, expect_ok: bool, label: &str) -> Result<(), String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir =
        std::env::temp_dir().join(format!("budlum-gates-value-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(dir.join("src/registry"));
    let _ = std::fs::create_dir_all(dir.join("src/core"));

    let fields = if mode == "merged_bridge" {
        FIELDS_MERGED
    } else {
        FIELDS
    };
    let validate = if mode == "unbounded" {
        VALIDATE_UNBOUNDED
    } else {
        VALIDATE_GOOD
    };
    let prop = match mode {
        "ignores_amount" => PROP_IGNORES,
        "truncates" => PROP_TRUNCATES,
        _ => PROP_GOOD,
    };
    let req = if mode == "maxes" { REQ_MAXES } else { REQ_GOOD };

    let mut tests = String::new();
    let test_count = if mode == "missing_test" {
        TEST_NAMES.len() - 1
    } else {
        TEST_NAMES.len()
    };
    for name in &TEST_NAMES[..test_count] {
        let _ = writeln!(tests, "#[test]\nfn {name}() {{}}");
    }

    std::fs::write(
        dir.join("src/registry/params.rs"),
        format!(
            "pub struct RegistryParams {{\n{fields}}}\nimpl RegistryParams {{\n{validate}{prop}{req}}}\n{tests}"
        ),
    )
    .map_err(|e| e.to_string())?;

    let apply_line = if mode == "unapplied" {
        "self.base_fee"
    } else {
        "self.registry.params().required_transfer_fee(tx.amount, self.base_fee)"
    };
    let arms: Vec<&str> = if mode == "half_governed" {
        vec!["\"transfer_fee_ppm\"", "\"swap_fee_ppm\""]
    } else {
        vec![
            "\"transfer_fee_ppm\"",
            "\"swap_fee_ppm\"",
            "\"bridge_fee_ppm\"",
        ]
    };
    let mut apply_match = String::new();
    for a in &arms {
        let _ = writeln!(apply_match, "            {a} => {{}}");
    }
    std::fs::write(
        dir.join("src/core/account.rs"),
        format!(
            "impl AccountState {{\n\
             \x20   pub fn validate_transaction_with_context(&self) -> Result<(), String> {{\n\
             \x20       let required = {apply_line};\n\
             \x20       Ok(())\n\
             \x20   }}\n\
             \x20   fn apply_registry_parameter_update(&mut self, key: &str) -> Result<(), String> {{\n\
             \x20       match key {{\n{apply_match}\
             \x20           other => return Err(format!(\"unknown registry parameter: {{other}}\")),\n\
             \x20       }}\n\
             \x20       Ok(())\n\
             \x20   }}\n\
             }}\n"
        ),
    )
    .map_err(|e| e.to_string())?;

    let wl = if mode == "not_governed" {
        "\"transfer_fee_ppm\", \"swap_fee_ppm\","
    } else {
        "\"transfer_fee_ppm\", \"swap_fee_ppm\", \"bridge_fee_ppm\","
    };
    std::fs::write(
        dir.join("src/core/governance.rs"),
        format!("pub const GOVERNANCE_PARAMETER_WHITELIST: &[&str] = &[{wl}];\n"),
    )
    .map_err(|e| e.to_string())?;

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
    // 1. The corrected shape must pass.
    check_fixture("good", true, "the corrected pricing was rejected")?;

    // 2. The fee ignores the amount: the original bug, wearing the right name.
    check_fixture(
        "ignores_amount",
        false,
        "a fee function that ignores the amount",
    )?;

    // 3. The rate exists but nothing applies it.
    check_fixture("unapplied", false, "a rate no validation path reads")?;

    // 4. Floor and cut maxed instead of added.
    check_fixture("maxes", false, "a floor maxed against the cut rather than added")?;

    // 5. Rounding reverts to truncation.
    check_fixture(
        "truncates",
        false,
        "truncation that prices small transfers free",
    )?;

    // 6. The rates lose their bounds.
    check_fixture("unbounded", false, "rates with no 100% bound")?;

    // 7. The protocol cut is merged into the relayer's compensation.
    check_fixture(
        "merged_bridge",
        false,
        "the protocol cut merged into relayer pay",
    )?;

    // 8. A rate drops off the governance whitelist.
    check_fixture("not_governed", false, "a rate governance cannot move")?;

    // 9. A regression test disappears.
    check_fixture("missing_test", false, "a missing regression test")?;

    // 10. A rate reaches the whitelist and not the match that applies it.
    check_fixture(
        "half_governed",
        false,
        "a rate whitelisted but never applied",
    )?;

    Ok(String::from("value pricing gate self-test OK: 10 canaries"))
}
