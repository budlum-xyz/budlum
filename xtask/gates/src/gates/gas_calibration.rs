//! Gas calibration: no opcode is both cheap to call and expensive to prove.
//!
//! # Why this gate exists
//!
//! `Vm::gas_cost` prices every opcode. The failure mode this gate exists for
//! is an opcode that is cheap in gas but whose proof *expands* into many trace
//! rows - a cheap call becomes a cheap way to force expensive prover work
//! (a griefing / DoS vector). The canonical case found this gate: `Div` is a
//! binary long division (the AIR expands one row per bit, up to 64 rows) yet
//! had fallen onto the cheap arithmetic default `_ => 1`, so a caller paid 1
//! gas per 64-row proof expansion.
//!
//! The gate asserts calibration invariants on the *actual* source so a later
//! edit cannot silently drop such an opcode back to the cheap default.
//!
//! # What it checks
//!
//! 1. Every opcode whose proof expands beyond a single trace row is priced
//!    *above* the arithmetic default (it is not the cheapest possible price).
//! 2. The cryptographically heavy opcodes hold a floor (they are not cheap).
//! 3. Memory/storage ordering holds: `SWrite > SRead > Load/Store` (a state
//!    root that persists and updates is more expensive than a plain memory
//!    access).
//! 4. The price table is total enough that the checks are not vacuous.

use std::collections::HashMap;
use std::fs;

/// Opcodes whose proof expands beyond a single trace row.
const EXPANDED: &[(&str, &str)] = &[
    ("VerifyMerkle", "64 trace rows per call (one per path bit)"),
    ("VerifyInference", "8 trace rows per call"),
    ("Div", "binary long division, one row per bit (up to 64)"),
];

/// The cryptographically focused opcodes (hashing / verification).
const HEAVY: &[&str] = &[
    "Poseidon",
    "VerifyMerkle",
    "VerifyInference",
    "PrivacyCommit",
    "NullifierCheck",
    "SumConservation",
];

fn opcode_names(lhs: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = lhs;
    while let Some(i) = rest.find("Opcode::") {
        let after = &rest[i + "Opcode::".len()..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            out.push(name);
        }
        rest = after;
    }
    out
}

fn first_integer(s: &str) -> u64 {
    let digits: String = s.chars().skip_while(|c| !c.is_ascii_digit()).take_while(char::is_ascii_digit).collect();
    digits.parse().unwrap_or(0)
}

/// Extract `(opcode -> gas)` and the `_` default from a `Vm::gas_cost` body.
fn parse_gas_map(body: &str) -> (HashMap<String, u64>, u64) {
    let mut map = HashMap::new();
    let mut default = 0u64;
    let mut rest = body;
    let mut pending: Vec<String> = Vec::new();
    loop {
        let Some(eq) = rest.find("=>") else { break };
        let lhs = &rest[..eq];
        pending.extend(opcode_names(lhs));
        let after = &rest[eq + 2..];
        let value = first_integer(after);
        if pending.is_empty() && lhs.contains('_') {
            default = value;
        } else {
            for name in pending.drain(..) {
                map.insert(name, value);
            }
        }
        rest = after;
    }
    (map, default)
}

/// Assert the calibration invariants on a parsed price table.
fn verify(map: &HashMap<String, u64>, default: u64, source_label: &str) -> Result<String, String> {
    let mut findings: Vec<String> = Vec::new();

    // 1) Expanded opcodes must be priced above the arithmetic default.
    for (op, why) in EXPANDED {
        let price = map.get(*op).copied().unwrap_or(default);
        if price <= default {
            findings.push(format!(
                "`{op}` is priced at {price} (the arithmetic default) but its proof {why}; \
                 a cheap call forces expensive prover work."
            ));
        }
    }

    // 2) The heavy set holds a floor.
    let heavy_floor = 8u64;
    for op in HEAVY {
        let price = map.get(*op).copied().unwrap_or(default);
        if price < heavy_floor {
            findings.push(format!(
                "`{op}` is priced at {price}, below the heavy-op floor of {heavy_floor}."
            ));
        }
    }

    // 3) Memory / storage ordering (state-root persistence above plain memory).
    let g = |n: &str| map.get(n).copied().unwrap_or(default);
    if !(g("SWrite") > g("SRead")) {
        findings.push(format!("storage write ({}) must cost more than storage read ({})", g("SWrite"), g("SRead")));
    }
    if !(g("SRead") > g("Load")) {
        findings.push(format!("storage read ({}) must cost more than a plain memory load ({})", g("SRead"), g("Load")));
    }
    if !(g("SWrite") > g("Store")) {
        findings.push(format!("storage write ({}) must cost more than a plain memory store ({})", g("SWrite"), g("Store")));
    }

    // 4) Vacuity: a price table with almost nothing in it proves nothing.
    if map.len() < 8 {
        findings.push(format!(
            "only {} opcodes priced under {source_label}; the gas table is too small to calibrate.",
            map.len()
        ));
    }

    if !findings.is_empty() {
        return Err(format!(
            "Gas calibration violations ({source_label}):\n{}",
            findings.join("\n")
        ));
    }

    Ok(format!(
        "Gas calibration OK: {} priced opcodes; expanded opcodes above the default, heavy floor holds, storage ordering holds.",
        map.len()
    ))
}

/// # Errors
///
/// A calibration violation, or a vacuous (too thin) price table.
pub fn run(root: &std::path::Path) -> Result<String, String> {
    let path = root.join("budzero").join("bud-vm").join("src").join("lib.rs");
    let src = fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

    let start = src
        .find("pub fn gas_cost")
        .ok_or("the gas_cost function was not found; the calibration gate is vacuous")?;
    let body = &src[start..];

    // Selector of the function body: open brace after the signature, matched
    // to its close (the `match` block is nested inside). We only need the
    // region up to the first top-level '}' that closes the function.
    let open = body.find('{').ok_or("gas_cost has no body")?;
    let mut depth = 0usize;
    let mut fn_end = body.len();
    for (i, ch) in body[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    fn_end = open + i;
                    break;
                }
            }
            _ => {}
        }
    }
    let fn_text = &body[open + 1..fn_end];

    let (map, default) = parse_gas_map(fn_text);
    verify(&map, default, &format!("{}", path.display()))
}

/// A fresh synthetic `gas_cost` body for the self-test.
fn synth_body(div_gas: u64) -> String {
    format!(
        "match opcode {{
            Opcode::Halt => 0,
            Opcode::Load | Opcode::Store => 3,
            Opcode::SRead => 8,
            Opcode::SWrite => 12,
            Opcode::Poseidon
            | Opcode::VerifyMerkle
            | Opcode::VerifyInference
            | Opcode::PrivacyCommit
            | Opcode::NullifierCheck
            | Opcode::SumConservation => 10,
            Opcode::Call | Opcode::Ret | Opcode::Push | Opcode::Pop => 2,
            Opcode::Syscall => 5,
            Opcode::Div => {div_gas},
            _ => 1,
        }}"
    )
}

/// # Errors
///
/// A canary that behaves contrary to the invariant.
pub fn self_test() -> Result<String, String> {
    // The calibrated table (Div priced at 10) must pass.
    let (map, default) = parse_gas_map(&synth_body(10));
    verify(&map, default, "self-test (calibrated)")?;

    // The exact regression this gate exists for: Div dropped to the cheap
    // default must be refused.
    let (map2, default2) = parse_gas_map(&synth_body(1));
    match verify(&map2, default2, "self-test (Div=cheap)") {
        Err(msg) if msg.contains("`Div` is priced at 1") => {}
        other => {
            return Err(format!(
                "canary: a cheap-priced Div was not refused as expected: {:?}",
                other
            ));
        }
    }

    // A broken storage ordering must be refused.
    let body = synth_body(10)
        .replace("Opcode::SRead => 8,", "Opcode::SRead => 3,")
        .replace("Opcode::SWrite => 12,", "Opcode::SWrite => 5,");
    let (map3, default3) = parse_gas_map(&body);
    if verify(&map3, default3, "self-test (ordering broken)").is_ok() {
        return Err(String::from(
            "canary: a broken storage ordering passed the gate",
        ));
    }

    Ok(String::from(
        "Self-test OK: calibrated table passes, cheap-priced Div refused, broken ordering refused.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_handles_multi_line_grouped_arms() {
        let (map, default) = parse_gas_map(&synth_body(10));
        assert_eq!(default, 1);
        assert_eq!(*map.get("VerifyMerkle").unwrap(), 10);
        assert_eq!(*map.get("Div").unwrap(), 10);
        assert_eq!(*map.get("Load").unwrap(), 3);
        assert_eq!(*map.get("Syscall").unwrap(), 5);
    }

    #[test]
    fn calibrated_table_passes() {
        let (map, default) = parse_gas_map(&synth_body(10));
        assert!(verify(&map, default, "unit").is_ok());
    }

    #[test]
    fn cheap_div_is_refused() {
        let (map, default) = parse_gas_map(&synth_body(1));
        assert!(verify(&map, default, "unit").is_err());
    }
}
