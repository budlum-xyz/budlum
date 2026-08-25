//! `LogUp` activity flags must never be scaled by a register index.
//!
//! Ported from `scripts/check-logup-multipliers-are-boolean.sh`. Multiplying
//! an activity term by a register number scales the `LogUp` demand side by the
//! register index; the boolean must be derived through an inverse witness,
//! asserted boolean, and pinned (`idx * (1 - z) == 0`).

use std::fmt::Write as _;
use std::path::Path;

const INDEX_LOCALS: &[&str] = &["rs1_idx", "rs2_idx", "rd_idx", "reg_idx"];
const ACTIVITY_TERMS: &[&str] = &[
    "is_real_mem_op",
    "is_stack_op",
    "is_storage_op",
    "is_any_mem_op",
];

fn strip_comments(text: &str) -> String {
    text.lines()
        .map(|l| {
            let idx = l.find("//").unwrap_or(l.len());
            l[..idx].to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `let <term> ... = <expr>;` - the expression may span lines.
fn find_def(src: &str, term: &str) -> Option<String> {
    let needle = format!("let {term}");
    let start = src.find(&needle)?;
    let after = &src[start + needle.len()..];
    let eq = after.find('=')?;
    let expr_start = start + needle.len() + eq + 1;
    let rest = &src[expr_start..];
    let end = rest.find(';')?;
    Some(strip_comments(&rest[..end]))
}

/// Bare `idx` not followed by `_` (so `rs1_idx_z`/`rs1_idx_inv` are safe).
fn mentions_bare(text: &str, idx: &str) -> bool {
    let mut rest = text;
    while let Some(pos) = rest.find(idx) {
        let after = &rest[pos + idx.len()..];
        if !after.starts_with('_') {
            return true;
        }
        rest = &rest[pos + idx.len()..];
    }
    false
}

/// Activity-term definitions multiplied by a bare register index.
fn check_activity_terms(air_src: &str, prover_src: &str, problems: &mut Vec<String>) -> usize {
    let mut checked = 0usize;
    for term in ACTIVITY_TERMS {
        for (src, what) in [(air_src, "AIR"), (prover_src, "prover")] {
            let Some(body) = find_def(src, term) else {
                problems.push(format!(
                    "{what}: `{term}` is gone or spelled differently, so this gate \
                     cannot tell what the memory argument multiplies by. Update the \
                     gate in the same commit as the rename."
                ));
                continue;
            };
            checked += 1;
            for idx in INDEX_LOCALS {
                if mentions_bare(&body, idx) {
                    problems.push(format!(
                        "{what}: `{term}` is built by multiplying with `{idx}`, \
                         which holds a register number rather than a flag. The \
                         LogUp demand side is then scaled by the register index \
                         while the table supplies the row once, so honest programs \
                         using any register but r1 have no valid proof. Derive a \
                         boolean through an inverse witness instead: \
                         `{idx} * {idx}_inv`, asserted boolean, with \
                         `{idx} * (1 - z) == 0`."
                    ));
                }
            }
        }
    }
    checked
}

/// Index witnesses must be derived, boolean, pinned, and read by the prover.
fn check_index_witnesses(air_src: &str, prover_src: &str, problems: &mut Vec<String>) -> usize {
    let mut checked = 0usize;
    for idx in INDEX_LOCALS {
        let inv = format!("{idx}_inv");
        if !air_src.contains(&inv) {
            continue;
        }
        let z_derived = air_src
            .lines()
            .any(|l| l.contains(&format!("let {idx}_z")) && l.contains(&inv));
        if !z_derived {
            problems.push(format!(
                "AIR: `{inv}` exists but no `{idx}_z` is derived from it, so the \
                 witness is carried and never used."
            ));
            continue;
        }
        checked += 1;
        if !air_src.contains(&format!("assert_bool({idx}_z")) {
            problems.push(format!(
                "AIR: `{idx}_z` is not asserted boolean, so the inverse witness \
                 can take a value that is neither 0 nor 1."
            ));
        }
        if !air_src.contains(&format!(
            "assert_zero({idx}.clone() * (one.clone() - {idx}_z"
        )) {
            problems.push(format!(
                "AIR: nothing forces `{idx}_z = 1` when `{idx}` is non-zero, so a \
                 prover can write zero for `{inv}` and take a row that does \
                 address memory off the demand side of the argument."
            ));
        }
        let col = format!("COL_{}_INV", idx.to_uppercase());
        if air_src.contains(&col) && !prover_src.contains(&col) {
            problems.push(format!(
                "prover: `{col}` is declared in the AIR but the prover never reads \
                 it, so the two sides are deciding the same flag independently. \
                 That is the shape the original bug hid in."
            ));
        }
    }
    checked
}

/// `one.clone() - <idx>.clone()` negates a register number.
fn one_minus_idx(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        for idx in INDEX_LOCALS {
            if t.contains(&format!("one.clone() - {idx}.clone()")) {
                out.push((i + 1, format!("one.clone() - {idx}.clone()")));
            }
        }
    }
    out
}

/// `.when(<body>)` where body mentions a bare index local.
fn when_gates_raw_index(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.contains(".when(") {
            for idx in INDEX_LOCALS {
                if mentions_bare(t, idx) {
                    out.push((i + 1, t.chars().take(70).collect()));
                    break;
                }
            }
        }
    }
    out
}

/// # Errors
///
/// Returns the list of violated claims.
pub fn run(root: &Path) -> Result<String, String> {
    let air_path = root.join("budzero/bud-proof/src/plonky3_air.rs");
    let prover_path = root.join("budzero/bud-proof/src/plonky3_prover.rs");
    if !air_path.is_file() {
        return Err(format!("no AIR at {}", air_path.display()));
    }
    if !prover_path.is_file() {
        return Err(format!("no prover at {}", prover_path.display()));
    }
    let air_src = std::fs::read_to_string(&air_path).map_err(|e| e.to_string())?;
    let prover_src = std::fs::read_to_string(&prover_path).map_err(|e| e.to_string())?;
    let air_nc = strip_comments(&air_src);
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    checked += check_activity_terms(&air_src, &prover_src, &mut problems);
    checked += check_index_witnesses(&air_src, &prover_src, &mut problems);

    for (line, expr) in one_minus_idx(&air_nc) {
        problems.push(format!(
            "AIR line ~{line}: `{expr}` negates a register number rather \
             than a boolean. At index 7 the coefficient is -6, not 0, so whatever \
             this gates fires on rows it was written to skip. Use \
             `one - <idx>_z` with the inverse witness."
        ));
    }
    checked += 1;
    for (line, body) in when_gates_raw_index(&air_nc) {
        problems.push(format!(
            "AIR line ~{line}: `.when({body})` gates a constraint \
             on a raw register index. A gate has to be boolean; a register \
             number switches the rule on with the wrong strength on every \
             index but one."
        ));
    }
    checked += 1;

    if checked == 0 {
        return Err(String::from("gate checked nothing"));
    }
    if !problems.is_empty() {
        let mut msg = String::new();
        for p in &problems {
            writeln!(msg, "FAIL: {p}").expect("writing to a String cannot fail");
        }
        return Err(msg);
    }
    Ok(format!(
        "logup multipliers OK: {checked} checks, no activity flag scaled by a register index"
    ))
}

/// # Errors
///
/// Returns a finding when a defect fixture passes.
pub fn self_test() -> Result<String, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!("budlum-gates-lm-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(dir.join("budzero/bud-proof/src"));

    let mut air = String::from(
        "let is_real_mem_op = is_load.clone() + is_store.clone();\n\
         let is_stack_op = is_real_mem_op.clone() & is_stack.clone();\n\
         let is_storage_op = is_real_mem_op.clone() & is_storage.clone();\n\
         let is_any_mem_op = is_real_mem_op.clone();\n",
    );
    let mut prover = air.clone();
    for idx in INDEX_LOCALS {
        writeln!(air, "pub const COL_{}_INV: usize = 5;", idx.to_uppercase())
            .expect("writing to a String cannot fail");
        writeln!(
            prover,
            "pub const COL_{}_INV: usize = 5;",
            idx.to_uppercase()
        )
        .expect("writing to a String cannot fail");
        let z_line = format!("let {idx}_z = {idx}.clone() * {idx}_inv.clone();\n");
        let bool_line = format!("builder.assert_bool({idx}_z.clone());\n");
        let pin_line =
            format!("builder.assert_zero({idx}.clone() * (one.clone() - {idx}_z.clone()));\n");
        air.push_str(&z_line);
        air.push_str(&bool_line);
        air.push_str(&pin_line);
    }
    std::fs::write(dir.join("budzero/bud-proof/src/plonky3_air.rs"), &air)
        .map_err(|e| e.to_string())?;
    std::fs::write(dir.join("budzero/bud-proof/src/plonky3_prover.rs"), &prover)
        .map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a correct tree was refused"));
    }
    let bad = air.replace(
        "is_load.clone() + is_store.clone()",
        "is_load.clone() * rs1_idx.clone()",
    );
    std::fs::write(dir.join("budzero/bud-proof/src/plonky3_air.rs"), bad)
        .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: register indeksi ile carpan flag gecti",
        ));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "logup-multipliers canary OK: a clean multiplier PASSes and an index multiplier FAILs.",
    ))
}
