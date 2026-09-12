//! AIR gating flags must be boolean and pinned.
//!
//! Ported from `scripts/check-gating-flags-are-pinned.sh`. `COL_REG_SAME` and
//! `COL_MEM_SAME` switch constraints off; a prover that picks the flag value
//! picks whether the rule applies. Each flag must be read into its local
//! binding, asserted boolean, and constrained on the `1 - flag` side or pinned
//! with `assert_eq`.

use std::fmt::Write as _;
use std::path::Path;

const FLAGS: &[(&str, &str)] = &[("COL_REG_SAME", "r_same"), ("COL_MEM_SAME", "m_same")];

fn strip_all(src: &str) -> String {
    // block comments
    let mut out = String::new();
    let b = src.as_bytes();
    let mut i = 0;
    let mut depth = 0i32;
    while i < b.len() {
        if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'*' {
            depth += 1;
            i += 2;
            continue;
        }
        if depth > 0 && i + 1 < b.len() && b[i] == b'*' && b[i + 1] == b'/' {
            depth -= 1;
            i += 2;
            continue;
        }
        if depth > 0 {
            i += 1;
            continue;
        }
        out.push(b[i] as char);
        i += 1;
    }
    // line comments
    let mut out2 = String::new();
    for l in out.lines() {
        let idx = l.find("//").unwrap_or(l.len());
        out2.push_str(&l[..idx]);
        out2.push('\n');
    }
    out2
}

/// `let <local>: AB::Expr = cur[COL_X]` present.
fn has_bind(code: &str, local: &str, column: &str) -> bool {
    code.contains(&format!("let {local}: AB::Expr = cur[{column}]"))
}

fn has_boolean(code: &str, local: &str) -> bool {
    code.contains(&format!("assert_bool({local}"))
}

fn has_negated(code: &str, local: &str) -> bool {
    code.contains(&format!("one.clone() - {local}.clone()"))
}

fn has_pinned(code: &str, local: &str) -> bool {
    code.contains(&format!("assert_eq({local}.clone()"))
}

/// # Errors
///
/// Returns the list of violated claims.
pub fn run(root: &Path) -> Result<String, String> {
    let f = root.join("budzero/bud-proof/src/plonky3_air.rs");
    if !f.is_file() {
        return Err(format!("no AIR at {}", f.display()));
    }
    let src = std::fs::read_to_string(&f).map_err(|e| e.to_string())?;
    let code = strip_all(&src);
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for (column, local) in FLAGS {
        if !code.contains(column) {
            problems.push(format!(
                "{column} is gone from the AIR. If the flag was removed the entry \
                 here should go with it, in the same commit, with the reason."
            ));
            continue;
        }
        if !has_bind(&code, local, column) {
            problems.push(format!(
                "{column} is not read into `{local}` the way this gate expects, so \
                 it cannot tell what is constraining it. Update the gate together \
                 with the rename."
            ));
            continue;
        }
        checked += 1;
        let boolean = has_boolean(&code, local);
        let negated = has_negated(&code, local);
        let pinned = has_pinned(&code, local);
        if !(boolean || negated || pinned) {
            problems.push(format!(
                "{column} gates constraints but nothing pins it: no booleanity, no \
                 constraint on the `1 - {local}` side, and no equality binding it. \
                 A prover can set it to zero for free and switch off whatever it \
                 gates."
            ));
        } else if !(negated || pinned) {
            problems.push(format!(
                "{column} is boolean but costs nothing when it is zero. Booleanity \
                 only says the flag is 0 or 1, not that 0 is a lie the prover has \
                 to pay for. Add a constraint on the `1 - {local}` side, or pin the \
                 flag to the condition it claims with an inverse witness."
            ));
        } else if !boolean {
            problems.push(format!(
                "{column} has a counterpart constraint but no booleanity, so it can \
                 take a field value that is neither 0 nor 1 and satisfy both sides \
                 at once."
            ));
        }
    }

    if checked == 0 {
        return Err(String::from(
            "none of the listed gating flags could be checked - the gate is vacuous",
        ));
    }
    if !problems.is_empty() {
        let mut msg = String::from("FAIL: these gating flags are not pinned:\n");
        for p in &problems {
            writeln!(msg, "  - {p}").expect("writing to a String cannot fail");
        }
        msg.push_str(
            "\nA flag that switches a constraint off is part of the constraint. If the\n\
             prover picks its value, the prover picks whether the rule applies.",
        );
        return Err(msg);
    }
    Ok(format!(
        "Gating-flag gate OK: all {checked} same-ness flags are boolean and pinned."
    ))
}

/// # Errors
///
/// Returns a finding when an unpinned flag passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-gf")?;
    let _ = std::fs::create_dir_all(dir.join("budzero/bud-proof/src"));

    let good = "pub const COL_REG_SAME: usize = 28;\npub const COL_MEM_SAME: usize = 54;\n        let r_same: AB::Expr = cur[COL_REG_SAME].into();\n        builder.assert_bool(r_same.clone());\n        builder.when_transition().assert_eq(r_same.clone(), one.clone() - reg_diff_z);\n        let m_same: AB::Expr = cur[COL_MEM_SAME].into();\n        builder.assert_bool(m_same.clone());\n        builder.when_transition().assert_zero(\n            m_active.clone() * (one.clone() - m_same.clone()) * nm_val.clone(),\n        );\n";
    std::fs::write(dir.join("budzero/bud-proof/src/plonky3_air.rs"), good)
        .map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: pinned flags were rejected"));
    }
    // Unpinned: no assert_bool, no negated side.
    let free = "pub const COL_REG_SAME: usize = 28;\n        let r_same: AB::Expr = cur[COL_REG_SAME].into();\n        builder.when_transition().assert_zero(\n            r_active.clone() * r_same.clone(),\n        );\n";
    std::fs::write(dir.join("budzero/bud-proof/src/plonky3_air.rs"), free)
        .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: an unpinned flag passed"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "gating-flags canary OK: pinned PASSes and unpinned FAILs.",
    ))
}
