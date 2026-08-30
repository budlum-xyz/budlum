//! Side-table accumulators must be bound on the last row of their own table.
//!
//! Ported from `scripts/check-cross-table-checks-use-last-row.sh`. A
//! `COL_*_ACC` column folded across a side table (memory, register) is only
//! guaranteed finished on that table's last row, so its public-input binding
//! must use `when_last_row`, never `is_halt`/`cpu_active` (which name the
//! last CPU row).
//!
//! The Strix CWE-184 hardening is kept: the block scan runs on a literal- and
//! comment-scrubbed view, so a commented-out or quoted binding block cannot
//! be mistaken for the real one (literals first, then block comments with a
//! depth counter, then line comments - the order the shell gate pinned).

use std::fmt::Write as _;
use std::path::Path;

use super::rust_literals;

const ACCUMULATORS: &[(&str, &str)] = &[
    ("COL_MEM_INIT_ACC", "the memory table"),
    ("COL_REG_INIT_ACC", "the register table"),
];

/// Non-nested brace blocks that mention `column` and `public_inputs`,
/// mirroring the shell regex `\{[^{}]*<column>[^{}]*\}`.
fn binding_blocks(src: &str, column: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let bytes = src.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'{' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] != b'{' && bytes[j] != b'}' {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'}' {
                let body = &src[i..=j];
                if body.contains(column) && body.contains("public_inputs") {
                    out.push((i, body.to_string()));
                }
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    out
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
    // Work on a literal- and comment-stripped view: a `/* ... */` or a string
    // that merely mentions the column must not look like the real binding.
    // Blanking keeps the newline structure, so line numbers stay right.
    let scrubbed = rust_literals::scrub(&src);
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for (column, table) in ACCUMULATORS {
        if !src.contains(column) {
            problems.push(format!(
                "{column} is gone from the AIR. If the accumulator was removed the \
                 entry here should go with it, in the same commit, with the reason."
            ));
            continue;
        }
        let blocks = binding_blocks(&scrubbed, column);
        if blocks.is_empty() {
            problems.push(format!(
                "{column} is never compared against a public input, so the \
                 accumulator is folded and then dropped. Either it binds \
                 something or it should not exist."
            ));
            continue;
        }
        for (start, body) in &blocks {
            checked += 1;
            let line = src[..*start].matches('\n').count() + 1;
            // The block body comes from the scrubbed view, so no comment or
            // literal can satisfy or trip the checks inside it.
            let code = body;
            if !code.contains("when_last_row") {
                problems.push(format!(
                    "AIR line ~{line}: the binding for {column} does not use \
                     `when_last_row`. {column} lives on {table}, whose length is \
                     not the CPU table's, so the fold may still be running when \
                     the CPU side halts."
                ));
            }
            for gate in ["is_halt", "cpu_active"] {
                if code.contains(&format!(".when({gate}")) {
                    problems.push(format!(
                        "AIR line ~{line}: the binding for {column} is gated on \
                         `{gate}`, which names the last *CPU* row. {column} is \
                         folded across {table}; when that table is longer the \
                         accumulator is mid-fold there and honest proofs fail. \
                         This is what happened to the register image."
                    ));
                }
            }
        }
    }

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
        "cross-table checks OK: {checked} side-table bindings, all on the last row"
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
    let dir = std::env::temp_dir().join(format!("budlum-gates-ct-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(dir.join("budzero/bud-proof/src"));

    let good = "pub const COL_MEM_INIT_ACC: usize = 731;\npub const COL_REG_INIT_ACC: usize = 736;\n        {\n            let acc_last: AB::Expr = cur[COL_MEM_INIT_ACC].into();\n            let expected = public_inputs[10].into();\n            builder.when_last_row().assert_eq(acc_last, expected);\n        }\n        {\n            let acc_last: AB::Expr = cur[COL_REG_INIT_ACC].into();\n            let expected = public_inputs[12].into();\n            builder.when_last_row().assert_eq(acc_last, expected);\n        }\n";
    std::fs::write(dir.join("budzero/bud-proof/src/plonky3_air.rs"), good)
        .map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a correct AIR was refused"));
    }
    // Gated on is_halt instead of last row.
    let bad = good.replace(
        "builder.when_last_row().assert_eq(acc_last, expected);",
        "builder.when(is_halt.clone()).when(cpu_active.clone()).assert_eq(acc_last, expected);",
    );
    std::fs::write(dir.join("budzero/bud-proof/src/plonky3_air.rs"), bad)
        .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: the last-CPU-row gate passed"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "cross-table canary OK: last_row PASSes and is_halt FAILs.",
    ))
}
