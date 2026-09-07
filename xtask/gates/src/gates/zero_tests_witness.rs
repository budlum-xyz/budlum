//! Every zero test in the VM goes through an inverse witness in the AIR.
//!
//! Ported from `scripts/check-zero-tests-use-an-inverse-witness.sh`. When the
//! VM refuses a zero value (`src1_val == 0`), the AIR must enforce it through
//! an inverse-witness column, never a direct `assert_one(reg)`: a field
//! element has no order, so non-zero cannot be stated directly.

use std::fmt::Write as _;
use std::path::Path;

const ZERO_TESTS: &[(&str, &str, &str)] = &[
    ("Assert", "src1_val", "COL_ASSERT_INV"),
    ("Div", "src2_val", "COL_DIV_INV"),
    ("Inv", "src1_val", "COL_INV_ZERO"),
    ("Jnz", "src1_val", "COL_JNZ_COND_INV"),
    ("Not", "src1_val", "COL_INV_ZERO"),
];

fn read(root: &Path, rel: &str, what: &str) -> Result<String, String> {
    let f = root.join(rel);
    if !f.is_file() {
        return Err(format!("no {what} at {}", f.display()));
    }
    std::fs::read_to_string(&f).map_err(|e| e.to_string())
}

/// Brace-balanced body of `Opcode::<name> => { ... }` in the VM.
fn vm_body(vm_src: &str, name: &str) -> Option<String> {
    let needle = format!("Opcode::{name} => {{");
    let start = vm_src.find(&needle)? + needle.len();
    let mut depth = 1i32;
    let mut i = start;
    let b = vm_src.as_bytes();
    while i < b.len() {
        match b[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(vm_src[start..i].to_string());
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Comments and literals gone, through the shared
/// [`rust_literals::scrub`](crate::gates::rust_literals::scrub): string and
/// char literals first (so a `//` or `/*` inside one is data), then nested
/// block comments, then line comments. This gate used to cut at `//` only,
/// so `builder.when /* note */ (is_assert).assert_one(rs1_val)` kept the
/// comment in the statement, `when(is_assert` never matched, and the
/// direct assertion passed.
fn strip_comments(text: &str) -> String {
    crate::gates::rust_literals::scrub(text)
}

/// The statements of a source fragment, comments gone, every run of
/// whitespace collapsed and the whitespace around punctuation removed, so
/// that a chain rustfmt spread over several lines is one string again and
/// `builder . when (is_assert) . assert_one(rs1_val)` reads the same as the
/// compact spelling. Matching per line was a hole: a long builder chain is
/// formatted as `builder\n    .when(..)\n    .assert_one(..);`, and no single
/// line of that carried all three tokens, so the direct form passed; spaces
/// kept around `.` and `(` were the same hole one token wide.
fn statements(text: &str) -> Vec<String> {
    strip_comments(text)
        .split(';')
        .map(|s| {
            let mut out = String::with_capacity(s.len());
            for word in s.split_whitespace() {
                let glue = out.is_empty()
                    || out.ends_with(['.', '(', ')', ',', '=', '!', '{', '}'])
                    || word.starts_with(['.', '(', ')', ',', '=', '!', '{', '}']);
                if !glue {
                    out.push(' ');
                }
                out.push_str(word);
            }
            out
        })
        .collect()
}

/// `reg (==|!=) 0` in the body, however it was spaced.
fn tests_zero(body: &str, reg: &str) -> bool {
    statements(body)
        .iter()
        .any(|s| s.contains(&format!("{reg}==0")) || s.contains(&format!("{reg}!=0")))
}

/// The AIR constrains the register directly with `assert_one`, bypassing the
/// witness: `.when(is_<snake>)...assert_one(<air_reg>)`.
fn has_direct_assert(air_code: &str, snake: &str, air_reg: &str) -> bool {
    statements(air_code).iter().any(|s| {
        s.contains(&format!("when(is_{snake}")) && s.contains("assert_one(") && s.contains(air_reg)
    })
}

/// # Errors
///
/// Returns the list of violated claims.
pub fn run(root: &Path) -> Result<String, String> {
    let vm_src = read(root, "budzero/bud-vm/src/lib.rs", "VM")?;
    let air_src = read(root, "budzero/bud-proof/src/plonky3_air.rs", "AIR")?;
    let air_code = strip_comments(&air_src);
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for (opcode, reg, witness) in ZERO_TESTS {
        let Some(body) = vm_body(&vm_src, opcode) else {
            problems.push(format!(
                "the VM has no `Opcode::{opcode}` arm this gate can read. If the \
                 opcode was removed the entry here should go with it, in the same \
                 commit."
            ));
            continue;
        };
        checked += 1;
        if !tests_zero(&body, reg) {
            problems.push(format!(
                "the VM's `{opcode}` no longer tests `{reg}` against zero, so this \
                 entry describes a rule that is gone. Update the gate together \
                 with the semantics."
            ));
            continue;
        }
        checked += 1;
        if !air_src.contains(witness) {
            problems.push(format!(
                "`{opcode}` tests `{reg}` against zero in the VM and the AIR has no \
                 `{witness}`. A field element has no order, so non-zero cannot be \
                 stated directly; without a witness the AIR is enforcing some \
                 other rule, and the two only have to agree on the values the \
                 tests happen to use."
            ));
            continue;
        }
        checked += 1;
        let snake = camel_to_snake(opcode);
        let air_reg = reg.replace("src", "rs");
        if has_direct_assert(&air_code, &snake, &air_reg) {
            problems.push(format!(
                "`{opcode}` constrains `{reg}` directly with `assert_one`, which \
                 demands exactly 1 where the VM only refuses zero. Those agree on \
                 0 and 1 and nowhere else, and comparison results are 0 or 1, so \
                 tests will not show the difference. Route it through \
                 `{witness}`."
            ));
        }
    }

    if checked == 0 {
        return Err(String::from("gate checked nothing"));
    }
    if !problems.is_empty() {
        let mut msg = String::new();
        for p in problems {
            writeln!(msg, "FAIL: {p}").expect("writing to a String cannot fail");
        }
        return Err(msg);
    }
    Ok(format!(
        "zero-test gate OK: {checked} checks, every zero test goes through a witness"
    ))
}

fn camel_to_snake(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// # Errors
///
/// Returns a finding when a defect fixture passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-ztw")?;
    let _ = std::fs::create_dir_all(dir.join("budzero/bud-vm/src"));
    let _ = std::fs::create_dir_all(dir.join("budzero/bud-proof/src"));

    let good_vm = "match opcode {\n            Opcode::Assert => {\n                if src1_val == 0 { return Err(VmError::AssertionFailed); }\n            }\n            Opcode::Div => {\n                let result = if src2_val != 0 { 1 } else { 0 };\n            }\n            Opcode::Inv => {\n                let result = if src1_val != 0 { 1 } else { 0 };\n            }\n            Opcode::Jnz => {\n                let taken = src1_val != 0;\n            }\n            Opcode::Not => {\n                let result = if src1_val == 0 { 1 } else { 0 };\n            }\n        }";
    let good_air = "pub const COL_ASSERT_INV: usize = 740;\npub const COL_DIV_INV: usize = 58;\npub const COL_INV_ZERO: usize = 60;\npub const COL_JNZ_COND_INV: usize = 62;\n        let assert_inv: AB::Expr = cur[COL_ASSERT_INV].into();\n        let assert_z = rs1_val.clone() * assert_inv;\n        builder.when(is_assert.clone()).assert_bool(assert_z.clone());\n        builder.when(is_assert).assert_one(assert_z);\n";
    std::fs::write(dir.join("budzero/bud-vm/src/lib.rs"), good_vm).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("budzero/bud-proof/src/plonky3_air.rs"), good_air)
        .map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a correct tree was refused"));
    }
    // Direct assert_one bypass. Prefixed with `good_air` so every witness
    // constant the gate looks for is present: the refusal must come from the
    // direct-assertion check alone, not from a missing witness column that
    // would have failed `run` earlier anyway.
    let direct_air = format!(
        "{good_air}        builder.when(is_assert).assert_one(rs1_val.clone());\n"
    );
    std::fs::write(dir.join("budzero/bud-proof/src/plonky3_air.rs"), direct_air)
        .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a direct assert_one passed"));
    }
    // The same bypass as rustfmt writes it, one call per line.
    let split_air = format!(
        "{good_air}        builder\n            .when(is_assert.clone())\n            .assert_one(rs1_val.clone());\n"
    );
    std::fs::write(dir.join("budzero/bud-proof/src/plonky3_air.rs"), split_air)
        .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a direct assert_one split across lines passed",
        ));
    }
    // The same bypass with spaces around the punctuation, which is still
    // valid Rust and read the same by the compiler.
    let spaced_air = format!(
        "{good_air}        builder . when (is_assert . clone ()) . assert_one (rs1_val . clone ());\n"
    );
    std::fs::write(dir.join("budzero/bud-proof/src/plonky3_air.rs"), spaced_air)
        .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a direct assert_one with spaces around its punctuation passed",
        ));
    }
    // The same bypass with a block comment inside the chain. A scanner that
    // removes only `//` comments leaves the comment between `when` and its
    // argument, so `when(is_assert` is never seen and the bypass passes.
    let commented_air = format!(
        "{good_air}        builder.when /* witness? no */ (is_assert).assert_one(rs1_val.clone());\n"
    );
    std::fs::write(
        dir.join("budzero/bud-proof/src/plonky3_air.rs"),
        commented_air,
    )
    .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a direct assert_one with a block comment inside the chain passed",
        ));
    }
    // A nested block comment holding the direct form is a comment, not an
    // assertion: the witness form next to it still passes.
    let nested_air = format!(
        "{good_air}        /* builder.when(is_assert).assert_one(rs1_val); /* nested */ still a comment */\n"
    );
    std::fs::write(dir.join("budzero/bud-proof/src/plonky3_air.rs"), nested_air)
        .map_err(|e| e.to_string())?;
    if let Err(e) = run(&dir) {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(format!(
            "canary: the direct form inside a nested block comment was taken as code: {e}"
        ));
    }
    // A zero test the VM writes across lines is still a zero test.
    std::fs::write(dir.join("budzero/bud-proof/src/plonky3_air.rs"), good_air)
        .map_err(|e| e.to_string())?;
    let split_vm = good_vm.replace(
        "if src1_val == 0 { return Err(VmError::AssertionFailed); }",
        "if src1_val\n                    == 0\n                {\n                    return Err(VmError::AssertionFailed);\n                }",
    );
    std::fs::write(dir.join("budzero/bud-vm/src/lib.rs"), split_vm).map_err(|e| e.to_string())?;
    if let Err(e) = run(&dir) {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(format!(
            "canary: a zero test written across lines was not recognised: {e}"
        ));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "zero-test canary OK: the witness form PASSes, the direct form FAILs on one line, \
         across lines, with spaced punctuation and with a block comment in the chain, a \
         commented-out direct form is not code, and a multi-line zero test is still \
         recognised.",
    ))
}
