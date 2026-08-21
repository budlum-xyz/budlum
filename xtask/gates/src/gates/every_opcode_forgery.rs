//! Every opcode must have a forgery test that actually attacks it.
//!
//! Ported from `scripts/check-every-opcode-has-a-forgery-test.sh`. The
//! opcode set comes from the ISA enum; each opcode must appear in some
//! `rejects_*` test, and those tests must assert the proof is refused
//! (directly, through `prove_fails_after_tamper`, or at the VM).

use std::fmt::Write as _;
use std::path::Path;

fn strip_comments(text: &str) -> String {
    text.lines()
        .map(|l| {
            let idx = l.find("//").unwrap_or(l.len());
            l[..idx].to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Each forgery test must assert a failure (directly, via the helper, or
/// at the VM).
fn check_test_refusals(
    tests: &std::collections::HashMap<String, String>,
    problems: &mut Vec<String>,
) -> usize {
    let mut checked = 0usize;
    checked += 1;
    let helper = "prove_fails_after_tamper";
    for (name, body) in tests {
        let delegates = body.contains(helper);
        let asserts_failure = body.contains("is_err()")
            || body.contains("expect_err")
            || body.contains("unwrap_err")
            || body.contains("Err(VerifyError::");
        let rejects_at_vm =
            body.contains("assert_eq!(vm.registers") || body.contains("assert!(!receipt.success");
        if !delegates && !asserts_failure && !rejects_at_vm {
            problems.push(format!(
                "`{name}` builds a forgery and never asserts the proof is \
                 refused. A test that tampers and then expects success is \
                 coverage on paper."
            ));
        }
    }
    checked
}

/// The shared helper must still assert failure.
fn check_helper(
    prover_src: &str,
    tests: &std::collections::HashMap<String, String>,
    problems: &mut Vec<String>,
) -> usize {
    let mut checked = 0usize;
    checked += 1;
    let helper = "prove_fails_after_tamper";
    let helper_pos = prover_src.find(&format!("fn {helper}("));
    match helper_pos {
        None => {
            if tests.values().any(|b| b.contains(helper)) {
                problems.push(format!(
                    "tests delegate to `{helper}` and it does not exist."
                ));
            }
        }
        Some(pos) => {
            checked += 1;
            match body_after(prover_src, pos) {
                Some(hbody) if !hbody.contains("is_err()") => problems.push(format!(
                    "`{helper}` no longer asserts that verification fails. Every \
                     test delegating to it inherits that, so the whole forgery suite \
                     would pass against a proof system that accepts tampered traces."
                )),
                None => problems.push(format!("`{helper}` exists but its body cannot be read.")),
                _ => {}
            }
        }
    }
    checked
}

/// Every `rejects_*` test with its brace-matched body.
fn collect_rejects_tests(prover_src: &str) -> std::collections::HashMap<String, String> {
    let mut tests: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut rest = prover_src;
    while let Some(pos) = rest.find("fn rejects_") {
        let after = &rest[pos + "fn rejects_".len()..];
        let name_end = after
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(after.len());
        let name = format!("rejects_{}", &after[..name_end]);
        if let Some(body) = body_after(rest, pos + "fn rejects_".len() + name_end) {
            tests.insert(name, body);
        }
        rest = &after[name_end..];
    }
    tests
}

/// Brace-matched body beginning at the first `{` at or after `start`.
fn body_after(text: &str, start: usize) -> Option<String> {
    let open = text[start..].find('{')? + start;
    let mut depth = 1i32;
    let mut i = open + 1;
    let b = text.as_bytes();
    while i < b.len() {
        match b[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(text[open..=i].to_string());
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// # Errors
///
/// Returns the list of violated claims.
pub fn run(root: &Path) -> Result<String, String> {
    let isa_path = root.join("budzero/bud-isa/src/lib.rs");
    let prover_path = root.join("budzero/bud-proof/src/plonky3_prover.rs");
    if !isa_path.is_file() {
        return Err(format!(
            "expected source file missing: {}",
            isa_path.display()
        ));
    }
    if !prover_path.is_file() {
        return Err(format!(
            "expected source file missing: {}",
            prover_path.display()
        ));
    }
    let isa_src = strip_comments(&std::fs::read_to_string(&isa_path).map_err(|e| e.to_string())?);
    let prover_src = std::fs::read_to_string(&prover_path).map_err(|e| e.to_string())?;
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    // Enumerate opcodes from the ISA enum.
    checked += 1;
    let enum_start = isa_src.find("pub enum Opcode {");
    let Some(enum_start) = enum_start else {
        return Err(String::from("cannot find `Opcode` in the ISA to enumerate"));
    };
    let enum_body = &isa_src[enum_start..];
    let enum_end = enum_body.find("\n}").unwrap_or(enum_body.len());
    let mut opcodes: Vec<String> = Vec::new();
    for line in enum_body[..enum_end].lines() {
        let t = line.trim();
        if let Some(eq) = t.find('=') {
            let name = t[..eq].trim().to_string();
            if !name.is_empty() && name.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                opcodes.push(name);
            }
        }
    }
    if opcodes.len() < 10 {
        return Err(format!(
            "only {} opcodes parsed from the ISA, which is too few to be the \
             real set; the enum shape changed and this gate is reading it wrong",
            opcodes.len()
        ));
    }

    let tests = collect_rejects_tests(&prover_src);
    checked += 1;
    if tests.is_empty() {
        problems.push(
            "no `rejects_*` tests found at all. Every AIR constraint is then \
             unwatched: honest execution passing is not evidence, because a \
             deleted constraint also lets honest execution pass."
                .to_string(),
        );
    }

    // 1. Coverage: each opcode must appear in some test body.
    checked += 1;
    let uncovered: Vec<&String> = opcodes
        .iter()
        .filter(|op| {
            let a = format!("Opcode::{op},");
            let b = format!("Opcode::{op})");
            !tests
                .values()
                .any(|body| body.contains(&a) || body.contains(&b))
        })
        .collect();
    if !uncovered.is_empty() {
        problems.push(format!(
            "{} opcode(s) have no forgery test: {}. A constraint nobody has \
             watched fail is a constraint nobody has tested.",
            uncovered.len(),
            uncovered
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    checked += check_test_refusals(&tests, &mut problems);
    checked += check_helper(&prover_src, &tests, &mut problems);

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
        "opcode forgery gate OK: {checked} checks, {} opcodes, {} forgery tests, every opcode attacked",
        opcodes.len(),
        tests.len()
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
    let dir = std::env::temp_dir().join(format!("budlum-gates-eof-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(dir.join("budzero/bud-isa/src"));
    let _ = std::fs::create_dir_all(dir.join("budzero/bud-proof/src"));

    let mut isa = String::from("pub enum Opcode {\n");
    for i in 0..16 {
        writeln!(isa, "    OP{i:02X} = 0x{i:02X},").expect("writing to a String cannot fail");
    }
    isa.push_str("}\n");
    std::fs::write(dir.join("budzero/bud-isa/src/lib.rs"), isa).map_err(|e| e.to_string())?;
    let prover = "fn rejects_op00() {\n    let t = tamper(Opcode::OP00);\n    assert!(prove_fails_after_tamper(t));\n}\nfn rejects_op01() {\n    let r = verify(Opcode::OP01);\n    assert!(r.is_err());\n}\nfn prove_fails_after_tamper(t: Trace) -> bool {\n    verify(t).is_err()\n}\n";
    std::fs::write(dir.join("budzero/bud-proof/src/plonky3_prover.rs"), prover)
        .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        // 16 opcodes, only 2 covered -> must FAIL
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: kapsanmayan opcode'lar gecti"));
    }
    // Full coverage.
    let mut prover2 = String::new();
    for i in 0..16 {
        writeln!(
            prover2,
            "fn rejects_op{i:02X}() {{ \n    let t = tamper(Opcode::OP{i:02X});\n    assert!(prove_fails_after_tamper(t));\n}}"
        )
        .expect("writing to a String cannot fail");
    }
    prover2
        .push_str("fn prove_fails_after_tamper(t: Trace) -> bool {\n    verify(t).is_err()\n}\n");
    std::fs::write(dir.join("budzero/bud-proof/src/plonky3_prover.rs"), prover2)
        .map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: tam kapsama reddedildi"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "every-opcode kanaryasi OK (kapsama FAIL, tam kapsama PASS).",
    ))
}
