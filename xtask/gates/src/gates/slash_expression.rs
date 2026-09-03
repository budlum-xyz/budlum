//! The slash expression has exactly one home (two files, kept identical).
//!
//! Ported from `scripts/check-slash-expression-has-one-home.sh`. The
//! stake-to-u64 slash arithmetic (`stake/bond ... u128 ... * ... u128 ...
//! / FIXED_POINT_SCALE ... as u64`) may only appear inside the two canonical
//! `slash_penalty` bodies, and those two bodies must be identical and still
//! clamp.

use std::path::Path;

const HOMES: &[&str] = &[
    "src/core/chain_config.rs",
    "budzero/verifier-registry/src/params.rs",
];

/// Does this line look like the slash expression: stake/bond-ish u128
/// multiply-divide by `FIXED_POINT_SCALE` with `as u64`?
fn is_slash_expr(line: &str) -> bool {
    let t = line.to_lowercase();
    let has_stake = t.contains("stake") || t.contains("bond");
    let has_u128 = t.contains("u128");
    let has_scale = t.contains("fixed_point_scale");
    let has_as_u64 = t.contains("as u64") || t.contains("as u64");
    let has_mul_div = (t.contains('*') || t.contains("mul")) && t.contains('/');
    has_stake && has_u128 && has_scale && has_as_u64 && has_mul_div
}

fn code_of(root: &Path, rel: &str) -> Result<String, String> {
    let f = root.join(rel);
    if !f.is_file() {
        return Err(format!("expected file missing: {}", f.display()));
    }
    std::fs::read_to_string(&f).map_err(|e| e.to_string())
}

fn is_comment_line(l: &str) -> bool {
    let t = l.trim_start();
    t.starts_with("//") || t.starts_with("///") || t.starts_with("//!") || t.starts_with('*')
}

/// Extract the brace-balanced body of `pub fn slash_penalty`.
fn slash_body(code: &str) -> Option<String> {
    let start = code.find("pub fn slash_penalty")?;
    let rest = &code[start..];
    let open = rest.find('{')? + start + 1;
    let mut depth = 1i32;
    let mut i = open;
    while i < code.len() {
        match code.as_bytes()[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
        i += 1;
    }
    Some(code[open..i].to_string())
}

/// Normalized body: comments stripped, whitespace collapsed.
/// Whether a normalized `slash_penalty` body clamps its result to the bond:
/// it compares the wide quotient against `u64::MAX` and, on the wide side,
/// yields `stake`. The yield is matched as an operation in any of the forms
/// Rust writes it: an early `return stake`, a block whose tail is `stake`,
/// or a `.min(stake)`. Matching the `return` keyword alone accepted exactly
/// one of those spellings and refused a correct clamp written as a tail
/// expression, while a body that returned `stake` for some other reason and
/// never compared anything would have passed.
fn clamps_to_stake(normalized_body: &str) -> bool {
    let compares_wide = normalized_body.contains(">u128::from(u64::MAX)");
    let yields_stake = normalized_body.contains("returnstake")
        || normalized_body.contains("{stake}")
        || normalized_body.contains(".min(stake)")
        || normalized_body.contains("stake.min(");
    compares_wide && yields_stake
}

fn normalized(body: &str) -> String {
    body.lines()
        .map(|l| l.split("//").next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("")
}

/// # Errors
///
/// Returns a finding when the expression appears outside the homes, the homes
/// drift, or the clamp is gone.
pub fn run(root: &Path) -> Result<String, String> {
    // Part 1: no inline copies outside the homes.
    let mut scanned = 0usize;
    let mut homes_seen = 0usize;
    let mut offenders: Vec<String> = Vec::new();
    // Only the crate source roots are scanned, matching the shell gate's
    // os.walk over the repo minus skip-dirs: the gate's own source under
    // xtask/ must not be treated as an inline copy.
    let mut stack: Vec<std::path::PathBuf> = ["src", "budzero", "wallet-core"]
        .iter()
        .map(|s| root.join(s))
        .collect();
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.filter_map(Result::ok) {
            let Ok(path_kind) = e.file_type() else {
                continue;
            };
            let path = e.path();
            if path_kind.is_dir() {
                let name = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                if !matches!(name.as_str(), ".git" | "target" | "node_modules" | ".cargo") {
                    stack.push(path);
                }
            } else if path.extension().is_some_and(|x| x == "rs") {
                scanned += 1;
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                if HOMES.contains(&rel.as_str()) {
                    homes_seen += 1;
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                for (i, line) in text.lines().enumerate() {
                    if is_slash_expr(line) && !is_comment_line(line) {
                        offenders.push(format!(
                            "  {rel}:{}: {}",
                            i + 1,
                            line.trim().chars().take(96).collect::<String>()
                        ));
                    }
                }
            }
        }
    }
    if scanned < 50 {
        return Err(format!(
            "only {scanned} .rs files scanned under {}; gate would be vacuous",
            root.display()
        ));
    }
    if !offenders.is_empty() {
        let mut msg = format!(
            "the slash expression is written out at {} place(s) outside its two homes:\n",
            offenders.len()
        );
        for o in &offenders {
            msg.push_str(o);
            msg.push('\n');
        }
        msg.push_str(
            "\n  Call `slash_penalty` instead. It clamps to the bond, which the\n  \
             bare expression does not: a ratio above FIXED_POINT_SCALE makes\n  \
             the quotient exceed u64 and `as u64` wraps it to a fraction of\n  \
             the stake. See B35.",
        );
        return Err(msg);
    }

    // Part 2: the two homes agree and both clamp.
    let mut bodies: Vec<String> = Vec::new();
    for rel in HOMES {
        let code = code_of(root, rel)?;
        let body =
            slash_body(&code).ok_or_else(|| format!("no `pub fn slash_penalty` in {rel}"))?;
        bodies.push(normalized(&body));
    }
    if bodies[0] != bodies[1] {
        return Err(format!(
            "FAIL: the two slash_penalty bodies have drifted apart.\n  {}:\n    {}\n  {}:\n    {}",
            HOMES[0],
            bodies[0].chars().take(200).collect::<String>(),
            HOMES[1],
            bodies[1].chars().take(200).collect::<String>()
        ));
    }
    if !clamps_to_stake(&bodies[0]) {
        return Err(String::from(
            "FAIL: slash_penalty no longer clamps; the identity check would be \
             comparing two copies of the bug.",
        ));
    }

    Ok(format!(
        "Slash expression OK: {scanned} .rs files scanned, {homes_seen} canonical home(s) found, no inline copies.\nBoth slash_penalty bodies agree and both still clamp."
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
    let dir =
        std::env::temp_dir().join(format!("budlum-gates-slash-{}-{nanos}", std::process::id()));
    // Build 60 files to clear the vacuity floor, under the scanned roots
    // (src/budzero/wallet-core): the shell gate walked the whole tree, but
    // this port scans only those roots, so a fixture at the top level would
    // trip the vacuity floor.
    let _ = std::fs::create_dir_all(dir.join("src"));
    for i in 0..60 {
        let sub = dir.join(format!("src/m{i}"));
        let _ = std::fs::create_dir_all(&sub);
        std::fs::write(sub.join("a.rs"), "fn f() {}\n").unwrap();
    }
    let _ = std::fs::create_dir_all(dir.join("src/core"));
    let _ = std::fs::create_dir_all(dir.join("budzero/verifier-registry/src"));
    // A clamp written with an early return, and the same clamp written as a
    // tail expression: both are the operation, and both must pass.
    let body = "pub fn slash_penalty(stake: u64, ratio: u64) -> u64 {\n    let r = u128::from(stake) * u128::from(ratio) / FIXED_POINT_SCALE;\n    if r > u128::from(u64::MAX) {\n        return stake;\n    }\n    (r as u64).min(stake)\n}\n";
    let tail = "pub fn slash_penalty(stake: u64, ratio: u64) -> u64 {\n    let r = u128::from(stake) * u128::from(ratio) / FIXED_POINT_SCALE;\n    if r > u128::from(u64::MAX) {\n        stake\n    } else {\n        (r as u64).min(stake)\n    }\n}\n";
    for (tag, clamp) in [("early return", body), ("tail expression", tail)] {
        std::fs::write(dir.join("src/core/chain_config.rs"), clamp).unwrap();
        std::fs::write(dir.join("budzero/verifier-registry/src/params.rs"), clamp).unwrap();
        if let Err(e) = run(&dir) {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(format!(
                "canary: a clean tree ({tag} clamp) was refused: {e}"
            ));
        }
    }
    // Both homes agree, and neither clamps: identical copies of the bug.
    let unclamped = "pub fn slash_penalty(stake: u64, ratio: u64) -> u64 {\n    let r = u128::from(stake) * u128::from(ratio) / FIXED_POINT_SCALE;\n    if r > u128::from(u64::MAX) {\n        return 0;\n    }\n    r as u64\n}\n";
    std::fs::write(dir.join("src/core/chain_config.rs"), unclamped).unwrap();
    std::fs::write(
        dir.join("budzero/verifier-registry/src/params.rs"),
        unclamped,
    )
    .unwrap();
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: two agreeing homes that never yield the stake passed",
        ));
    }
    std::fs::write(dir.join("src/core/chain_config.rs"), body).unwrap();
    std::fs::write(dir.join("budzero/verifier-registry/src/params.rs"), body).unwrap();
    // Drift one home.
    let drifted = body.replace("u64::MAX", "u64::MIN");
    std::fs::write(dir.join("budzero/verifier-registry/src/params.rs"), drifted).unwrap();
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a diverging slash_penalty passed"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "slash canary OK (an early-return clamp and a tail-expression clamp PASS, two \
         agreeing unclamped homes FAIL, a diverging home FAILs).",
    ))
}
