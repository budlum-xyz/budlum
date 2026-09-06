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

/// Whether a normalized `slash_penalty` body clamps its result to the bond.
/// Two halves, both required.
///
/// The wide half: the body compares the `u128` quotient against `u64::MAX`
/// and the block that comparison opens yields `stake` in a form whose value
/// is kept. Two forms are the operation: an early `return stake;` inside
/// that block, or a `{ stake } else { .. }` whose else block closes the
/// function body, so the conditional is the tail expression. A `{ stake }`
/// block followed by anything else (`if r > MAX { stake }; r as u64`) is a
/// discarded value with the truncating cast still live.
///
/// The narrow half: what runs when the quotient fits a `u64` caps the cast
/// value to `stake` as well (see [`caps_narrow_to_stake`]). A ratio above
/// `FIXED_POINT_SCALE` can leave the quotient between the stake and
/// `u64::MAX`, where the wide guard does not fire and the bare cast returns
/// more than the bond. The gate used to accept `return stake;` alone and
/// never read past it.
fn clamps_to_stake(normalized_body: &str) -> bool {
    const COMPARE: &str = ">u128::from(u64::MAX){";
    let Some(at) = normalized_body.find(COMPARE) else {
        return false;
    };
    let after = &normalized_body[at + COMPARE.len()..];
    if let Some(narrow) = after
        .strip_prefix("returnstake;}")
        .or_else(|| after.strip_prefix("returnstake}"))
    {
        return caps_narrow_to_stake(narrow);
    }
    let Some(rest) = after.strip_prefix("stake}else{") else {
        return false;
    };
    let mut depth = 1usize;
    for (i, b) in rest.bytes().enumerate() {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return rest[i + 1..].is_empty() && caps_narrow_to_stake(&rest[..i]);
                }
            }
            _ => {}
        }
    }
    false
}

/// Whether the narrow side of a normalized body keeps the `as u64` value
/// only up to `stake`. The cap has to be on the value the narrow side
/// returns: its tail expression (or `return` operand) is `.min(stake)` on
/// the narrowed value, `stake.min(..)`, `min(.., stake)` or `min(stake, ..)`
/// of it, or an `if` that compares against `stake` and yields `stake` in one
/// branch and the narrowed value in the other. The narrowed value is an
/// `as u64` cast written in place or a `let` binding of one, and a binding
/// of a capped expression is followed to the expression. A cap written in an
/// earlier statement and thrown away (`let _ = 0u64.min(stake); r as u64`)
/// caps nothing that is returned, and is refused; the gate used to accept
/// `.min(stake)` anywhere in the text. A narrow side without an `as u64` is
/// not the operation this gate guards and is refused too.
fn caps_narrow_to_stake(narrow: &str) -> bool {
    if !narrow.contains("asu64") {
        return false;
    }
    let statements = top_level_statements(narrow);
    let Some(&tail) = statements.last() else {
        return false;
    };
    let bindings: Vec<(&str, &str)> = statements.iter().copied().filter_map(binding_of).collect();
    let tail = resolve(tail.strip_prefix("return").unwrap_or(tail), &bindings);
    let narrowed = |v: &str| resolve(v, &bindings).contains("asu64");
    if let Some(receiver) = tail.strip_suffix(".min(stake)") {
        return narrowed(receiver);
    }
    if let Some(arg) = tail
        .strip_prefix("stake.min(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        return narrowed(arg);
    }
    if let Some((a, b)) = min_call_args(tail) {
        return (a == "stake" && narrowed(b)) || (b == "stake" && narrowed(a));
    }
    let Some((cond, yes, no)) = if_else_parts(tail) else {
        return false;
    };
    let compares = cond.contains("stake") && cond.contains(['<', '>']);
    compares && ((yes == "stake" && narrowed(no)) || (no == "stake" && narrowed(yes)))
}

/// The statements of a normalized fragment, split at the `;` that sit
/// outside every bracket; a trailing expression is the last entry.
fn top_level_statements(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (i, b) in text.bytes().enumerate() {
        match b {
            b'{' | b'(' | b'[' => depth += 1,
            b'}' | b')' | b']' => depth = depth.saturating_sub(1),
            b';' if depth == 0 => {
                if i > start {
                    out.push(&text[start..i]);
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

/// `let [mut] name[: T] = expr` as `(name, expr)`; anything else is `None`.
fn binding_of(statement: &str) -> Option<(&str, &str)> {
    let rest = statement.strip_prefix("let")?;
    let rest = rest.strip_prefix("mut").unwrap_or(rest);
    let name_end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    let name = &rest[..name_end];
    let eq = rest[name_end..].find('=')?;
    Some((name, &rest[name_end + eq + 1..]))
}

/// A bare identifier is followed to what it was bound to, a few hops at
/// most; anything that is not a bound identifier is returned as written,
/// less a pair of parentheses around the whole of it.
fn resolve<'a>(value: &'a str, bindings: &[(&'a str, &'a str)]) -> &'a str {
    let mut current = without_outer_parens(value);
    for _ in 0..4 {
        let Some((_, expr)) = bindings.iter().find(|(name, _)| *name == current) else {
            break;
        };
        current = without_outer_parens(expr);
    }
    current
}

/// `(expr)` as `expr`, only when the opening parenthesis is closed by the
/// last character; `(a).min(b)` is left alone.
fn without_outer_parens(value: &str) -> &str {
    let mut current = value;
    while let Some(inner) = current.strip_prefix('(').and_then(|r| r.strip_suffix(')')) {
        let mut depth = 0usize;
        let mut closes_early = false;
        for b in inner.bytes() {
            match b {
                b'(' => depth += 1,
                b')' if depth == 0 => {
                    closes_early = true;
                    break;
                }
                b')' => depth -= 1,
                _ => {}
            }
        }
        if closes_early {
            break;
        }
        current = inner;
    }
    current
}

/// The two arguments of a `min(a, b)` call that is the whole expression,
/// with or without a path in front of it (`u64::min`, `std::cmp::min`).
fn min_call_args(expr: &str) -> Option<(&str, &str)> {
    let at = expr.find("min(")?;
    let head = &expr[..at];
    if !(head.is_empty() || head.ends_with("::")) {
        return None;
    }
    let inner = expr[at + 4..].strip_suffix(')')?;
    let mut depth = 0usize;
    for (i, b) in inner.bytes().enumerate() {
        match b {
            b'{' | b'(' | b'[' => depth += 1,
            b'}' | b')' | b']' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => return Some((&inner[..i], &inner[i + 1..])),
            _ => {}
        }
    }
    None
}

/// `if cond { yes } else { no }` that is the whole expression, as its three
/// parts; `None` for any other shape.
fn if_else_parts(expr: &str) -> Option<(&str, &str, &str)> {
    let body = expr.strip_prefix("if")?;
    let open = body.find('{')?;
    let cond = &body[..open];
    let yes_end = open + matching_brace(&body[open..])?;
    let yes = &body[open + 1..yes_end];
    let after = body[yes_end + 1..].strip_prefix("else{")?;
    let no_end = matching_brace(&body[yes_end + 1 + 4..])?;
    let no = &after[..no_end - 1];
    if !after[no_end..].is_empty() {
        return None;
    }
    Some((cond, yes, no))
}

/// The offset of the `}` that closes the `{` at the start of `text`.
fn matching_brace(text: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (i, b) in text.bytes().enumerate() {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
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
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-slash")?;
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
    // A clamp written with an early return, the same clamp written as a
    // tail expression, and the in-tree shape that caps the narrow value with
    // an `if`: all three are the operation, and all three must pass.
    let body = "pub fn slash_penalty(stake: u64, ratio: u64) -> u64 {\n    let r = u128::from(stake) * u128::from(ratio) / FIXED_POINT_SCALE;\n    if r > u128::from(u64::MAX) {\n        return stake;\n    }\n    (r as u64).min(stake)\n}\n";
    let tail = "pub fn slash_penalty(stake: u64, ratio: u64) -> u64 {\n    let r = u128::from(stake) * u128::from(ratio) / FIXED_POINT_SCALE;\n    if r > u128::from(u64::MAX) {\n        stake\n    } else {\n        (r as u64).min(stake)\n    }\n}\n";
    let branch = "pub fn slash_penalty(stake: u64, ratio: u64) -> u64 {\n    let r = u128::from(stake) * u128::from(ratio) / FIXED_POINT_SCALE;\n    if r > u128::from(u64::MAX) {\n        return stake;\n    }\n    let narrow = r as u64;\n    if narrow > stake {\n        stake\n    } else {\n        narrow\n    }\n}\n";
    let bound = "pub fn slash_penalty(stake: u64, ratio: u64) -> u64 {\n    let r = u128::from(stake) * u128::from(ratio) / FIXED_POINT_SCALE;\n    if r > u128::from(u64::MAX) {\n        return stake;\n    }\n    let capped = u64::min(r as u64, stake);\n    capped\n}\n";
    for (tag, clamp) in [
        ("early return", body),
        ("tail expression", tail),
        ("if/else cap", branch),
        ("cap bound to a name", bound),
    ] {
        std::fs::write(dir.join("src/core/chain_config.rs"), clamp).unwrap();
        std::fs::write(dir.join("budzero/verifier-registry/src/params.rs"), clamp).unwrap();
        if let Err(e) = run(&dir) {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(format!(
                "canary: a clean tree ({tag} clamp) was refused: {e}"
            ));
        }
    }
    // Both homes agree, and neither clamps: identical copies of the bug. The
    // second fixture names `stake` in the block the comparison opens, then
    // throws that value away and keeps the truncating cast. The third and
    // fourth guard the overflow and return the bare cast on the other side,
    // which pays out more than the bond for any ratio above the scale.
    let unclamped = "pub fn slash_penalty(stake: u64, ratio: u64) -> u64 {\n    let r = u128::from(stake) * u128::from(ratio) / FIXED_POINT_SCALE;\n    if r > u128::from(u64::MAX) {\n        return 0;\n    }\n    r as u64\n}\n";
    let discarded = "pub fn slash_penalty(stake: u64, ratio: u64) -> u64 {\n    let r = u128::from(stake) * u128::from(ratio) / FIXED_POINT_SCALE;\n    if r > u128::from(u64::MAX) {\n        stake\n    };\n    r as u64\n}\n";
    let uncapped_return = "pub fn slash_penalty(stake: u64, ratio: u64) -> u64 {\n    let r = u128::from(stake) * u128::from(ratio) / FIXED_POINT_SCALE;\n    if r > u128::from(u64::MAX) {\n        return stake;\n    }\n    r as u64\n}\n";
    let uncapped_tail = "pub fn slash_penalty(stake: u64, ratio: u64) -> u64 {\n    let r = u128::from(stake) * u128::from(ratio) / FIXED_POINT_SCALE;\n    if r > u128::from(u64::MAX) {\n        stake\n    } else {\n        r as u64\n    }\n}\n";
    let discarded_cap = "pub fn slash_penalty(stake: u64, ratio: u64) -> u64 {\n    let r = u128::from(stake) * u128::from(ratio) / FIXED_POINT_SCALE;\n    if r > u128::from(u64::MAX) {\n        return stake;\n    }\n    let _ = 0u64.min(stake);\n    r as u64\n}\n";
    let capped_other = "pub fn slash_penalty(stake: u64, ratio: u64) -> u64 {\n    let r = u128::from(stake) * u128::from(ratio) / FIXED_POINT_SCALE;\n    if r > u128::from(u64::MAX) {\n        return stake;\n    }\n    let narrow = r as u64;\n    let _ = narrow.min(stake);\n    narrow\n}\n";
    for (tag, bug) in [
        ("never yield the stake", unclamped),
        ("discard the stake", discarded),
        ("return the bare cast after the guard", uncapped_return),
        ("return the bare cast in the else block", uncapped_tail),
        (
            "cap an unrelated value and return the bare cast",
            discarded_cap,
        ),
        (
            "cap the narrowed value in a statement and return it uncapped",
            capped_other,
        ),
    ] {
        std::fs::write(dir.join("src/core/chain_config.rs"), bug).unwrap();
        std::fs::write(dir.join("budzero/verifier-registry/src/params.rs"), bug).unwrap();
        if run(&dir).is_ok() {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(format!("canary: two agreeing homes that {tag} passed"));
        }
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
        "slash canary OK (an early-return clamp, a tail-expression clamp, an if/else \
         cap and a cap bound to a name PASS, two agreeing unclamped homes FAIL, a \
         discarded `{ stake }` block FAILs, a bare cast after the guard FAILs on both \
         shapes, a cap on a value that is not returned FAILs, a diverging home FAILs).",
    ))
}
