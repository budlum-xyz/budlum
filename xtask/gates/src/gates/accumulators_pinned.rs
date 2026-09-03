//! Forward accumulators must have their first row pinned.
//!
//! Ported from `scripts/check-accumulators-pin-their-first-row.sh`. A column
//! that accumulates across transitions and is read out against a public input
//! must be pinned on row zero (a `when_first_row` constraint that relates it
//! to a value the prover cannot choose), or the whole sequence slides.

use std::fmt::Write as _;
use std::path::Path;

const ACCUMULATORS: &[(&str, &str, &str)] = &[
    (
        "COL_EVENT_DIGEST_0",
        "the rs1 of every Log row",
        "an event digest for events the program never emitted, which is the replay context storage challenges are bound by",
    ),
    (
        "COL_MEM_INIT_ACC",
        "the committed initial memory image",
        "a starting memory image the host never provided",
    ),
    (
        "COL_REG_INIT_ACC",
        "the committed initial register file",
        "a starting register file the host never provided",
    ),
    (
        "COL_GAS_USED",
        "the running gas total",
        "a gas figure that does not match the work done",
    ),
];

/// `builder.<...>;` statements (gates and operands read together). The
/// `builder` keyword may be followed by whitespace before the dot, so a
/// statement split across lines (`builder\n    .when(...)`) is captured.
fn statements(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = code;
    while let Some(start) = rest.find("builder") {
        let after = &rest[start + "builder".len()..];
        // skip whitespace, then require a dot
        let dot = after.char_indices().find(|(_, c)| !c.is_whitespace());
        let Some((i, '.')) = dot else {
            rest = &after[1..];
            continue;
        };
        let stmt_start = start;
        let after_dot = &after[i + 1..];
        let Some(end_rel) = after_dot.find(';') else {
            break;
        };
        let end = stmt_start + "builder".len() + i + 1 + end_rel;
        out.push(rest[..end].to_string());
        rest = &rest[end + 1..];
    }
    out
}

/// Column plus every local the AIR reads it into. Line-based so only the
/// line where the `let` sits is inspected.
fn names_for(code: &str, column: &str) -> Vec<String> {
    let mut found = vec![column.to_string()];
    for line in code.lines() {
        let t = line.trim_start();
        let Some(rest) = t.strip_prefix("let ") else {
            continue;
        };
        let Some(eq) = rest.find('=') else {
            continue;
        };
        let local_name: String = rest[..eq]
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        if !local_name.is_empty() && rest[eq..].contains(&format!("cur[{column}]")) {
            found.push(local_name);
        }
    }
    found
}

fn mentions(stmt: &str, names: &[String]) -> bool {
    names.iter().any(|n| word_in(stmt, n))
}

fn word_in(text: &str, word: &str) -> bool {
    let mut rest = text;
    while let Some(pos) = rest.find(word) {
        let before_ok = pos == 0 || !rest.as_bytes()[pos - 1].is_ascii_alphanumeric();
        let after = &rest[pos + word.len()..];
        let after_ok = after.is_empty() || !after.as_bytes()[0].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        rest = &rest[pos + word.len()..];
    }
    false
}

/// Strip redundant outer parens: `(x)` -> `x`.
fn normalize_expr(text: &str) -> String {
    let mut t = text.trim().to_string();
    loop {
        let b = t.as_bytes();
        if b.is_empty() || b.len() < 2 {
            break;
        }
        let open = b[0];
        let close = b[b.len() - 1];
        let is_pair = (open == b'(' && close == b')')
            || (open == b'[' && close == b']')
            || (open == b'{' && close == b'}');
        if !is_pair {
            break;
        }
        // check balanced
        let mut depth = 0i32;
        let mut balanced = true;
        for (i, ch) in t.char_indices() {
            if ch == open as char {
                depth += 1;
            } else if ch == close as char {
                depth -= 1;
                if depth == 0 && i != t.len() - 1 {
                    balanced = false;
                    break;
                }
            }
        }
        if !balanced || depth != 0 {
            break;
        }
        t = t[1..t.len() - 1].trim().to_string();
    }
    t
}

/// Top-level args of a call: split on commas at depth 0.
fn split_top_level_args(text: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    let bytes = text.as_bytes();
    for (i, ch) in text.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                args.push(text[start..i].trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
        let _ = bytes;
    }
    let tail = text[start..].trim().to_string();
    if !tail.is_empty() {
        args.push(tail);
    }
    args
}

/// Is this a tautology? `assert_zero/eq(A, A)` or `assert_zero(A - A)`.
fn is_tautology(stmt: &str) -> bool {
    let Some(args_start) = stmt.find(".assert_") else {
        return false;
    };
    let after = &stmt[args_start..];
    let Some(open) = after.find('(') else {
        return false;
    };
    let inner = &after[open + 1..];
    let Some(close) = inner.rfind(')') else {
        return false;
    };
    let mut args = split_top_level_args(&inner[..close]);
    args = args.into_iter().map(|a| normalize_expr(&a)).collect();
    if args.len() >= 2 && args[0] == args[1] {
        return true;
    }
    if args.len() == 1 {
        // split on top-level minus
        let mut sides = Vec::new();
        let mut depth = 0i32;
        let mut cur = String::new();
        for ch in args[0].chars() {
            match ch {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth -= 1,
                '-' if depth == 0 => {
                    sides.push(cur.trim().to_string());
                    cur.clear();
                    continue;
                }
                _ => {}
            }
            cur.push(ch);
        }
        sides.push(cur.trim().to_string());
        let sides: Vec<String> = sides.into_iter().map(|s| normalize_expr(&s)).collect();
        if sides.len() == 2 && sides[0] == sides[1] {
            return true;
        }
    }
    false
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
    let code = src
        .lines()
        .map(|l| {
            let idx = l.find("//").unwrap_or(l.len());
            l[..idx].to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");
    let statements = statements(&code);
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for (column, accumulates, risk) in ACCUMULATORS {
        if !src.contains(column) {
            problems.push(format!(
                "{column} is gone from the AIR. If the accumulator was removed the \
                 entry here should go with it, in the same commit, with the reason."
            ));
            continue;
        }
        checked += 1;
        let names = names_for(&code, column);
        let in_transition = statements
            .iter()
            .any(|st| st.contains("when_transition") && mentions(st, &names));
        let first_row_stmts: Vec<String> = statements
            .iter()
            .filter(|st| st.contains("when_first_row") && mentions(st, &names))
            .cloned()
            .collect();
        let in_first_row = !first_row_stmts.is_empty();

        if in_first_row {
            let tautological: Vec<String> = first_row_stmts
                .iter()
                .filter(|st| is_tautology(st))
                .map(|st| st.trim().chars().take(80).collect())
                .collect();
            if !tautological.is_empty() {
                problems.push(format!(
                    "{column} is 'pinned' only by a tautological first-row constraint \
                     (same expression on both sides): {}. A pin must relate the \
                     accumulator to a value the prover cannot choose, not subtract \
                     it from itself.",
                    tautological.join("; ")
                ));
            }
        }

        if !in_transition {
            problems.push(format!(
                "{column} appears in no `when_transition` constraint, so this gate \
                 cannot confirm it is still an accumulator. If it stopped being \
                 one, remove it from the list in the same commit."
            ));
            continue;
        }
        if !in_first_row {
            problems.push(format!(
                "{column} accumulates {accumulates} across a transition but its \
                 first row is not pinned. A transition constrains differences \
                 between rows and never the starting point, so the whole sequence \
                 slides and a prover can claim {risk}."
            ));
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
        "accumulator gate OK: {checked} accumulators, every first row pinned"
    ))
}

/// # Errors
///
/// Returns a finding when a defect fixture passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-acc")?;
    let _ = std::fs::create_dir_all(dir.join("budzero/bud-proof/src"));

    let good = "pub const COL_EVENT_DIGEST_0: usize = 1;\npub const COL_MEM_INIT_ACC: usize = 2;\npub const COL_REG_INIT_ACC: usize = 3;\npub const COL_GAS_USED: usize = 4;\nlet cur_event_0: AB::Expr = cur[COL_EVENT_DIGEST_0].into();\nbuilder.when_transition().assert_eq(cur_event_0.clone(), nxt_event_0.clone() + log_rs1);\nbuilder.when_first_row().assert_zero(cur_event_0.clone() - zero.clone());\nlet mem_acc: AB::Expr = cur[COL_MEM_INIT_ACC].into();\nbuilder.when_transition().assert_eq(mem_acc.clone(), nxt_mem.clone());\nbuilder.when_first_row().assert_zero(mem_acc.clone() - zero.clone());\nlet reg_acc: AB::Expr = cur[COL_REG_INIT_ACC].into();\nbuilder.when_transition().assert_eq(reg_acc.clone(), nxt_reg.clone());\nbuilder.when_first_row().assert_zero(reg_acc.clone() - zero.clone());\nlet gas: AB::Expr = cur[COL_GAS_USED].into();\nbuilder.when_transition().assert_eq(gas.clone(), nxt_gas.clone() + cost);\nbuilder.when_first_row().assert_zero(gas.clone() - zero.clone());\n";
    std::fs::write(dir.join("budzero/bud-proof/src/plonky3_air.rs"), good)
        .map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: pinned accumulators were rejected"));
    }
    // Unpinned: remove the first-row constraint for gas.
    let bad = good.replace(
        "builder.when_first_row().assert_zero(gas.clone() - zero.clone());\n",
        "",
    );
    std::fs::write(dir.join("budzero/bud-proof/src/plonky3_air.rs"), bad)
        .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: an unpinned accumulator passed"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "accumulators canary OK: pinned PASSes and unpinned FAILs.",
    ))
}
