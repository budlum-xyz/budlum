//! Storage penalties must be enforced end to end.
//!
//! Ported from `scripts/check-storage-penalties-are-enforced.sh`. Nine
//! claims over `src/domain/storage_deal.rs` and `src/chain/blockchain.rs`:
//! the cooldown is a six-hour named constant, `begin_operator_cooldown` takes
//! the later deadline, `prune_expired_cooldowns` exists and is called, `root`
//! hashes both cooldowns and operator classes, `open_storage_deal_with_escrow`
//! enforces the cooldown, `open_deal` enforces the mobile-primary rule, and
//! nine regression tests exist.

use std::fmt::Write as _;
use std::path::Path;

fn strip_comments_and_literals(src: &str) -> String {
    let mut out = String::new();
    let mut i = 0;
    let b = src.as_bytes();
    while i < b.len() {
        if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'/' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if b[i] == b'"' || b[i] == b'\'' {
            let q = b[i] as char;
            // Mirror python's regex: if the closing quote is never found the
            // regex does not match and the text is left untouched. Our manual
            // scan must do the same, not swallow the rest of the file.
            let mut j = i + 1;
            let mut closed = false;
            while j < b.len() {
                // python's regex `'(?:\\\\.|[^'\\\\\\n]|\\\\\\n)*'` never
                // crosses a newline: an apostrophe in prose (e.g. Turkish
                // `'nin`) is not a char literal and must not swallow lines.
                if b[j] == b'\n' {
                    break;
                }
                if b[j] == b'\\' && j + 1 < b.len() {
                    j += 2;
                    continue;
                }
                if b[j] == b[i] {
                    closed = true;
                    break;
                }
                j += 1;
            }
            if closed {
                out.push_str(if b[i] == b'"' { "\"\"" } else { "''" });
                i = j + 1;
            } else {
                out.push(q);
                i += 1;
            }
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}

/// Checks 1-3: cooldown constant, `begin_operator_cooldown`, prune.
fn check_cooldown(deal_code: &str, chain_code: &str, problems: &mut Vec<String>) -> usize {
    let mut checked = 0usize;

    // 1. Cooldown is a six-hour named constant.
    checked += 1;
    let const_re = "pub const MISSED_CHALLENGE_COOLDOWN_SECS: u64 = ";
    let value = deal_code.find(const_re).and_then(|s| {
        let rest = &deal_code[s + const_re.len()..];
        let end = rest.find(';')?;
        eval_u64(&rest[..end])
    });
    match value {
        None => problems.push(
            "no `MISSED_CHALLENGE_COOLDOWN_SECS`. The cooldown must be a named \
             constant in seconds; an epoch is two governance parameters \
             multiplied together, so a punishment counted in epochs changes \
             length whenever either is tuned."
                .to_string(),
        ),
        Some(v) if v != 21_600 => problems.push(
            "`MISSED_CHALLENGE_COOLDOWN_SECS` is not six hours (21600 seconds). If \
             the policy changed, change this gate in the same commit so the number \
             stays deliberate."
                .to_string(),
        ),
        Some(_) => {}
    }

    // 2. begin_operator_cooldown takes the later deadline.
    checked += 1;
    let begin = body_of(deal_code, "pub fn begin_operator_cooldown(");
    match begin {
        None => {
            problems.push("no `begin_operator_cooldown`; nothing records the penalty.".to_string());
        }
        Some(b) if !b.contains(".max(") => problems.push(
            "`begin_operator_cooldown` does not take the later of the existing \
             deadline and the new one. A failure replayed with an older timestamp \
             would then shorten a running cooldown, so failing twice would cost \
             less than failing once."
                .to_string(),
        ),
        Some(_) => {}
    }

    // 3. prune_expired_cooldowns exists and is called.
    checked += 1;
    if deal_code.contains("fn prune_expired_cooldowns(") {
        checked += 1;
        if chain_code.contains("prune_expired_cooldowns") {
            checked += 1;
        } else {
            problems.push(
                "`prune_expired_cooldowns` exists and no production path calls it. \
                 A prune nothing runs bounds nothing; the map still grows with \
                 every failure and still reaches the state root."
                    .to_string(),
            );
        }
    } else {
        problems.push(
            "no `prune_expired_cooldowns`. The map is hashed into the state root, \
             so without a prune every node pays storage forever to remember a \
             six-hour punishment."
                .to_string(),
        );
    }

    checked
}

/// Checks 4-6: root hashes both maps, escrow enforces the cooldown,
/// `open_deal` enforces the mobile-primary rule.
fn check_root_escrow_deal(deal_code: &str, chain_code: &str, problems: &mut Vec<String>) -> usize {
    let mut checked = 0usize;
    // 4. root hashes both maps.
    checked += 1;
    let root_fn = body_of(deal_code, "pub fn root(");
    match root_fn {
        None => problems
            .push("cannot find `StorageRegistry::root` to check what it commits to.".to_string()),
        Some(r) => {
            for field in ["operator_cooldowns", "operator_classes"] {
                checked += 1;
                if !r.contains(field) {
                    problems.push(format!(
                        "`root()` does not hash `{field}`. It decides who may open a \
                         deal, so two nodes disagreeing about it would accept \
                         different blocks."
                    ));
                }
            }
        }
    }

    // 5. Escrow enforces the cooldown.
    checked += 1;
    let escrow = body_of(chain_code, "pub fn open_storage_deal_with_escrow(");
    match escrow {
        None => problems.push(
            "cannot find `open_storage_deal_with_escrow`. If it was renamed, \
             update this gate in the same commit so the enforcement stays watched."
                .to_string(),
        ),
        Some(e) if !e.contains("operator_cooldown_until") => problems.push(
            "`open_storage_deal_with_escrow` never calls \
             `operator_cooldown_until`. The cooldown would be recorded, hashed \
             into the state root, and never once stop anybody."
                .to_string(),
        ),
        Some(e) => {
            checked += 1;
            let args = e.find("operator_cooldown_until(").and_then(|s| {
                let rest = &e[s + "operator_cooldown_until(".len()..];
                let end = rest.find(')')?;
                Some(rest[..end].to_string())
            });
            match args {
                None => problems.push(
                    "`operator_cooldown_until` appears in \
                     `open_storage_deal_with_escrow` but not as a call this gate can \
                     read. Keep it a direct call so its arguments stay checkable."
                        .to_string(),
                ),
                Some(a) if !a.contains("operator") => problems.push(
                    "`open_storage_deal_with_escrow` asks about somebody other \
                     than the operator opening the deal. Every operator would \
                     then be subject to somebody else's cooldown."
                        .to_string(),
                ),
                Some(_) => {}
            }
        }
    }

    // 6. open_deal enforces the mobile-primary rule.
    checked += 1;
    let open_deal = body_of(deal_code, "pub fn open_deal(");
    match open_deal {
        None => problems.push("cannot find `StorageRegistry::open_deal`.".to_string()),
        Some(od) => {
            checked += 1;
            if !od.contains("may_hold_primary") {
                problems.push(
                    "`open_deal` does not call `may_hold_primary`. A phone could then \
                     take `replica_index = 0`, which is the copy a reader reaches \
                     first and a repair rebuilds from."
                        .to_string(),
                );
            }
            checked += 1;
            if !od.contains("replica_index == 0") {
                problems.push(
                    "`open_deal` does not single out `replica_index == 0`. The rule is \
                     about the primary specifically: a mobile operator may hold a \
                     second or third copy, and a check that refuses every replica is a \
                     ban on mobile storage rather than the rule."
                        .to_string(),
                );
            }
        }
    }

    checked
}

/// Brace-balanced body of the first function matching `header` in `code`.
fn body_of(code: &str, header: &str) -> Option<String> {
    let start = code.find(header)?;
    let rest = &code[start..];
    // Find the `{` after the header.
    let open = rest.find('{')? + start + 1;
    let mut depth = 1i32;
    let mut i = open;
    let b = code.as_bytes();
    while i < b.len() {
        match b[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(code[open..i].to_string());
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn has_test(deal_src: &str, name: &str) -> bool {
    deal_src.contains(&format!("fn {name}("))
}

/// Evaluate a plain u64 constant expression like `6 * 60 * 60`.
fn eval_u64(expr: &str) -> Option<u64> {
    let mut acc: Option<u64> = None;
    for part in expr.split('*') {
        let p = part.trim();
        let Ok(v) = p.parse::<u64>() else {
            return None;
        };
        acc = Some(acc.map_or(v, |a| a.saturating_mul(v)));
    }
    acc
}

/// # Errors
///
/// Returns the list of violated claims.
pub fn run(root: &Path) -> Result<String, String> {
    let deal = root.join("src/domain/storage_deal.rs");
    let chain = root.join("src/chain/blockchain.rs");
    if !deal.is_file() {
        return Err(format!("expected source file missing: {}", deal.display()));
    }
    if !chain.is_file() {
        return Err(format!("expected source file missing: {}", chain.display()));
    }
    let deal_src = std::fs::read_to_string(&deal).map_err(|e| e.to_string())?;
    let chain_src = std::fs::read_to_string(&chain).map_err(|e| e.to_string())?;
    let deal_code = strip_comments_and_literals(&deal_src);
    let chain_code = strip_comments_and_literals(&chain_src);
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    checked += check_cooldown(deal_code.as_str(), chain_code.as_str(), &mut problems);
    checked += check_root_escrow_deal(deal_code.as_str(), chain_code.as_str(), &mut problems);
    // 7. Regression tests.
    checked += 1;
    for test in [
        "a_missed_challenge_locks_the_operator_out_for_six_hours",
        "the_cooldown_lifts_when_it_expires",
        "a_second_failure_never_shortens_a_running_cooldown",
        "expired_cooldowns_are_pruned",
        "a_cooldown_changes_the_registry_root",
        "a_mobile_operator_cannot_take_the_primary_replica",
        "a_mobile_operator_may_take_a_secondary_replica",
        "an_undeclared_operator_defaults_to_always_on",
        "a_declared_class_changes_the_registry_root",
    ] {
        if !has_test(&deal_src, test) {
            problems.push(format!(
                "required regression test `{test}` is missing or is not a `#[test]`."
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
        "storage penalties gate OK: {checked} checks, penalties are enforced"
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
    let dir = std::env::temp_dir().join(format!("budlum-gates-pen-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(dir.join("src/domain"));
    let _ = std::fs::create_dir_all(dir.join("src/chain"));

    let mut deal = String::from(
        "pub const MISSED_CHALLENGE_COOLDOWN_SECS: u64 = 6 * 60 * 60;\nimpl StorageRegistry {\n    pub fn begin_operator_cooldown(&mut self, o: Address, now: u64) -> u64 {\n        let until = now + MISSED_CHALLENGE_COOLDOWN_SECS;\n        let e = self.operator_cooldowns.entry(o).or_insert(until);\n        *e = (*e).max(until);\n        *e\n    }\n    pub fn prune_expired_cooldowns(&mut self, now: u64) -> usize { 0 }\n    pub fn root(&self) -> [u8; 32] {\n        for (o, u) in &self.operator_cooldowns { hash(o, u); }\n        for (o, c) in &self.operator_classes { hash(o, c); }\n        [0u8; 32]\n    }\n    pub fn open_deal(&mut self) -> Result<u64, StorageError> {\n        if replica_index == 0 && !self.operator_class(&operator).may_hold_primary() {\n            return Err(StorageError::MobileOperatorCannotHoldPrimary(operator));\n        }\n        Ok(0)\n    }\n}\n",
    );
    for t in [
        "a_missed_challenge_locks_the_operator_out_for_six_hours",
        "the_cooldown_lifts_when_it_expires",
        "a_second_failure_never_shortens_a_running_cooldown",
        "expired_cooldowns_are_pruned",
        "a_cooldown_changes_the_registry_root",
        "a_mobile_operator_cannot_take_the_primary_replica",
        "a_mobile_operator_may_take_a_secondary_replica",
        "an_undeclared_operator_defaults_to_always_on",
        "a_declared_class_changes_the_registry_root",
    ] {
        writeln!(deal, "#[test]\nfn {t}() {{}}").expect("writing to a String cannot fail");
    }
    std::fs::write(dir.join("src/domain/storage_deal.rs"), &deal).map_err(|e| e.to_string())?;
    let chain = "fn f() {\n    self.state.storage_registry.prune_expired_cooldowns(now_unix);\n    let _ = self.state.storage_registry.operator_cooldown_until(&operator, now_unix);\n}\npub fn open_storage_deal_with_escrow() {\n    let _ = self.state.storage_registry.operator_cooldown_until(&operator, now_unix);\n}\n";
    std::fs::write(dir.join("src/chain/blockchain.rs"), chain).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a correct tree was refused"));
    }

    // Bad: cooldown wrong length.
    let bad = deal.replace("6 * 60 * 60", "60");
    std::fs::write(dir.join("src/domain/storage_deal.rs"), bad).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a wrong cooldown passed"));
    }

    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "storage-penalties canary OK (correct PASSes, a wrong cooldown FAILs).",
    ))
}
