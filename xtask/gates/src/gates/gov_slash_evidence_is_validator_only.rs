//! Governance slash evidence gate (Round 4 finding).
//!
//! Bir HIGH bulgusu giderildi (Strix CWE-345):
//! `SlashValidator` used to accept a slashing record from ANY role as
//! evidence. The fix requires `record.report.role == VALIDATOR` and digests
//! the full report.
//!
//! Strix CWE-697 follow-ups: substring checks anywhere in the file can be
//! satisfied by bait snippets (comments, strings, raw strings, earlier
//! decoy arms) outside the live `SlashValidator` path. This gate strips
//! comments and literals, anchors to the live `fn execute_proposal` ->
//! `match &proposal.p_type` path, and validates the arm found there.

use std::path::Path;

fn account_path(root: &Path) -> std::path::PathBuf {
    root.join("src/core/account.rs")
}

fn collect(root: &Path) -> Result<String, String> {
    let p = account_path(root);
    std::fs::read_to_string(&p).map_err(|e| format!("cannot read {}: {e}", p.display()))
}

/// Strip Rust comments, ordinary strings and raw strings (preserving line
/// structure) so dead text cannot satisfy the gate (Strix CWE-697).
fn strip_rust_noise(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut pos = 0usize;
    while pos < bytes.len() {
        if bytes[pos..].starts_with(b"//") {
            while pos < bytes.len() && bytes[pos] != b'\n' {
                out.push(' ');
                pos += 1;
            }
            continue;
        }
        if bytes[pos..].starts_with(b"/*") {
            // Rust block comments nest (`/* outer /* inner */ tail */`); a
            // flat scan stops at the first `*/` and leaves the tail looking
            // like live code. Track depth instead (Strix CWE-697).
            out.push(' ');
            out.push(' ');
            pos += 2;
            let mut depth = 1usize;
            while pos < bytes.len() && depth > 0 {
                if bytes[pos..].starts_with(b"/*") {
                    depth += 1;
                    out.push(' ');
                    out.push(' ');
                    pos += 2;
                    continue;
                }
                if bytes[pos..].starts_with(b"*/") {
                    depth -= 1;
                    out.push(' ');
                    out.push(' ');
                    pos += 2;
                    continue;
                }
                out.push(if bytes[pos] == b'\n' { '\n' } else { ' ' });
                pos += 1;
            }
            continue;
        }
        if bytes[pos] == b'r' || bytes[pos] == b'b' {
            let mut scan = pos;
            if bytes[scan] == b'b' {
                scan += 1;
            }
            if scan < bytes.len() && bytes[scan] == b'r' {
                scan += 1;
                let mut hash_count = 0usize;
                while scan < bytes.len() && bytes[scan] == b'#' {
                    hash_count += 1;
                    scan += 1;
                }
                if scan < bytes.len() && bytes[scan] == b'"' {
                    let mut end = scan + 1;
                    while end < bytes.len() {
                        if bytes[end] == b'"' {
                            let mut hashes = 0usize;
                            let mut cursor = end + 1;
                            while cursor < bytes.len()
                                && bytes[cursor] == b'#'
                                && hashes < hash_count
                            {
                                hashes += 1;
                                cursor += 1;
                            }
                            if hashes == hash_count {
                                break;
                            }
                        }
                        end += 1;
                    }
                    let mut blank_to = if end < bytes.len() {
                        end + 1 + hash_count
                    } else {
                        bytes.len()
                    };
                    if blank_to > bytes.len() {
                        blank_to = bytes.len();
                    }
                    while pos < blank_to {
                        out.push(if bytes[pos] == b'\n' { '\n' } else { ' ' });
                        pos += 1;
                    }
                    continue;
                }
            }
        }
        if bytes[pos] == b'"' {
            out.push(' ');
            pos += 1;
            while pos < bytes.len() && bytes[pos] != b'"' {
                if bytes[pos] == b'\\' && pos + 1 < bytes.len() {
                    pos += 2;
                    continue;
                }
                out.push(if bytes[pos] == b'\n' { '\n' } else { ' ' });
                pos += 1;
            }
            if pos < bytes.len() {
                out.push(' ');
                pos += 1;
            }
            continue;
        }
        out.push(bytes[pos] as char);
        pos += 1;
    }
    out
}

/// Extract the live `SlashValidator` arm body from the noise-stripped view:
/// `fn execute_proposal` -> `match &proposal.p_type` -> arm `=> { .. }`.
fn slash_validator_block(src: &str) -> Option<String> {
    let clean = strip_rust_noise(src);
    let exec_start = clean.find("fn execute_proposal")?;
    let exec_src = &clean[exec_start..];
    let match_start = exec_src.find("match &proposal.p_type")?;
    let match_src = &exec_src[match_start..];
    let start = match_src.find("ProposalType::SlashValidator {")?;
    let rest = &match_src[start..];
    let open = rest.find('{')?;
    let mut depth = 0i32;
    let mut variant_end = None;
    for (offset, ch) in rest[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    variant_end = Some(open + offset + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    let variant_end = variant_end?;
    let after = &rest[variant_end..];
    let arrow = after.find("=>")?;
    let body_open = after[arrow..].find('{')? + arrow;
    let mut body_depth = 0i32;
    for (offset, ch) in after[body_open..].char_indices() {
        match ch {
            '{' => body_depth += 1,
            '}' => {
                body_depth -= 1;
                if body_depth == 0 {
                    return Some(after[..=body_open + offset].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

fn judge(src: &str) -> Vec<String> {
    let mut problems = Vec::new();

    let Some(block) = slash_validator_block(src) else {
        problems.push(String::from(
            "account.rs no longer contains the live SlashValidator branch; the governance slash protection is missing.",
        ));
        return problems;
    };

    if !block.contains("record.report.role != crate::registry::role::roles::VALIDATOR") {
        problems.push(String::from(
            "account.rs no longer requires the slashing evidence to be a VALIDATOR record inside the SlashValidator path. Any-role evidence reopens the governance-slash bypass (CWE-345).",
        ));
    }

    if !block.contains("bincode::serialize(&record.report)") {
        problems.push(String::from(
            "account.rs no longer digests the full serialized SlashingReport inside the SlashValidator path. A partial or hand-built digest weakens the evidence binding.",
        ));
    }

    if !block.contains("sha2::Sha256::digest(&bytes).as_slice() == evidence_hash") {
        problems.push(String::from(
            "account.rs no longer compares the computed evidence digest against the provided evidence_hash inside the SlashValidator path. Mentioning evidence_hash without the equality check leaves the slash evidence unverifiable.",
        ));
    }

    // The digest comparison must be used as a CONDITION (`if .. ==
    // evidence_hash { .. }`), not assigned to any binding (`let x = .. ==
    // evidence_hash`). A renamed no-op binding still bypasses a bare
    // substring check (Strix CWE-697, round 5 finding: arbitrary `let`
    // binding).
    // The digest comparison must drive the success. Two legitimate forms:
    //   1. `if sha2::Sha256::digest(..) == evidence_hash { return true; }`
    //      with a NON-INERT body (the guard body must actually return true),
    //      or
    //   2. `sha2::Sha256::digest(..) == evidence_hash` as a tail expression
    //      (the closure's result, as in `any(|r| { ..; digest == hash })`).
    // A comparison bound to an unused variable, or an `if` whose body does
    // not contain the success, is cosmetic (Strix CWE-697, round 5 finding:
    // inert `if` bodies).
    let digest_cmp = "sha2::Sha256::digest(&bytes).as_slice() == evidence_hash";
    let guard_str = format!("if {digest_cmp} {{");
    // The guarded `return true` must be inside the digest-guard block AND not
    // inside a closure (`|| { return true; }`) or nested helper; a closure
    // decoy does not control the slash decision (Strix CWE-697, round 6).
    let guarded_form = block.find(&guard_str).is_some_and(|guard_start| {
        let guard_rest = &block[guard_start..];
        let open = guard_rest.find('{').unwrap_or(0);
        let mut depth = 0i32;
        let mut guard_end = None;
        for (offset, ch) in guard_rest[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        guard_end = Some(open + offset + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        guard_end.is_some_and(|end| {
            let body = &guard_rest[..end];
            let closure_ret = body.contains("= ||")
                || body.contains("= |")
                || body.contains("move |")
                || body.contains("|_|");
            let empty_body = body.trim_end().ends_with('{')
                || body.trim().ends_with("{ //")
                || body.trim().ends_with("{ /*");
            // `return true` must be at the guard's top level (nested_depth
            // <= 1: the guard's own if). A return nested deeper (closure or
            // move-closure body) is a decoy (Strix CWE-697, round 9).
            let mut nested_depth = 0i32;
            let mut top_level_return = false;
            let mut nested_return = false;
            for line in body.lines() {
                let trimmed = line.trim();
                if nested_depth <= 1 && trimmed.contains("return true;") {
                    top_level_return = true;
                }
                if nested_depth > 1 && trimmed.contains("return true;") {
                    nested_return = true;
                }
                nested_depth = nested_depth
                    .saturating_add(trimmed.matches('{').count().try_into().unwrap_or(i32::MAX))
                    .saturating_sub(trimmed.matches('}').count().try_into().unwrap_or(i32::MAX));
            }
            // The guard body must itself end in `return true;` so a trailing
            // fall-through cannot carry the success (Strix CWE-697, round
            // 5/6/7 findings, kept from the round-8 refactor on main).
            let inside = &guard_rest[open + 1..end.saturating_sub(1)];
            let ends_with_return = inside.trim_end().ends_with("return true;");
            // An enclosing `.any(...)` whose result is then overridden
            // (`|| true`, `&& x`) must be rejected: the guard is accepted
            // while the slash decision is forced by the override (Strix
            // CWE-697, round 8 finding).
            let no_any_override = block[..guard_start].rfind(".any(").is_none_or(|any_at| {
                let any_rest = &block[any_at..];
                let any_open = any_rest.find('{').unwrap_or(0);
                let mut closure_depth = 0i32;
                let mut closure_end = None;
                for (offset, ch) in any_rest[any_open..].char_indices() {
                    match ch {
                        '{' => closure_depth += 1,
                        '}' => {
                            closure_depth -= 1;
                            if closure_depth == 0 {
                                closure_end = Some(any_open + offset);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                closure_end.is_some_and(|closure_end| {
                    let after = any_rest[closure_end + 1..].trim_start();
                    after.strip_prefix(')').is_some_and(|rest| {
                        let rest = rest.trim_start();
                        rest.is_empty()
                            || rest.starts_with(';')
                            || rest.starts_with(',')
                            || rest.starts_with(')')
                            || rest.starts_with('}')
                            || rest.starts_with(']')
                    })
                })
            });
            top_level_return
                && !nested_return
                && !closure_ret
                && !empty_body
                && ends_with_return
                && no_any_override
        })
    });
    // tail_form: the digest comparison is the closure's last expression when
    // it appears inside `.any(|..| { .. })` with no `let` binding of it, no
    // separate `return true;`, and nothing that overrides the result right
    // after the comparison. `... == evidence_hash }) || true` must be
    // rejected: the `|| true` immediately overrides the closure result, so
    // slashing succeeds without evidence control (Strix CWE-697, round 8
    // finding).
    let tail_form = block.contains(digest_cmp)
        && !block.lines().any(|l| {
            let t = l.trim();
            (t.starts_with("let ") || t.starts_with("let_")) && t.contains("== evidence_hash")
        })
        && !block.contains("return true;")
        && block.contains(".any(|")
        && block.rfind(digest_cmp).is_some_and(|cmp_at| {
            let after = block[cmp_at + digest_cmp.len()..].trim_start();
            // Accept the comparison as a tail only when what follows is the
            // closure/expression close (`}`, `)`, `]`, `,`) or a bare `;`
            // statement end. A `||`/`&&` continuation (`|| true`, `&& x`)
            // overrides the digest result and must fail.
            let until_stop = after.find([';', ',']).map_or(after, |i| &after[..i]);
            !until_stop.contains("||")
                && !until_stop.contains("&&")
                && (after.strip_prefix('}').is_some_and(|rest| {
                    let rest = rest.trim_start();
                    rest.is_empty()
                        || rest.starts_with(';')
                        || rest.starts_with(',')
                        || rest.starts_with(')')
                        || rest.starts_with('}')
                        || rest.starts_with(']')
                }) || after.starts_with(')'))
        });
    if !guarded_form && !tail_form {
        problems.push(String::from(
            "account.rs no longer drives the slash success with the digest comparison. The evidence check must either guard the success with a non-inert body (`if digest == evidence_hash { return true; }`) or be the closure's tail expression; a cosmetic binding or inert if body is insufficient.",
        ));
    }

    problems
}

pub fn run(root: &Path) -> Result<String, String> {
    let src = collect(root)?;
    let problems = judge(&src);
    if problems.is_empty() {
        return Ok(String::from(
            "governance-slash gate OK: the live SlashValidator branch requires a VALIDATOR record with a full-report digest compared against the evidence hash.",
        ));
    }
    Err(problems.join("\n"))
}

fn check_canary(problems: &mut Vec<String>, name: &str, src: &str) {
    if !judge(src)
        .iter()
        .any(|p| p.contains("VALIDATOR record inside the SlashValidator path"))
    {
        problems.push(format!("VACUOUS: {name} steered the gate."));
    }
}

pub fn self_test() -> Result<String, String> {
    let mut problems = Vec::new();

    let good = "\
fn execute_proposal(&mut self, proposal: &Proposal) {
    match &proposal.p_type {
        ProposalType::SlashValidator { address, evidence_hash } => {
            if record.report.role != crate::registry::role::roles::VALIDATOR {
                return false;
            }
            let bytes = bincode::serialize(&record.report).expect(\"x\");
            if sha2::Sha256::digest(&bytes).as_slice() == evidence_hash {
                return true;
            }
        }
    }
}
";
    if !judge(good).is_empty() {
        problems.push(String::from(
            "BROKEN: the protected form was reported as missing.",
        ));
    }

    let live = "fn execute_proposal(&mut self, proposal: &Proposal) { match &proposal.p_type { ProposalType::SlashValidator { address, evidence_hash } => { return true; } } }\n";

    check_canary(&mut problems, "helper bait",
        &format!("fn helper() {{ record.report.role != crate::registry::role::roles::VALIDATOR bincode::serialize(&record.report) sha2::Sha256::digest(&bytes).as_slice() == evidence_hash }}\n{live}"));

    check_canary(&mut problems, "comment bait",
        "fn execute_proposal(&mut self, proposal: &Proposal) { /* match &proposal.p_type { ProposalType::SlashValidator { address, evidence_hash } => { if record.report.role != crate::registry::role::roles::VALIDATOR { return false; } let bytes = bincode::serialize(&record.report).expect(\"x\"); if sha2::Sha256::digest(&bytes).as_slice() == evidence_hash { return true; } } } */ match &proposal.p_type { ProposalType::SlashValidator { address, evidence_hash } => { return true; } } }\n");

    check_canary(&mut problems, "string bait",
        "fn execute_proposal(&mut self, proposal: &Proposal) { let _d = \"match &proposal.p_type { ProposalType::SlashValidator { address, evidence_hash } => { if record.report.role != crate::registry::role::roles::VALIDATOR { return false; } } }\"; match &proposal.p_type { ProposalType::SlashValidator { address, evidence_hash } => { return true; } } }\n");

    check_canary(&mut problems, "raw-string bait",
        "fn execute_proposal(&mut self, proposal: &Proposal) { let _d = r#\"match &proposal.p_type { ProposalType::SlashValidator { address, evidence_hash } => { if record.report.role != crate::registry::role::roles::VALIDATOR { return false; } } }\"#; match &proposal.p_type { ProposalType::SlashValidator { address, evidence_hash } => { return true; } } }\n");

    check_canary(&mut problems, "nested-comment bait",
        "fn execute_proposal(&mut self, proposal: &Proposal) { /* outer /* inner match &proposal.p_type { ProposalType::SlashValidator { address, evidence_hash } => { if record.report.role != crate::registry::role::roles::VALIDATOR { return false; } } } */ tail */ match &proposal.p_type { ProposalType::SlashValidator { address, evidence_hash } => { return true; } } }\n");

    // A closure-decoy `return true;` inside the digest guard must not satisfy
    // the guarded form: the guard body must end with the return, so a nested
    // closure or inner block cannot carry it while the outer success falls
    // through to an unconditional tail (Strix CWE-697, round 7 finding).
    check_canary(&mut problems, "closure-decoy bait",
        "fn execute_proposal(&mut self, proposal: &Proposal) { match &proposal.p_type { ProposalType::SlashValidator { address, evidence_hash } => { if sha2::Sha256::digest(&bytes).as_slice() == evidence_hash { let _d = || { return true; }; } true } } }\n");

    // A `|| true` right after the digest comparison overrides the closure
    // result, so the tail form must be rejected (Strix CWE-697, round 8
    // finding).
    check_canary(&mut problems, "tail-or-true bait",
        "fn execute_proposal(&mut self, proposal: &Proposal) { match &proposal.p_type { ProposalType::SlashValidator { address, evidence_hash } => { records.iter().any(|record| { let bytes = bincode::serialize(&record.report).expect(\"x\"); sha2::Sha256::digest(&bytes).as_slice() == evidence_hash }) || true } } }\n");

    // A guarded `return true` inside `.any(|...| { ... })` whose result is
    // then overridden with `|| true` must be rejected too (Strix CWE-697,
    // round 8 finding: guarded_form acceptance with a forced decision).
    check_canary(&mut problems, "guarded-or-true bait",
        "fn execute_proposal(&mut self, proposal: &Proposal) { match &proposal.p_type { ProposalType::SlashValidator { address, evidence_hash } => { records.iter().any(|record| { if sha2::Sha256::digest(&bytes).as_slice() == evidence_hash { return true; } false }) || true } } }\n");

    // The same with a `move` closure: `.any(move |record| ...) || true` must
    // be rejected even though `.any(|` is absent (Strix CWE-697, round 8
    // finding: exact `.any(|` match misses move closures).
    check_canary(&mut problems, "guarded-move-or-true bait",
        "fn execute_proposal(&mut self, proposal: &Proposal) { match &proposal.p_type { ProposalType::SlashValidator { address, evidence_hash } => { records.iter().any(move |record| { if sha2::Sha256::digest(&bytes).as_slice() == evidence_hash { return true; } false }) || true } } }\n");

    if !problems.is_empty() {
        return Err(problems.join("\n  "));
    }
    Ok(String::from(
        "governance-slash gate self-test OK: the protected branch passes, bait outside the branch fails.",
    ))
}
