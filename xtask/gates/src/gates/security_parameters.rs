//! The security parameters absorbed into the transcript must be read out of
//! the FRI configuration, not written down a second time.
//!
//! Ported from `scripts/check-security-parameters-are-derived.sh`.
//!
//! # The failure this closes
//!
//! The Fiat-Shamir transcript carries the degrees, the commitments and the
//! public values. It did not carry the FRI parameters, and those are what
//! decide what a proof is worth: `num_queries` and `log_blowup` set the
//! soundness error, the proof-of-work bits set the grinding cost. Least
//! Authority's audit of Plonky3 found this class directly.
//!
//! # What is checked
//!
//! 1. The trait declares `security_parameters`, and both prover and verifier
//!    absorb it (the value, or the binding it was stored into) before their
//!    first `sample_algebra_element`, with shadowing rejected.
//! 2. `build_config` builds the absorbed vector out of the `fri_params`
//!    binding; a bare integer literal in that vector is the drift this gate
//!    is named for.
//! 3. Every numeric field of the `FriParameters` literal is represented, and
//!    the derived vector is the one passed into `new_with_security`.
//!
//! Comments and literals are stripped (delimiter-aware raw strings included)
//! so inert text cannot satisfy the evidence checks.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

/// Python `\s`.
fn skip_py_ws(s: &str) -> &str {
    let mut idx = 0usize;
    for (i, c) in s.char_indices() {
        if matches!(c, ' ' | '\t' | '\n' | '\r' | '\u{000c}' | '\u{000b}') {
            idx = i + c.len_utf8();
        } else {
            break;
        }
    }
    &s[idx..]
}

fn word_before(s: &str, idx: usize) -> bool {
    s[..idx]
        .chars()
        .next_back()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn word_at(s: &str, idx: usize) -> bool {
    s[idx..]
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn blank_chars(chars: &[char]) -> String {
    chars
        .iter()
        .map(|&c| if c == '\n' { '\n' } else { ' ' })
        .collect()
}

/// Blank Rust block comments, which nest.
fn strip_block_comments(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    let mut depth = 0usize;
    let n = chars.len();
    while i < n {
        if i + 1 < n && chars[i] == '/' && chars[i + 1] == '*' {
            depth += 1;
            out.push_str("  ");
            i += 2;
            continue;
        }
        if depth > 0 && i + 1 < n && chars[i] == '*' && chars[i + 1] == '/' {
            depth -= 1;
            out.push_str("  ");
            i += 2;
            continue;
        }
        if depth > 0 {
            out.push(if chars[i] == '\n' { '\n' } else { ' ' });
            i += 1;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Blank raw strings (`r"..."`, `br"..."`, `rb"..."`), delimiter-aware: the
/// closing quote must be followed by the same hash run that opened it.
fn strip_raw_strings(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut out = String::new();
    let mut i = 0usize;
    while i < n {
        let step = if (chars[i] == 'b' && i + 1 < n && chars[i + 1] == 'r')
            || (chars[i] == 'r' && i + 1 < n && chars[i + 1] == 'b')
        {
            2
        } else if chars[i] == 'r' {
            1
        } else {
            out.push(chars[i]);
            i += 1;
            continue;
        };
        let mut j = i + step;
        let hash_start = j;
        while j < n && chars[j] == '#' {
            j += 1;
        }
        if j >= n || chars[j] != '"' {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let closing: String = std::iter::once('"')
            .chain(chars[hash_start..j].iter().copied())
            .collect();
        let closing_len = closing.chars().count();
        let mut end = None;
        let mut k = j + 1;
        while k + closing_len <= n {
            let cand: String = chars[k..k + closing_len].iter().collect();
            if cand == closing {
                end = Some(k);
                break;
            }
            k += 1;
        }
        let Some(end) = end else {
            out.push(chars[i]);
            i += 1;
            continue;
        };
        let span_end = end + closing_len;
        out.push_str(&blank_chars(&chars[i..span_end]));
        i = span_end;
    }
    out
}

/// Blank string literals (`b?"..."`) and char literals (`b?'...'`).
fn strip_quoted(text: &str, quote: char) -> String {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut out = String::new();
    let mut i = 0usize;
    while i < n {
        let c = chars[i];
        let start = if c == quote || (c == 'b' && i + 1 < n && chars[i + 1] == quote) {
            Some(i)
        } else {
            None
        };
        let Some(start) = start else {
            out.push(c);
            i += 1;
            continue;
        };
        let content_start = start + 1 + usize::from(chars[start] == 'b');
        let mut ok = false;
        let mut close_at = 0usize;
        if quote == '\'' {
            if content_start < n {
                let item_end = if chars[content_start] == '\\' {
                    if content_start + 1 < n {
                        content_start + 2
                    } else {
                        content_start + 1
                    }
                } else {
                    content_start + 1
                };
                if item_end < n && chars[item_end] == '\'' {
                    ok = true;
                    close_at = item_end;
                }
            }
        } else {
            let mut j = content_start;
            while j < n {
                match chars[j] {
                    '\\' => {
                        if j + 1 < n {
                            j += 2;
                        } else {
                            break;
                        }
                    }
                    '"' => {
                        ok = true;
                        close_at = j;
                        break;
                    }
                    _ => j += 1,
                }
            }
        }
        if !ok {
            out.push(chars[start]);
            i = start + 1;
            continue;
        }
        out.push_str(&blank_chars(&chars[start..=close_at]));
        i = close_at + 1;
    }
    out
}

/// Strip line comments, nested block comments, raw strings, ordinary strings
/// and chars, preserving line structure.
fn strip_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for line in s.split_inclusive('\n') {
        let Some(pos) = line.find("//") else {
            out.push_str(line);
            continue;
        };
        out.push_str(&line[..pos]);
        for c in line[pos..].chars() {
            out.push(if c == '\n' { '\n' } else { ' ' });
        }
    }
    let out = strip_block_comments(&out);
    let out = strip_raw_strings(&out);
    let out = strip_quoted(&out, '"');
    strip_quoted(&out, '\'')
}

/// `fn\s+security_parameters\s*\(&self\)` in the raw config.
fn has_trait_decl(cfg_src: &str) -> bool {
    let mut from = 0usize;
    while let Some(pos) = cfg_src[from..].find("fn") {
        let abs = from + pos;
        if word_before(cfg_src, abs) {
            from = abs + 1;
            continue;
        }
        let r = &cfg_src[abs + 2..];
        if r.len() == skip_py_ws(r).len() {
            from = abs + 1;
            continue; // `\s+` after `fn`
        }
        let r = skip_py_ws(r);
        let Some(rest) = r.strip_prefix("security_parameters") else {
            from = abs + 1;
            continue;
        };
        if skip_py_ws(rest).starts_with("(&self)") {
            return true;
        }
        from = abs + 1;
    }
    false
}

/// `\blet\s+(?:mut\s+)?NAME\b\s*=.*security_parameters\s*\(` on the statement
/// line; returns the binding name.
fn let_binding(sec_stmt: &str) -> Option<String> {
    let mut from = 0usize;
    while let Some(pos) = sec_stmt[from..].find("let") {
        let abs = from + pos;
        if word_before(sec_stmt, abs) {
            from = abs + 1;
            continue;
        }
        let r = &sec_stmt[abs + 3..];
        if r.len() == skip_py_ws(r).len() {
            from = abs + 1;
            continue;
        }
        let mut r = skip_py_ws(r);
        if let Some(rest) = r.strip_prefix("mut") {
            let rest2 = skip_py_ws(rest);
            if rest2.len() < rest.len() {
                r = rest2;
            }
        }
        let name_end = r
            .char_indices()
            .take_while(|&(_, c)| c.is_ascii_alphanumeric() || c == '_')
            .map(|(i, c)| i + c.len_utf8())
            .last();
        let Some(name_end) = name_end else {
            from = abs + 1;
            continue;
        };
        let name = &r[..name_end];
        if word_at(r, name_end) {
            from = abs + 1;
            continue; // `\b`
        }
        let r = skip_py_ws(&r[name_end..]);
        let Some(r) = r.strip_prefix('=') else {
            from = abs + 1;
            continue;
        };
        let Some(spos) = r.find("security_parameters") else {
            from = abs + 1;
            continue;
        };
        if skip_py_ws(&r[spos + "security_parameters".len()..]).starts_with('(') {
            return Some(name.to_string());
        }
        from = abs + 1;
    }
    None
}

/// `observe(?:_slice)?\s*\(\s*&?\s*(?:config\.)?security_parameters\s*\([^\n;]*\)\s*\)`.
fn observe_direct(after_sec: &str) -> bool {
    let mut from = 0usize;
    while let Some(pos) = after_sec[from..].find("observe") {
        let abs = from + pos;
        let mut r = &after_sec[abs + "observe".len()..];
        if r.starts_with("_slice") {
            r = &r["_slice".len()..];
        }
        let r = skip_py_ws(r);
        let Some(r) = r.strip_prefix('(') else {
            from = abs + 1;
            continue;
        };
        let r = skip_py_ws(r);
        let r = if let Some(rest) = r.strip_prefix('&') {
            skip_py_ws(rest)
        } else {
            r
        };
        let r = if let Some(rest) = r.strip_prefix("config.") {
            rest
        } else {
            r
        };
        let Some(r) = r.strip_prefix("security_parameters") else {
            from = abs + 1;
            continue;
        };
        let r = skip_py_ws(r);
        let Some(r) = r.strip_prefix('(') else {
            from = abs + 1;
            continue;
        };
        // `[^\n;]*\)` then `\s*\)`.
        let Some(close) = r.find(')') else {
            from = abs + 1;
            continue;
        };
        if r[..close].contains(';') || r[..close].contains('\n') {
            from = abs + 1;
            continue;
        }
        if skip_py_ws(&r[close + 1..]).starts_with(')') {
            return true;
        }
        from = abs + 1;
    }
    false
}

/// `observe(?:_slice)?\s*\(\s*&?\s*BINDING\s*\)`; returns the match position.
fn observe_binding_pos(after_sec: &str, binding: &str) -> Option<usize> {
    let mut from = 0usize;
    while let Some(pos) = after_sec[from..].find("observe") {
        let abs = from + pos;
        let mut r = &after_sec[abs + "observe".len()..];
        if r.starts_with("_slice") {
            r = &r["_slice".len()..];
        }
        let r = skip_py_ws(r);
        let Some(r) = r.strip_prefix('(') else {
            from = abs + 1;
            continue;
        };
        let r = skip_py_ws(r);
        let r = if let Some(rest) = r.strip_prefix('&') {
            skip_py_ws(rest)
        } else {
            r
        };
        let Some(r) = r.strip_prefix(binding) else {
            from = abs + 1;
            continue;
        };
        if skip_py_ws(r).starts_with(')') {
            return Some(abs);
        }
        from = abs + 1;
    }
    None
}

/// `\blet\s+(?:mut\s+)?BINDING\b\s*=` or `\bBINDING\b\s*=(?!=)`.
fn has_rebinding(before: &str, binding: &str) -> bool {
    let mut from = 0usize;
    while let Some(pos) = before[from..].find("let") {
        let abs = from + pos;
        if word_before(before, abs) {
            from = abs + 1;
            continue;
        }
        let r = &before[abs + 3..];
        if r.len() == skip_py_ws(r).len() {
            from = abs + 1;
            continue;
        }
        let mut r = skip_py_ws(r);
        if let Some(rest) = r.strip_prefix("mut") {
            let rest2 = skip_py_ws(rest);
            if rest2.len() < rest.len() {
                r = rest2;
            }
        }
        let Some(rest) = r.strip_prefix(binding) else {
            from = abs + 1;
            continue;
        };
        if word_at(rest, 0) {
            from = abs + 1;
            continue; // `\b`
        }
        if skip_py_ws(rest).starts_with('=') {
            return true;
        }
        from = abs + 1;
    }
    // Plain mutable assignment: `\bBINDING\b\s*=(?!=)`.
    let mut from = 0usize;
    while let Some(pos) = before[from..].find(binding) {
        let abs = from + pos;
        if word_before(before, abs) {
            from = abs + 1;
            continue;
        }
        let rest = &before[abs + binding.len()..];
        if word_at(rest, 0) {
            from = abs + 1;
            continue;
        }
        let rest = skip_py_ws(rest);
        if rest.starts_with('=') && !rest.starts_with("==") {
            return true;
        }
        from = abs + 1;
    }
    false
}

/// Check that one side absorbs `security_parameters()` before its first
/// challenge.
fn check_absorption(src: &str, name: &str, problems: &mut Vec<String>, checked: &mut usize) {
    let code = strip_comments(src);
    let lines: Vec<&str> = code.split('\n').collect();
    *checked += 1;
    let stops: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.contains("sample_algebra_element()"))
        .map(|(i, _)| i)
        .collect();
    let Some(&stop) = stops.first() else {
        problems.push(format!(
            "{name}.rs samples no challenge; this gate cannot place the absorption."
        ));
        return;
    };
    let before = lines[..stop].join("\n");
    if !before.contains("security_parameters()") {
        problems.push(format!(
            "{name}.rs does not absorb `security_parameters()` before its first \
             challenge. A parameter set the prover controls and the transcript \
             does not cover can be chosen after the challenge is drawn."
        ));
        return;
    }

    let sec_line = lines[..stop]
        .iter()
        .position(|l| l.contains("security_parameters()"))
        .expect("checked above");
    let sec_stmt = lines[sec_line];
    let after_sec = lines[sec_line..stop].join("\n");
    let binding = let_binding(sec_stmt);
    let direct_observed = observe_direct(&after_sec);

    let mut bound_observed = false;
    let mut shadowed_before_observe = false;
    if let Some(binding) = &binding {
        let observe_pos = observe_binding_pos(&after_sec, binding);
        let before_observe = match observe_pos {
            Some(pos) => after_sec[..pos].to_string(),
            None => after_sec[sec_stmt.len()..].to_string(),
        };
        shadowed_before_observe = has_rebinding(&before_observe, binding);
        bound_observed = observe_pos.is_some();
    }

    if (shadowed_before_observe && bound_observed) || !(direct_observed || bound_observed) {
        if shadowed_before_observe {
            problems.push(format!(
                "{name}.rs shadows the `security_parameters()` binding \
                 before observing it, so an attacker-chosen value can \
                 reach the transcript while the identifier matches."
            ));
        } else {
            problems.push(format!(
                "{name}.rs reads `security_parameters()` but never observes the \
                 value (or its binding) into the challenger before the first \
                 challenge. An unrelated observe call leaves the FRI parameters \
                 outside the transcript."
            ));
        }
        problems.push(format!(
            "{name}.rs reads `security_parameters()` but never observes the \
             value (or its binding) into the challenger before the first \
             challenge. An unrelated observe call leaves the FRI parameters \
             outside the transcript."
        ));
    }
}

/// `let\s+fri_params\s*=\s*p3_fri::FriParameters\s*\{(.*?)\};` body.
fn fri_params_body(build_src: &str) -> Option<String> {
    let mut from = 0usize;
    while let Some(pos) = build_src[from..].find("let") {
        let abs = from + pos;
        if word_before(build_src, abs) {
            from = abs + 1;
            continue;
        }
        let r = &build_src[abs + 3..];
        if r.len() == skip_py_ws(r).len() {
            from = abs + 1;
            continue;
        }
        let r = skip_py_ws(r);
        let Some(r) = r.strip_prefix("fri_params") else {
            from = abs + 1;
            continue;
        };
        let r = skip_py_ws(r);
        let Some(r) = r.strip_prefix('=') else {
            from = abs + 1;
            continue;
        };
        let r = skip_py_ws(r);
        let Some(r) = r.strip_prefix("p3_fri::FriParameters") else {
            from = abs + 1;
            continue;
        };
        let r = skip_py_ws(r);
        let Some(r) = r.strip_prefix('{') else {
            from = abs + 1;
            continue;
        };
        if let Some(close) = r.find("};") {
            return Some(r[..close].to_string());
        }
        from = abs + 1;
    }
    None
}

/// The field names of `(\w+)\s*:\s*[0-9]+\s*,` pairs in the literal body.
fn fri_fields(fri_body: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut from = 0usize;
    while let Some(pos) = fri_body[from..].find(':') {
        let abs = from + pos;
        let before = &fri_body[..abs];
        let name_start = before
            .char_indices()
            .rev()
            .take_while(|&(_, c)| c.is_ascii_alphanumeric() || c == '_')
            .map(|(i, _)| i)
            .last()
            .unwrap_or(abs);
        let name = &before[name_start..];
        if name.is_empty() {
            from = abs + 1;
            continue;
        }
        let r = skip_py_ws(&fri_body[abs + 1..]);
        let Some(digits_end) = r
            .char_indices()
            .take_while(|&(_, c)| c.is_ascii_digit())
            .map(|(i, c)| i + c.len_utf8())
            .last()
        else {
            from = abs + 1;
            continue;
        };
        if skip_py_ws(&r[digits_end..]).starts_with(',') {
            out.insert(name.to_string());
        }
        from = abs + 1;
    }
    out
}

/// `let\s+security\s*=\s*vec!\[(.*?)\];` - returns the body and the end
/// position of the whole statement (after `];`).
fn security_vec(build_src: &str) -> Option<(String, usize)> {
    let mut from = 0usize;
    while let Some(pos) = build_src[from..].find("let") {
        let abs = from + pos;
        if word_before(build_src, abs) {
            from = abs + 1;
            continue;
        }
        let r0 = &build_src[abs + 3..];
        if r0.len() == skip_py_ws(r0).len() {
            from = abs + 1;
            continue;
        }
        let r = skip_py_ws(r0);
        let Some(r) = r.strip_prefix("security") else {
            from = abs + 1;
            continue;
        };
        let r = skip_py_ws(r);
        let Some(r) = r.strip_prefix('=') else {
            from = abs + 1;
            continue;
        };
        let r = skip_py_ws(r);
        let Some(r) = r.strip_prefix("vec![") else {
            from = abs + 1;
            continue;
        };
        if let Some(close) = r.find("];") {
            let body_start = build_src.len() - r.len();
            let content = r[..close].to_string();
            let end = body_start + close + 2;
            return Some((content, end));
        }
        from = abs + 1;
    }
    None
}

/// `[0-9]+\s*(as\s+u64)?` fullmatch on a trimmed entry.
fn is_literal_entry(e: &str) -> bool {
    let t = e.trim();
    let Some(digits_end) = t
        .char_indices()
        .take_while(|&(_, c)| c.is_ascii_digit())
        .map(|(i, c)| i + c.len_utf8())
        .last()
    else {
        return false;
    };
    let rest = t[digits_end..].trim();
    rest.is_empty() || rest == "as u64"
}

/// `\blet\s+(?:mut\s+)?security\b\s*=` in the config tail.
fn has_security_rebound(config_tail: &str) -> bool {
    let mut from = 0usize;
    while let Some(pos) = config_tail[from..].find("let") {
        let abs = from + pos;
        if word_before(config_tail, abs) {
            from = abs + 1;
            continue;
        }
        let r = &config_tail[abs + 3..];
        if r.len() == skip_py_ws(r).len() {
            from = abs + 1;
            continue;
        }
        let mut r = skip_py_ws(r);
        if let Some(rest) = r.strip_prefix("mut") {
            let rest2 = skip_py_ws(rest);
            if rest2.len() < rest.len() {
                r = rest2;
            }
        }
        let Some(rest) = r.strip_prefix("security") else {
            from = abs + 1;
            continue;
        };
        if word_at(rest, 0) {
            from = abs + 1;
            continue;
        }
        if skip_py_ws(rest).starts_with('=') {
            return true;
        }
        from = abs + 1;
    }
    false
}

/// `new_with_security\s*\([^;]*?,\s*&?\s*security\s*(?:,|\))`.
fn passes_security(config_tail: &str) -> bool {
    let mut from = 0usize;
    while let Some(pos) = config_tail[from..].find("new_with_security") {
        let abs = from + pos;
        let r = skip_py_ws(&config_tail[abs + "new_with_security".len()..]);
        let Some(r) = r.strip_prefix('(') else {
            from = abs + 1;
            continue;
        };
        let mut k = 0usize;
        while let Some(comma) = r[k..].find(',') {
            let cabs = k + comma;
            if r[..cabs].contains(';') {
                break;
            }
            let after = skip_py_ws(&r[cabs + 1..]);
            let after = if let Some(rest) = after.strip_prefix('&') {
                skip_py_ws(rest)
            } else {
                after
            };
            let Some(rest) = after.strip_prefix("security") else {
                k = cabs + 1;
                continue;
            };
            let rest = skip_py_ws(rest);
            if rest.starts_with(',') || rest.starts_with(')') {
                return true;
            }
            k = cabs + 1;
        }
        from = abs + 1;
    }
    false
}

fn check_build_config(build_src: &str, problems: &mut Vec<String>, checked: &mut usize) {
    // The absorbed vector must be derived from the FriParameters binding.
    *checked += 1;
    let Some(fri_body) = fri_params_body(build_src) else {
        problems.push(String::from(
            "plonky3_prover.rs does not build a `fri_params` binding this gate can \
             read. Either the configuration moved, in which case update the gate in \
             the same commit, or there is no single place the FRI parameters are \
             stated.",
        ));
        return;
    };
    let fri_body = strip_comments(&fri_body);
    let fields = fri_fields(&fri_body);

    let Some((sec_body_raw, sec_end)) = security_vec(build_src) else {
        problems.push(String::from(
            "plonky3_prover.rs builds no `security` vector, so nothing states \
             which parameters reach the transcript. Derive one from the \
             `fri_params` binding.",
        ));
        return;
    };
    let sec_body = strip_comments(&sec_body_raw);

    // Every entry must read from fri_params, never be a literal.
    let entries: Vec<&str> = sec_body
        .split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .collect();
    for e in &entries {
        if is_literal_entry(e) {
            problems.push(format!(
                "the absorbed security vector contains the literal `{e}` \
                 instead of reading the field from `fri_params`. A \
                 hand-written copy is a second source of truth and can \
                 drift from the parameters that actually govern the proof."
            ));
        } else if !e.contains("fri_params.") {
            problems.push(format!(
                "the absorbed security vector entry `{e}` does not read \
                 from `fri_params`, so this gate cannot tell that it \
                 describes the configuration in use."
            ));
        }
    }

    // Every numeric FRI field must appear.
    for field in &fields {
        if !sec_body.contains(&format!("fri_params.{field}")) {
            problems.push(format!(
                "`{field}` is set on the FRI parameters but is not absorbed \
                 into the transcript. A parameter that governs the proof \
                 and sits outside the transcript is the exact shape of the \
                 bug this binding was added for."
            ));
        }
    }
    *checked += fields.len();

    // The derived vector must be the one passed into the final config.
    let config_tail = strip_comments(&build_src[sec_end..]);
    let rebound = has_security_rebound(&config_tail);
    if rebound || !passes_security(&config_tail) {
        problems.push(String::from(
            "the derived `security` vector is never passed into \
             `new_with_security` (or is rebound first): the transcript \
             absorbs one parameter set while the config is built from \
             another.",
        ));
    }
}

/// # Errors
///
/// A missing or unabsorbed `security_parameters`, hand-written literals in
/// the absorbed vector, a FRI field left out, or a derived vector never
/// passed into the config.
pub fn run(root: &Path) -> Result<String, String> {
    let cfg = root.join("budzero/bud-proof/src/bud_stark/config.rs");
    let prover = root.join("budzero/bud-proof/src/bud_stark/prover.rs");
    let verifier = root.join("budzero/bud-proof/src/bud_stark/verifier.rs");
    let build = root.join("budzero/bud-proof/src/plonky3_prover.rs");

    for (path, what) in [
        (&cfg, "config"),
        (&prover, "prover"),
        (&verifier, "verifier"),
        (&build, "build_config"),
    ] {
        if !path.is_file() {
            return Err(format!("FAIL: no {what} at {}", path.display()));
        }
    }

    let cfg_src = std::fs::read_to_string(&cfg).unwrap_or_default();
    let prover_src = std::fs::read_to_string(&prover).unwrap_or_default();
    let verifier_src = std::fs::read_to_string(&verifier).unwrap_or_default();
    let build_src = std::fs::read_to_string(&build).unwrap_or_default();

    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    // 1. The trait must declare it.
    checked += 1;
    if !has_trait_decl(&cfg_src) {
        problems.push(String::from(
            "config.rs does not declare `security_parameters`, so the FRI \
             parameters are outside the Fiat-Shamir transcript. num_queries and \
             log_blowup set the soundness error and the proof-of-work bits set the \
             grinding cost; a proof produced under weaker parameters has the same \
             shape as one produced under the real ones.",
        ));
    }

    // 1b. Both sides must absorb it before the first challenge.
    check_absorption(&prover_src, "prover", &mut problems, &mut checked);
    check_absorption(&verifier_src, "verifier", &mut problems, &mut checked);

    // 2. The absorbed vector must be derived from the FriParameters binding.
    check_build_config(&build_src, &mut problems, &mut checked);

    if checked == 0 {
        return Err(String::from("FAIL: gate checked nothing"));
    }

    if !problems.is_empty() {
        let mut msg = String::new();
        for p in &problems {
            let _ = writeln!(msg, "FAIL: {p}");
        }
        return Err(msg);
    }

    Ok(format!(
        "security parameters OK: {checked} checks, every FRI field is derived and absorbed"
    ))
}

// ---------------------------------------------------------------------------
// Self-test: the eighteen canaries of the shell version.
// ---------------------------------------------------------------------------

const GOOD_CFG: &str = "    fn security_parameters(&self) -> Vec<Val<Self>>;\n";
const GOOD_PV: &str = "    challenger.observe_slice(&config.security_parameters());\n\
    let rand_1: SC::Challenge = challenger.sample_algebra_element();\n";
const GOOD_BUILD: &str = "    let fri_params = p3_fri::FriParameters {\n\
        log_blowup: 3,\n\
        num_queries: 100,\n\
        commit_proof_of_work_bits: 16,\n\
        mmcs: challenge_mmcs,\n\
    };\n\
    let security = vec![\n\
        fri_params.log_blowup as u64,\n\
        fri_params.num_queries as u64,\n\
        fri_params.commit_proof_of_work_bits as u64,\n\
    ];\n\
    StarkConfig::new_with_security(0, security, fri_params.mmcs.clone());\n";

/// Write a fixture tree and check the gate's verdict.
fn check_fixture(
    cfg: &str,
    pv: &str,
    build: &str,
    verifier_override: Option<&str>,
    expect_ok: bool,
    label: &str,
) -> Result<(), String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!(
        "budlum-gates-security-{}-{nanos}",
        std::process::id()
    ));
    let stark = dir.join("budzero/bud-proof/src/bud_stark");
    let _ = std::fs::create_dir_all(&stark);
    std::fs::write(stark.join("config.rs"), cfg).map_err(|e| e.to_string())?;
    std::fs::write(stark.join("prover.rs"), pv).map_err(|e| e.to_string())?;
    std::fs::write(stark.join("verifier.rs"), verifier_override.unwrap_or(pv))
        .map_err(|e| e.to_string())?;
    std::fs::write(dir.join("budzero/bud-proof/src/plonky3_prover.rs"), build)
        .map_err(|e| e.to_string())?;

    let result = run(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    if expect_ok {
        result.map(|_| ()).map_err(|e| format!("{label}: {e}"))
    } else {
        match result {
            Err(_) => Ok(()),
            Ok(_) => Err(format!("{label}: gate passed when it must fail")),
        }
    }
}

/// # Errors
///
/// The canaries that did not behave.
const NO_ABSORB: &str = "    let rand_1: SC::Challenge = challenger.sample_algebra_element();\n";

const LATE: &str = "    let rand_1: SC::Challenge = challenger.sample_algebra_element();\n\
        challenger.observe_slice(&config.security_parameters());\n";

const LITERAL_BUILD: &str = "    let fri_params = p3_fri::FriParameters {\n\
        log_blowup: 3,\n\
        num_queries: 100,\n\
        commit_proof_of_work_bits: 16,\n\
        mmcs: challenge_mmcs,\n\
    };\n\
    let security = vec![3, 100, 16];\n";

const MISSING_BUILD: &str = "    let fri_params = p3_fri::FriParameters {\n\
        log_blowup: 3,\n\
        num_queries: 100,\n\
        commit_proof_of_work_bits: 16,\n\
        mmcs: challenge_mmcs,\n\
    };\n\
    let security = vec![\n\
        fri_params.log_blowup as u64,\n\
        fri_params.num_queries as u64,\n\
    ];\n";

const NOTRAIT_CFG: &str = "    fn is_zk(&self) -> bool;\n";

const STRLIT_PV: &str =
    "    let _doc = \"challenger.observe_slice(&config.security_parameters());\";\n\
        let rand_1: SC::Challenge = challenger.sample_algebra_element();\n";

const STRLIT_GOOD: &str =
    "    let _doc = \"challenger.observe_slice(&config.security_parameters());\";\n\
        challenger.observe_slice(&config.security_parameters());\n\
        let rand_1: SC::Challenge = challenger.sample_algebra_element();\n";

const RAWSTR_PV: &str =
    "    let _doc = r#\"quote: \" challenger.observe_slice(&config.security_parameters())\"#;\n\
        let rand_1: SC::Challenge = challenger.sample_algebra_element();\n";

const RAWPLAIN_PV: &str =
    "    let _doc = r\"challenger.observe_slice(&config.security_parameters())\";\n\
        let rand_1: SC::Challenge = challenger.sample_algebra_element();\n";

const RAWBUILD: &str = "    let _doc = br#\"let fri_params = p3_fri::FriParameters { log_blowup: 3, num_queries: 100, commit_proof_of_work_bits: 16, mmcs: m }; let security = vec![1, 2, 3]; StarkConfig::new_with_security(0, security, m);\"#;\n";

const RAW_GOOD: &str = "    let _doc = r#\"the real absorption is on the next line\"#;\n\
        challenger.observe_slice(&config.security_parameters());\n\
        let rand_1: SC::Challenge = challenger.sample_algebra_element();\n";

const RAW_MISMATCH: &str = "    let _doc = r##\"prefix \"# challenger.observe_slice(&config.security_parameters()) \"##;\n\
        let rand_1: SC::Challenge = challenger.sample_algebra_element();\n";

const NESTEDC_PV: &str =
    "    /* outer /* inner */ challenger.observe_slice(&config.security_parameters()) */\n\
        let rand_1: SC::Challenge = challenger.sample_algebra_element();\n";

const NESTED_GOOD: &str = "    /* outer /* inner */ harmless */\n\
        challenger.observe_slice(&config.security_parameters());\n\
        let rand_1: SC::Challenge = challenger.sample_algebra_element();\n";

/// # Errors
///
/// Returns the first canary that misbehaves. The eighteen canaries mirror the
/// shell gate's one for one; the fixture strings live as consts above so the
/// function stays small enough for clippy's line budget.
/// # Errors
///
/// Returns the first canary that misbehaves. The eighteen canaries mirror the
/// shell gate's one for one; the fixture strings live as consts above.
/// One self-test case: (cfg, prover, build, verifier override, expect pass, label).
type Case = (
    &'static str,
    &'static str,
    &'static str,
    Option<&'static str>,
    bool,
    &'static str,
);

/// The eighteen canaries of the shell version, as a data table.
#[rustfmt::skip]
const CASES: &[Case] = &[
    (GOOD_CFG, GOOD_PV, GOOD_BUILD, None, true, "the corrected tree was rejected"),
    (GOOD_CFG, NO_ABSORB, GOOD_BUILD, None, false, "a transcript that never absorbs the parameters"),
    (GOOD_CFG, LATE, GOOD_BUILD, None, false, "parameters absorbed after the challenge"),
    (GOOD_CFG, GOOD_PV, LITERAL_BUILD, None, false, "hand-written literals as the absorbed parameters"),
    (GOOD_CFG, GOOD_PV, MISSING_BUILD, None, false, "a FRI parameter left out of the transcript"),
    (NOTRAIT_CFG, GOOD_PV, GOOD_BUILD, None, false, "a config with no security_parameters declaration"),
    (GOOD_CFG, GOOD_PV, GOOD_BUILD, Some(NO_ABSORB), false, "only the prover absorbing"),
    ("", "", "", None, false, "a tree with no sources"),
    (GOOD_CFG, STRLIT_PV, GOOD_BUILD, None, false, "a string literal containing the absorption call"),
    (GOOD_CFG, GOOD_PV, RAWBUILD, None, false, "a string literal containing the config wiring"),
    (GOOD_CFG, STRLIT_GOOD, GOOD_BUILD, None, true, "a real absorption next to a string literal was rejected"),
    (GOOD_CFG, RAWSTR_PV, GOOD_BUILD, None, false, "a raw string literal containing the absorption call"),
    (GOOD_CFG, RAWPLAIN_PV, GOOD_BUILD, None, false, "a hash-free raw string literal"),
    (GOOD_CFG, GOOD_PV, RAWBUILD, None, false, "a raw byte string containing the config wiring"),
    (GOOD_CFG, RAW_GOOD, GOOD_BUILD, None, true, "a real absorption next to a raw string was rejected"),
    (GOOD_CFG, RAW_MISMATCH, GOOD_BUILD, None, false, "a raw string with mismatched hash delimiters"),
    (GOOD_CFG, NESTEDC_PV, GOOD_BUILD, None, false, "a nested block comment containing the absorption call"),
    (GOOD_CFG, NESTED_GOOD, GOOD_BUILD, None, true, "a real absorption next to a nested block comment was rejected"),
];

/// # Errors
///
/// Returns the first canary that misbehaves. The eighteen canaries mirror the
/// shell gate's one for one; the fixture strings and the case table live as
/// module-level items so the function stays inside clippy's line budget.
pub fn self_test() -> Result<String, String> {
    for (cfg, pv, build, verifier_override, expect_ok, label) in CASES {
        check_fixture(cfg, pv, build, *verifier_override, *expect_ok, label)?;
    }
    Ok(String::from(
        "security parameter gate self-test OK: no absorption, late absorption, \
         hand-written literals, a missing FRI field, a removed trait method, \
         one-sided absorption, a missing tree, inert string-literal lookalikes, \
         a string next to the real call, raw string lookalikes, a raw string \
         next to the real call, a mismatched-delimiter raw string, nested block \
         comment lookalikes and a nested comment next to the real call are \
         handled correctly; the derived tree passes.",
    ))
}
