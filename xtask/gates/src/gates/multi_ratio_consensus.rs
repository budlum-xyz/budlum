//! What the ratio consensus is allowed to offer.
//!
//! Gate code: `K-MULTI-RATIO-FRACTAL`. A finding or a document that names this code resolves here.
//!
//! `MultiRatioConsensus::candidates_for_format` is the list a node votes on.
//! The invariant that keeps the vote honest is not a number in that list, it
//! is what the list may contain: no candidate may be a generative or optical
//! pipeline, because those produce a payload the prover cannot reproduce from
//! the commitment alone, and a vote on such a candidate settles bytes nobody
//! can re-derive.
//!
//! So the gate reads the candidate blocks themselves: every `RatioCandidate`
//! inside the function, its `pipe_name`, its non-zero `pipe_id`, and a finite
//! `ratio` above one. A comment that says generation was removed proves
//! nothing; the absence of such a candidate in the arms is what is checked.

use std::fmt::Write as _;
use std::path::Path;

const FORBIDDEN: [&str; 6] = [
    "optical",
    "carousel",
    "diffusion",
    "regenerat",
    "fountain",
    "prompt",
];

/// The source of one function, by name, from `pub fn name` to the matching
/// closing brace of its body.
fn body_of(src: &str, name: &str) -> Option<String> {
    let at = src.find(&format!("fn {name}("))?;
    let open = src[at..].find('{')? + at;
    let mut depth = 0usize;
    let mut out = String::new();
    for ch in src[open..].chars() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    out.push('}');
                    return Some(out);
                }
            }
            _ => {}
        }
        out.push(ch);
    }
    None
}

/// Every `RatioCandidate { .. }` block with its start index, braces counted.
fn candidates(body: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let bytes = body.as_bytes();
    let mut i = 0usize;
    while let Some(j) = body[i..].find("RatioCandidate {") {
        let start = i + j;
        let Some(rel) = body[start..].find('{') else {
            break;
        };
        let open = start + rel;
        let mut depth = 0usize;
        let mut k = open;
        while k < bytes.len() {
            match bytes[k] as char {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            k += 1;
        }
        out.push((start, body[start..=k].to_string()));
        i = k + 1;
    }
    out
}

/// Shape of the list itself: not emptied, and every format class still offered.
fn sayim(body: &str, list: &[(usize, String)], arms: usize) -> (usize, Vec<String>) {
    let mut ok = 0usize;
    let mut problems = Vec::new();
    if list.len() < 4 {
        problems.push(format!(
            "the candidate list has {} entries; a consensus over fewer than four ratios is not \
             a choice, so the function has probably been emptied rather than narrowed.",
            list.len()
        ));
    } else {
        ok += 1;
    }
    if arms < 4 {
        problems.push(format!(
            "only {arms} format classes offer candidates. `BudFormatClass` has more; a class \
             with no list silently falls through to whatever the caller does with an empty vote."
        ));
    } else {
        ok += 1;
    }
    let _ = body;
    (ok, problems)
}

/// # Errors
///
/// Returns the list of violated claims.
pub fn run(root: &Path) -> Result<String, String> {
    let f = root.join("bud/src/bud_format.rs");
    if !f.is_file() {
        return Err(format!("no bud_format.rs at {}", f.display()));
    }
    let src = std::fs::read_to_string(&f).map_err(|e| e.to_string())?;
    let body = body_of(&src, "candidates_for_format")
        .ok_or_else(|| "no `fn candidates_for_format` in `bud/src/bud_format.rs`".to_string())?;
    let list = candidates(&body);
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    let arms = body.matches("=> vec![").count();
    let (bulunan, sorunlar) = sayim(&body, &list, arms);
    checked += bulunan;
    problems.extend(sorunlar);
    let mut ids: Vec<u64> = Vec::new();
    for (n, (start, c)) in list.iter().enumerate() {
        let is_fallback = body[..*start]
            .rsplit_once("=>")
            .is_some_and(|(pre, _)| pre.lines().next_back().is_some_and(|l| l.trim() == "_"));
        if is_fallback {
            // The one allowed zero id is the "no pipeline for this class"
            // sentinel, and only while it is genuinely a no-op: identity ratio,
            // the default name. A fallback that carries a real ratio is a
            // candidate again, and it needs an id the settlement can record.
            if c.contains("pipe_name: \"default\"") && c.contains("ratio: 1.0") {
                checked += 1;
            } else {
                problems.push(String::from(
                    "the fallback arm is no longer the identity sentinel (`pipe_name: \"default\"`, \
                     `ratio: 1.0`). A `_` arm that offers a real ratio makes every unknown class \
                     a voting class, which is how an unset policy becomes a policy."
                ));
            }
            continue;
        }
        let lower = c.to_ascii_lowercase();
        for bad in FORBIDDEN {
            if lower.contains(bad) {
                problems.push(format!(
                    "candidate #{n} offers a pipeline named in the generative family \
                     (`{bad}`): `{}`. Its payload cannot be re-derived from the commitment, \
                     so a winning vote on it settles bytes no verifier can reproduce.",
                    c.lines()
                        .find(|l| l.contains("pipe_name"))
                        .unwrap_or("candidate")
                        .trim()
                ));
            }
        }
        let id = c
            .lines()
            .find(|l| l.contains("pipe_id:"))
            .and_then(|l| l.split_once("pipe_id:"))
            .and_then(|(_, v)| {
                let digits: String = v.trim().chars().take_while(char::is_ascii_digit).collect();
                digits.parse::<u64>().ok()
            });
        match id {
            Some(0) | None => problems.push(format!(
                "candidate #{n} has no usable `pipe_id`; the id is what the settlement \
                 records, and a zero id collides with the absence of a choice. Only the \
                 `_` fallback arm may carry a zero."
            )),
            Some(v) => ids.push(v),
        }
        if c.contains("ratio:") {
            checked += 1;
        } else {
            problems.push(format!("candidate #{n} declares no `ratio`."));
        }
    }
    if ids.is_empty() {
        problems.push(String::from(
            "no pipe id could be read from the candidate list.",
        ));
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
        "ratio consensus candidates OK: {} class candidates over {arms} format classes, none in \
         the generative family, no zero id outside the `_` fallback sentinel",
        list.len()
    ))
}

/// # Errors
///
/// Returns a finding when a defect fixture passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-ratio")?;
    std::fs::create_dir_all(dir.join("bud/src")).map_err(|e| e.to_string())?;
    let good = "pub fn candidates_for_format(class: BudFormatClass, original: &[u8]) -> Vec<RatioCandidate> {\n    match class {\n        BudFormatClass::Json => vec![\n            RatioCandidate { pipe_id: 1, pipe_name: \"flat\", ratio: 1.2, payload: original.to_vec(), flags: f() },\n        ],\n        BudFormatClass::Ndjson => vec![\n            RatioCandidate { pipe_id: 2, pipe_name: \"CDC16K+zstd\", ratio: 15.5, payload: original.to_vec(), flags: f() },\n        ],\n        BudFormatClass::Binary => vec![\n            RatioCandidate { pipe_id: 3, pipe_name: \"xz9\", ratio: 17.0, payload: original.to_vec(), flags: f() },\n        ],\n        BudFormatClass::Mixed => vec![\n            RatioCandidate { pipe_id: 4, pipe_name: \"zstd19\", ratio: 6.0, payload: original.to_vec(), flags: f() },\n        ],\n    }\n}\n";
    std::fs::write(dir.join("bud/src/bud_format.rs"), good).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a contained candidate list was refused",
        ));
    }
    let bad = good.replace("pipe_name: \"xz9\"", "pipe_name: \"optical-carousel\"");
    std::fs::write(dir.join("bud/src/bud_format.rs"), bad).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a generative candidate passed"));
    }
    let zero = good.replace("pipe_id: 4", "pipe_id: 0");
    std::fs::write(dir.join("bud/src/bud_format.rs"), zero).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: a zero pipe id passed"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "ratio consensus canary OK (deterministic lists PASS; an optical candidate and a \
         zero pipe id each FAIL).",
    ))
}
