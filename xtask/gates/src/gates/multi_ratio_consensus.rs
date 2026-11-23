//! What the ratio consensus is allowed to offer.
//!
//! Gate code: `K-MULTI-RATIO-FRACTAL`. A finding or a document that names this code resolves here.
//!
//! `MultiRatioConsensus::candidates_for_format` is the list a node votes on.
//! It measures the ratios of the list that `claimed_candidates` writes, so the
//! gate reads `claimed_candidates`.
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

/// The number of match arms that offer at least one candidate: `=> vec![` not
/// followed at once by `]`.
fn non_empty_arms(body: &str) -> usize {
    body.match_indices("=> vec![")
        .filter(|(i, m)| !body[i + m.len()..].trim_start().starts_with(']'))
        .count()
}

/// The f64 literal after `ratio:` in one candidate literal.
fn ratio_of(candidate: &str) -> Option<f64> {
    let (_, rest) = candidate.split_once("ratio:")?;
    let lit: String = rest
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit() || matches!(c, '.' | '_' | 'e' | 'E' | '-' | '+'))
        .filter(|c| *c != '_')
        .collect();
    lit.parse::<f64>().ok()
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

/// The successor surface: B.U.D. 3.0's own module tree.
const SUCCESSOR_ROOTS: [&str; 2] = ["src/storage/bud3", "src/storage"];

/// Every `.rs` file under [`SUCCESSOR_ROOTS`], sorted, so the walk is
/// deterministic and a canary tree is measured the same way as the real one.
fn successor_sources(root: &Path) -> Result<Vec<(String, String)>, String> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for rel in SUCCESSOR_ROOTS {
        let base = root.join(rel);
        if !base.is_dir() {
            continue;
        }
        walk_rs(&base, &mut out, &mut seen)?;
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn walk_rs(
    dir: &Path,
    out: &mut Vec<(String, String)>,
    seen: &mut std::collections::BTreeSet<String>,
) -> Result<(), String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    let mut entries: Vec<_> = rd.filter_map(Result::ok).collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let kind = entry
            .file_type()
            .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
        if kind.is_dir() {
            walk_rs(&path, out, seen)?;
        } else if path.extension().is_some_and(|x| x == "rs") {
            let key = path.to_string_lossy().replace('\\', "/");
            if !seen.insert(key.clone()) {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            out.push((key, text));
        }
    }
    Ok(())
}

/// The retired tree's absence must not retire the invariant.
///
/// The earlier `bud/`-only arm returned `Ok` as soon as the directory was gone.
/// That made the gate pass by deletion: a generative or optical candidate list
/// could reappear in the successor B.U.D. 3.0 tree and the gate would still
/// report the ratio consensus as contained. The measurement below is the
/// surviving half of the same claim - no candidate list may name a generative
/// pipeline - and it reads the successor tree wherever the legacy one is gone.
fn missing_bud_format(root: &Path, f: &Path) -> Result<String, String> {
    if root.join("bud").exists() {
        return Err(format!("no bud_format.rs at {}", f.display()));
    }
    let sources = successor_sources(root)?;
    if sources.is_empty() {
        return Err(String::from(
            "the standalone bud/ ratio tree is gone and no successor B.U.D. 3.0 source \
             (src/storage/bud3) was found; a ratio consensus that cannot be read is not \
             a ratio consensus that was checked",
        ));
    }
    let mut offenders: Vec<String> = Vec::new();
    let mut candidate_lists = 0usize;
    for (path, text) in &sources {
        let lower = text.to_lowercase();
        if lower.contains("ratiocandidate {") {
            candidate_lists += 1;
            for needle in FORBIDDEN {
                if lower.contains(needle) {
                    offenders.push(format!("{path} names `{needle}`"));
                }
            }
        }
    }
    if let Some(first) = offenders.first() {
        return Err(format!(
            "the successor B.U.D. 3.0 ratio surface offers a pipeline a vote cannot \
             reproduce ({first}); {} offending site(s) in {candidate_lists} candidate \
             list(s)",
            offenders.len()
        ));
    }
    Ok(format!(
        "multi-ratio-consensus OK: standalone bud/ legacy ratio tree removed; {} successor \
         B.U.D. 3.0 source file(s) measured in src/storage/bud3, {candidate_lists} candidate \
         list(s), none naming a generative or optical pipeline.",
        sources.len()
    ))
}

/// # Errors
///
/// Returns the list of violated claims.
pub fn run(root: &Path) -> Result<String, String> {
    let f = root.join("bud/src/bud_format.rs");
    if !f.is_file() {
        return missing_bud_format(root, &f);
    }
    let src = std::fs::read_to_string(&f).map_err(|e| e.to_string())?;
    // `candidates_for_format` only measures the ratios; the list itself is
    // written in `claimed_candidates`.
    let body = body_of(&src, "claimed_candidates")
        .ok_or_else(|| "no `fn claimed_candidates` in `bud/src/bud_format.rs`".to_string())?;
    let list = candidates(&body);
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;

    let arms = non_empty_arms(&body);
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
        match ratio_of(c) {
            Some(r) if r.is_finite() && r > 1.0 => checked += 1,
            Some(r) => problems.push(format!(
                "candidate #{n} has ratio {r}; a candidate ratio has to be finite and above one."
            )),
            None => problems.push(format!("candidate #{n} declares no readable `ratio`.")),
        }
    }
    if ids.is_empty() {
        problems.push(String::from(
            "no pipe id could be read from the candidate list.",
        ));
    }
    let mut sorted_ids = ids.clone();
    sorted_ids.sort_unstable();
    if sorted_ids.windows(2).any(|w| w[0] == w[1]) {
        problems.push(String::from(
            "two candidates share one `pipe_id`; the settlement records the id, so a shared id \
             cannot say which pipeline won.",
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
    let good = "fn claimed_candidates(class: BudFormatClass, original: &[u8]) -> Vec<RatioCandidate> {\n    match class {\n        BudFormatClass::Json => vec![\n            RatioCandidate { pipe_id: 1, pipe_name: \"flat\", ratio: 1.2, payload: original.to_vec(), flags: f() },\n        ],\n        BudFormatClass::Ndjson => vec![\n            RatioCandidate { pipe_id: 2, pipe_name: \"CDC16K+zstd\", ratio: 15.5, payload: original.to_vec(), flags: f() },\n        ],\n        BudFormatClass::Binary => vec![\n            RatioCandidate { pipe_id: 3, pipe_name: \"xz9\", ratio: 17.0, payload: original.to_vec(), flags: f() },\n        ],\n        BudFormatClass::Mixed => vec![\n            RatioCandidate { pipe_id: 4, pipe_name: \"zstd19\", ratio: 6.0, payload: original.to_vec(), flags: f() },\n        ],\n    }\n}\n";
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
    // The retired tree must not retire the invariant. With `bud/` gone and the
    // successor B.U.D. 3.0 tree present, a reappeared generative candidate has
    // to fail - and an absent successor tree has to fail as unreadable rather
    // than pass.
    let successor = dir.join("src/storage/bud3");
    std::fs::create_dir_all(&successor).map_err(|e| e.to_string())?;
    std::fs::write(successor.join("pipeline.rs"), "pub struct Pipeline;\n")
        .map_err(|e| e.to_string())?;
    std::fs::remove_dir_all(dir.join("bud")).map_err(|e| e.to_string())?;
    std::fs::remove_dir_all(&successor).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: with the legacy tree removed and no successor tree, the gate passed as \
             unreadable",
        ));
    }
    std::fs::create_dir_all(&successor).map_err(|e| e.to_string())?;
    std::fs::write(successor.join("pipeline.rs"), "pub struct Pipeline;\n")
        .map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a contained successor tree with no candidate list was refused",
        ));
    }
    std::fs::write(
        successor.join("ratio_choice.rs"),
        "pub fn candidates() -> Vec<RatioCandidate> {\n    vec![RatioCandidate { pipe_id: 7, \
         pipe_name: \"optical-carousel\", ratio: 12.0 }]\n}\n",
    )
    .map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a generative candidate reappearing in the successor tree passed",
        ));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "ratio consensus canary OK (deterministic lists PASS; an optical candidate and a \
         zero pipe id each FAIL).",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratio_and_empty_arms_are_read() {
        assert_eq!(ratio_of("RatioCandidate { ratio: 17.19, x }"), Some(17.19));
        assert_eq!(ratio_of("RatioCandidate { ratio: 0.0, x }"), Some(0.0));
        assert_eq!(ratio_of("RatioCandidate { ratio: f64::NAN, x }"), None);
        assert_eq!(
            non_empty_arms("A => vec![], B => vec![ R {} ], C => vec![\n],"),
            1
        );
    }
}
