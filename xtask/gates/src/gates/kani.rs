//! Model-checking gate for bond arithmetic.
//!
//! Ported from `scripts/check-kani.sh`. The shell gate ran real harnesses
//! (`kani/src/lib.rs`) and checked two things, because either alone can pass
//! while the property is unverified:
//!
//!   1. A Kani run log reports `VERIFICATION:- SUCCESSFUL` and no failures.
//!   2. The number of harnesses Kani actually ran matches the number declared
//!      in the source. A proof that silently stops being compiled, a stray
//!      `cfg`, a renamed module, a harness filtered out by a `--harness` flag
//!      that no longer matches, would otherwise leave the gate green with
//!      nothing behind it.
//!
//! The port keeps the shell gate's counts, its fast/slow split driven by the
//! `// SLOW:` marker, the stray-marker vacuity rule, the module path helper
//! and every canary, so the two gates agree on every fixture.
//!
//! # Modes
//!
//! * `kani <kani-output-log>` - the gate, counting a real Kani run.
//! * `kani --fast-names` / `kani --slow-names` - harness names split by the
//!   marker, for the workflow's `--harness` selection.
//! * `kani --module-path` - the fully qualified module the harnesses live in.
//! * `kani --self-test` - the canary set.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// The proofs file, exactly where the shell gate pointed.
fn proofs_path(root: &Path) -> PathBuf {
    root.join("kani/src/lib.rs")
}

/// How many `#[kani::proof]` attributes sit above a `fn` in the proofs file,
/// and how many `// SLOW:` markers there are, in the shell gate's sense.
struct HarnessCounts {
    total: usize,
    slow: usize,
}

fn count_proofs(path: &Path) -> Result<HarnessCounts, String> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let lines: Vec<&str> = text.lines().collect();
    let total = lines
        .iter()
        .filter(|line| line.contains("#[kani::proof]"))
        .count();
    let slow = lines
        .iter()
        .filter(|line| line.trim_start().starts_with("// SLOW:"))
        .count();
    Ok(HarnessCounts { total, slow })
}

/// The count a pull-request run has to match: total minus the marked-slow
/// harnesses, unless the all-scope restores the full count.
///
/// A marker that does not sit above a `#[kani::proof]` would shrink the
/// expected count without excluding anything, which is the vacuous direction,
/// so it is rejected exactly like the shell gate rejected it.
fn declared_count(path: &Path, scope_all: bool) -> Result<usize, String> {
    if !path.is_file() {
        return Err(format!("harness file missing: {}", path.display()));
    }
    let counts = count_proofs(path)?;
    if scope_all {
        return Ok(counts.total);
    }
    let mut marked_proofs = 0usize;
    let source =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let lines: Vec<&str> = source.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        if line.trim_start().starts_with("// SLOW:")
            && lines
                .get(idx + 1)
                .is_some_and(|next| next.contains("#[kani::proof]"))
        {
            marked_proofs += 1;
        }
    }
    if counts.slow != marked_proofs {
        return Err(format!(
            "{} SLOW markers but {marked_proofs} of them sit above a #[kani::proof]; \
             a stray marker would lower the expected count without excluding a harness",
            counts.slow
        ));
    }
    Ok(counts.total - counts.slow)
}

/// If the trimmed line is `fn <name>(`, return the name.
fn fn_name(trimmed: &str) -> Option<&str> {
    let rest = trimmed.strip_prefix("fn ")?;
    let mut end = 0usize;
    for ch in rest.chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' {
            end += ch.len_utf8();
        } else {
            break;
        }
    }
    if end == 0 {
        return None;
    }
    rest[end..].starts_with('(').then(|| &rest[..end])
}

/// The first `fn <name>(` inside a window of text, if any.
fn first_fn_name(window: &str) -> Option<String> {
    let mut idx = 0usize;
    while idx < window.len() {
        let rel = window[idx..].find("fn ")? + idx;
        let start = rel + "fn ".len();
        let mut end = start;
        for ch in window[start..].chars() {
            if ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' {
                end += ch.len_utf8();
            } else {
                break;
            }
        }
        if end > start && window[end..].starts_with('(') {
            return Some(window[start..end].to_string());
        }
        idx = start;
    }
    None
}

/// Names that carry a `#[kani::proof]` attribute: from each attribute, walk
/// forward to the next `fn <name>(` before the closing brace.
fn harness_set(text: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    let mut idx = 0usize;
    while let Some(rel) = text[idx..].find("#[kani::proof]") {
        let attr = idx + rel;
        let tail = &text[attr + "#[kani::proof]".len()..];
        let window_end = tail.find('}').unwrap_or(tail.len());
        if let Some(name) = first_fn_name(&tail[..window_end]) {
            set.insert(name);
        }
        idx = attr + "#[kani::proof]".len() + 1;
    }
    set
}

/// The harness names, split by the `// SLOW:` marker, in file order. A name
/// counts as a harness only when a `#[kani::proof]` attribute sits above it,
/// mirroring the shell gate's two-pass scan.
fn harness_names(path: &Path, want_slow: bool) -> Result<Vec<String>, String> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let lines: Vec<&str> = text.lines().collect();

    // First pass: every `fn name(` with the slow flag in effect at that point.
    // A marker applies to the next function, through doc comments and
    // attributes; a blank line or a closing brace ends its run.
    let mut out: Vec<(String, bool)> = Vec::new();
    let mut marked = false;
    for line in &lines {
        let trimmed = line.trim();
        if trimmed.starts_with("// SLOW:") {
            marked = true;
            continue;
        }
        if let Some(name) = fn_name(trimmed) {
            out.push((name.to_string(), marked));
            marked = false;
            continue;
        }
        if !trimmed.is_empty()
            && !trimmed.starts_with("///")
            && !trimmed.starts_with("//!")
            && !trimmed.starts_with("//")
            && !trimmed.starts_with("#[")
        {
            marked = false;
        }
    }

    // Reduce to harnesses only: a name is a harness when the attribute appears
    // above it, checked by rescanning with the attribute in view.
    let harnesses = harness_set(&text);
    let mut result = Vec::new();
    for (name, slow) in out {
        if harnesses.contains(&name) && want_slow == slow {
            result.push(name);
        }
    }
    Ok(result)
}

/// The module path a fully-qualified harness name would need. Kept because
/// the next person will try `--exact` again; the workflow filters on the bare
/// name instead and relies on the harness count for exactness.
fn harness_module_path(root: &Path) -> Result<String, String> {
    let manifest = root.join("kani/Cargo.toml");
    let toml = fs::read_to_string(&manifest)
        .map_err(|e| format!("cannot read {}: {e}", manifest.display()))?;
    let crate_name = toml
        .lines()
        .find_map(|line| {
            let line = line.trim();
            line.strip_prefix("name = \"")
                .and_then(|rest| rest.strip_suffix('"'))
        })
        .ok_or_else(|| String::from("could not read the crate name from kani/Cargo.toml"))?
        .replace('-', "_");
    let lib = fs::read_to_string(root.join("kani/src/lib.rs"))
        .map_err(|e| format!("cannot read kani/src/lib.rs: {e}"))?;
    let module = lib
        .lines()
        .find_map(|line| {
            let line = line.trim();
            let name = line
                .strip_prefix("pub mod ")
                .or_else(|| line.strip_prefix("mod "))?
                .strip_suffix(" {")?;
            (name.chars().all(|c| c.is_ascii_lowercase() || c == '_')).then_some(name)
        })
        .ok_or_else(|| String::from("could not find the module the harnesses live in"))?;
    Ok(format!("{crate_name}::{module}"))
}

/// The gate itself: a Kani output log plus the declared harness count.
fn gate(log: &Path, declared: usize) -> Result<String, String> {
    let meta = fs::metadata(log)
        .map_err(|_| format!("kani output missing or empty: {}", log.display()))?;
    if meta.len() == 0 {
        return Err(format!("kani output missing or empty: {}", log.display()));
    }
    let text =
        fs::read_to_string(log).map_err(|e| format!("cannot read {}: {e}", log.display()))?;
    let lines: Vec<&str> = text.lines().collect();

    if lines
        .iter()
        .any(|line| line.starts_with("VERIFICATION:- FAILED"))
    {
        let mut msg = String::from("--- failing checks ---\n");
        for line in &lines {
            if line.contains("Failed Checks") || line.starts_with("VERIFICATION:- FAILED") {
                msg.push_str(line);
                msg.push('\n');
            }
        }
        msg.push_str("a Kani proof failed");
        return Err(msg);
    }

    let successful = lines
        .iter()
        .filter(|line| line.starts_with("VERIFICATION:- SUCCESSFUL"))
        .count();
    if successful == 0 {
        return Err(String::from(
            "no successful verification in output - did Kani run at all?",
        ));
    }
    if successful != declared {
        return Err(format!(
            "Kani verified {successful} harness(es) but {declared} are declared in \
             kani/src/lib.rs - a proof stopped running without anyone noticing"
        ));
    }

    Ok(format!(
        "Kani gate OK: {successful}/{declared} harnesses verified."
    ))
}

/// # Errors
///
/// Returns a finding when the Kani run failed, produced no success, or ran
/// fewer harnesses than declared.
pub fn run_args(root: &Path, args: &[&str]) -> Result<String, String> {
    match args {
        ["--slow-names"] => Ok(harness_names(&proofs_path(root), true)?.join("\n")),
        ["--fast-names"] => Ok(harness_names(&proofs_path(root), false)?.join("\n")),
        ["--module-path"] => harness_module_path(root),
        [log] => {
            let declared = declared_count(&proofs_path(root), false)?;
            gate(Path::new(log), declared)
        }
        _ => Err(String::from(
            "usage: kani <kani-output-log> | --fast-names | --slow-names | --module-path",
        )),
    }
}

fn scratch_dir() -> Result<PathBuf, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir =
        std::env::temp_dir().join(format!("budlum-gates-kani-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create scratch dir: {e}"))?;
    Ok(dir)
}

/// # Errors
///
/// Returns the first canary that misbehaves. The canaries mirror the shell
/// gate's one for one: a failing proof fails, empty output fails, a short run
/// fails, a full run passes, a stray SLOW marker is rejected, the fast/slow
/// split counts 2/3 on its fixture, and the split names its exclusions.
pub fn self_test() -> Result<String, String> {
    let root = std::env::var_os("BUDLUM_ROOT").map_or_else(
        || std::env::current_dir().unwrap_or_default(),
        PathBuf::from,
    );
    let proofs = proofs_path(&root);
    if !proofs.is_file() {
        return Err(String::from(
            "canary: real tree not found (run from the repo root)",
        ));
    }
    let declared = declared_count(&proofs, false)?;
    let tmp = scratch_dir()?;

    // 1. A failing proof must fail the gate.
    fs::write(
        tmp.join("failed.log"),
        "Checking harness penalty_never_exceeds_stake...\nVERIFICATION:- FAILED\n",
    )
    .map_err(|e| e.to_string())?;
    if gate(&tmp.join("failed.log"), declared).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "VACUOUS GATE: a FAILED verification was accepted!",
        ));
    }

    // 2. Empty output must fail, the case where Kani never ran.
    fs::write(tmp.join("empty.log"), "").map_err(|e| e.to_string())?;
    if gate(&tmp.join("empty.log"), declared).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "VACUOUS GATE: empty Kani output was accepted!",
        ));
    }

    // 3. Fewer harnesses than declared must fail, even though every one that
    //    ran succeeded. This is the specific way the previous script was
    //    hollow.
    fs::write(tmp.join("short.log"), "VERIFICATION:- SUCCESSFUL\n").map_err(|e| e.to_string())?;
    if declared > 1 && gate(&tmp.join("short.log"), declared).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!(
            "VACUOUS GATE: {declared} declared but 1 verified was accepted!"
        ));
    }

    // 4. A full, clean run must pass, or the gate rejects everything.
    let mut ok_log = String::new();
    for _ in 0..declared {
        ok_log.push_str("VERIFICATION:- SUCCESSFUL\n");
    }
    fs::write(tmp.join("ok.log"), ok_log).map_err(|e| e.to_string())?;
    if gate(&tmp.join("ok.log"), declared).is_err() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!(
            "BROKEN GATE: a clean run of all {declared} harnesses was rejected!"
        ));
    }

    // 5. A `// SLOW:` marker that does not sit above a `#[kani::proof]` lowers
    //    the expected count while excluding nothing, so it has to be rejected.
    let stray = tmp.join("stray.rs");
    fs::write(
        &stray,
        "    // SLOW: not above a proof at all\n    fn helper() {}\n    #[kani::proof]\n    fn a() {}\n    #[kani::proof]\n    fn b() {}\n",
    )
    .map_err(|e| e.to_string())?;
    if declared_count(&stray, false).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "VACUOUS GATE: a stray SLOW marker was accepted; it would lower the \
             expected count without excluding a harness!",
        ));
    }

    // 6. A well-formed split must produce total-minus-slow, and `all` must
    //    produce the total. If these ever coincide the split is doing nothing.
    let split = tmp.join("split.rs");
    fs::write(
        &split,
        "    #[kani::proof]\n    fn fast_one() {}\n    #[kani::proof]\n    fn fast_two() {}\n    // SLOW: measured, does not close in CI budget\n    #[kani::proof]\n    fn slow_one() {}\n",
    )
    .map_err(|e| e.to_string())?;
    let fast_n = declared_count(&split, false)?;
    let all_n = declared_count(&split, true)?;
    if fast_n != 2 || all_n != 3 {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!(
            "BROKEN GATE: fast count was {fast_n}, all count was {all_n}, expected 2/3"
        ));
    }

    // 7. The workflow needs the slow names to exclude them, and a rename must
    //    show up here rather than silently dropping an exclusion.
    let names = harness_names(&split, true)?;
    if names != ["slow_one"] {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!(
            "BROKEN GATE: slow names came out as '{}', expected 'slow_one'",
            names.join(",")
        ));
    }

    let _ = fs::remove_dir_all(&tmp);
    Ok(String::from(
        "kani gate self-test OK: failure, empty output and a short run all rejected; \
         a full run passes; the fast/slow split counts 2/3 and names its exclusions.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        scratch_dir().expect("scratch dir")
    }

    #[test]
    fn fn_name_parses_only_harness_shaped_lines() {
        assert_eq!(
            fn_name("fn penalty_never_exceeds_stake() {"),
            Some("penalty_never_exceeds_stake")
        );
        assert_eq!(fn_name("fn x () {"), None);
        assert_eq!(fn_name("not a fn"), None);
        assert_eq!(fn_name("fn _() {"), Some("_"));
    }

    #[test]
    fn split_fixture_counts() {
        let d = scratch();
        let split = d.join("split.rs");
        fs::write(
            &split,
            "    #[kani::proof]\n    fn fast_one() {}\n    #[kani::proof]\n    fn fast_two() {}\n    // SLOW: measured\n    #[kani::proof]\n    fn slow_one() {}\n",
        )
        .expect("fixture");
        assert_eq!(declared_count(&split, false).expect("fast"), 2);
        assert_eq!(declared_count(&split, true).expect("all"), 3);
        let slow = harness_names(&split, true).expect("slow names");
        assert_eq!(slow, ["slow_one"]);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn stray_marker_is_rejected() {
        let d = scratch();
        let stray = d.join("stray.rs");
        fs::write(
            &stray,
            "    // SLOW: not above a proof at all\n    fn helper() {}\n    #[kani::proof]\n    fn a() {}\n",
        )
        .expect("fixture");
        assert!(declared_count(&stray, false).is_err());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn gate_accepts_a_full_run_and_rejects_shorter_ones() {
        let d = scratch();
        let log = d.join("run.log");
        fs::write(
            &log,
            "VERIFICATION:- SUCCESSFUL\nVERIFICATION:- SUCCESSFUL\n",
        )
        .expect("log");
        assert!(gate(&log, 2).is_ok());
        assert!(gate(&log, 3).is_err());
        fs::write(&log, "VERIFICATION:- FAILED\n").expect("log");
        assert!(gate(&log, 1).is_err());
        let _ = fs::remove_dir_all(&d);
    }
}
