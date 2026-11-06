//! Locks on how the node reads the wall clock.
//!
//! `SystemTime::now().duration_since(UNIX_EPOCH)` returns an `Err` when the
//! system clock is set before 1970. That is not a hypothetical: a container
//! started with a bad RTC, a VM restored from a snapshot, or an operator
//! typo can all produce it. Unwrapping it turns a misconfigured clock into a
//! process abort.
//!
//! The tree already knew this - `consensus/mod.rs` and `core/transaction.rs`
//! used `unwrap_or_default()` - but 19 other call sites did not, including
//! `Block::new` on the consensus path and fourteen RPC handlers reachable
//! from a public endpoint. These tests pin the convention so the two halves
//! cannot drift apart again.
//!
//! Falling back to zero is not a silent wrong answer here: a zero timestamp
//! is outside `MAX_PAST_BLOCK_TIME_MS` and fails `validate_timestamp`'s
//! monotonicity check, so a block built under a broken clock is rejected
//! rather than accepted with a bogus time.

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file under `src/`, excluding the test tree itself.
fn production_sources() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "tests") {
                    continue;
                }
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(&repo_root().join("src"), &mut out);
    out
}

/// Strip `#[cfg(test)]` modules so a test helper's `unwrap()` is not counted
/// as a production panic.
fn without_test_modules(body: &str) -> String {
    let mut kept = Vec::new();
    let mut depth: Option<i32> = None;
    let mut armed = false;
    for line in body.lines() {
        let trimmed = line.trim();
        if depth.is_none() {
            if trimmed.starts_with("#[cfg(test)]") {
                armed = true;
                continue;
            }
            if armed {
                if !line.contains('{') && trimmed.ends_with(';') {
                    // A braceless item such as `#[cfg(test)] use ...;`.
                    armed = false;
                    continue;
                }
                if line.contains('{') {
                    let d = line.matches('{').count() as i32 - line.matches('}').count() as i32;
                    if d > 0 {
                        depth = Some(d);
                    } else {
                        armed = false;
                    }
                }
                continue;
            }
            kept.push(line);
        } else {
            let d = depth.unwrap_or(0) + line.matches('{').count() as i32
                - line.matches('}').count() as i32;
            if d <= 0 {
                depth = None;
                armed = false;
            } else {
                depth = Some(d);
            }
        }
    }
    kept.join("\n")
}

/// Clock reads whose `Err` is turned into a panic: `.unwrap()` or `.expect(`
/// within the call and the next two lines, with no fallback in the window.
fn panicking_clock_reads(body: &str) -> Vec<String> {
    let lines: Vec<&str> = body.lines().collect();
    let mut found = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if !line.contains("duration_since") {
            continue;
        }
        let window = lines[i..(i + 5).min(lines.len())].join("\n");
        if !window.contains("UNIX_EPOCH") {
            continue;
        }
        let panics = (window.contains(".unwrap()") || window.contains(".expect("))
            && !window.contains(".unwrap_or");
        if panics {
            found.push(line.trim().to_string());
        }
    }
    found
}

#[test]
fn no_production_code_unwraps_the_wall_clock() {
    let mut offenders = Vec::new();
    for path in production_sources() {
        let Ok(raw) = fs::read_to_string(&path) else {
            continue;
        };
        let rel = path
            .strip_prefix(repo_root())
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        for line in panicking_clock_reads(&without_test_modules(&raw)) {
            offenders.push(format!("{rel}: {line}"));
        }
    }
    assert!(
        offenders.is_empty(),
        "a clock set before 1970 would abort the process at these call sites; \
         use `unwrap_or_default()` like consensus/mod.rs does:\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn the_clock_scan_detects_planted_violations() {
    let unwrap_split = "let t = SystemTime::now()\n    .duration_since(\n        UNIX_EPOCH,\n    )\n    .unwrap();";
    let expect_one = "let t = SystemTime::now().duration_since(UNIX_EPOCH).expect(\"clock\");";
    let safe = "let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();";
    assert_eq!(panicking_clock_reads(unwrap_split).len(), 1);
    assert_eq!(panicking_clock_reads(expect_one).len(), 1);
    assert!(panicking_clock_reads(safe).is_empty());
    let kept = without_test_modules("#[cfg(test)]\nuse std::fs;\nfn live() {\n    body();\n}\n");
    assert!(
        kept.contains("body();"),
        "a braceless test item must not hide the next block"
    );
}

#[test]
fn a_zero_timestamp_block_is_refused_rather_than_accepted() {
    // The fallback has to fail closed. If a broken clock produced a zero
    // timestamp and the chain accepted it, replacing a panic with silent
    // corruption would be the worse trade.
    use crate::consensus::poa::PoAConfig;
    use crate::consensus::{ConsensusEngine, PoAEngine};
    use crate::core::account::AccountState;
    use crate::core::block::Block;

    let engine = PoAEngine::new(PoAConfig::default(), None);
    let state = AccountState::new();

    let mut prev = Block::new(1, "0".repeat(64), vec![]);
    prev.timestamp = 1_700_000_000_000;
    prev.hash = prev.calculate_hash();

    let mut broken = Block::new(2, prev.hash.clone(), vec![]);
    broken.timestamp = 0;
    broken.hash = broken.calculate_hash();

    let chain = vec![prev];
    assert!(
        engine.full_validate(&broken, &chain, &state).is_err(),
        "a zero timestamp is not monotonic against a real predecessor and must \
         be refused"
    );
}

#[test]
fn the_safe_idiom_is_what_the_consensus_layer_already_used() {
    // The convention was not invented here: this records where it came from,
    // so a future reader can see the two halves were made consistent rather
    // than a new rule being imposed.
    let consensus = fs::read_to_string(repo_root().join("src/consensus/mod.rs"))
        .expect("consensus/mod.rs is readable");
    assert!(
        consensus.contains("duration_since(std::time::UNIX_EPOCH)")
            && consensus.contains("unwrap_or_default()"),
        "consensus/mod.rs is the reference for this idiom; if it changed, this \
         lock and the convention need revisiting together"
    );
}
