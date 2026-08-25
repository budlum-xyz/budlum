//! README badges must match reality.
//!
//! Ported from `scripts/check-badges-are-current.sh`. Four claims: the test
//! badge count equals the last measured `N passed` in the CI log (and the log
//! is green), the CI badge pins `branch=main&event=push`, the rust badge
//! matches `rust-toolchain.toml`, and the license badge matches `Cargo.toml`
//! and links to `LICENSE.md`.

use std::path::Path;

fn read_file(root: &Path, rel: &str) -> Result<String, String> {
    let f = root.join(rel);
    std::fs::read_to_string(&f).map_err(|e| format!("missing {rel}: {e}"))
}

fn badge_count(readme: &str) -> Option<String> {
    // `tests-<N>%20lib`
    for tok in readme.split("tests-").skip(1) {
        let n: String = tok.chars().take_while(char::is_ascii_digit).collect();
        if !n.is_empty() && tok[n.len()..].starts_with("%20lib") {
            return Some(n);
        }
    }
    None
}

fn measured_count(log: &str) -> Option<String> {
    log.lines().rev().find_map(|l| {
        let idx = l.find(" passed")?;
        let num: String = l[..idx]
            .chars()
            .rev()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        if num.is_empty() {
            None
        } else {
            Some(num)
        }
    })
}

fn check_ci_badge(readme: &str) -> Result<(), String> {
    let line = readme
        .lines()
        .find(|l| l.contains("actions/workflows/ci.yml/badge.svg"))
        .ok_or_else(|| String::from("no CI badge found in README.md"))?;
    if !line.contains("badge.svg?branch=main&event=push") {
        return Err(String::from(
            "the CI badge does not pin branch and event.\n  Without `?branch=main&event=push` GitHub reports the newest run on ANY\n  branch when main has none, and otherwise reports the pull_request run,\n  which builds a merge commit that is on no branch. Use:\n      https://github.com/budlum-xyz/budlum/actions/workflows/ci.yml/badge.svg?branch=main&event=push",
        ));
    }
    if !line.contains("ci.yml?query=branch%3Amain+event%3Apush") {
        return Err(String::from(
            "the CI badge image is filtered but its link is not.\n  Point the link at the same query the image reports:\n      https://github.com/budlum-xyz/budlum/actions/workflows/ci.yml?query=branch%3Amain+event%3Apush",
        ));
    }
    Ok(())
}

fn check_rust_badge(root: &Path, readme: &str) -> Result<(), String> {
    let toolchain = read_file(root, "rust-toolchain.toml")?;
    let badge = readme
        .split("badge/rust-")
        .nth(1)
        .and_then(|r| {
            let v: String = r
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        })
        .ok_or_else(|| String::from("no rust-VERSION badge found in README.md"))?;
    let pinned = toolchain
        .lines()
        .find(|l| l.trim_start().starts_with("channel"))
        .and_then(|l| l.split('=').nth(1))
        .map(|v| v.trim().trim_matches('"').to_string())
        .ok_or_else(|| {
            String::from(
                "could not read the channel from rust-toolchain.toml - gate would be vacuous",
            )
        })?;
    if badge != pinned {
        return Err(format!(
            "README rust badge says {badge}, rust-toolchain.toml pins {pinned}"
        ));
    }
    Ok(())
}

/// Percent-decodes a shields.io badge label (`%20` -> space, `%2D` -> '-').
fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hi = hex_val(b[i + 1]);
            let lo = hex_val(b[i + 2]);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn check_license_badge(root: &Path, readme: &str) -> Result<(), String> {
    let manifest = read_file(root, "Cargo.toml")?;
    let badge = readme
        .split("badge/license-")
        .nth(1)
        .and_then(|r| {
            let head = r.split("-blue").next().unwrap_or(r);
            let decoded = url_decode(head);
            if decoded.is_empty() {
                None
            } else {
                Some(decoded)
            }
        })
        .ok_or_else(|| String::from("no license badge found in README.md"))?;
    // shields.io encodes '-' as '--' and a space as %20; the badge shows the
    // human-readable license name. Normalize it to hyphens so it lines up with
    // Cargo.toml, whose `LicenseRef-` prefix we drop below.
    let badge_canon = badge.replace("--", "-").replace(' ', "-");
    let declared = manifest
        .lines()
        .find(|l| l.trim_start().starts_with("license"))
        .and_then(|l| l.split('=').nth(1))
        .map(|v| v.trim().trim_matches('"').to_string())
        .ok_or_else(|| String::from("Cargo.toml declares no license - gate would be vacuous"))?;
    let declared_canon = declared
        .strip_prefix("LicenseRef-")
        .unwrap_or(&declared)
        .to_string();
    if badge_canon != declared_canon {
        return Err(format!(
            "README license badge says '{badge_canon}', Cargo.toml declares '{declared_canon}'"
        ));
    }
    let link = readme
        .lines()
        .find(|l| l.contains("badge/license-"))
        .ok_or_else(|| String::from("no license badge link found"))?;
    if !link.contains("](LICENSE.md)") {
        return Err(String::from(
            "the license badge does not link to LICENSE.md",
        ));
    }
    if !root.join("LICENSE.md").is_file() {
        return Err(String::from(
            "the license badge links to LICENSE.md, which does not exist",
        ));
    }
    Ok(())
}

/// # Errors
///
/// Returns a finding when any badge claim is violated.
pub fn run(root: &Path, log: &Path) -> Result<String, String> {
    if !log.is_file() {
        return Err(format!("test log missing or empty: {}", log.display()));
    }
    let log_text = std::fs::read_to_string(log).map_err(|e| e.to_string())?;
    if log_text.lines().any(|l| {
        // A red run: `<N> failed` with N > 0. `0 failed` is green.
        l.find(" failed")
            .and_then(|idx| {
                let mut i = idx;
                while i > 0 && l.as_bytes()[i - 1].is_ascii_digit() {
                    i -= 1;
                }
                let n: String = l[i..idx].chars().collect();
                n.parse::<u64>().ok().filter(|n| *n > 0).map(|_| ())
            })
            .is_some()
    }) {
        return Err(String::from(
            "test log records failures; refusing to compare badge against a red run",
        ));
    }
    let measured = measured_count(&log_text).ok_or_else(|| {
        String::from("could not parse a test count from log - gate would be vacuous")
    })?;
    let readme = read_file(root, "README.md")?;
    let badge = badge_count(&readme)
        .ok_or_else(|| String::from("no tests-N%20lib badge found in README.md"))?;
    if badge != measured {
        return Err(format!(
            "README test badge says {badge}, this run measured {measured}.\n  Update the badge in README.md in this pull request:\n      [![Tests](https://img.shields.io/badge/tests-{measured}%20lib-blue)](https://github.com/budlum-xyz/budlum/actions/workflows/ci.yml?query=branch%3Amain+event%3Apush)"
        ));
    }
    check_ci_badge(&readme)?;
    check_rust_badge(root, &readme)?;
    check_license_badge(root, &readme)?;
    Ok(format!(
        "Badge gate OK: README advertises {badge} tests, run measured {measured};\n  CI badge pins branch=main&event=push, rust badge matches rust-toolchain.toml,\n  license badge matches Cargo.toml and links to LICENSE.md."
    ))
}

/// # Errors
///
/// Returns a finding when a drifted badge or a red run passes.
pub fn self_test() -> Result<String, String> {
    let root = std::env::var_os("BUDLUM_ROOT").map_or_else(
        || std::env::current_dir().unwrap_or_default(),
        std::path::PathBuf::from,
    );
    if !root.join("README.md").is_file() {
        return Err(String::from(
            "canary: real tree not found (run from the repo root)",
        ));
    }
    let readme = read_file(&root, "README.md")?;
    let real =
        badge_count(&readme).ok_or_else(|| String::from("self-test needs a badge in README.md"))?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!(
        "budlum-gates-badges-{}-{nanos}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&dir);

    let drifted = dir.join("drifted.log");
    let n: u64 = real.parse::<u64>().map_err(|e| e.to_string())? + 1;
    std::fs::write(
        &drifted,
        format!("test result: ok. {n} passed; 0 failed; 1 ignored\n"),
    )
    .map_err(|e| e.to_string())?;
    let drift_fails = run(&root, &drifted).is_err();

    let red = dir.join("red.log");
    std::fs::write(
        &red,
        format!("test result: FAILED. {real} passed; 2 failed; 0 ignored\n"),
    )
    .map_err(|e| e.to_string())?;
    let red_fails = run(&root, &red).is_err();

    let empty = dir.join("empty.log");
    std::fs::write(&empty, "").map_err(|e| e.to_string())?;
    let empty_fails = run(&root, &empty).is_err();

    let _ = std::fs::remove_dir_all(&dir);

    if !drift_fails {
        return Err(String::from("canary: a badge one test behind was accepted"));
    }
    if !red_fails {
        return Err(String::from(
            "canary: a badge against a red run was accepted",
        ));
    }
    if !empty_fails {
        return Err(String::from("canary: empty test output was accepted"));
    }
    Ok(String::from("badge canary OK (drift/red/empty FAIL)."))
}
