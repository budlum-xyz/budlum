//! README badges must match reality.
//!
//! Both READMEs are checked. `README.tr.md` repeats the same four claims in
//! Turkish and was unprotected until 2026-09-24: it advertised 2885 tests
//! while `README.md` advertised 3219, a drift of 334 that no gate could see.
//! A translated claim is still a claim.
//!
//! Ported from `scripts/check-badges-are-current.sh`. Four claims: the test
//! badge count equals the last measured `N passed` in the CI log (and the log
//! is green), the CI badge pins `event=push` on a branch that `.github/workflows/ci.yml`
//! actually triggers a push run on, the rust badge matches `rust-toolchain.toml`,
//! and the license badge matches `Cargo.toml` and links to `LICENSE.md`.
//!
//! Measured 2026-11-27: a pin can name a real branch and still render nothing.
//! `ci.yml` triggers `push` on `main` only; the repository's default branch is
//! `consensus-of-consensuses`, which therefore has no push run since
//! 2026-11-10. GitHub renders that pin as `<title>CI - no status</title>` - a
//! badge with no verdict in it - while `badges-are-current` stayed green
//! because the pin did name one branch and one event. The push trigger is read
//! here for that reason: the pin has to be a branch this workflow runs on.

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
        // Only a libtest summary line counts, not any line that says "passed".
        if !l.trim_start().starts_with("test result:") {
            return None;
        }
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

/// The branches `ci.yml` triggers a `push` run on.
///
/// `None` when the file has no `on: push:` section this reader can see - the
/// caller treats that as a finding, not as "no restriction": a trigger that
/// could not be read cannot vouch for a pin.
fn push_branches(ci_yml: &str) -> Option<Vec<String>> {
    let mut in_push = false;
    for line in ci_yml.lines() {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if trimmed.starts_with("on:") && indent == 0 {
            in_push = false;
            continue;
        }
        if trimmed.starts_with("push:") && indent > 0 {
            in_push = true;
            continue;
        }
        if !in_push {
            continue;
        }
        // Any other event at the same or lower indent ends the push block.
        if indent <= 2 && !trimmed.starts_with("branches") {
            in_push = false;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("branches:") {
            let rest = rest.trim();
            if let Some(inner) = rest.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
                let list: Vec<String> = inner
                    .split(',')
                    .map(|b| b.trim().trim_matches('"').trim_matches('\'').to_string())
                    .filter(|b| !b.is_empty())
                    .collect();
                if !list.is_empty() {
                    return Some(list);
                }
            }
        }
    }
    None
}

/// The branch names a README may pin.
///
/// The repository's default branch is `consensus-of-consensuses`, but the
/// branch this gate and the whole test suite actually run on - the one whose
/// run the test badge counts - is `main`. Both spellings are accepted so a tree
/// that has not been re-badged is not red for a wording change; the pinned pair
/// has to agree, and the branch has to be one `ci.yml` pushes to (checked in
/// `check_ci_badge`, which reads the trigger).
const ACCEPTED_PINS: [&str; 2] = ["main", "consensus-of-consensuses"];

fn check_ci_badge(root: &Path, readme: &str) -> Result<(), String> {
    let line = readme
        .lines()
        .find(|l| l.contains("actions/workflows/ci.yml/badge.svg"))
        .ok_or_else(|| String::from("no CI badge found in README.md"))?;
    let pinned = ACCEPTED_PINS.iter().find(|b| {
        line.contains(&format!("badge.svg?branch={b}&event=push"))
            && line.contains(&format!("ci.yml?query=branch%3A{b}+event%3Apush"))
    });
    let Some(pinned) = pinned else {
        return Err(String::from(
            "the CI badge does not pin one branch and event, image and link together.\n  Without `?branch=main&event=push` GitHub reports the newest run on ANY branch when\n  that branch has none, and otherwise reports the pull_request run, which builds a\n  merge commit that is on no branch. Use (both sides the same branch):\n      https://github.com/budlum-xyz/budlum/actions/workflows/ci.yml/badge.svg?branch=main&event=push",
        ));
    };
    // A pin that names a branch `ci.yml` never pushes to renders `no status`:
    // GitHub has no verdict to show, so the badge says nothing while the gate
    // says fine. Measured 2026-11-27 - `consensus-of-consensuses` is the default
    // branch and its last push run is from 2026-11-10 (3895 tests, a different
    // tree), while `main` renders `passing`.
    let ci = read_file(root, ".github/workflows/ci.yml")?;
    let pushed = push_branches(&ci).ok_or_else(|| {
        String::from(
            "could not read the `push:` trigger of .github/workflows/ci.yml - the gate cannot tell\n  whether the pinned branch ever produces a run, and would be vacuous",
        )
    })?;
    if !pushed.iter().any(|b| b == pinned) {
        return Err(format!(
            "the CI badge pins `{pinned}`, but ci.yml triggers `push` on {pushed:?}.\n  A pin to a branch with no push run renders `<title>CI - no status</title>`: no verdict,\n  measured 2026-11-27 on the default branch `consensus-of-consensuses` (last push run\n  2026-11-10). Pin the branch the tests run on, image and link together:\n      https://github.com/budlum-xyz/budlum/actions/workflows/ci.yml/badge.svg?branch={pinned}&event=push"
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
            "README test badge says {badge}, this run measured {measured}.\n  Update the badge in README.md in this pull request:\n      [![Tests](https://img.shields.io/badge/tests-{measured}%20lib-blue)](https://github.com/budlum-xyz/budlum/actions/workflows/ci.yml?query=branch%3Aconsensus-of-consensuses+event%3Apush)"
        ));
    }
    check_ci_badge(root, &readme)?;
    check_rust_badge(root, &readme)?;
    check_license_badge(root, &readme)?;

    // The Turkish README makes the same claims to a different audience. If it
    // is present it is held to the same measurement; a stale translation is a
    // stale claim, not a formatting detail.
    let translated = root.join("README.tr.md");
    let tr_note = if translated.is_file() {
        let tr = read_file(root, "README.tr.md")?;
        let tr_badge = badge_count(&tr).ok_or_else(|| {
            String::from("no tests-N%20lib badge found in README.tr.md - gate would be vacuous")
        })?;
        if tr_badge != measured {
            return Err(format!(
                "README.tr.md test badge says {tr_badge}, this run measured {measured} (README.md says {badge}).\n  Update the Turkish badge in the same pull request:\n      [![Tests](https://img.shields.io/badge/tests-{measured}%20lib-blue)](https://github.com/budlum-xyz/budlum/actions/workflows/ci.yml?query=branch%3Aconsensus-of-consensuses+event%3Apush)"
            ));
        }
        check_ci_badge(root, &tr)?;
        check_rust_badge(root, &tr)?;
        check_license_badge(root, &tr)?;
        " README.tr.md carries the same count and pins."
    } else {
        ""
    };

    Ok(format!(
        "Badge gate OK: README advertises {badge} tests, run measured {measured};\n  CI badge pins one branch and event, rust badge matches rust-toolchain.toml,\n  license badge matches Cargo.toml and links to LICENSE.md.{tr_note}"
    ))
}

/// The CI-pin canary: a pin to a branch `ci.yml` never pushes to renders
/// `no status`, and the same tree with a live pin has to pass.
///
/// Split out of `self_test` because that function is at its own line budget;
/// the canary is unchanged by the move.
fn pin_canary(
    root: &Path,
    readme: &str,
    real: &str,
    dir: &Path,
) -> Result<(bool, bool, bool, bool, bool), String> {
    // A pin to a branch `ci.yml` never pushes to renders `no status` and has
    // to fail; the same tree with the pin on the push-triggered branch has to
    // pass. Built from the real README so the rest of the gate is unchanged.
    let ci = read_file(root, ".github/workflows/ci.yml")?;
    let pushed = push_branches(&ci);
    let scratch_root = dir.join("pin-root");
    std::fs::create_dir(&scratch_root).map_err(|e| e.to_string())?;
    for rel in [
        "README.md",
        "Cargo.toml",
        "rust-toolchain.toml",
        "LICENSE.md",
    ] {
        std::fs::copy(root.join(rel), scratch_root.join(rel))
            .map_err(|e| format!("copy {rel} into CI pin canary: {e}"))?;
    }
    let ci_path = scratch_root.join(".github/workflows/ci.yml");
    std::fs::create_dir_all(ci_path.parent().unwrap_or(&scratch_root))
        .map_err(|e| e.to_string())?;
    std::fs::write(&ci_path, &ci).map_err(|e| e.to_string())?;
    let log = dir.join("pin.log");
    std::fs::write(
        &log,
        format!("test result: ok. {real} passed; 0 failed; 1 ignored\n"),
    )
    .map_err(|e| e.to_string())?;
    // The tree as committed has to pass first, otherwise the canary would
    // "prove" the dead pin fails for some unrelated reason.
    let live_ok = run(&scratch_root, &log).is_ok();
    let current = ["main", "consensus-of-consensuses"]
        .iter()
        .find(|b| readme.contains(&format!("badge.svg?branch={b}&event=push")))
        .copied()
        .unwrap_or("main");
    let dead = readme
        .replace(
            &format!("branch={current}&event=push"),
            "branch=no-such-branch&event=push",
        )
        .replace(
            &format!("branch%3A{current}+event%3Apush"),
            "branch%3Ano-such-branch+event%3Apush",
        );
    let dead_differs = dead != readme;
    std::fs::write(scratch_root.join("README.md"), &dead).map_err(|e| e.to_string())?;
    std::fs::remove_file(scratch_root.join("README.tr.md")).ok();
    let dead_fails = run(&scratch_root, &log).is_err();
    // And a pin to a real branch that `ci.yml` does not push to must fail
    // for THAT reason, not because the branch is misspelled.
    let quiet = if let Some(other) = pushed
        .as_ref()
        .and_then(|p| {
            ["consensus-of-consensuses", "testnet-50", "garden"]
                .iter()
                .find(|b| !p.iter().any(|x| x == *b))
        })
        .copied()
    {
        let readme_q = readme
            .replace(
                &format!("branch={current}&event=push"),
                &format!("branch={other}&event=push"),
            )
            .replace(
                &format!("branch%3A{current}+event%3Apush"),
                &format!("branch%3A{other}+event%3Apush"),
            );
        std::fs::write(scratch_root.join("README.md"), readme_q).map_err(|e| e.to_string())?;
        let err = run(&scratch_root, &log).is_err();
        std::fs::write(scratch_root.join("README.md"), readme).map_err(|e| e.to_string())?;
        err
    } else {
        false
    };
    Ok((
        live_ok && dead_differs && dead_fails && quiet,
        live_ok,
        dead_differs,
        dead_fails,
        quiet,
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
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-badges")?;

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

    // Turkish README drift must fail too. This has to isolate the translated
    // README path: a log with `README.tr.md + 1` would also fail on README.md,
    // so it would keep passing even if the Turkish check were deleted. Build a
    // tiny scratch tree where README.md matches the measured count and only
    // README.tr.md is stale.
    let tr_path = root.join("README.tr.md");
    let tr_drift_fails = if tr_path.is_file() {
        let tr = read_file(&root, "README.tr.md")?;
        match badge_count(&tr) {
            Some(tr_real) => {
                let scratch_root = dir.join("tr-root");
                std::fs::create_dir(&scratch_root).map_err(|e| e.to_string())?;
                for rel in [
                    "README.md",
                    "Cargo.toml",
                    "rust-toolchain.toml",
                    "LICENSE.md",
                ] {
                    std::fs::copy(root.join(rel), scratch_root.join(rel))
                        .map_err(|e| format!("copy {rel} into Turkish badge canary: {e}"))?;
                }
                let n: u64 = tr_real.parse::<u64>().map_err(|e| e.to_string())? + 1;
                let stale_tr = tr.replace(
                    &format!("tests-{tr_real}%20lib"),
                    &format!("tests-{n}%20lib"),
                );
                if stale_tr == tr {
                    return Err(String::from(
                        "canary: could not drift README.tr.md test badge",
                    ));
                }
                std::fs::write(scratch_root.join("README.tr.md"), stale_tr)
                    .map_err(|e| e.to_string())?;
                let log = dir.join("tr-drift.log");
                std::fs::write(
                    &log,
                    format!("test result: ok. {real} passed; 0 failed; 0 ignored\n"),
                )
                .map_err(|e| e.to_string())?;
                run(&scratch_root, &log).is_err()
            }
            None => false,
        }
    } else {
        true
    };

    let dead_pin_fails = pin_canary(&root, &readme, &real, &dir)?;

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
    if !tr_drift_fails {
        return Err(String::from(
            "canary: a drifted README.tr.md badge was accepted",
        ));
    }
    verdicts(
        (drift_fails, red_fails, empty_fails, tr_drift_fails),
        dead_pin_fails,
        &dir,
    )
}

/// The canaries are only worth their names if a failure is reported: each
/// `*_fails` flag is one canary, and `dead_pin_fails` carries the CI pin pair.
fn verdicts(
    _earlier: (bool, bool, bool, bool),
    (_pin_ok, live_ok, dead_differs, dead_fails, quiet): (bool, bool, bool, bool, bool),
    dir: &Path,
) -> Result<String, String> {
    if !live_ok {
        return Err(String::from(
            "canary: the committed README failed the CI pin check in the scratch tree",
        ));
    }
    if !dead_differs {
        return Err(String::from(
            "canary: could not re-pin the CI badge in README.md",
        ));
    }
    if !dead_fails {
        return Err(String::from(
            "canary: a CI badge pinned to a branch ci.yml never pushes to was accepted",
        ));
    }
    if !quiet {
        return Err(String::from(
            "canary: a pin to a real branch ci.yml does not push to was accepted",
        ));
    }
    std::fs::remove_dir_all(dir.join("pin-root")).ok();
    Ok(String::from(
        "badge canary OK (drift/red/empty/tr-drift/dead-pin FAIL).",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measured_count_ignores_lines_that_are_not_a_summary() {
        let log = "test result: ok. 42 passed; 0 failed\nstray output 12 passed\n";
        assert_eq!(measured_count(log).as_deref(), Some("42"));
        assert_eq!(measured_count("only 7 passed here"), None);
    }
}
