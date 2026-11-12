//! Build and submit a GitHub Dependency Submission snapshot for every
//! `Cargo.lock` in the repository.
//!
//! GitHub's native static Cargo scanner only indexes top-level manifests it
//! discovers directly; workspaces under `budzero/`, `fuzz/`, `crates/*` and
//! `xtask/*` carry independent lockfiles. This module parses every committed
//! `Cargo.lock`, distinguishes `direct` from `indirect` dependencies, emits
//! Package URLs (`pkg:cargo/<name>@<version>`), and optionally posts the
//! snapshot to `POST /repos/{owner}/{repo}/dependency-snapshots`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::json;

#[derive(Default, Debug, Clone)]
struct LockPackage {
    name: String,
    version: String,
    source: Option<String>,
    deps: Vec<String>,
}

fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 4);
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

fn collect_lockfiles(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read entry in {}: {e}", dir.display()))?;
        let ty = entry
            .file_type()
            .map_err(|e| format!("cannot stat {}: {e}", entry.path().display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if ty.is_dir() {
            if !matches!(name.as_str(), ".git" | "target" | "node_modules") {
                collect_lockfiles(root, &entry.path(), out)?;
            }
        } else if name == "Cargo.lock" {
            let rel = entry
                .path()
                .strip_prefix(root)
                .unwrap_or(&entry.path())
                .to_path_buf();
            out.push(rel);
        }
    }
    Ok(())
}

fn unquote(raw: &str) -> Option<&str> {
    raw.trim().strip_prefix('"')?.strip_suffix('"')
}

/// Parse `[[package]]` stanzas out of a `Cargo.lock` v3/v4 text.
fn parse_cargo_lock(text: &str) -> Vec<LockPackage> {
    let mut packages = Vec::new();
    let mut current: Option<LockPackage> = None;
    let mut in_deps = false;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[package]]" {
            if let Some(pkg) = current.take() {
                if !pkg.name.is_empty() && !pkg.version.is_empty() {
                    packages.push(pkg);
                }
            }
            current = Some(LockPackage::default());
            in_deps = false;
            continue;
        }
        if line.starts_with('[') {
            in_deps = false;
            continue;
        }
        let Some(pkg) = current.as_mut() else {
            continue;
        };
        if in_deps {
            if line.starts_with(']') {
                in_deps = false;
                continue;
            }
            let item = line.trim_end_matches(',');
            if let Some(dep) = unquote(item) {
                pkg.deps.push(dep.to_string());
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("name =") {
            if let Some(v) = unquote(rest) {
                pkg.name = v.to_string();
            }
        } else if let Some(rest) = line.strip_prefix("version =") {
            if let Some(v) = unquote(rest) {
                pkg.version = v.to_string();
            }
        } else if let Some(rest) = line.strip_prefix("source =") {
            if let Some(v) = unquote(rest) {
                pkg.source = Some(v.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("dependencies =") {
            let rhs = rest.trim();
            if let Some(inline) = rhs.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                for part in inline.split(',') {
                    if let Some(dep) = unquote(part) {
                        pkg.deps.push(dep.to_string());
                    }
                }
            } else if rhs == "[" {
                in_deps = true;
            }
        }
    }
    if let Some(pkg) = current {
        if !pkg.name.is_empty() && !pkg.version.is_empty() {
            packages.push(pkg);
        }
    }
    packages
}

fn resolve_dep_purl(spec: &str, by_name: &BTreeMap<&str, Vec<&LockPackage>>) -> Option<String> {
    let mut parts = spec.split_whitespace();
    let name = parts.next()?;
    let maybe_ver = parts.next();
    let candidates = by_name.get(name)?;
    let chosen = if let Some(ver) = maybe_ver {
        candidates
            .iter()
            .copied()
            .find(|p| p.version == ver)
            .or_else(|| candidates.first().copied())?
    } else {
        candidates.first().copied()?
    };
    chosen.source.as_ref()?;
    Some(format!("pkg:cargo/{}@{}", chosen.name, chosen.version))
}

fn render_manifest_entry(rel_path: &str, packages: &[LockPackage]) -> String {
    let mut by_name: BTreeMap<&str, Vec<&LockPackage>> = BTreeMap::new();
    for p in packages {
        by_name.entry(p.name.as_str()).or_default().push(p);
    }

    let mut direct_purls = BTreeSet::new();
    for p in packages.iter().filter(|p| p.source.is_none()) {
        for dep in &p.deps {
            if let Some(purl) = resolve_dep_purl(dep, &by_name) {
                direct_purls.insert(purl);
            }
        }
    }

    let mut resolved: BTreeMap<String, (&str, Vec<String>)> = BTreeMap::new();
    for p in packages.iter().filter(|p| p.source.is_some()) {
        let purl = format!("pkg:cargo/{}@{}", p.name, p.version);
        let rel_kind = if direct_purls.contains(&purl) {
            "direct"
        } else {
            "indirect"
        };
        let mut child_purls = Vec::new();
        for dep in &p.deps {
            if let Some(cp) = resolve_dep_purl(dep, &by_name) {
                child_purls.push(cp);
            }
        }
        child_purls.sort();
        child_purls.dedup();
        resolved.insert(purl, (rel_kind, child_purls));
    }

    let escaped_path = json_escape(rel_path);
    let mut out = String::new();
    let _ = write!(
        out,
        "    \"{escaped_path}\": {{\n      \"name\": \"{escaped_path}\",\n      \"file\": {{\"source_location\": \"{escaped_path}\"}},\n      \"resolved\": {{"
    );
    for (idx, (purl, (rel_kind, deps))) in resolved.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let ep = json_escape(purl);
        let _ = write!(
            out,
            "\n        \"{ep}\": {{\n          \"package_url\": \"{ep}\",\n          \"relationship\": \"{rel_kind}\",\n          \"scope\": \"runtime\",\n          \"dependencies\": ["
        );
        for (d_idx, d) in deps.iter().enumerate() {
            if d_idx > 0 {
                out.push_str(", ");
            }
            let _ = write!(out, "\"{}\"", json_escape(d));
        }
        out.push_str("]\n        }");
    }
    if !resolved.is_empty() {
        out.push_str("\n      ");
    }
    out.push_str("}\n    }");
    out
}

fn iso8601_now() -> Result<String, String> {
    let out = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .map_err(|e| format!("cannot run `date`: {e}"))?;
    if !out.status.success() {
        return Err("`date -u` exited non-zero".to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Build the full GitHub Dependency Submission JSON payload from `manifests`.
fn build_snapshot_json(
    manifests: &[(String, Vec<LockPackage>)],
    sha: &str,
    git_ref: &str,
    job_id: &str,
    correlator: &str,
    scanned: &str,
) -> String {
    let mut out = String::new();
    out.push_str("{\n  \"version\": 0,\n");
    let _ = writeln!(out, "  \"sha\": \"{}\",", json_escape(sha));
    let _ = writeln!(out, "  \"ref\": \"{}\",", json_escape(git_ref));
    let _ = writeln!(
        out,
        "  \"job\": {{\"id\": \"{}\", \"correlator\": \"{}\"}},",
        json_escape(job_id),
        json_escape(correlator)
    );
    out.push_str(
        "  \"detector\": {\n    \"name\": \"budlum-cargo-lock-snapshot\",\n    \"version\": \"0.1.0\",\n    \"url\": \"https://github.com/budlum-xyz/budlum\"\n  },\n",
    );
    let _ = writeln!(out, "  \"scanned\": \"{}\",", json_escape(scanned));
    out.push_str("  \"manifests\": {\n");
    for (idx, (path, pkgs)) in manifests.iter().enumerate() {
        if idx > 0 {
            out.push_str(",\n");
        }
        out.push_str(&render_manifest_entry(path, pkgs));
    }
    out.push_str("\n  }\n}\n");
    out
}

fn github_snapshot_url(repo: &str) -> String {
    format!("https://api.github.com/repos/{repo}/dependency-graph/snapshots")
}

fn submit_to_github(snapshot_path: &Path) -> Result<String, String> {
    let repo = std::env::var("GITHUB_REPOSITORY")
        .map_err(|_| "GITHUB_REPOSITORY is not set for --submit".to_string())?;
    let token = std::env::var("GITHUB_TOKEN")
        .map_err(|_| "GITHUB_TOKEN is not set for --submit".to_string())?;
    if repo.is_empty() || token.is_empty() {
        return Err("GITHUB_REPOSITORY and GITHUB_TOKEN must be non-empty".to_string());
    }
    let url = github_snapshot_url(&repo);
    let data_arg = format!("@{}", snapshot_path.display());
    let out = Command::new("curl")
        .args([
            "--fail-with-body",
            "-sS",
            "-X",
            "POST",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "X-GitHub-Api-Version: 2022-11-28",
            "-H",
            &format!("Authorization: Bearer {token}"),
            &url,
            "--data-binary",
            &data_arg,
        ])
        .output()
        .map_err(|e| format!("failed to execute curl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "dependency snapshot upload failed ({}): {}{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(format!("submitted dependency snapshot to {repo}"))
}

/// CLI entry: `budlum-tools dependency-snapshot <out.json> [--submit]`
///
/// # Errors
///
/// If lockfiles cannot be read, the snapshot cannot be written, or submission
/// fails when `--submit` is requested.
pub fn run(root: &Path, args: &[&str]) -> Result<String, String> {
    if args == ["--self-test"] {
        return self_test();
    }
    let mut submit = false;
    let mut out_arg: Option<&str> = None;
    for &arg in args {
        if arg == "--submit" {
            submit = true;
        } else if out_arg.is_none() {
            out_arg = Some(arg);
        } else {
            return Err(format!("unexpected argument `{arg}`"));
        }
    }
    let out_file = out_arg.ok_or_else(|| {
        "usage: budlum-tools dependency-snapshot <out.json> [--submit]".to_string()
    })?;
    let out_path = if Path::new(out_file).is_absolute() {
        PathBuf::from(out_file)
    } else {
        root.join(out_file)
    };

    let mut lock_paths = Vec::new();
    collect_lockfiles(root, root, &mut lock_paths)?;
    lock_paths.sort();
    if lock_paths.is_empty() {
        return Err("no Cargo.lock files found in repository".to_string());
    }

    let mut manifests = Vec::with_capacity(lock_paths.len());
    let mut total_pkgs = 0usize;
    for rel in &lock_paths {
        let text = std::fs::read_to_string(root.join(rel))
            .map_err(|e| format!("cannot read {}: {e}", rel.display()))?;
        let pkgs = parse_cargo_lock(&text);
        total_pkgs += pkgs.iter().filter(|p| p.source.is_some()).count();
        manifests.push((rel.to_string_lossy().replace('\\', "/"), pkgs));
    }

    let sha = std::env::var("GITHUB_SHA").unwrap_or_else(|_| "0".repeat(40));
    let git_ref = std::env::var("GITHUB_REF").unwrap_or_else(|_| "refs/heads/main".to_string());
    let job_id = std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| "local".to_string());
    let correlator = std::env::var("BUDLUM_DEP_CORRELATOR")
        .unwrap_or_else(|_| "cargo-dependency-submission".to_string());
    let scanned = iso8601_now()?;

    let payload = build_snapshot_json(&manifests, &sha, &git_ref, &job_id, &correlator, &scanned);
    json::parse(&payload).map_err(|e| format!("generated invalid snapshot JSON: {e}"))?;
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
    }
    std::fs::write(&out_path, &payload)
        .map_err(|e| format!("cannot write {}: {e}", out_path.display()))?;

    let mut summary = format!(
        "dependency-snapshot: {} manifest(s), {} external package entries -> {}",
        manifests.len(),
        total_pkgs,
        out_path.display()
    );
    if submit {
        let res = submit_to_github(&out_path)?;
        let _ = write!(summary, " ({res})");
    }
    Ok(summary)
}

/// Canary for `Cargo.lock` parsing and GitHub snapshot JSON generation.
///
/// # Errors
///
/// If direct/indirect classification or JSON serialization fails.
pub fn self_test() -> Result<String, String> {
    let sample_lock = "\
version = 3

[[package]]
name = \"demo-root\"
version = \"0.1.0\"
dependencies = [
 \"serde\",
]

[[package]]
name = \"serde\"
version = \"1.0.200\"
source = \"registry+https://github.com/rust-lang/crates.io-index\"
dependencies = [
 \"serde_derive 1.0.200\",
]

[[package]]
name = \"serde_derive\"
version = \"1.0.200\"
source = \"registry+https://github.com/rust-lang/crates.io-index\"
";
    let pkgs = parse_cargo_lock(sample_lock);
    let doc = build_snapshot_json(
        &[("Cargo.lock".to_string(), pkgs)],
        "0123456789abcdef0123456789abcdef01234567",
        "refs/heads/main",
        "1",
        "cargo-dependency-submission",
        "2026-11-08T00:00:00Z",
    );
    let parsed = json::parse(&doc).map_err(|e| format!("snapshot JSON invalid: {e}"))?;
    let resolved = parsed
        .get("manifests")
        .and_then(|m| m.get("Cargo.lock"))
        .and_then(|c| c.get("resolved"))
        .ok_or_else(|| "missing manifests.Cargo.lock.resolved".to_string())?;
    let serde_rel = resolved
        .get("pkg:cargo/serde@1.0.200")
        .and_then(|p| p.get("relationship"))
        .and_then(json::Value::as_str);
    let derive_rel = resolved
        .get("pkg:cargo/serde_derive@1.0.200")
        .and_then(|p| p.get("relationship"))
        .and_then(json::Value::as_str);
    if serde_rel != Some("direct") || derive_rel != Some("indirect") {
        return Err(format!(
            "unexpected relationships: serde={serde_rel:?}, derive={derive_rel:?}"
        ));
    }
    let url = github_snapshot_url("budlum-xyz/budlum");
    if url != "https://api.github.com/repos/budlum-xyz/budlum/dependency-graph/snapshots" {
        return Err(format!("unexpected snapshot endpoint URL: {url}"));
    }
    Ok(
        "ok: dependency-snapshot self-test (direct + indirect PURLs + endpoint verified)"
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_canary_passes() {
        self_test().unwrap();
    }
}
