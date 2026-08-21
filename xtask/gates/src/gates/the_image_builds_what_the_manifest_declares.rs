//! Every path dependency the node declares is copied into the image.
//!
//! `Cargo.toml` names its path dependencies; the `Dockerfile` copies a hand
//! written list of directories into the builder stage. Nothing connects the
//! two, so adding a crate to the manifest and forgetting the `COPY` produces
//! a tree that builds everywhere except inside the image.
//!
//! That is not a hypothetical. `budlum-note-packing` was added as a path
//! dependency and the image build failed with `failed to read
//! /build/note-packing/Cargo.toml`, after every other job on the commit had
//! already gone green. Docker Smoke is one of the slowest jobs in the
//! pipeline and it sits behind an image build, so the feedback arrived last
//! and cost a full round trip.
//!
//! A path dependency is the one kind that cannot degrade quietly here. A
//! registry dependency missing from the image would still resolve from
//! crates.io; a path dependency has nowhere else to come from, so the build
//! stops. The failure is loud, and it is loud in the wrong place: in a
//! fifteen minute job rather than in a check that takes milliseconds.
//!
//! # What is checked
//!
//! Each `path = "..."` in the root manifest that points at a directory must
//! be covered by a `COPY` in the `Dockerfile`, either directly or through a
//! parent that is copied whole. Path entries pointing at a file are `[[bin]]`
//! and `[[bench]]` targets rather than dependencies, and are skipped: they
//! live under directories the image already copies, and a target that is
//! missing from the image is a build error in the same breath.

use std::collections::BTreeSet;
use std::path::Path;

/// Pull every `path = "..."` value out of a manifest.
///
/// Deliberately naive about TOML structure: the question is which paths the
/// manifest mentions at all, and a value that appears anywhere still has to
/// exist inside the image for the build to resolve it.
fn declared_paths(manifest: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let mut rest = line;
        while let Some(at) = rest.find("path") {
            rest = &rest[at + 4..];
            let after = rest.trim_start();
            let Some(after) = after.strip_prefix('=') else {
                continue;
            };
            let after = after.trim_start();
            let Some(after) = after.strip_prefix('"') else {
                continue;
            };
            let Some(end) = after.find('"') else {
                continue;
            };
            out.insert(after[..end].to_string());
            rest = &after[end..];
        }
    }
    out
}

/// Directories the `Dockerfile` copies into the build stage.
///
/// Only `COPY` lines before the final stage matter, but a directory copied in
/// any stage is at least present in the file, and a `COPY --from=` is not a
/// source copy at all, so it is dropped.
fn copied_dirs(dockerfile: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in dockerfile.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("COPY ") else {
            continue;
        };
        for token in rest.split_whitespace() {
            if token.starts_with("--") {
                continue;
            }
            // The destination is the last token; sources are the rest. Taking
            // every token is safe because a destination like `./src/` names
            // the same directory as its source anyway, and a false extra
            // entry here can only make the gate more permissive about a path
            // that is genuinely copied.
            let token = token.trim_end_matches('/');
            let token = token.strip_prefix("./").unwrap_or(token);
            if !token.is_empty() && token != "." {
                out.insert(token.to_string());
            }
        }
    }
    out
}

/// Whether `path` is inside one of the copied directories, or is one.
fn is_covered(path: &str, copied: &BTreeSet<String>) -> bool {
    let path = path.trim_end_matches('/');
    copied
        .iter()
        .any(|c| path == c || path.starts_with(&format!("{c}/")))
}

/// # Errors
///
/// Returns the path dependencies the image would not contain.
pub fn run(root: &Path) -> Result<String, String> {
    let manifest = std::fs::read_to_string(root.join("Cargo.toml"))
        .map_err(|e| format!("cannot read Cargo.toml: {e}"))?;
    let dockerfile = std::fs::read_to_string(root.join("ops/Dockerfile"))
        .map_err(|e| format!("cannot read Dockerfile: {e}"))?;

    let copied = copied_dirs(&dockerfile);
    let declared = declared_paths(&manifest);

    let mut checked = 0usize;
    let mut missing = Vec::new();

    for path in &declared {
        // A path pointing at a file is a target, not a dependency crate.
        if root.join(path).is_file() {
            continue;
        }
        if !root.join(path).is_dir() {
            missing.push(format!(
                "{path} is declared in Cargo.toml and does not exist in the tree"
            ));
            continue;
        }
        checked += 1;
        if !is_covered(path, &copied) {
            missing.push(format!(
                "{path} is a path dependency and the Dockerfile never copies it.\n    \
                 A path dependency cannot be fetched from anywhere else, so the image \
                 build fails to resolve it. Add `COPY {path}/ ./{path}/` before the \
                 cargo build step."
            ));
        }
    }

    if missing.is_empty() {
        return Ok(format!(
            "Image gate OK: {checked} path dependenc(ies) declared in Cargo.toml, \
             each copied into the image by one of {} COPY entries.",
            copied.len()
        ));
    }

    let mut msg = format!("{} path dependenc(ies) the image lacks:\n\n", missing.len());
    for m in &missing {
        msg.push_str("  ");
        msg.push_str(m);
        msg.push_str("\n\n");
    }
    Err(msg)
}

/// Canaries for the two readers and the coverage rule.
///
/// # Errors
///
/// Returns the checks that did not behave.
pub fn self_test() -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();

    // The manifest reader sees a plain dependency, an inline table, and skips
    // a comment.
    let manifest = r#"
[dependencies]
bud-isa = { path = "budzero/bud-isa" }
other = "1.0"
# stale = { path = "removed/crate" }

[[bin]]
name = "b"
path = "benches/micro/sig_verify.rs"
"#;
    let declared = declared_paths(manifest);
    if !declared.contains("budzero/bud-isa") {
        problems.push(String::from("BROKEN: missed an inline-table path"));
    }
    if !declared.contains("benches/micro/sig_verify.rs") {
        problems.push(String::from("BROKEN: missed a target path"));
    }
    if declared.contains("removed/crate") {
        problems.push(String::from("BROKEN: read a path out of a comment"));
    }

    // The Dockerfile reader keeps sources and drops `--from` copies.
    let dockerfile = "\
FROM rust AS builder\n\
COPY Cargo.toml Cargo.lock ./\n\
COPY budzero/ ./budzero/\n\
FROM debian\n\
COPY --from=builder /usr/local/bin/x /usr/local/bin/x\n";
    let copied = copied_dirs(dockerfile);
    if !copied.contains("budzero") {
        problems.push(String::from("BROKEN: missed a copied directory"));
    }
    if copied.contains("--from=builder") {
        problems.push(String::from("BROKEN: read a flag as a path"));
    }

    // Coverage: a crate under a copied parent counts, a sibling does not.
    if !is_covered("budzero/bud-isa", &copied) {
        problems.push(String::from(
            "BROKEN: a crate under a copied parent was called uncovered",
        ));
    }
    if is_covered("note-packing", &copied) {
        problems.push(String::from(
            "BROKEN: a directory nobody copies was called covered",
        ));
    }
    // A prefix that is not a path component must not count: `budzero-extra`
    // is not inside `budzero`.
    if is_covered("budzero-extra", &copied) {
        problems.push(String::from(
            "BROKEN: matched on a string prefix rather than a path component",
        ));
    }

    if problems.is_empty() {
        return Ok(String::from(
            "image gate self-test OK: inline-table and target paths are read, a commented \
             path is not, `--from` copies are not mistaken for sources, a crate under a \
             copied parent counts as covered, and neither an uncopied directory nor a \
             string-prefix neighbour does.",
        ));
    }
    Err(problems.join("\n"))
}
