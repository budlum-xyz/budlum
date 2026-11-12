//! Every path dependency and embedded object-layer source the node needs is
//! copied into the image.
//!
//! `Cargo.toml` names its path dependencies; `include_bytes!` in the VM family
//! modules names contract sources outside `src/`. The `Dockerfile` copies a
//! hand-written list into the builder. Forgetting either kind of `COPY` builds
//! locally but breaks the image before any rehearsal can start.
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
//!
//! The VM-family modules also embed reviewed contract sources from
//! `contracts/object-layer/`; these are neither Cargo path dependencies nor
//! under `src/`. Check each embedded file against the builder's `COPY` list.
//! This would have caught the eight missing files in rehearsal 43123295605
//! before the Docker release build reached rustc.

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

/// Sources copied into the stage that runs the first `cargo build`, *before*
/// that instruction. A later runtime-stage COPY cannot repair a builder.
/// `COPY --from=` reads a previous stage, not the repository build context.
fn copied_dirs(dockerfile: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in dockerfile.lines() {
        let line = line.trim();
        if line.starts_with("FROM ") {
            out.clear();
            continue;
        }
        if line.starts_with("RUN ") && line.contains("cargo build") {
            break;
        }
        let Some(rest) = line.strip_prefix("COPY ") else {
            continue;
        };
        if rest.contains("--from=") {
            continue;
        }
        // The last token is the destination. Only sources are copied in.
        let tokens: Vec<&str> = rest
            .split_whitespace()
            .filter(|t| !t.starts_with("--"))
            .collect();
        let Some((_, sources)) = tokens.split_last() else {
            continue;
        };
        for token in sources {
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

/// Static, non-test contract sources embedded by one VM family module.
fn embedded_object_layer_paths(source: &str) -> BTreeSet<String> {
    source
        .lines()
        .filter_map(|line| {
            line.split_once("include_bytes!(\"../../../contracts/object-layer/")
                .and_then(|(_, suffix)| suffix.split_once('"'))
                .map(|(name, _)| format!("contracts/object-layer/{name}"))
        })
        .collect()
}

/// Non-vacuously enumerate every object-layer artifact that release rustc
/// reads from outside `src/`. The Dockerfile must include those files too.
fn embedded_object_layer_sources(root: &Path) -> Result<BTreeSet<String>, String> {
    let family = root.join("src/object_layer/family");
    let entries = std::fs::read_dir(&family)
        .map_err(|e| format!("cannot enumerate {}: {e}", family.display()))?;
    let mut paths = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot enumerate VM families: {e}"))?;
        if entry.path().extension().and_then(std::ffi::OsStr::to_str) != Some("rs") {
            continue;
        }
        let source = std::fs::read_to_string(entry.path())
            .map_err(|e| format!("cannot read {}: {e}", entry.path().display()))?;
        paths.extend(embedded_object_layer_paths(&source));
    }
    if paths.is_empty() {
        return Err(
            "image gate would be vacuous: no object-layer embedded contract sources found".into(),
        );
    }
    Ok(paths)
}

/// # Errors
///
/// Returns the path dependencies or embedded artifacts the image would lack.
pub fn run(root: &Path) -> Result<String, String> {
    let manifest = std::fs::read_to_string(root.join("Cargo.toml"))
        .map_err(|e| format!("cannot read Cargo.toml: {e}"))?;
    let dockerfile = std::fs::read_to_string(root.join("ops/Dockerfile"))
        .map_err(|e| format!("cannot read Dockerfile: {e}"))?;
    if !dockerfile
        .lines()
        .any(|line| line.trim_start().starts_with("RUN ") && line.contains("cargo build"))
    {
        return Err(
            "ops/Dockerfile has no `RUN ... cargo build`; image-input gate would be vacuous".into(),
        );
    }

    let copied = copied_dirs(&dockerfile);
    let declared = declared_paths(&manifest);

    if declared.is_empty() {
        return Err(String::from(
            "Cargo.toml declares no path dependency; this gate would check nothing",
        ));
    }
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

    let embedded = embedded_object_layer_sources(root)?;
    let mut uncopied = Vec::new();
    for path in &embedded {
        if !root.join(path).is_file() {
            missing.push(format!(
                "embedded artifact {path} does not exist in the tree"
            ));
        } else if !is_covered(path, &copied) {
            uncopied.push(path.as_str());
        }
    }
    if !uncopied.is_empty() {
        missing.push(format!(
            "{} object-layer contract source(s) embedded by the node are absent from the image: {}. Add `COPY contracts/object-layer/ ./contracts/object-layer/` before cargo build.",
            uncopied.len(),
            uncopied.join(", ")
        ));
    }

    if missing.is_empty() {
        return Ok(format!(
            "Image gate OK: {checked} path dependenc(ies) and {} embedded contract source(s) copied into the image by one of {} COPY entries.",
            embedded.len(),
            copied.len()
        ));
    }

    let mut msg = format!("{} missing image input(s):\n\n", missing.len());
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
RUN cargo build\n\
COPY too-late/ ./too-late/\n\
FROM debian\n\
COPY runtime-only/ ./runtime-only/\n\
COPY --from=builder /usr/local/bin/x /usr/local/bin/x\n";
    let copied = copied_dirs(dockerfile);
    if !copied.contains("budzero") {
        problems.push(String::from("BROKEN: missed a copied directory"));
    }
    if copied.contains("--from=builder") {
        problems.push(String::from("BROKEN: read a flag as a path"));
    }
    if copied.contains("too-late") || copied.contains("runtime-only") {
        problems.push(String::from(
            "BROKEN: counted a COPY after the builder's cargo build",
        ));
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

    let sample =
        "const SOURCE: &[u8] = include_bytes!(\"../../../contracts/object-layer/svm/src/lib.rs\");";
    let embedded = embedded_object_layer_paths(sample);
    let artifact = "contracts/object-layer/svm/src/lib.rs";
    if !embedded.contains(artifact) {
        problems.push(String::from("BROKEN: missed an embedded contract artifact"));
    }
    if is_covered(artifact, &copied) {
        problems.push(String::from(
            "BROKEN: called an uncopied contract artifact covered",
        ));
    }
    if !is_covered(
        artifact,
        &copied_dirs("COPY contracts/object-layer/ ./contracts/object-layer/"),
    ) {
        problems.push(String::from(
            "BROKEN: a copied contract directory was missed",
        ));
    }

    if problems.is_empty() {
        return Ok(String::from(
            "image gate self-test OK: inline-table and target paths are read, a commented \
             path is not, `--from` copies are not mistaken for sources, a crate under a \
             copied parent counts as covered, neither an uncopied directory nor a \
             string-prefix neighbour does, and embedded contract sources need a source COPY.",
        ));
    }
    Err(problems.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_destination_is_not_a_source() {
        let copied = copied_dirs("COPY other/ ./crates/bpqs/\nCOPY a b ./dst/\n");
        assert!(!is_covered("crates/bpqs", &copied));
        assert!(is_covered("a", &copied) && is_covered("b", &copied));
    }

    #[test]
    fn a_copy_after_build_or_in_runtime_does_not_supply_the_builder() {
        let dockerfile = "FROM rust AS builder\nCOPY early/ ./early/\nRUN cargo build\nCOPY too-late/ ./too-late/\nFROM runtime\nCOPY runtime-only/ ./runtime-only/\n";
        let copied = copied_dirs(dockerfile);
        assert!(is_covered("early/file", &copied));
        assert!(!is_covered("too-late/file", &copied));
        assert!(!is_covered("runtime-only/file", &copied));
    }

    #[test]
    fn release_image_copies_every_embedded_object_layer_source() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let result =
            run(&root).expect("the release Docker image must contain every embedded source");
        assert!(result.contains("8 embedded contract source(s)"), "{result}");
    }
}
