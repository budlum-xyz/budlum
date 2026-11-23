//! Gate source provenance: the binary and the tree it scans must agree.
//!
//! A gate binary compiled from one revision of `xtask/gates` and pointed at a
//! different repository tree by `BUDLUM_ROOT` (or by running from another
//! checkout) reports findings that belong to neither tree: the binary carries
//! one set of gates and baselines, the tree carries another. The result looks
//! like a long list of code failures and is actually a measurement artefact.
//!
//! This gate binds the two together. At compile time `include_str!` embeds the
//! committed source baseline into the binary. At run time the gate:
//!
//!   1. reads the baseline from the scanned tree and requires it to be
//!      byte-identical to the embedded one - a binary from another tree fails
//!      before it emits any verdict about the code;
//!   2. walks `xtask/gates` in sorted order and hashes every regular file;
//!   3. recomputes the baseline and requires the measured digest, file set and
//!      per-file digests to equal the embedded pin.
//!
//! Every input is a repository file or bytes derived from one; there is no
//! wall clock, no directory-iteration order in the digest and no network
//! access. The baseline is regenerated with `--print-baseline` in the same
//! change that modifies the gate sources.
//!
//! # Errors
//!
//! The public entry points return a finding when the baseline is missing or
//! corrupt, the binary and tree baselines differ, the gate source has moved
//! without re-pinning, or the walk is too small to be a real gate tree.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use crate::sha256::hex_digest;

/// The baseline pinned into the binary at compile time.
const EMBEDDED_BASELINE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../.github/gate-source-provenance-baseline.txt"
));

/// Where the scanned tree keeps the same baseline.
const BASELINE_PATH: &str = ".github/gate-source-provenance-baseline.txt";

/// A pruned walk must not hash happily and pass. The real crate carries
/// over a hundred source files; the floor sits just above a synthetic canary so
/// only an empty or pruned walk trips it.
const MIN_SOURCE_FILES: usize = 3;

/// Files the walk must contain for the result to describe this gate crate.
const REQUIRED_FILES: &[&str] = &["Cargo.toml", "src/main.rs"];

/// A source file set, keyed by its path relative to `xtask/gates`.
type SourceFiles = BTreeMap<String, Vec<u8>>;

/// A parsed baseline: the digest of the ordered file lines and the lines
/// themselves, keyed by path.
struct Baseline {
    digest: String,
    files: BTreeMap<String, String>,
}

/// Run the provenance review against the repository root.
///
/// # Errors
///
/// Returns a finding when the baseline or source tree does not match the
/// binary's embedded pin.
pub fn run(root: &Path) -> Result<String, String> {
    run_args(root, &[])
}

/// Run the review, or emit a freshly measured baseline with
/// `--print-baseline`.
///
/// # Errors
///
/// Returns a finding for an unknown argument, a missing or corrupt baseline,
/// a cross-tree binary, or a source tree that moved without re-pinning.
pub fn run_args(root: &Path, args: &[&str]) -> Result<String, String> {
    match args.first().copied() {
        None => review(root),
        Some("--print-baseline") => print_baseline(root),
        Some(other) => Err(format!(
            "unknown argument `{other}`; pass nothing for the review, or \
             `--print-baseline` to emit the source pin"
        )),
    }
}

fn review(root: &Path) -> Result<String, String> {
    let baseline = fs::read_to_string(root.join(BASELINE_PATH)).map_err(|error| {
        format!("{BASELINE_PATH} is missing; pin the gate sources in the same change: {error}")
    })?;
    let files = collect_sources(root)?;
    enforce_floor(&files)?;
    check(EMBEDDED_BASELINE, &baseline, &files)
}

fn print_baseline(root: &Path) -> Result<String, String> {
    let files = collect_sources(root)?;
    enforce_floor(&files)?;
    Ok(baseline_text(&files))
}

/// Walk `xtask/gates` and hash every regular file, sorted by relative path.
fn collect_sources(root: &Path) -> Result<SourceFiles, String> {
    let base = root.join("xtask").join("gates");
    if !base.is_dir() {
        return Err(format!("{} is not a directory", base.display()));
    }
    let mut files = SourceFiles::new();
    collect_into(&base, &base, &mut files)?;
    Ok(files)
}

fn collect_into(base: &Path, dir: &Path, out: &mut SourceFiles) -> Result<(), String> {
    let entries =
        fs::read_dir(dir).map_err(|error| format!("cannot read {}: {error}", dir.display()))?;
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot list {}: {error}", dir.display()))?;
        paths.push(entry.path());
    }
    paths.sort();
    for path in paths {
        let name = match path.file_name().and_then(|value| value.to_str()) {
            Some(value) => value.to_string(),
            None => continue,
        };
        let kind = path
            .metadata()
            .map_err(|error| format!("cannot stat {}: {error}", path.display()))?
            .file_type();
        if kind.is_dir() {
            if matches!(name.as_str(), ".git" | "target" | "node_modules") {
                continue;
            }
            collect_into(base, &path, out)?;
        } else if kind.is_file() {
            let rel = path
                .strip_prefix(base)
                .map_err(|error| format!("cannot relativize {}: {error}", path.display()))?
                .to_string_lossy()
                .replace('\\', "/");
            let bytes = fs::read(&path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
            out.insert(rel, bytes);
        }
    }
    Ok(())
}

fn enforce_floor(files: &SourceFiles) -> Result<(), String> {
    if files.len() < MIN_SOURCE_FILES {
        return Err(format!(
            "vacuous gate source walk: {len} file(s), the floor is {MIN_SOURCE_FILES}",
            len = files.len()
        ));
    }
    for required in REQUIRED_FILES {
        if !files.contains_key(*required) {
            return Err(format!(
                "the gate source walk has no `{required}`; run the gate from a repository root"
            ));
        }
    }
    Ok(())
}

/// The ordered `path<TAB>digest` lines the baseline pins.
fn source_lines(files: &SourceFiles) -> Vec<String> {
    files
        .iter()
        .map(|(path, bytes)| format!("{path}\t{}", hex_digest(bytes)))
        .collect()
}

fn digest_of(lines: &[String]) -> String {
    hex_digest(lines.join("\n").as_bytes())
}

fn baseline_text(files: &SourceFiles) -> String {
    let lines = source_lines(files);
    let digest = digest_of(&lines);
    let mut text = String::new();
    text.push_str("# Gate source provenance baseline.\n");
    text.push_str("# The binary embeds this file; the scanned tree must carry the same\n");
    text.push_str("# bytes and hash to the same digest. Re-measure in the same change:\n");
    text.push_str("#   cargo run --release --manifest-path xtask/gates/Cargo.toml -- gate-source-provenance --print-baseline\n");
    let _ = writeln!(text, "digest: {digest}");
    let _ = writeln!(text, "files: {}", lines.len());
    for line in &lines {
        let _ = writeln!(text, "{line}");
    }
    text
}

fn parse_baseline(text: &str) -> Result<Baseline, String> {
    let mut digest: Option<String> = None;
    let mut declared: Option<usize> = None;
    let mut files = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("digest:") {
            digest = Some(rest.trim().to_string());
            continue;
        }
        if let Some(rest) = line.strip_prefix("files:") {
            declared = Some(
                rest.trim()
                    .parse::<usize>()
                    .map_err(|_| format!("baseline `files:` line is not a number: {line}"))?,
            );
            continue;
        }
        let Some((path, hash)) = line.split_once('\t') else {
            return Err(format!("baseline line has no path/hash separator: {line}"));
        };
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!("baseline line carries no SHA-256 digest: {line}"));
        }
        if files.insert(path.to_string(), hash.to_string()).is_some() {
            return Err(format!("baseline pins `{path}` twice"));
        }
    }
    let Some(digest) = digest else {
        return Err(String::from("baseline has no `digest:` line"));
    };
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(String::from("baseline `digest:` is not a SHA-256 digest"));
    }
    let Some(declared) = declared else {
        return Err(String::from("baseline has no `files:` line"));
    };
    if declared != files.len() {
        return Err(format!(
            "baseline declares `files: {declared}` but carries {} lines",
            files.len()
        ));
    }
    Ok(Baseline { digest, files })
}

fn lines_to_map(lines: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for line in lines {
        let Some((path, hash)) = line.split_once('\t') else {
            return Err(format!("measured line has no path/hash separator: {line}"));
        };
        out.insert(path.to_string(), hash.to_string());
    }
    Ok(out)
}

fn short_digest(digest: &str) -> &str {
    let end = digest.len().min(12);
    &digest[..end]
}

/// Compare the embedded pin, the tree's pin and the measured sources.
fn check(embedded: &str, baseline: &str, files: &SourceFiles) -> Result<String, String> {
    if embedded != baseline {
        let embedded_digest = match parse_baseline(embedded) {
            Ok(value) => value.digest,
            Err(_) => String::from("unparsable"),
        };
        let tree_digest = match parse_baseline(baseline) {
            Ok(value) => value.digest,
            Err(_) => String::from("unparsable"),
        };
        return Err(format!(
            "the gate binary and the scanned tree carry different source baselines \
             (binary {}, tree {}); rebuild the binary from this tree before \
             trusting any gate verdict",
            short_digest(&embedded_digest),
            short_digest(&tree_digest)
        ));
    }
    let pinned = parse_baseline(embedded)?;
    let lines = source_lines(files);
    let measured_digest = digest_of(&lines);
    if measured_digest != pinned.digest {
        return Err(format!(
            "gate source digest mismatch: pinned {}, measured {}; re-measure with \
             `--print-baseline` in the same change",
            short_digest(&pinned.digest),
            short_digest(&measured_digest)
        ));
    }
    let measured = lines_to_map(&lines)?;
    if measured != pinned.files {
        let grown: Vec<&String> = measured
            .keys()
            .filter(|key| !pinned.files.contains_key(*key))
            .collect();
        let shrank: Vec<&String> = pinned
            .files
            .keys()
            .filter(|key| !measured.contains_key(*key))
            .collect();
        return Err(format!(
            "gate source set moved without re-pinning: {} new file(s), {} removed file(s); \
             re-measure with `--print-baseline`",
            grown.len(),
            shrank.len()
        ));
    }
    Ok(format!(
        "gate source provenance: {} files pinned, binary and tree agree ({})",
        measured.len(),
        short_digest(&measured_digest)
    ))
}

fn expect_red<T>(label: &str, outcome: &Result<T, String>) -> Result<(), String> {
    if outcome.is_ok() {
        Err(format!("gate-source-provenance self-test: {label} passed"))
    } else {
        Ok(())
    }
}

fn fixture_files(entries: &[(&str, &str)]) -> SourceFiles {
    entries
        .iter()
        .map(|(path, body)| ((*path).to_string(), body.as_bytes().to_vec()))
        .collect()
}

/// Canary: every failure mode the gate claims to catch must be red, and the
/// aligned case must be green.
///
/// # Errors
///
/// Returns a finding when a tampered fixture is accepted or a good one is
/// refused.
pub fn self_test() -> Result<String, String> {
    let files = fixture_files(&[
        ("Cargo.toml", "[package]\nname = \"gates\"\n"),
        ("src/main.rs", "fn main() {}\n"),
        ("src/gates/one.rs", "pub fn one() {}\n"),
    ]);
    let baseline = baseline_text(&files);
    check(&baseline, &baseline, &files).map_err(|error| {
        format!("gate-source-provenance self-test: an aligned tree was refused: {error}")
    })?;

    let other = fixture_files(&[
        ("Cargo.toml", "[package]\nname = \"gates\"\n"),
        ("src/main.rs", "fn other() {}\n"),
        ("src/gates/one.rs", "pub fn one() {}\n"),
    ]);
    let other_baseline = baseline_text(&other);
    expect_red(
        "a binary built from another source tree",
        &check(&other_baseline, &baseline, &files),
    )?;

    let tampered_baseline = baseline.replacen("Cargo.toml\t", "Cargo.toml.bak\t", 1);
    expect_red(
        "a tree baseline that differs from the binary",
        &check(&baseline, &tampered_baseline, &files),
    )?;

    let mut changed = files.clone();
    changed.insert("src/main.rs".to_string(), b"fn changed() {}\n".to_vec());
    expect_red(
        "a gate source that moved without re-pinning",
        &check(&baseline, &baseline, &changed),
    )?;

    let no_digest = baseline.replacen("digest: ", "# digest: ", 1);
    expect_red(
        "a baseline without a digest line",
        &check(&no_digest, &no_digest, &files),
    )?;

    let empty = SourceFiles::new();
    expect_red("a vacuous source walk", &enforce_floor(&empty))?;

    enforce_floor(&fixture_files(&[
        ("Cargo.toml", "[package]\n"),
        ("src/main.rs", "fn main() {}\n"),
        ("src/gates/one.rs", "pub fn one() {}\n"),
    ]))
    .map_err(|error| {
        format!(
            "gate-source-provenance self-test: a minimal real walk was refused by the floor: {error}"
        )
    })?;

    Ok(String::from(
        "gate-source-provenance self-test: cross-tree, stale-baseline, moved-source, \
         corrupt-baseline and vacuous-walk shapes all fail",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_test_passes() {
        super::self_test().expect("gate-source-provenance self-test");
    }
}
