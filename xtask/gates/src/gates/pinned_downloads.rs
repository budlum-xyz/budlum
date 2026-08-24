//! Downloads must be pinned with a hash written in the repository.
//!
//! Ported from `scripts/check-pinned-downloads-are-really-pinned.sh`. A
//! checksum fetched from the same host as the artefact verifies transit, not
//! provenance; the expected hash must be written into the workflow. This gate
//! refuses any `curl`/`wget` line that fetches a `.sha256`-style file, and
//! requires at least one workflow to verify a checksum with `sha256sum -c`.
//!
//! The Strix hardening (follow-up work) is kept: the extension match is
//! case-insensitive so `.SHA256`/`.Sha512` variants are caught, a checksum
//! URL is any URL whose path ends in a checksum-ish resource (`/hash`,
//! `/checksum`, `/sum`) regardless of extension, and a query-string checksum
//! (`?checksum=`, `&hash=`) is a remote checksum fetch too.

use std::fmt::Write as _;
use std::path::Path;

/// The checksum extensions, lowercased, in the shell gate's pattern order.
const CHECKSUM_EXTS: &[&str] = &[
    ".sha256",
    ".sha512",
    ".sha1",
    ".md5",
    ".checksum",
    ".checksums",
];

/// The checksum-ish path segments and query parameters.
const CHECKSUM_WORDS: &[&str] = &["hash", "checksum", "checksums", "sum", "sums"];

/// Does this URL's path end with a checksum extension, the shell gate's
/// first pattern `https?://[^[:space:]]+\.(ext)([[:space:]]|$|\\)`? The token
/// already ended at whitespace or a backslash, so "end of token" is the
/// boundary.
fn ends_with_checksum_ext(url: &str) -> bool {
    CHECKSUM_EXTS.iter().any(|ext| url.ends_with(ext))
}

/// Does this URL end with a checksum-ish resource path, the shell gate's
/// second pattern? Inside a single token there is no whitespace to act as a
/// boundary, so only the token end (or the backslash that already cut it)
/// can follow the word; both reduce to "the token ends with /word".
fn ends_with_checksum_path(url: &str) -> bool {
    CHECKSUM_WORDS
        .iter()
        .any(|word| url.ends_with(&format!("/{word}")))
}

/// Does this URL carry a checksum query parameter, the shell gate's third
/// pattern `[?&](hash|checksum|checksums|sums?)[=]`?
fn has_checksum_query(url: &str) -> bool {
    CHECKSUM_WORDS
        .iter()
        .any(|word| url.contains(&format!("?{word}=")) || url.contains(&format!("&{word}=")))
}

/// Scan a lowercased line for `http(s)://` tokens and apply the three
/// checksum rules, mirroring the shell gate's `grep -qiE` triple.
fn checksum_url(lower: &str) -> bool {
    let mut idx = 0usize;
    while idx < lower.len() {
        let (rel, scheme_len) = if let Some(p) = lower[idx..].find("https://") {
            (p, "https://".len())
        } else if let Some(p) = lower[idx..].find("http://") {
            (p, "http://".len())
        } else {
            break;
        };
        let start = idx + rel;
        let token = &lower[start..];
        let end = token
            .find(|c: char| c.is_whitespace() || c == '\\')
            .unwrap_or(token.len());
        let url = &token[..end];
        if ends_with_checksum_ext(url) || ends_with_checksum_path(url) || has_checksum_query(url) {
            return true;
        }
        idx = start + scheme_len;
    }
    false
}

/// Does this line fetch a checksum over http(s)?
fn fetches_checksum(line: &str) -> bool {
    let t = line.trim();
    if !(t.contains("curl") || t.contains("wget")) {
        return false;
    }
    checksum_url(&t.to_lowercase())
}

/// # Errors
///
/// Returns a finding when a checksum is fetched from the network, or when no
/// workflow verifies a checksum at all.
pub fn run(root: &Path) -> Result<String, String> {
    let workflows = root.join(".github/workflows");
    if !workflows.is_dir() {
        return Err(format!("no workflow directory at {}", workflows.display()));
    }
    let mut found_any = false;
    let mut offenders: Vec<String> = Vec::new();
    let mut verifying = 0usize;

    let rd = std::fs::read_dir(&workflows).map_err(|e| e.to_string())?;
    for e in rd.filter_map(Result::ok) {
        let path = e.path();
        let ext = path.extension().and_then(|x| x.to_str()).unwrap_or("");
        if ext != "yml" && ext != "yaml" {
            continue;
        }
        found_any = true;
        let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        for (n, line) in text.lines().enumerate() {
            if fetches_checksum(line) {
                offenders.push(format!("{name}:{}", n + 1));
            }
        }
        if text.contains("sha256sum -c") || text.contains("shasum -a 256 -c") {
            verifying += 1;
        }
    }

    if !found_any {
        return Err(format!(
            "no workflow files found under {} - wrong root?",
            workflows.display()
        ));
    }
    if !offenders.is_empty() {
        let mut msg = String::from(
            "these workflow lines download a checksum from the same host as the artefact:\n",
        );
        for o in &offenders {
            writeln!(msg, "  - {o}").expect("writing to a String cannot fail");
        }
        msg.push_str(
            "\nA hash served next to the file it describes verifies transit, not provenance:\n\
             whoever can replace one can replace the other. Write the expected hash into the\n\
             workflow instead, the way the cargo-llvm-cov step does:\n\
                 curl -sSfL -o /tmp/tool.tar.gz https://.../tool.tar.gz\n\
                 echo \"<hash>  /tmp/tool.tar.gz\" | sha256sum -c -\n\
             Obtain the hash by downloading the artefact once and hashing it yourself, and\n\
             record when it was taken.",
        );
        return Err(msg);
    }
    if verifying == 0 {
        return Err(String::from(
            "no workflow verifies any checksum - the gate would be vacuous",
        ));
    }
    Ok(format!(
        "Download pinning OK: every verified checksum is written in the repository ({verifying} workflow file(s) verify hashes; none fetch one)."
    ))
}

/// # Errors
///
/// Returns a finding when a defect fixture passes.
pub fn self_test() -> Result<String, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!("budlum-gates-pin-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(dir.join(".github/workflows"));

    // Fetched checksum must fail.
    let fetched = "run: |\n  curl -sSfLO https://github.com/x/y/releases/download/v1/tool.sha256\n  sha256sum -c tool.sha256\n";
    std::fs::write(dir.join(".github/workflows/ci.yml"), fetched).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a workflow downloading a checksum from the network passed",
        ));
    }

    // An uppercase extension must fail too: the extension match is
    // case-insensitive (CWE-184).
    let upper = "run: |\n  curl -sSfLO https://example.com/tool.tar.gz\n  curl -sSfLO https://example.com/tool.SHA256\n  sha256sum -c tool.SHA256\n";
    std::fs::write(dir.join(".github/workflows/ci.yml"), upper).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a workflow downloading a .SHA256 checksum from the network passed",
        ));
    }

    // A checksum URL carrying a query string must fail too: `?checksum=` or
    // `&hash=` in the URL is still a remote checksum fetch (Strix MEDIUM,
    // CWE-184, follow-up work).
    let query = "run: |\n  curl -sSfL \"https://example.com/download?checksum=abc\" -o tool.tar.gz\n  curl -sSfL \"https://example.com/tool?hash=def\" -o tool2.tar.gz\n";
    std::fs::write(dir.join(".github/workflows/ci.yml"), query).map_err(|e| e.to_string())?;
    if run(&dir).is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from(
            "canary: a workflow with a query-string checksum URL passed",
        ));
    }

    // Pinned hash written in-repo must pass.
    let good = "run: |\n  curl -sSfL -o /tmp/tool.tar.gz https://github.com/x/y/releases/download/v1/tool.tar.gz\n  echo \"abc123  /tmp/tool.tar.gz\" | sha256sum -c -\n";
    std::fs::write(dir.join(".github/workflows/ci.yml"), good).map_err(|e| e.to_string())?;
    if run(&dir).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(String::from("canary: repo-ici hash gecti"));
    }

    let _ = std::fs::remove_dir_all(&dir);
    Ok(String::from(
        "pinned-downloads canary OK (network checksum FAILs, in-repo hash PASSes).",
    ))
}
